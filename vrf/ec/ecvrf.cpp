// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "vrf/ec/ecvrf.h"
#include "vrf/common.h"
#include "vrf/ec/utils.h"
#include "vrf/guards.h"
#include "vrf/log.h"
#include <algorithm>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <tuple>
#include <utility>

namespace vrf::ec
{

namespace
{

template <typename... Points>
    requires(sizeof...(Points) >= 1) && (std::convertible_to<Points, const EC_POINT_Guard &> && ...)
ScalarType make_challenge(Type type, const EC_GROUP_Guard &group, Points &&...points)
{
    // Check that type and group are matching in terms of the NID.
    const ECVRFParams params = get_ecvrf_params(type);
    if (params.algorithm_name.empty() || group.get_curve() != params.curve)
    {
        GetLogger()->debug("make_challenge called with invalid or mismatched EC_GROUP.");
        return {};
    }

    BN_CTX_Guard bcg{false};
    if (!bcg.has_value())
    {
        GetLogger()->error("make_challenge failed to create BN_CTX.");
        return {};
    }

    const std::byte domain_separator_front = std::byte{0x02};
    const std::byte domain_separator_back = std::byte{0x00};
    const std::size_t suite_string_len = params.suite_string.size();

    const std::optional<std::size_t> challenge_input_buf_size =
        safe_add(suite_string_len, 2U /* domain separators */, (sizeof...(Points) * params.pt_len));
    if (!challenge_input_buf_size.has_value() || !std::in_range<std::ptrdiff_t>(*challenge_input_buf_size))
    {
        GetLogger()->debug("make_challenge failed to compute challenge input buffer size.");
        return {};
    }

    std::vector<std::byte> challenge_buf(*challenge_input_buf_size);
    const auto suite_string_start = challenge_buf.begin();
    const auto domain_separator_front_start = suite_string_start + static_cast<std::ptrdiff_t>(suite_string_len);
    const auto points_start = domain_separator_front_start + 1;
    const auto domain_separator_back_start =
        points_start + static_cast<std::ptrdiff_t>(sizeof...(Points) * params.pt_len);

    std::transform(params.suite_string.begin(), params.suite_string.end(), suite_string_start,
                   [](char c) { return static_cast<std::byte>(c); });
    *domain_separator_front_start = domain_separator_front;
    auto [success, written] = append_ecpoint_to_bytes(group, PointToBytesMethod::sec1_compressed, bcg, points_start,
                                                      std::forward<Points>(points)...);
    if (!success || challenge_buf.size() != written + suite_string_len + 2 /* domain separators */)
    {
        GetLogger()->debug("make_challenge failed to encode {} points to bytes.", sizeof...(Points));
        return {};
    }
    *domain_separator_back_start = domain_separator_back;

    // Hash the concatenated point representations to create the challenge.
    std::vector<std::byte> challenge = compute_hash(params.digest.data(), challenge_buf);

    // Note that params.h_len >= params.c_len always.
    challenge.resize(params.c_len);

    // Convert to BIGNUM. Note that there is no reduction modulo order here.
    bytes_to_int_ptr_t bytes_to_int = get_bytes_to_int_method(params.bytes_to_int);
    if (nullptr == bytes_to_int)
    {
        GetLogger()->error("make_challenge failed to get bytes_to_int method.");
        return {};
    }

    ScalarType ret = bytes_to_int({challenge.data(), challenge.size()}, false);
    if (!ret.has_value())
    {
        GetLogger()->debug("make_challenge failed to convert challenge hash to BIGNUM.");
        return {};
    }

    GetLogger()->trace("make_challenge computed challenge of size {} bytes for VRF type {}.", challenge.size(),
                       to_string(type));
    return ret;
}

std::tuple<bool, ECPoint, ScalarType, ScalarType> decode_proof(Type type, const EC_GROUP_Guard &group,
                                                               std::span<const std::byte> proof, BN_CTX_Guard &bcg)
{
    const ECVRFParams params = get_ecvrf_params(type);
    if (params.algorithm_name.empty())
    {
        GetLogger()->debug("decode_proof called with non-EC VRF type {}.", to_string(type));
        return {false, {}, {}, {}};
    }
    if (group.get_curve() != params.curve)
    {
        GetLogger()->debug("decode_proof called with mismatched EC_GROUP for VRF type {}.", to_string(type));
        return {false, {}, {}, {}};
    }
    if (!ensure_bcg_set(bcg, false))
    {
        GetLogger()->error("decode_proof failed to obtain BN_CTX.");
        return {false, {}, {}, {}};
    }

    const std::size_t expected_proof_size = params.pt_len + params.c_len + params.q_len;
    if (expected_proof_size != proof.size())
    {
        GetLogger()->debug("decode_proof called with proof of incorrect size: expected {} bytes, got {} bytes",
                           expected_proof_size, proof.size());
        return {false, {}, {}, {}};
    }

    const auto gamma_start = proof.begin();
    const auto challenge_start = gamma_start + static_cast<std::ptrdiff_t>(params.pt_len);
    const auto s_start = challenge_start + static_cast<std::ptrdiff_t>(params.c_len);

    // Decode gamma point.
    const bytes_to_point_ptr_t bytes_to_point = get_bytes_to_point_method(params.bytes_to_point);
    if (nullptr == bytes_to_point)
    {
        GetLogger()->error("decode_proof failed to get bytes_to_point method.");
        return {false, {}, {}, {}};
    }
    const bytes_to_int_ptr_t bytes_to_int = get_bytes_to_int_method(params.bytes_to_int);
    if (nullptr == bytes_to_int)
    {
        GetLogger()->error("decode_proof failed to get bytes_to_int method.");
        return {false, {}, {}, {}};
    }

    ECPoint gamma = bytes_to_point(group, {gamma_start, params.pt_len}, bcg);
    ScalarType challenge = bytes_to_int({challenge_start, params.c_len}, false);
    ScalarType s = bytes_to_int({s_start, params.q_len}, false);
    if (!gamma.has_value() || !challenge.has_value() || !s.has_value())
    {
        GetLogger()->debug("decode_proof failed to decode one of the proof components.");
        return {false, {}, {}, {}};
    }

    const BIGNUM *order = EC_GROUP_get0_order(group.get());
    if (0 <= BN_cmp(s.get().get(), order))
    {
        GetLogger()->debug("decode_proof found 's' value not in valid range.");
        return {false, {}, {}, {}};
    }

    GetLogger()->trace("decode_proof decoded proof for VRF type {}.", to_string(type));
    return {true, std::move(gamma), std::move(challenge), std::move(s)};
}

bool validate_public_key(Type type, const ECPoint &pk, const EC_GROUP_Guard &group, BN_CTX_Guard &bcg)
{
    if (!pk.has_value() || !group.has_value() || group.get_curve() != pk.get_curve())
    {
        GetLogger()->debug("validate_key called with invalid or mismatched ECPoint and EC_GROUP.");
        return false;
    }

    if (!ensure_bcg_set(bcg, false))
    {
        GetLogger()->error("validate_key failed to obtain BN_CTX.");
        return false;
    }

    const ECVRFParams params = get_ecvrf_params(type);
    if (params.algorithm_name.empty())
    {
        GetLogger()->debug("validate_key called with non-EC VRF type {}.", to_string(type));
        return false;
    }

    // Check that the group matches the type.
    if (group.get_curve() != params.curve)
    {
        GetLogger()->debug("validate_key called with mismatched EC_GROUP for VRF type {}.", to_string(type));
        return false;
    }

    ECPoint cofactor_cleared_pk{pk};

    // Clear any cofactor from the public key.
    if (1 != params.cofactor)
    {
        ScalarType cofactor{false};
        if (!cofactor.has_value() || 1 != BN_set_word(cofactor.get().get(), params.cofactor))
        {
            GetLogger()->debug("validate_key failed to create or set cofactor BIGNUM.");
            return false;
        }

        if (!cofactor_cleared_pk.scalar_multiply(group, cofactor, bcg))
        {
            GetLogger()->debug("validate_key failed to multiply public key by cofactor.");
            return false;
        }
    }

    // Check that the cofactor-cleared public key is not the point at infinity.
    if (1 == EC_POINT_is_at_infinity(group.get(), cofactor_cleared_pk.get().get()))
    {
        GetLogger()->debug(
            "validate_key found invalid public key: cofactor-cleared public key is the point at infinity.");
        return false;
    }

    GetLogger()->trace("validate_key validated public key for VRF type {}.", to_string(type));
    return true;
}

std::vector<std::byte> get_vrf_value_internal(const ECVRFParams &params, const EC_GROUP_Guard &group, ECPoint gamma,
                                              BN_CTX_Guard &bcg)
{
    // This function does no validation of its inputs.

    // Clear any cofactor from gamma.
    if (1 != params.cofactor)
    {
        ScalarType cofactor{false};
        if (!cofactor.has_value() || 1 != BN_set_word(cofactor.get().get(), params.cofactor))
        {
            GetLogger()->debug("ECProof::get_vrf_value failed to create or set cofactor BIGNUM.");
            return {};
        }

        if (!gamma.scalar_multiply(group, cofactor, bcg))
        {
            GetLogger()->debug("ECProof::get_vrf_value failed to multiply gamma by cofactor.");
            return {};
        }
    }

    // Write the cofactor-cleared gamma into a new buffer.
    std::vector<std::byte> cofactor_cleared_gamma_buf(params.pt_len);
    point_to_bytes_ptr_t point_to_bytes = get_point_to_bytes_method(params.point_to_bytes);
    if (nullptr == point_to_bytes)
    {
        GetLogger()->error("ECProof::get_vrf_value failed to get point_to_bytes method.");
        return {};
    }
    if (params.pt_len != point_to_bytes(group, gamma.get(), bcg, cofactor_cleared_gamma_buf))
    {
        GetLogger()->debug("ECProof::get_vrf_value failed to convert cofactor-cleared gamma to bytes.");
        return {};
    }

    const std::byte domain_separator_front{0x03};
    const std::byte domain_separator_back{0x00};
    const std::size_t hash_buf_size = params.suite_string.size() + 1 /* domain_separator_front */ +
                                      params.pt_len /* cofactor-cleared gamma */ + 1 /* domain_separator_back */;

    std::vector<std::byte> hash_buf(hash_buf_size);

    const auto suite_string_start = hash_buf.begin();
    const auto domain_separator_front_start =
        suite_string_start + static_cast<std::ptrdiff_t>(params.suite_string.size());
    const auto cofactor_cleared_gamma_start = domain_separator_front_start + 1;
    const auto domain_separator_back_start = cofactor_cleared_gamma_start + static_cast<std::ptrdiff_t>(params.pt_len);

    std::ranges::transform(params.suite_string, suite_string_start, [](char c) { return static_cast<std::byte>(c); });
    *domain_separator_front_start = domain_separator_front;
    std::ranges::copy_n(cofactor_cleared_gamma_buf.begin(), static_cast<std::ptrdiff_t>(params.pt_len),
                        cofactor_cleared_gamma_start);
    *domain_separator_back_start = domain_separator_back;

    std::vector<std::byte> vrf_value = compute_hash(params.digest.data(), hash_buf);
    GetLogger()->trace("ECProof::get_vrf_value computed VRF output of size {} bytes.", vrf_value.size());
    return vrf_value;
}

} // namespace

std::vector<std::byte> ECProof::get_vrf_value() const
{
    if (!is_initialized())
    {
        GetLogger()->warning("ECProof::get_vrf_value called on an incorrectly initialized proof.");
        return {};
    }

    const Type type = get_type();
    const ECVRFParams params = get_ecvrf_params(type);
    if (params.algorithm_name.empty())
    {
        GetLogger()->warning("ECProof::get_vrf_value called with non-EC VRF type {}.", to_string(type));
        return {};
    }

    const EC_GROUP_Guard group{params.curve};
    if (!group.has_value())
    {
        GetLogger()->warning("ECProof::get_vrf_value failed to create EC_GROUP for VRF type {}.", vrf::to_string(type));
        return {};
    }

    BN_CTX_Guard bcg{false};
    if (!bcg.has_value())
    {
        GetLogger()->error("ECProof::get_vrf_value failed to create BN_CTX.");
        return {};
    }

    auto [success, gamma, challenge, s] = decode_proof(get_type(), group, proof_, bcg);
    if (!success)
    {
        GetLogger()->warning("ECProof::get_vrf_value failed to decode proof.");
        return {};
    }

    std::vector<std::byte> vrf_value = get_vrf_value_internal(params, group, std::move(gamma), bcg);
    if (vrf_value.empty())
    {
        GetLogger()->warning("ECProof::get_vrf_value failed to compute VRF value from proof.");
    }
    return vrf_value;
}

std::vector<std::byte> ECProof::to_bytes() const
{
    if (!is_initialized())
    {
        GetLogger()->warning("ECProof::to_bytes called on an incorrectly initialized proof.");
        return {};
    }

    const std::byte type_byte = to_byte(get_type());
    std::vector<std::byte> ret;
    ret.reserve(1 + proof_.size());
    ret.push_back(type_byte);
    ret.insert(ret.end(), proof_.begin(), proof_.end());

    GetLogger()->trace("ECProof::to_bytes serialized proof of size {} to byte vector of size {}.", proof_.size(),
                       ret.size());
    return ret;
}

void ECProof::from_bytes(std::span<const std::byte> data)
{
    const auto [type, data_without_type] = extract_type_from_span(data);
    GetLogger()->trace("ECProof::from_bytes extracted VRF type {} from input byte vector of size {}.", to_string(type),
                       data.size());

    ECProof ec_proof{type, std::vector<std::byte>(data_without_type.begin(), data_without_type.end())};
    if (!ec_proof.is_initialized())
    {
        GetLogger()->warning("ECProof::from_bytes called with invalid proof data for VRF type {}.", to_string(type));
        return;
    }

    GetLogger()->trace("ECProof::from_bytes initialized ECProof from input byte vector.");
    *this = std::move(ec_proof);
}

ECProof::ECProof(const ECProof &source) = default;

ECProof &ECProof::operator=(ECProof &&rhs) noexcept
{
    if (this != &rhs)
    {
        const Type type = get_type();
        set_type(rhs.get_type());
        rhs.set_type(type);

        using std::swap;
        swap(proof_, rhs.proof_);
    }
    return *this;
}

ECSecretKey::ECSecretKey(Type type) : SecretKey{Type::unknown}
{
    ScalarType sk{true};
    if (!sk.has_value())
    {
        GetLogger()->error("ECSecretKey constructor failed to create ScalarType for secret key.");
        return;
    }

    const ECVRFParams params = get_ecvrf_params(type);
    if (params.algorithm_name.empty())
    {
        GetLogger()->warning("ECSecretKey constructor called with non-EC VRF type {}.", to_string(type));
        return;
    }

    EC_GROUP_Guard group{params.curve};
    if (!group.has_value())
    {
        GetLogger()->warning("ECSecretKey constructor failed to create EC_GROUP for VRF type {}.",
                             vrf::to_string(type));
        return;
    }

    // Set sk to a random non-zero value.
    do
    {
        if (!sk.set_random(group))
        {
            GetLogger()->warning("ECSecretKey constructor failed to set random secret key.");
            return;
        }
    } while (sk.is_zero());

    // Create the public key.
    ECPoint pk{group};
    if (!pk.has_value())
    {
        GetLogger()->warning("ECSecretKey constructor failed to create public key point.");
        return;
    }

    // Multiply the generator by the secret key to get the public key point.
    BN_CTX_Guard bcg{true};
    if (!pk.set_to_generator_multiple(group, sk, bcg))
    {
        GetLogger()->warning("ECSecretKey constructor failed to compute public key point.");
        return;
    }

    // Everything worked, so set the values in the new object.
    using std::swap;
    swap(sk_, sk);
    swap(pk_, pk);
    swap(group_, group);
    set_type(type);

    GetLogger()->trace("ECSecretKey constructor generated key pair for VRF type {}.", to_string(type));
}

ECSecretKey::ECSecretKey(Type type, ScalarType sk) : SecretKey{Type::unknown}
{
    if (!sk.has_value())
    {
        GetLogger()->warning("ECSecretKey constructor called with uninitialized secret key.");
        return;
    }

    const ECVRFParams params = get_ecvrf_params(type);
    if (params.algorithm_name.empty())
    {
        GetLogger()->warning("ECSecretKey constructor called with non-EC VRF type {}.", to_string(type));
        return;
    }

    EC_GROUP_Guard group{params.curve};
    if (!group.has_value())
    {
        GetLogger()->warning("ECSecretKey constructor failed to create EC_GROUP for VRF type {}.",
                             vrf::to_string(type));
        return;
    }

    // Check that the given sk is in the valid range [1, order-1].
    const BIGNUM *order = EC_GROUP_get0_order(group.get());
    if (0 > BN_cmp(sk.get().get(), BN_value_one()) || 0 <= BN_cmp(sk.get().get(), order))
    {
        GetLogger()->warning("ECSecretKey constructor called with secret key out of valid range.");
        return;
    }

    // Create the public key.
    ECPoint pk{group};
    if (!pk.has_value())
    {
        GetLogger()->warning("ECSecretKey constructor failed to create public key point.");
        return;
    }

    // Multiply the generator by the secret key to get the public key point.
    BN_CTX_Guard bcg{true};
    if (!pk.set_to_generator_multiple(group, sk, bcg))
    {
        GetLogger()->warning("ECSecretKey constructor failed to compute public key point.");
        return;
    }

    // Everything worked, so set the values in the new object.
    using std::swap;
    swap(sk_, sk);
    swap(pk_, pk);
    swap(group_, group);
    set_type(type);

    GetLogger()->trace("ECSecretKey constructor initialized ECSecretKey from given secret key for VRF type {}.",
                       to_string(type));
}

std::unique_ptr<PublicKey> ECSecretKey::get_public_key() const
{
    if (!is_initialized())
    {
        GetLogger()->warning("ECSecretKey::get_public_key called on invalid ECSecretKey.");
        return nullptr;
    }

    std::unique_ptr<PublicKey> ret{new ECPublicKey{get_type(), group_, pk_}};
    if (nullptr == ret || !ret->is_initialized())
    {
        GetLogger()->warning("ECSecretKey::get_public_key failed to create ECPublicKey from ECSecretKey.");
        return nullptr;
    }

    GetLogger()->trace("ECSecretKey::get_public_key created ECPublicKey from ECSecretKey for VRF type {}.",
                       to_string(get_type()));
    return ret;
}

ECSecretKey &ECSecretKey::operator=(ECSecretKey &&rhs) noexcept
{
    if (this != &rhs)
    {
        const Type type = get_type();
        set_type(rhs.get_type());
        rhs.set_type(type);

        using std::swap;
        swap(sk_, rhs.sk_);
        swap(pk_, rhs.pk_);
        swap(group_, rhs.group_);
    }
    return *this;
}

ECSecretKey::ECSecretKey(const ECSecretKey &source) : SecretKey(source)
{
    if (!source.is_initialized())
    {
        GetLogger()->warning("ECSecretKey copy constructor called on invalid ECSecretKey.");
        return;
    }

    ScalarType sk_copy = source.sk_;
    ECPoint pk_copy = source.pk_;
    EC_GROUP_Guard group_copy = source.group_;
    if (!sk_copy.has_value() || !pk_copy.has_value() || !group_copy.has_value())
    {
        GetLogger()->error("ECSecretKey copy constructor failed to clone the given secret key.");
        return;
    }

    sk_ = std::move(sk_copy);
    pk_ = std::move(pk_copy);
    group_ = std::move(group_copy);
    set_type(source.get_type());

    GetLogger()->trace("ECSecretKey copy constructor initialized secret key copy for VRF type {}.",
                       to_string(get_type()));
}

std::unique_ptr<Proof> ECSecretKey::get_vrf_proof(std::span<const std::byte> in)
{
    if (!is_initialized())
    {
        GetLogger()->warning("ECSecretKey::get_vrf_proof called on invalid ECSecretKey.");
        return nullptr;
    }

    const Type type = get_type();
    const ECVRFParams params = get_ecvrf_params(type);
    if (params.algorithm_name.empty())
    {
        GetLogger()->warning("ECSecretKey::get_vrf_proof called with non-EC VRF type {}.", to_string(type));
        return nullptr;
    }

    // Set up a BN_CTX that we can use repeatedly.
    BN_CTX_Guard bcg{true};
    if (!bcg.has_value())
    {
        GetLogger()->error("ECSecretKey::get_vrf_proof failed to create BN_CTX.");
        return nullptr;
    }

    const point_to_bytes_ptr_t point_to_bytes = get_point_to_bytes_method(params.point_to_bytes);
    if (nullptr == point_to_bytes)
    {
        GetLogger()->error("ECSecretKey::get_vrf_proof failed to get point_to_bytes method.");
        return nullptr;
    }
    const int_to_bytes_ptr_t int_to_bytes = get_int_to_bytes_method(params.bytes_to_int);
    if (nullptr == int_to_bytes)
    {
        GetLogger()->error("ECSecretKey::get_vrf_proof failed to get int_to_bytes method.");
        return nullptr;
    }

    // The proof requires the hash of the following data:
    // 1. public key
    // 2. encode-to-curve(e2c_salt, data)
    // 3. gamma <- encode-to-curve(e2c_salt, data) multiplied by secret key
    // 4. generator multiplied by nonce
    // 5. hash-to-curve(e2c_salt, data) multiplied by nonce

    // First get the encode-to-curve salt.
    const e2c_salt_ptr_t e2c_salt_method = get_e2c_salt_method(params.e2c_salt);
    if (nullptr == e2c_salt_method)
    {
        GetLogger()->error("ECSecretKey::get_vrf_proof failed to get encode-to-curve salt method.");
        return nullptr;
    }
    std::vector<std::byte> e2c_salt = e2c_salt_method(type, group_, pk_.get(), bcg);
    if (e2c_salt.empty())
    {
        GetLogger()->warning("ECSecretKey::get_vrf_proof failed to compute encode-to-curve salt.");
        return nullptr;
    }

    // Get the e2c value.
    const e2c_ptr_t e2c_method = get_e2c_method(params.e2c);
    if (nullptr == e2c_method)
    {
        GetLogger()->error("ECSecretKey::get_vrf_proof failed to get encode-to-curve method.");
        return nullptr;
    }
    ECPoint e2c_point = e2c_method(type, group_, e2c_salt, in, bcg);
    if (!e2c_point.has_value())
    {
        GetLogger()->warning("ECSecretKey::get_vrf_proof failed to compute encode-to-curve point.");
        return nullptr;
    }

    // We also need the encoded point as an octet string.
    std::vector<std::byte> e2c_data(params.pt_len);
    if (params.pt_len != point_to_bytes(group_, e2c_point.get(), bcg, e2c_data))
    {
        GetLogger()->warning("ECSecretKey::get_vrf_proof failed to convert encode-to-curve point to bytes.");
        return nullptr;
    }

    // Next, compute the gamma value.
    ECPoint gamma = e2c_point;
    if (!gamma.scalar_multiply(group_, sk_, bcg))
    {
        GetLogger()->warning("ECSecretKey::get_vrf_proof failed to compute gamma point.");
        return nullptr;
    }

    // Create the nonce from the secret key and e2c_data.
    nonce_gen_ptr_t nonce_gen_method = get_nonce_gen_method(params.nonce_gen);
    if (nullptr == nonce_gen_method)
    {
        GetLogger()->error("ECSecretKey::get_vrf_proof failed to get nonce generation method.");
        return nullptr;
    }
    ScalarType nonce = nonce_gen_method(type, group_, sk_.get(), e2c_data);
    if (!nonce.has_value())
    {
        GetLogger()->warning("ECSecretKey::get_vrf_proof failed to compute nonce.");
        return nullptr;
    }

    // We need nonce*G for the challenge.
    ECPoint nonce_times_generator{group_};
    if (!nonce_times_generator.set_to_generator_multiple(group_, nonce, bcg))
    {
        GetLogger()->warning("ECSecretKey::get_vrf_proof failed to compute nonce*generator point.");
        return nullptr;
    }

    // We also need nonce*e2c_point for the challenge.
    ECPoint nonce_times_e2c_point = e2c_point;
    if (!nonce_times_e2c_point.scalar_multiply(group_, nonce, bcg))
    {
        GetLogger()->warning("ECSecretKey::get_vrf_proof failed to compute nonce*e2c_point.");
        return nullptr;
    }

    // The challenge "hashes" the following points in order:
    // (1) public key; (2) e2c_point; (3) gamma; (4) nonce*generator; (5) nonce*e2c_point.
    const ScalarType challenge = make_challenge(type, group_, pk_.get(), e2c_point.get(), gamma.get(),
                                                nonce_times_generator.get(), nonce_times_e2c_point.get());
    if (!challenge.has_value())
    {
        GetLogger()->warning("ECSecretKey::get_vrf_proof failed to compute challenge.");
        return nullptr;
    }

    ScalarType s = sk_;
    if (!s.has_value() || !s.multiply(challenge, group_, bcg) || !s.reduce_mod_order(group_, bcg) ||
        !s.add(nonce, group_, bcg) || !s.reduce_mod_order(group_, bcg))
    {
        GetLogger()->warning("ECSecretKey::get_vrf_proof failed to compute 's' value for proof.");
        return nullptr;
    }

    std::vector<std::byte> proof(params.pt_len + params.c_len + params.q_len);
    const auto gamma_start = proof.begin();
    const auto challenge_start = gamma_start + static_cast<std::ptrdiff_t>(params.pt_len);
    const auto s_start = challenge_start + static_cast<std::ptrdiff_t>(params.c_len);
    if (params.pt_len != point_to_bytes(group_, gamma.get(), bcg, {gamma_start, params.pt_len}) ||
        params.c_len != int_to_bytes(challenge.get(), {challenge_start, params.c_len}) ||
        params.q_len != int_to_bytes(s.get(), {s_start, params.q_len}))
    {
        GetLogger()->warning("ECSecretKey::get_vrf_proof failed to assemble proof.");
        return nullptr;
    }

    std::unique_ptr<Proof> ret{new ECProof{type, std::move(proof)}};
    if (nullptr == ret || !ret->is_initialized())
    {
        GetLogger()->warning("ECSecretKey::get_vrf_proof failed to create ECProof from proof data.");
        return nullptr;
    }

    GetLogger()->trace("ECSecretKey::get_vrf_proof generated proof for VRF type {}.", to_string(type));
    return ret;
}

std::vector<std::byte> ECSecretKey::to_bytes() const
{
    GetLogger()->error("ECSecretKey::to_bytes is disabled; use to_secure_bytes() instead.");
    return {};
}

SecureBuf ECSecretKey::to_secure_bytes() const
{
    if (!is_initialized())
    {
        GetLogger()->warning("ECSecretKey::to_secure_bytes called on invalid ECSecretKey.");
        return {};
    }

    const ECVRFParams params = get_ecvrf_params(get_type());
    if (params.algorithm_name.empty())
    {
        GetLogger()->warning("ECSecretKey::to_secure_bytes failed to get ECVRF params.");
        return {};
    }

    const BIGNUM *sk_bn = sk_.get().get();
    if (nullptr == sk_bn)
    {
        GetLogger()->warning("ECSecretKey::to_secure_bytes failed to access secret key scalar.");
        return {};
    }

    SecureBuf buf{params.q_len + 1 /* for type byte */};
    if (!buf.has_value())
    {
        GetLogger()->error("ECSecretKey::to_secure_bytes failed to allocate secure buffer.");
        return {};
    }

    buf.get()[0] = to_byte(get_type());

    const int written =
        BN_bn2binpad(sk_bn, reinterpret_cast<unsigned char *>(buf.get() + 1), static_cast<int>(params.q_len));
    if (std::cmp_not_equal(written, params.q_len))
    {
        GetLogger()->warning("ECSecretKey::to_secure_bytes failed to convert secret key scalar to bytes.");
        return {};
    }

    GetLogger()->trace("ECSecretKey::to_secure_bytes serialized secret key to secure buffer of size {}.", buf.size());
    return buf;
}

void ECSecretKey::from_bytes(std::span<const std::byte> data)
{
    const auto [type, data_without_type] = extract_type_from_span(data);
    GetLogger()->trace("ECSecretKey::from_bytes extracted VRF type {} from input byte vector of size {}.",
                       to_string(type), data.size());

    if (!is_ec_type(type))
    {
        GetLogger()->warning("ECSecretKey::from_bytes called with non-EC VRF type {}.", to_string(type));
        return;
    }

    const ECVRFParams params = get_ecvrf_params(type);
    if (params.algorithm_name.empty())
    {
        GetLogger()->warning("ECSecretKey::from_bytes called with non-EC VRF type {}.", to_string(type));
        return;
    }

    if (data_without_type.empty() || !std::in_range<int>(data_without_type.size()) ||
        data_without_type.size() != params.q_len)
    {
        GetLogger()->warning("ECSecretKey::from_bytes called with invalid scalar size for VRF type {}.",
                             to_string(type));
        return;
    }

    BIGNUM *bn = BN_bin2bn(reinterpret_cast<const unsigned char *>(data_without_type.data()),
                           static_cast<int>(data_without_type.size()), nullptr);
    if (nullptr == bn)
    {
        GetLogger()->error("ECSecretKey::from_bytes failed to convert bytes to BIGNUM.");
        return;
    }

    BIGNUM_Guard sk_bn{bn, true};
    ScalarType sk{std::move(sk_bn)};
    if (!sk.has_value())
    {
        GetLogger()->error("ECSecretKey::from_bytes failed to create ScalarType from secret key.");
        return;
    }

    ECSecretKey secret_key{type, std::move(sk)};
    if (!secret_key.is_initialized())
    {
        GetLogger()->warning("ECSecretKey::from_bytes called with invalid secret key bytes for VRF type {}.",
                             to_string(type));
        return;
    }

    GetLogger()->trace("ECSecretKey::from_bytes initialized ECSecretKey from input byte vector.");
    *this = std::move(secret_key);
}

ECPublicKey::ECPublicKey(const ECPublicKey &source) : PublicKey{Type::unknown}
{
    ECPoint pk_copy{source.pk_};
    EC_GROUP_Guard group_copy{source.group_};
    if (pk_copy.has_value() != source.pk_.has_value() || group_copy.has_value() != source.group_.has_value())
    {
        GetLogger()->error("ECPublicKey copy constructor failed to clone the given public key.");
        return;
    }

    pk_ = std::move(pk_copy);
    group_ = std::move(group_copy);
    set_type(source.get_type());

    GetLogger()->trace("ECPublicKey copy constructor initialized public key copy for VRF type {}.",
                       to_string(get_type()));
}

ECPublicKey &ECPublicKey::operator=(ECPublicKey &&rhs) noexcept
{
    if (this != &rhs)
    {
        const Type type = get_type();
        set_type(rhs.get_type());
        rhs.set_type(type);

        using std::swap;
        swap(pk_, rhs.pk_);
        swap(group_, rhs.group_);
    }
    return *this;
}

// NOLINTNEXTLINE(performance-unnecessary-value-param)
ECPublicKey::ECPublicKey(Type type, EC_GROUP_Guard group, ECPoint pk) : PublicKey{Type::unknown}
{
    const ECVRFParams params = get_ecvrf_params(type);
    if (params.algorithm_name.empty())
    {
        GetLogger()->warning("ECPublicKey constructor called with non-EC VRF type {}.", to_string(type));
        return;
    }

    if (!group.has_value() || !pk.has_value() || group.get_curve() != params.curve || params.curve != pk.get_curve())
    {
        GetLogger()->warning(
            "ECPublicKey constructor called with invalid or mismatched EC_GROUP and ECPoint for VRF type {}.",
            to_string(type));
        return;
    }

    using std::swap;
    swap(pk_, pk);
    swap(group_, group);
    set_type(type);

    GetLogger()->trace("ECPublicKey constructor initialized ECPublicKey from EC_GROUP and ECPoint for VRF type {}.",
                       to_string(type));
}

ECPublicKey::ECPublicKey(Type type, std::span<const std::byte> der_spki) : PublicKey{Type::unknown}
{
    if (!is_ec_type(type))
    {
        GetLogger()->warning("ECPublicKey constructor called with non-EC VRF type {}.", to_string(type));
        return;
    }

    const ECVRFParams params = get_ecvrf_params(type);
    if (params.algorithm_name.empty())
    {
        GetLogger()->warning("ECPublicKey constructor called with non-EC VRF type {}.", to_string(type));
        return;
    }

    EC_GROUP_Guard group{params.curve};
    if (!group.has_value())
    {
        GetLogger()->warning("ECPublicKey constructor failed to create EC_GROUP for VRF type {}.",
                             vrf::to_string(type));
        return;
    }

    EVP_PKEY_Guard pkey{decode_public_key_from_der_spki(params.algorithm_name.data(), der_spki)};
    if (!pkey.has_value())
    {
        GetLogger()->warning("ECPublicKey constructor failed to decode DER SPKI for VRF type {}.", to_string(type));
        return;
    }

    // Extract the curve name from OSSL_PKEY_PARAM_GROUP_NAME.
    std::size_t group_name_size = 0;
    if (1 != EVP_PKEY_get_utf8_string_param(pkey.get(), OSSL_PKEY_PARAM_GROUP_NAME, nullptr, 0, &group_name_size))
    {
        GetLogger()->warning("ECPublicKey constructor failed to get size of OSSL_PKEY_PARAM_GROUP_NAME.");
        return;
    }

    // group_name_size does *not* include the null terminator, so we need to add that to the allocation.
    std::vector<char> group_name(group_name_size + 1);
    if (1 != EVP_PKEY_get_utf8_string_param(pkey.get(), OSSL_PKEY_PARAM_GROUP_NAME, group_name.data(),
                                            group_name.size(), &group_name_size) ||
        group_name.size() != group_name_size + 1)
    {
        GetLogger()->warning("ECPublicKey constructor failed to get OSSL_PKEY_PARAM_GROUP_NAME.");
        return;
    }

    // Extract the key bytes from OSSL_PKEY_PARAM_PUB_KEY.
    std::size_t pk_size = 0;
    if (1 != EVP_PKEY_get_octet_string_param(pkey.get(), OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &pk_size))
    {
        GetLogger()->warning("ECPublicKey constructor failed to get size of OSSL_PKEY_PARAM_PUB_KEY.");
        return;
    }

    std::vector<std::byte> pk_bytes(pk_size);
    if (1 != EVP_PKEY_get_octet_string_param(pkey.get(), OSSL_PKEY_PARAM_PUB_KEY,
                                             reinterpret_cast<unsigned char *>(pk_bytes.data()), pk_bytes.size(),
                                             &pk_size) ||
        pk_bytes.size() != pk_size)
    {
        GetLogger()->warning("ECPublicKey constructor failed to get OSSL_PKEY_PARAM_PUB_KEY.");
        return;
    }

    BN_CTX_Guard bcg{false};
    if (!bcg.has_value())
    {
        GetLogger()->error("ECPublicKey constructor failed to create BN_CTX.");
        return;
    }

    bytes_to_point_ptr_t point_from_bytes = get_bytes_to_point_method(params.bytes_to_point);
    if (nullptr == point_from_bytes)
    {
        GetLogger()->error("ECPublicKey constructor failed to get bytes_to_point method.");
        return;
    }
    ECPoint pk = point_from_bytes(group, pk_bytes, bcg);
    if (!pk.has_value())
    {
        GetLogger()->warning("ECPublicKey constructor failed to convert public key bytes to ECPoint.");
        return;
    }

    // All OK. Set the values.
    pk_ = std::move(pk);
    group_ = std::move(group);
    set_type(type);

    GetLogger()->trace("ECPublicKey constructor initialized ECPublicKey from DER SPKI for VRF type {}.",
                       to_string(type));
}

std::pair<bool, std::vector<std::byte>> ECPublicKey::verify_vrf_proof(std::span<const std::byte> in, const Proof &proof)
{
    if (!is_initialized())
    {
        GetLogger()->warning("ECPublicKey::verify_vrf_proof called on invalid ECPublicKey.");
        return {false, {}};
    }

    // Downcast the proof type to ECProof.
    const ECProof *ec_proof = dynamic_cast<const ECProof *>(&proof);
    if (nullptr == ec_proof)
    {
        GetLogger()->warning("ECPublicKey::verify_vrf_proof called with proof that is not of type ECProof.");
        return {false, {}};
    }

    const Type type = get_type();
    if (!ec_proof->is_initialized() || ec_proof->get_type() != type)
    {
        GetLogger()->warning("ECPublicKey::verify_vrf_proof called with invalid or mismatched proof type.");
        return {false, {}};
    }

    BN_CTX_Guard bcg{false};
    if (!bcg.has_value())
    {
        GetLogger()->error("ECPublicKey::verify_vrf_proof failed to create BN_CTX.");
        return {false, {}};
    }

    const ECVRFParams params = get_ecvrf_params(type);

    // Verify that the public key is valid.
    if (!validate_public_key(type, pk_, group_, bcg))
    {
        GetLogger()->warning("ECPublicKey::verify_vrf_proof found public key is invalid.");
        return {false, {}};
    }

    auto [success, gamma, challenge, s] = decode_proof(type, group_, ec_proof->proof_, bcg);
    if (!success)
    {
        GetLogger()->warning("ECPublicKey::verify_vrf_proof failed to decode proof.");
        return {false, {}};
    }

    e2c_salt_ptr_t e2c_salt_method = get_e2c_salt_method(params.e2c_salt);
    if (nullptr == e2c_salt_method)
    {
        GetLogger()->error("ECPublicKey::verify_vrf_proof failed to get encode-to-curve salt method.");
        return {false, {}};
    }
    std::vector<std::byte> e2c_salt = e2c_salt_method(type, group_, pk_.get(), bcg);
    if (e2c_salt.empty())
    {
        GetLogger()->warning("ECPublicKey::verify_vrf_proof failed to compute encode-to-curve salt.");
        return {false, {}};
    }

    e2c_ptr_t e2c_method = get_e2c_method(params.e2c);
    if (nullptr == e2c_method)
    {
        GetLogger()->error("ECPublicKey::verify_vrf_proof failed to get encode-to-curve method.");
        return {false, {}};
    }
    ECPoint e2c_point = e2c_method(type, group_, e2c_salt, in, bcg);
    if (!e2c_point.has_value())
    {
        GetLogger()->warning("ECPublicKey::verify_vrf_proof failed to compute encode-to-curve point.");
        return {false, {}};
    }

    // We will need s*e2c_point.
    ECPoint s_times_e2c_point{e2c_point};
    if (!s_times_e2c_point.scalar_multiply(group_, s, bcg))
    {
        GetLogger()->warning("ECPublicKey::verify_vrf_proof failed to compute s*e2c_point.");
        return {false, {}};
    }

    ECPoint U{pk_};
    if (!U.negate(group_, bcg) || !U.double_scalar_multiply(group_, challenge, s, bcg))
    {
        GetLogger()->warning("ECPublicKey::verify_vrf_proof failed to compute U point.");
        return {false, {}};
    }

    ECPoint V{gamma};
    if (!V.negate(group_, bcg) || !V.scalar_multiply(group_, challenge, bcg) || !V.add(group_, s_times_e2c_point, bcg))
    {
        GetLogger()->warning("ECPublicKey::verify_vrf_proof failed to compute V point.");
        return {false, {}};
    }

    // Compute the challenge directly.
    const ScalarType challenge_comp =
        make_challenge(type, group_, pk_.get(), e2c_point.get(), gamma.get(), U.get(), V.get());
    if (!challenge_comp.has_value() || challenge_comp != challenge)
    {
        GetLogger()->warning("ECPublicKey::verify_vrf_proof failed to verify proof: challenge does not match.");
        return {false, {}};
    }

    // Compute the VRF value from the proof.
    std::vector<std::byte> vrf_value = get_vrf_value_internal(params, group_, std::move(gamma), bcg);
    if (vrf_value.empty())
    {
        GetLogger()->warning("ECPublicKey::verify_vrf_proof failed to compute VRF value from proof.");
        return {false, {}};
    }

    GetLogger()->trace(
        "ECPublicKey::verify_vrf_proof successfully verified proof and computed VRF value of size {} bytes.",
        vrf_value.size());
    return {true, std::move(vrf_value)};
}

std::vector<std::byte> ECPublicKey::to_bytes() const
{
    if (!is_initialized())
    {
        GetLogger()->warning("ECPublicKey::to_bytes called on invalid ECPublicKey.");
        return {};
    }

    BN_CTX_Guard bcg{false};
    if (!bcg.has_value())
    {
        GetLogger()->error("ECPublicKey::to_bytes failed to create BN_CTX.");
        return {};
    }

    // Get the public key bytes.
    point_to_bytes_ptr_t point_to_bytes = get_point_to_bytes_method(PointToBytesMethod::sec1_compressed);
    if (nullptr == point_to_bytes)
    {
        GetLogger()->error("ECPublicKey::to_bytes failed to get point_to_bytes method.");
        return {};
    }
    std::size_t pk_size = point_to_bytes(group_, pk_.get(), bcg, {});
    std::vector<std::byte> pk_bytes(pk_size);
    if (0 == pk_size || pk_size != point_to_bytes(group_, pk_.get(), bcg, pk_bytes))
    {
        GetLogger()->warning("ECPublicKey::to_bytes failed to convert public key point to bytes.");
        return {};
    }

    const ECVRFParams params = get_ecvrf_params(get_type());

    EVP_PKEY_CTX_Guard pctx{EVP_PKEY_CTX_new_from_name(get_libctx(), params.algorithm_name.data(), get_propquery())};
    if (!pctx.has_value())
    {
        GetLogger()->warning("ECPublicKey::to_bytes failed to create EVP_PKEY_CTX.");
        return {};
    }

    if (1 != EVP_PKEY_fromdata_init(pctx.get()))
    {
        GetLogger()->error("ECPublicKey::to_bytes failed to initialize EVP_PKEY from data.");
        return {};
    }

    // Obtain the short name from the curve NID.
    int nid = curve_to_nid(params.curve);
    const char *curve_sn = OBJ_nid2sn(nid);
    if (nullptr == curve_sn)
    {
        GetLogger()->warning("ECPublicKey::to_bytes failed to get curve short name from NID {}.", nid);
        return {};
    }

    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    OSSL_PARAM pkey_params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char *>(curve_sn), 0),
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY, pk_bytes.data(), pk_bytes.size()), OSSL_PARAM_END};

    EVP_PKEY_Guard pkey{nullptr};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
    if (1 != EVP_PKEY_fromdata(pctx.get(), pkey.free_and_get_addr(), EVP_PKEY_PUBLIC_KEY, pkey_params))
    {
        GetLogger()->warning("ECPublicKey::to_bytes failed to create EVP_PKEY from data.");
        return {};
    }

    std::vector<std::byte> ret = encode_public_key_to_der_spki_with_type(get_type(), pkey.get());
    if (ret.empty())
    {
        GetLogger()->warning("ECPublicKey::to_bytes failed to encode public key to DER SPKI.");
        return {};
    }

    GetLogger()->trace("ECPublicKey::to_bytes serialized public key to DER SPKI byte vector of size {}.", ret.size());
    return ret;
};

void ECPublicKey::from_bytes(std::span<const std::byte> data)
{
    const auto [type, data_without_type] = extract_type_from_span(data);
    GetLogger()->trace("ECPublicKey::from_bytes extracted VRF type {} from input byte vector of size {}.",
                       to_string(type), data.size());

    ECPublicKey public_key{type, data_without_type};
    if (!public_key.is_initialized())
    {
        GetLogger()->warning("ECPublicKey::from_bytes called with invalid public key DER for VRF type {}.",
                             to_string(type));
        return;
    }

    GetLogger()->trace("ECPublicKey::from_bytes initialized ECPublicKey from input byte vector.");
    *this = std::move(public_key);
}

} // namespace vrf::ec
