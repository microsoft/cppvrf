// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "vrf/rsa/keys.h"
#include "vrf/common.h"
#include "vrf/guards.h"
#include "vrf/log.h"
#include "vrf/rsa/params.h"
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#include <openssl/params.h>
#include <span>

namespace vrf::rsa
{

namespace
{

bool set_rsa_keygen_params(EVP_PKEY_CTX_Guard &pctx, Type type)
{
    RSAVRFParams params = get_rsavrf_params(type);
    const OSSL_PARAM params_to_set[] = {OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_RSA_BITS, &params.bits),
                                        OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_RSA_PRIMES, &params.primes),
                                        OSSL_PARAM_construct_uint(OSSL_PKEY_PARAM_RSA_E, &params.e), OSSL_PARAM_END};

    return (1 == EVP_PKEY_CTX_set_params(pctx.get(), params_to_set));
}

std::vector<std::byte> generate_mgf1_salt(const EVP_PKEY_Guard &pkey)
{
    // We need OSSL_PKEY_PARAM_RSA_N to generate the salt.
    BIGNUM_Guard n{};
    if (1 != EVP_PKEY_get_bn_param(pkey.get(), OSSL_PKEY_PARAM_RSA_N, n.free_and_get_addr(true)))
    {
        GetLogger()->warn("Failed to retrieve RSA modulus from EVP_PKEY in generate_mgf1_salt.");
        return {};
    }

    // In the salt, first we have a 4-byte big-endian representation of the length of the RSA modulus.
    const std::size_t n_len = static_cast<std::size_t>(BN_num_bytes(n.get()));
    std::vector<std::byte> salt(4 + n_len);
    salt[0] = static_cast<std::byte>((n_len >> 24) & 0xFF);
    salt[1] = static_cast<std::byte>((n_len >> 16) & 0xFF);
    salt[2] = static_cast<std::byte>((n_len >> 8) & 0xFF);
    salt[3] = static_cast<std::byte>(n_len & 0xFF);

    // Next, convert bn_n to a byte array with I2OSP and append to the salt.
    if (n_len != int_to_bytes_big_endian(n, std::span<std::byte>(salt.data() + 4, n_len)))
    {
        GetLogger()->err("Failed to convert RSA modulus to byte array in generate_mgf1_salt.");
        return {};
    }

    GetLogger()->trace("Generated MGF1 salt of size {} for RSA modulus of size {}.", salt.size(), n_len);
    return salt;
}

bool check_rsa_params(Type type, EVP_PKEY_Guard &pkey, bool check_pk, bool check_sk)
{
    if (!is_rsa_type(type) || !pkey.has_value())
    {
        GetLogger()->trace("check_rsa_params called with invalid type {} or uninitialized EVP_PKEY.", to_string(type));
        return false;
    }

    EVP_PKEY_CTX_Guard pctx{EVP_PKEY_CTX_new_from_pkey(get_libctx(), pkey.get(), get_propquery())};
    if (!pctx.has_value() || 1 != EVP_PKEY_param_check(pctx.get()))
    {
        GetLogger()->trace("EVP_PKEY_param_check failed in check_rsa_params; invalid RSA parameters.");
        return false;
    }

    // Retrieve n and check that it has the expected size.
    const RSAVRFParams params = get_rsavrf_params(type);
    BIGNUM_Guard n{};
    if (1 != EVP_PKEY_get_bn_param(pkey.get(), OSSL_PKEY_PARAM_RSA_N, n.free_and_get_addr(true)))
    {
        GetLogger()->debug("Failed to retrieve RSA modulus from EVP_PKEY in check_rsa_params.");
        return false;
    }

    const unsigned bits = static_cast<unsigned>(BN_num_bits(n.get()));
    if (bits != params.bits)
    {
        GetLogger()->trace("RSA modulus size in bits {} does not match expected size {} for VRF type {}.", bits,
                           params.bits, to_string(type));
        return false;
    }

    if (check_pk)
    {
        // Check that the public key is present.
        BIGNUM_Guard e{};
        bool ret = false;
        if (1 == EVP_PKEY_public_check(pctx.get()) &&
            1 == EVP_PKEY_get_bn_param(pkey.get(), OSSL_PKEY_PARAM_RSA_E, e.free_and_get_addr(true)))
        {
            // Public key was retrieved. Check that it matches the expected value.
            BN_ULONG ew = BN_get_word(e.get());
            if (ew != ~static_cast<BN_ULONG>(0))
            {
                // Does the exponent match what we expected?
                ret = (ew == params.e);
            }
        }

        if (!ret)
        {
            GetLogger()->trace("Public key check failed in check_rsa_params; public exponent is missing or "
                               "does not match expected value for VRF type {}.",
                               to_string(type));
            return false;
        }
    }

    // Check that the secret key is present without actually retrieving it.
    if (check_sk)
    {
        if (1 != EVP_PKEY_private_check(pctx.get()))
        {
            GetLogger()->trace("Private key check failed in check_rsa_params; private key is missing or invalid.");
            return false;
        }
    }

    // Finally, if both keys are checked, verify that their relationship is valid.
    if (check_pk && check_sk)
    {
        if (1 != EVP_PKEY_pairwise_check(pctx.get()))
        {
            GetLogger()->trace("Pairwise check failed in check_rsa_params; public and private key parameters do not "
                               "match or are invalid.");
            return false;
        }
    }

    GetLogger()->trace("RSA parameters check passed for VRF type {}.", to_string(type));
    return true;
}

} // namespace

RSA_SK_Guard &RSA_SK_Guard::operator=(RSA_SK_Guard &&rhs) noexcept
{
    if (this != &rhs)
    {
        using std::swap;
        swap(type_, rhs.type_);
        swap(pkey_, rhs.pkey_);
    }
    return *this;
}

EVP_PKEY_Guard RSA_SK_Guard::GenerateRSAKey(Type type)
{
    if (!is_rsa_type(type))
    {
        GetLogger()->debug("generate_rsa_key called with non-RSA VRF type {}.", to_string(type));
        return {};
    }

    const RSAVRFParams params = get_rsavrf_params(type);
    EVP_PKEY_CTX_Guard pctx{EVP_PKEY_CTX_new_from_name(get_libctx(), params.algorithm_name.data(), get_propquery())};
    if (!pctx.has_value())
    {
        GetLogger()->err("Failed to create EVP_PKEY_CTX in GenerateRSAKey.");
        return {};
    }

    if (0 >= EVP_PKEY_keygen_init(pctx.get()))
    {
        GetLogger()->err("Failed to initialize RSA key generation; EVP_PKEY_keygen_init failed in GenerateRSAKey.");
        return {};
    }

    if (!set_rsa_keygen_params(pctx, type))
    {
        GetLogger()->err(
            "Failed to set RSA key generation parameters; set_rsa_keygen_params failed  in GenerateRSAKey.");
        return {};
    }

    EVP_PKEY_Guard pkey{};
    if (1 != EVP_PKEY_generate(pctx.get(), pkey.free_and_get_addr()))
    {
        GetLogger()->err("Failed to generate RSA key pair; EVP_PKEY_generate failed in GenerateRSAKey.");
        return {};
    }

    GetLogger()->trace("Generated RSA key pair (address {:p}) for VRF type {}.", static_cast<const void *>(pkey.get()),
                       to_string(type));
    return pkey;
}

RSA_SK_Guard::RSA_SK_Guard(Type type) : type_{Type::UNKNOWN}, pkey_{nullptr}
{
    EVP_PKEY_Guard pkey{GenerateRSAKey(type)};
    if (!pkey.has_value())
    {
        GetLogger()->debug("RSA_PKEY_Guard constructor failed to generate RSA key.");
    }
    else
    {
        type_ = type;
        pkey_ = std::move(pkey);
        GetLogger()->trace("RSA_SK_Guard initialized with generated key for VRF type {}.", to_string(type));
    }
}

RSA_SK_Guard::RSA_SK_Guard(Type type, std::span<const std::byte> der_pkcs8) : type_{Type::UNKNOWN}, pkey_{nullptr}
{
    if (!is_rsa_type(type))
    {
        GetLogger()->debug("RSA_SK_Guard constructor called with non-RSA VRF type {}.", to_string(type));
        return;
    }

    const RSAVRFParams params = get_rsavrf_params(type);

    EVP_PKEY_Guard pkey{decode_secret_key_from_der_pkcs8(params.algorithm_name.data(), der_pkcs8)};
    if (!pkey.has_value())
    {
        GetLogger()->debug("RSA_SK_Guard constructor failed to load EVP_PKEY from provided DER PKCS#8.");
        return;
    }

    if (!check_rsa_params(type, pkey, true /* check_pk */, true /* check_sk */))
    {
        GetLogger()->debug(
            "RSA_SK_Guard constructor found mismatched or invalid RSA parameters in provided DER PKCS#8.");
        return;
    }

    pkey_ = std::move(pkey);
    type_ = type;
    GetLogger()->trace("RSA_SK_Guard initialized with loaded key from DER PKCS#8 for VRF type {}.", to_string(type));
}

RSA_SK_Guard RSA_SK_Guard::clone() const
{
    RSA_SK_Guard ret{type_, pkey_.clone()};
    if (!ret.has_value())
    {
        GetLogger()->debug("RSA_SK_Guard::clone failed to clone the RSA secret key.");
    }

    GetLogger()->trace("RSA_SK_Guard::clone successfully cloned RSA secret key for VRF type {}.", to_string(type_));
    return ret;
}

std::vector<std::byte> RSA_SK_Guard::get_mgf1_salt() const
{
    if (!pkey_.has_value())
    {
        GetLogger()->debug("get_mgf1_salt called on uninitialized RSA_SK_Guard.");
        return {};
    }

    return generate_mgf1_salt(pkey_);
}

RSA_PK_Guard &RSA_PK_Guard::operator=(RSA_PK_Guard &&rhs) noexcept
{
    if (this != &rhs)
    {
        using std::swap;
        swap(type_, rhs.type_);
        swap(pkey_, rhs.pkey_);
    }
    return *this;
}

RSA_PK_Guard::RSA_PK_Guard(const RSA_SK_Guard &sk_guard) : type_{Type::UNKNOWN}, pkey_{}
{
    if (!sk_guard.has_value())
    {
        GetLogger()->debug("RSA_PK_Guard constructor called with uninitialized RSA_SK_Guard.");
        return;
    }

    const std::vector<std::byte> der_spki_with_type =
        encode_public_key_to_der_spki_with_type(sk_guard.get_type(), sk_guard.get());
    if (der_spki_with_type.empty())
    {
        GetLogger()->debug("RSA_PK_Guard constructor failed to encode public key from RSA_SK_Guard.");
        return;
    }

    // Use the DER SPKI constructor to initialize the public key guard.
    RSA_PK_Guard pk_guard{der_spki_with_type};
    if (!pk_guard.has_value())
    {
        GetLogger()->debug("RSA_PK_Guard constructor failed to initialize from DER SPKI encoded public key.");
        return;
    }

    // Everything OK. Move the data.
    type_ = pk_guard.type_;
    pkey_ = std::move(pk_guard.pkey_);
    GetLogger()->trace("RSA_PK_Guard successfully initialized from RSA_SK_Guard for VRF type {}.", to_string(type_));
}

RSA_PK_Guard::RSA_PK_Guard(std::span<const std::byte> der_spki_with_type) : type_(Type::UNKNOWN), pkey_(nullptr)
{
    const auto [type, der_spki] = extract_type_from_span(der_spki_with_type);
    GetLogger()->trace("RSA_PK_Guard constructor extracted VRF type {} from input byte vector of size {}.",
                       to_string(type), der_spki_with_type.size());

    const RSAVRFParams params = get_rsavrf_params(type);
    EVP_PKEY_Guard pkey{decode_public_key_from_der_spki(params.algorithm_name.data(), der_spki)};
    if (!pkey.has_value())
    {
        GetLogger()->debug("RSA_PK_Guard constructor failed to load EVP_PKEY from provided DER SPKI.");
        return;
    }

    // We need to still check that the loaded public key matches the expected parameters.
    if (!check_rsa_params(type, pkey, true /* check_pk */, false /* check_sk */))
    {
        GetLogger()->debug("RSA_PK_Guard constructor found mismatched or invalid RSA parameters in provided DER SPKI.");
        return;
    }

    // Everything OK. Store the pkey and set the type.
    pkey_ = std::move(pkey);
    type_ = type;
    GetLogger()->trace("RSA_PK_Guard successfully initialized from DER SPKI for VRF type {}.", to_string(type_));
}

RSA_PK_Guard RSA_PK_Guard::clone() const
{
    RSA_PK_Guard ret{type_, pkey_.clone()};
    if (!ret.has_value())
    {
        GetLogger()->debug("RSA_PK_Guard::clone failed to clone the RSA public key.");
    }

    GetLogger()->trace("RSA_PK_Guard::clone successfully cloned RSA public key for VRF type {}.", to_string(type_));
    return ret;
}

std::vector<std::byte> RSA_PK_Guard::get_mgf1_salt() const
{
    if (!pkey_.has_value())
    {
        GetLogger()->debug("get_mgf1_salt called on uninitialized RSA_PK_Guard.");
        return {};
    }

    return generate_mgf1_salt(pkey_);
}

} // namespace vrf::rsa
