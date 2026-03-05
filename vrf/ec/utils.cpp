// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "vrf/ec/utils.h"
#include "vrf/common.h"
#include "vrf/ec/params.h"
#include "vrf/guards.h"
#include "vrf/log.h"
#include <limits>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/kdf.h>

namespace vrf::ec
{

namespace
{

std::size_t sec1_point_to_bytes(const EC_GROUP_Guard &group, PointCompression compression, const EC_POINT_Guard &pt,
                                BN_CTX_Guard &bcg, std::span<std::byte> out)
{
    if (!group.has_value() || !pt.has_value())
    {
        GetLogger()->debug("sec1_point_to_bytes called with uninitialized EC_GROUP or EC_POINT.");
        return 0;
    }

    const point_conversion_form_t form = static_cast<point_conversion_form_t>(compression);

    std::size_t buf_size = EC_POINT_point2oct(group.get(), pt.get(), form, nullptr, 0, bcg.get());
    if (0 == buf_size)
    {
        GetLogger()->debug("sec1_point_to_bytes failed to determine EC_POINT size.");
        return 0;
    }

    if (out.empty())
    {
        GetLogger()->trace("sec1_point_to_bytes called with empty output buffer; returning required size {}.",
                           buf_size);
        return buf_size;
    }

    // Require at least buf_size bytes in out.
    if (out.size() < buf_size)
    {
        GetLogger()->debug("sec1_point_to_bytes called with insufficient output buffer size.");
        return 0;
    }

    buf_size = EC_POINT_point2oct(group.get(), pt.get(), form, reinterpret_cast<unsigned char *>(out.data()),
                                  out.size(), bcg.get());
    if (0 == buf_size)
    {
        GetLogger()->debug("sec1_point_to_bytes failed to convert EC_POINT to bytes.");
        return 0;
    }

    GetLogger()->trace("sec1_point_to_bytes converted EC_POINT to bytes with size {}.", buf_size);
    return buf_size;
}

EC_POINT_Guard sec1_bytes_to_point(const EC_GROUP_Guard &group, std::span<const std::byte> in, BN_CTX_Guard &bcg)
{
    if (!group.has_value())
    {
        GetLogger()->debug("sec1_bytes_to_point called with uninitialized EC_GROUP.");
        return {};
    }
    if (in.empty())
    {
        GetLogger()->debug("sec1_bytes_to_point called with empty input data.");
        return {};
    }
    if (!ensure_bcg_set(bcg, false))
    {
        GetLogger()->err("sec1_bytes_to_point failed to obtain BN_CTX.");
        return {};
    }

    EC_POINT_Guard pt{group};
    if (!pt.has_value())
    {
        GetLogger()->debug("Failed to create EC_POINT in sec1_bytes_to_point.");
        return {};
    }

    if (1 != EC_POINT_oct2point(group.get(), pt.get(), reinterpret_cast<const unsigned char *>(in.data()), in.size(),
                                bcg.get()))
    {
        // This happens in normal operation when encoding to a curve.
        GetLogger()->trace("Call to EC_POINT_oct2point failed in sec1_bytes_to_point.");
        return {};
    }

    GetLogger()->trace("sec1_bytes_to_point converted bytes to EC_POINT.");
    return pt;
}

std::vector<std::byte> e2c_salt_from_public_key(Type type, const EC_GROUP_Guard &group, const EC_POINT_Guard &pk,
                                                BN_CTX_Guard &bcg)
{
    // Only check that type and group are matching in terms of the NID. Other inputs are checked
    // by functions called.
    const ECVRFParams params = get_ecvrf_params(type);
    if (params.algorithm_name.empty() || group.get_curve() != params.curve)
    {
        GetLogger()->debug("e2c_salt_from_public_key called with invalid or mismatched EC_GROUP.");
        return {};
    }

    // The salt is just the compressed encoding of the public key.
    std::vector<std::byte> salt(params.pt_len);
    auto [success, _] = append_ecpoint_to_bytes(group, PointToBytesMethod::sec1_compressed, bcg, salt.begin(), pk);

    return success ? salt : std::vector<std::byte>{};
}

EC_POINT_Guard ecvrf_try_and_increment_method(Type type, const EC_GROUP_Guard &group,
                                              std::span<const std::byte> e2c_salt, std::span<const std::byte> data,
                                              BN_CTX_Guard &bcg)
{
    if (!bcg.has_value() || !ensure_bcg_set(bcg, true))
    {
        GetLogger()->err("ecvrf_try_and_increment_method failed to obtain BN_CTX.");
        return {};
    }

    const ECVRFParams params = get_ecvrf_params(type);
    if (params.algorithm_name.empty() || E2CMethod::try_and_increment != params.e2c)
    {
        GetLogger()->debug("ecvrf_try_and_increment_method called with non-TAI VRF type.");
        return {};
    }
    if (!group.has_value() || group.get_curve() != params.curve)
    {
        GetLogger()->debug("ecvrf_try_and_increment_method called with invalid or mismatched EC_GROUP.");
        return {};
    }

    const std::size_t suite_string_len = params.suite_string.size();
    const std::byte domain_separator_front = std::byte{0x01};
    const std::byte domain_separator_back = std::byte{0x00};

    // Check that we are not getting any overflows in the size calculations.
    const std::optional<std::size_t> buf_size = safe_add(
        suite_string_len, std::uint32_t{3} /* 2x domain separator + ctr string*/, e2c_salt.size(), data.size());
    if (!buf_size || !std::in_range<std::ptrdiff_t>(*buf_size))
    {
        GetLogger()->debug("Buffer size overflow in ecvrf_try_and_increment_method.");
        return {};
    }

    std::vector<std::byte> buf(*buf_size);

    const auto suite_string_start = buf.begin();
    const auto domain_separator_front_start = suite_string_start + static_cast<std::ptrdiff_t>(suite_string_len);
    const auto e2c_salt_start = domain_separator_front_start + 1;
    const auto data_start = e2c_salt_start + static_cast<std::ptrdiff_t>(e2c_salt.size());
    const auto ctr_start = data_start + static_cast<std::ptrdiff_t>(data.size());
    const auto domain_separator_back_start = ctr_start + 1 /* ctr */;

    // Copy in everything except the counter value.
    std::ranges::transform(params.suite_string, suite_string_start, [](char c) { return static_cast<std::byte>(c); });
    *domain_separator_front_start = domain_separator_front;
    std::ranges::copy(e2c_salt, e2c_salt_start);
    std::ranges::copy(data, data_start);
    *domain_separator_back_start = domain_separator_back;

    BIGNUM_Guard cofactor{};
    if (1 != params.cofactor)
    {
        cofactor = BIGNUM_Guard{false};
        if (!cofactor.has_value() || 1 != BN_set_word(cofactor.get(), params.cofactor))
        {
            GetLogger()->err("Failed to allocate or set cofactor BIGNUM in ecvrf_try_and_increment_method.");
            return {};
        }
    }

    EC_POINT_Guard pt{};
    bytes_to_point_ptr_t bytes_to_point = get_bytes_to_point_method(params.bytes_to_point);
    if (nullptr == bytes_to_point)
    {
        GetLogger()->err("ecvrf_try_and_increment_method failed to get bytes_to_point method.");
        return {};
    }

    std::uint8_t ctr = 0;
    do
    {
        // Copy in the counter value.
        *ctr_start = static_cast<std::byte>(ctr);

        // Hash buf.
        std::vector<std::byte> hash = compute_hash(params.digest.data(), buf);
        if (hash.empty())
        {
            GetLogger()->debug("Failed to compute {} hash in ecvrf_try_and_increment_method.", params.digest);
            return {};
        }

        hash.insert(hash.begin(), std::byte{0x02}); // Compressed point indicator
        pt = bytes_to_point(group, hash, bcg);
        if (pt.has_value() && 0 == EC_POINT_is_at_infinity(group.get(), pt.get()))
        {
            // If cofactor is not 1, we need to clear it.
            if (1 != params.cofactor)
            {
                if (1 != EC_POINT_mul(group.get(), pt.get(), nullptr, pt.get(), cofactor.get(), bcg.get()))
                {
                    GetLogger()->err("Failed to clear cofactor in ecvrf_try_and_increment_method.");
                    return {};
                }
            }

            GetLogger()->trace("ecvrf_try_and_increment_method found valid point on curve with counter value {}.", ctr);
            return pt; // Success
        }

        ctr++;
    } while (ctr != 0); // Try until counter wraps around.

    GetLogger()->debug("ecvrf_try_and_increment_method failed to find a valid point on the curve.");
    return {}; // Failure
}

std::vector<std::byte> rfc6979_bits2octets(const BIGNUM *modulus, std::span<const std::byte> data, BN_CTX_Guard &bcg)
{
    if (nullptr == modulus || data.empty())
    {
        GetLogger()->debug("rfc6979_bits2octets called with uninitialized modulus or empty data.");
        return {};
    }

    // We check that even if data.size() is multiplied by 8 (to get bit count) it does not overflow int.
    if (data.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()) / 8)
    {
        GetLogger()->debug("rfc6979_bits2octets called with too large data size.");
        return {};
    }

    // This is OK as the above check just passed.
    const int data_len = static_cast<int>(data.size());
    const int data_bitlen = data_len * 8;
    const int mod_bitlen = BN_num_bits(modulus);
    if (mod_bitlen <= 0)
    {
        GetLogger()->debug("Invalid modulus in rfc6979_bits2octets.");
        return {};
    }
    // NOLINTNEXTLINE(readability-redundant-casting)
    const int mod_len = static_cast<int>((static_cast<std::size_t>(mod_bitlen) + 7) / 8);

    // This is by how many bits we need to right-shift if data is longer than mod_bitlen.
    const int shift_bits = data_bitlen - mod_bitlen;

    // Make sure we have a BN_CTX we can use. If not, allocate a secure one just to be safe.
    if (!bcg.has_value() || !ensure_bcg_set(bcg, true))
    {
        GetLogger()->err("rfc6979_bits2octets failed to obtain BN_CTX.");
        return {};
    }

    BN_CTX_start(bcg.get());
    BIGNUM *data_bn = BN_CTX_get(bcg.get());
    if (nullptr == data_bn)
    {
        GetLogger()->err("Failed to allocate temporary BIGNUM in rfc6979_bits2octets.");
        BN_CTX_end(bcg.get());
        return {};
    }

    if (nullptr == BN_bin2bn(reinterpret_cast<const unsigned char *>(data.data()), data_len, data_bn))
    {
        GetLogger()->err("Failed to convert bits to BIGNUM in rfc6979_bits2octets.");
        BN_CTX_end(bcg.get());
        return {};
    }

    // First, if data is longer than mod_bitlen, we need to right-shift it.
    if (0 < shift_bits && 1 != BN_rshift(data_bn, data_bn, shift_bits))
    {
        GetLogger()->err("Failed to right-shift data in rfc6979_bits2octets.");
        BN_CTX_end(bcg.get());
        return {};
    }

    // Now reduce modulo the given modulus. This can be done with a conditional subtraction.
    if (0 <= BN_ucmp(data_bn, modulus) && 1 != BN_sub(data_bn, data_bn, modulus))
    {
        GetLogger()->err("Failed to reduce data mod modulus in rfc6979_bits2octets.");
        BN_CTX_end(bcg.get());
        return {};
    }

    // Finally, allocate a buffer of the right size and convert data_bn to it.
    std::vector<std::byte> out(static_cast<std::size_t>(mod_len));
    if (out.size() != int_to_bytes_big_endian(BIGNUM_Guard{data_bn, false /* owned */}, out))
    {
        GetLogger()->debug("Failed to convert reduced data to bytes in rfc6979_bits2octets.");
        BN_CTX_end(bcg.get());
        return {};
    }

    BN_CTX_end(bcg.get());

    GetLogger()->trace("rfc6979_bits2octets converted data to {} octets.", out.size());
    return out;
}

BIGNUM_Guard rfc6979_nonce_gen(Type type, const EC_GROUP_Guard &group, const BIGNUM_Guard &sk,
                               const std::span<const std::byte> m)
{
    const ECVRFParams params = get_ecvrf_params(type);
    if (params.algorithm_name.empty() || NonceGenMethod::rfc6979 != params.nonce_gen)
    {
        GetLogger()->debug("rfc6979_nonce_gen called with non-RFC6979 VRF type.");
        return {};
    }

    if (!group.has_value() || group.get_curve() != params.curve)
    {
        GetLogger()->debug("rfc6979_nonce_gen called with invalid or mismatched EC_GROUP.");
        return {};
    }

    const BIGNUM *order = EC_GROUP_get0_order(group.get());
    if (nullptr == order)
    {
        GetLogger()->debug("Failed to retrieve group order in rfc6979_nonce_gen.");
        return {};
    }

    const int order_bitlen = BN_num_bits(order);
    if (0 >= order_bitlen)
    {
        GetLogger()->err("Invalid group order in rfc6979_nonce_gen.");
        return {};
    }

    BN_CTX_Guard bcg{true};
    if (!bcg.has_value())
    {
        GetLogger()->err("rfc6979_nonce_gen failed to create BN_CTX.");
        return {};
    }

    EVP_KDF *kdf = EVP_KDF_fetch(get_libctx(), "HMAC-DRBG-KDF", get_propquery());
    if (nullptr == kdf)
    {
        GetLogger()->err("Failed to fetch HMAC-DRBG-KDF in rfc6979_nonce_gen.");
        return {};
    }

    EVP_KDF_CTX *kdf_ctx = EVP_KDF_CTX_new(kdf);
    if (nullptr == kdf_ctx)
    {
        EVP_KDF_free(kdf);
        GetLogger()->err("Failed to create KDF context in rfc6979_nonce_gen.");
        return {};
    }

    // We need the bits2octets conversion of the hash of m.
    const std::vector<std::byte> mhash = compute_hash(params.digest.data(), m);
    std::vector<std::byte> mhash_octets = rfc6979_bits2octets(order, mhash, bcg);
    if (mhash.empty() || mhash_octets.empty())
    {
        EVP_KDF_CTX_free(kdf_ctx);
        EVP_KDF_free(kdf);
        GetLogger()->debug("Failed to compute bits2octets of message hash in rfc6979_nonce_gen.");
        return {};
    }

    // We also need the int2octets conversion of the secret key.
    const int sk_bits = BN_num_bits(sk.get());
    if (0 >= sk_bits)
    {
        EVP_KDF_CTX_free(kdf_ctx);
        EVP_KDF_free(kdf);
        GetLogger()->debug("Invalid secret key in rfc6979_nonce_gen.");
        return {};
    }

    const std::size_t sk_bytes = (static_cast<std::size_t>(sk_bits) + 7) / 8;
    SecureBuf sk_buf{sk_bytes};
    const std::size_t written = int_to_bytes_big_endian(sk, sk_buf);
    if (!sk_buf.has_value() || written != sk_bytes)
    {
        EVP_KDF_CTX_free(kdf_ctx);
        EVP_KDF_free(kdf);
        GetLogger()->debug("Failed to convert secret key to octets in rfc6979_nonce_gen.");
        return {};
    }

    // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,hicpp-avoid-c-arrays,modernize-avoid-c-arrays)
    OSSL_PARAM kdf_params[] = {
        OSSL_PARAM_utf8_string(OSSL_DRBG_PARAM_DIGEST, const_cast<char *>(params.digest.data()), 0),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_HMACDRBG_ENTROPY, sk_buf.get(), sk_bytes),
        OSSL_PARAM_octet_string(OSSL_KDF_PARAM_HMACDRBG_NONCE, mhash_octets.data(), mhash_octets.size()),
        OSSL_PARAM_END};

    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-array-to-pointer-decay,hicpp-no-array-decay)
    if (1 != EVP_KDF_CTX_set_params(kdf_ctx, kdf_params))
    {
        EVP_KDF_CTX_free(kdf_ctx);
        EVP_KDF_free(kdf);
        GetLogger()->debug("Failed to set KDF parameters in rfc6979_nonce_gen.");
        return {};
    }

    const std::size_t nonce_len = (static_cast<std::size_t>(order_bitlen) + 7) / 8;

    SecureBuf nonce_buf{nonce_len};
    BIGNUM_Guard ret{true};
    if (!nonce_buf.has_value() || !ret.has_value())
    {
        EVP_KDF_CTX_free(kdf_ctx);
        EVP_KDF_free(kdf);
        GetLogger()->err("Failed to allocate buffers in rfc6979_nonce_gen.");
        return {};
    }

    // We need to request nonce_len bytes from the KDF and convert to a BIGNUM until
    // we get a value in the range [1, order-1].
    do
    {
        if (1 != EVP_KDF_derive(kdf_ctx, reinterpret_cast<unsigned char *>(nonce_buf.get()), nonce_len, nullptr))
        {
            GetLogger()->err("Failed to derive nonce from KDF in rfc6979_nonce_gen.");
            break;
        }

        BIGNUM_Guard nonce = bytes_to_int_big_endian(nonce_buf, bcg.is_secure());
        if (!nonce.has_value())
        {
            GetLogger()->debug("Failed to convert derived nonce to BIGNUM in rfc6979_nonce_gen.");
            break;
        }

        // Check that 1 <= nonce < order
        if (1 != BN_is_negative(nonce.get()) && 1 != BN_is_zero(nonce.get()) && BN_ucmp(nonce.get(), order) < 0)
        {
            if (!ret.has_value() || nullptr == BN_copy(ret.get(), nonce.get()))
            {
                GetLogger()->err("Failed to copy nonce to return value in rfc6979_nonce_gen.");
                break;
            }

            // Success!
            GetLogger()->trace("rfc6979_nonce_gen generated nonce.");
            break;
        }
    } while (true);

    EVP_KDF_CTX_free(kdf_ctx);
    EVP_KDF_free(kdf);

    return ret;
}

} // namespace

point_to_bytes_ptr_t get_point_to_bytes_method(PointToBytesMethod method)
{
    switch (method)
    {
    case PointToBytesMethod::sec1_uncompressed:
        return +[](const EC_GROUP_Guard &group, const EC_POINT_Guard &pt, BN_CTX_Guard &bcg,
                   std::span<std::byte> out) -> std::size_t {
            return sec1_point_to_bytes(group, PointCompression::uncompressed, pt, bcg, out);
        };
    case PointToBytesMethod::sec1_compressed:
        return +[](const EC_GROUP_Guard &group, const EC_POINT_Guard &pt, BN_CTX_Guard &bcg,
                   std::span<std::byte> out) -> std::size_t {
            return sec1_point_to_bytes(group, PointCompression::compressed, pt, bcg, out);
        };
    default:
        GetLogger()->debug("get_point_to_bytes_method called with unsupported method.");
        return nullptr;
    }
}

bytes_to_point_ptr_t get_bytes_to_point_method(BytesToPointMethod method)
{
    switch (method)
    {
    case BytesToPointMethod::sec1:
        return sec1_bytes_to_point;
    default:
        GetLogger()->debug("get_bytes_to_point_method called with unsupported method.");
        return nullptr;
    }
}

std::size_t do_append_ecpoint_to_bytes(const EC_GROUP_Guard &group, PointToBytesMethod p2b_method, BN_CTX_Guard &bcg,
                                       std::vector<std::byte> &append_to_out, const EC_POINT_Guard &pt)
{
    if (!group.has_value() || !pt.has_value())
    {
        GetLogger()->debug("do_append_ecpoint_to_bytes called with uninitialized EC_GROUP or EC_POINT.");
        return 0;
    }
    if (!ensure_bcg_set(bcg, false))
    {
        GetLogger()->err("do_append_ecpoint_to_bytes failed to obtain BN_CTX.");
        return 0;
    }

    point_to_bytes_ptr_t pt_to_bytes = get_point_to_bytes_method(p2b_method);
    std::size_t buf_size = pt_to_bytes(group, pt, bcg, {});
    if (0 == buf_size)
    {
        GetLogger()->debug("do_append_ecpoint_to_bytes failed to determine EC_POINT size.");
        return 0;
    }

    const std::size_t old_size = append_to_out.size();
    append_to_out.resize(old_size + buf_size);
    buf_size = pt_to_bytes(group, pt, bcg, std::span{append_to_out.data() + old_size, buf_size});
    if (0 == buf_size)
    {
        append_to_out.resize(old_size);
        GetLogger()->debug("do_append_ecpoint_to_bytes failed to convert EC_POINT to bytes.");
        return 0;
    }

    const std::size_t new_size = old_size + buf_size;
    append_to_out.resize(new_size);

    GetLogger()->trace("do_append_ecpoint_to_bytes appended EC_POINT to a byte buffer (size now {} bytes).", new_size);
    return buf_size;
}

e2c_salt_ptr_t get_e2c_salt_method(E2CSaltMethod method)
{
    switch (method)
    {
    case E2CSaltMethod::public_key_compressed:
        return e2c_salt_from_public_key;
    default:
        GetLogger()->debug("get_e2c_salt_method called with unsupported method.");
        return nullptr;
    }
}

e2c_ptr_t get_e2c_method(E2CMethod method)
{
    switch (method)
    {
    case E2CMethod::try_and_increment:
        return ecvrf_try_and_increment_method;
    default:
        GetLogger()->debug("get_e2c_method called with unsupported method.");
        return nullptr;
    }
}

nonce_gen_ptr_t get_nonce_gen_method(NonceGenMethod method)
{
    switch (method)
    {
    case NonceGenMethod::rfc6979:
        return rfc6979_nonce_gen;
    default:
        GetLogger()->debug("get_nonce_gen_method called with unsupported method.");
        return nullptr;
    }
}

} // namespace vrf::ec
