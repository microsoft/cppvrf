// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "vrf/rsa/rsavrf.h"
#include "vrf/common.h"
#include "vrf/guards.h"
#include "vrf/log.h"
#include "vrf/rsa/params.h"
#include <algorithm>
#include <cstdint>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rsa.h>

namespace vrf::rsa
{

namespace
{

/**
 * Verifies that the byte sequence `test` represents a non-negative integer
 * that is less than the RSA modulus `n` contained in the provided `pkey`.
 *
 * Logs an error (and returns false) if any of the following conditions are met:
 *   - `test` is empty.
 *   - `guard` does not hold a valid RSA public or secret key.
 *   - The length of `test` does not match the RSA modulus size.
 *   - The modulus `n` cannot be retrieved from the `pkey`.
 *   - The byte sequence `test` cannot be converted to a BIGNUM.
 */
template <RSAGuard T> bool check_bytes_in_modulus_range(std::span<const std::byte> test, const T &guard)
{
    if (test.empty())
    {
        GetLogger()->trace("Test input is empty in check_bytes_in_modulus_range.");
        return false;
    }
    if (!guard.has_value())
    {
        GetLogger()->debug("Guard object is uninitialized in check_bytes_in_modulus_range.");
        return false;
    }

    const RSAVRFParams params = get_rsavrf_params(guard.get_type());
    const std::size_t n_len = (params.bits + 7) / 8;
    if (n_len != test.size())
    {
        GetLogger()->trace("Test input in check_bytes_in_modulus_range has incorrect size {}; required size {}.",
                           test.size(), n_len);
        return false;
    }

    BIGNUM_Guard n{};
    const EVP_PKEY *pkey = guard.get();
    if (1 != EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, n.free_and_get_addr(true)))
    {
        GetLogger()->debug("Failed to retrieve RSA modulus from EVP_PKEY for range check.");
        return false;
    }

    const BIGNUM_Guard bn_test = bytes_to_int_big_endian(test, true /* secure */);
    if (!bn_test.has_value())
    {
        GetLogger()->debug("Failed to convert test input to BIGNUM for range check.");
        return false;
    }

    // Test condition: 0 <= bn_test < n
    return !BN_is_negative(bn_test.get()) && BN_ucmp(n.get(), bn_test.get()) > 0;
}

/**
 * Computes the RSA verification primitive on the provided signature using the given
 * RSA public key. The signature must be the same length as the RSA modulus and must
 * represent a non-negative integer less than the modulus.
 *
 * Logs an error (and returns an empty vector) if any of the following conditions are met:
 *   - `signature` or `pk_guard` are out of range or invalid.
 *   - Any of the OpenSSL verification operations failed.
 */
std::vector<std::byte> rsa_verification_primitive(std::span<const std::byte> signature, RSA_PK_Guard &pk_guard)
{
    if (!check_bytes_in_modulus_range(signature, pk_guard))
    {
        GetLogger()->debug("Inputs to rsa_verification_primitive are out of range or invalid.");
        return {};
    }

    const RSAVRFParams params = get_rsavrf_params(pk_guard.get_type());
    if (RSA_NO_PADDING != params.pad_mode)
    {
        GetLogger()->debug("rsa_verification_primitive called with non-raw RSA VRF type {}.",
                           to_string(pk_guard.get_type()));
        return {};
    }

    EVP_PKEY *pkey = pk_guard.get();
    EVP_PKEY_CTX_Guard pctx{EVP_PKEY_CTX_new_from_pkey(get_libctx(), pkey, get_propquery())};
    if (!pctx.has_value())
    {
        GetLogger()->err("Failed to create EVP_PKEY_CTX in rsa_verification_primitive.");
        return {};
    }

    if (0 >= EVP_PKEY_encrypt_init(pctx.get()) || 0 >= EVP_PKEY_CTX_set_rsa_padding(pctx.get(), params.pad_mode))
    {
        GetLogger()->err("Failed to initialize RSA verification primitive in rsa_verification_primitive; "
                         "EVP_PKEY_encrypt_init failed.");
        return {};
    }

    std::size_t m_len = 0;
    if (0 >= EVP_PKEY_encrypt(pctx.get(), nullptr, &m_len, reinterpret_cast<const unsigned char *>(signature.data()),
                              signature.size()))
    {
        GetLogger()->err("Failed to determine output length in rsa_verification_primitive.");
        return {};
    }

    std::vector<std::byte> message(m_len);
    if (0 >= EVP_PKEY_encrypt(pctx.get(), reinterpret_cast<unsigned char *>(message.data()), &m_len,
                              reinterpret_cast<const unsigned char *>(signature.data()), signature.size()))
    {
        GetLogger()->err("Failed to perform RSA verification primitive in rsa_verification_primitive; "
                         "EVP_PKEY_encrypt failed.");
        return {};
    }

    // Resize the message to the actual size.
    message.resize(m_len);

    GetLogger()->trace("rsa_verification_primitive computed message of size {} from signature of size {}.",
                       message.size(), signature.size());
    return message;
}

/**
 * Computes a raw RSA signature on the provided data using the given RSA secret key.
 * The data to be signed must be the same length as the RSA modulus and must represent
 * a non-negative integer less than the modulus.
 *
 * Logs an error (and returns an empty vector) if any of the following conditions are met:
 *   - `tbs` or `sk_guard` are out of range or invalid.
 *   - Any of the OpenSSL signature operations failed.
 */
std::vector<std::byte> rsa_signing_primitive(std::span<const std::byte> tbs, RSA_SK_Guard &sk_guard,
                                             RSA_PK_Guard &pk_guard)
{
    if (!check_bytes_in_modulus_range(tbs, sk_guard))
    {
        GetLogger()->debug("Inputs to rsa_signing_primitive are out of range or invalid.");
        return {};
    }

    const RSAVRFParams params = get_rsavrf_params(sk_guard.get_type());
    if (RSA_NO_PADDING != params.pad_mode)
    {
        GetLogger()->debug("rsa_signing_primitive called with non-raw RSA VRF type {}.",
                           to_string(sk_guard.get_type()));
        return {};
    }

    // Create the signing context for raw RSA (no padding).
    EVP_PKEY *pkey = sk_guard.get();
    EVP_PKEY_CTX_Guard pctx{EVP_PKEY_CTX_new_from_pkey(get_libctx(), pkey, get_propquery())};
    if (1 != EVP_PKEY_sign_init(pctx.get()))
    {
        GetLogger()->err("Failed to initialize signing context for raw RSA in rsa_signing_primitive; "
                         "EVP_PKEY_sign_init failed.");
        return {};
    }

    if (0 >= EVP_PKEY_CTX_set_rsa_padding(pctx.get(), params.pad_mode))
    {
        GetLogger()->err("Failed to configure RSA (no padding) for signing in rsa_signing_primitive.");
        return {};
    }

    // Determine the length of the required signature buffer.
    std::size_t siglen = 0;
    if (0 >=
        EVP_PKEY_sign(pctx.get(), nullptr, &siglen, reinterpret_cast<const unsigned char *>(tbs.data()), tbs.size()))
    {
        GetLogger()->err(
            "Failed to determine signature length for raw RSA in rsa_signing_primitive; EVP_PKEY_sign failed.");
        return {};
    }

    // Actually sign.
    std::vector<std::byte> signature(siglen);
    if (0 >= EVP_PKEY_sign(pctx.get(), reinterpret_cast<unsigned char *>(signature.data()), &siglen,
                           reinterpret_cast<const unsigned char *>(tbs.data()), tbs.size()))
    {
        GetLogger()->err("Failed to generate raw RSA signature in rsa_signing_primitive; EVP_PKEY_sign failed.");
        return {};
    }

    // Resize the signature to the actual size.
    signature.resize(siglen);

    // Verify that the signature was computed correctly. This is standard practice for RSA signatures.
    const std::vector<std::byte> verified_message = rsa_verification_primitive(signature, pk_guard);
    if (!std::ranges::equal(verified_message, tbs))
    {
        GetLogger()->err("rsa_signing_primitive produced an invalid signature.");
        return {};
    }

    GetLogger()->trace("rsa_signing_primitive generated signature of size {} from message of size {}.",
                       signature.size(), tbs.size());
    return signature;
}

/**
 * Performs RSA-PSS verification with zero-length salt on the provided signature and data using
 * the given RSA public key. The data to be verified can be of any length.
 *
 * Logs an error (and returns false) if any of the following conditions are met:
 *   - `signature`, `tbs`, or `pk_guard` are out of range or invalid.
 *   - The VRF type in `pk_guard` is not an RSA-PSS type.
 *   - Any of the OpenSSL operations failed.
 */
bool rsa_pss_nosalt_verify(std::span<const std::byte> signature, std::span<const std::byte> tbs, RSA_PK_Guard &pk_guard)
{
    if (!check_bytes_in_modulus_range(signature, pk_guard))
    {
        GetLogger()->debug("Inputs to rsa_pss_nosalt_verify are out of range or invalid.");
        return false;
    }
    if (tbs.empty())
    {
        GetLogger()->debug("rsa_pss_nosalt_sign called with empty data to sign.");
        return {};
    }

    const Type type = pk_guard.get_type();
    const RSAVRFParams params = get_rsavrf_params(type);
    if (RSA_PKCS1_PSS_PADDING != params.pad_mode)
    {
        GetLogger()->debug("rsa_pss_nosalt_verify called with non-PSS RSA VRF type {}.", to_string(type));
        return {};
    }

    MD_CTX_Guard mctx{true /* oneshot only */};
    if (!mctx.has_value())
    {
        GetLogger()->err("Failed to get EVP_MD_CTX.");
        return false;
    }

    // Create the verification context.
    EVP_PKEY *pkey = pk_guard.get();
    EVP_PKEY_CTX *pctx = nullptr;
    if (1 !=
        EVP_DigestVerifyInit_ex(mctx.get(), &pctx, params.digest.data(), get_libctx(), get_propquery(), pkey, nullptr))
    {
        GetLogger()->err("Failed to initialize verification context for RSA-PSS in rsa_pss_nosalt_verify; "
                         "EVP_DigestVerifyInit_ex failed.");
        return false;
    }

    // Configure the PSS padding. We set the salt length to 0. This is necessary for the VRF
    // since we need the signature to be deterministic (but unpredictable).
    if (0 >= EVP_PKEY_CTX_set_rsa_padding(pctx, params.pad_mode) || 0 >= EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 0))
    {
        GetLogger()->err("Failed to configure RSA-PSS padding for verification in rsa_pss_nosalt_verify.");
        return false;
    }

    // We don't need to call EVP_PKEY_CTX_set_rsa_mgf1_md because it defaults to the same digest
    // as the signature digest.

    // One-shot digest-verify.
    return EVP_DigestVerify(mctx.get(), reinterpret_cast<const unsigned char *>(signature.data()), signature.size(),
                            reinterpret_cast<const unsigned char *>(tbs.data()), tbs.size());
}

/**
 * Performs RSA-PSS signing with zero-length salt on the provided data using the given RSA secret key.
 * The data to be signed can be of any length.
 *
 * Logs an error (and returns an empty vector) if any of the following conditions are met:
 *   - `tbs` is empty or `sk_guard` is invalid.
 *   - The VRF type in `sk_guard` is not an RSA-PSS type.
 *   - Any of the OpenSSL operations failed.
 */
std::vector<std::byte> rsa_pss_nosalt_sign(std::span<const std::byte> tbs, RSA_SK_Guard &sk_guard,
                                           RSA_PK_Guard &pk_guard)
{
    if (!sk_guard.has_value())
    {
        GetLogger()->debug("rsa_pss_nosalt_sign called with invalid RSA secret key.");
        return {};
    }
    if (tbs.empty())
    {
        GetLogger()->debug("rsa_pss_nosalt_sign called with empty data to sign.");
        return {};
    }

    const Type type = sk_guard.get_type();
    const RSAVRFParams params = get_rsavrf_params(type);
    if (RSA_PKCS1_PSS_PADDING != params.pad_mode)
    {
        GetLogger()->debug("rsa_pss_nosalt_sign called with non-PSS RSA VRF type {}.", to_string(type));
        return {};
    }

    MD_CTX_Guard mctx{true /* oneshot only */};
    if (!mctx.has_value())
    {
        GetLogger()->err("Failed to get EVP_MD_CTX.");
        return {};
    }

    // Create the signing context. Note that `pctx` does *not* need to be freed manually, as mctx will own it.
    EVP_PKEY *pkey = sk_guard.get();
    EVP_PKEY_CTX *pctx = nullptr;
    if (1 !=
        EVP_DigestSignInit_ex(mctx.get(), &pctx, params.digest.data(), get_libctx(), get_propquery(), pkey, nullptr))
    {
        GetLogger()->err("Failed to initialize signing context for RSA-PSS in rsa_pss_nosalt_sign; "
                         "EVP_DigestSignInit_ex failed.");
        return {};
    }

    // Configure the PSS padding. We set the salt length to 0. This is necessary for the VRF
    // since we need the signature to be deterministic (but unpredictable).
    if (0 >= EVP_PKEY_CTX_set_rsa_padding(pctx, params.pad_mode) || 0 >= EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, 0))
    {
        GetLogger()->err("Failed to configure PSS padding for signing in rsa_pss_nosalt_sign.");
        return {};
    }

    // We don't need to call EVP_PKEY_CTX_set_rsa_mgf1_md because it defaults to the same digest
    // as the signature digest.

    // One-shot digest-sign. Get the signature length first.
    std::size_t siglen = 0;
    if (0 >=
        EVP_DigestSign(mctx.get(), nullptr, &siglen, reinterpret_cast<const unsigned char *>(tbs.data()), tbs.size()))
    {
        GetLogger()->err(
            "Failed to determine signature length for RSA-PSS in rsa_pss_nosalt_sign; EVP_DigestSign failed.");
        return {};
    }

    std::vector<std::byte> signature(siglen);
    if (0 >= EVP_DigestSign(mctx.get(), reinterpret_cast<unsigned char *>(signature.data()), &siglen,
                            reinterpret_cast<const unsigned char *>(tbs.data()), tbs.size()))
    {
        GetLogger()->err("Failed to generate RSA-PSS signature in rsa_pss_nosalt_sign; EVP_DigestSign failed.");
        return {};
    }

    // Resize the signature to the actual size.
    signature.resize(siglen);

    // Verify that the signature was computed correctly. This is standard practice for RSA signatures.
    if (!rsa_pss_nosalt_verify(signature, tbs, pk_guard))
    {
        GetLogger()->err("rsa_pss_nosalt_sign produced an invalid signature.");
        return {};
    }

    GetLogger()->trace("rsa_pss_nosalt_sign generated signature of size {} from message of size {}.", signature.size(),
                       tbs.size());
    return signature;
}

bool mgf1(std::span<std::byte> mask, std::span<const std::byte> seed, const EVP_MD *dgst)
{
    if (mask.empty() || nullptr == dgst)
    {
        GetLogger()->debug("mgf1 called with empty mask or null digest.");
        return false;
    }

    // If the mask is too large, we cannot generate it.
    if (!std::in_range<std::ptrdiff_t>(mask.size()))
    {
        GetLogger()->debug("Requested MGF1 mask size is too large: {} bytes.", mask.size());
        return false;
    }

    const std::size_t len = mask.size();
    const std::size_t seedlen = seed.size();
    std::size_t outlen = 0;

    std::array<std::byte, 4> ctr{};
    std::array<std::byte, EVP_MAX_MD_SIZE> md{};

    MD_CTX_Guard mctx{false /* oneshot only */};
    if (!mctx.has_value())
    {
        GetLogger()->err("Failed to get EVP_MD_CTX for MGF1.");
        return false;
    }

    const int mdlen = EVP_MD_get_size(dgst);
    if (mdlen <= 0)
    {
        GetLogger()->err("Invalid digest size for MGF1.");
        return false;
    }
    const std::size_t mdlen_sz = static_cast<std::size_t>(mdlen);

    for (std::uint32_t i = 0; outlen < len; i++)
    {
        // Set the counter value for this iteration.
        ctr[0] = static_cast<std::byte>((i >> 24U) & 0xFFU);
        ctr[1] = static_cast<std::byte>((i >> 16U) & 0xFFU);
        ctr[2] = static_cast<std::byte>((i >> 8U) & 0xFFU);
        ctr[3] = static_cast<std::byte>(i & 0xFFU);

        if (!EVP_DigestInit_ex(mctx.get(), dgst, nullptr) || !EVP_DigestUpdate(mctx.get(), seed.data(), seedlen) ||
            !EVP_DigestUpdate(mctx.get(), ctr.data(), ctr.size()))
        {
            GetLogger()->err("Failed to compute MGF1 digest; EVP_Digest* operations failed.");
            return false;
        }

        if (outlen + mdlen_sz <= len)
        {
            if (!EVP_DigestFinal_ex(mctx.get(), reinterpret_cast<unsigned char *>(mask.data()) + outlen, nullptr))
            {
                GetLogger()->err("Failed to finalize MGF1 digest; EVP_DigestFinal_ex failed.");
                return false;
            }
            outlen += mdlen_sz;
        }
        else
        {
            // len - outlen > mdlen_sz
            if (!EVP_DigestFinal_ex(mctx.get(), reinterpret_cast<unsigned char *>(md.data()), nullptr))
            {
                GetLogger()->err("Failed to finalize MGF1 digest; EVP_DigestFinal_ex failed.");
                return false;
            }

            std::copy_n(md.begin(), len - outlen, mask.begin() + static_cast<std::ptrdiff_t>(outlen));
            outlen = len;
        }
    }

    GetLogger()->trace("MGF1 generated mask of size {} from seed of size {}.", mask.size(), seed.size());
    return true;
}

std::vector<std::byte> construct_rsa_fdh_tbs(Type type, std::span<const std::byte> mgf1_salt,
                                             std::span<const std::byte> data)
{
    // We need to evaluate the MGF1 function on suite_string || 0x01 || mgf1_salt || data.
    // The output must have length k-1, where k is the length in bytes of the RSA modulus.

    if (!is_rsa_type(type))
    {
        GetLogger()->debug("construct_rsa_fdh_tbs called with non-RSA VRF type {}.", to_string(type));
        return {};
    }

    const RSAVRFParams params = get_rsavrf_params(type);
    if (RSA_NO_PADDING != params.pad_mode)
    {
        GetLogger()->debug("construct_rsa_fdh_tbs called with non-FDH RSA VRF type {}.", to_string(type));
        return {};
    }

    const std::byte domain_separator = std::byte{0x01};

    const std::size_t suite_string_len = params.suite_string.size();
    const std::size_t n_len = (params.bits + 7) / 8;
    const std::optional<std::size_t> tbs_len =
        safe_add(suite_string_len, 1U /* domain separator */, mgf1_salt.size(), data.size());

    // Set up the seed for MGF1,
    if (!tbs_len.has_value() || !std::in_range<std::ptrdiff_t>(*tbs_len))
    {
        GetLogger()->debug("construct_rsa_fdh_tbs computed TBS length ({}) is invalid or too large.",
                           tbs_len.has_value() ? std::to_string(*tbs_len) : "n/a");
        return {};
    }

    std::vector<std::byte> tbs(*tbs_len);

    const auto suite_string_start = tbs.begin();
    const auto domain_separator_pos = suite_string_start + static_cast<std::ptrdiff_t>(suite_string_len);
    const auto mgf1_salt_start = domain_separator_pos + 1;
    const auto data_start = mgf1_salt_start + static_cast<std::ptrdiff_t>(mgf1_salt.size());

    std::ranges::transform(params.suite_string, suite_string_start,
                           [](char c) { return static_cast<std::byte>(c); });
    *domain_separator_pos = domain_separator;
    std::ranges::copy(mgf1_salt, mgf1_salt_start);
    std::ranges::copy(data, data_start);

    // Evaluate MGF1. The output *must* have size `n_len` bytes. Otherwise, raw RSA signing will fail.
    std::vector<std::byte> ret(n_len);
    const EVP_MD *md = EVP_MD_fetch(get_libctx(), params.digest.data(), get_propquery());
    if (nullptr == md)
    {
        GetLogger()->err("Failed to get EVP_MD for VRF type {}.", to_string(type));
        return {};
    }

    // We will only output n_len - 1 bytes of mask, leaving the first byte of ret to zero, as ret will be
    // read as a big-endian integer by the raw RSA signing primitive. Note that all bytes of ret are zero
    // at this point.
    const std::span<std::byte> mask_span{ret.begin() + 1, n_len - 1};
    if (!mgf1(mask_span, tbs, md))
    {
        GetLogger()->trace("Failed to compute MGF1 output for in a call to construct_rsa_fdh_tbs.");
        return {};
    }

    GetLogger()->trace("construct_rsa_fdh_tbs constructed TBS of size {} and MGF1 output of size {} for VRF type {}.",
                       tbs.size(), mask_span.size(), to_string(type));
    return ret;
}

std::vector<std::byte> construct_rsa_pss_tbs(Type type, std::span<const std::byte> mgf1_salt,
                                             std::span<const std::byte> data)
{
    if (!is_rsa_type(type))
    {
        GetLogger()->debug("construct_rsa_pss_tbs called with non-RSA VRF type {}.", to_string(type));
        return {};
    }

    const RSAVRFParams params = get_rsavrf_params(type);
    if (RSA_PKCS1_PSS_PADDING != params.pad_mode)
    {
        GetLogger()->debug("construct_rsa_pss_tbs called with non-PSS RSA VRF type {}.", to_string(type));
        return {};
    }

    const std::byte domain_separator = std::byte{0x01};

    const std::size_t suite_string_len = params.suite_string.size();
    const std::optional<std::size_t> tbs_len =
        safe_add(suite_string_len, 1U /* domain separator */, mgf1_salt.size(), data.size());
    if (!tbs_len.has_value() || !std::in_range<std::ptrdiff_t>(*tbs_len))
    {
        GetLogger()->debug("construct_rsa_pss_tbs computed TBS length ({}) is invalid or too large.",
                           tbs_len.has_value() ? std::to_string(*tbs_len) : "n/a");
        return {};
    }

    std::vector<std::byte> tbs(*tbs_len);

    const auto suite_string_start = tbs.begin();
    const auto domain_separator_start = suite_string_start + static_cast<std::ptrdiff_t>(suite_string_len);
    const auto mgf1_salt_start = domain_separator_start + 1;
    const auto data_start = mgf1_salt_start + static_cast<std::ptrdiff_t>(mgf1_salt.size());

    std::ranges::transform(params.suite_string, suite_string_start,
                           [](char c) { return static_cast<std::byte>(c); });
    *domain_separator_start = domain_separator;
    std::ranges::copy(mgf1_salt, mgf1_salt_start);
    std::ranges::copy(data, data_start);

    GetLogger()->trace(
        "construct_rsa_pss_tbs constructed TBS of size {} for RSA-PSS VRF type {} (suite string length {}, "
        "MGF1 salt length {}, data length {}).",
        tbs.size(), to_string(type), suite_string_len, mgf1_salt.size(), data.size());
    return tbs;
}

} // namespace

std::vector<std::byte> RSAProof::to_bytes() const
{
    if (!is_initialized())
    {
        GetLogger()->warn("RSAProof::to_bytes called on uninitialized proof.");
        return {};
    }

    const std::byte type_byte = as_byte(get_type());
    std::vector<std::byte> ret;
    ret.reserve(1 + proof_.size());
    ret.push_back(type_byte);
    ret.insert(ret.end(), proof_.begin(), proof_.end());

    GetLogger()->trace("RSAProof::to_bytes serialized proof of size {} to byte vector of size {}.", proof_.size(),
                       ret.size());
    return ret;
}

void RSAProof::from_bytes(std::span<const std::byte> data)
{
    const auto [type, data_without_type] = extract_type_from_span(data);
    GetLogger()->trace("RSAProof::from_bytes extracted VRF type {} from input byte vector of size {}.", to_string(type),
                       data.size());

    RSAProof rsa_proof{type, std::vector<std::byte>(data_without_type.begin(), data_without_type.end())};
    if (!rsa_proof.is_initialized())
    {
        GetLogger()->warn("RSAProof::from_bytes called with invalid proof data for VRF type {}.", to_string(type));
        return;
    }

    GetLogger()->trace("RSAProof::from_bytes initialized RSAProof from input byte vector.");
    *this = std::move(rsa_proof);
}

RSAProof::RSAProof(const RSAProof &source) = default;

RSAProof &RSAProof::operator=(RSAProof &&rhs) noexcept
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

std::vector<std::byte> RSAProof::get_vrf_value() const
{
    if (!is_initialized())
    {
        GetLogger()->warn("RSAProof::get_vrf_value called on an incorrectly initialized proof.");
        return {};
    }

    const Type type = get_type();
    const RSAVRFParams params = get_rsavrf_params(type);

    const std::byte domain_separator = std::byte{0x02};

    const std::size_t suite_string_len = params.suite_string.size();
    const std::optional<std::size_t> tbh_len = safe_add(suite_string_len, 1U /* domain separator */, proof_.size());

    if (!tbh_len.has_value() || !std::in_range<std::ptrdiff_t>(*tbh_len))
    {
        GetLogger()->warn("RSAProof::get_vrf_value computed TBH length ({}) is invalid or too large.",
                          tbh_len.has_value() ? std::to_string(*tbh_len) : "n/a");
        return {};
    }

    std::vector<std::byte> tbh(*tbh_len);

    const auto suite_string_start = tbh.begin();
    const auto domain_separator_pos = suite_string_start + static_cast<std::ptrdiff_t>(suite_string_len);
    const auto proof_start = domain_separator_pos + 1;

    std::ranges::transform(params.suite_string, suite_string_start,
                           [](char c) { return static_cast<std::byte>(c); });
    *domain_separator_pos = domain_separator;
    std::ranges::copy(proof_, proof_start);

    GetLogger()->trace("RSAProof::get_vrf_value constructed TBH of size {} for VRF type {} (suite string length {}, "
                       "proof length {}).",
                       tbh.size(), to_string(type), suite_string_len, proof_.size());
    return compute_hash(params.digest.data(), tbh);
}

std::unique_ptr<Proof> RSASecretKey::get_vrf_proof(std::span<const std::byte> in)
{
    if (!is_initialized())
    {
        GetLogger()->warn("RSASecretKey::get_vrf_proof called on invalid RSASecretKey.");
        return nullptr;
    }

    const Type type = get_type();
    const RSAVRFParams params = get_rsavrf_params(type);
    if (params.algorithm_name.empty())
    {
        GetLogger()->warn("RSASecretKey::get_vrf_proof called with non-RSA VRF type {}.", to_string(type));
        return nullptr;
    }

    std::unique_ptr<Proof> ret = nullptr;
    switch (params.pad_mode)
    {
    case RSA_NO_PADDING: {
        const std::vector<std::byte> tbs = construct_rsa_fdh_tbs(type, mgf1_salt_, in);
        std::vector<std::byte> signature = rsa_signing_primitive(tbs, sk_guard_, pk_guard_);
        if (signature.empty())
        {
            GetLogger()->warn("RSASecretKey::get_vrf_proof failed to generate raw RSA signature.");
            return nullptr;
        }

        // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
        ret.reset(new RSAProof{type, std::move(signature)});
        break;
    }
    case RSA_PKCS1_PSS_PADDING: {
        const std::vector<std::byte> tbs = construct_rsa_pss_tbs(type, mgf1_salt_, in);
        std::vector<std::byte> signature = rsa_pss_nosalt_sign(tbs, sk_guard_, pk_guard_);
        if (signature.empty())
        {
            GetLogger()->warn("RSASecretKey::get_vrf_proof failed to generate RSA-PSS signature.");
            return nullptr;
        }

        // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
        ret.reset(new RSAProof{type, std::move(signature)});
        break;
    }
    default:
        GetLogger()->warn("RSASecretKey::get_vrf_proof called with unsupported padding mode: {}", params.pad_mode);
        break;
    }

    if (ret->is_initialized())
    {
        GetLogger()->trace("RSASecretKey::get_vrf_proof generated proof of size {} for VRF type {}.",
                           ret->to_bytes().size(), to_string(type));
    }
    return ret;
}

RSASecretKey::RSASecretKey(Type type) : SecretKey{Type::unknown}
{
    RSA_SK_Guard sk_guard{type};
    if (!sk_guard.has_value())
    {
        GetLogger()->warn("RSASecretKey constructor failed to generate RSA key for VRF type {}.", to_string(type));
        return;
    }

    RSA_PK_Guard pk_guard{sk_guard};
    if (!pk_guard.has_value())
    {
        GetLogger()->err("RSASecretKey constructor failed to create RSA public key from secret key.");
        return;
    }

    std::vector<std::byte> mgf1_salt = sk_guard.get_mgf1_salt();
    if (mgf1_salt.empty())
    {
        GetLogger()->err("RSASecretKey constructor failed to generate MGF1 salt.");
        return;
    }

    sk_guard_ = std::move(sk_guard);
    pk_guard_ = std::move(pk_guard);
    mgf1_salt_ = std::move(mgf1_salt);
    set_type(type);

    GetLogger()->trace("RSASecretKey constructor generated RSA key pair and MGF1 salt for VRF type {}.",
                       to_string(type));
}

RSASecretKey::RSASecretKey(RSA_SK_Guard sk_guard) : SecretKey{Type::unknown}
{
    if (!sk_guard.has_value())
    {
        GetLogger()->warn("RSASecretKey constructor called with invalid RSA_SK_Guard.");
        return;
    }

    RSA_PK_Guard pk_guard{sk_guard};
    if (!pk_guard.has_value())
    {
        GetLogger()->err("RSASecretKey constructor failed to create RSA public key from secret key.");
        return;
    }

    std::vector<std::byte> mgf1_salt = sk_guard.get_mgf1_salt();
    if (mgf1_salt.empty())
    {
        GetLogger()->err("RSASecretKey constructor failed to generate MGF1 salt.");
        return;
    }

    sk_guard_ = std::move(sk_guard);
    pk_guard_ = std::move(pk_guard);
    mgf1_salt_ = std::move(mgf1_salt);
    set_type(sk_guard_.get_type());

    GetLogger()->trace("RSASecretKey constructor initialized RSASecretKey from RSA_SK_Guard for VRF type {}.",
                       to_string(get_type()));
}

RSASecretKey &RSASecretKey::operator=(RSASecretKey &&rhs) noexcept
{
    if (this != &rhs)
    {
        const Type type = get_type();
        set_type(rhs.get_type());
        rhs.set_type(type);

        using std::swap;
        swap(sk_guard_, rhs.sk_guard_);
        swap(pk_guard_, rhs.pk_guard_);
        swap(mgf1_salt_, rhs.mgf1_salt_);
    }
    return *this;
}

RSASecretKey::RSASecretKey(const RSASecretKey &source) : SecretKey(source)
{
    if (!source.is_initialized())
    {
        GetLogger()->warn("RSASecretKey copy constructor called on invalid RSASecretKey.");
        return;
    }

    RSA_SK_Guard sk_guard_copy = source.sk_guard_.clone();
    if (!sk_guard_copy.has_value())
    {
        GetLogger()->err("RSASecretKey copy constructor failed to clone the given secret key.");
        return;
    }

    RSA_PK_Guard pk_guard_copy = source.pk_guard_.clone();
    if (!pk_guard_copy.has_value())
    {
        GetLogger()->err("RSASecretKey copy constructor failed to clone the given public key.");
        return;
    }

    std::vector<std::byte> mgf1_salt_copy = source.mgf1_salt_;

    sk_guard_ = std::move(sk_guard_copy);
    pk_guard_ = std::move(pk_guard_copy);
    mgf1_salt_ = std::move(mgf1_salt_copy);
    set_type(source.get_type());

    GetLogger()->trace("RSASecretKey copy constructor initialized secret key copy.");
}

std::unique_ptr<PublicKey> RSASecretKey::get_public_key() const
{
    if (!is_initialized())
    {
        GetLogger()->warn("RSASecretKey::get_public_key called on invalid RSASecretKey.");
        return nullptr;
    }

    RSA_PK_Guard pk_guard = pk_guard_.clone();
    std::unique_ptr<RSAPublicKey> public_key{new RSAPublicKey{get_type(), std::move(pk_guard)}};
    if (nullptr == public_key || !public_key->is_initialized())
    {
        GetLogger()->err("RSASecretKey::get_public_key failed to create RSAPublicKey from RSA_PK_Guard.");
        return nullptr;
    }

    GetLogger()->trace("RSASecretKey::get_public_key created RSAPublicKey from RSASecretKey for VRF type {}..",
                       to_string(get_type()));
    return public_key;
}

std::vector<std::byte> RSASecretKey::to_bytes() const
{
    GetLogger()->err("RSASecretKey::to_bytes is disabled; use to_secure_bytes() instead.");
    return {};
}

SecureBuf RSASecretKey::to_secure_bytes() const
{
    if (!is_initialized())
    {
        GetLogger()->warn("RSASecretKey::to_secure_bytes called on invalid RSASecretKey.");
        return {};
    }

    SecureBuf buf = encode_secret_key_to_der_pkcs8_with_type(get_type(), sk_guard_.get());
    if (!buf.has_value())
    {
        GetLogger()->err("RSASecretKey::to_secure_bytes failed to encode EVP_PKEY to DER PKCS#8.");
    }

    GetLogger()->trace("RSASecretKey::to_secure_bytes encoded RSA secret key to DER PKCS#8 for VRF type {}..",
                       to_string(get_type()));
    return buf;
}

void RSASecretKey::from_bytes(std::span<const std::byte> data)
{
    const auto [type, data_without_type] = extract_type_from_span(data);
    GetLogger()->trace("RSASecretKey::from_bytes extracted VRF type {} from input byte vector of size {}.",
                       to_string(type), data.size());

    RSA_SK_Guard sk_guard{type, data_without_type};
    if (!sk_guard.has_value())
    {
        GetLogger()->warn("RSASecretKey::from_bytes called with invalid private key DER for VRF type {}.",
                          to_string(type));
        return;
    }

    RSASecretKey secret_key{std::move(sk_guard)};
    if (!secret_key.is_initialized())
    {
        GetLogger()->err("RSASecretKey::from_bytes failed to initialize RSASecretKey.");
        return;
    }

    GetLogger()->trace("RSASecretKey::from_bytes initialized RSASecretKey from input byte vector.");
    *this = std::move(secret_key);
}

RSAPublicKey::RSAPublicKey(const RSAPublicKey &source) : PublicKey{Type::unknown}
{
    RSA_PK_Guard pk_guard_copy = source.pk_guard_.clone();
    if (pk_guard_copy.has_value() != source.pk_guard_.has_value())
    {
        GetLogger()->err("RSAPublicKey copy constructor failed to clone the given public key.");
        return;
    }

    std::vector<std::byte> mgf1_salt_copy = source.mgf1_salt_;

    pk_guard_ = std::move(pk_guard_copy);
    mgf1_salt_ = std::move(mgf1_salt_copy);
    set_type(source.get_type());

    GetLogger()->trace("RSAPublicKey copy constructor initialized public key copy.");
}

RSAPublicKey &RSAPublicKey::operator=(RSAPublicKey &&rhs) noexcept
{
    if (this != &rhs)
    {
        const Type type = get_type();
        set_type(rhs.get_type());
        rhs.set_type(type);

        using std::swap;
        swap(pk_guard_, rhs.pk_guard_);
        swap(mgf1_salt_, rhs.mgf1_salt_);
    }
    return *this;
}

RSAPublicKey::RSAPublicKey(std::span<const std::byte> der_spki_with_type)
    : PublicKey{Type::unknown}
{
    RSA_PK_Guard pk_guard{der_spki_with_type};
    if (!pk_guard.has_value())
    {
        GetLogger()->warn("RSAPublicKey constructor failed to load EVP_PKEY from provided DER SPKI.");
        return;
    }

    std::vector<std::byte> mgf1_salt = pk_guard.get_mgf1_salt();
    if (mgf1_salt.empty())
    {
        GetLogger()->err("RSAPublicKey constructor failed to generate MGF1 salt from loaded EVP_PKEY.");
        return;
    }

    pk_guard_ = std::move(pk_guard);
    mgf1_salt_ = std::move(mgf1_salt);
    set_type(pk_guard_.get_type());

    GetLogger()->trace("RSAPublicKey constructor initialized RSAPublicKey from DER SPKI for VRF type {}..",
                       to_string(get_type()));
}

RSAPublicKey::RSAPublicKey(Type type, RSA_PK_Guard pk_guard) : PublicKey{Type::unknown}
{
    if (!pk_guard.has_value())
    {
        GetLogger()->warn("RSAPublicKey constructor called with invalid RSA_PK_Guard.");
        return;
    }

    std::vector<std::byte> mgf1_salt = pk_guard.get_mgf1_salt();
    if (mgf1_salt.empty())
    {
        GetLogger()->err("RSAPublicKey constructor failed to generate MGF1 salt from provided EVP_PKEY.");
        return;
    }

    pk_guard_ = std::move(pk_guard);
    mgf1_salt_ = std::move(mgf1_salt);
    set_type(type);

    GetLogger()->trace("RSAPublicKey constructor initialized RSAPublicKey from RSA_PK_Guard for VRF type {}..",
                       to_string(type));
}

std::vector<std::byte> RSAPublicKey::to_bytes() const
{
    if (!is_initialized())
    {
        GetLogger()->warn("RSAPublicKey::to_bytes called on invalid RSAPublicKey.");
        return {};
    }

    std::vector<std::byte> der_spki = encode_public_key_to_der_spki_with_type(get_type(), pk_guard_.get());
    if (der_spki.empty())
    {
        GetLogger()->err("RSAPublicKey::to_bytes failed to encode EVP_PKEY to DER SPKI.");
    }

    GetLogger()->trace("RSAPublicKey::to_bytes encoded RSA public key to DER SPKI for VRF type {}.. "
                       "Output size is {} bytes.",
                       to_string(get_type()), der_spki.size());
    return der_spki;
}

void RSAPublicKey::from_bytes(std::span<const std::byte> data)
{
    RSAPublicKey public_key{data};
    if (!public_key.is_initialized())
    {
        GetLogger()->warn("RSAPublicKey::from_bytes called with invalid public key DER.");
        return;
    }

    GetLogger()->trace("RSAPublicKey::from_bytes initialized RSAPublicKey from input byte vector.");
    *this = std::move(public_key);
}

std::pair<bool, std::vector<std::byte>> RSAPublicKey::verify_vrf_proof(std::span<const std::byte> in,
                                                                       const std::unique_ptr<Proof> &proof)
{
    if (!is_initialized())
    {
        GetLogger()->warn("RSAPublicKey::verify_vrf_proof called on invalid RSAPublicKey.");
        return {false, {}};
    }

    // Downcast the proof type to RSAProof.
    const RSAProof *rsa_proof = dynamic_cast<const RSAProof *>(proof.get());
    if (nullptr == rsa_proof)
    {
        GetLogger()->warn("RSAPublicKey::verify_vrf_proof called with proof that is not of type RSAProof.");
        return {false, {}};
    }

    const Type type = get_type();
    if (!rsa_proof->is_initialized() || rsa_proof->get_type() != type)
    {
        GetLogger()->warn("RSAPublicKey::verify_vrf_proof called with invalid or mismatched proof type.");
        return {false, {}};
    }

    const RSAVRFParams params = get_rsavrf_params(type);

    bool success = false;
    switch (params.pad_mode)
    {
    case RSA_NO_PADDING: {
        const std::vector<std::byte> tbs_expected = rsa_verification_primitive(rsa_proof->proof_, pk_guard_);
        if (tbs_expected.empty())
        {
            success = false;
            GetLogger()->warn("RSAPublicKey::verify_vrf_proof failed to compute raw RSA verification primitive.");
            break;
        }
        const std::vector<std::byte> tbs = construct_rsa_fdh_tbs(type, mgf1_salt_, in);
        success = (tbs_expected == tbs);
        if (!success)
        {
            GetLogger()->warn("RSAPublicKey::verify_vrf_proof failed to verify raw RSA signature.");
        }
        break;
    }
    case RSA_PKCS1_PSS_PADDING: {
        const std::vector<std::byte> tbs = construct_rsa_pss_tbs(type, mgf1_salt_, in);
        success = rsa_pss_nosalt_verify(rsa_proof->proof_, tbs, pk_guard_);
        if (!success)
        {
            GetLogger()->warn("RSAPublicKey::verify_vrf_proof failed to verify RSA-PSS signature.");
        }
        break;
    }
    default:
        GetLogger()->warn("RSAPublicKey::verify_vrf_proof called with unsupported padding mode: {}", params.pad_mode);
        break;
    }

    if (!success)
    {
        return {false, {}};
    }

    GetLogger()->trace("RSAPublicKey::verify_vrf_proof verified proof for VRF type {}.", to_string(type));
    return {true, rsa_proof->get_vrf_value()};
}

} // namespace vrf::rsa
