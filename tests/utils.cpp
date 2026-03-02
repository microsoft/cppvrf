// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "vrf/../tests/utils.h"
#include "vrf/../tests/ec_test_vectors.h"
#include "vrf/../tests/rsa_test_vectors.h"
#include "vrf/common.h"
#include "vrf/ec/ecvrf.h"
#include "vrf/log.h"
#include "vrf/rsa/keys.h"
#include "vrf/rsa/params.h"
#include "vrf/rsa/rsavrf.h"
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/params.h>

namespace vrf::tests::utils
{

using enum Type;

namespace
{

template <typename T>
concept CharKind =
    std::is_same_v<std::remove_cvref_t<T>, char> || std::is_same_v<std::remove_cvref_t<T>, unsigned char> ||
    std::is_same_v<std::remove_cvref_t<T>, signed char>;

template <CharKind C> constexpr int hexval(C c) noexcept
{
    C zero = static_cast<C>('0');
    C nine = static_cast<C>('9');
    C a_lower = static_cast<C>('a');
    C f_lower = static_cast<C>('f');
    C A_upper = static_cast<C>('A');
    C F_upper = static_cast<C>('F');

    if (c >= zero && c <= nine)
    {
        return c - zero;
    }
    if (c >= a_lower && c <= f_lower)
    {
        return c - a_lower + 10;
    }
    if (c >= A_upper && c <= F_upper)
    {
        return c - A_upper + 10;
    }
    return -1;
}

} // namespace

// Converts a hexadecimal string to a BIGNUM_Guard.
BIGNUM_Guard hex_string_to_bignum(const std::string &hex_str)
{
    BIGNUM_Guard bn{};
    if (0 == BN_hex2bn(bn.free_and_get_addr(true), hex_str.c_str()))
    {
        GetLogger()->err("Failed to convert hex string to BIGNUM: {}", hex_str);
        return {};
    }

    return bn;
}

// Creates an RSA secret key (EVP_PKEY) from hexadecimal strings representing
// the RSA parameters p and q.
EVP_PKEY_Guard make_rsa_secret_key(Type type, const std::string &p_hex, const std::string &q_hex)
{
    BIGNUM_Guard p = hex_string_to_bignum(p_hex);
    BIGNUM_Guard q = hex_string_to_bignum(q_hex);
    if (!p.has_value() || !q.has_value())
    {
        GetLogger()->err("Failed to create BIGNUMs for RSA parameters.");
        return {};
    }

    rsa::RSAVRFParams params = rsa::get_rsavrf_params(type);
    if (params.algorithm_name.empty())
    {
        GetLogger()->err("Unsupported VRF type for RSA key generation.");
        return {};
    }

    EVP_PKEY_CTX_Guard pctx{EVP_PKEY_CTX_new_from_name(get_libctx(), params.algorithm_name.data(), get_propquery())};
    if (!pctx.has_value())
    {
        GetLogger()->err("Failed to create EVP_PKEY_CTX for RSA key generation.");
        return {};
    }

    BN_CTX_Guard bn_ctx{true};
    if (!bn_ctx.has_value())
    {
        GetLogger()->err("Failed to allocate BN_CTX.");
        return {};
    }

    BIGNUM_Guard e_bn{false};
    BIGNUM_Guard n{false};
    BIGNUM_Guard p_minus_1{true};
    BIGNUM_Guard q_minus_1{true};
    BIGNUM_Guard gcd{true};
    BIGNUM_Guard lcm{true};
    BIGNUM_Guard tmp{true};
    BIGNUM_Guard d{true};
    BIGNUM_Guard dmp1{true};
    BIGNUM_Guard dmq1{true};
    BIGNUM_Guard iqmp{true};

    if (!e_bn.has_value() || !n.has_value() || !p_minus_1.has_value() || !q_minus_1.has_value() || !gcd.has_value() ||
        !lcm.has_value() || !tmp.has_value() || !d.has_value() || !dmp1.has_value() || !dmq1.has_value() ||
        !iqmp.has_value())
    {
        GetLogger()->err("Failed to allocate BIGNUMs for RSA key generation.");
        return {};
    }

    if (1 != BN_set_word(e_bn.get(), params.e))
    {
        GetLogger()->err("Failed to set public exponent e.");
        return {};
    }

    if (1 != BN_mul(n.get(), p.get(), q.get(), bn_ctx.get()))
    {
        GetLogger()->err("Failed to compute RSA modulus n = p*q.");
        return {};
    }

    // Compute λ(n) = lcm(p-1, q-1) = (p-1)*(q-1) / gcd(p-1, q-1)
    if (nullptr == BN_copy(p_minus_1.get(), p.get()) || 1 != BN_sub_word(p_minus_1.get(), 1) ||
        nullptr == BN_copy(q_minus_1.get(), q.get()) || 1 != BN_sub_word(q_minus_1.get(), 1))
    {
        GetLogger()->err("Failed to compute p-1 and q-1.");
        return {};
    }

    if (1 != BN_gcd(gcd.get(), p_minus_1.get(), q_minus_1.get(), bn_ctx.get()))
    {
        GetLogger()->err("Failed to compute gcd(p-1, q-1).");
        return {};
    }

    // tmp = (p-1) / gcd
    if (1 != BN_div(tmp.get(), nullptr, p_minus_1.get(), gcd.get(), bn_ctx.get()))
    {
        GetLogger()->err("Failed to divide (p-1) by gcd for lcm.");
        return {};
    }

    // lcm = tmp * (q-1)
    if (1 != BN_mul(lcm.get(), tmp.get(), q_minus_1.get(), bn_ctx.get()))
    {
        GetLogger()->err("Failed to compute lcm(p-1, q-1).");
        return {};
    }

    // d = e^{-1} mod lcm
    if (nullptr == BN_mod_inverse(d.get(), e_bn.get(), lcm.get(), bn_ctx.get()))
    {
        GetLogger()->err("Public exponent e is not invertible modulo λ(n). Bad RSA parameters?");
        return {};
    }

    // dmp1 = d mod (p-1), dmq1 = d mod (q-1)
    if (1 != BN_mod(dmp1.get(), d.get(), p_minus_1.get(), bn_ctx.get()) ||
        1 != BN_mod(dmq1.get(), d.get(), q_minus_1.get(), bn_ctx.get()))
    {
        GetLogger()->err("Failed to compute CRT exponents dmp1/dmq1.");
        return {};
    }

    // iqmp = q^{-1} mod p
    if (nullptr == BN_mod_inverse(iqmp.get(), q.get(), p.get(), bn_ctx.get()))
    {
        GetLogger()->err("Failed to compute iqmp = q^{{-1}} mod p.");
        return {};
    }

    // Sanity check: ensure gcd(e, p-1) == 1 and gcd(e, q-1) == 1
    {
        BIGNUM_Guard ge{true};
        BIGNUM_Guard gq{true};
        if (!ge.has_value() || !gq.has_value() || 1 != BN_gcd(ge.get(), e_bn.get(), p_minus_1.get(), bn_ctx.get()) ||
            1 != BN_gcd(gq.get(), e_bn.get(), q_minus_1.get(), bn_ctx.get()) || !BN_is_one(ge.get()) ||
            !BN_is_one(gq.get()))
        {
            GetLogger()->err("Public exponent e is not coprime with p-1 and/or q-1.");
            return {};
        }
    }

    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    if (nullptr == bld)
    {
        GetLogger()->err("OSSL_PARAM_BLD_new failed.");
        return {};
    }

    bool ok = OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n.get()) &&
              OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e_bn.get()) &&
              OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_D, d.get()) &&
              OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR1, p.get()) &&
              OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_FACTOR2, q.get()) &&
              OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, dmp1.get()) &&
              OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, dmq1.get()) &&
              OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, iqmp.get());

    if (!ok)
    {
        OSSL_PARAM_BLD_free(bld);
        GetLogger()->err("Failed to push RSA parameters into OSSL_PARAM_BLD.");
        return {};
    }

    OSSL_PARAM *paramlist = OSSL_PARAM_BLD_to_param(bld);
    if (!paramlist)
    {
        OSSL_PARAM_BLD_free(bld);
        GetLogger()->err("OSSL_PARAM_BLD_to_param failed.");
        return {};
    }

    // Finally create the EVP_PKEY.
    EVP_PKEY_Guard pkey{};
    if (1 != EVP_PKEY_fromdata_init(pctx.get()))
    {
        OSSL_PARAM_free(paramlist);
        OSSL_PARAM_BLD_free(bld);
        GetLogger()->err("EVP_PKEY_fromdata_init failed.");
        return {};
    }

    if (1 != EVP_PKEY_fromdata(pctx.get(), pkey.free_and_get_addr(), EVP_PKEY_KEYPAIR, paramlist))
    {
        OSSL_PARAM_free(paramlist);
        OSSL_PARAM_BLD_free(bld);
        GetLogger()->err("EVP_PKEY_fromdata failed to create RSA EVP_PKEY.");
        return {};
    }

    OSSL_PARAM_free(paramlist);
    OSSL_PARAM_BLD_free(bld);

    // Check the created key.
    {
        EVP_PKEY_CTX_Guard ck{EVP_PKEY_CTX_new_from_pkey(get_libctx(), pkey.get(), get_propquery())};
        if (!ck.has_value())
        {
            GetLogger()->err("Failed to create EVP_PKEY_CTX for checking constructed RSA key.");
            return {};
        }

        if (1 != EVP_PKEY_check(ck.get()))
        {
            GetLogger()->err("Constructed RSA EVP_PKEY failed EVP_PKEY_check.");
            return {};
        }
    }

    return pkey;
}

std::unique_ptr<SecretKey> make_rsa_vrf_secret_key(Type type, const std::string &p_hex, const std::string &q_hex)
{
    EVP_PKEY_Guard pkey = make_rsa_secret_key(type, p_hex, q_hex);
    if (!pkey.has_value())
    {
        GetLogger()->err("Failed to create RSA EVP_PKEY for VRF secret key.");
        return nullptr;
    }

    rsa::RSA_SK_Guard sk_guard{type, std::move(pkey)};
    if (!sk_guard.has_value())
    {
        GetLogger()->err("Failed to create RSA_SK_Guard for VRF secret key.");
        return nullptr;
    }

    std::unique_ptr<SecretKey> sk = std::make_unique<rsa::RSASecretKey>(std::move(sk_guard));
    if (!sk->is_initialized())
    {
        GetLogger()->err("Failed to create RSA VRF secret key from EVP_PKEY.");
        return nullptr;
    }

    return sk;
}

std::unique_ptr<SecretKey> make_ec_vrf_secret_key(Type type, const std::string &sk_hex)
{
    ec::ScalarType sk_scalar{hex_string_to_bignum(sk_hex)};
    if (!sk_scalar.has_value())
    {
        GetLogger()->err("Failed to convert hex string to EC scalar for VRF secret key.");
        return nullptr;
    }

    std::unique_ptr<SecretKey> sk = std::make_unique<ec::ECSecretKey>(type, std::move(sk_scalar));
    if (!sk->is_initialized())
    {
        GetLogger()->err("Failed to create EC VRF secret key from scalar.");
        return nullptr;
    }

    return sk;
}

std::vector<std::byte> parse_hex_bytes(std::string_view s)
{
    if (s.length() % 2 != 0)
    {
        GetLogger()->err("Hex string has odd length: {}", s.size());
        return {};
    }

    std::vector<std::byte> out{};
    out.reserve(s.size() / 2);

    int hi = -1;
    for (decltype(s)::value_type ch : s)
    {
        int v = hexval(ch);
        if (v < 0)
        {
            // Skip non-hex chars (spaces, newlines, dots, etc.)
            continue;
        }
        if (hi < 0)
        {
            hi = v;
        }
        else
        {
            unsigned next_byte = (static_cast<unsigned>(hi) << 4) | static_cast<unsigned>(v);
            out.push_back(static_cast<std::byte>(next_byte));
            hi = -1;
        }
    }
    if (hi != -1)
    {
        GetLogger()->err("Hex string has odd number of hex digits after filtering: {}", s.size());
        return {};
    }

    return out;
}

RSA_VRF_TestVectorParams get_rsa_vrf_test_vector_params(Type type)
{
    switch (type)
    {
    case RSA_FDH_VRF_RSA2048_SHA256:
        return RSA_FDH_2048_SHA256_PARAMS;
    case RSA_FDH_VRF_RSA3072_SHA256:
        return RSA_FDH_3072_SHA256_PARAMS;
    case RSA_FDH_VRF_RSA4096_SHA384:
        return RSA_FDH_4096_SHA384_PARAMS;
    case RSA_FDH_VRF_RSA4096_SHA512:
        return RSA_FDH_4096_SHA512_PARAMS;
    default:
        GetLogger()->err("No test vector parameters defined for VRF type {}.", to_string(type));
        return {};
    }
}

EC_VRF_TestVectorParams get_ec_vrf_test_vector_params(Type type)
{
    switch (type)
    {
    case EC_VRF_P256_SHA256_TAI:
        return EC_VRF_P256_SHA256_TAI_PARAMS;
    default:
        GetLogger()->err("No test vector parameters defined for VRF type {}.", to_string(type));
        return {};
    }
}

} // namespace vrf::tests::utils
