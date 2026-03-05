// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "vrf/rsa/params.h"
#include <cstring>
#include <openssl/rsa.h>

namespace vrf::rsa
{

using enum Type;

RSAVRFParams get_rsavrf_params(Type type) noexcept
{
    switch (type)
    {
    case rsa_fdh_vrf_rsa2048_sha256:
        return RSAVRFParams{
            .algorithm_name = "RSA", .bits = 2048, .primes = 2, .e = 65537,
            .digest = "SHA256", .pad_mode = RSA_NO_PADDING, .suite_string = "\001"};
    case rsa_fdh_vrf_rsa3072_sha256:
        return RSAVRFParams{
            .algorithm_name = "RSA", .bits = 3072, .primes = 2, .e = 65537,
            .digest = "SHA256", .pad_mode = RSA_NO_PADDING, .suite_string = "\001"};
    case rsa_fdh_vrf_rsa4096_sha384:
        return RSAVRFParams{
            .algorithm_name = "RSA", .bits = 4096, .primes = 2, .e = 65537,
            .digest = "SHA384", .pad_mode = RSA_NO_PADDING, .suite_string = "\002"};
    case rsa_fdh_vrf_rsa4096_sha512:
        return RSAVRFParams{
            .algorithm_name = "RSA", .bits = 4096, .primes = 2, .e = 65537,
            .digest = "SHA512", .pad_mode = RSA_NO_PADDING, .suite_string = "\003"};
    case rsa_pss_nosalt_vrf_rsa2048_sha256:
        return RSAVRFParams{
            .algorithm_name = "RSA", .bits = 2048, .primes = 2, .e = 65537,
            .digest = "SHA256", .pad_mode = RSA_PKCS1_PSS_PADDING, .suite_string = "\361RSA-PSS"};
    case rsa_pss_nosalt_vrf_rsa3072_sha256:
        return RSAVRFParams{
            .algorithm_name = "RSA", .bits = 3072, .primes = 2, .e = 65537,
            .digest = "SHA256", .pad_mode = RSA_PKCS1_PSS_PADDING, .suite_string = "\361RSA-PSS"};
    case rsa_pss_nosalt_vrf_rsa4096_sha384:
        return RSAVRFParams{
            .algorithm_name = "RSA", .bits = 4096, .primes = 2, .e = 65537,
            .digest = "SHA384", .pad_mode = RSA_PKCS1_PSS_PADDING, .suite_string = "\362RSA-PSS"};
    case rsa_pss_nosalt_vrf_rsa4096_sha512:
        return RSAVRFParams{
            .algorithm_name = "RSA", .bits = 4096, .primes = 2, .e = 65537,
            .digest = "SHA512", .pad_mode = RSA_PKCS1_PSS_PADDING, .suite_string = "\363RSA-PSS"};
    default:
        return RSAVRFParams{};
    }
}

} // namespace vrf::rsa
