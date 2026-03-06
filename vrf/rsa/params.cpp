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
    auto create_params = [](unsigned bits, const char *digest, int pad_mode, const char *suite_string) {
        return RSAVRFParams{.algorithm_name = "RSA",
                            .bits = bits,
                            .primes = 2,
                            .e = 65537,
                            .digest = digest,
                            .pad_mode = pad_mode,
                            .suite_string = suite_string};
    };

    switch (type)
    {
    case rsa_fdh_vrf_rsa2048_sha256:
        return create_params(2048, "SHA256", RSA_NO_PADDING, "\001");
    case rsa_fdh_vrf_rsa3072_sha256:
        return create_params(3072, "SHA256", RSA_NO_PADDING, "\001");
    case rsa_fdh_vrf_rsa4096_sha384:
        return create_params(4096, "SHA384", RSA_NO_PADDING, "\002");
    case rsa_fdh_vrf_rsa4096_sha512:
        return create_params(4096, "SHA512", RSA_NO_PADDING, "\003");
    case rsa_pss_nosalt_vrf_rsa2048_sha256:
        return create_params(2048, "SHA256", RSA_PKCS1_PSS_PADDING, "\361RSA-PSS");
    case rsa_pss_nosalt_vrf_rsa3072_sha256:
        return create_params(3072, "SHA256", RSA_PKCS1_PSS_PADDING, "\361RSA-PSS");
    case rsa_pss_nosalt_vrf_rsa4096_sha384:
        return create_params(4096, "SHA384", RSA_PKCS1_PSS_PADDING, "\362RSA-PSS");
    case rsa_pss_nosalt_vrf_rsa4096_sha512:
        return create_params(4096, "SHA512", RSA_PKCS1_PSS_PADDING, "\363RSA-PSS");
    default:
        return RSAVRFParams{};
    }
}

} // namespace vrf::rsa
