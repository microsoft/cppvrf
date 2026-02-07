// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "vrf/rsa/params.h"
#include <cstring>
#include <openssl/rsa.h>

#define RSAVRF_PARAMS(KEY_SIZE, DIGEST, PAD_MODE, SUITE_STRING)                                                        \
    "RSA", KEY_SIZE, 2, 65537, DIGEST, PAD_MODE, SUITE_STRING

namespace vrf::rsa
{

using enum Type;

RSAVRFParams get_rsavrf_params(Type type) noexcept
{
    switch (type)
    {
    case RSA_FDH_VRF_RSA2048_SHA256:
        return RSAVRFParams{RSAVRF_PARAMS(2048, "SHA256", RSA_NO_PADDING, "\001")};
    case RSA_FDH_VRF_RSA3072_SHA256:
        return RSAVRFParams{RSAVRF_PARAMS(3072, "SHA256", RSA_NO_PADDING, "\001")};
    case RSA_FDH_VRF_RSA4096_SHA384:
        return RSAVRFParams{RSAVRF_PARAMS(4096, "SHA384", RSA_NO_PADDING, "\002")};
    case RSA_FDH_VRF_RSA4096_SHA512:
        return RSAVRFParams{RSAVRF_PARAMS(4096, "SHA512", RSA_NO_PADDING, "\003")};
    case RSA_PSS_NOSALT_VRF_RSA2048_SHA256:
        return RSAVRFParams{RSAVRF_PARAMS(2048, "SHA256", RSA_PKCS1_PSS_PADDING, "\361RSA-PSS")};
    case RSA_PSS_NOSALT_VRF_RSA3072_SHA256:
        return RSAVRFParams{RSAVRF_PARAMS(3072, "SHA256", RSA_PKCS1_PSS_PADDING, "\361RSA-PSS")};
    case RSA_PSS_NOSALT_VRF_RSA4096_SHA384:
        return RSAVRFParams{RSAVRF_PARAMS(4096, "SHA384", RSA_PKCS1_PSS_PADDING, "\362RSA-PSS")};
    case RSA_PSS_NOSALT_VRF_RSA4096_SHA512:
        return RSAVRFParams{RSAVRF_PARAMS(4096, "SHA512", RSA_PKCS1_PSS_PADDING, "\363RSA-PSS")};
    default:
        return RSAVRFParams{};
    }
}

} // namespace vrf::rsa
