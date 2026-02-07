// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "vrf/ec/params.h"
#include "vrf/ec/utils.h"
#include <cstring>

#define ECVRF_PARAMS(CURVE, COFACTOR, DIGEST, B2I, P2B, B2P, E2C_SALT, E2C, NONCE, SUITE_STRING, FLEN, CLEN, QLEN,     \
                     PTLEN, HLEN)                                                                                      \
    "EC", CURVE, COFACTOR, DIGEST, B2I, P2B, B2P, E2C_SALT, E2C, NONCE, SUITE_STRING, FLEN, CLEN, QLEN, PTLEN, HLEN

namespace vrf::ec
{

using enum Type;

ECVRFParams get_ecvrf_params(Type type) noexcept
{
    switch (type)
    {
    case EC_VRF_P256_SHA256_TAI:
        return ECVRFParams{ECVRF_PARAMS(Curve::PRIME256V1, 1, "SHA256", BytesToIntMethod::BE,
                                        PointToBytesMethod::SEC1_COMPRESSED, BytesToPointMethod::SEC1,
                                        E2CSaltMethod::PUBLIC_KEY_COMPRESSED, E2CMethod::TRY_AND_INCREMENT,
                                        NonceGenMethod::RFC6979, "\001", 32, 16, 32, 33, 32)};
    default:
        return ECVRFParams{};
    }
}

} // namespace vrf::ec
