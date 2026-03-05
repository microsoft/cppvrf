// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "vrf/ec/params.h"
#include "vrf/ec/utils.h"
#include <cstring>

namespace vrf::ec
{

using enum Type;

ECVRFParams get_ecvrf_params(Type type) noexcept
{
    switch (type)
    {
    case EC_VRF_P256_SHA256_TAI:
        return ECVRFParams{
            .algorithm_name = "EC",
            .curve = Curve::PRIME256V1,
            .cofactor = 1,
            .digest = "SHA256",
            .bytes_to_int = BytesToIntMethod::BE,
            .point_to_bytes = PointToBytesMethod::SEC1_COMPRESSED,
            .bytes_to_point = BytesToPointMethod::SEC1,
            .e2c_salt = E2CSaltMethod::PUBLIC_KEY_COMPRESSED,
            .e2c = E2CMethod::TRY_AND_INCREMENT,
            .nonce_gen = NonceGenMethod::RFC6979,
            .suite_string = "\001",
            .f_len = 32,
            .c_len = 16,
            .q_len = 32,
            .pt_len = 33,
            .h_len = 32};
    default:
        return ECVRFParams{};
    }
}

} // namespace vrf::ec
