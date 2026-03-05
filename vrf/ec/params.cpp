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
    case ec_vrf_p256_sha256_tai:
        return ECVRFParams{
            .algorithm_name = "EC",
            .curve = Curve::prime256v1,
            .cofactor = 1,
            .digest = "SHA256",
            .bytes_to_int = BytesToIntMethod::big_endian,
            .point_to_bytes = PointToBytesMethod::sec1_compressed,
            .bytes_to_point = BytesToPointMethod::sec1,
            .e2c_salt = E2CSaltMethod::public_key_compressed,
            .e2c = E2CMethod::try_and_increment,
            .nonce_gen = NonceGenMethod::rfc6979,
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
