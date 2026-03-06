// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "vrf/guards.h"
#include "vrf/log.h"
#include "vrf/type.h"
#include <algorithm>
#include <cstddef>
#include <iterator>
#include <openssl/ec.h>
#include <span>
#include <utility>
#include <vector>

namespace vrf::ec
{

enum class PointCompression : int
{
    compressed = POINT_CONVERSION_COMPRESSED,
    uncompressed = POINT_CONVERSION_UNCOMPRESSED,
};

enum class PointToBytesMethod
{
    undefined = 0,
    sec1_uncompressed = 1,
    sec1_compressed = 2,
};

enum class BytesToPointMethod
{
    undefined = 0,
    sec1 = 1,
};

using point_to_bytes_ptr_t = std::size_t (*)(const EC_GROUP_Guard &group, const EC_POINT_Guard &pt, BN_CTX_Guard &bcg,
                                             std::span<std::byte> out);

[[nodiscard]]
point_to_bytes_ptr_t get_point_to_bytes_method(PointToBytesMethod method);

using bytes_to_point_ptr_t = EC_POINT_Guard (*)(const EC_GROUP_Guard &group, std::span<const std::byte> in,
                                                BN_CTX_Guard &bcg);

[[nodiscard]]
bytes_to_point_ptr_t get_bytes_to_point_method(BytesToPointMethod method);

template <std::output_iterator<std::byte> Out>
std::size_t do_append_ecpoint_to_bytes(const EC_GROUP_Guard &group, PointToBytesMethod p2b_method, BN_CTX_Guard &bcg,
                                       Out out, const EC_POINT_Guard &pt)
{
    if (!group.has_value() || !pt.has_value() || !ensure_bcg_set(bcg, false))
    {
        GetLogger()->debug(
            "do_append_ecpoint_to_bytes called with invalid group or point, or failed to obtain BN_CTX.");
        return 0;
    }

    point_to_bytes_ptr_t pt_to_bytes = get_point_to_bytes_method(p2b_method);
    std::size_t buf_size = pt_to_bytes(group, pt, bcg, {});
    if (0 == buf_size)
    {
        GetLogger()->debug("do_append_ecpoint_to_bytes failed to get buffer size for point to bytes conversion.");
        return 0;
    }

    std::vector<std::byte> append_to_out(buf_size);
    buf_size = pt_to_bytes(group, pt, bcg, append_to_out);
    if (append_to_out.size() != buf_size)
    {
        GetLogger()->debug(
            "do_append_ecpoint_to_bytes failed to convert point to bytes; expected buffer size was {}, but {} "
            "bytes were written.",
            append_to_out.size(), buf_size);
        return 0;
    }

    std::copy(append_to_out.begin(), append_to_out.end(), out);
    return buf_size;
}

template <std::output_iterator<std::byte> Out, typename... Points>
    requires(sizeof...(Points) >= 1) && (std::convertible_to<Points, const EC_POINT_Guard &> && ...)
std::pair<bool, std::size_t> append_ecpoint_to_bytes(const EC_GROUP_Guard &group, PointToBytesMethod p2b_method,
                                                     BN_CTX_Guard &bcg, Out out, Points &&...points)
{
    bool success = true;
    std::size_t total_size = 0;

    // Fold over the comma operator.
    (
        [&]() {
            const std::size_t written = do_append_ecpoint_to_bytes(group, p2b_method, bcg, out, points);
            total_size += written;
            out += static_cast<std::ptrdiff_t>(written);
            success &= (written != 0);
        }(),
        ...);

    GetLogger()->trace("append_ecpoint_to_bytes attempted to convert and append {} EC_POINTs to output iterator; "
                       "success: {}, total bytes written: {}.",
                       sizeof...(Points), success, total_size);
    return std::make_pair(success, total_size);
}

enum class E2CSaltMethod
{
    undefined = 0,
    public_key_compressed = 1,
};

using e2c_salt_ptr_t = std::vector<std::byte> (*)(Type type, const EC_GROUP_Guard &group, const EC_POINT_Guard &pk,
                                                  BN_CTX_Guard &bcg);

[[nodiscard]]
e2c_salt_ptr_t get_e2c_salt_method(E2CSaltMethod method);

enum class E2CMethod
{
    undefined = 0,
    try_and_increment = 1,
};

using e2c_ptr_t = EC_POINT_Guard (*)(Type type, const EC_GROUP_Guard &group, std::span<const std::byte> e2c_salt,
                                     std::span<const std::byte> data, BN_CTX_Guard &bcg);

[[nodiscard]]
e2c_ptr_t get_e2c_method(E2CMethod method);

enum class NonceGenMethod
{
    undefined = 0,
    rfc6979 = 1,
};

using nonce_gen_ptr_t = BIGNUM_Guard (*)(Type type, const EC_GROUP_Guard &group, const BIGNUM_Guard &sk,
                                         const std::span<const std::byte> m);

[[nodiscard]]
nonce_gen_ptr_t get_nonce_gen_method(NonceGenMethod method);

} // namespace vrf::ec
