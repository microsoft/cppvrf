// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstddef>
#include <cstdint>
#include <ostream>
#include <string_view>
#include <utility>

namespace vrf
{

enum class Type : std::uint8_t
{
    rsa_fdh_vrf_rsa2048_sha256,
    rsa_fdh_vrf_rsa3072_sha256,
    rsa_fdh_vrf_rsa4096_sha384,
    rsa_fdh_vrf_rsa4096_sha512,
    rsa_pss_nosalt_vrf_rsa2048_sha256,
    rsa_pss_nosalt_vrf_rsa3072_sha256,
    rsa_pss_nosalt_vrf_rsa4096_sha384,
    rsa_pss_nosalt_vrf_rsa4096_sha512,
    ec_vrf_p256_sha256_tai,
    unknown
};

constexpr bool is_rsa_type(Type type)
{
    return type == Type::rsa_fdh_vrf_rsa2048_sha256 || type == Type::rsa_fdh_vrf_rsa3072_sha256 ||
           type == Type::rsa_fdh_vrf_rsa4096_sha384 || type == Type::rsa_fdh_vrf_rsa4096_sha512 ||
           type == Type::rsa_pss_nosalt_vrf_rsa2048_sha256 || type == Type::rsa_pss_nosalt_vrf_rsa3072_sha256 ||
           type == Type::rsa_pss_nosalt_vrf_rsa4096_sha384 || type == Type::rsa_pss_nosalt_vrf_rsa4096_sha512;
}

constexpr bool is_ec_type(Type type)
{
    return type == Type::ec_vrf_p256_sha256_tai;
}

constexpr std::string_view to_string(Type type)
{
    switch (type)
    {
    case Type::rsa_fdh_vrf_rsa2048_sha256:
        return "rsa_fdh_vrf_rsa2048_sha256";
    case Type::rsa_fdh_vrf_rsa3072_sha256:
        return "rsa_fdh_vrf_rsa3072_sha256";
    case Type::rsa_fdh_vrf_rsa4096_sha384:
        return "rsa_fdh_vrf_rsa4096_sha384";
    case Type::rsa_fdh_vrf_rsa4096_sha512:
        return "rsa_fdh_vrf_rsa4096_sha512";
    case Type::rsa_pss_nosalt_vrf_rsa2048_sha256:
        return "rsa_pss_nosalt_vrf_rsa2048_sha256";
    case Type::rsa_pss_nosalt_vrf_rsa3072_sha256:
        return "rsa_pss_nosalt_vrf_rsa3072_sha256";
    case Type::rsa_pss_nosalt_vrf_rsa4096_sha384:
        return "rsa_pss_nosalt_vrf_rsa4096_sha384";
    case Type::rsa_pss_nosalt_vrf_rsa4096_sha512:
        return "rsa_pss_nosalt_vrf_rsa4096_sha512";
    case Type::ec_vrf_p256_sha256_tai:
        return "ec_vrf_p256_sha256_tai";
    default:
        return "unknown";
    }
}

constexpr std::byte to_byte(Type type)
{
    if (static_cast<std::uint8_t>(type) > static_cast<std::uint8_t>(Type::unknown))
    {
        return static_cast<std::byte>(Type::unknown);
    }
    return static_cast<std::byte>(type);
}

constexpr Type from_byte(std::byte b)
{
    const std::uint8_t value = std::to_integer<std::uint8_t>(b);
    if (static_cast<std::uint8_t>(Type::unknown) < value)
    {
        return Type::unknown;
    }
    return static_cast<Type>(value);
}

inline std::ostream &operator<<(std::ostream &os, Type t)
{
    return os << to_string(t);
}

} // namespace vrf
