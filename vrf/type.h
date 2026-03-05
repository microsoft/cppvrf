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

enum class Type : std::size_t
{
    RSA_FDH_VRF_RSA2048_SHA256,
    RSA_FDH_VRF_RSA3072_SHA256,
    RSA_FDH_VRF_RSA4096_SHA384,
    RSA_FDH_VRF_RSA4096_SHA512,
    RSA_PSS_NOSALT_VRF_RSA2048_SHA256,
    RSA_PSS_NOSALT_VRF_RSA3072_SHA256,
    RSA_PSS_NOSALT_VRF_RSA4096_SHA384,
    RSA_PSS_NOSALT_VRF_RSA4096_SHA512,
    EC_VRF_P256_SHA256_TAI,
    UNKNOWN
};

constexpr bool is_rsa_type(Type type)
{
    return type == Type::RSA_FDH_VRF_RSA2048_SHA256 || type == Type::RSA_FDH_VRF_RSA3072_SHA256 ||
           type == Type::RSA_FDH_VRF_RSA4096_SHA384 || type == Type::RSA_FDH_VRF_RSA4096_SHA512 ||
           type == Type::RSA_PSS_NOSALT_VRF_RSA2048_SHA256 || type == Type::RSA_PSS_NOSALT_VRF_RSA3072_SHA256 ||
           type == Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA384 || type == Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA512;
}

constexpr bool is_ec_type(Type type)
{
    return type == Type::EC_VRF_P256_SHA256_TAI;
}

constexpr std::string_view to_string(Type type)
{
    switch (type)
    {
    case Type::RSA_FDH_VRF_RSA2048_SHA256:
        return "RSA_FDH_VRF_RSA2048_SHA256";
    case Type::RSA_FDH_VRF_RSA3072_SHA256:
        return "RSA_FDH_VRF_RSA3072_SHA256";
    case Type::RSA_FDH_VRF_RSA4096_SHA384:
        return "RSA_FDH_VRF_RSA4096_SHA384";
    case Type::RSA_FDH_VRF_RSA4096_SHA512:
        return "RSA_FDH_VRF_RSA4096_SHA512";
    case Type::RSA_PSS_NOSALT_VRF_RSA2048_SHA256:
        return "RSA_PSS_NOSALT_VRF_RSA2048_SHA256";
    case Type::RSA_PSS_NOSALT_VRF_RSA3072_SHA256:
        return "RSA_PSS_NOSALT_VRF_RSA3072_SHA256";
    case Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA384:
        return "RSA_PSS_NOSALT_VRF_RSA4096_SHA384";
    case Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA512:
        return "RSA_PSS_NOSALT_VRF_RSA4096_SHA512";
    case Type::EC_VRF_P256_SHA256_TAI:
        return "EC_VRF_P256_SHA256_TAI";
    default:
        return "UNKNOWN";
    }
}

constexpr std::byte as_byte(Type type)
{
    static_assert(std::in_range<std::uint8_t>(static_cast<std::size_t>(Type::UNKNOWN)));
    return static_cast<std::byte>(type);
}

constexpr Type from_byte(std::byte b)
{
    const std::size_t value = static_cast<std::size_t>(b);
    if (static_cast<std::size_t>(Type::UNKNOWN) < value)
    {
        return Type::UNKNOWN;
    }
    return static_cast<Type>(value);
}

inline std::ostream &operator<<(std::ostream &os, Type t)
{
    return os << to_string(t);
}

} // namespace vrf
