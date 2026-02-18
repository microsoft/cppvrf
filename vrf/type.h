// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstddef>
#include <ostream>
#include <string_view>

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

inline constexpr bool is_rsa_type(Type type)
{
    return type == Type::RSA_FDH_VRF_RSA2048_SHA256 || type == Type::RSA_FDH_VRF_RSA3072_SHA256 ||
           type == Type::RSA_FDH_VRF_RSA4096_SHA384 || type == Type::RSA_FDH_VRF_RSA4096_SHA512 ||
           type == Type::RSA_PSS_NOSALT_VRF_RSA2048_SHA256 || type == Type::RSA_PSS_NOSALT_VRF_RSA3072_SHA256 ||
           type == Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA384 || type == Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA512;
}

inline constexpr bool is_ec_type(Type type)
{
    return type == Type::EC_VRF_P256_SHA256_TAI;
}

inline constexpr std::string_view to_string(Type type)
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

inline std::ostream &operator<<(std::ostream &os, Type t)
{
    return os << to_string(t);
}

} // namespace vrf
