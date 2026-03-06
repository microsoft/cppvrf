// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "vrf/type.h"
#include <string_view>

namespace vrf::rsa
{

struct RSAVRFParams
{
    std::string_view algorithm_name;
    unsigned bits = 0;
    unsigned primes = 0;
    unsigned e = 0;
    std::string_view digest;
    int pad_mode = 0;
    std::string_view suite_string;
};

[[nodiscard]]
RSAVRFParams get_rsavrf_params(Type type) noexcept;

} // namespace vrf::rsa
