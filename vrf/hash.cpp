// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "vrf/guards.h"
#include "vrf/log.h"
#include <array>
#include <openssl/evp.h>
#include <span>
#include <vector>

namespace vrf
{

std::vector<std::byte> compute_hash(const char *md_name, std::span<const std::byte> tbh)
{
    // Get an EVP_MD for the specified VRF type.
    const EVP_MD *md = EVP_MD_fetch(get_libctx(), md_name, get_propquery());
    if (nullptr == md)
    {
        GetLogger()->debug("Failed to get EVP_MD for digest {}.", nullptr == md_name ? "null" : md_name);
        return {};
    }

    MD_CTX_Guard mctx = MD_CTX_Guard{true /* oneshot only */};
    if (!mctx.has_value())
    {
        GetLogger()->err("Failed to get EVP_MD_CTX.");
        return {};
    }

    std::array<std::byte, EVP_MAX_MD_SIZE> md_out{};
    unsigned md_outlen = 0;
    if (1 != EVP_DigestInit(mctx.get(), md) || 1 != EVP_DigestUpdate(mctx.get(), tbh.data(), tbh.size()) ||
        1 != EVP_DigestFinal_ex(mctx.get(), reinterpret_cast<unsigned char *>(md_out.data()), &md_outlen))
    {
        GetLogger()->err("Failed to compute digest; EVP_Digest* operations failed.");
        return {};
    }

    GetLogger()->trace("Computed hash with digest {} for data size {}, output size {}.", md_name, tbh.size(),
                       md_outlen);
    // NOLINTNEXTLINE(modernize-return-braced-init-list)
    return std::vector<std::byte>(md_out.begin(), md_out.begin() + md_outlen);
}

} // namespace vrf
