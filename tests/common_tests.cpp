// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "vrf/common.h"
#include <cstdint>
#include <gtest/gtest.h>
#include <limits>
#include <vector>

namespace vrf::tests
{

TEST(CommonTests, GetLibCtx)
{
    const OSSL_LIB_CTX *libctx = vrf::get_libctx();

    // The default implementation returns nullptr.
    EXPECT_EQ(libctx, nullptr);
}

TEST(CommonTests, GetPropQuery)
{
    const char *propquery = vrf::get_propquery();

    // The default implementation returns nullptr.
    EXPECT_EQ(propquery, nullptr);
}

TEST(CommonTests, ComputeHashSHA256)
{
    const char *md_sha256 = "SHA256";
    std::string_view data = "hello world\n";
    std::vector<std::byte> hash = vrf::compute_hash(md_sha256, std::as_bytes(std::span{data}));
    ASSERT_FALSE(hash.empty());

    // Precomputed SHA256 hash of "hello world\n" is a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447.
    const std::vector<std::byte> expected_hash = {
        std::byte{0xa9}, std::byte{0x48}, std::byte{0x90}, std::byte{0x4f}, std::byte{0x2f}, std::byte{0x0f},
        std::byte{0x47}, std::byte{0x9b}, std::byte{0x8f}, std::byte{0x81}, std::byte{0x97}, std::byte{0x69},
        std::byte{0x4b}, std::byte{0x30}, std::byte{0x18}, std::byte{0x4b}, std::byte{0x0d}, std::byte{0x2e},
        std::byte{0xd1}, std::byte{0xc1}, std::byte{0xcd}, std::byte{0x2a}, std::byte{0x1e}, std::byte{0xc0},
        std::byte{0xfb}, std::byte{0x85}, std::byte{0xd2}, std::byte{0x99}, std::byte{0xa1}, std::byte{0x92},
        std::byte{0xa4}, std::byte{0x47}};
    EXPECT_EQ(hash, expected_hash);
}

TEST(CommonTests, ComputeHashInvalidAlgorithm)
{
    const char *md_invalid = "INVALID_ALGO";
    std::string_view data = "hello world";
    std::vector<std::byte> hash = vrf::compute_hash(md_invalid, std::as_bytes(std::span{data}));
    EXPECT_TRUE(hash.empty());
}

TEST(CommonTests, AddOverflow)
{
    {
        std::uint32_t a = std::numeric_limits<std::uint32_t>::max() - 2;
        std::uint32_t b = 1;
        std::uint32_t result = 0;
        bool overflow = vrf::add_with_overflow(a, b, result);
        EXPECT_FALSE(overflow);
        EXPECT_EQ(result, a + 1);
    }
    {
        std::uint32_t a = std::numeric_limits<std::uint32_t>::max();
        std::uint32_t b = 1;
        std::uint32_t result = 0;
        bool overflow = vrf::add_with_overflow(a, b, result);
        EXPECT_TRUE(overflow);
        EXPECT_EQ(result, 0);
    }
    {
        std::uint32_t a = std::numeric_limits<std::uint32_t>::max();
        std::uint16_t b = std::numeric_limits<std::uint16_t>::max();
        std::uint32_t result = 0;
        bool overflow = vrf::add_with_overflow(a, b, result);
        EXPECT_TRUE(overflow);
        EXPECT_EQ(result, std::numeric_limits<std::uint16_t>::max() - 1);
    }
}

TEST(CommonTests, SafeAdd)
{
    {
        auto result = vrf::safe_add(std::uint32_t{1}, std::uint32_t{2}, std::uint32_t{3});
        ASSERT_TRUE(result.has_value());
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        EXPECT_EQ(result.value(), 6);
    }
    {
        auto result = vrf::safe_add(std::uint32_t{1}, std::uint32_t{2}, std::numeric_limits<std::uint32_t>::max());
        EXPECT_FALSE(result.has_value());
    }
    {
        auto result = vrf::safe_add(std::uint32_t{1}, std::uint16_t{2}, std::uint8_t{3});
        ASSERT_TRUE(result.has_value());
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        EXPECT_EQ(result.value(), 6);
    }
    {
        auto result = vrf::safe_add(std::uint32_t{1}, std::uint16_t{2}, std::numeric_limits<std::uint64_t>::max() - 3);
        ASSERT_TRUE(result.has_value());
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        EXPECT_EQ(result.value(), std::numeric_limits<std::uint64_t>::max());
    }
    {
        auto result = vrf::safe_add(std::numeric_limits<std::uint8_t>::max(), std::numeric_limits<std::uint8_t>::max(),
                                    std::uint16_t{1});
        ASSERT_TRUE(result.has_value());
        // NOLINTNEXTLINE(bugprone-unchecked-optional-access)
        EXPECT_EQ(result.value(), std::uint16_t{255 + 255 + 1});
    }
}

} // namespace vrf::tests
