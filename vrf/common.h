// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "vrf/secure_buf.h"
#include <cstddef>
#include <limits>
#include <openssl/evp.h>
#include <openssl/types.h>
#include <optional>
#include <span>
#include <vector>

namespace vrf
{

[[nodiscard]]
OSSL_LIB_CTX *get_libctx();

[[nodiscard]]
const char *get_propquery();

[[nodiscard]]
EVP_PKEY *decode_public_key_from_der_spki(const char *algorithm_name, std::span<const std::byte> der_spki);

[[nodiscard]]
std::vector<std::byte> encode_public_key_to_der_spki(const EVP_PKEY *pkey);

[[nodiscard]]
EVP_PKEY *decode_secret_key_from_der_pkcs8(const char *algorithm_name, std::span<const std::byte> der_pkcs8);

[[nodiscard]]
SecureBuf encode_secret_key_to_der_pkcs8(const EVP_PKEY *pkey);

EVP_PKEY *evp_pkey_upref(EVP_PKEY *pkey);

[[nodiscard]]
extern std::vector<std::byte> compute_hash(const char *md_name, std::span<const std::byte> tbh);

template <std::unsigned_integral... Ts> using unsigned_common_t = std::make_unsigned_t<std::common_type_t<Ts...>>;

template <std::unsigned_integral T, std::unsigned_integral S>
[[nodiscard]]
constexpr bool add_with_overflow(T a, S b, unsigned_common_t<T, S> &c) noexcept
{
    using U = unsigned_common_t<T, S>;
    const U au = static_cast<U>(a);
    const U bu = static_cast<U>(b);
    c = au + bu;
    if (au > std::numeric_limits<U>::max() - bu)
    {
        return true;
    }
    return false;
}

template <std::unsigned_integral... Ts>
[[nodiscard]]
constexpr std::optional<unsigned_common_t<Ts...>> safe_add(Ts... args) noexcept
    requires(sizeof...(Ts) >= 2)
{
    using result_t = unsigned_common_t<Ts...>;
    result_t sum{};
    bool overflow = (add_with_overflow(sum, args, sum) || ...);
    if (overflow)
    {
        return std::nullopt;
    }
    return sum;
}

// Forward declaration of BIGNUM_Guard to avoid including guards.h here.
class BIGNUM_Guard;

enum class BytesToIntMethod
{
    UNDEFINED = 0,
    BE = 1,
    LE = 2,
};

using bytes_to_int_ptr_t = BIGNUM_Guard (*)(std::span<const std::byte> in, bool secure);

extern bytes_to_int_ptr_t bytes_to_int_big_endian;
extern bytes_to_int_ptr_t bytes_to_int_little_endian;

[[nodiscard]]
constexpr bytes_to_int_ptr_t get_bytes_to_int_method(BytesToIntMethod method)
{
    switch (method)
    {
    case BytesToIntMethod::BE:
        return bytes_to_int_big_endian;
    case BytesToIntMethod::LE:
        return bytes_to_int_little_endian;
    default:
        return nullptr;
    }
}

using int_to_bytes_ptr_t = std::size_t (*)(const BIGNUM_Guard &bn, std::span<std::byte> out);

extern int_to_bytes_ptr_t int_to_bytes_big_endian;
extern int_to_bytes_ptr_t int_to_bytes_little_endian;

[[nodiscard]]
constexpr int_to_bytes_ptr_t get_int_to_bytes_method(BytesToIntMethod method)
{
    switch (method)
    {
    case BytesToIntMethod::BE:
        return int_to_bytes_big_endian;
    case BytesToIntMethod::LE:
        return int_to_bytes_little_endian;
    default:
        return nullptr;
    }
}

enum class Curve : int
{
    UNDEFINED = NID_undef,
    PRIME256V1 = NID_X9_62_prime256v1,
};

[[nodiscard]]
constexpr int curve_to_nid(Curve curve) noexcept
{
    return static_cast<int>(curve);
}

[[nodiscard]]
constexpr Curve nid_to_curve(int nid) noexcept
{
    switch (nid)
    {
    case NID_X9_62_prime256v1:
        return Curve::PRIME256V1;
    default:
        return Curve::UNDEFINED;
    }
}

} // namespace vrf
