// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "vrf/guards.h"
#include "vrf/type.h"
#include <concepts>
#include <openssl/evp.h>
#include <span>
#include <utility>
#include <vector>

namespace vrf::rsa
{

class RSA_SK_Guard
{
  public:
    RSA_SK_Guard() = default;

    explicit RSA_SK_Guard(Type type);

    RSA_SK_Guard(Type type, EVP_PKEY_Guard pkey) : type_{type}, pkey_{std::move(pkey)} {};

    RSA_SK_Guard(Type type, std::span<const std::byte> der_pkcs8);

    ~RSA_SK_Guard()
    {
        free();
    }

    RSA_SK_Guard &operator=(const RSA_SK_Guard &) = delete;

    RSA_SK_Guard &operator=(RSA_SK_Guard &&) noexcept;

    RSA_SK_Guard(const RSA_SK_Guard &) = delete;

    RSA_SK_Guard(RSA_SK_Guard &&rhs) noexcept
    {
        *this = std::move(rhs);
    }

    [[nodiscard]]
    const EVP_PKEY *get() const noexcept
    {
        return pkey_.get();
    }

    [[nodiscard]]
    EVP_PKEY *get() noexcept
    {
        return pkey_.get();
    }

    [[nodiscard]]
    bool has_value() const noexcept
    {
        return pkey_.has_value() && is_rsa_type(type_);
    }

    [[nodiscard]]
    Type get_type() const noexcept
    {
        return type_;
    }

    [[nodiscard]]
    RSA_SK_Guard clone() const;

    [[nodiscard]]
    std::vector<std::byte> get_mgf1_salt() const;

    void free()
    {
        pkey_.free();
        type_ = Type::UNKNOWN;
    }

  private:
    static EVP_PKEY_Guard GenerateRSAKey(Type type);

    Type type_ = Type::UNKNOWN;

    EVP_PKEY_Guard pkey_;
};

class RSA_PK_Guard
{
  public:
    RSA_PK_Guard() = default;

    explicit RSA_PK_Guard(const RSA_SK_Guard &sk_guard);

    explicit RSA_PK_Guard(std::span<const std::byte> der_spki_with_type);

    ~RSA_PK_Guard()
    {
        free();
    }

    RSA_PK_Guard &operator=(const RSA_PK_Guard &) = delete;

    RSA_PK_Guard &operator=(RSA_PK_Guard &&) noexcept;

    RSA_PK_Guard(const RSA_PK_Guard &) = delete;

    RSA_PK_Guard(RSA_PK_Guard &&rhs) noexcept
    {
        *this = std::move(rhs);
    }

    [[nodiscard]]
    const EVP_PKEY *get() const noexcept
    {
        return pkey_.get();
    }

    [[nodiscard]]
    EVP_PKEY *get() noexcept
    {
        return pkey_.get();
    }

    [[nodiscard]]
    bool has_value() const noexcept
    {
        return pkey_.has_value() && is_rsa_type(type_);
    }

    [[nodiscard]]
    Type get_type() const noexcept
    {
        return type_;
    }

    [[nodiscard]]
    RSA_PK_Guard clone() const;

    [[nodiscard]]
    std::vector<std::byte> get_mgf1_salt() const;

    void free()
    {
        pkey_.free();
        type_ = Type::UNKNOWN;
    }

  private:
    RSA_PK_Guard(Type type, EVP_PKEY_Guard pkey) : type_{type}, pkey_{std::move(pkey)} {};

    Type type_ = Type::UNKNOWN;

    EVP_PKEY_Guard pkey_;
};

template <typename T>
concept RSAGuard = std::same_as<T, RSA_PK_Guard> || std::same_as<T, RSA_SK_Guard>;

} // namespace vrf::rsa
