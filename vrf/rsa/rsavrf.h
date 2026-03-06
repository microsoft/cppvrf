// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "vrf/rsa/keys.h"
#include "vrf/type.h"
#include "vrf/vrf_base.h"
#include <cstddef>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace vrf::rsa
{

class RSAProof final : public Proof
{
  public:
    RSAProof() = default;

    ~RSAProof() override = default;

    [[nodiscard]]
    std::vector<std::byte> get_vrf_value() const override;

    [[nodiscard]]
    std::unique_ptr<Proof> clone() const override
    {
        return std::unique_ptr<RSAProof>(new RSAProof(*this));
    }

    [[nodiscard]]
    std::vector<std::byte> to_bytes() const override;

    void from_bytes(std::span<const std::byte> data) override;

    [[nodiscard]]
    bool is_initialized() const noexcept override
    {
        return !proof_.empty() && is_rsa_type(get_type());
    }

    RSAProof &operator=(const RSAProof &) = delete;

  private:
    RSAProof(const RSAProof &source);

    RSAProof(Type type, std::vector<std::byte> proof) : Proof{type}, proof_{std::move(proof)}
    {
    }

    RSAProof &operator=(RSAProof &&) noexcept;

    RSAProof(RSAProof &&source) noexcept
    {
        *this = std::move(source);
    }

    std::vector<std::byte> proof_;

    friend class RSASecretKey;

    friend class RSAPublicKey;
};

class RSASecretKey final : public SecretKey
{
  public:
    RSASecretKey() = default;

    ~RSASecretKey() override = default;

    explicit RSASecretKey(Type type);

    explicit RSASecretKey(RSA_SK_Guard sk_guard);

    [[nodiscard]]
    std::unique_ptr<Proof> get_vrf_proof(std::span<const std::byte> in) override;

    [[nodiscard]]
    bool is_initialized() const noexcept override
    {
        return sk_guard_.has_value() && pk_guard_.has_value() && !mgf1_salt_.empty() &&
               get_type() == sk_guard_.get_type();
    }

    [[nodiscard]]
    std::vector<std::byte> to_bytes() const override;

    [[nodiscard]]
    SecureBuf to_secure_bytes() const override;

    void from_bytes(std::span<const std::byte> data) override;

    [[nodiscard]]
    std::unique_ptr<SecretKey> clone() const override
    {
        return std::unique_ptr<RSASecretKey>(new RSASecretKey(*this));
    }

    [[nodiscard]]
    std::unique_ptr<PublicKey> get_public_key() const override;

    RSASecretKey &operator=(const RSASecretKey &) = delete;

  private:
    RSASecretKey &operator=(RSASecretKey &&) noexcept;

    RSASecretKey(RSASecretKey &&source) noexcept
    {
        *this = std::move(source);
    }

    RSASecretKey(const RSASecretKey &);

    RSA_SK_Guard sk_guard_;

    RSA_PK_Guard pk_guard_;

    std::vector<std::byte> mgf1_salt_;
};

class RSAPublicKey final : public PublicKey
{
  public:
    RSAPublicKey() = default;

    ~RSAPublicKey() override = default;

    [[nodiscard]]
    std::pair<bool, std::vector<std::byte>> verify_vrf_proof(std::span<const std::byte> in,
                                                             const std::unique_ptr<Proof> &proof) override;

    [[nodiscard]]
    bool is_initialized() const noexcept override
    {
        return pk_guard_.has_value() && !mgf1_salt_.empty() && get_type() == pk_guard_.get_type();
    }

    [[nodiscard]]
    std::vector<std::byte> to_bytes() const override;

    void from_bytes(std::span<const std::byte> data) override;

    [[nodiscard]]
    std::unique_ptr<PublicKey> clone() const override
    {
        return std::unique_ptr<RSAPublicKey>{new RSAPublicKey(*this)};
    }

    RSAPublicKey &operator=(const RSAPublicKey &) = delete;

  private:
    explicit RSAPublicKey(std::span<const std::byte> der_spki_with_type);

    RSAPublicKey(Type type, RSA_PK_Guard pk_guard);

    RSAPublicKey(const RSAPublicKey &);

    RSAPublicKey &operator=(RSAPublicKey &&) noexcept;

    RSAPublicKey(RSAPublicKey &&source) noexcept
    {
        *this = std::move(source);
    }

    RSA_PK_Guard pk_guard_;

    std::vector<std::byte> mgf1_salt_;

    friend class RSASecretKey;
};

} // namespace vrf::rsa
