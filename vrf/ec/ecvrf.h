// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "vrf/ec/ecpoint.h"
#include "vrf/ec/params.h"
#include "vrf/type.h"
#include "vrf/vrf_base.h"
#include <cstddef>
#include <span>
#include <vector>

namespace vrf::ec
{

class ECProof : public Proof
{
  public:
    ECProof() = default;

    ~ECProof() override = default;

    [[nodiscard]]
    std::vector<std::byte> get_vrf_value() const override;

    [[nodiscard]]
    std::unique_ptr<Proof> clone() const override
    {
        return std::unique_ptr<ECProof>(new ECProof(*this));
    }

    [[nodiscard]]
    std::vector<std::byte> to_bytes() override
    {
        return proof_;
    }

    void from_bytes(Type type, std::span<const std::byte> data) override;

    [[nodiscard]]
    bool is_initialized() const noexcept override
    {
        return !proof_.empty() && is_ec_type(get_type());
    }

  private:
    ECProof(const ECProof &source);

    ECProof(Type type, std::vector<std::byte> proof) : Proof{type}, proof_{std::move(proof)}
    {
    }

    ECProof &operator=(const ECProof &) = delete;

    ECProof &operator=(ECProof &&) noexcept;

    ECProof(ECProof &&source) noexcept
    {
        *this = std::move(source);
    }

    std::vector<std::byte> proof_{};

    friend class ECSecretKey;

    friend class ECPublicKey;
};

class ECSecretKey : public SecretKey
{
  public:
    ECSecretKey() = default;

    ~ECSecretKey() override = default;

    ECSecretKey(Type type);

    ECSecretKey(Type type, ScalarType sk);

    [[nodiscard]] bool is_initialized() const noexcept override
    {
        return !sk_.is_zero() && pk_.has_value() && group_.has_value() && is_ec_type(get_type());
    }

    [[nodiscard]]
    std::vector<std::byte> to_bytes() override;

    void from_bytes(Type type, std::span<const std::byte> data) override;

    [[nodiscard]]
    std::unique_ptr<Proof> get_vrf_proof(std::span<const std::byte> in) override;

    [[nodiscard]]
    std::unique_ptr<SecretKey> clone() const override
    {
        return std::unique_ptr<SecretKey>{new ECSecretKey{*this}};
    }

    [[nodiscard]]
    std::unique_ptr<PublicKey> get_public_key() override;

  private:
    ECSecretKey &operator=(ECSecretKey &&) noexcept;

    ECSecretKey(ECSecretKey &&source) noexcept
    {
        *this = std::move(source);
    }

    ECSecretKey &operator=(const ECSecretKey &) = delete;

    ECSecretKey(const ECSecretKey &);

    ScalarType sk_{};

    ECPoint pk_{};

    EC_GROUP_Guard group_{};
};

class ECPublicKey : public PublicKey
{
  public:
    ECPublicKey() = default;

    ~ECPublicKey() override = default;

    [[nodiscard]]
    std::pair<bool, std::vector<std::byte>> verify_vrf_proof(std::span<const std::byte> in,
                                                             const std::unique_ptr<Proof> &proof) override;

    [[nodiscard]]
    bool is_initialized() const noexcept override
    {
        return is_ec_type(get_type()) && pk_.has_value() && group_.has_value() &&
               pk_.get_curve() == group_.get_curve() && get_ecvrf_params(get_type()).curve == group_.get_curve();
    }

    [[nodiscard]]
    std::vector<std::byte> to_bytes() override;

    void from_bytes(Type type, std::span<const std::byte> data) override;

    [[nodiscard]]
    std::unique_ptr<PublicKey> clone() const override
    {
        return std::unique_ptr<ECPublicKey>{new ECPublicKey(*this)};
    }

  private:
    ECPublicKey(Type type, EC_GROUP_Guard, ECPoint);

    ECPublicKey(Type type, std::span<const std::byte> der_spki);

    ECPublicKey &operator=(const ECPublicKey &) = delete;

    ECPublicKey(const ECPublicKey &);

    ECPublicKey &operator=(ECPublicKey &&) noexcept;

    ECPublicKey(ECPublicKey &&source) noexcept
    {
        *this = std::move(source);
    }

    ECPoint pk_{};

    EC_GROUP_Guard group_{};

    friend class ECSecretKey;
};

} // namespace vrf::ec
