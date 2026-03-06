// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "vrf/guards.h"

namespace vrf::ec
{

class ScalarType
{
  public:
    ScalarType() = default;

    ScalarType(BIGNUM_Guard &&bn);

    explicit ScalarType(bool secure);

    ~ScalarType()
    {
        free();
    }

    ScalarType &operator=(const ScalarType &);

    ScalarType(const ScalarType &copy)
    {
        operator=(copy);
    }

    ScalarType &operator=(ScalarType &&) noexcept;

    ScalarType(ScalarType &&source) noexcept
    {
        operator=(std::move(source));
    }

    bool negate(const EC_GROUP_Guard &group, BN_CTX_Guard &bcg);

    bool add(const ScalarType &rhs, const EC_GROUP_Guard &group, BN_CTX_Guard &bcg);

    bool subtract(const ScalarType &rhs, const EC_GROUP_Guard &group, BN_CTX_Guard &bcg);

    bool multiply(const ScalarType &rhs, const EC_GROUP_Guard &group, BN_CTX_Guard &bcg);

    bool reduce_mod_order(const EC_GROUP_Guard &group, BN_CTX_Guard &bcg);

    [[nodiscard]]
    bool operator==(const ScalarType &rhs) const;

    [[nodiscard]]
    bool operator!=(const ScalarType &rhs) const
    {
        return !operator==(rhs);
    }

    [[nodiscard]]
    BIGNUM_Guard &get() noexcept
    {
        return scalar_;
    }

    [[nodiscard]]
    const BIGNUM_Guard &get() const noexcept
    {
        return scalar_;
    }

    [[nodiscard]]
    bool has_value() const noexcept
    {
        return scalar_.has_value();
    }

    [[nodiscard]]
    bool is_secure() const noexcept
    {
        return scalar_.is_secure();
    }

    void set_zero() noexcept;

    [[nodiscard]]
    bool is_zero() const noexcept;

    bool set_random(const EC_GROUP_Guard &group);

  private:
    void free() noexcept
    {
        scalar_.free();
    }

    BIGNUM_Guard scalar_;
};

class ECPoint
{
  public:
    enum class SpecialPoint
    {
        infinity = 0,
        generator = 1,
    };

    ECPoint() = default;

    explicit ECPoint(const EC_GROUP_Guard &group, SpecialPoint set_to = SpecialPoint::infinity);

    ECPoint(EC_POINT_Guard &&source);

    ~ECPoint()
    {
        free();
    }

    ECPoint &operator=(const ECPoint &assign);

    ECPoint &operator=(ECPoint &&source) noexcept;

    ECPoint(const ECPoint &copy)
    {
        operator=(copy);
    }

    ECPoint(ECPoint &&source) noexcept
    {
        operator=(std::move(source));
    }

    [[nodiscard]]
    EC_POINT_Guard &get() noexcept
    {
        return pt_;
    }

    [[nodiscard]]
    const EC_POINT_Guard &get() const noexcept
    {
        return pt_;
    }

    [[nodiscard]]
    Curve get_curve() const noexcept
    {
        return pt_.get_curve();
    }

    [[nodiscard]]
    bool has_value() const noexcept
    {
        return pt_.has_value();
    }

    // Computes scalar1*this+scalar2*generator
    bool double_scalar_multiply(const EC_GROUP_Guard &group, const ScalarType &scalar1, const ScalarType &scalar2,
                                BN_CTX_Guard &bcg);

    bool scalar_multiply(const EC_GROUP_Guard &group, const ScalarType &scalar, BN_CTX_Guard &bcg);

    bool set_to_generator_multiple(const EC_GROUP_Guard &group, const ScalarType &scalar, BN_CTX_Guard &bcg);

    [[nodiscard]]
    bool in_prime_order_subgroup() const;

    bool add(const EC_GROUP_Guard &group, const ECPoint &other, BN_CTX_Guard &bcg);

    bool negate(const EC_GROUP_Guard &group, BN_CTX_Guard &bcg);

  private:
    void free() noexcept
    {
        pt_.free();
    }

    EC_POINT_Guard pt_;
};

} // namespace vrf::ec
