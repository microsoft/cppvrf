// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "vrf/ec/ecpoint.h"
#include "vrf/common.h"
#include "vrf/log.h"
#include <openssl/ec.h>

namespace vrf::ec
{

namespace
{

std::optional<bool> try_subtract_reduce_mod_group_order(BIGNUM_Guard &bn, const EC_GROUP_Guard &group,
                                                        BN_CTX_Guard &bcg)
{
    if (!bn.has_value() || !group.has_value())
    {
        GetLogger()->debug(
            "try_subtract_reduce_mod_group_order called with uninitialized BIGNUM, EC_GROUP, or BN_CTX.");
        return std::nullopt;
    }

    if (!ensure_bcg_set(bcg, bn.is_secure()))
    {
        GetLogger()->err("try_subtract_reduce_mod_group_order failed to obtain BN_CTX.");
        return std::nullopt;
    }

    const BIGNUM *order = EC_GROUP_get0_order(group.get());
    if (nullptr == order)
    {
        GetLogger()->err("Failed to get group order from EC_GROUP.");
        return std::nullopt;
    }

    if (0 > BN_cmp(bn.get(), order))
    {
        // bn is already reduced
        return true;
    }

    if (1 != BN_sub(bn.get(), bn.get(), order))
    {
        GetLogger()->err("Call to BN_sub failed in try_subtract_reduce_mod_group_order.");
        return std::nullopt;
    }

    return (0 > BN_cmp(bn.get(), order));
}

bool reduce_mod_group_order(BIGNUM_Guard &bn, const EC_GROUP_Guard &group, BN_CTX_Guard &bcg)
{
    // First try the fast path of a single subtraction.
    std::optional<bool> try_quick = try_subtract_reduce_mod_group_order(bn, group, bcg);
    if (!try_quick.has_value())
    {
        return false;
    }
    else if (*try_quick)
    {
        return true;
    }

    if (!bn.has_value() || !group.has_value())
    {
        GetLogger()->debug("reduce_mod_group_order called with uninitialized BIGNUM, EC_GROUP, or BN_CTX.");
        return false;
    }

    if (!ensure_bcg_set(bcg, bn.is_secure()))
    {
        GetLogger()->err("reduce_mod_group_order failed to obtain BN_CTX.");
        return false;
    }

    const BIGNUM *order = EC_GROUP_get0_order(group.get());
    if (nullptr == order)
    {
        GetLogger()->err("Failed to get group order from EC_GROUP.");
        return false;
    }

    BIGNUM_Guard bn_temp{bn.is_secure()};
    if (!bn_temp.has_value())
    {
        GetLogger()->err("Failed to create temporary BN_CTX or BIGNUM for reduce_mod_group_order.");
        return false;
    }

    if (1 != BN_nnmod(bn_temp.get(), bn.get(), order, bcg.get()) || nullptr == BN_copy(bn.get(), bn_temp.get()))
    {
        GetLogger()->err("Call to BN_mod or BN_copy failed in reduce_mod_group_order.");
        return false;
    }

    return true;
}

} // namespace

ScalarType::ScalarType(BIGNUM_Guard &&bn) : scalar_{}
{
    if (!bn.has_value())
    {
        GetLogger()->debug("ScalarType constructor called with uninitialized BIGNUM_Guard.");
        return;
    }
    scalar_ = std::move(bn);
}

ScalarType::ScalarType(bool secure) : scalar_{}
{
    scalar_ = BIGNUM_Guard{secure};
    if (!scalar_.has_value())
    {
        GetLogger()->debug("Failed to allocate BIGNUM in ScalarType constructor.");
    }
}

ScalarType &ScalarType::operator=(const ScalarType &assign)
{
    if (this != &assign)
    {
        BIGNUM_Guard bn_copy{};
        bool success = true;
        if (assign.has_value())
        {
            bn_copy = BIGNUM_Guard{BN_dup(assign.scalar_.get()), true};
            success = bn_copy.has_value();
        }

        if (!success)
        {
            GetLogger()->err("Failed to copy BIGNUM in ScalarType copy assignment.");
            return *this;
        }
        else
        {
            using std::swap;
            swap(scalar_, bn_copy);
        }
    }

    return *this;
}

void ScalarType::set_zero() noexcept
{
    if (has_value())
    {
        BN_zero(scalar_.get());
    }
}

bool ScalarType::is_zero() const noexcept
{
    return !has_value() || 1 == BN_is_zero(scalar_.get());
}

bool ScalarType::set_random(const EC_GROUP_Guard &group)
{
    if (!has_value() || !group.has_value())
    {
        GetLogger()->debug("set_random called with uninitialized ScalarType or EC_GROUP.");
        return false;
    }

    const bool secure = is_secure();
    BN_CTX_Guard bcg{secure};
    if (!bcg.has_value())
    {
        GetLogger()->err("Failed to create temporary BN_CTX in set_random.");
        return false;
    }

    const int group_order_bits = EC_GROUP_order_bits(group.get());
    const int random_bits = 2 * group_order_bits; // Double the bits to reduce bias.
    const unsigned prg_strength = static_cast<unsigned>(group_order_bits / 2);
    BIGNUM_Guard bn_temp{secure};
    if (1 != BN_priv_rand_ex(bn_temp.get(), random_bits, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY, prg_strength, bcg.get()))
    {
        GetLogger()->err("Call to BN_priv_rand_ex failed in set_random.");
        return false;
    }

    if (!reduce_mod_group_order(bn_temp, group, bcg))
    {
        GetLogger()->debug("Failed to reduce random value mod group order in set_random.");
        return false;
    }

    // All good. Set the value.
    using std::swap;
    swap(scalar_, bn_temp);

    GetLogger()->trace("set_random generated random scalar with {} bits and reduced mod group order.", random_bits);
    return true;
}

ScalarType &ScalarType::ScalarType::operator=(ScalarType &&rhs) noexcept
{
    if (this != &rhs)
    {
        using std::swap;
        swap(scalar_, rhs.scalar_);
    }
    return *this;
}

bool ScalarType::negate(const EC_GROUP_Guard &group, BN_CTX_Guard &bcg)
{
    if (!has_value() || !group.has_value())
    {
        GetLogger()->debug("negate called with uninitialized ScalarType or EC_GROUP.");
        return false;
    }

    const bool secure = is_secure();
    if (!ensure_bcg_set(bcg, secure))
    {
        GetLogger()->err("Failed to ensure BN_CTX is available for negate.");
        return false;
    }

    const BIGNUM *order = EC_GROUP_get0_order(group.get());
    if (nullptr == order)
    {
        GetLogger()->err("Failed to get group order from EC_GROUP in negate.");
        return false;
    }

    if (1 == BN_is_zero(scalar_.get()))
    {
        return true;
    }
    if (0 <= BN_cmp(scalar_.get(), order))
    {
        if (!reduce_mod_group_order(scalar_, group, bcg))
        {
            GetLogger()->debug("Failed to reduce scalar mod group order in negate.");
            return false;
        }
    }

    BIGNUM_Guard bn_temp{secure};
    if (!bn_temp.has_value())
    {
        GetLogger()->err("Failed to create temporary BIGNUM for negate.");
        return false;
    }

    // bn_temp = order - scalar_
    if (1 != BN_sub(bn_temp.get(), order, scalar_.get()))
    {
        GetLogger()->err("Call to BN_sub failed in negate.");
        return false;
    }

    if (nullptr == BN_copy(scalar_.get(), bn_temp.get()))
    {
        GetLogger()->err("Call to BN_copy failed in negate.");
        return false;
    }

    return true;
}

bool ScalarType::add(const ScalarType &rhs, const EC_GROUP_Guard &group, BN_CTX_Guard &bcg)
{
    if (!has_value() || !rhs.has_value() || !group.has_value())
    {
        GetLogger()->debug("add called with uninitialized ScalarType or EC_GROUP.");
        return false;
    }

    const bool secure = is_secure();
    if (!ensure_bcg_set(bcg, secure))
    {
        GetLogger()->err("Failed to ensure BN_CTX is available for add.");
        return false;
    }

    const BIGNUM *order = EC_GROUP_get0_order(group.get());
    if (nullptr == order)
    {
        GetLogger()->err("Failed to get group order from EC_GROUP in add.");
        return false;
    }

    if (0 <= BN_cmp(scalar_.get(), order) || 0 <= BN_cmp(rhs.scalar_.get(), order))
    {
        BIGNUM_Guard bn_temp{secure};
        if (1 != BN_mod_add(bn_temp.get(), scalar_.get(), rhs.scalar_.get(), order, bcg.get()) ||
            nullptr == BN_copy(scalar_.get(), bn_temp.get()))
        {
            GetLogger()->err("Call to BN_mod_add or BN_copy failed in add.");
            return false;
        }
    }
    else
    {
        // Both scalars are < order, so we can just add and conditionally subtract order.
        if (1 != BN_add(scalar_.get(), scalar_.get(), rhs.scalar_.get()) ||
            !reduce_mod_group_order(scalar_, group, bcg))
        {
            GetLogger()->err("Call to BN_add or reduce_mod_group_order failed in add.");
            return false;
        }
    }

    return true;
}

bool ScalarType::subtract(const ScalarType &rhs, const EC_GROUP_Guard &group, BN_CTX_Guard &bcg)
{
    if (!has_value() || !rhs.has_value() || !group.has_value())
    {
        GetLogger()->debug("subtract called with uninitialized ScalarType or EC_GROUP.");
        return false;
    }

    const bool secure = is_secure();
    if (!ensure_bcg_set(bcg, secure))
    {
        GetLogger()->err("Failed to ensure BN_CTX is available for subtract.");
        return false;
    }

    const BIGNUM *order = EC_GROUP_get0_order(group.get());
    if (nullptr == order)
    {
        GetLogger()->err("Failed to get group order from EC_GROUP in subtract.");
        return false;
    }

    if (0 <= BN_cmp(scalar_.get(), rhs.scalar_.get()))
    {
        if (1 != BN_sub(scalar_.get(), scalar_.get(), rhs.scalar_.get()))
        {
            GetLogger()->err("Call to BN_sub failed in subtract.");
            return false;
        }
    }
    else
    {
        // scalar_ < rhs.scalar_, so we need to add order first.
        if (1 != BN_add(scalar_.get(), scalar_.get(), order) ||
            1 != BN_sub(scalar_.get(), scalar_.get(), rhs.scalar_.get()))
        {
            GetLogger()->err("Call to BN_add or BN_sub failed in subtract.");
            return false;
        }
    }

    // Finally, ensure the result is reduced mod order.
    if (!reduce_mod_group_order(scalar_, group, bcg))
    {
        GetLogger()->debug("Failed to reduce scalar mod group order in subtract.");
        return false;
    }

    return true;
}

bool ScalarType::multiply(const ScalarType &rhs, const EC_GROUP_Guard &group, BN_CTX_Guard &bcg)
{
    if (!has_value() || !rhs.has_value() || !group.has_value())
    {
        GetLogger()->debug("multiply called with uninitialized ScalarType or EC_GROUP.");
        return false;
    }

    const bool secure = is_secure();
    if (!ensure_bcg_set(bcg, secure))
    {
        GetLogger()->err("Failed to ensure BN_CTX is available for multiply.");
        return false;
    }

    const BIGNUM *order = EC_GROUP_get0_order(group.get());
    if (nullptr == order)
    {
        GetLogger()->err("Failed to get group order from EC_GROUP in multiply.");
        return false;
    }

    BIGNUM_Guard bn_temp{secure};
    if (!bn_temp.has_value())
    {
        GetLogger()->err("Failed to create temporary BIGNUM for multiply.");
        return false;
    }

    if (1 != BN_mod_mul(bn_temp.get(), scalar_.get(), rhs.scalar_.get(), order, bcg.get()) ||
        nullptr == BN_copy(scalar_.get(), bn_temp.get()))
    {
        GetLogger()->err("Call to BN_mod_mul or BN_copy failed in multiply.");
        return false;
    }

    return true;
}

bool ScalarType::reduce_mod_order(const EC_GROUP_Guard &group, BN_CTX_Guard &bcg)
{
    if (!reduce_mod_group_order(scalar_, group, bcg))
    {
        GetLogger()->debug("Failed to reduce scalar mod group order in reduce_mod_order.");
        return false;
    }

    return true;
}

bool ScalarType::ScalarType::operator==(const ScalarType &rhs) const
{
    if (this == &rhs)
    {
        return true;
    }
    if (!has_value() || !rhs.has_value())
    {
        return false;
    }

    const BIGNUM *bn_this = scalar_.get();
    const BIGNUM *bn_rhs = rhs.scalar_.get();
    return (0 == BN_cmp(bn_this, bn_rhs));
}

ECPoint::ECPoint(const EC_GROUP_Guard &group, SpecialPoint set_to)
{
    EC_POINT_Guard pt{group};
    if (!pt.has_value())
    {
        GetLogger()->debug("Failed to create EC_POINT in ECPoint constructor.");
        return;
    }

    if (SpecialPoint::GENERATOR == set_to)
    {
        const EC_POINT *gen = EC_GROUP_get0_generator(group.get());
        if (1 != EC_POINT_copy(pt.get(), gen))
        {
            GetLogger()->err("Call to EC_POINT_copy failed in ECPoint constructor.");
            return;
        }
    }

    pt_ = std::move(pt);
}

ECPoint::ECPoint(EC_POINT_Guard &&source) : pt_{}
{
    if (!source.has_value())
    {
        GetLogger()->debug("ECPoint constructor called with uninitialized EC_POINT_Guard.");
        return;
    }
    pt_ = std::move(source);
}

ECPoint &ECPoint::operator=(const ECPoint &assign)
{
    if (this != &assign)
    {
        EC_POINT_Guard pt_copy{};
        bool success = true;
        if (assign.has_value())
        {
            // Retrieve EC_GROUP based on assign.get().get_nid().
            const EC_GROUP_Guard group{assign.pt_.get_curve()};

            // Make a copy of the point and set.
            EC_POINT *ec_pt = EC_POINT_dup(assign.pt_.get(), group.get());
            if (nullptr == ec_pt)
            {
                GetLogger()->err("EC_POINT_dup failed in ECPoint copy assignment.");
                return *this;
            }

            BN_CTX_Guard bcg{false};
            pt_copy = EC_POINT_Guard{assign.pt_.get_curve(), ec_pt, bcg};
            success = pt_copy.has_value();
        }

        if (!success)
        {
            GetLogger()->err("Failed to copy EC_POINT in ECPoint copy assignment.");
            return *this;
        }
        else
        {
            using std::swap;
            swap(pt_, pt_copy);
        }
    }

    return *this;
}

ECPoint &ECPoint::operator=(ECPoint &&source) noexcept
{
    if (this != &source)
    {
        using std::swap;
        swap(pt_, source.pt_);
    }
    return *this;
}

bool ECPoint::double_scalar_multiply(const EC_GROUP_Guard &group, const ScalarType &scalar1, const ScalarType &scalar2,
                                     BN_CTX_Guard &bcg)
{
    // Computes scalar1*this + scalar2*generator

    if (!group.has_value() || group.get_curve() != get_curve())
    {
        GetLogger()->debug("double_scalar_multiply called with uninitialized EC_GROUP or mismatched EC_GROUP.");
        return false;
    }

    // We require that at least one of the scalar inputs has a value.
    if (!scalar1.has_value() && !scalar2.has_value())
    {
        GetLogger()->debug("double_scalar_multiply called with both scalars uninitialized.");
        return false;
    }

    const bool secure = (scalar1.has_value() && scalar1.is_secure()) || (scalar2.has_value() && scalar2.is_secure());
    if (!ensure_bcg_set(bcg, secure))
    {
        GetLogger()->err("double_scalar_multiply failed to obtain BN_CTX.");
        return false;
    }

    if (1 != EC_POINT_mul(group.get(), pt_.get(), scalar2.get().get(), pt_.get(), scalar1.get().get(), bcg.get()))
    {
        GetLogger()->err("Call to EC_POINT_mul failed in double_scalar_multiply.");
        return false;
    }

    return true;
}

bool ECPoint::scalar_multiply(const EC_GROUP_Guard &group, const ScalarType &scalar, BN_CTX_Guard &bcg)
{
    return double_scalar_multiply(group, scalar, ScalarType{}, bcg);
}

bool ECPoint::set_to_generator_multiple(const EC_GROUP_Guard &group, const ScalarType &scalar, BN_CTX_Guard &bcg)
{
    return double_scalar_multiply(group, ScalarType{}, scalar, bcg);
}

bool ECPoint::add(const EC_GROUP_Guard &group, const ECPoint &other, BN_CTX_Guard &bcg)
{
    if (!has_value() || !other.has_value() || !group.has_value() || get_curve() != other.get_curve() ||
        group.get_curve() != get_curve())
    {
        GetLogger()->debug("add called with uninitialized ECPoint or mismatched curves.");
        return false;
    }

    if (!ensure_bcg_set(bcg, false))
    {
        GetLogger()->err("add failed to obtain BN_CTX.");
        return false;
    }

    if (1 != EC_POINT_add(group.get(), pt_.get(), pt_.get(), other.pt_.get(), bcg.get()))
    {
        GetLogger()->err("Call to EC_POINT_add failed in add.");
        return false;
    }

    return true;
}

bool ECPoint::negate(const EC_GROUP_Guard &group, BN_CTX_Guard &bcg)
{
    if (!has_value() || !group.has_value() || group.get_curve() != get_curve())
    {
        GetLogger()->debug("negate called with uninitialized ECPoint or mismatched curves.");
        return false;
    }

    if (!ensure_bcg_set(bcg, false))
    {
        GetLogger()->err("subtract failed to obtain BN_CTX.");
        return false;
    }

    if (1 != EC_POINT_invert(group.get(), pt_.get(), bcg.get()))
    {
        GetLogger()->err("Call to EC_POINT_invert failed in negate.");
        return false;
    }

    return true;
}

} // namespace vrf::ec
