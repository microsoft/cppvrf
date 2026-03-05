// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "vrf/common.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <utility>

namespace vrf
{

class EVP_PKEY_Guard
{
  public:
    EVP_PKEY_Guard() = default;

    explicit EVP_PKEY_Guard(EVP_PKEY *pkey) : pkey_{pkey} {};

    void free() noexcept
    {
        if (nullptr != pkey_)
        {
            EVP_PKEY_free(pkey_);
            pkey_ = nullptr;
        }
    }

    [[nodiscard]]
    EVP_PKEY **free_and_get_addr() noexcept
    {
        free();
        return &pkey_;
    }

    ~EVP_PKEY_Guard()
    {
        free();
    }

    EVP_PKEY_Guard(const EVP_PKEY_Guard &) = delete;

    EVP_PKEY_Guard &operator=(EVP_PKEY_Guard &&rhs) noexcept
    {
        if (this != &rhs)
        {
            using std::swap;
            swap(pkey_, rhs.pkey_);
        }
        return *this;
    }

    EVP_PKEY_Guard(EVP_PKEY_Guard &&source) noexcept
    {
        *this = std::move(source);
    }

    EVP_PKEY_Guard &operator=(const EVP_PKEY_Guard &) = delete;

    [[nodiscard]]
    EVP_PKEY_Guard clone() const
    {
        return EVP_PKEY_Guard{upref()};
    }

    friend void swap(EVP_PKEY_Guard &first, EVP_PKEY_Guard &second) noexcept
    {
        using std::swap;
        swap(first.pkey_, second.pkey_);
    }

    [[nodiscard]]
    EVP_PKEY *get() noexcept
    {
        return pkey_;
    }

    [[nodiscard]]
    const EVP_PKEY *get() const noexcept
    {
        return pkey_;
    }

    [[nodiscard]]
    bool has_value() const noexcept
    {
        return nullptr != pkey_;
    }

  private:
    [[nodiscard]]
    EVP_PKEY *upref() const
    {
        return evp_pkey_upref(pkey_);
    }

    EVP_PKEY *pkey_ = nullptr;
};

class EVP_PKEY_CTX_Guard
{
  public:
    EVP_PKEY_CTX_Guard() = default;

    explicit EVP_PKEY_CTX_Guard(EVP_PKEY_CTX *pkey_ctx) : pkey_ctx_{pkey_ctx} {};

    void free() noexcept
    {
        if (nullptr != pkey_ctx_)
        {
            EVP_PKEY_CTX_free(pkey_ctx_);
            pkey_ctx_ = nullptr;
        }
    }

    [[nodiscard]]
    EVP_PKEY_CTX **free_and_get_addr() noexcept
    {
        free();
        return &pkey_ctx_;
    }

    ~EVP_PKEY_CTX_Guard()
    {
        free();
    }

    EVP_PKEY_CTX_Guard(const EVP_PKEY_CTX_Guard &) = delete;

    EVP_PKEY_CTX_Guard(EVP_PKEY_CTX_Guard &&) = delete;

    EVP_PKEY_CTX_Guard &operator=(const EVP_PKEY_CTX_Guard &) = delete;

    EVP_PKEY_CTX_Guard &operator=(EVP_PKEY_CTX_Guard &&) = delete;

    [[nodiscard]]
    EVP_PKEY_CTX *get() noexcept
    {
        return pkey_ctx_;
    }

    [[nodiscard]]
    const EVP_PKEY_CTX *get() const noexcept
    {
        return pkey_ctx_;
    }

    [[nodiscard]]
    bool has_value() const noexcept
    {
        return nullptr != pkey_ctx_;
    }

  private:
    EVP_PKEY_CTX *pkey_ctx_ = nullptr;
};

class MD_CTX_Guard
{
  public:
    explicit MD_CTX_Guard(bool oneshot_only);

    ~MD_CTX_Guard()
    {
        EVP_MD_CTX_free(mctx_);
        mctx_ = nullptr;
    }

    MD_CTX_Guard(const MD_CTX_Guard &) = delete;

    MD_CTX_Guard(MD_CTX_Guard &&) = delete;

    MD_CTX_Guard &operator=(const MD_CTX_Guard &) = delete;

    MD_CTX_Guard &operator=(MD_CTX_Guard &&) = delete;

    [[nodiscard]]
    EVP_MD_CTX *get() noexcept
    {
        return mctx_;
    }

    [[nodiscard]]
    const EVP_MD_CTX *get() const noexcept
    {
        return mctx_;
    }

    [[nodiscard]]
    bool has_value() const noexcept
    {
        return nullptr != mctx_;
    }

  private:
    EVP_MD_CTX *mctx_ = nullptr;
};

class EC_GROUP_Guard
{
  public:
    EC_GROUP_Guard() = default;

    explicit EC_GROUP_Guard(Curve curve);

    EC_GROUP_Guard &operator=(const EC_GROUP_Guard &) = delete;

    EC_GROUP_Guard &operator=(EC_GROUP_Guard &&) noexcept;

    EC_GROUP_Guard(const EC_GROUP_Guard &);

    EC_GROUP_Guard(EC_GROUP_Guard &&rhs) noexcept
    {
        *this = std::move(rhs);
    }

    ~EC_GROUP_Guard()
    {
        free();
    }

    [[nodiscard]]
    EC_GROUP *get() noexcept
    {
        return ec_group_;
    }

    [[nodiscard]]
    const EC_GROUP *get() const noexcept
    {
        return ec_group_;
    }

    [[nodiscard]]
    Curve get_curve() const noexcept
    {
        return curve_;
    }

    [[nodiscard]]
    bool has_value() const noexcept
    {
        return nullptr != ec_group_ && Curve::UNDEFINED != curve_;
    }

    void free() noexcept;

  private:
    EC_GROUP *ec_group_ = nullptr;

    Curve curve_ = Curve::UNDEFINED;
};

class BIGNUM_Guard
{
  public:
    BIGNUM_Guard() = default;

    explicit BIGNUM_Guard(bool secure);

    BIGNUM_Guard(BIGNUM *bn, bool owned) : bn_(bn), owned_(owned)
    {
    }

    BIGNUM_Guard &operator=(const BIGNUM_Guard &) = delete;

    BIGNUM_Guard &operator=(BIGNUM_Guard &&) noexcept;

    BIGNUM_Guard(const BIGNUM_Guard &) = delete;

    BIGNUM_Guard(BIGNUM_Guard &&rhs) noexcept
    {
        *this = std::move(rhs);
    }

    ~BIGNUM_Guard()
    {
        free();
    }

    [[nodiscard]]
    BIGNUM **free_and_get_addr(bool owned) noexcept;

    [[nodiscard]]
    BIGNUM *get()
    {
        return bn_;
    }

    [[nodiscard]]
    const BIGNUM *get() const
    {
        return bn_;
    }

    [[nodiscard]]
    bool is_secure() const noexcept;

    [[nodiscard]]
    bool has_value() const noexcept
    {
        return nullptr != bn_;
    }

    void free() noexcept;

  private:
    BIGNUM *bn_ = nullptr;

    bool owned_ = true;
};

class BN_CTX_Guard
{
  public:
    BN_CTX_Guard() = default;

    explicit BN_CTX_Guard(bool secure);

    BN_CTX_Guard &operator=(const BN_CTX_Guard &) = delete;

    BN_CTX_Guard &operator=(BN_CTX_Guard &&) noexcept;

    BN_CTX_Guard(const BN_CTX_Guard &) = delete;

    BN_CTX_Guard(BN_CTX_Guard &&rhs) noexcept
    {
        *this = std::move(rhs);
    }

    ~BN_CTX_Guard()
    {
        free();
    }

    [[nodiscard]]
    BN_CTX *get()
    {
        return bcg_;
    }

    [[nodiscard]]
    const BN_CTX *get() const
    {
        return bcg_;
    }

    [[nodiscard]]
    bool is_secure() const noexcept
    {
        return secure_;
    }

    [[nodiscard]]
    bool has_value() const noexcept
    {
        return nullptr != bcg_;
    }

    [[nodiscard]]
    bool has_value(bool secure) const noexcept
    {
        return nullptr != bcg_ && secure_ == secure;
    }

    void free() noexcept;

  private:
    BN_CTX *bcg_ = nullptr;

    bool secure_ = false;
};

class EC_POINT_Guard
{
  public:
    EC_POINT_Guard() = default;

    EC_POINT_Guard(Curve curve, EC_POINT *ec_pt, BN_CTX_Guard &bcg);

    explicit EC_POINT_Guard(const EC_GROUP_Guard &group);

    EC_POINT_Guard &operator=(const EC_POINT_Guard &) = delete;

    EC_POINT_Guard &operator=(EC_POINT_Guard &&) noexcept;

    EC_POINT_Guard(const EC_POINT_Guard &) = delete;

    EC_POINT_Guard(EC_POINT_Guard &&rhs) noexcept
    {
        *this = std::move(rhs);
    }

    ~EC_POINT_Guard()
    {
        free();
    }

    [[nodiscard]]
    EC_POINT *get()
    {
        return ec_pt_;
    }

    [[nodiscard]]
    const EC_POINT *get() const
    {
        return ec_pt_;
    }

    [[nodiscard]]
    Curve get_curve() const noexcept
    {
        return curve_;
    }

    [[nodiscard]]
    bool has_value() const noexcept
    {
        return nullptr != ec_pt_ && Curve::UNDEFINED != curve_;
    }

    void free() noexcept;

  private:
    EC_POINT *ec_pt_ = nullptr;

    Curve curve_ = Curve::UNDEFINED;
};

bool ensure_bcg_set(BN_CTX_Guard &bcg, bool secure);

} // namespace vrf
