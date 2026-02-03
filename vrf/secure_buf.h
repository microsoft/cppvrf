// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <cstddef>
#include <span>
#include <utility>

namespace vrf
{

/**
 * SecureBuf is a simple wrapper for buffers allocated with OPENSSL_secure_malloc. SecureBuf is move-only;
 * copying is deleted to prevent accidental duplication of secrets. On move, the source is left in a safe empty
 * state. On destruction, the memory is securely zeroed and freed.
 */
class SecureBuf
{
  public:
    SecureBuf() = default;

    explicit SecureBuf(std::size_t size);

    SecureBuf(const SecureBuf &) = delete;

    SecureBuf &operator=(const SecureBuf &) = delete;

    SecureBuf &operator=(SecureBuf &&rhs) noexcept;

    SecureBuf(SecureBuf &&other) noexcept : size_(0), buf_(nullptr)
    {
        *this = std::move(other);
    }

    // Destructor securely zeros the buffer via OPENSSL_secure_clear_free before releasing it.
    ~SecureBuf();

    bool has_value() const noexcept
    {
        return nullptr != buf_ && size_ > 0;
    }

    [[nodiscard]]
    operator std::span<std::byte>() & noexcept
    {
        return {buf_, size_};
    }
    [[nodiscard]]
    operator std::span<const std::byte>() const & noexcept
    {
        return {buf_, size_};
    }

    // Prevent implicit conversion to span on temporaries, which would create a dangling span.
    operator std::span<std::byte>() && = delete;

    operator std::span<const std::byte>() && = delete;

    [[nodiscard]]
    std::size_t size() const noexcept
    {
        return size_;
    }

    [[nodiscard]]
    std::byte *get() noexcept
    {
        return buf_;
    }

    [[nodiscard]]
    const std::byte *get() const noexcept
    {
        return buf_;
    }

    // Securely zeroes the given memory region using OPENSSL_cleanse.
    static void Cleanse(void *ptr, std::size_t size);

  private:
    std::size_t size_ = 0;

    std::byte *buf_ = nullptr;
};

} // namespace vrf
