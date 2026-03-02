// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "vrf/secure_buf.h"
#include "vrf/log.h"
#include <openssl/crypto.h>

namespace vrf
{

SecureBuf::SecureBuf(std::size_t size)
{
    if (0 == size)
    {
        return;
    }

    std::byte *buf = static_cast<std::byte *>(OPENSSL_secure_malloc(size));
    if (nullptr != buf)
    {
        buf_ = buf;
        size_ = size;
    }

    GetLogger()->trace("SecureBuf allocated buffer of size {} at address {:p}.", size, static_cast<const void *>(buf_));
}

SecureBuf &SecureBuf::operator=(SecureBuf &&rhs) noexcept
{
    if (this != &rhs)
    {
        using std::swap;
        swap(size_, rhs.size_);
        swap(buf_, rhs.buf_);
    }
    return *this;
}

SecureBuf::~SecureBuf()
{
    const void *buf_addr = static_cast<const void *>(buf_);
    OPENSSL_secure_clear_free(buf_, size_);
    size_ = 0;
    buf_ = nullptr;

    GetLogger()->trace("SecureBuf at address {:p} securely cleared and freed.", buf_addr);
}

void SecureBuf::Cleanse(void *ptr, std::size_t size)
{
    OPENSSL_cleanse(ptr, size);
    GetLogger()->trace("Cleansed {} bytes at address {:p}.", size, ptr);
}

} // namespace vrf
