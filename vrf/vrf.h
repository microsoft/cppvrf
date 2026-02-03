// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "vrf/vrf_base.h"
#include <span>

namespace vrf
{

/**
 * The main VRF class that encapsulates VRF operations. All functions are static.
 */
class VRF
{
  public:
    VRF() = delete;

    /**
     * Creates a new VRF secret key for the specified VRF type. Returns a unique pointer to the created
     * secret key object, or nullptr if key generation fails.
     */
    [[nodiscard]]
    static std::unique_ptr<SecretKey> Create(Type type);

    /**
     * Deserializes a VRF proof from a span of bytes for the specified VRF type. Returns a unique
     * pointer to the deserialized proof object, or nullptr if deserialization fails.
     */
    [[nodiscard]]
    static std::unique_ptr<Proof> ProofFromBytes(Type type, std::span<const std::byte> data);

    /**
     * Deserializes a VRF proof from a span of bytes for the specified VRF type. Returns a unique
     * pointer to the deserialized proof object, or nullptr if deserialization fails.
     */
    template <ByteLike T, std::size_t N = std::dynamic_extent>
        requires(!std::same_as<std::remove_cv_t<T>, std::byte>)
    [[nodiscard]]
    static std::unique_ptr<Proof> ProofFromBytes(Type type, std::span<const T, N> data)
    {
        return ProofFromBytes(type, std::as_bytes(data));
    }

    /**
     * Deserializes a VRF proof from a contiguous range of bytes for the specified VRF type. Returns
     * a unique pointer to the deserialized proof object, or nullptr if deserialization fails.
     */
    template <ByteRange R>
    [[nodiscard]]
    static std::unique_ptr<Proof> ProofFromBytes(Type type, R &&data)
    {
        return ProofFromBytes(type, byte_range_to_span(data));
    }

    /**
     * Deserializes a VRF public key from a span of bytes for the specified VRF type. Returns a unique
     * pointer to the deserialized public key object, or nullptr if deserialization fails.
     */
    [[nodiscard]]
    static std::unique_ptr<PublicKey> PublicKeyFromBytes(Type type, std::span<const std::byte> data);

    /**
     * Deserializes a VRF public key from a span of bytes for the specified VRF type. Returns a unique
     * pointer to the deserialized public key object, or nullptr if deserialization fails.
     */
    template <ByteLike T, std::size_t N = std::dynamic_extent>
        requires(!std::same_as<std::remove_cv_t<T>, std::byte>)
    [[nodiscard]]
    static std::unique_ptr<PublicKey> PublicKeyFromBytes(Type type, std::span<const T, N> data)
    {
        return PublicKeyFromBytes(type, std::as_bytes(data));
    }

    /**
     * Deserializes a VRF public key from a contiguous range of bytes for the specified VRF type. Returns
     * a unique pointer to the deserialized public key object, or nullptr if deserialization fails.
     */
    template <ByteRange R>
    [[nodiscard]]
    static std::unique_ptr<PublicKey> PublicKeyFromBytes(Type type, R &&data)
    {
        return PublicKeyFromBytes(type, byte_range_to_span(data));
    }

    /**
     * Deserializes a VRF secret key from a span of bytes for the specified VRF type. Returns a unique
     * pointer to the deserialized secret key object, or nullptr if deserialization fails.
     */
    [[nodiscard]]
    static std::unique_ptr<SecretKey> SecretKeyFromBytes(Type type, std::span<const std::byte> data);

    /**
     * Deserializes a VRF secret key from a span of bytes for the specified VRF type. Returns a unique
     * pointer to the deserialized secret key object, or nullptr if deserialization fails.
     */
    template <ByteLike T, std::size_t N = std::dynamic_extent>
        requires(!std::same_as<std::remove_cv_t<T>, std::byte>)
    [[nodiscard]]
    static std::unique_ptr<SecretKey> SecretKeyFromBytes(Type type, std::span<const T, N> data)
    {
        return SecretKeyFromBytes(type, std::as_bytes(data));
    }

    /**
     * Deserializes a VRF secret key from a contiguous range of bytes for the specified VRF type. Returns
     * a unique pointer to the deserialized secret key object, or nullptr if deserialization fails.
     */
    template <ByteRange R>
    [[nodiscard]]
    static std::unique_ptr<SecretKey> SecretKeyFromBytes(Type type, R &&data)
    {
        return SecretKeyFromBytes(type, byte_range_to_span(data));
    }
};

} // namespace vrf
