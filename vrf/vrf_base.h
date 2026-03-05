// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "vrf/secure_buf.h"
#include "vrf/type.h"
#include <algorithm>
#include <cstddef>
#include <memory>
#include <span>
#include <type_traits>
#include <vector>

namespace vrf
{

/**
 * Concept representing types that can be treated as single bytes. This is only used for serialization.
 * Internally, all binary data is handled as std::byte arrays.
 */
template <typename T>
concept ByteLike = std::is_trivially_copyable_v<T> && !std::is_reference_v<T> && sizeof(T) == 1 &&
                   !std::same_as<std::remove_cv_t<T>, bool>;

/**
 * Concept representing ranges of byte-like elements that can be treated as contiguous byte arrays.
 * This is only used for serialization. Internally, all binary data is handled as std::byte arrays.
 */
template <typename R>
concept ByteRange =
    std::ranges::contiguous_range<R> && ByteLike<std::ranges::range_value_t<R>> && std::ranges::sized_range<R>;

/**
 * Converts a byte range to a span of const bytes. Importantly, the input range is passed by reference
 * to ensure that temporary ranges are not accepted. Otherwise, the returned span would point to destroyed
 * data. The caller must ensure that the input range remains valid while the returned span is used.
 */
template <ByteRange R>
inline auto byte_range_to_span(R &in) noexcept -> std::span<const std::remove_cv_t<std::ranges::range_value_t<R>>>
{
    using elt_t = std::remove_cv_t<std::ranges::range_value_t<R>>;
    const elt_t *const data = std::ranges::data(in);
    const auto size = std::ranges::size(in);
    return std::span<const elt_t>{data, size};
};

/**
 * Abstract base class representing a VRF object associated with a specific VRF type. This class provides
 * common functionality for VRF-related objects such as secret keys, public keys, and proofs.
 */
template <typename T> class VRFObject
{
  public:
    virtual ~VRFObject() = default;

    /**
     * Checks whether this object is properly initialized.
     */
    [[nodiscard]]
    virtual bool is_initialized() const noexcept = 0;

    /**
     * Returns the VRF type associated with this object. For the full list of supported types,
     * see vrf::Type in vrf/type.h.
     */
    [[nodiscard]]
    Type get_type() const noexcept
    {
        return type_;
    }

    VRFObject &operator=(const VRFObject<T> &) = delete;

    VRFObject(VRFObject<T> &&) = delete;

    VRFObject &operator=(VRFObject<T> &&) = delete;

  protected:
    VRFObject() = default; // NOLINT(bugprone-crtp-constructor-accessibility)

    explicit VRFObject(Type type) : type_(type) {}; // NOLINT(bugprone-crtp-constructor-accessibility)

    VRFObject(const VRFObject<T> &) = default; // NOLINT(bugprone-crtp-constructor-accessibility)

    /**
     * Sets the VRF type for this object.
     */
    void set_type(Type type) noexcept
    {
        type_ = type;
    }

  private:
    Type type_ = Type::UNKNOWN;
};

/**
 * Abstract base class representing a clonable VRF object. Derived classes must implement the clone() method
 * to return a unique pointer to a new instance of the derived type.
 */
// NOLINTNEXTLINE(bugprone-crtp-constructor-accessibility)
template <typename T> class Clonable
{
  public:
    virtual ~Clonable() = default;

    /**
     * Creates a deep copy of this object and returns it as a unique pointer.
     */
    [[nodiscard]]
    virtual std::unique_ptr<T> clone() const = 0;
};

/**
 * Abstract base class representing a serializable VRF object. Derived classes must implement the to_bytes()
 * and from_bytes() methods for serialization and deserialization.
 */
class Serializable
{
  public:
    virtual ~Serializable() = default;

    /**
     * Serializes the object into a vector of bytes.
     */
    [[nodiscard]]
    virtual std::vector<std::byte> to_bytes() const = 0;

    /**
     * Serializes the object into a SecureBuf. The default implementation calls to_bytes() and copies
     * the result into secure memory. Derived classes handling secret key material must override this
     * to avoid the intermediate non-secure allocation.
     */
    [[nodiscard]]
    virtual SecureBuf to_secure_bytes() const
    {
        std::vector<std::byte> bytes = to_bytes();

        SecureBuf buf{bytes.size()};
        if (buf.has_value())
        {
            std::copy_n(bytes.data(), bytes.size(), buf.get());
        }

        // Clean up the std::vector.
        SecureBuf::Cleanse(bytes.data(), bytes.size());

        return buf;
    }

    /**
     * Deserializes an object from a span of bytes. Deserialization failure is indicated by checking the output of
     * VRFObject::is_initialized().
     */
    virtual void from_bytes(std::span<const std::byte> data) = 0;

    /**
     * Deserializes an object from a span of byte-like elements. Deserialization failure is indicated by checking the
     * output of VRFObject::is_initialized().
     */
    template <ByteLike T, std::size_t N = std::dynamic_extent>
        requires(!std::same_as<std::remove_cv_t<T>, std::byte>)
    void from_bytes(std::span<const T, N> data)
    {
        from_bytes(std::as_bytes(data));
    }

    /**
     * Deserializes an object from a byte range. Deserialization failure is indicated by checking the output of
     * VRFObject::is_initialized().
     */
    template <ByteRange R> void from_bytes(R &&data)
    {
        from_bytes(byte_range_to_span(data));
    }
};

/**
 * Abstract base class representing a VRF proof object. The proof object can be serialized to and
 * deserialized from a byte array. It can also be used to extract the VRF value itself.
 */
class Proof : public VRFObject<Proof>, public Clonable<Proof>, public Serializable
{
  public:
    ~Proof() override = default;

    /**
     * Returns the VRF value associated with this proof as a vector of bytes. The length of the
     * returned vector depends on the VRF type.
     */
    [[nodiscard]]
    virtual std::vector<std::byte> get_vrf_value() const = 0;

  protected:
    using VRFObject<Proof>::VRFObject;
};

class PublicKey;

/**
 * Abstract base class representing a VRF secret key object. The secret key can be used to
 * generate VRF proofs for given inputs, and it can also provide the corresponding public key.
 * The secret key can be cloned and serialized/deserialized.
 */
class SecretKey : public VRFObject<SecretKey>, public Clonable<SecretKey>, public Serializable
{
  public:
    ~SecretKey() override = default;

    /**
     * Generates a VRF proof for the given input data using this secret key.
     */
    [[nodiscard]]
    virtual std::unique_ptr<Proof> get_vrf_proof(std::span<const std::byte> in) = 0;

    /**
     * Generates a VRF proof for the given input data using this secret key.
     */
    template <ByteLike T, std::size_t N = std::dynamic_extent>
        requires(!std::same_as<std::remove_cv_t<T>, std::byte>)
    [[nodiscard]]
    std::unique_ptr<Proof> get_vrf_proof(std::span<const T, N> in)
    {
        return get_vrf_proof(std::as_bytes(in));
    }

    /**
     * Generates a VRF proof for the given input data using this secret key.
     */
    template <ByteRange R>
    [[nodiscard]]
    std::unique_ptr<Proof> get_vrf_proof(R &&in)
    {
        return get_vrf_proof(byte_range_to_span(in));
    }

    /**
     * Returns the public key corresponding to this secret key.
     */
    [[nodiscard]]
    virtual std::unique_ptr<PublicKey> get_public_key() const = 0;

  protected:
    using VRFObject<SecretKey>::VRFObject;
};

/**
 * Abstract base class representing a VRF public key object. The public key can be used to
 * verify VRF proofs for given inputs. The public key can be cloned and serialized/deserialized.
 */
class PublicKey : public VRFObject<PublicKey>, public Clonable<PublicKey>, public Serializable
{
  public:
    ~PublicKey() override = default;

    /**
     * Verifies the given VRF proof against the provided input data using this public key.
     * If the proof is valid, the function returns a pair where the first element is true
     * and the second element is the VRF value as a vector of bytes. If the proof is invalid,
     * the function returns a pair where the first element is false and the second element
     * is an empty vector.
     */
    [[nodiscard]]
    virtual std::pair<bool, std::vector<std::byte>> verify_vrf_proof(std::span<const std::byte> in,
                                                                     const std::unique_ptr<Proof> &proof) = 0;

    /**
     * Verifies the given VRF proof against the provided input data using this public key.
     * If the proof is valid, the function returns a pair where the first element is true
     * and the second element is the VRF value as a vector of bytes. If the proof is invalid,
     * the function returns a pair where the first element is false and the second element
     * is an empty vector.
     */
    template <ByteLike T, std::size_t N = std::dynamic_extent>
        requires(!std::same_as<std::remove_cv_t<T>, std::byte>)
    [[nodiscard]]
    std::pair<bool, std::vector<std::byte>> verify_vrf_proof(std::span<const T, N> in,
                                                             const std::unique_ptr<Proof> &proof)
    {
        return verify_vrf_proof(std::as_bytes(in), proof);
    }

    /**
     * Verifies the given VRF proof against the provided input data using this public key.
     * If the proof is valid, the function returns a pair where the first element is true
     * and the second element is the VRF value as a vector of bytes. If the proof is invalid,
     * the function returns a pair where the first element is false and the second element
     * is an empty vector.
     */
    template <ByteRange R>
    [[nodiscard]]
    std::pair<bool, std::vector<std::byte>> verify_vrf_proof(R &&in, const std::unique_ptr<Proof> &proof)
    {
        return verify_vrf_proof(byte_range_to_span(in), proof);
    }

  protected:
    using VRFObject<PublicKey>::VRFObject;
};

} // namespace vrf
