// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "vrf/vrf.h"
#include "vrf/ec/ecvrf.h"
#include "vrf/log.h"
#include "vrf/rsa/rsavrf.h"

namespace vrf
{

std::unique_ptr<SecretKey> VRF::Create(Type type)
{
    if (is_rsa_type(type))
    {
        GetLogger()->trace("Creating RSA VRF secret key of type {}.", to_string(type));
        return std::unique_ptr<SecretKey>{new rsa::RSASecretKey{type}};
    }
    if (is_ec_type(type))
    {
        GetLogger()->trace("Creating EC VRF secret key of type {}.", to_string(type));
        return std::unique_ptr<SecretKey>{new ec::ECSecretKey{type}};
    }

    GetLogger()->warning("VRF type {} is not supported", to_string(type));
    return nullptr;
}

std::unique_ptr<Proof> VRF::ProofFromBytes(std::span<const std::byte> data)
{
    std::unique_ptr<Proof> proof = nullptr;

    // Try first to deserialize as RSA VRF proof.
    proof = std::make_unique<rsa::RSAProof>();
    proof->from_bytes(data);
    if (proof->is_initialized())
    {
        GetLogger()->trace("Successfully deserialized RSA VRF proof.");
        return proof;
    }

    // Next try to deserialize as EC VRF proof.
    proof = std::make_unique<ec::ECProof>();
    proof->from_bytes(data);
    if (proof->is_initialized())
    {
        GetLogger()->trace("Successfully deserialized EC VRF proof.");
        return proof;
    }

    GetLogger()->warning("Failed to deserialize VRF proof.");
    return nullptr;
}

std::unique_ptr<PublicKey> VRF::PublicKeyFromBytes(std::span<const std::byte> data)
{
    std::unique_ptr<PublicKey> pk = nullptr;

    // Try first to deserialize as RSA VRF public key.
    pk = std::make_unique<rsa::RSAPublicKey>();
    pk->from_bytes(data);
    if (pk->is_initialized())
    {
        GetLogger()->trace("Successfully deserialized RSA VRF public key.");
        return pk;
    }

    // Next try to deserialize as EC VRF proof.
    pk = std::make_unique<ec::ECPublicKey>();
    pk->from_bytes(data);
    if (pk->is_initialized())
    {
        GetLogger()->trace("Successfully deserialized EC VRF public key.");
        return pk;
    }

    GetLogger()->warning("Failed to deserialize VRF public key.");
    return nullptr;
}

std::unique_ptr<SecretKey> VRF::SecretKeyFromBytes(std::span<const std::byte> data)
{
    std::unique_ptr<SecretKey> sk = nullptr;

    // Try first to deserialize as RSA VRF secret key.
    sk = std::make_unique<rsa::RSASecretKey>();
    sk->from_bytes(data);
    if (sk->is_initialized())
    {
        GetLogger()->trace("Successfully deserialized RSA VRF secret key.");
        return sk;
    }

    // Next try to deserialize as EC VRF secret key.
    sk = std::make_unique<ec::ECSecretKey>();
    sk->from_bytes(data);
    if (sk->is_initialized())
    {
        GetLogger()->trace("Successfully deserialized EC VRF secret key.");
        return sk;
    }

    GetLogger()->warning("Failed to deserialize VRF secret key.");
    return nullptr;
}

} // namespace vrf
