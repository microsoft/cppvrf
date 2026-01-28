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
        return std::unique_ptr<SecretKey>{new rsa::RSASecretKey{type}};
    }
    else if (is_ec_type(type))
    {
        return std::unique_ptr<SecretKey>{new ec::ECSecretKey{type}};
    }
    else
    {
        GetLogger()->error("VRF type {} is not supported", to_string(type));
        return nullptr;
    }
}

std::unique_ptr<Proof> VRF::proof_from_bytes(Type type, std::span<const std::byte> data)
{
    std::unique_ptr<Proof> proof = nullptr;

    if (is_rsa_type(type))
    {
        proof.reset(new rsa::RSAProof{});
    }
    else if (is_ec_type(type))
    {
        proof.reset(new ec::ECProof{});
    }
    else
    {
        GetLogger()->warn("VRF type {} is not supported", to_string(type));
    }

    if (nullptr == proof)
    {
        GetLogger()->error("Failed to allocate memory for VRF proof of type {}", to_string(type));
        return nullptr;
    }

    proof->from_bytes(type, data);
    if (!proof->is_initialized())
    {
        GetLogger()->warn("Failed to deserialize VRF proof for type {}", to_string(type));
        return nullptr;
    }

    return proof;
}

std::unique_ptr<PublicKey> VRF::public_key_from_bytes(Type type, std::span<const std::byte> data)
{
    std::unique_ptr<PublicKey> pk = nullptr;

    if (is_rsa_type(type))
    {
        pk.reset(new rsa::RSAPublicKey{});
    }
    else if (is_ec_type(type))
    {
        pk.reset(new ec::ECPublicKey{});
    }
    else
    {
        GetLogger()->warn("VRF type {} is not supported", to_string(type));
    }

    if (nullptr == pk)
    {
        GetLogger()->error("Failed to allocate memory for VRF public key of type {}", to_string(type));
        return nullptr;
    }

    pk->from_bytes(type, data);
    if (!pk->is_initialized())
    {
        GetLogger()->warn("Failed to deserialize VRF public key for type {}", to_string(type));
        return nullptr;
    }

    return pk;
}

std::unique_ptr<SecretKey> VRF::secret_key_from_bytes(Type type, std::span<const std::byte> data)
{
    std::unique_ptr<SecretKey> sk = nullptr;

    if (is_rsa_type(type))
    {
        sk.reset(new rsa::RSASecretKey{});
    }
    else if (is_ec_type(type))
    {
        sk.reset(new ec::ECSecretKey{});
    }
    else
    {
        GetLogger()->warn("VRF type {} is not supported", to_string(type));
    }

    if (nullptr == sk)
    {
        GetLogger()->error("Failed to allocate memory for VRF secret key of type {}", to_string(type));
        return nullptr;
    }

    sk->from_bytes(type, data);
    if (!sk->is_initialized())
    {
        GetLogger()->warn("Failed to deserialize VRF secret key for type {}", to_string(type));
        return nullptr;
    }

    return sk;
}

} // namespace vrf
