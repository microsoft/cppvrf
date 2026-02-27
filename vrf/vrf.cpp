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

std::unique_ptr<Proof> VRF::ProofFromBytes(std::span<const std::byte> data)
{
    std::unique_ptr<Proof> proof = nullptr;

    do
    {
        // Try first to deserialize as RSA VRF proof.
        proof.reset(new rsa::RSAProof{});
        if (nullptr == proof)
        {
            GetLogger()->error("Failed to allocate memory for RSA VRF proof.");
            return nullptr;
        }
        proof->from_bytes(data);
        if (proof->is_initialized())
        {
            break;
        }

        // Next try to deserialize as EC VRF proof.
        proof.reset(new ec::ECProof{});
        if (nullptr == proof)
        {
            GetLogger()->error("Failed to allocate memory for EC VRF proof.");
            return nullptr;
        }
        proof->from_bytes(data);
        if (proof->is_initialized())
        {
            break;
        }
    } while (false);

    if (!proof->is_initialized())
    {
        GetLogger()->warn("Failed to deserialize VRF proof.");
        return nullptr;
    }

    return proof;
}

std::unique_ptr<PublicKey> VRF::PublicKeyFromBytes(std::span<const std::byte> data)
{
    std::unique_ptr<PublicKey> pk = nullptr;

    do
    {
        // Try first to deserialize as RSA VRF public key.
        pk.reset(new rsa::RSAPublicKey{});
        if (nullptr == pk)
        {
            GetLogger()->error("Failed to allocate memory for RSA VRF public key.");
            return nullptr;
        }
        pk->from_bytes(data);
        if (pk->is_initialized())
        {
            break;
        }

        // Next try to deserialize as EC VRF proof.
        pk.reset(new ec::ECPublicKey{});
        if (nullptr == pk)
        {
            GetLogger()->error("Failed to allocate memory for EC VRF public key.");
            return nullptr;
        }
        pk->from_bytes(data);
        if (pk->is_initialized())
        {
            break;
        }
    } while (false);

    if (!pk->is_initialized())
    {
        GetLogger()->warn("Failed to deserialize VRF public key.");
        return nullptr;
    }

    return pk;
}

std::unique_ptr<SecretKey> VRF::SecretKeyFromBytes(std::span<const std::byte> data)
{
    std::unique_ptr<SecretKey> sk = nullptr;

    do
    {
        // Try first to deserialize as RSA VRF secret key.
        sk.reset(new rsa::RSASecretKey{});
        if (nullptr == sk)
        {
            GetLogger()->error("Failed to allocate memory for RSA VRF secret key.");
            return nullptr;
        }
        sk->from_bytes(data);
        if (sk->is_initialized())
        {
            break;
        }

        // Next try to deserialize as EC VRF secret key.
        sk.reset(new ec::ECSecretKey{});
        if (nullptr == sk)
        {
            GetLogger()->error("Failed to allocate memory for EC VRF secret key.");
            return nullptr;
        }
        sk->from_bytes(data);
        if (sk->is_initialized())
        {
            break;
        }
    } while (false);

    if (!sk->is_initialized())
    {
        GetLogger()->warn("Failed to deserialize VRF secret key.");
        return nullptr;
    }

    return sk;
}

} // namespace vrf
