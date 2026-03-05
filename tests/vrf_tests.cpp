// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "vrf/../tests/utils.h"
#include "vrf/vrf.h"
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <limits>
#include <random>
#include <string>

namespace vrf::tests
{

namespace
{

std::vector<std::byte> random_bytes(std::size_t length)
{
    using word_t = std::uint64_t;
    std::size_t word_length = (length + sizeof(word_t) - 1) / sizeof(word_t);
    std::vector<word_t> words(word_length);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<std::uint64_t> dis(0, std::numeric_limits<word_t>::max());

    for (std::size_t i = 0; i < word_length; ++i)
    {
        words[i] = dis(gen);
    }

    std::vector<std::byte> result(length);
    std::copy(reinterpret_cast<std::byte *>(words.data()), reinterpret_cast<std::byte *>(words.data()) + length,
              result.data());

    return result;
}

void check_test_vector(const std::unique_ptr<SecretKey> &vrf_sk, const std::vector<std::byte> &data,
                       const std::vector<std::byte> &expected_proof, const std::vector<std::byte> &expected_value)
{
    ASSERT_NE(nullptr, vrf_sk.get());
    ASSERT_TRUE(vrf_sk->is_initialized());
    std::unique_ptr<Proof> proof = vrf_sk->get_vrf_proof(data);
    ASSERT_NE(nullptr, proof);
    ASSERT_TRUE(proof->is_initialized());

    std::vector<std::byte> proof_bytes = proof->to_bytes();
    Type type = vrf_sk->get_type();
    ASSERT_EQ(as_byte(type), proof_bytes[0]);
    proof_bytes.erase(proof_bytes.begin());
    ASSERT_EQ(expected_proof, proof_bytes);

    std::unique_ptr<PublicKey> vrf_pk = vrf_sk->get_public_key();
    ASSERT_NE(nullptr, vrf_pk.get());
    auto [success, value] = vrf_pk->verify_vrf_proof(data, proof);
    ASSERT_TRUE(success);
    ASSERT_EQ(expected_value, value);
}

} // namespace

class VRFTest : public testing::TestWithParam<vrf::Type>
{
};

TEST_P(VRFTest, Create)
{
    vrf::Type type = GetParam();
    auto sk = vrf::VRF::Create(type);
    ASSERT_NE(sk, nullptr);
    ASSERT_TRUE(sk->is_initialized());
    ASSERT_EQ(sk->get_type(), type);
}

TEST_P(VRFTest, GetPublicKey)
{
    vrf::Type type = GetParam();
    auto sk = vrf::VRF::Create(type);

    auto pk = sk->get_public_key();
    ASSERT_NE(pk, nullptr);
    ASSERT_TRUE(pk->is_initialized());
    ASSERT_EQ(pk->get_type(), type);

    auto der_spki = pk->to_bytes();
    ASSERT_FALSE(der_spki.empty());

    // Get the public key again and compare.
    auto pk2 = sk->get_public_key();
    ASSERT_NE(pk2, nullptr);
    ASSERT_TRUE(pk2->is_initialized());
    ASSERT_EQ(pk2->get_type(), type);
    auto der_spki2 = pk2->to_bytes();
    ASSERT_EQ(der_spki, der_spki2);
}

TEST_P(VRFTest, CreateVerifyProof)
{
    vrf::Type type = GetParam();
    auto sk = vrf::VRF::Create(type);
    auto pk = sk->get_public_key();

    auto prove_and_verify = [&](std::vector<std::byte> data) {
        auto proof = sk->get_vrf_proof(data);
        ASSERT_NE(proof, nullptr);
        ASSERT_TRUE(proof->is_initialized());
        auto [success, hash] = pk->verify_vrf_proof(data, proof);
        ASSERT_TRUE(success);
        ASSERT_FALSE(hash.empty());
    };

    prove_and_verify({});
    prove_and_verify({std::byte{0x00}});
    prove_and_verify({std::byte{0x01}, std::byte{0x02}, std::byte{0x03}, std::byte{0x04}, std::byte{0x05}});
    prove_and_verify(random_bytes(32));
    prove_and_verify(random_bytes(128));
    prove_and_verify(random_bytes(16384));
}

TEST_P(VRFTest, ProofToBytesFromBytes)
{
    vrf::Type type = GetParam();
    auto sk = vrf::VRF::Create(type);
    auto pk = sk->get_public_key();

    std::vector<std::byte> data = random_bytes(32);
    auto proof = sk->get_vrf_proof(data);
    ASSERT_NE(proof, nullptr);
    ASSERT_TRUE(proof->is_initialized());

    std::vector<std::byte> proof_bytes = proof->to_bytes();
    ASSERT_FALSE(proof_bytes.empty());

    auto proof_from_bytes = vrf::VRF::ProofFromBytes(proof_bytes);
    ASSERT_NE(proof_from_bytes, nullptr);
    ASSERT_TRUE(proof_from_bytes->is_initialized());
    ASSERT_EQ(proof_from_bytes->get_type(), type);

    auto [success, hash] = pk->verify_vrf_proof(data, proof_from_bytes);
    ASSERT_TRUE(success);
    ASSERT_FALSE(hash.empty());
}

TEST_P(VRFTest, PublicKeyEncodeDecode)
{
    vrf::Type type = GetParam();
    auto sk = vrf::VRF::Create(type);
    auto pk = sk->get_public_key();

    std::vector<std::byte> der_spki = pk->to_bytes();
    ASSERT_FALSE(der_spki.empty());

    auto pk_from_string = vrf::VRF::PublicKeyFromBytes(der_spki);
    ASSERT_NE(pk_from_string, nullptr);
    ASSERT_EQ(pk_from_string->get_type(), type);

    std::vector<std::byte> data = random_bytes(32);
    auto proof = sk->get_vrf_proof(data);

    auto [success, hash] = pk_from_string->verify_vrf_proof(data, proof);
    ASSERT_TRUE(success);
    ASSERT_FALSE(hash.empty());
}

TEST_P(VRFTest, ValueIsDeterministic)
{
    vrf::Type type = GetParam();
    auto sk = vrf::VRF::Create(type);
    auto pk = sk->get_public_key();

    std::vector<std::byte> data = random_bytes(32);
    auto proof1 = sk->get_vrf_proof(data);
    ASSERT_NE(proof1, nullptr);
    ASSERT_TRUE(proof1->is_initialized());
    auto proof2 = sk->get_vrf_proof(data);
    ASSERT_NE(proof2, nullptr);
    ASSERT_TRUE(proof2->is_initialized());

    auto [success1, hash1] = pk->verify_vrf_proof(data, proof1);
    auto [success2, hash2] = pk->verify_vrf_proof(data, proof2);
    ASSERT_TRUE(success1);
    ASSERT_TRUE(success2);
    ASSERT_FALSE(hash1.empty());
    ASSERT_FALSE(hash2.empty());
    ASSERT_EQ(proof1->to_bytes(), proof2->to_bytes());
    ASSERT_EQ(hash1, hash2);

    {
        // Invert the first bit in data.
        std::vector<std::byte> different_data = data;
        different_data[0] ^= std::byte{0x01};
        auto proof3 = sk->get_vrf_proof(different_data);
        auto [success3, hash3] = pk->verify_vrf_proof(different_data, proof3);
        ASSERT_TRUE(success3);
        ASSERT_FALSE(hash3.empty());
        ASSERT_NE(proof1->to_bytes(), proof3->to_bytes());
    }
    {
        // Invert the last bit in data.
        std::vector<std::byte> different_data = data;
        different_data[different_data.size() - 1] ^= std::byte{0x01};
        auto proof3 = sk->get_vrf_proof(different_data);
        auto [success3, hash3] = pk->verify_vrf_proof(different_data, proof3);
        ASSERT_TRUE(success3);
        ASSERT_FALSE(hash3.empty());
        ASSERT_NE(proof1->to_bytes(), proof3->to_bytes());
    }
    {
        // Invert all bits in data.
        std::vector<std::byte> different_data(data.size());
        for (std::size_t i = 0; i < data.size(); ++i)
        {
            different_data[i] = ~data[i];
        }
        auto proof3 = sk->get_vrf_proof(different_data);
        auto [success3, hash3] = pk->verify_vrf_proof(different_data, proof3);
        ASSERT_TRUE(success3);
        ASSERT_FALSE(hash3.empty());
        ASSERT_NE(proof1->to_bytes(), proof3->to_bytes());
    }
}

TEST_P(VRFTest, InvalidProof)
{
    vrf::Type type = GetParam();
    auto sk = vrf::VRF::Create(type);
    auto pk = sk->get_public_key();

    std::vector<std::byte> data = random_bytes(32);
    auto proof = sk->get_vrf_proof(data);
    std::vector<std::byte> proof_bytes = proof->to_bytes();

    // Modify the proof to make it invalid: modification in the beginning.
    {
        std::vector<std::byte> invalid_proof_data = proof_bytes;
        invalid_proof_data[1] ^= std::byte{0xFF};
        auto invalid_proof = vrf::VRF::ProofFromBytes(invalid_proof_data);
        ASSERT_NE(invalid_proof, nullptr);
        ASSERT_TRUE(invalid_proof->is_initialized());
        auto [success, hash] = pk->verify_vrf_proof(data, invalid_proof);
        ASSERT_FALSE(success);
        ASSERT_TRUE(hash.empty());
    }

    // Modify the proof to make it invalid: modification in the middle.
    {
        std::vector<std::byte> invalid_proof_data = proof_bytes;
        invalid_proof_data[invalid_proof_data.size() / 2] ^= std::byte{0xFF};
        auto invalid_proof = vrf::VRF::ProofFromBytes(invalid_proof_data);
        ASSERT_NE(invalid_proof, nullptr);
        ASSERT_TRUE(invalid_proof->is_initialized());
        auto [success, hash] = pk->verify_vrf_proof(data, invalid_proof);
        ASSERT_FALSE(success);
        ASSERT_TRUE(hash.empty());
    }

    // Modify the proof to make it invalid: modification in the end.
    {
        std::vector<std::byte> invalid_proof_data = proof_bytes;
        invalid_proof_data[invalid_proof_data.size() - 1] ^= std::byte{0xFF};
        auto invalid_proof = vrf::VRF::ProofFromBytes(invalid_proof_data);
        ASSERT_NE(invalid_proof, nullptr);
        ASSERT_TRUE(invalid_proof->is_initialized());
        auto [success, hash] = pk->verify_vrf_proof(data, invalid_proof);
        ASSERT_FALSE(success);
        ASSERT_TRUE(hash.empty());
    }

    // Empty proof.
    {
        std::vector<std::byte> invalid_proof_data = {};
        auto invalid_proof = vrf::VRF::ProofFromBytes(invalid_proof_data);
        ASSERT_EQ(invalid_proof, nullptr);
    }

    // Totally wrong size proof.
    {
        std::vector<std::byte> invalid_proof_data(proof_bytes.begin(), proof_bytes.begin() + static_cast<std::ptrdiff_t>(proof_bytes.size() / 2));
        auto invalid_proof = vrf::VRF::ProofFromBytes(invalid_proof_data);
        ASSERT_NE(invalid_proof, nullptr);
        ASSERT_TRUE(invalid_proof->is_initialized());
        auto [success, hash] = pk->verify_vrf_proof(data, invalid_proof);
        ASSERT_FALSE(success);
        ASSERT_TRUE(hash.empty());
    }

    // Very large size proof.
    {
        std::vector<std::byte> invalid_proof_data = proof_bytes;
        invalid_proof_data.insert(invalid_proof_data.end(), proof_bytes.begin(), proof_bytes.end());
        auto invalid_proof = vrf::VRF::ProofFromBytes(invalid_proof_data);
        ASSERT_NE(invalid_proof, nullptr);
        ASSERT_TRUE(invalid_proof->is_initialized());
        auto [success, hash] = pk->verify_vrf_proof(data, invalid_proof);
        ASSERT_FALSE(success);
        ASSERT_TRUE(hash.empty());
    }
}

TEST_P(VRFTest, InvalidPublicKey)
{
    vrf::Type type = GetParam();
    auto sk = vrf::VRF::Create(type);

    std::vector<std::byte> data = random_bytes(32);
    auto proof = sk->get_vrf_proof(data);

    // Create an invalid public key by modifying the DER SPKI: modification in the beginning.
    {
        auto pk = sk->get_public_key();
        auto der_spki = pk->to_bytes();
        der_spki[1] ^= std::byte{1};
        auto invalid_pk = vrf::VRF::PublicKeyFromBytes(der_spki);
        ASSERT_TRUE(invalid_pk == nullptr || !invalid_pk->is_initialized() ||
                    !invalid_pk->verify_vrf_proof(data, proof).first);
    }

    // Create an invalid public key by modifying the DER SPKI: modification in the middle.
    {
        auto pk = sk->get_public_key();
        auto der_spki = pk->to_bytes();
        der_spki[der_spki.size() / 2] ^= std::byte{1};
        auto invalid_pk = vrf::VRF::PublicKeyFromBytes(der_spki);
        ASSERT_TRUE(invalid_pk == nullptr || !invalid_pk->is_initialized() ||
                    !invalid_pk->verify_vrf_proof(data, proof).first);
    }

    // Create an invalid public key by modifying the DER SPKI: modification in the end.
    {
        auto pk = sk->get_public_key();
        auto der_spki = pk->to_bytes();
        der_spki[der_spki.size() - 1] ^= std::byte{1};
        auto invalid_pk = vrf::VRF::PublicKeyFromBytes(der_spki);
        ASSERT_TRUE(invalid_pk == nullptr || !invalid_pk->is_initialized() ||
                    !invalid_pk->verify_vrf_proof(data, proof).first);
    }
}

TEST(VRFTest, InputFlexibility)
{
    vrf::Type type = vrf::Type::RSA_FDH_VRF_RSA2048_SHA256;
    auto sk = vrf::VRF::Create(type);
    auto pk = sk->get_public_key();

    // Span of chars for input
    {
        auto data = std::span{"hello world"};
        auto proof = sk->get_vrf_proof(data);
        ASSERT_NE(proof, nullptr);
        ASSERT_TRUE(proof->is_initialized());
        auto [success, hash] = pk->verify_vrf_proof(data, proof);
        ASSERT_TRUE(success);
        ASSERT_FALSE(hash.empty());
    }

    // Get data from unsigned char vector.
    {
        std::vector<unsigned char> data = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};
        auto proof = sk->get_vrf_proof(data);
        ASSERT_NE(proof, nullptr);
        ASSERT_TRUE(proof->is_initialized());
        auto [success, hash] = pk->verify_vrf_proof(data, proof);
        ASSERT_TRUE(success);
        ASSERT_FALSE(hash.empty());
    }

    // Get data from array of std::uint8_t.
    {
        std::array<std::uint8_t, 11> data = {'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd'};
        auto proof = sk->get_vrf_proof(data);
        ASSERT_NE(proof, nullptr);
        ASSERT_TRUE(proof->is_initialized());
        auto [success, hash] = pk->verify_vrf_proof(data, proof);
        ASSERT_TRUE(success);
        ASSERT_FALSE(hash.empty());
    }

    // Get data from a temporary object.
    {
        auto proof = sk->get_vrf_proof(std::string("hello world"));
        ASSERT_NE(proof, nullptr);
        ASSERT_TRUE(proof->is_initialized());
        auto [success, hash] = pk->verify_vrf_proof(std::string("hello world"), proof);
        ASSERT_TRUE(success);
        ASSERT_FALSE(hash.empty());
    }
}

TEST_P(VRFTest, SecretKeyRoundTrip)
{
    auto type = GetParam();
    auto sk = vrf::VRF::Create(type);
    ASSERT_NE(sk, nullptr);
    ASSERT_TRUE(sk->is_initialized());

    vrf::SecureBuf sk_bytes = sk->to_secure_bytes();
    ASSERT_TRUE(sk_bytes.has_value());

    auto sk_roundtrip = vrf::VRF::SecretKeyFromBytes(sk_bytes);
    ASSERT_NE(sk_roundtrip, nullptr);
    ASSERT_TRUE(sk_roundtrip->is_initialized());
    ASSERT_EQ(sk_roundtrip->get_type(), type);

    vrf::SecureBuf sk_roundtrip_bytes = sk_roundtrip->to_secure_bytes();
    ASSERT_TRUE(sk_roundtrip_bytes.has_value());
    ASSERT_EQ(sk_bytes.size(), sk_roundtrip_bytes.size());
    ASSERT_TRUE(std::equal(sk_bytes.get(), sk_bytes.get() + sk_bytes.size(), sk_roundtrip_bytes.get()));

    std::vector<std::byte> data = random_bytes(32);
    auto proof = sk_roundtrip->get_vrf_proof(data);
    ASSERT_NE(proof, nullptr);
    ASSERT_TRUE(proof->is_initialized());

    auto pk = sk_roundtrip->get_public_key();
    ASSERT_NE(pk, nullptr);
    auto [success, hash] = pk->verify_vrf_proof(data, proof);
    ASSERT_TRUE(success);
    ASSERT_FALSE(hash.empty());
}

TEST_P(VRFTest, SKSerializationVerifyCross)
{
    const auto type = GetParam();

    auto sk1 = vrf::VRF::Create(type);
    ASSERT_NE(sk1, nullptr);
    ASSERT_TRUE(sk1->is_initialized());

    auto data1 = random_bytes(32);
    auto proof1 = sk1->get_vrf_proof(data1);
    ASSERT_NE(proof1, nullptr);
    ASSERT_TRUE(proof1->is_initialized());

    vrf::SecureBuf sk_bytes = sk1->to_secure_bytes();
    ASSERT_TRUE(sk_bytes.has_value());

    auto sk2 = vrf::VRF::SecretKeyFromBytes(sk_bytes);
    ASSERT_NE(sk2, nullptr);
    ASSERT_TRUE(sk2->is_initialized());

    auto data2 = random_bytes(32);
    auto proof2 = sk2->get_vrf_proof(data2);
    ASSERT_NE(proof2, nullptr);

    auto pk1 = sk1->get_public_key();
    ASSERT_NE(pk1, nullptr);

    auto pk2 = sk2->get_public_key();
    ASSERT_NE(pk2, nullptr);

    auto proof_result1 = pk1->verify_vrf_proof(data1, proof1);
    auto proof_result2 = pk1->verify_vrf_proof(data2, proof2);
    auto proof_result3 = pk2->verify_vrf_proof(data1, proof1);
    auto proof_result4 = pk2->verify_vrf_proof(data2, proof2);

    ASSERT_TRUE(proof_result1.first);
    ASSERT_TRUE(proof_result2.first);
    ASSERT_TRUE(proof_result3.first);
    ASSERT_TRUE(proof_result4.first);
}

INSTANTIATE_TEST_SUITE_P(RSAVRFTypes, VRFTest,
                         testing::Values(vrf::Type::RSA_FDH_VRF_RSA2048_SHA256, vrf::Type::RSA_FDH_VRF_RSA3072_SHA256,
                                         vrf::Type::RSA_FDH_VRF_RSA4096_SHA384, vrf::Type::RSA_FDH_VRF_RSA4096_SHA512,
                                         vrf::Type::RSA_PSS_NOSALT_VRF_RSA2048_SHA256,
                                         vrf::Type::RSA_PSS_NOSALT_VRF_RSA3072_SHA256,
                                         vrf::Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA384,
                                         vrf::Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA512),
                         testing::PrintToStringParamName());

INSTANTIATE_TEST_SUITE_P(ECVRFTypes, VRFTest, testing::Values(vrf::Type::EC_VRF_P256_SHA256_TAI),
                         testing::PrintToStringParamName());

class RSATestVectors : public testing::TestWithParam<vrf::Type>
{
};

TEST_P(RSATestVectors, TestVectors)
{
    vrf::Type type = GetParam();
    if (!is_rsa_type(type))
    {
        GTEST_SKIP() << "Skipping non-RSA type in RSAVRFTestVectors.";
    }

    // Create a VRF key pair.
    const utils::RSA_VRF_TestVectorParams params = utils::get_rsa_vrf_test_vector_params(type);
    const std::unique_ptr<SecretKey> sk = utils::make_rsa_vrf_secret_key(type, params.p, params.q);

    check_test_vector(sk, utils::parse_hex_bytes(params.m), utils::parse_hex_bytes(params.proof),
                      utils::parse_hex_bytes(params.value));
}

class ECTestVectors : public testing::TestWithParam<vrf::Type>
{
};

TEST_P(ECTestVectors, TestVectors)
{
    vrf::Type type = GetParam();
    if (!is_ec_type(type))
    {
        GTEST_SKIP() << "Skipping non-EC type in ECVRFTestVectors.";
    }

    // Get the test vector parameters.
    const utils::EC_VRF_TestVectorParams params = utils::get_ec_vrf_test_vector_params(type);
    const std::size_t test_vector_count = params.sk.size();

    for (std::size_t i = 0; i < test_vector_count; ++i)
    {
        const std::unique_ptr<SecretKey> sk = utils::make_ec_vrf_secret_key(type, params.sk[i]);

        check_test_vector(sk, utils::parse_hex_bytes(params.m[i]), utils::parse_hex_bytes(params.proof[i]),
                          utils::parse_hex_bytes(params.value[i]));
    }
}

INSTANTIATE_TEST_SUITE_P(TestVectorTypes, RSATestVectors,
                         testing::Values(vrf::Type::RSA_FDH_VRF_RSA2048_SHA256, vrf::Type::RSA_FDH_VRF_RSA3072_SHA256,
                                         vrf::Type::RSA_FDH_VRF_RSA4096_SHA384, vrf::Type::RSA_FDH_VRF_RSA4096_SHA512),
                         testing::PrintToStringParamName());

INSTANTIATE_TEST_SUITE_P(TestVectorTypes, ECTestVectors, testing::Values(vrf::Type::EC_VRF_P256_SHA256_TAI),
                         testing::PrintToStringParamName());

} // namespace vrf::tests
