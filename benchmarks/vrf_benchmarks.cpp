// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "vrf/vrf.h"
#include <benchmark/benchmark.h>

static void BM_VRF_GenerateKeys(benchmark::State &state)
{
    vrf::Type type = static_cast<vrf::Type>(state.range(0));
    for (auto _ : state)
    {
        auto sk = vrf::VRF::Create(type);
        benchmark::DoNotOptimize(sk);
    }
    state.SetLabel(std::string{vrf::to_string(type)});
}

BENCHMARK(BM_VRF_GenerateKeys)
    ->Unit(benchmark::kMillisecond)
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA2048_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA3072_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA4096_SHA384))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA4096_SHA512))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA2048_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA3072_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA384))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA512))
    ->Arg(static_cast<std::size_t>(vrf::Type::EC_VRF_P256_SHA256_TAI));

static void BM_VRF_GenerateProof(benchmark::State &state)
{
    vrf::Type type = static_cast<vrf::Type>(state.range(0));
    auto sk = vrf::VRF::Create(type);
    std::vector<std::byte> data(512, std::byte{0}); // Fixed 512-bit input for benchmarking
    for (auto _ : state)
    {
        auto proof = sk->get_vrf_proof(data);
        benchmark::DoNotOptimize(proof);
    }
    state.SetLabel(std::string{vrf::to_string(type)});
}

BENCHMARK(BM_VRF_GenerateProof)
    ->Unit(benchmark::kMillisecond)
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA2048_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA3072_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA4096_SHA384))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA4096_SHA512))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA2048_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA3072_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA384))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA512))
    ->Arg(static_cast<std::size_t>(vrf::Type::EC_VRF_P256_SHA256_TAI));

static void BM_VRF_VerifyProof(benchmark::State &state)
{
    vrf::Type type = static_cast<vrf::Type>(state.range(0));
    auto sk = vrf::VRF::Create(type);
    auto pk = sk->get_public_key();
    std::vector<std::byte> data(512, std::byte{0}); // Fixed 512-bit input for benchmarking
    auto proof = sk->get_vrf_proof(data);
    for (auto _ : state)
    {
        auto [success, hash] = pk->verify_vrf_proof(data, proof);
        benchmark::DoNotOptimize(success);
        benchmark::DoNotOptimize(hash);
    }
    state.SetLabel(std::string{vrf::to_string(type)});
}

BENCHMARK(BM_VRF_VerifyProof)
    ->Unit(benchmark::kMicrosecond)
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA2048_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA3072_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA4096_SHA384))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA4096_SHA512))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA2048_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA3072_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA384))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA512))
    ->Arg(static_cast<std::size_t>(vrf::Type::EC_VRF_P256_SHA256_TAI));

static void BM_VRF_ProofToBytes(benchmark::State &state)
{
    vrf::Type type = static_cast<vrf::Type>(state.range(0));
    auto sk = vrf::VRF::Create(type);
    std::vector<std::byte> data(512, std::byte{0}); // Fixed 512-bit input for benchmarking
    auto proof = sk->get_vrf_proof(data);
    for (auto _ : state)
    {
        auto proof_bytes = proof->to_bytes();
        benchmark::DoNotOptimize(proof_bytes);
    }
    state.SetLabel(std::string{vrf::to_string(type)});
}

BENCHMARK(BM_VRF_ProofToBytes)
    ->Unit(benchmark::kMicrosecond)
    ->Iterations(1000)
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA2048_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA3072_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA4096_SHA384))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA4096_SHA512))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA2048_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA3072_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA384))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA512))
    ->Arg(static_cast<std::size_t>(vrf::Type::EC_VRF_P256_SHA256_TAI));

static void BM_VRF_ProofFromBytes(benchmark::State &state)
{
    vrf::Type type = static_cast<vrf::Type>(state.range(0));
    auto sk = vrf::VRF::Create(type);
    std::vector<std::byte> data(512, std::byte{0}); // Fixed 512-bit input for benchmarking
    auto proof = sk->get_vrf_proof(data);
    auto proof_bytes = proof->to_bytes();
    for (auto _ : state)
    {
        auto proof_from_bytes = vrf::VRF::ProofFromBytes(proof_bytes);
        benchmark::DoNotOptimize(proof_from_bytes);
    }
    state.SetLabel(std::string{vrf::to_string(type)});
}

BENCHMARK(BM_VRF_ProofFromBytes)
    ->Unit(benchmark::kMicrosecond)
    ->Iterations(1000)
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA2048_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA3072_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA4096_SHA384))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA4096_SHA512))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA2048_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA3072_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA384))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA512))
    ->Arg(static_cast<std::size_t>(vrf::Type::EC_VRF_P256_SHA256_TAI));

static void BM_VRF_PublicKeyToBytes(benchmark::State &state)
{
    vrf::Type type = static_cast<vrf::Type>(state.range(0));
    auto sk = vrf::VRF::Create(type);
    auto pk = sk->get_public_key();
    for (auto _ : state)
    {
        auto der_spki = pk->to_bytes();
        benchmark::DoNotOptimize(der_spki);
    }
    state.SetLabel(std::string{vrf::to_string(type)});
}

BENCHMARK(BM_VRF_PublicKeyToBytes)
    ->Unit(benchmark::kMicrosecond)
    ->Iterations(1000)
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA2048_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA3072_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA4096_SHA384))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA4096_SHA512))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA2048_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA3072_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA384))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA512))
    ->Arg(static_cast<std::size_t>(vrf::Type::EC_VRF_P256_SHA256_TAI));

static void BM_VRF_PublicKeyFromBytes(benchmark::State &state)
{
    vrf::Type type = static_cast<vrf::Type>(state.range(0));
    auto sk = vrf::VRF::Create(type);
    auto pk = sk->get_public_key();
    auto der_spki = pk->to_bytes();
    for (auto _ : state)
    {
        auto public_key_from_string = vrf::VRF::PublicKeyFromBytes(der_spki);
        benchmark::DoNotOptimize(public_key_from_string);
    }
    state.SetLabel(std::string{vrf::to_string(type)});
}

BENCHMARK(BM_VRF_PublicKeyFromBytes)
    ->Unit(benchmark::kMicrosecond)
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA2048_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA3072_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA4096_SHA384))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA4096_SHA512))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA2048_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA3072_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA384))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA512))
    ->Arg(static_cast<std::size_t>(vrf::Type::EC_VRF_P256_SHA256_TAI));

static void BM_VRF_SecretKeyToSecureBytes(benchmark::State &state)
{
    vrf::Type type = static_cast<vrf::Type>(state.range(0));
    auto sk = vrf::VRF::Create(type);
    for (auto _ : state)
    {
        auto sk_bytes = sk->to_secure_bytes();
        benchmark::DoNotOptimize(sk_bytes);
    }
    state.SetLabel(std::string{vrf::to_string(type)});
}

BENCHMARK(BM_VRF_SecretKeyToSecureBytes)
    ->Unit(benchmark::kMicrosecond)
    ->Iterations(1000)
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA2048_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA3072_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA4096_SHA384))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA4096_SHA512))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA2048_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA3072_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA384))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA512))
    ->Arg(static_cast<std::size_t>(vrf::Type::EC_VRF_P256_SHA256_TAI));

static void BM_VRF_SecretKeyFromBytes(benchmark::State &state)
{
    vrf::Type type = static_cast<vrf::Type>(state.range(0));
    auto sk = vrf::VRF::Create(type);
    auto sk_bytes = sk->to_secure_bytes();
    for (auto _ : state)
    {
        auto sk_from_bytes = vrf::VRF::SecretKeyFromBytes(sk_bytes);
        benchmark::DoNotOptimize(sk_from_bytes);
    }
    state.SetLabel(std::string{vrf::to_string(type)});
}

BENCHMARK(BM_VRF_SecretKeyFromBytes)
    ->Unit(benchmark::kMicrosecond)
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA2048_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA3072_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA4096_SHA384))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_FDH_VRF_RSA4096_SHA512))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA2048_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA3072_SHA256))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA384))
    ->Arg(static_cast<std::size_t>(vrf::Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA512))
    ->Arg(static_cast<std::size_t>(vrf::Type::EC_VRF_P256_SHA256_TAI));

BENCHMARK_MAIN();
