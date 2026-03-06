# cppvrf

## Verifiable Random Functions

A Verifiable Random Function (VRF) is a cryptographic public-key primitive that, from a secret key and a given input, produces a unique pseudorandom output, along with a proof that the output was correctly computed.
Only the secret key holder can generate the output–proof pair, but anyone with the corresponding public key can verify the proof.

`cppvrf` is a C++20 implementation of several VRFs.
It comes with a CMake based build system, unit tests, and benchmarks.
The easiest way to include `cppvrf` in your CMake project is using [vcpkg](https://GitHub.com/Microsoft/vcpkg).

### Build

To build `cppvrf`, ensure [vcpkg](https://GitHub.com/Microsoft/vcpkg) is installed (and the environment variable `VCPKG_ROOT` is set).
Then run
```bash
cmake -S . --preset <configure-preset-name>
cmake --build --preset <build-preset-name>
cmake --install out/build/<build-preset-name> # optional; to install in custom destination, include --prefix <destination>
```
The list of available options for `<preset-name>` can be seen by running `cmake --list-presets=all`.
The presets will automatically build the test and benchmark suites.
After building, the executables `vrf_tests[.exe]` and `vrf_benchmarks[.exe]` are available in `out/build/<preset-name>/bin`.

If you do not want to use presets, you can specify `-DCPPVRF_BUILD_TESTS=ON` and `-DCPPVRF_BUILD_BENCHMARKS=ON` to build the test and the benchmark suites.

## Implemented VRFs

`cppvrf` implements RSA-FDH VRF and elliptic curve VRF based on [RFC9381](https://datatracker.ietf.org/doc/rfc9381).
It also implements an RSA VRF variant based on RSA-PSS signatures with no nonce.

### Warning

The security models of VRFs are non-trivial.
For example, RSA-based VRFs are not secure unless the key generation process is trusted.
For more details and explanation of the security guarantees, see [RFC9381](https://datatracker.ietf.org/doc/rfc9381).

## Usage

`cppvrf` exposes a simple API for creating VRF keypairs, producing proofs, verifying them, and (de)serializing keys and proofs.
These functionalities are illustrated in the examples below.

### 1) Choosing the VRF type and key generation

All supported VRF implementations are listed in [vrf/type.h](vrf/type.h).
They are described by the following enum values:

- `vrf::Type::RSA_FDH_VRF_RSA2048_SHA256`
- `vrf::Type::RSA_FDH_VRF_RSA3072_SHA256`
- `vrf::Type::RSA_FDH_VRF_RSA4096_SHA384`
- `vrf::Type::RSA_FDH_VRF_RSA4096_SHA512`
- `vrf::Type::RSA_PSS_NOSALT_VRF_RSA2048_SHA256`
- `vrf::Type::RSA_PSS_NOSALT_VRF_RSA3072_SHA256`
- `vrf::Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA384`
- `vrf::Type::RSA_PSS_NOSALT_VRF_RSA4096_SHA512`
- `vrf::Type::EC_VRF_P256_SHA256_TAI`

The following code snippet creates an RSA-FDH VRF with a 2048-bit key and uses SHA-256 as a hash function.
The `vrf::VRF::Create` function creates a VRF secret key and stores it in memory.
Failure can be tested by checking that the output is not `nullptr` and the `is_initialized()` member function returns `true`.
```cpp
#include <memory>
#include <stdexcept>
#include "vrf/vrf.h"

vrf::Type type = vrf::Type::RSA_FDH_VRF_RSA2048_SHA256;
std::unique_ptr<vrf::SecretKey> sk = vrf::VRF::Create(type);
if (!sk || !sk->is_initialized()) {
    throw std::runtime_error("VRF secret key creation failed");
}
```

### 2) Accessing keys

Once a `vrf::SecretKey` instance has been successfully created, the public key can be retrieved as follows:
```cpp
std::unique_ptr<vrf::PublicKey> pk = sk->get_public_key();
if (!pk || !pk->is_initialized()) {
    throw std::runtime_error("VRF public key creation failed");
}
```

The public key can be serialized (to a DER-encoded SPKI struct) and deserialized as follows:
```cpp
// The to_bytes member function serializes the VRF type as the first byte of
// the output, followed by an encoding of the public key.
std::vector<std::byte> der_spki = pk->to_bytes();
if (der_spki.empty()) {
    throw std::runtime_error("Failed to serialize public key");
}

std::unique_ptr<vrf::PublicKey> pk2 = vrf::VRF::PublicKeyFromBytes(der_spki);
if (!pk2 || !pk2->is_initialized()) {
    throw std::runtime_error("Deserialization failed");
}
```

The secret key can be serialized to a `vrf::SecureBuf`, which uses OpenSSL secure memory that is zeroed on destruction.
For EC-based VRFs, the serialized form is the raw scalar bytes; for RSA-based VRFs, it is a DER-encoded PKCS#8 structure.
```cpp
vrf::SecureBuf sk_bytes = sk->to_secure_bytes();
if (!sk_bytes.has_value()) {
    throw std::runtime_error("Failed to serialize secret key");
}

std::unique_ptr<vrf::SecretKey> sk2 = vrf::VRF::SecretKeyFromBytes(sk_bytes);
if (!sk2 || !sk2->is_initialized()) {
    throw std::runtime_error("Deserialization failed");
}
```

### 3) Prove and verify

Given an input `data`, the secret key can produce a VRF proof.
The public key verifies the proof and returns whether the verification succeeded, and if so, the VRF "hash" value.
```cpp
std::vector<std::byte> data = /* your bytes */;

// The proof is sent to the verifier (who has the public key).
std::unique_ptr<vrf::Proof> proof = sk->get_vrf_proof(data);
if (!proof || !proof->is_initialized()) {
    throw std::runtime_error("Proof creation failed");
}

// Verify the proof with the public key.
std::pair<bool, std::vector<std::byte>> res = pk->verify_vrf_proof(data, proof);
if (!res.first) {
    throw std::runtime_error("Proof verification failed");
}

// If res.first is true, the VRF value is in the second value of the pair.
std::vector<std::byte> hash1 = res.first;

// The VRF value can also be obtained directly from the proof object as follows.
// However, this does *not* verify the proof!
std::vector<std::byte> hash2 = proof->get_vrf_value();
if (hash2.empty()) {
    throw std::runtime_error("Failed to extract VRF value");
}

if (hash1 != hash2) {
    throw std::runtime_error("This should never be reached");
}
```

The proof can be serialized and deserialized as follows:
```cpp
std::vector<std::byte> proof_bytes = proof->to_bytes();
if (proof_bytes.empty()) {
    throw std::runtime_error("Failed to serialize proof");
}

std::unique_ptr<vrf::Proof> proof2 = vrf::VRF::ProofFromBytes(proof_bytes);
if (!proof2 || !proof2->is_initialized()) {
    throw std::runtime_error("Deserialization failed");
}
```

### 4) Other functions

All of the VRF objects above (`vrf::SecretKey`, `vrf::PublicKey`, `vrf::Proof`) store their `vrf::Type`.
This can retrieved using the member function `get_type()`.

Each of the functions taking as input `std::span` of bytes has a flexible set of overloads that accepts spans of other 1-byte types (e.g., `unsigned char`, see the `ByteLike` concept in [vrf/vrf_base.h](vrf/vrf_base.h)), as well as overloads that accept a `std::ranges::contiguous_range` of similar 1-byte types with some limitations (see the `ByteRange` concept in [vrf/vrf_base.h](vrf/vrf_base.h)).
This means that these functions can be called also by passing directly (by value or reference) `std::vector`, `std:array`, or other similar containers.

### 5) Logging

`cppvrf` provides a simple logging API (see [vrf/log.h](vrf/log.h)), which can be adapted to work with almost any logging system.
By default, the library simply logs to `std::cout` and `std::cerr` using the logger specified in [vrf/stdout_log.cpp](vrf/stdout_log.cpp).
To create a custom logger, include [vrf/log.h](vrf/log.h) in your source file and create an instance of `std::shared_ptr<vrf::Logger>` using `vrf::Logger::Create`.
This function takes as input three arrays of operation handlers (wrapped in `std::function`) for (1) the actual logging operations, (2) manual flush events, and (3) closing the log.
Any of the handlers can be left empty, in which case the function is simply not called.
For simple examples, see [vrf/stdout_log.cpp](vrf/stdout_log.cpp) and [tests/log_tests.cpp](tests/log_tests.cpp).

Once a `std::shared_ptr<vrf::Logger>` instance has been created, it can be used to log messages at different log levels (see `vrf::LogLevel` in [vrf/log.h](vrf/log.h)).
It can also be used to set a (minimum) log level, so that logs at any lower level will not be logged.
The default log level is `vrf::LogLevel::info`.

