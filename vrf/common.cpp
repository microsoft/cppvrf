// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "vrf/common.h"
#include "vrf/log.h"
#include <openssl/decoder.h>
#include <openssl/encoder.h>

namespace vrf
{

OSSL_LIB_CTX *get_libctx()
{
    // For a custom libctx, create a RAII wrapper here instead and return
    // a pointer to the underlying OSSL_LIB_CTX.
    static OSSL_LIB_CTX *libctx = nullptr;
    return libctx;
}

const char *get_propquery()
{
    // Set a custom propquery here.
    static const char *propquery = nullptr;
    return propquery;
}

EVP_PKEY *decode_public_key_from_der_spki(const char *algorithm_name, std::span<const std::byte> der_spki)
{
    if (nullptr == algorithm_name || der_spki.empty())
    {
        GetLogger()->debug("decode_public_key_from_der_spki failed for algorithm {}, data size {}.",
                           nullptr == algorithm_name ? "null" : algorithm_name, der_spki.size());
        return nullptr;
    }

    EVP_PKEY *pkey = nullptr;
    OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", "SubjectPublicKeyInfo", algorithm_name,
                                                           EVP_PKEY_PUBLIC_KEY, get_libctx(), get_propquery());
    if (nullptr == dctx)
    {
        GetLogger()->error("Failed to create OSSL_DECODER_CTX for loading public key.");
        return nullptr;
    }

    const unsigned char *der_data = reinterpret_cast<const unsigned char *>(der_spki.data());
    std::size_t der_data_len = der_spki.size();
    if (1 != OSSL_DECODER_from_data(dctx, &der_data, &der_data_len))
    {
        GetLogger()->debug("Failed to decode DER SPKI into EVP_PKEY using OSSL_DECODER_from_data.");
        EVP_PKEY_free(pkey);
        OSSL_DECODER_CTX_free(dctx);
        return nullptr;
    }

    OSSL_DECODER_CTX_free(dctx);

    GetLogger()->trace("Decoded public key (address {:p}) from DER SPKI for algorithm {}, data size {}.",
                       static_cast<const void *>(pkey), algorithm_name, der_spki.size());
    return pkey;
}

std::vector<std::byte> encode_public_key_to_der_spki_with_type(Type type, const EVP_PKEY *pkey)
{
    if (nullptr == pkey)
    {
        GetLogger()->debug("encode_public_key_from_der_spki_with_type called with null key.");
        return {};
    }

    OSSL_ENCODER_CTX *ectx =
        OSSL_ENCODER_CTX_new_for_pkey(pkey, EVP_PKEY_PUBLIC_KEY, "DER", "SubjectPublicKeyInfo", get_propquery());
    if (nullptr == ectx)
    {
        GetLogger()->error("Failed to create OSSL_ENCODER_CTX for saving public key.");
        return {};
    }

    unsigned char *der_data = nullptr;
    std::size_t der_data_len = 0;
    if (1 != OSSL_ENCODER_to_data(ectx, &der_data, &der_data_len))
    {
        GetLogger()->error("Failed to encode public key to DER SPKI using OSSL_ENCODER_to_data.");
        OSSL_ENCODER_CTX_free(ectx);
        return {};
    }

    const std::byte *der_data_begin = reinterpret_cast<const std::byte *>(der_data);
    const std::byte *der_data_end = der_data_begin + der_data_len;

    std::vector<std::byte> buf{der_data_len + 1 /* for type byte */};
    buf[0] = to_byte(type);
    std::copy(der_data_begin, der_data_end, buf.begin() + 1);

    OPENSSL_free(der_data);
    OSSL_ENCODER_CTX_free(ectx);

    GetLogger()->trace("Encoded public key (address {:p}) to DER SPKI for type {}, data size {}.",
                       static_cast<const void *>(pkey), to_string(type), buf.size());
    return buf;
}

EVP_PKEY *decode_secret_key_from_der_pkcs8(const char *algorithm_name, std::span<const std::byte> der_pkcs8)
{
    if (nullptr == algorithm_name || der_pkcs8.empty())
    {
        GetLogger()->debug("decode_secret_key_from_der_pkcs8 failed for algorithm {}, data size {}.",
                           nullptr == algorithm_name ? "null" : algorithm_name, der_pkcs8.size());
        return nullptr;
    }

    EVP_PKEY *pkey = nullptr;
    OSSL_DECODER_CTX *dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, "DER", "PrivateKeyInfo", algorithm_name,
                                                           EVP_PKEY_KEYPAIR, get_libctx(), get_propquery());
    if (nullptr == dctx)
    {
        GetLogger()->error("Failed to create OSSL_DECODER_CTX for loading secret key.");
        return nullptr;
    }

    const unsigned char *der_data = reinterpret_cast<const unsigned char *>(der_pkcs8.data());
    std::size_t der_data_len = der_pkcs8.size();
    if (1 != OSSL_DECODER_from_data(dctx, &der_data, &der_data_len))
    {
        GetLogger()->debug("Failed to decode DER PKCS#8 into EVP_PKEY using OSSL_DECODER_from_data.");
        EVP_PKEY_free(pkey);
        OSSL_DECODER_CTX_free(dctx);
        return nullptr;
    }

    OSSL_DECODER_CTX_free(dctx);

    GetLogger()->trace("Decoded secret key (address {:p}) from DER PKCS#8 for algorithm {}, data size {}.",
                       static_cast<const void *>(pkey), algorithm_name, der_pkcs8.size());
    return pkey;
}

SecureBuf encode_secret_key_to_der_pkcs8_with_type(vrf::Type type, const EVP_PKEY *pkey)
{
    if (nullptr == pkey)
    {
        GetLogger()->debug("encode_secret_key_to_der_pkcs8_with_type called with null key.");
        return {};
    }

    OSSL_ENCODER_CTX *ectx =
        OSSL_ENCODER_CTX_new_for_pkey(pkey, EVP_PKEY_KEYPAIR, "DER", "PrivateKeyInfo", get_propquery());
    if (nullptr == ectx)
    {
        GetLogger()->error("Failed to create OSSL_ENCODER_CTX for saving secret key.");
        return {};
    }

    unsigned char *der_data = nullptr;
    std::size_t der_data_len = 0;
    if (1 != OSSL_ENCODER_to_data(ectx, &der_data, &der_data_len))
    {
        GetLogger()->error("Failed to encode to DER PKCS#8 using OSSL_ENCODER_to_data.");
        OSSL_ENCODER_CTX_free(ectx);
        return {};
    }

    SecureBuf buf{der_data_len + 1 /* for type byte */};
    if (buf.has_value())
    {
        // buf.has_value() is true only if the size is at least 1.
        buf.get()[0] = to_byte(type);

        // Copy in the value to the remaining buffer.
        std::copy_n(reinterpret_cast<const std::byte *>(der_data), der_data_len, buf.get() + 1);
    }

    SecureBuf::Cleanse(der_data, der_data_len);
    OPENSSL_free(der_data);
    OSSL_ENCODER_CTX_free(ectx);

    GetLogger()->trace("Encoded secret key (address {:p}) to DER PKCS#8 for type {}, data size {}.",
                       static_cast<const void *>(pkey), to_string(type), buf.size());
    return buf;
}

EVP_PKEY *evp_pkey_upref(EVP_PKEY *pkey)
{
    if (nullptr == pkey)
    {
        return nullptr;
    }

    if (1 != EVP_PKEY_up_ref(pkey))
    {
        GetLogger()->error("Failed to increment reference count for EVP_PKEY (address {:p}).",
                           static_cast<const void *>(pkey));
        return nullptr;
    }

    GetLogger()->trace("Incremented reference count for EVP_PKEY (address {:p}).", static_cast<const void *>(pkey));
    return pkey;
}

std::pair<vrf::Type, std::span<const std::byte>> extract_type_from_span(std::span<const std::byte> data)
{
    // We extract the first byte of the data as the type, and return the rest of the data as a separate span. If the
    // data is empty, we return UNKNOWN as the type and an empty span.
    if (data.empty())
    {
        GetLogger()->debug("extract_type_from_span called with empty data.");
        return {vrf::Type::unknown, std::span<const std::byte>{}};
    }

    const std::uint8_t type_byte = std::to_integer<std::uint8_t>(data[0]);

    // First check that this is in range, i.e., less than vrf::Type::UNKNOWN.
    if (static_cast<std::size_t>(type_byte) >= static_cast<std::size_t>(vrf::Type::unknown))
    {
        GetLogger()->debug("extract_type_from_span called with invalid type byte: {}", type_byte);
        return {vrf::Type::unknown, std::span<const std::byte>{}};
    }

    // We can safely static_cast here since we've verified that the type byte is in range.
    const vrf::Type type = static_cast<vrf::Type>(type_byte);

    // We need to check data.size() > 1, because otherwise data.subspan(1) if undefined behavior.
    const bool subspan_is_empty = data.size() <= 1;
    std::span<const std::byte> remaining_data = subspan_is_empty ? std::span<const std::byte>{} : data.subspan(1);

    GetLogger()->trace("Extracted type {} from data span, remaining data size {} (start address {:p}).",
                       to_string(type), remaining_data.size(), static_cast<const void *>(remaining_data.data()));
    return {type, remaining_data};
}

} // namespace vrf
