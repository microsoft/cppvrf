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
        GetLogger()->warn("decode_public_key_from_der_spki called with null algorithm name or empty DER data.");
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
        GetLogger()->warn("Failed to decode DER SPKI into EVP_PKEY using OSSL_DECODER_from_data.");
        EVP_PKEY_free(pkey);
        OSSL_DECODER_CTX_free(dctx);
        return nullptr;
    }

    OSSL_DECODER_CTX_free(dctx);
    return pkey;
}

std::vector<std::byte> encode_public_key_to_der_spki(const EVP_PKEY *pkey)
{
    if (nullptr == pkey)
    {
        GetLogger()->warn("encode_public_key_from_der_spki called with null key.");
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
        GetLogger()->error("Failed to encode to DER SPKI using OSSL_ENCODER_to_data.");
        OSSL_ENCODER_CTX_free(ectx);
        return {};
    }

    const std::byte *der_data_begin = reinterpret_cast<const std::byte *>(der_data);
    const std::byte *der_data_end = der_data_begin + der_data_len;
    std::vector<std::byte> der_spki(der_data_begin, der_data_end);

    OPENSSL_free(der_data);
    OSSL_ENCODER_CTX_free(ectx);

    return der_spki;
}

EVP_PKEY *decode_secret_key_from_der_pkcs8(const char *algorithm_name, std::span<const std::byte> der_pkcs8)
{
    if (nullptr == algorithm_name || der_pkcs8.empty())
    {
        GetLogger()->warn("decode_secret_key_from_der_pkcs8 called with null algorithm name or empty DER data.");
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
        GetLogger()->warn("Failed to decode DER PKCS#8 into EVP_PKEY using OSSL_DECODER_from_data.");
        EVP_PKEY_free(pkey);
        OSSL_DECODER_CTX_free(dctx);
        return nullptr;
    }

    OSSL_DECODER_CTX_free(dctx);
    return pkey;
}

SecureBuf encode_secret_key_to_der_pkcs8(const EVP_PKEY *pkey)
{
    if (nullptr == pkey)
    {
        GetLogger()->warn("encode_secret_key_to_der_pkcs8 called with null key.");
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

    SecureBuf buf{der_data_len};
    if (buf.has_value())
    {
        std::copy_n(reinterpret_cast<const std::byte *>(der_data), der_data_len, buf.get());
    }

    SecureBuf::Cleanse(der_data, der_data_len);
    OPENSSL_free(der_data);
    OSSL_ENCODER_CTX_free(ectx);

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
        GetLogger()->error("Failed to increment reference count for EVP_PKEY.");
        return nullptr;
    }

    return pkey;
}

} // namespace vrf
