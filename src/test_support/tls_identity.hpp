/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */
#pragma once
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

namespace yume::test {
// Only for isolated test directories; never a production identity generator.
inline void write_tls_identity(const std::filesystem::path& certificate_path,
                             const std::filesystem::path& private_key_path) {
    // Fixture setup and validation must also execute in NDEBUG qualification builds.
    const auto require = [](bool condition, const char* description) {
        if (!condition) throw std::runtime_error(description);
    };
    const auto write_file = [&require](const std::filesystem::path& path,
                                     const std::string& contents) {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        require(out.is_open(), "test TLS identity file open failed");
        out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
        out.close();
        require(static_cast<bool>(out), "test TLS identity file write failed");
    };
    using KeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using CertPtr = std::unique_ptr<X509, decltype(&X509_free)>;
    using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;

    KeyPtr key(EVP_EC_gen("P-256"), EVP_PKEY_free);
    require(key != nullptr, "test TLS key generation failed");
    CertPtr certificate(X509_new(), X509_free);
    require(certificate != nullptr, "test TLS certificate allocation failed");
    require(X509_set_version(certificate.get(), 2) == 1,
            "test TLS certificate version failed");
    require(ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1) == 1,
            "test TLS certificate serial failed");
    require(X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0) != nullptr,
            "test TLS certificate start time failed");
    require(X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600) != nullptr,
            "test TLS certificate end time failed");
    require(X509_set_pubkey(certificate.get(), key.get()) == 1,
            "test TLS certificate public key failed");
    X509_NAME* name = X509_get_subject_name(certificate.get());
    require(name != nullptr, "test TLS certificate subject missing");
    require(X509_NAME_add_entry_by_txt(
               name, "CN", MBSTRING_ASC,
               reinterpret_cast<const unsigned char*>("yume-lock-test"), -1,
               -1, 0) == 1, "test TLS certificate subject failed");
    require(X509_set_issuer_name(certificate.get(), name) == 1,
            "test TLS certificate issuer failed");
    require(X509_sign(certificate.get(), key.get(), EVP_sha256()) > 0,
            "test TLS certificate signing failed");

    BioPtr certificate_bio(BIO_new(BIO_s_mem()), BIO_free);
    BioPtr key_bio(BIO_new(BIO_s_mem()), BIO_free);
    require(certificate_bio && key_bio, "test TLS PEM allocation failed");
    require(PEM_write_bio_X509(certificate_bio.get(), certificate.get()) == 1,
            "test TLS certificate encoding failed");
    require(PEM_write_bio_PrivateKey(key_bio.get(), key.get(), nullptr, nullptr,
                                    0, nullptr, nullptr) == 1,
            "test TLS private key encoding failed");
    char* certificate_data = nullptr;
    char* key_data = nullptr;
    const long certificate_size =
        BIO_get_mem_data(certificate_bio.get(), &certificate_data);
    const long key_size = BIO_get_mem_data(key_bio.get(), &key_data);
    require(certificate_size > 0 && certificate_data,
            "test TLS certificate encoding empty");
    require(key_size > 0 && key_data, "test TLS private key encoding empty");
    write_file(certificate_path,
               std::string(certificate_data,
                           static_cast<std::size_t>(certificate_size)));
    write_file(private_key_path,
               std::string(key_data, static_cast<std::size_t>(key_size)));
}

}  // namespace yume::test
