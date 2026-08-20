/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * CLI certificate and OpenSSL helpers.
 */

#include "client/cli/connect/cert.hpp"

#include <filesystem>
#include <iostream>
#include <memory>
#include <string>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "util.hpp"

namespace yume::client {

std::string hex_encode(const unsigned char* data, size_t len) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(kHex[(data[i] >> 4) & 0xF]);
        out.push_back(kHex[data[i] & 0xF]);
    }
    return out;
}

void warn_security_disabled(const std::string& what, bool boring) {
    if (boring) {
        std::cerr << "\033[1;31mSecurity warning: " << what << " disabled\033[0m\n";
        return;
    }
    std::cerr << "\033[1;31m🔓⛓️‍💥 YOUR SECURITY IS SUFFERING BECAUSE YOU HAVE DISABLED: "
              << what << "\033[0m\n";
}

std::string get_peer_cert_fingerprint(EVP_PKEY* key, SSL* ssl) {
    (void)key;
    if (!ssl) {
        return {};
    }
    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        return {};
    }
    unsigned char* der = nullptr;
    int len = i2d_X509(cert, &der);
    X509_free(cert);
    if (len <= 0 || !der) {
        if (der) OPENSSL_free(der);
        return {};
    }
    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};
    SHA256(der, static_cast<size_t>(len), hash);
    OPENSSL_free(der);
    return hex_encode(hash, SHA256_DIGEST_LENGTH);
}

crypto::EVP_PKEY_ptr load_pubkey_from_cert(const std::string& path) {
    BIO* bio = BIO_new_file(path.c_str(), "r");
    if (!bio) {
        return {nullptr, EVP_PKEY_free};
    }
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!cert) {
        return {nullptr, EVP_PKEY_free};
    }
    EVP_PKEY* key = X509_get_pubkey(cert);
    X509_free(cert);
    return {key, EVP_PKEY_free};
}


X509_ptr load_cert_from_pem(const std::string& pem) {
    if (pem.empty()) {
        return {nullptr, X509_free};
    }
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) {
        return {nullptr, X509_free};
    }
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return {cert, X509_free};
}

crypto::EVP_PKEY_ptr load_pubkey_from_cert_pem(const std::string& pem) {
    auto cert = load_cert_from_pem(pem);
    if (!cert) {
        return {nullptr, EVP_PKEY_free};
    }
    EVP_PKEY* key = X509_get_pubkey(cert.get());
    return {key, EVP_PKEY_free};
}

X509_ptr load_cert_from_file(const std::string& path) {
    BIO* bio = BIO_new_file(path.c_str(), "r");
    if (!bio) {
        return {nullptr, X509_free};
    }
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return {cert, X509_free};
}

bool is_cert_time_valid(X509* cert) {
    if (!cert) {
        return false;
    }
    const ASN1_TIME* not_before = X509_get0_notBefore(cert);
    const ASN1_TIME* not_after = X509_get0_notAfter(cert);
    if (!not_before || !not_after) {
        return false;
    }
    if (X509_cmp_time(not_before, nullptr) > 0) {
        return false;
    }
    if (X509_cmp_time(not_after, nullptr) < 0) {
        return false;
    }
    return true;
}

std::string describe_verify_result(long code, const std::string& host) {
    if (code == X509_V_OK) {
        return {};
    }
    switch (code) {
        case X509_V_ERR_HOSTNAME_MISMATCH:
            return "hostname mismatch (" + host + ")";
#ifdef X509_V_ERR_IP_ADDRESS_MISMATCH
        case X509_V_ERR_IP_ADDRESS_MISMATCH:
            return "IP address mismatch (" + host + ")";
#endif
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
            return "issuer CA not found";
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            return "self-signed leaf certificate";
        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
            return "self-signed certificate in chain";
        case X509_V_ERR_CERT_HAS_EXPIRED:
            return "certificate expired";
        case X509_V_ERR_CERT_NOT_YET_VALID:
            return "certificate not yet valid";
        default:
            return X509_verify_cert_error_string(code);
    }
}

std::string describe_openssl_error() {
    unsigned long err = ERR_peek_last_error();
    if (!err) {
        return {};
    }
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return buf;
}

bool file_exists(const std::string& path) {
    if (path.empty()) {
        return false;
    }
    std::error_code ec;
    auto st = std::filesystem::status(path, ec);
    if (ec) {
        return false;
    }
    return std::filesystem::is_regular_file(st);
}

bool require_file(const char* label, const std::string& path) {
    if (path.empty()) {
        return true;
    }
    if (!file_exists(path)) {
        util::log_error(std::string(label) + " not found or not a file: " + path);
        return false;
    }
    return true;
}

bool verify_cert_signed_by_ca(X509* cert, X509* ca) {
    if (!cert || !ca) {
        return false;
    }
    // This proof uses a CA trust anchor and a non-CA delegated server leaf.
    // Checking only the leaf signature would ignore validity periods, issuer
    // binding, and basic constraints.
    if (X509_check_ca(ca) <= 0 || X509_check_ca(cert) != 0 ||
        !is_cert_time_valid(ca) || !is_cert_time_valid(cert) ||
        X509_NAME_cmp(X509_get_issuer_name(cert), X509_get_subject_name(ca)) != 0) {
        return false;
    }
    EVP_PKEY* ca_pub = X509_get_pubkey(ca);
    if (!ca_pub) {
        return false;
    }
    bool ok = X509_verify(cert, ca_pub) == 1;
    EVP_PKEY_free(ca_pub);
    return ok;
}
}  // namespace yume::client
