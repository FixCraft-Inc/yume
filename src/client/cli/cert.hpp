#pragma once

/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 *
 * CLI certificate / OpenSSL helpers, extracted from client/cli/entry.cpp.
 * No behavior change.
 */

#include <cstddef>
#include <memory>
#include <string>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "core/crypto.hpp"

namespace yume::client {

using X509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;

std::string hex_encode(const unsigned char* data, size_t len);
void warn_security_disabled(const std::string& what, bool boring);
std::string get_peer_cert_fingerprint(EVP_PKEY* key, SSL* ssl);
crypto::EVP_PKEY_ptr load_pubkey_from_cert(const std::string& path);
X509_ptr load_cert_from_pem(const std::string& pem);
crypto::EVP_PKEY_ptr load_pubkey_from_cert_pem(const std::string& pem);
X509_ptr load_cert_from_file(const std::string& path);
bool is_cert_time_valid(X509* cert);
std::string describe_verify_result(long code, const std::string& host);
std::string describe_openssl_error();
bool file_exists(const std::string& path);
bool require_file(const char* label, const std::string& path);
bool verify_cert_signed_by_ca(X509* cert, X509* ca);

}  // namespace yume::client
