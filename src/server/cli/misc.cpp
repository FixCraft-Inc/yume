/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/cli/misc.hpp"

#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>

#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include "platform/platform.hpp"
#include "util.hpp"

namespace yume::server_cli {

std::string read_file_bytes(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open file: " + path);
    }
    std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return data;
}

std::string cert_fingerprint_sha256(const std::string& cert_path) {
    std::ifstream in(cert_path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open cert: " + cert_path);
    }
    std::string pem((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) {
        throw std::runtime_error("failed to read cert bio");
    }
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!cert) {
        throw std::runtime_error("failed to parse cert");
    }
    unsigned char* der = nullptr;
    int len = i2d_X509(cert, &der);
    X509_free(cert);
    if (len <= 0 || !der) {
        if (der) OPENSSL_free(der);
        throw std::runtime_error("failed to encode cert");
    }
    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};
    SHA256(der, static_cast<size_t>(len), hash);
    OPENSSL_free(der);
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(SHA256_DIGEST_LENGTH * 2);
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        out.push_back(kHex[(hash[i] >> 4) & 0xF]);
        out.push_back(kHex[hash[i] & 0xF]);
    }
    return out;
}

std::string sha256_hex(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(SHA256_DIGEST_LENGTH * 2);
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        out.push_back(kHex[(hash[i] >> 4) & 0xF]);
        out.push_back(kHex[hash[i] & 0xF]);
    }
    return out;
}

std::string get_self_path(const char* argv0) {
    return yume::platform::executable_path(argv0);
}

std::string resolve_filter_list_spec_path(const std::string& spec,
                                          const std::string& base_dir,
                                          const std::string& exe_dir) {
    const auto first = spec.find(':');
    const auto second = first == std::string::npos ? std::string::npos : spec.find(':', first + 1);
    if (first == std::string::npos || second == std::string::npos || second + 1 >= spec.size()) {
        return spec;
    }
    const std::string prefix = spec.substr(0, second + 1);
    const std::string path = yume::util::resolve_path(spec.substr(second + 1), base_dir, exe_dir);
    return prefix + path;
}

}  // namespace yume::server_cli
