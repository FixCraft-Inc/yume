/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "server/auth.hpp"

#include <openssl/pem.h>
#include <openssl/sha.h>

#include <mutex>
#include <fstream>
#include <ctime>
#include <stdexcept>

#include <nlohmann/json.hpp>

namespace yume::server {

std::vector<crypto::Bytes> load_authorized_keys(const std::string& path) {
    std::vector<crypto::Bytes> keys;
    if (path.empty()) {
        return keys;
    }

    BIO* bio = BIO_new_file(path.c_str(), "r");
    if (!bio) {
        throw std::runtime_error("failed to open authorized_keys");
    }

    while (true) {
        EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        if (!key) {
            break;
        }
        int len = i2d_PUBKEY(key, nullptr);
        if (len > 0) {
            crypto::Bytes der(static_cast<size_t>(len));
            unsigned char* p = der.data();
            i2d_PUBKEY(key, &p);
            keys.push_back(std::move(der));
        }
        EVP_PKEY_free(key);
    }
    BIO_free(bio);

    return keys;
}

bool is_authorized(EVP_PKEY* pubkey, const std::vector<crypto::Bytes>& authorized) {
    if (!pubkey) {
        return false;
    }
    int len = i2d_PUBKEY(pubkey, nullptr);
    if (len <= 0) {
        return false;
    }
    crypto::Bytes der(static_cast<size_t>(len));
    unsigned char* p = der.data();
    i2d_PUBKEY(pubkey, &p);

    for (const auto& allowed : authorized) {
        if (allowed == der) {
            return true;
        }
    }
    return false;
}

crypto::Bytes read_field(const crypto::Bytes& payload, size_t& offset) {
    if (offset + 2 > payload.size()) {
        throw std::runtime_error("auth payload truncated");
    }
    uint16_t len = static_cast<uint16_t>((payload[offset] << 8) | payload[offset + 1]);
    offset += 2;
    if (offset + len > payload.size()) {
        throw std::runtime_error("auth payload truncated");
    }
    crypto::Bytes out(payload.begin() + offset, payload.begin() + offset + len);
    offset += len;
    return out;
}

std::string fingerprint_pubkey(EVP_PKEY* pubkey) {
    if (!pubkey) {
        return "";
    }
    int len = i2d_PUBKEY(pubkey, nullptr);
    if (len <= 0) {
        return "";
    }
    crypto::Bytes der(static_cast<size_t>(len));
    unsigned char* p = der.data();
    i2d_PUBKEY(pubkey, &p);

    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};
    SHA256(der.data(), der.size(), hash);

    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(SHA256_DIGEST_LENGTH * 2);
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        out.push_back(kHex[(hash[i] >> 4) & 0xF]);
        out.push_back(kHex[hash[i] & 0xF]);
    }
    return out;
}

void update_auth_meta(const std::string& meta_path, const std::string& fingerprint, const std::string& alias) {
    if (meta_path.empty() || fingerprint.empty()) {
        return;
    }
    static std::mutex meta_mutex;
    std::lock_guard<std::mutex> lock(meta_mutex);

    nlohmann::json meta = nlohmann::json::object();
    std::ifstream in(meta_path);
    if (in) {
        try {
            in >> meta;
        } catch (...) {
            meta = nlohmann::json::object();
        }
    }
    nlohmann::json entry = meta.value(fingerprint, nlohmann::json::object());
    if (!alias.empty()) {
        entry["alias"] = alias;
    }
    entry["last_seen"] = static_cast<long long>(std::time(nullptr));
    meta[fingerprint] = entry;

    std::ofstream out(meta_path);
    out << meta.dump(2);
}

}  // namespace yume::server
