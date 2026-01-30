/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "server/auth.hpp"

#include <openssl/pem.h>

#include <stdexcept>

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

}  // namespace yume::server
