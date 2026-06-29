/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

namespace yume::crypto {

using Bytes = std::vector<uint8_t>;
using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

struct KeyPair {
    EVP_PKEY_ptr private_key{nullptr, EVP_PKEY_free};
    EVP_PKEY_ptr public_key{nullptr, EVP_PKEY_free};
};

KeyPair load_keypair(const std::string& path_priv, const std::string& path_pub);

bool verify_key(EVP_PKEY* pubkey, const Bytes& message, const Bytes& signature);
Bytes sign_message(EVP_PKEY* privkey, const Bytes& message);

Bytes generate_session_key(EVP_PKEY* ecdh_local, EVP_PKEY* ecdh_remote, size_t out_len = 32);
EVP_PKEY_ptr generate_x25519_key();
EVP_PKEY_ptr import_x25519_public_key(const Bytes& raw_public_key);
Bytes export_raw_public_key(EVP_PKEY* key);
Bytes hkdf_sha256(const Bytes& key_material,
                  std::string_view info,
                  size_t out_len,
                  const Bytes& salt = {});

Bytes encrypt_chacha20(const Bytes& data, const Bytes& key, const Bytes& nonce);
Bytes decrypt_chacha20(const Bytes& data, const Bytes& key, const Bytes& nonce);

Bytes hmac_sha256(const Bytes& data, const Bytes& key);
Bytes random_bytes(size_t len);

}  // namespace yume::crypto
