/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "modules/relay/storage_crypto.hpp"

#include <limits>
#include <stdexcept>

#include <basefwx/crypto.hpp>
#include <openssl/rand.h>

namespace yume::relay::storage {

Bytes seal_chacha20(const Bytes& plaintext, const Bytes& key, const Bytes& nonce) {
    return basefwx::crypto::ChaCha20Poly1305EncryptWithIv(key, nonce, plaintext, {});
}

Bytes open_chacha20(const Bytes& sealed, const Bytes& key, const Bytes& nonce) {
    return basefwx::crypto::ChaCha20Poly1305DecryptWithIvOwned(
        key, nonce, sealed.data(), sealed.size(), {});
}

Bytes random_bytes(std::size_t length) {
    if (length > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        throw std::runtime_error("random byte request is too large");
    }
    Bytes out(length);
    if (length != 0U && RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
        throw std::runtime_error("random byte generation failed");
    }
    return out;
}

}  // namespace yume::relay::storage
