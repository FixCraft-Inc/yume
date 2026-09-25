/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace yume::relay::storage {

using Bytes = std::vector<std::uint8_t>;

// At-rest encryption for relay state on disk, such as history lines:
// ChaCha20-Poly1305 with a 32-byte key, a 12-byte nonce and empty associated
// data. The output is the ciphertext followed by the 16-byte tag. This is the
// stored format, so it never changes in place.
Bytes seal_chacha20(const Bytes& plaintext, const Bytes& key, const Bytes& nonce);
// Throws when the tag does not verify.
Bytes open_chacha20(const Bytes& sealed, const Bytes& key, const Bytes& nonce);

// Bytes from OpenSSL's generator. Throws when it fails.
Bytes random_bytes(std::size_t length);

}  // namespace yume::relay::storage
