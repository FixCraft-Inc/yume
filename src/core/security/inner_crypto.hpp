/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

// ML-KEM keypair helpers.
//
// Establishment belongs to AUTH v2 (ML-KEM-1024 + X25519 + PSK), which pins
// its key schedule to HKDF and never accepts a peer-supplied KDF request.
// There is deliberately no config-derived KDF, no peer-selectable
// Argon2/PBKDF2 parameter family, no admission guard for one, and no static
// inner AEAD. Those were attack surface AUTH v2 removed, and a replayable
// static-key primitive must not come back alongside the ratchet.
namespace yume::inner {

using Bytes = std::vector<std::uint8_t>;

bool pq_supported();

bool generate_pq_keypair(const std::string& private_path,
                         const std::string& public_path,
                         std::string* error);

}  // namespace yume::inner
