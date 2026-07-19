/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>

#include "core/security/ratchet.hpp"

namespace yume::tools::benchmark {

struct TransferResult {
    std::uint64_t plaintext_bytes{0};
    std::uint64_t frames{0};
    std::uint64_t rekeys{0};
    double seconds{0.0};
};

// Exercises the complete ML-KEM-1024 + X25519 + random-PSK establishment
// schedule and verifies that both peers derive the same initial root.
void verify_hybrid_establishment();

// In-memory client/server pair using the production SessionRatchet. This is a
// crypto benchmark: it deliberately excludes TLS, H2 and socket overhead.
class SessionPair {
public:
    SessionPair();
    ~SessionPair();
    SessionPair(const SessionPair&) = delete;
    SessionPair& operator=(const SessionPair&) = delete;
    SessionPair(SessionPair&&) noexcept;
    SessionPair& operator=(SessionPair&&) noexcept;

    TransferResult transfer(std::uint64_t plaintext_bytes,
                            std::size_t chunk_bytes,
                            ratchet::Direction direction);
    void rekey(ratchet::Direction direction);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace yume::tools::benchmark
