/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace yume::inner {

using Bytes = std::vector<std::uint8_t>;

struct Argon2Limits {
    std::uint32_t time_max{0};
    std::uint32_t memory_max{0};
    std::uint32_t parallelism_max{0};
};

struct Config {
    bool enabled{false};
    std::string pq_public_key;
    std::string pq_private_key;
    bool allow_embedded_master{false};
    Argon2Limits argon2_limits;
};

struct ClientHandshake {
    bool enabled{false};
    Bytes pq_ciphertext;
    Bytes salt;
    Bytes key;
    std::string kdf;
    std::uint32_t argon2_time{0};
    std::uint32_t argon2_memory{0};
    std::uint32_t argon2_parallelism{0};
    std::uint32_t pbkdf2_iters{0};
};

// Builds the legacy client-side inner handshake material. Like the resolvers
// below, this is no longer on a shipped path: the 2.0 client establishes its
// inner channel through AUTH v2 (ML-KEM-1024 + X25519 + PSK), never through a
// config-derived legacy KDF. It is retained because the KDF policy tests pin
// their expected parameters against it. Do not treat a call site appearing here
// as evidence that legacy establishment is reachable.
ClientHandshake client_prepare(const Config& cfg, bool heavy);
struct DerivedKey {
    Bytes key;
    std::string kdf;
};

struct KdfParams {
    std::string name;
    std::uint32_t argon2_time{0};
    std::uint32_t argon2_memory{0};
    std::uint32_t argon2_parallelism{0};
    std::uint32_t pbkdf2_iters{0};
};

// Resolves zero/omitted KDF fields to the exact values a legacy server-side
// derivation would use. Callers that reserve resources or enforce caps before
// derivation must use this rather than accounting the peer's raw zeros.
//
// No shipped code path performs a server-side legacy KDF derivation. The
// server session speaks only AUTH v2, which pins its KDF to HKDF and never
// accepts a peer-supplied KDF request, and federation dials speak AUTH v2 too
// (yume/federation-v2). The resolver and the *_exceed_limits guards below are
// therefore not live controls; they are retained because the admission tests
// pin their policy values. Do not read their presence as runtime enforcement,
// and do not wire a peer-selectable KDF back in: that revives attack surface
// AUTH v2 deliberately removed.
KdfParams resolve_server_kdf_params(const Config& cfg,
                                    bool heavy,
                                    const std::optional<KdfParams>& kdf_params);

// The client-side counterpart, reporting exactly the parameters client_prepare
// would use for this config. Non-live for the same reason: see client_prepare.
KdfParams resolve_client_kdf_params(const Config& cfg, bool heavy);

bool pq_supported();
bool argon2_supported();
bool pbkdf2_supported();
std::string pq_backend_version();
std::string argon2_backend_version();
Argon2Limits argon2_env_limits();
bool argon2_params_exceed_limits(const KdfParams& params,
                                 const Argon2Limits& limits,
                                 std::string* reason);
std::uint32_t pbkdf2_env_iters_max();
bool pbkdf2_params_exceed_limits(const KdfParams& params,
                                 std::uint32_t iters_max,
                                 std::string* reason);

bool generate_pq_keypair(const std::string& private_path,
                         const std::string& public_path,
                         std::string* err);

bool validate_pq_keypair(const std::string& private_path,
                         const std::string& public_path,
                         std::string* err);

Bytes encrypt_payload(const Bytes& key, std::uint8_t frame_type, std::uint8_t stream_id, const Bytes& plaintext);
Bytes decrypt_payload(const Bytes& key, std::uint8_t frame_type, std::uint8_t stream_id, const Bytes& blob);

}  // namespace yume::inner
