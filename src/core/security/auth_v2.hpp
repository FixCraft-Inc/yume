/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

#include "core/security/ratchet_policy.hpp"
#include "core/version.hpp"

namespace yume::auth_v2 {

using Bytes = std::vector<std::uint8_t>;

inline constexpr std::string_view kTransportVersion = yume::kTransportVersion;
inline constexpr std::string_view kTransportProfile = yume::kTransportProfile;
inline constexpr std::size_t kMaxRecordBytes = 64U * 1024U;

// Length of the TLS 1.3 exporter value bound into the AUTH transcript. The
// codec owns the constant because it is the layer that enforces it; the
// exporter itself is produced by `core/security/channel_binding.hpp`, which
// keeps OpenSSL out of this translation unit.
inline constexpr std::size_t kChannelBindingLen = 32;

enum class RecordKind : std::uint8_t {
    Challenge = 1,
    Response = 2,
    AuthOk = 3,
    RekeyInit = 4,
    RekeyAck = 5,
};

struct Field {
    std::uint8_t id{0};
    bool critical{true};
    Bytes value;
};

struct Record {
    RecordKind kind{};
    std::vector<Field> fields;
};

Bytes EncodeRecord(RecordKind kind, const std::vector<Field>& fields);
Record DecodeRecord(const Bytes& encoded,
                    RecordKind expected_kind,
                    const std::vector<std::uint8_t>& known_fields);

struct Challenge {
    Bytes encoded;
    Bytes challenge;
    Bytes mlkem_public_key;
    Bytes x25519_public_key;
    Bytes psk_salt;
    Bytes transcript_salt;
    // Concurrent directional epoch offers this endpoint accepts inbound. It
    // bounds the peer's sending window, so it is the only thing that lets a
    // peer make this endpoint do repeated ML-KEM work or retain future roots.
    std::uint16_t rekey_window{0};
    ratchet::RatchetPolicy ratchet_policy{};
    std::string transport_profile;
};

struct Response {
    Bytes encoded;
    Bytes x25519_public_key;
    Bytes mlkem_ciphertext;
    Bytes identity;
    std::uint16_t rekey_window{0};
    ratchet::RatchetPolicy ratchet_policy{};
    std::string transport_profile;
    Bytes signature;
};

struct RekeyInit {
    std::uint64_t next_epoch{0};
    Bytes mlkem_public_key;
    Bytes x25519_public_key;
};

struct RekeyAck {
    std::uint64_t next_epoch{0};
    Bytes mlkem_ciphertext;
    Bytes x25519_public_key;
};

Bytes BuildChallenge(const Bytes& challenge,
                     const Bytes& mlkem_public_key,
                     const Bytes& x25519_public_key,
                     const Bytes& psk_salt,
                     const Bytes& transcript_salt,
                     std::uint16_t rekey_window,
                     const ratchet::RatchetPolicy& ratchet_policy);
Challenge ParseChallenge(const Bytes& encoded);

Bytes BuildUnsignedResponse(const Bytes& x25519_public_key,
                            const Bytes& mlkem_ciphertext,
                            const Bytes& identity,
                            std::uint16_t rekey_window,
                            const ratchet::RatchetPolicy& ratchet_policy);
Bytes BuildResponse(const Bytes& x25519_public_key,
                    const Bytes& mlkem_ciphertext,
                    const Bytes& identity,
                    std::uint16_t rekey_window,
                    const ratchet::RatchetPolicy& ratchet_policy,
                    const Bytes& signature);
Response ParseResponse(const Bytes& encoded);
// `channel_binding` is the 32-byte TLS 1.3 exporter each endpoint computes
// from its own live `SSL*` (see `core/security/channel_binding.hpp`). It is
// never transmitted: the client signs over its value and the server rebuilds
// the input from its own, so an endpoint relaying a live exchange to a second
// compatible server presents a signature over the wrong connection. A binding
// that is not exactly `kChannelBindingLen` bytes is rejected here so no build
// can fall back to an unbound transcript.
Bytes BuildSignatureInput(const Bytes& challenge_record,
                          const Bytes& unsigned_response_record,
                          const Bytes& channel_binding);

Bytes BuildAuthOk(const Bytes& server_info);
Bytes ParseAuthOk(const Bytes& encoded);

Bytes BuildRekeyInit(std::uint64_t next_epoch,
                     const Bytes& mlkem_public_key,
                     const Bytes& x25519_public_key);
RekeyInit ParseRekeyInit(const Bytes& encoded);
Bytes BuildRekeyAck(std::uint64_t next_epoch,
                    const Bytes& mlkem_ciphertext,
                    const Bytes& x25519_public_key);
RekeyAck ParseRekeyAck(const Bytes& encoded);

}  // namespace yume::auth_v2
