/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

#include "core/version.hpp"

namespace yume::auth_v2 {

using Bytes = std::vector<std::uint8_t>;

inline constexpr std::string_view kTransportVersion = yume::kTransportVersion;
inline constexpr std::size_t kMaxRecordBytes = 64U * 1024U;

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
};

struct Response {
    Bytes encoded;
    Bytes x25519_public_key;
    Bytes mlkem_ciphertext;
    Bytes identity;
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
                     const Bytes& transcript_salt);
Challenge ParseChallenge(const Bytes& encoded);

Bytes BuildUnsignedResponse(const Bytes& x25519_public_key,
                            const Bytes& mlkem_ciphertext,
                            const Bytes& identity);
Bytes BuildResponse(const Bytes& x25519_public_key,
                    const Bytes& mlkem_ciphertext,
                    const Bytes& identity,
                    const Bytes& signature);
Response ParseResponse(const Bytes& encoded);
Bytes BuildSignatureInput(const Bytes& challenge_record,
                          const Bytes& unsigned_response_record);

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
