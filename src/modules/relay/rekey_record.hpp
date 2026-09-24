/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace yume::relay::ratchet {

// The REKEY_INIT and REKEY_ACK payloads a relay ratchet exchanges. They use
// the transport-v2 AUTH record format, which the relay v2 ratchet was defined
// with:
//
//   schema[1]=3 | kind[1] | field_count[2] | fields...
//   field: flags[1] (0x01 critical) | id[1] | length[4] | value
//
// Integers are big-endian and field ids strictly increase. A record is at
// most 64 KiB and holds at most 64 fields. An unknown field is refused when
// critical and kept otherwise.

using RecordBytes = std::vector<std::uint8_t>;

inline constexpr std::size_t kMaxRekeyRecordBytes = 64U * 1024U;

enum class RekeyRecordKind : std::uint8_t {
    Init = 4,
    Ack = 5,
};

struct RecordField {
    std::uint8_t id{0};
    bool critical{true};
    RecordBytes value;
};

struct RekeyRecord {
    RekeyRecordKind kind{};
    std::vector<RecordField> fields;
};

RecordBytes EncodeRekeyRecord(RekeyRecordKind kind,
                              const std::vector<RecordField>& fields);
RekeyRecord DecodeRekeyRecord(const RecordBytes& encoded,
                              RekeyRecordKind expected_kind,
                              const std::vector<std::uint8_t>& known_fields);

struct RekeyInit {
    std::uint64_t next_epoch{0};
    RecordBytes mlkem_public_key;
    RecordBytes x25519_public_key;
};

struct RekeyAck {
    std::uint64_t next_epoch{0};
    RecordBytes mlkem_ciphertext;
    RecordBytes x25519_public_key;
};

// Build and parse check the epoch (nonzero), the ML-KEM-1024 field (1568
// bytes) and the X25519 public key (32 bytes), and throw std::runtime_error.
RecordBytes BuildRekeyInit(std::uint64_t next_epoch,
                           const RecordBytes& mlkem_public_key,
                           const RecordBytes& x25519_public_key);
RekeyInit ParseRekeyInit(const RecordBytes& encoded);
RecordBytes BuildRekeyAck(std::uint64_t next_epoch,
                          const RecordBytes& mlkem_ciphertext,
                          const RecordBytes& x25519_public_key);
RekeyAck ParseRekeyAck(const RecordBytes& encoded);

}  // namespace yume::relay::ratchet
