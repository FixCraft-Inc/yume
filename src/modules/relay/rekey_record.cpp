/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "modules/relay/rekey_record.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>

namespace yume::relay::ratchet {
namespace {

constexpr std::uint8_t kSchema = 3;
constexpr std::uint8_t kCritical = 0x01;
constexpr std::size_t kMaxFields = 64;
// ML-KEM-1024 public keys and ciphertexts have this exact width.
constexpr std::size_t kMlKem1024Bytes = 1568;
constexpr std::size_t kX25519PublicKeyBytes = 32;

void AppendU16(RecordBytes& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value >> 8));
    out.push_back(static_cast<std::uint8_t>(value));
}

void AppendU32(RecordBytes& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>(value >> 24));
    out.push_back(static_cast<std::uint8_t>(value >> 16));
    out.push_back(static_cast<std::uint8_t>(value >> 8));
    out.push_back(static_cast<std::uint8_t>(value));
}

std::uint16_t ReadU16(const RecordBytes& in, std::size_t* offset) {
    if (!offset || *offset > in.size() || in.size() - *offset < 2) {
        throw std::runtime_error("relay rekey record truncated u16");
    }
    const auto value = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(in[*offset]) << 8) |
        static_cast<std::uint16_t>(in[*offset + 1]));
    *offset += 2;
    return value;
}

std::uint32_t ReadU32(const RecordBytes& in, std::size_t* offset) {
    if (!offset || *offset > in.size() || in.size() - *offset < 4) {
        throw std::runtime_error("relay rekey record truncated u32");
    }
    std::uint32_t value = 0;
    for (int i = 0; i < 4; ++i) value = (value << 8) | in[(*offset)++];
    return value;
}

RecordBytes EpochBytes(std::uint64_t epoch) {
    RecordBytes value;
    value.reserve(8);
    for (int shift = 56; shift >= 0; shift -= 8) {
        value.push_back(static_cast<std::uint8_t>(epoch >> shift));
    }
    return value;
}

std::uint64_t ParseEpoch(const RecordBytes& value) {
    if (value.size() != 8) throw std::runtime_error("relay rekey epoch size is invalid");
    std::uint64_t out = 0;
    for (std::uint8_t byte : value) out = (out << 8) | byte;
    if (out == 0) throw std::runtime_error("invalid relay rekey epoch");
    return out;
}

const RecordBytes& Required(const RekeyRecord& record, std::uint8_t id) {
    const auto it = std::find_if(record.fields.begin(), record.fields.end(),
                                 [id](const RecordField& field) { return field.id == id; });
    if (it == record.fields.end() || !it->critical) {
        throw std::runtime_error("relay rekey record lacks required field " +
                                 std::to_string(id));
    }
    return it->value;
}

void RequireSize(const RecordBytes& value, std::size_t size, std::string_view name) {
    if (value.size() != size) {
        throw std::runtime_error("relay rekey " + std::string(name) + " size is invalid");
    }
}

RecordBytes Build(RekeyRecordKind kind, std::uint64_t next_epoch,
                  const RecordBytes& mlkem, std::string_view mlkem_name,
                  const RecordBytes& x25519_public_key) {
    if (next_epoch == 0) throw std::runtime_error("invalid relay rekey epoch");
    RequireSize(mlkem, kMlKem1024Bytes, mlkem_name);
    RequireSize(x25519_public_key, kX25519PublicKeyBytes, "X25519 public key");
    return EncodeRekeyRecord(kind, {
        {1, true, EpochBytes(next_epoch)}, {2, true, mlkem},
        {3, true, x25519_public_key},
    });
}

}  // namespace

RecordBytes EncodeRekeyRecord(RekeyRecordKind kind,
                              const std::vector<RecordField>& fields) {
    if (fields.size() > kMaxFields) {
        throw std::runtime_error("relay rekey record has too many fields");
    }
    RecordBytes out{kSchema, static_cast<std::uint8_t>(kind)};
    AppendU16(out, static_cast<std::uint16_t>(fields.size()));
    std::uint8_t previous = 0;
    for (const auto& field : fields) {
        if (field.id == 0 || field.id <= previous ||
            field.value.size() > std::numeric_limits<std::uint32_t>::max()) {
            throw std::runtime_error("relay rekey record fields are not canonical");
        }
        if (out.size() > kMaxRekeyRecordBytes - 6U ||
            field.value.size() > kMaxRekeyRecordBytes - out.size() - 6U) {
            throw std::runtime_error("relay rekey record exceeds 64 KiB");
        }
        out.push_back(field.critical ? kCritical : 0);
        out.push_back(field.id);
        AppendU32(out, static_cast<std::uint32_t>(field.value.size()));
        out.insert(out.end(), field.value.begin(), field.value.end());
        previous = field.id;
    }
    return out;
}

RekeyRecord DecodeRekeyRecord(const RecordBytes& encoded,
                              RekeyRecordKind expected_kind,
                              const std::vector<std::uint8_t>& known_fields) {
    if (encoded.size() < 4 || encoded.size() > kMaxRekeyRecordBytes) {
        throw std::runtime_error("relay rekey record size is invalid");
    }
    if (encoded[0] != kSchema || encoded[1] != static_cast<std::uint8_t>(expected_kind)) {
        throw std::runtime_error("relay rekey record schema or kind mismatch");
    }
    std::size_t offset = 2;
    const std::uint16_t field_count = ReadU16(encoded, &offset);
    if (field_count > kMaxFields) {
        throw std::runtime_error("relay rekey record field count exceeds cap");
    }
    RekeyRecord record{expected_kind, {}};
    record.fields.reserve(field_count);
    std::uint8_t previous = 0;
    for (std::uint16_t i = 0; i < field_count; ++i) {
        if (offset > encoded.size() || encoded.size() - offset < 6) {
            throw std::runtime_error("relay rekey record truncated field header");
        }
        const std::uint8_t flags = encoded[offset++];
        const std::uint8_t id = encoded[offset++];
        if ((flags & ~kCritical) != 0 || id == 0 || id <= previous) {
            throw std::runtime_error("relay rekey record field flags or order are invalid");
        }
        const std::uint32_t length = ReadU32(encoded, &offset);
        if (length > encoded.size() - offset) {
            throw std::runtime_error("relay rekey record truncated field value");
        }
        const bool known = std::find(known_fields.begin(), known_fields.end(), id) !=
                           known_fields.end();
        if (!known && (flags & kCritical) != 0) {
            throw std::runtime_error("relay rekey record unknown critical field");
        }
        RecordField field{id, (flags & kCritical) != 0, {}};
        field.value.assign(encoded.begin() + static_cast<std::ptrdiff_t>(offset),
                           encoded.begin() + static_cast<std::ptrdiff_t>(offset + length));
        record.fields.push_back(std::move(field));
        offset += length;
        previous = id;
    }
    if (offset != encoded.size()) throw std::runtime_error("relay rekey record trailing bytes");
    return record;
}

RecordBytes BuildRekeyInit(std::uint64_t next_epoch,
                           const RecordBytes& mlkem_public_key,
                           const RecordBytes& x25519_public_key) {
    return Build(RekeyRecordKind::Init, next_epoch, mlkem_public_key,
                 "ML-KEM public key", x25519_public_key);
}

RekeyInit ParseRekeyInit(const RecordBytes& encoded) {
    const RekeyRecord record =
        DecodeRekeyRecord(encoded, RekeyRecordKind::Init, {1, 2, 3});
    RekeyInit out{ParseEpoch(Required(record, 1)), Required(record, 2),
                  Required(record, 3)};
    RequireSize(out.mlkem_public_key, kMlKem1024Bytes, "ML-KEM public key");
    RequireSize(out.x25519_public_key, kX25519PublicKeyBytes, "X25519 public key");
    return out;
}

RecordBytes BuildRekeyAck(std::uint64_t next_epoch,
                          const RecordBytes& mlkem_ciphertext,
                          const RecordBytes& x25519_public_key) {
    return Build(RekeyRecordKind::Ack, next_epoch, mlkem_ciphertext,
                 "ML-KEM ciphertext", x25519_public_key);
}

RekeyAck ParseRekeyAck(const RecordBytes& encoded) {
    const RekeyRecord record =
        DecodeRekeyRecord(encoded, RekeyRecordKind::Ack, {1, 2, 3});
    RekeyAck out{ParseEpoch(Required(record, 1)), Required(record, 2),
                 Required(record, 3)};
    RequireSize(out.mlkem_ciphertext, kMlKem1024Bytes, "ML-KEM ciphertext");
    RequireSize(out.x25519_public_key, kX25519PublicKeyBytes, "X25519 public key");
    return out;
}

}  // namespace yume::relay::ratchet
