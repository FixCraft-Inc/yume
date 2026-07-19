/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/security/auth_v2.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string>

namespace yume::auth_v2 {
namespace {

constexpr std::uint8_t kSchema = 2;
constexpr std::uint8_t kCritical = 0x01;
constexpr std::string_view kSignatureDomain = "yume/2.0/auth-signature/v1";

void AppendU16(Bytes& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value >> 8));
    out.push_back(static_cast<std::uint8_t>(value));
}

void AppendU32(Bytes& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>(value >> 24));
    out.push_back(static_cast<std::uint8_t>(value >> 16));
    out.push_back(static_cast<std::uint8_t>(value >> 8));
    out.push_back(static_cast<std::uint8_t>(value));
}

void AppendU64(Bytes& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

std::uint16_t ReadU16(const Bytes& in, std::size_t* offset) {
    if (!offset || *offset > in.size() || in.size() - *offset < 2) {
        throw std::runtime_error("AUTH v2 truncated u16");
    }
    const auto value = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(in[*offset]) << 8) |
        static_cast<std::uint16_t>(in[*offset + 1]));
    *offset += 2;
    return value;
}

std::uint32_t ReadU32(const Bytes& in, std::size_t* offset) {
    if (!offset || *offset > in.size() || in.size() - *offset < 4) {
        throw std::runtime_error("AUTH v2 truncated u32");
    }
    std::uint32_t value = 0;
    for (int i = 0; i < 4; ++i) value = (value << 8) | in[(*offset)++];
    return value;
}

std::uint64_t ParseU64(const Bytes& value) {
    if (value.size() != 8) throw std::runtime_error("AUTH v2 invalid epoch size");
    std::uint64_t out = 0;
    for (std::uint8_t byte : value) out = (out << 8) | byte;
    return out;
}

const Bytes& Required(const Record& record, std::uint8_t id) {
    const auto it = std::find_if(record.fields.begin(), record.fields.end(),
                                 [id](const Field& field) { return field.id == id; });
    if (it == record.fields.end() || !it->critical) {
        throw std::runtime_error("AUTH v2 missing required field " + std::to_string(id));
    }
    return it->value;
}

void RequireSize(const Bytes& value, std::size_t size, std::string_view name) {
    if (value.size() != size) {
        throw std::runtime_error("AUTH v2 invalid " + std::string(name) + " size");
    }
}

void RequireKemBlob(const Bytes& value, std::string_view name) {
    if (value.size() < 1024 || value.size() > 4096) {
        throw std::runtime_error("AUTH v2 invalid " + std::string(name) + " size");
    }
}

Bytes EpochBytes(std::uint64_t epoch) {
    Bytes value;
    value.reserve(8);
    AppendU64(value, epoch);
    return value;
}

}  // namespace

Bytes EncodeRecord(RecordKind kind, const std::vector<Field>& fields) {
    if (fields.size() > std::numeric_limits<std::uint16_t>::max()) {
        throw std::runtime_error("AUTH v2 has too many fields");
    }
    Bytes out{kSchema, static_cast<std::uint8_t>(kind)};
    AppendU16(out, static_cast<std::uint16_t>(fields.size()));
    std::uint8_t previous = 0;
    for (const auto& field : fields) {
        if (field.id == 0 || field.id <= previous ||
            field.value.size() > std::numeric_limits<std::uint32_t>::max()) {
            throw std::runtime_error("AUTH v2 fields are not canonical");
        }
        if (out.size() > kMaxRecordBytes - 6U ||
            field.value.size() > kMaxRecordBytes - out.size() - 6U) {
            throw std::runtime_error("AUTH v2 record exceeds 64 KiB");
        }
        out.push_back(field.critical ? kCritical : 0);
        out.push_back(field.id);
        AppendU32(out, static_cast<std::uint32_t>(field.value.size()));
        out.insert(out.end(), field.value.begin(), field.value.end());
        previous = field.id;
    }
    return out;
}

Record DecodeRecord(const Bytes& encoded,
                    RecordKind expected_kind,
                    const std::vector<std::uint8_t>& known_fields) {
    if (encoded.size() < 4 || encoded.size() > kMaxRecordBytes) {
        throw std::runtime_error("AUTH v2 record size is invalid");
    }
    if (encoded[0] != kSchema || encoded[1] != static_cast<std::uint8_t>(expected_kind)) {
        throw std::runtime_error("AUTH v2 schema or record kind mismatch");
    }
    std::size_t offset = 2;
    const std::uint16_t field_count = ReadU16(encoded, &offset);
    if (field_count > 64) throw std::runtime_error("AUTH v2 field count exceeds cap");
    Record record{expected_kind, {}};
    record.fields.reserve(field_count);
    std::uint8_t previous = 0;
    for (std::uint16_t i = 0; i < field_count; ++i) {
        if (offset > encoded.size() || encoded.size() - offset < 6) {
            throw std::runtime_error("AUTH v2 truncated field header");
        }
        const std::uint8_t flags = encoded[offset++];
        const std::uint8_t id = encoded[offset++];
        if ((flags & ~kCritical) != 0 || id == 0 || id <= previous) {
            throw std::runtime_error("AUTH v2 field flags/order are invalid");
        }
        const std::uint32_t length = ReadU32(encoded, &offset);
        if (length > encoded.size() - offset) {
            throw std::runtime_error("AUTH v2 truncated field value");
        }
        const bool known = std::find(known_fields.begin(), known_fields.end(), id) !=
                           known_fields.end();
        if (!known && (flags & kCritical) != 0) {
            throw std::runtime_error("AUTH v2 unknown critical field");
        }
        Field field{id, (flags & kCritical) != 0, {}};
        field.value.assign(encoded.begin() + static_cast<std::ptrdiff_t>(offset),
                           encoded.begin() + static_cast<std::ptrdiff_t>(offset + length));
        record.fields.push_back(std::move(field));
        offset += length;
        previous = id;
    }
    if (offset != encoded.size()) throw std::runtime_error("AUTH v2 trailing bytes");
    return record;
}

Bytes BuildChallenge(const Bytes& challenge, const Bytes& mlkem_public_key,
                     const Bytes& x25519_public_key, const Bytes& psk_salt,
                     const Bytes& transcript_salt) {
    RequireSize(challenge, 32, "challenge");
    RequireKemBlob(mlkem_public_key, "ML-KEM public key");
    RequireSize(x25519_public_key, 32, "X25519 public key");
    RequireSize(psk_salt, 32, "PSK salt");
    RequireSize(transcript_salt, 32, "transcript salt");
    return EncodeRecord(RecordKind::Challenge, {
        {1, true, Bytes(kTransportVersion.begin(), kTransportVersion.end())},
        {2, true, challenge}, {3, true, mlkem_public_key},
        {4, true, x25519_public_key}, {5, true, psk_salt},
        {6, true, transcript_salt},
    });
}

Challenge ParseChallenge(const Bytes& encoded) {
    const Record record = DecodeRecord(encoded, RecordKind::Challenge,
                                       {1, 2, 3, 4, 5, 6});
    const Bytes& version = Required(record, 1);
    if (std::string_view(reinterpret_cast<const char*>(version.data()), version.size()) !=
        kTransportVersion) {
        throw std::runtime_error("AUTH v2 exact transport version mismatch");
    }
    Challenge out{encoded, Required(record, 2), Required(record, 3),
                  Required(record, 4), Required(record, 5), Required(record, 6)};
    RequireSize(out.challenge, 32, "challenge");
    RequireKemBlob(out.mlkem_public_key, "ML-KEM public key");
    RequireSize(out.x25519_public_key, 32, "X25519 public key");
    RequireSize(out.psk_salt, 32, "PSK salt");
    RequireSize(out.transcript_salt, 32, "transcript salt");
    return out;
}

Bytes BuildUnsignedResponse(const Bytes& x25519_public_key,
                            const Bytes& mlkem_ciphertext,
                            const Bytes& identity) {
    RequireSize(x25519_public_key, 32, "X25519 public key");
    RequireKemBlob(mlkem_ciphertext, "ML-KEM ciphertext");
    if (identity.empty() || identity.size() > 16U * 1024U) {
        throw std::runtime_error("AUTH v2 identity size is invalid");
    }
    return EncodeRecord(RecordKind::Response, {
        {1, true, x25519_public_key}, {2, true, mlkem_ciphertext},
        {3, true, identity},
    });
}

Bytes BuildResponse(const Bytes& x25519_public_key,
                    const Bytes& mlkem_ciphertext, const Bytes& identity,
                    const Bytes& signature) {
    if (signature.size() != 64) {
        throw std::runtime_error("AUTH v2 Ed25519 signature must be 64 bytes");
    }
    (void)BuildUnsignedResponse(x25519_public_key, mlkem_ciphertext, identity);
    return EncodeRecord(RecordKind::Response, {
        {1, true, x25519_public_key}, {2, true, mlkem_ciphertext},
        {3, true, identity}, {4, true, signature},
    });
}

Response ParseResponse(const Bytes& encoded) {
    const Record record = DecodeRecord(encoded, RecordKind::Response, {1, 2, 3, 4});
    Response out{encoded, Required(record, 1), Required(record, 2),
                 Required(record, 3), Required(record, 4)};
    RequireSize(out.x25519_public_key, 32, "X25519 public key");
    RequireKemBlob(out.mlkem_ciphertext, "ML-KEM ciphertext");
    if (out.identity.empty() || out.identity.size() > 16U * 1024U) {
        throw std::runtime_error("AUTH v2 identity size is invalid");
    }
    RequireSize(out.signature, 64, "Ed25519 signature");
    return out;
}

Bytes BuildSignatureInput(const Bytes& challenge_record,
                          const Bytes& unsigned_response_record) {
    if (challenge_record.size() > std::numeric_limits<std::uint32_t>::max() ||
        unsigned_response_record.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error("AUTH v2 transcript is too large");
    }
    Bytes out(kSignatureDomain.begin(), kSignatureDomain.end());
    AppendU32(out, static_cast<std::uint32_t>(challenge_record.size()));
    out.insert(out.end(), challenge_record.begin(), challenge_record.end());
    AppendU32(out, static_cast<std::uint32_t>(unsigned_response_record.size()));
    out.insert(out.end(), unsigned_response_record.begin(),
               unsigned_response_record.end());
    return out;
}

Bytes BuildAuthOk(const Bytes& server_info) {
    if (server_info.size() > 32U * 1024U) {
        throw std::runtime_error("AUTH v2 server info exceeds cap");
    }
    return EncodeRecord(RecordKind::AuthOk, {
        {1, true, Bytes(kTransportVersion.begin(), kTransportVersion.end())},
        {2, true, server_info},
    });
}

Bytes ParseAuthOk(const Bytes& encoded) {
    const Record record = DecodeRecord(encoded, RecordKind::AuthOk, {1, 2});
    const Bytes& version = Required(record, 1);
    if (std::string_view(reinterpret_cast<const char*>(version.data()), version.size()) !=
        kTransportVersion) {
        throw std::runtime_error("AUTH_OK exact transport version mismatch");
    }
    return Required(record, 2);
}

Bytes BuildRekeyInit(std::uint64_t next_epoch, const Bytes& mlkem_public_key,
                     const Bytes& x25519_public_key) {
    if (next_epoch == 0) throw std::runtime_error("invalid rekey epoch");
    RequireKemBlob(mlkem_public_key, "ML-KEM public key");
    RequireSize(x25519_public_key, 32, "X25519 public key");
    return EncodeRecord(RecordKind::RekeyInit, {
        {1, true, EpochBytes(next_epoch)}, {2, true, mlkem_public_key},
        {3, true, x25519_public_key},
    });
}

RekeyInit ParseRekeyInit(const Bytes& encoded) {
    const Record record = DecodeRecord(encoded, RecordKind::RekeyInit, {1, 2, 3});
    RekeyInit out{ParseU64(Required(record, 1)), Required(record, 2),
                  Required(record, 3)};
    if (out.next_epoch == 0) throw std::runtime_error("invalid rekey epoch");
    RequireKemBlob(out.mlkem_public_key, "ML-KEM public key");
    RequireSize(out.x25519_public_key, 32, "X25519 public key");
    return out;
}

Bytes BuildRekeyAck(std::uint64_t next_epoch, const Bytes& mlkem_ciphertext,
                    const Bytes& x25519_public_key) {
    if (next_epoch == 0) throw std::runtime_error("invalid rekey epoch");
    RequireKemBlob(mlkem_ciphertext, "ML-KEM ciphertext");
    RequireSize(x25519_public_key, 32, "X25519 public key");
    return EncodeRecord(RecordKind::RekeyAck, {
        {1, true, EpochBytes(next_epoch)}, {2, true, mlkem_ciphertext},
        {3, true, x25519_public_key},
    });
}

RekeyAck ParseRekeyAck(const Bytes& encoded) {
    const Record record = DecodeRecord(encoded, RecordKind::RekeyAck, {1, 2, 3});
    RekeyAck out{ParseU64(Required(record, 1)), Required(record, 2),
                 Required(record, 3)};
    if (out.next_epoch == 0) throw std::runtime_error("invalid rekey epoch");
    RequireKemBlob(out.mlkem_ciphertext, "ML-KEM ciphertext");
    RequireSize(out.x25519_public_key, 32, "X25519 public key");
    return out;
}

}  // namespace yume::auth_v2
