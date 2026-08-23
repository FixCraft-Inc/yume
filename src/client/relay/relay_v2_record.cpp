/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/relay/relay_v2_record.hpp"

#include <algorithm>
#include <limits>
#include <string>
#include <utility>

#include "client/relay/relay_v2_crypto.hpp"
#include "core/security/secure_erase.hpp"

namespace yume::client::relay_v2::record {
namespace {

inline constexpr std::size_t kMagicOffset = 0;
inline constexpr std::size_t kSchemaOffset = 4;
inline constexpr std::size_t kReservedOffset = 5;
inline constexpr std::size_t kProtocolOffset = 6;
inline constexpr std::size_t kTotalLengthOffset = 8;
inline constexpr std::size_t kPayloadLengthOffset = 12;
inline constexpr std::size_t kTypeOffset = 16;
inline constexpr std::size_t kStreamOffset = 17;
inline constexpr std::size_t kFlagsOffset = 18;

static_assert(kWireHeaderBytes == 20);
static_assert(kWireProtocolVersion ==
              ::yume::client::relay_v2::kProtocolVersion);

void WriteU16(Bytes& out, std::size_t offset, std::uint16_t value) {
    if (offset > out.size() || out.size() - offset < 2U) {
        throw Error("relay-v2 record header output is too small");
    }
    out[offset] = static_cast<std::uint8_t>(value >> 8U);
    out[offset + 1U] = static_cast<std::uint8_t>(value);
}

void WriteU32(Bytes& out, std::size_t offset, std::uint32_t value) {
    if (offset > out.size() || out.size() - offset < 4U) {
        throw Error("relay-v2 record header output is too small");
    }
    out[offset] = static_cast<std::uint8_t>(value >> 24U);
    out[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
    out[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
    out[offset + 3U] = static_cast<std::uint8_t>(value);
}

std::uint16_t ReadU16(std::span<const std::uint8_t> input,
                      std::size_t offset) {
    if (offset > input.size() || input.size() - offset < 2U) {
        throw Error("relay-v2 record header is truncated");
    }
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(input[offset]) << 8U) |
        static_cast<std::uint16_t>(input[offset + 1U]));
}

std::uint32_t ReadU32(std::span<const std::uint8_t> input,
                      std::size_t offset) {
    if (offset > input.size() || input.size() - offset < 4U) {
        throw Error("relay-v2 record header is truncated");
    }
    return (static_cast<std::uint32_t>(input[offset]) << 24U) |
           (static_cast<std::uint32_t>(input[offset + 1U]) << 16U) |
           (static_cast<std::uint32_t>(input[offset + 2U]) << 8U) |
           static_cast<std::uint32_t>(input[offset + 3U]);
}

void ValidateTypeStreamAndFlags(const protocol::Frame& frame,
                                std::uint16_t expected_flags) {
    if (!IsAllowedFrameType(frame.header.type)) {
        throw Error("relay-v2 record contains a forbidden inner frame type");
    }
    if (frame.header.stream_id != 0) {
        throw Error("relay-v2 record inner stream id must be zero");
    }
    if (frame.header.flags != expected_flags) {
        throw Error("relay-v2 record inner flags are not canonical");
    }
}

void ValidateSealedFrame(const protocol::Frame& sealed) {
    ValidateTypeStreamAndFlags(sealed, protocol::kFlagInnerEncrypted);
    if (sealed.payload.size() < kMinSealedPayloadBytes) {
        throw Error("relay-v2 record ratchet envelope is truncated");
    }
    if (sealed.payload.size() > kMaxSealedPayloadBytes) {
        throw Error("relay-v2 record ratchet envelope exceeds the size cap");
    }
    if (sealed.header.len != sealed.payload.size()) {
        throw Error("relay-v2 record frame length is not exact");
    }
}

void ValidateOpenedApplication(const protocol::Frame& frame) {
    if (frame.header.type != protocol::DATA || frame.header.stream_id != 0 ||
        frame.header.flags != 0) {
        throw Error("relay-v2 ratchet returned a non-canonical application frame");
    }
    if (frame.payload.size() > kMaxPlaintextPayloadBytes ||
        frame.header.len != frame.payload.size()) {
        throw Error("relay-v2 ratchet returned an invalid application length");
    }
}

void ValidateControlResponse(protocol::Frame& frame) {
    if (frame.header.type != protocol::REKEY_ACK ||
        frame.header.stream_id != 0 || frame.header.flags != 0) {
        throw Error("relay-v2 ratchet returned an invalid control response");
    }
    if (frame.payload.size() > kMaxPlaintextPayloadBytes ||
        frame.payload.size() >
            static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        throw Error("relay-v2 ratchet control response exceeds the size cap");
    }
    // SessionRatchet deliberately returns a plaintext ACK before the write
    // path assigns its protected length. Canonicalize it for the caller.
    frame.header.len = static_cast<std::uint32_t>(frame.payload.size());
}

}  // namespace

bool IsAllowedFrameType(std::uint8_t type) noexcept {
    return type == protocol::DATA || type == protocol::REKEY_INIT ||
           type == protocol::REKEY_ACK;
}

Bytes EncodeSealedFrame(const protocol::Frame& sealed) {
    ValidateSealedFrame(sealed);
    const std::size_t total_size = kWireHeaderBytes + sealed.payload.size();
    if (total_size > kMaxEncodedRecordBytes ||
        total_size >
            static_cast<std::size_t>(std::numeric_limits<std::uint32_t>::max())) {
        throw Error("relay-v2 encoded record exceeds the size cap");
    }

    Bytes encoded(total_size, 0);
    std::copy(kMagic.begin(), kMagic.end(),
              encoded.begin() + static_cast<std::ptrdiff_t>(kMagicOffset));
    encoded[kSchemaOffset] = kSchemaVersion;
    encoded[kReservedOffset] = 0;
    WriteU16(encoded, kProtocolOffset, kWireProtocolVersion);
    WriteU32(encoded, kTotalLengthOffset,
             static_cast<std::uint32_t>(total_size));
    WriteU32(encoded, kPayloadLengthOffset,
             static_cast<std::uint32_t>(sealed.payload.size()));
    encoded[kTypeOffset] = sealed.header.type;
    encoded[kStreamOffset] = sealed.header.stream_id;
    WriteU16(encoded, kFlagsOffset, sealed.header.flags);
    std::copy(sealed.payload.begin(), sealed.payload.end(),
              encoded.begin() +
                  static_cast<std::ptrdiff_t>(kWireHeaderBytes));
    return encoded;
}

protocol::Frame DecodeSealedFrame(std::span<const std::uint8_t> encoded) {
    if (encoded.size() > kMaxEncodedRecordBytes) {
        throw Error("relay-v2 encoded record exceeds the size cap");
    }
    if (encoded.size() < kWireHeaderBytes) {
        throw Error("relay-v2 record header is truncated");
    }
    if (!std::equal(kMagic.begin(), kMagic.end(),
                    encoded.begin() +
                        static_cast<std::ptrdiff_t>(kMagicOffset))) {
        throw Error("relay-v2 record magic mismatch");
    }
    if (encoded[kSchemaOffset] != kSchemaVersion) {
        throw Error("relay-v2 record schema version mismatch");
    }
    if (encoded[kReservedOffset] != 0) {
        throw Error("relay-v2 record reserved byte is non-zero");
    }
    if (ReadU16(encoded, kProtocolOffset) != kWireProtocolVersion) {
        throw Error("relay-v2 record protocol version mismatch");
    }

    const std::uint32_t declared_total =
        ReadU32(encoded, kTotalLengthOffset);
    const std::uint32_t declared_payload =
        ReadU32(encoded, kPayloadLengthOffset);
    if (declared_total != encoded.size()) {
        throw Error("relay-v2 record total length is not exact");
    }
    if (declared_total < kWireHeaderBytes ||
        declared_payload != declared_total - kWireHeaderBytes) {
        throw Error("relay-v2 record payload length is not exact");
    }
    if (declared_payload < kMinSealedPayloadBytes) {
        throw Error("relay-v2 record ratchet envelope is truncated");
    }
    if (declared_payload > kMaxSealedPayloadBytes) {
        throw Error("relay-v2 record ratchet envelope exceeds the size cap");
    }

    protocol::Frame sealed{
        {declared_payload, encoded[kTypeOffset], encoded[kStreamOffset],
         ReadU16(encoded, kFlagsOffset)},
        Bytes(encoded.begin() +
                  static_cast<std::ptrdiff_t>(kWireHeaderBytes),
              encoded.end())};
    ValidateSealedFrame(sealed);
    return sealed;
}

Bytes SealApplication(ratchet::SessionRatchet& ratchet,
                      Bytes plaintext,
                      std::chrono::steady_clock::time_point now) {
    if (plaintext.size() > kMaxPlaintextPayloadBytes) {
        throw Error("relay-v2 application payload exceeds the size cap");
    }
    protocol::Frame frame{
        {static_cast<std::uint32_t>(plaintext.size()), protocol::DATA, 0, 0},
        std::move(plaintext)};
    struct PlaintextWiper {
        protocol::Frame& frame;
        ~PlaintextWiper() { security::secure_erase(frame.payload); }
    } plaintext_wiper{frame};
    return EncodeSealedFrame(ratchet.Seal(frame, now));
}

Bytes SealControlResponse(ratchet::SessionRatchet& ratchet,
                          protocol::Frame response,
                          std::chrono::steady_clock::time_point now) {
    ValidateControlResponse(response);
    struct PlaintextWiper {
        protocol::Frame& frame;
        ~PlaintextWiper() { security::secure_erase(frame.payload); }
    } plaintext_wiper{response};
    return EncodeSealedFrame(ratchet.Seal(response, now));
}

ratchet::OpenResult OpenRecord(
    ratchet::SessionRatchet& ratchet,
    std::span<const std::uint8_t> encoded,
    std::chrono::steady_clock::time_point now) {
    const protocol::Frame sealed = DecodeSealedFrame(encoded);
    ratchet::OpenResult result = ratchet.Open(sealed, now);

    if (sealed.header.type == protocol::DATA) {
        if (!result.application_frame || result.control_response ||
            result.outbound_rekey_completed) {
            throw Error("relay-v2 ratchet returned an invalid DATA result");
        }
        ValidateOpenedApplication(*result.application_frame);
    } else if (sealed.header.type == protocol::REKEY_INIT) {
        if (result.application_frame || !result.control_response ||
            result.outbound_rekey_completed) {
            throw Error("relay-v2 ratchet returned an invalid REKEY_INIT result");
        }
        ValidateControlResponse(*result.control_response);
    } else {
        if (result.application_frame || result.control_response ||
            !result.outbound_rekey_completed) {
            throw Error("relay-v2 ratchet returned an invalid REKEY_ACK result");
        }
    }
    return result;
}

}  // namespace yume::client::relay_v2::record
