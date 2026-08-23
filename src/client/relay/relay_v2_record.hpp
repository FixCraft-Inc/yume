/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <stdexcept>
#include <vector>

#include "core/protocol/protocol.hpp"
#include "core/security/session_ratchet.hpp"

namespace yume::client::relay_v2::record {

using Bytes = std::vector<std::uint8_t>;

// Relay DATA carries exactly one record. The fixed header is:
//
//   magic[4] | schema[1] | reserved[1] | protocol[2] |
//   total_len[4] | payload_len[4] | type[1] | stream[1] | flags[2]
//
// All multi-byte integers are big-endian. A schema change is required before
// adding fields or assigning the reserved byte; same-schema extensions and
// trailing bytes are deliberately rejected.
inline constexpr std::array<std::uint8_t, 4> kMagic{
    0x59, 0x52, 0x52, 0x32};  // "YRR2"
inline constexpr std::uint8_t kSchemaVersion = 1;
inline constexpr std::uint16_t kWireProtocolVersion = 2;
inline constexpr std::size_t kWireHeaderBytes = 20;

// A transfer chunk is 32 KiB before base64. The resulting JSON record is about
// 43 KiB, so a 64-KiB plaintext ceiling leaves bounded room for the message
// name/type fields without shrinking the existing transfer geometry.
inline constexpr std::size_t kTransferChunkBytes = 32U * 1024U;
inline constexpr std::size_t kTransferChunkBase64Bytes =
    ((kTransferChunkBytes + 2U) / 3U) * 4U;
inline constexpr std::size_t kTransferJsonHeadroomBytes = 1024U;
inline constexpr std::size_t kMaxPlaintextPayloadBytes = 64U * 1024U;

// SessionRatchet's sealed payload is epoch[8] | sequence[8] | ciphertext,
// where AES-GCM adds a 16-byte tag. Keep this schema-coupled value explicit:
// changing the ratchet envelope requires reviewing and versioning this record.
inline constexpr std::size_t kRatchetEnvelopeOverheadBytes = 32U;
inline constexpr std::size_t kMinSealedPayloadBytes =
    kRatchetEnvelopeOverheadBytes;
inline constexpr std::size_t kMaxSealedPayloadBytes =
    kMaxPlaintextPayloadBytes + kRatchetEnvelopeOverheadBytes;
inline constexpr std::size_t kMaxEncodedRecordBytes =
    kWireHeaderBytes + kMaxSealedPayloadBytes;

static_assert(kTransferChunkBase64Bytes + kTransferJsonHeadroomBytes <=
              kMaxPlaintextPayloadBytes);
static_assert(kMaxEncodedRecordBytes <=
              static_cast<std::size_t>(
                  std::numeric_limits<std::uint32_t>::max()));

class Error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

bool IsAllowedFrameType(std::uint8_t type) noexcept;

// Encodes or decodes one already-ratchet-sealed frame. Only DATA, REKEY_INIT,
// and REKEY_ACK on logical stream zero are valid, and the only permitted wire
// flag is kFlagInnerEncrypted. `FrameHeader::len` must exactly equal the sealed
// payload size on encode; decode produces that canonical value.
Bytes EncodeSealedFrame(const protocol::Frame& sealed);
protocol::Frame DecodeSealedFrame(std::span<const std::uint8_t> encoded);

// Convenience for ordinary application DATA. This does not initiate a rekey
// or bypass ApplicationWriteBlocked(): the caller remains responsible for one
// ordered send queue containing INIT, application DATA, and ACK frames. Once a
// Seal*/OpenRecord call reaches SessionRatchet it may advance one directional
// chain; any exception from that point is channel-fatal and must not be retried
// on the same ratchet instance.
Bytes SealApplication(
    ratchet::SessionRatchet& ratchet,
    Bytes plaintext,
    std::chrono::steady_clock::time_point now);

// Consumes the plaintext REKEY_ACK returned by OpenRecord. It intentionally
// accepts no other control type, and seals only when the caller reaches the ACK
// in that same ordered send queue.
Bytes SealControlResponse(
    ratchet::SessionRatchet& ratchet,
    protocol::Frame response,
    std::chrono::steady_clock::time_point now);

// Decodes one record and opens it through SessionRatchet. A REKEY_INIT result
// retains its plaintext control_response for the caller to queue and seal
// later; this read-side helper never assigns an outbound sequence number.
ratchet::OpenResult OpenRecord(
    ratchet::SessionRatchet& ratchet,
    std::span<const std::uint8_t> encoded,
    std::chrono::steady_clock::time_point now);

}  // namespace yume::client::relay_v2::record
