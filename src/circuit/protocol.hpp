/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "ytp/protocol.hpp"

// Circuit 1 codec: cells, handshake encodings and relay messages, with the
// bounds docs/protocol/CIRCUIT_1.md sets. It performs no cryptography and
// allocates only for encoders that return owned bytes. Every decoder consumes
// its whole input and reports the first violation with its offset.
namespace yume::circuit1 {

enum class ErrorCode : std::uint8_t {
    Ok = 0,
    Truncated,
    TrailingData,
    UnsupportedVersion,
    InvalidCommand,
    InvalidBucket,
    InvalidLength,
    NonzeroFiller,
    NonzeroReserved,
    InvalidDepth,
    InvalidType,
    WrongDirection,
    InvalidStream,
    InvalidReason,
    InvalidDestination,
    InvalidCredit,
    OutputTooSmall,
};

struct Status {
    ErrorCode code{ErrorCode::Ok};
    std::size_t offset{0};

    [[nodiscard]] constexpr bool ok() const noexcept {
        return code == ErrorCode::Ok;
    }
    [[nodiscard]] static constexpr Status Success() noexcept { return {}; }
};

template <typename T>
struct Result {
    Status status{};
    std::optional<T> value{};

    [[nodiscard]] bool ok() const noexcept {
        return status.ok() && value.has_value();
    }
};

enum class Direction : std::uint8_t {
    Forward = 1,
    Backward = 2,
};

inline constexpr std::uint8_t kCellVersion = 1;
inline constexpr std::size_t kCellHeaderBytes = 4;
// The buckets of each direction, smallest first. A full largest cell, its
// YTP/1 PACKET record, the carrier envelope, one WebSocket frame header and
// one HTTP/2 DATA frame header fill exactly one 16384-byte TLS record.
// Forward cells travel on the dialing side of every session and link, whose
// WebSocket frames carry a 4-byte mask, so the forward bucket is 4 bytes
// smaller.
inline constexpr std::array<std::size_t, 3> kForwardBuckets{512, 4096, 16311};
inline constexpr std::array<std::size_t, 3> kBackwardBuckets{512, 4096, 16315};
inline constexpr std::size_t kMaxCellBytes = kBackwardBuckets[2];
inline constexpr std::size_t kMaxHops = 3;
inline constexpr std::size_t kLayerTagBytes = 16;
inline constexpr std::size_t kRelayHeaderBytes = 8;
inline constexpr std::size_t kFingerprintBytes = 32;
inline constexpr std::size_t kNonceBytes = 32;
inline constexpr std::size_t kX25519Bytes = 32;
inline constexpr std::size_t kMlKemPublicBytes = 1568;
inline constexpr std::size_t kMlKemCiphertextBytes = 1568;
inline constexpr std::size_t kConfirmationBytes = 32;
inline constexpr std::size_t kSignatureBytes = 4691;
inline constexpr std::uint8_t kHandshakeSchema = 1;
inline constexpr std::size_t kClientHandshakeBytes =
    4 + kNonceBytes + kX25519Bytes + kMlKemPublicBytes;
inline constexpr std::size_t kHopHandshakeBytes =
    4 + kX25519Bytes + kMlKemCiphertextBytes + kConfirmationBytes +
    kSignatureBytes;
inline constexpr std::size_t kCreateBodyBytes = 2 + kClientHandshakeBytes;
inline constexpr std::size_t kCreateBucket = 4096;
inline constexpr std::size_t kCreatedBucket = kBackwardBuckets[2];
inline constexpr std::size_t kExtendPayloadBytes =
    kFingerprintBytes + kClientHandshakeBytes;
inline constexpr std::uint32_t kMaxCreditIncrement = 1U << 30;

static_assert(kClientHandshakeBytes == 1636);
static_assert(kHopHandshakeBytes == 6327);

enum class Command : std::uint8_t {
    Create = 1,
    Created = 2,
    Relay = 3,
};

enum class RelayType : std::uint8_t {
    Begin = 1,
    Data = 2,
    End = 3,
    StreamCredit = 4,
    Extend = 5,
    Connected = 6,
    Extended = 7,
    ExtendFailed = 8,
    CircuitFailed = 9,
};

enum class CircuitReason : std::uint8_t {
    Unreachable = 1,
    Busy = 2,
    Timeout = 3,
    Protocol = 4,
    Refused = 5,
    Closing = 6,
};

enum class StreamReason : std::uint8_t {
    Done = 0,
    Policy = 1,
    ConnectionRefused = 2,
    Unreachable = 3,
    NameNotFound = 4,
    Timeout = 5,
    Resources = 6,
    Protocol = 7,
    Closed = 8,
};

[[nodiscard]] constexpr bool IsBucket(Direction direction,
                                      std::size_t size) noexcept {
    if (direction != Direction::Forward && direction != Direction::Backward) {
        return false;
    }
    const auto& buckets =
        direction == Direction::Forward ? kForwardBuckets : kBackwardBuckets;
    return size == buckets[0] || size == buckets[1] || size == buckets[2];
}

// The padded size of a relay message in a bucket: the bucket less the cell
// header and three layer tags. Zero for a size that is not a bucket of the
// direction.
[[nodiscard]] constexpr std::size_t RelayCapacity(Direction direction,
                                                  std::size_t bucket) noexcept {
    return IsBucket(direction, bucket)
               ? bucket - kCellHeaderBytes - kMaxHops * kLayerTagBytes
               : 0U;
}

// The largest DATA payload one relay message of the direction carries.
[[nodiscard]] constexpr std::size_t MaxDataPayload(
    Direction direction) noexcept {
    const auto& buckets =
        direction == Direction::Forward ? kForwardBuckets : kBackwardBuckets;
    return RelayCapacity(direction, buckets[2]) - kRelayHeaderBytes;
}

static_assert(kCreateBodyBytes <= kCreateBucket - kCellHeaderBytes);
static_assert(kHopHandshakeBytes <= kCreatedBucket - kCellHeaderBytes);
static_assert(kRelayHeaderBytes + kExtendPayloadBytes <=
              RelayCapacity(Direction::Forward, kCreateBucket));
static_assert(kRelayHeaderBytes + kHopHandshakeBytes <=
              RelayCapacity(Direction::Backward, kCreatedBucket));

// The smallest bucket of the direction whose relay capacity holds a relay
// payload of this size, or nothing when none does.
[[nodiscard]] std::optional<std::size_t> BucketForPayload(
    Direction direction, std::size_t payload_bytes) noexcept;

// A decoded cell. body borrows from the decoded input. layers is the RELAY
// layer count, 1 to 3, and zero for CREATE and CREATED.
struct CellView {
    Command command{Command::Relay};
    std::size_t bucket{0};
    std::span<const std::uint8_t> body;
    std::size_t layers{0};
};

// Checks the bucket size for the direction, the version, the command and its
// direction (CREATE forward, CREATED backward), the body length for the
// command and zero filler.
[[nodiscard]] Result<CellView> DecodeCell(
    Direction direction, std::span<const std::uint8_t> cell) noexcept;
// Writes one cell of the given bucket into output, which must hold exactly
// the bucket. The body must be valid for the command as DecodeCell checks it.
[[nodiscard]] Status EncodeCell(Direction direction, Command command,
                                std::size_t bucket,
                                std::span<const std::uint8_t> body,
                                std::span<std::uint8_t> output) noexcept;
[[nodiscard]] Result<std::vector<std::uint8_t>> EncodeCell(
    Direction direction, Command command, std::size_t bucket,
    std::span<const std::uint8_t> body);

struct ClientHandshake {
    std::array<std::uint8_t, kNonceBytes> nonce{};
    std::array<std::uint8_t, kX25519Bytes> x25519_public{};
    std::array<std::uint8_t, kMlKemPublicBytes> mlkem_public{};

    friend bool operator==(const ClientHandshake&,
                           const ClientHandshake&) = default;
};

struct HopHandshake {
    std::array<std::uint8_t, kX25519Bytes> x25519_public{};
    std::array<std::uint8_t, kMlKemCiphertextBytes> mlkem_ciphertext{};
    std::array<std::uint8_t, kConfirmationBytes> confirmation{};
    std::array<std::uint8_t, kSignatureBytes> signature{};

    friend bool operator==(const HopHandshake&, const HopHandshake&) = default;
};

[[nodiscard]] std::array<std::uint8_t, kClientHandshakeBytes>
EncodeClientHandshake(const ClientHandshake& handshake) noexcept;
[[nodiscard]] Result<ClientHandshake> DecodeClientHandshake(
    std::span<const std::uint8_t> bytes) noexcept;
[[nodiscard]] std::vector<std::uint8_t> EncodeHopHandshake(
    const HopHandshake& handshake);
[[nodiscard]] Result<HopHandshake> DecodeHopHandshake(
    std::span<const std::uint8_t> bytes) noexcept;

// The CREATE body: the receiving hop's depth, one reserved byte and the
// client handshake bytes, which it borrows.
struct CreateView {
    std::uint8_t depth{0};
    std::span<const std::uint8_t> client_handshake;
};

// Refuses a depth outside 1 to 3 and a handshake whose schema or reserved
// bytes are wrong.
[[nodiscard]] Result<std::array<std::uint8_t, kCreateBodyBytes>> EncodeCreate(
    std::uint8_t depth, std::span<const std::uint8_t, kClientHandshakeBytes>
                            client_handshake) noexcept;
[[nodiscard]] Result<CreateView> DecodeCreate(
    std::span<const std::uint8_t> body) noexcept;

// A decoded relay message. payload borrows from the decoded plaintext.
struct RelayMessageView {
    RelayType type{RelayType::Data};
    std::uint32_t stream{0};
    std::span<const std::uint8_t> payload;
};

// Decodes the plaintext under the last layer, which is exactly the relay
// capacity of the cell's bucket, and checks the type against the direction,
// the stream rule, the payload's size and reason or credit value, and zero
// padding. It does not allocate, so a BEGIN destination is checked only for
// its size range: the exit decodes it with DecodeBeginPayload.
[[nodiscard]] Result<RelayMessageView> DecodeRelayMessage(
    Direction direction, std::span<const std::uint8_t> plaintext) noexcept;
// Writes a relay message padded to output's size, which must be a relay
// capacity. The message must be valid as DecodeRelayMessage checks it.
[[nodiscard]] Status EncodeRelayMessage(
    Direction direction, RelayType type, std::uint32_t stream,
    std::span<const std::uint8_t> payload,
    std::span<std::uint8_t> output) noexcept;

// BEGIN's payload: an address kind, then a YTP/1 OPEN destination, TCP.
[[nodiscard]] Result<std::vector<std::uint8_t>> EncodeBeginPayload(
    const ytp1::Destination& destination);
[[nodiscard]] Result<ytp1::Destination> DecodeBeginPayload(
    std::span<const std::uint8_t> payload);

struct ExtendView {
    std::span<const std::uint8_t, kFingerprintBytes> next_identity;
    std::span<const std::uint8_t> client_handshake;
};

[[nodiscard]] std::array<std::uint8_t, kExtendPayloadBytes> EncodeExtendPayload(
    std::span<const std::uint8_t, kFingerprintBytes> next_identity,
    std::span<const std::uint8_t, kClientHandshakeBytes>
        client_handshake) noexcept;
// The payload of an already decoded EXTEND message, whose size the relay
// decoder has checked.
[[nodiscard]] Result<ExtendView> DecodeExtendPayload(
    std::span<const std::uint8_t> payload) noexcept;

[[nodiscard]] std::string_view ErrorName(ErrorCode code) noexcept;

}  // namespace yume::circuit1
