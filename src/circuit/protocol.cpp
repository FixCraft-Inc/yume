/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "circuit/protocol.hpp"

#include <algorithm>
#include <utility>

namespace yume::circuit1 {
namespace {

std::uint16_t read_u16(std::span<const std::uint8_t> input,
                       std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(
        (static_cast<unsigned>(input[offset]) << 8U) | input[offset + 1U]);
}

std::uint32_t read_u32(std::span<const std::uint8_t> input,
                       std::size_t offset) noexcept {
    return (static_cast<std::uint32_t>(input[offset]) << 24U) |
           (static_cast<std::uint32_t>(input[offset + 1U]) << 16U) |
           (static_cast<std::uint32_t>(input[offset + 2U]) << 8U) |
           static_cast<std::uint32_t>(input[offset + 3U]);
}

void write_u16(std::span<std::uint8_t> output, std::size_t offset,
               std::uint16_t value) noexcept {
    output[offset] = static_cast<std::uint8_t>(value >> 8U);
    output[offset + 1U] = static_cast<std::uint8_t>(value);
}

void write_u32(std::span<std::uint8_t> output, std::size_t offset,
               std::uint32_t value) noexcept {
    output[offset] = static_cast<std::uint8_t>(value >> 24U);
    output[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
    output[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
    output[offset + 3U] = static_cast<std::uint8_t>(value);
}

// The offset of the first nonzero byte at or after start, or nothing.
std::optional<std::size_t> first_nonzero(std::span<const std::uint8_t> bytes,
                                         std::size_t start) noexcept {
    const auto found =
        std::find_if(bytes.begin() + static_cast<std::ptrdiff_t>(start),
                     bytes.end(), [](std::uint8_t byte) { return byte != 0U; });
    if (found == bytes.end()) return std::nullopt;
    return static_cast<std::size_t>(found - bytes.begin());
}

template <typename T>
Result<T> failure(ErrorCode code, std::size_t offset) noexcept {
    return {{code, offset}, std::nullopt};
}

template <typename T>
Result<T> success(T value) {
    return {Status::Success(), std::optional<T>(std::move(value))};
}

// Exact-size input check shared by the fixed-size decoders.
Status exact_size(std::span<const std::uint8_t> input,
                  std::size_t expected) noexcept {
    if (input.size() < expected) return {ErrorCode::Truncated, input.size()};
    if (input.size() > expected) return {ErrorCode::TrailingData, expected};
    return Status::Success();
}

// Schema and reserved bytes at the front of both handshakes, found at base.
Status handshake_prefix(std::span<const std::uint8_t> input,
                        std::size_t base) noexcept {
    if (input[base] != kHandshakeSchema) {
        return {ErrorCode::UnsupportedVersion, base};
    }
    for (std::size_t index = 1U; index < 4U; ++index) {
        if (input[base + index] != 0U) {
            return {ErrorCode::NonzeroReserved, base + index};
        }
    }
    return Status::Success();
}

bool is_known_command(std::uint8_t value) noexcept {
    return value >= static_cast<std::uint8_t>(Command::Create) &&
           value <= static_cast<std::uint8_t>(Command::Relay);
}

bool is_known_relay_type(std::uint8_t value) noexcept {
    return value >= static_cast<std::uint8_t>(RelayType::Begin) &&
           value <= static_cast<std::uint8_t>(RelayType::CircuitFailed);
}

bool is_known_circuit_reason(std::uint8_t value) noexcept {
    return value >= static_cast<std::uint8_t>(CircuitReason::Unreachable) &&
           value <= static_cast<std::uint8_t>(CircuitReason::Closing);
}

bool is_known_stream_reason(std::uint8_t value) noexcept {
    return value <= static_cast<std::uint8_t>(StreamReason::Closed);
}

bool allowed_in(RelayType type, Direction direction) noexcept {
    switch (type) {
        case RelayType::Begin:
        case RelayType::Extend:
            return direction == Direction::Forward;
        case RelayType::Connected:
        case RelayType::Extended:
        case RelayType::ExtendFailed:
        case RelayType::CircuitFailed:
            return direction == Direction::Backward;
        case RelayType::Data:
        case RelayType::End:
        case RelayType::StreamCredit:
            return direction == Direction::Forward ||
                   direction == Direction::Backward;
    }
    return false;
}

// Stream messages name a nonzero stream, circuit messages stream zero.
bool is_stream_message(RelayType type) noexcept {
    switch (type) {
        case RelayType::Begin:
        case RelayType::Data:
        case RelayType::End:
        case RelayType::StreamCredit:
        case RelayType::Connected:
            return true;
        case RelayType::Extend:
        case RelayType::Extended:
        case RelayType::ExtendFailed:
        case RelayType::CircuitFailed:
            break;
    }
    return false;
}

const std::array<std::size_t, 3>& buckets_of(Direction direction) noexcept {
    return direction == Direction::Forward ? kForwardBuckets : kBackwardBuckets;
}

bool is_relay_capacity(Direction direction, std::size_t size) noexcept {
    const auto& buckets = buckets_of(direction);
    return std::any_of(buckets.begin(), buckets.end(),
                       [direction, size](std::size_t bucket) {
                           return RelayCapacity(direction, bucket) == size;
                       });
}

// The smallest and largest BEGIN payloads: an IPv4 destination, and a DNS
// name of the longest canonical length.
constexpr std::size_t kMinBeginPayload = 1U + 2U + 4U;
constexpr std::size_t kMaxBeginPayload = 1U + 2U + 1U + ytp1::kMaxDnsNameBytes;

// The payload rules of each type, checked after the header. Offsets are those
// of the whole message. BEGIN's destination itself is DecodeBeginPayload's.
Status check_payload(RelayType type,
                     std::span<const std::uint8_t> payload) noexcept {
    constexpr std::size_t kLengthOffset = 2U;
    constexpr std::size_t kPayloadOffset = kRelayHeaderBytes;
    const auto size_is = [&](std::size_t expected) {
        return payload.size() == expected
                   ? Status::Success()
                   : Status{ErrorCode::InvalidLength, kLengthOffset};
    };
    switch (type) {
        case RelayType::Begin:
            if (payload.size() < kMinBeginPayload ||
                payload.size() > kMaxBeginPayload) {
                return {ErrorCode::InvalidLength, kLengthOffset};
            }
            return Status::Success();
        case RelayType::Data:
            return payload.empty()
                       ? Status{ErrorCode::InvalidLength, kLengthOffset}
                       : Status::Success();
        case RelayType::End: {
            const auto status = size_is(1U);
            if (!status.ok()) return status;
            return is_known_stream_reason(payload[0])
                       ? Status::Success()
                       : Status{ErrorCode::InvalidReason, kPayloadOffset};
        }
        case RelayType::StreamCredit: {
            const auto status = size_is(4U);
            if (!status.ok()) return status;
            const auto increment = read_u32(payload, 0U);
            return increment >= 1U && increment <= kMaxCreditIncrement
                       ? Status::Success()
                       : Status{ErrorCode::InvalidCredit, kPayloadOffset};
        }
        case RelayType::Extend:
            return size_is(kExtendPayloadBytes);
        case RelayType::Connected:
            return size_is(0U);
        case RelayType::Extended:
            return size_is(kHopHandshakeBytes);
        case RelayType::ExtendFailed:
        case RelayType::CircuitFailed: {
            const auto status = size_is(1U);
            if (!status.ok()) return status;
            return is_known_circuit_reason(payload[0])
                       ? Status::Success()
                       : Status{ErrorCode::InvalidReason, kPayloadOffset};
        }
    }
    return {ErrorCode::InvalidType, 0U};
}

// The body rule of each command in a bucket, shared by decode and encode.
// CREATE only goes forward and CREATED only backward.
Status check_body(Direction direction, Command command, std::size_t bucket,
                  std::size_t body_bytes) noexcept {
    constexpr std::size_t kLengthOffset = 2U;
    switch (command) {
        case Command::Create:
            if (direction != Direction::Forward) {
                return {ErrorCode::WrongDirection, 1U};
            }
            if (bucket != kCreateBucket) return {ErrorCode::InvalidBucket, 0U};
            return body_bytes == kCreateBodyBytes
                       ? Status::Success()
                       : Status{ErrorCode::InvalidLength, kLengthOffset};
        case Command::Created:
            if (direction != Direction::Backward) {
                return {ErrorCode::WrongDirection, 1U};
            }
            if (bucket != kCreatedBucket) return {ErrorCode::InvalidBucket, 0U};
            return body_bytes == kHopHandshakeBytes
                       ? Status::Success()
                       : Status{ErrorCode::InvalidLength, kLengthOffset};
        case Command::Relay: {
            const auto capacity = RelayCapacity(direction, bucket);
            if (body_bytes <= capacity ||
                (body_bytes - capacity) % kLayerTagBytes != 0U ||
                (body_bytes - capacity) / kLayerTagBytes > kMaxHops) {
                return {ErrorCode::InvalidLength, kLengthOffset};
            }
            return Status::Success();
        }
    }
    return {ErrorCode::InvalidCommand, 1U};
}

}  // namespace

std::optional<std::size_t> BucketForPayload(
    Direction direction, std::size_t payload_bytes) noexcept {
    if (direction != Direction::Forward && direction != Direction::Backward) {
        return std::nullopt;
    }
    for (const auto bucket : buckets_of(direction)) {
        if (payload_bytes <=
            RelayCapacity(direction, bucket) - kRelayHeaderBytes) {
            return bucket;
        }
    }
    return std::nullopt;
}

Result<CellView> DecodeCell(Direction direction,
                            std::span<const std::uint8_t> cell) noexcept {
    if (!IsBucket(direction, cell.size())) {
        return failure<CellView>(ErrorCode::InvalidBucket, 0U);
    }
    if (cell[0] != kCellVersion) {
        return failure<CellView>(ErrorCode::UnsupportedVersion, 0U);
    }
    if (!is_known_command(cell[1])) {
        return failure<CellView>(ErrorCode::InvalidCommand, 1U);
    }
    const auto command = static_cast<Command>(cell[1]);
    const std::size_t body_bytes = read_u16(cell, 2U);
    if (body_bytes > cell.size() - kCellHeaderBytes) {
        return failure<CellView>(ErrorCode::InvalidLength, 2U);
    }
    const auto rule = check_body(direction, command, cell.size(), body_bytes);
    if (!rule.ok()) return {rule, std::nullopt};
    if (const auto nonzero =
            first_nonzero(cell, kCellHeaderBytes + body_bytes)) {
        return failure<CellView>(ErrorCode::NonzeroFiller, *nonzero);
    }
    CellView view;
    view.command = command;
    view.bucket = cell.size();
    view.body = cell.subspan(kCellHeaderBytes, body_bytes);
    view.layers = command == Command::Relay
                      ? (body_bytes - RelayCapacity(direction, cell.size())) /
                            kLayerTagBytes
                      : 0U;
    return success(view);
}

Status EncodeCell(Direction direction, Command command, std::size_t bucket,
                  std::span<const std::uint8_t> body,
                  std::span<std::uint8_t> output) noexcept {
    if (!IsBucket(direction, bucket)) return {ErrorCode::InvalidBucket, 0U};
    if (output.size() != bucket) return {ErrorCode::OutputTooSmall, 0U};
    if (!is_known_command(static_cast<std::uint8_t>(command))) {
        return {ErrorCode::InvalidCommand, 1U};
    }
    if (body.size() > bucket - kCellHeaderBytes) {
        return {ErrorCode::InvalidLength, 2U};
    }
    const auto rule = check_body(direction, command, bucket, body.size());
    if (!rule.ok()) return rule;
    output[0] = kCellVersion;
    output[1] = static_cast<std::uint8_t>(command);
    write_u16(output, 2U, static_cast<std::uint16_t>(body.size()));
    std::copy(body.begin(), body.end(), output.begin() + kCellHeaderBytes);
    std::fill(output.begin() +
                  static_cast<std::ptrdiff_t>(kCellHeaderBytes + body.size()),
              output.end(), std::uint8_t{0});
    return Status::Success();
}

Result<std::vector<std::uint8_t>> EncodeCell(
    Direction direction, Command command, std::size_t bucket,
    std::span<const std::uint8_t> body) {
    if (!IsBucket(direction, bucket)) {
        return failure<std::vector<std::uint8_t>>(ErrorCode::InvalidBucket, 0U);
    }
    std::vector<std::uint8_t> output(bucket);
    const auto status = EncodeCell(direction, command, bucket, body, output);
    if (!status.ok()) return {status, std::nullopt};
    return success(std::move(output));
}

std::array<std::uint8_t, kClientHandshakeBytes> EncodeClientHandshake(
    const ClientHandshake& handshake) noexcept {
    std::array<std::uint8_t, kClientHandshakeBytes> output{};
    output[0] = kHandshakeSchema;
    auto cursor = output.begin() + 4;
    cursor = std::copy(handshake.nonce.begin(), handshake.nonce.end(), cursor);
    cursor = std::copy(handshake.x25519_public.begin(),
                       handshake.x25519_public.end(), cursor);
    std::copy(handshake.mlkem_public.begin(), handshake.mlkem_public.end(),
              cursor);
    return output;
}

Result<ClientHandshake> DecodeClientHandshake(
    std::span<const std::uint8_t> bytes) noexcept {
    auto status = exact_size(bytes, kClientHandshakeBytes);
    if (!status.ok()) return {status, std::nullopt};
    status = handshake_prefix(bytes, 0U);
    if (!status.ok()) return {status, std::nullopt};
    ClientHandshake handshake;
    auto cursor = bytes.begin() + 4;
    std::copy_n(cursor, kNonceBytes, handshake.nonce.begin());
    cursor += kNonceBytes;
    std::copy_n(cursor, kX25519Bytes, handshake.x25519_public.begin());
    cursor += kX25519Bytes;
    std::copy_n(cursor, kMlKemPublicBytes, handshake.mlkem_public.begin());
    return success(handshake);
}

std::vector<std::uint8_t> EncodeHopHandshake(const HopHandshake& handshake) {
    std::vector<std::uint8_t> output(kHopHandshakeBytes, 0U);
    output[0] = kHandshakeSchema;
    auto cursor = output.begin() + 4;
    cursor = std::copy(handshake.x25519_public.begin(),
                       handshake.x25519_public.end(), cursor);
    cursor = std::copy(handshake.mlkem_ciphertext.begin(),
                       handshake.mlkem_ciphertext.end(), cursor);
    cursor = std::copy(handshake.confirmation.begin(),
                       handshake.confirmation.end(), cursor);
    std::copy(handshake.signature.begin(), handshake.signature.end(), cursor);
    return output;
}

Result<HopHandshake> DecodeHopHandshake(
    std::span<const std::uint8_t> bytes) noexcept {
    auto status = exact_size(bytes, kHopHandshakeBytes);
    if (!status.ok()) return {status, std::nullopt};
    status = handshake_prefix(bytes, 0U);
    if (!status.ok()) return {status, std::nullopt};
    HopHandshake handshake;
    auto cursor = bytes.begin() + 4;
    std::copy_n(cursor, kX25519Bytes, handshake.x25519_public.begin());
    cursor += kX25519Bytes;
    std::copy_n(cursor, kMlKemCiphertextBytes,
                handshake.mlkem_ciphertext.begin());
    cursor += kMlKemCiphertextBytes;
    std::copy_n(cursor, kConfirmationBytes, handshake.confirmation.begin());
    cursor += kConfirmationBytes;
    std::copy_n(cursor, kSignatureBytes, handshake.signature.begin());
    return success(handshake);
}

Result<std::array<std::uint8_t, kCreateBodyBytes>> EncodeCreate(
    std::uint8_t depth, std::span<const std::uint8_t, kClientHandshakeBytes>
                            client_handshake) noexcept {
    using Body = std::array<std::uint8_t, kCreateBodyBytes>;
    if (depth < 1U || depth > kMaxHops) {
        return failure<Body>(ErrorCode::InvalidDepth, 0U);
    }
    const auto prefix = handshake_prefix(client_handshake, 0U);
    if (!prefix.ok()) {
        return failure<Body>(prefix.code, prefix.offset + 2U);
    }
    Body body{};
    body[0] = depth;
    std::copy(client_handshake.begin(), client_handshake.end(),
              body.begin() + 2);
    return success(body);
}

Result<CreateView> DecodeCreate(std::span<const std::uint8_t> body) noexcept {
    auto status = exact_size(body, kCreateBodyBytes);
    if (!status.ok()) return {status, std::nullopt};
    if (body[0] < 1U || body[0] > kMaxHops) {
        return failure<CreateView>(ErrorCode::InvalidDepth, 0U);
    }
    if (body[1] != 0U) {
        return failure<CreateView>(ErrorCode::NonzeroReserved, 1U);
    }
    status = handshake_prefix(body, 2U);
    if (!status.ok()) return {status, std::nullopt};
    return success(CreateView{body[0], body.subspan(2U)});
}

Result<RelayMessageView> DecodeRelayMessage(
    Direction direction, std::span<const std::uint8_t> plaintext) noexcept {
    if (!is_relay_capacity(direction, plaintext.size())) {
        return failure<RelayMessageView>(ErrorCode::InvalidLength, 0U);
    }
    if (!is_known_relay_type(plaintext[0])) {
        return failure<RelayMessageView>(ErrorCode::InvalidType, 0U);
    }
    const auto type = static_cast<RelayType>(plaintext[0]);
    if (!allowed_in(type, direction)) {
        return failure<RelayMessageView>(ErrorCode::WrongDirection, 0U);
    }
    if (plaintext[1] != 0U) {
        return failure<RelayMessageView>(ErrorCode::NonzeroReserved, 1U);
    }
    const std::size_t length = read_u16(plaintext, 2U);
    if (length > plaintext.size() - kRelayHeaderBytes) {
        return failure<RelayMessageView>(ErrorCode::InvalidLength, 2U);
    }
    const auto stream = read_u32(plaintext, 4U);
    if ((stream != 0U) != is_stream_message(type)) {
        return failure<RelayMessageView>(ErrorCode::InvalidStream, 4U);
    }
    const auto payload = plaintext.subspan(kRelayHeaderBytes, length);
    const auto rule = check_payload(type, payload);
    if (!rule.ok()) return {rule, std::nullopt};
    if (const auto nonzero =
            first_nonzero(plaintext, kRelayHeaderBytes + length)) {
        return failure<RelayMessageView>(ErrorCode::NonzeroFiller, *nonzero);
    }
    return success(RelayMessageView{type, stream, payload});
}

Status EncodeRelayMessage(Direction direction, RelayType type,
                          std::uint32_t stream,
                          std::span<const std::uint8_t> payload,
                          std::span<std::uint8_t> output) noexcept {
    if (!is_relay_capacity(direction, output.size())) {
        return {ErrorCode::OutputTooSmall, 0U};
    }
    if (!is_known_relay_type(static_cast<std::uint8_t>(type))) {
        return {ErrorCode::InvalidType, 0U};
    }
    if (!allowed_in(type, direction)) return {ErrorCode::WrongDirection, 0U};
    if (payload.size() > output.size() - kRelayHeaderBytes) {
        return {ErrorCode::InvalidLength, 2U};
    }
    if ((stream != 0U) != is_stream_message(type)) {
        return {ErrorCode::InvalidStream, 4U};
    }
    const auto rule = check_payload(type, payload);
    if (!rule.ok()) return rule;
    output[0] = static_cast<std::uint8_t>(type);
    output[1] = 0U;
    write_u16(output, 2U, static_cast<std::uint16_t>(payload.size()));
    write_u32(output, 4U, stream);
    std::copy(payload.begin(), payload.end(),
              output.begin() + kRelayHeaderBytes);
    std::fill(output.begin() + static_cast<std::ptrdiff_t>(kRelayHeaderBytes +
                                                           payload.size()),
              output.end(), std::uint8_t{0});
    return Status::Success();
}

Result<std::vector<std::uint8_t>> EncodeBeginPayload(
    const ytp1::Destination& destination) {
    using Bytes = std::vector<std::uint8_t>;
    if (destination.address_kind == ytp1::AddressKind::None ||
        !ytp1::ValidateDestination(ytp1::ServiceKind::ByteStream, destination)
             .ok()) {
        return failure<Bytes>(ErrorCode::InvalidDestination, 0U);
    }
    Bytes output;
    output.push_back(static_cast<std::uint8_t>(destination.address_kind));
    output.push_back(static_cast<std::uint8_t>(destination.port >> 8U));
    output.push_back(static_cast<std::uint8_t>(destination.port));
    switch (destination.address_kind) {
        case ytp1::AddressKind::Ipv4:
        case ytp1::AddressKind::Ipv6:
            output.insert(
                output.end(), destination.address.begin(),
                destination.address.begin() + destination.address_length);
            break;
        case ytp1::AddressKind::Dns:
            output.push_back(
                static_cast<std::uint8_t>(destination.dns_name.size()));
            output.insert(output.end(), destination.dns_name.begin(),
                          destination.dns_name.end());
            break;
        case ytp1::AddressKind::None:
            break;
    }
    return success(std::move(output));
}

Result<ytp1::Destination> DecodeBeginPayload(
    std::span<const std::uint8_t> payload) {
    using ytp1::AddressKind;
    if (payload.size() < 3U) {
        return failure<ytp1::Destination>(ErrorCode::Truncated, payload.size());
    }
    ytp1::Destination destination;
    destination.transport = ytp1::TransportProtocol::Tcp;
    destination.port = read_u16(payload, 1U);
    const auto rest = payload.subspan(3U);
    switch (payload[0]) {
        case static_cast<std::uint8_t>(AddressKind::Ipv4):
        case static_cast<std::uint8_t>(AddressKind::Ipv6): {
            const std::size_t size =
                payload[0] == static_cast<std::uint8_t>(AddressKind::Ipv4)
                    ? 4U
                    : 16U;
            const auto status = exact_size(rest, size);
            if (!status.ok()) {
                return failure<ytp1::Destination>(status.code,
                                                  status.offset + 3U);
            }
            destination.address_kind = static_cast<AddressKind>(payload[0]);
            destination.address_length = static_cast<std::uint8_t>(size);
            std::copy(rest.begin(), rest.end(), destination.address.begin());
            break;
        }
        case static_cast<std::uint8_t>(AddressKind::Dns): {
            if (rest.empty()) {
                return failure<ytp1::Destination>(ErrorCode::Truncated, 3U);
            }
            const auto status = exact_size(rest.subspan(1U), rest[0]);
            if (!status.ok()) {
                return failure<ytp1::Destination>(status.code,
                                                  status.offset + 4U);
            }
            destination.address_kind = AddressKind::Dns;
            destination.dns_name.assign(rest.begin() + 1, rest.end());
            break;
        }
        default:
            return failure<ytp1::Destination>(ErrorCode::InvalidDestination,
                                              0U);
    }
    if (!ytp1::ValidateDestination(ytp1::ServiceKind::ByteStream, destination)
             .ok()) {
        return failure<ytp1::Destination>(ErrorCode::InvalidDestination, 0U);
    }
    return success(std::move(destination));
}

std::array<std::uint8_t, kExtendPayloadBytes> EncodeExtendPayload(
    std::span<const std::uint8_t, kFingerprintBytes> next_identity,
    std::span<const std::uint8_t, kClientHandshakeBytes>
        client_handshake) noexcept {
    std::array<std::uint8_t, kExtendPayloadBytes> output{};
    const auto cursor =
        std::copy(next_identity.begin(), next_identity.end(), output.begin());
    std::copy(client_handshake.begin(), client_handshake.end(), cursor);
    return output;
}

Result<ExtendView> DecodeExtendPayload(
    std::span<const std::uint8_t> payload) noexcept {
    const auto size = exact_size(payload, kExtendPayloadBytes);
    if (!size.ok()) return {size, std::nullopt};
    const auto prefix = handshake_prefix(payload, kFingerprintBytes);
    if (!prefix.ok()) return {prefix, std::nullopt};
    return success(ExtendView{payload.first<kFingerprintBytes>(),
                              payload.subspan(kFingerprintBytes)});
}

std::string_view ErrorName(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::Ok:
            return "ok";
        case ErrorCode::Truncated:
            return "truncated";
        case ErrorCode::TrailingData:
            return "trailing data";
        case ErrorCode::UnsupportedVersion:
            return "unsupported version";
        case ErrorCode::InvalidCommand:
            return "invalid command";
        case ErrorCode::InvalidBucket:
            return "invalid bucket";
        case ErrorCode::InvalidLength:
            return "invalid length";
        case ErrorCode::NonzeroFiller:
            return "nonzero filler";
        case ErrorCode::NonzeroReserved:
            return "nonzero reserved";
        case ErrorCode::InvalidDepth:
            return "invalid depth";
        case ErrorCode::InvalidType:
            return "invalid type";
        case ErrorCode::WrongDirection:
            return "wrong direction";
        case ErrorCode::InvalidStream:
            return "invalid stream";
        case ErrorCode::InvalidReason:
            return "invalid reason";
        case ErrorCode::InvalidDestination:
            return "invalid destination";
        case ErrorCode::InvalidCredit:
            return "invalid credit";
        case ErrorCode::OutputTooSmall:
            return "output too small";
    }
    return "unknown";
}

}  // namespace yume::circuit1
