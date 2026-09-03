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
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "common/service_name.hpp"

namespace yume::ytp1 {

enum class ErrorCode {
    Ok = 0,
    Truncated,
    TrailingData,
    UnsupportedVersion,
    UnsupportedRecordType,
    InvalidFlags,
    PayloadTooLarge,
    InvalidLength,
    InvalidStreamId,
    WrongStreamClass,
    WrongStreamOwner,
    StreamIdExhausted,
    InvalidEnum,
    InvalidUtf8,
    InvalidServiceName,
    InvalidDestination,
    InvalidPort,
    NonCanonical,
    DuplicateField,
    OutOfOrderField,
    UnknownCriticalField,
    TooManyFields,
    MissingField,
    InvalidField,
    CreditOutOfRange,
    OutputTooSmall,
    OverlappingBuffer,
    IntegerOverflow,
};

struct Status {
    ErrorCode code{ErrorCode::Ok};
    std::size_t offset{0};

    [[nodiscard]] constexpr bool ok() const noexcept {
        return code == ErrorCode::Ok;
    }

    [[nodiscard]] constexpr explicit operator bool() const noexcept {
        return ok();
    }

    [[nodiscard]] static constexpr Status Success() noexcept {
        return {};
    }
};

template <typename T>
struct Result {
    Status status{};
    std::optional<T> value{};

    [[nodiscard]] bool ok() const noexcept {
        return status.ok() && value.has_value();
    }

    [[nodiscard]] explicit operator bool() const noexcept {
        return ok();
    }

    [[nodiscard]] static Result Success(T result) {
        return {Status::Success(), std::move(result)};
    }

    [[nodiscard]] static Result Failure(ErrorCode code,
                                        std::size_t offset = 0) noexcept {
        return {{code, offset}, std::nullopt};
    }
};

inline constexpr std::uint8_t kWireVersion = 1;
inline constexpr std::size_t kFrameHeaderSize = 12;
inline constexpr std::uint32_t kMaxStreamId = 0x7fff'ffffU;
inline constexpr std::uint32_t kDefaultMaxFramePayload = 1U << 20;

enum class EndpointRole : std::uint8_t {
    Client = 1,
    Server = 2,
};

class StreamId final {
public:
    [[nodiscard]] static constexpr StreamId Control() noexcept {
        return StreamId(0);
    }

    [[nodiscard]] static Result<StreamId> FromWire(std::uint32_t value) noexcept;
    [[nodiscard]] static Result<StreamId> FirstOwnedBy(EndpointRole role) noexcept;

    [[nodiscard]] constexpr std::uint32_t value() const noexcept {
        return value_;
    }

    [[nodiscard]] constexpr bool is_control() const noexcept {
        return value_ == 0;
    }

    [[nodiscard]] constexpr bool is_application() const noexcept {
        return value_ != 0;
    }

    [[nodiscard]] constexpr bool is_owned_by(EndpointRole role) const noexcept {
        return is_application() &&
               ((role == EndpointRole::Client && (value_ & 1U) == 1U) ||
                (role == EndpointRole::Server && (value_ & 1U) == 0U));
    }

    [[nodiscard]] Result<StreamId> NextOwned() const noexcept;

    friend constexpr bool operator==(StreamId, StreamId) noexcept = default;

private:
    explicit constexpr StreamId(std::uint32_t value) noexcept : value_(value) {}

    std::uint32_t value_;
};

[[nodiscard]] Status ValidateOpenStreamOwner(StreamId stream_id,
                                             EndpointRole opener) noexcept;

enum class RecordType : std::uint8_t {
    Auth = 1,
    AuthResult = 2,
    Capabilities = 3,
    Open = 4,
    Data = 5,
    Packet = 6,
    Close = 7,
    ConnectionCredit = 8,
    StreamCredit = 9,
    RekeyInit = 10,
    RekeyAck = 11,
    Ping = 12,
    Pong = 13,
};

[[nodiscard]] constexpr bool IsControlRecord(RecordType type) noexcept {
    switch (type) {
    case RecordType::Auth:
    case RecordType::AuthResult:
    case RecordType::Capabilities:
    case RecordType::ConnectionCredit:
    case RecordType::RekeyInit:
    case RecordType::RekeyAck:
    case RecordType::Ping:
    case RecordType::Pong:
        return true;
    case RecordType::Open:
    case RecordType::Data:
    case RecordType::Packet:
    case RecordType::Close:
    case RecordType::StreamCredit:
        return false;
    }
    return false;
}

struct FrameHeader {
    RecordType type{RecordType::Auth};
    std::uint16_t flags{0};
    StreamId stream_id{StreamId::Control()};
    std::uint32_t payload_length{0};
};

// Canonical 12-byte header, in network byte order:
//   u8 version | u8 record_type | u16 flags | u32 stream_id | u32 payload_len
// The stream-ID high bit and every flag bit are reserved and rejected in
// YTP/1. DecodeRecord returns a borrowed payload only after checking its exact
// length against the caller's bounded limit.

struct RecordView {
    FrameHeader header;
    std::span<const std::uint8_t> payload;
};

[[nodiscard]] Status ValidateFrameHeader(
    const FrameHeader& header,
    std::uint32_t max_payload = kDefaultMaxFramePayload) noexcept;
[[nodiscard]] Status EncodeFrameHeader(
    const FrameHeader& header,
    std::span<std::uint8_t, kFrameHeaderSize> output,
    std::uint32_t max_payload = kDefaultMaxFramePayload) noexcept;
[[nodiscard]] Result<FrameHeader> DecodeFrameHeader(
    std::span<const std::uint8_t> input,
    std::uint32_t max_payload = kDefaultMaxFramePayload) noexcept;
[[nodiscard]] Result<RecordView> DecodeRecord(
    std::span<const std::uint8_t> input,
    std::uint32_t max_payload = kDefaultMaxFramePayload) noexcept;

enum class ServiceKind : std::uint8_t {
    ByteStream = 1,
    Packet = 2,
};

enum class TransportProtocol : std::uint8_t {
    None = 0,
    Tcp = 1,
    Udp = 2,
};

enum class AddressKind : std::uint8_t {
    None = 0,
    Ipv4 = 1,
    Ipv6 = 2,
    Dns = 3,
};

inline constexpr std::size_t kMaxServiceNameBytes =
    common::kMaxServiceNameBytes;
inline constexpr std::size_t kMaxDnsNameBytes = 253;
inline constexpr std::size_t kMaxOpenPayload = 512;

struct Destination {
    TransportProtocol transport{TransportProtocol::None};
    AddressKind address_kind{AddressKind::None};
    std::array<std::uint8_t, 16> address{};
    std::uint8_t address_length{0};
    std::string dns_name;
    std::uint16_t port{0};

    friend bool operator==(const Destination&, const Destination&) = default;
};

struct OpenRequest {
    ServiceKind service_kind{ServiceKind::ByteStream};
    std::string service_name;
    Destination destination;

    friend bool operator==(const OpenRequest&, const OpenRequest&) = default;
};

// OPEN begins with version, service kind, transport, address kind, then u16
// service-name and destination lengths. A destination is absent, or is a
// nonzero u16 port followed by fixed binary IPv4/IPv6 or a length-prefixed,
// canonical lowercase DNS name. TCP is valid only for byte streams and UDP
// only for packet channels.

[[nodiscard]] bool IsValidServiceName(std::string_view name) noexcept;
[[nodiscard]] Status ValidateDestination(ServiceKind service_kind,
                                         const Destination& destination) noexcept;
[[nodiscard]] Result<std::vector<std::uint8_t>> EncodeOpen(
    const OpenRequest& request);
[[nodiscard]] Result<OpenRequest> DecodeOpen(
    std::span<const std::uint8_t> payload);

inline constexpr std::size_t kMaxCapabilities = 256;
inline constexpr std::size_t kMaxCapabilityManifestSize = 64U << 10;
inline constexpr std::uint32_t kMaxCapabilityConcurrentStreams = 1U << 20;

struct Capability {
    std::string service_name;
    ServiceKind service_kind{ServiceKind::ByteStream};
    std::uint32_t max_concurrent_streams{1};

    friend bool operator==(const Capability&, const Capability&) = default;
};

struct CapabilityManifest {
    std::vector<Capability> entries;

    friend bool operator==(const CapabilityManifest&,
                           const CapabilityManifest&) = default;
};

// Manifest entries are encoded in unsigned UTF-8 byte order, then service-kind
// order. Duplicate keys and noncanonical order are rejected on decode.

[[nodiscard]] Result<std::vector<std::uint8_t>> EncodeCapabilityManifest(
    const CapabilityManifest& manifest);
[[nodiscard]] Result<CapabilityManifest> DecodeCapabilityManifest(
    std::span<const std::uint8_t> payload);
[[nodiscard]] Status ValidateCapabilityManifestEncoding(
    std::span<const std::uint8_t> payload) noexcept;

inline constexpr std::uint32_t kMaxCreditIncrement = 1U << 30;

[[nodiscard]] Result<std::array<std::uint8_t, 4>> EncodeCreditUpdate(
    std::uint32_t increment) noexcept;
[[nodiscard]] Result<std::uint32_t> DecodeCreditUpdate(
    std::span<const std::uint8_t> payload) noexcept;

} // namespace yume::ytp1
