/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "ytp/protocol.hpp"

#include <algorithm>
#include <limits>

namespace yume::ytp1 {
namespace {

constexpr std::size_t kOpenPrefixSize = 8;
constexpr std::size_t kCapabilityPrefixSize = 4;
constexpr std::size_t kCapabilityEntryPrefixSize = 8;

[[nodiscard]] constexpr std::uint16_t ReadU16(
    std::span<const std::uint8_t> input,
    std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(input[offset]) << 8U) |
        static_cast<std::uint16_t>(input[offset + 1]));
}

[[nodiscard]] constexpr std::uint32_t ReadU32(
    std::span<const std::uint8_t> input,
    std::size_t offset) noexcept {
    return (static_cast<std::uint32_t>(input[offset]) << 24U) |
           (static_cast<std::uint32_t>(input[offset + 1]) << 16U) |
           (static_cast<std::uint32_t>(input[offset + 2]) << 8U) |
           static_cast<std::uint32_t>(input[offset + 3]);
}

constexpr void WriteU16(std::span<std::uint8_t> output,
                        std::size_t offset,
                        std::uint16_t value) noexcept {
    output[offset] = static_cast<std::uint8_t>(value >> 8U);
    output[offset + 1] = static_cast<std::uint8_t>(value);
}

constexpr void WriteU32(std::span<std::uint8_t> output,
                        std::size_t offset,
                        std::uint32_t value) noexcept {
    output[offset] = static_cast<std::uint8_t>(value >> 24U);
    output[offset + 1] = static_cast<std::uint8_t>(value >> 16U);
    output[offset + 2] = static_cast<std::uint8_t>(value >> 8U);
    output[offset + 3] = static_cast<std::uint8_t>(value);
}

[[nodiscard]] constexpr bool IsKnownRecordType(RecordType type) noexcept {
    switch (type) {
    case RecordType::Auth:
    case RecordType::AuthResult:
    case RecordType::Capabilities:
    case RecordType::Open:
    case RecordType::Data:
    case RecordType::Packet:
    case RecordType::Close:
    case RecordType::ConnectionCredit:
    case RecordType::StreamCredit:
    case RecordType::RekeyInit:
    case RecordType::RekeyAck:
    case RecordType::Ping:
    case RecordType::Pong:
        return true;
    }
    return false;
}

[[nodiscard]] constexpr bool IsKnownServiceKind(ServiceKind kind) noexcept {
    return kind == ServiceKind::ByteStream || kind == ServiceKind::Packet;
}

[[nodiscard]] constexpr bool IsKnownTransport(
    TransportProtocol transport) noexcept {
    return transport == TransportProtocol::None ||
           transport == TransportProtocol::Tcp ||
           transport == TransportProtocol::Udp;
}

[[nodiscard]] constexpr bool IsKnownAddressKind(AddressKind kind) noexcept {
    return kind == AddressKind::None || kind == AddressKind::Ipv4 ||
           kind == AddressKind::Ipv6 || kind == AddressKind::Dns;
}

[[nodiscard]] bool IsAllZero(std::span<const std::uint8_t> input) noexcept {
    std::uint8_t aggregate = 0;
    for (const std::uint8_t byte : input) {
        aggregate = static_cast<std::uint8_t>(aggregate | byte);
    }
    return aggregate == 0;
}

[[nodiscard]] bool IsCanonicalDnsName(std::string_view name) noexcept {
    if (name.empty() || name.size() > kMaxDnsNameBytes || name.front() == '.' ||
        name.back() == '.') {
        return false;
    }

    std::size_t label_start = 0;
    for (std::size_t i = 0; i <= name.size(); ++i) {
        if (i != name.size() && name[i] != '.') {
            const unsigned char c = static_cast<unsigned char>(name[i]);
            if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                  c == '-')) {
                return false;
            }
            continue;
        }

        const std::size_t label_length = i - label_start;
        if (label_length == 0 || label_length > 63 ||
            name[label_start] == '-' || name[i - 1] == '-') {
            return false;
        }
        label_start = i + 1;
    }
    return true;
}

[[nodiscard]] int CompareCapabilityKeys(std::string_view lhs_name,
                                        ServiceKind lhs_kind,
                                        std::string_view rhs_name,
                                        ServiceKind rhs_kind) noexcept {
    const std::size_t common = std::min(lhs_name.size(), rhs_name.size());
    for (std::size_t i = 0; i < common; ++i) {
        const auto lhs = static_cast<unsigned char>(lhs_name[i]);
        const auto rhs = static_cast<unsigned char>(rhs_name[i]);
        if (lhs < rhs) {
            return -1;
        }
        if (lhs > rhs) {
            return 1;
        }
    }
    if (lhs_name.size() < rhs_name.size()) {
        return -1;
    }
    if (lhs_name.size() > rhs_name.size()) {
        return 1;
    }
    const auto lhs = static_cast<std::uint8_t>(lhs_kind);
    const auto rhs = static_cast<std::uint8_t>(rhs_kind);
    if (lhs < rhs) {
        return -1;
    }
    if (lhs > rhs) {
        return 1;
    }
    return 0;
}

} // namespace

Result<StreamId> StreamId::FromWire(std::uint32_t value) noexcept {
    if (value > kMaxStreamId) {
        return Result<StreamId>::Failure(ErrorCode::InvalidStreamId);
    }
    return Result<StreamId>::Success(StreamId(value));
}

Result<StreamId> StreamId::FirstOwnedBy(EndpointRole role) noexcept {
    if (role == EndpointRole::Client) {
        return Result<StreamId>::Success(StreamId(1));
    }
    if (role == EndpointRole::Server) {
        return Result<StreamId>::Success(StreamId(2));
    }
    return Result<StreamId>::Failure(ErrorCode::InvalidEnum);
}

Result<StreamId> StreamId::NextOwned() const noexcept {
    if (is_control()) {
        return Result<StreamId>::Failure(ErrorCode::InvalidStreamId);
    }
    if (value_ > kMaxStreamId - 2U) {
        return Result<StreamId>::Failure(ErrorCode::StreamIdExhausted);
    }
    return Result<StreamId>::Success(StreamId(value_ + 2U));
}

Status ValidateOpenStreamOwner(StreamId stream_id,
                               EndpointRole opener) noexcept {
    if (opener != EndpointRole::Client && opener != EndpointRole::Server) {
        return {ErrorCode::InvalidEnum, 0};
    }
    if (!stream_id.is_application()) {
        return {ErrorCode::WrongStreamClass, 0};
    }
    if (!stream_id.is_owned_by(opener)) {
        return {ErrorCode::WrongStreamOwner, 0};
    }
    return Status::Success();
}

Status ValidateFrameHeader(const FrameHeader& header,
                           std::uint32_t max_payload) noexcept {
    if (!IsKnownRecordType(header.type)) {
        return {ErrorCode::UnsupportedRecordType, 1};
    }
    if (header.flags != 0) {
        return {ErrorCode::InvalidFlags, 2};
    }
    if (header.stream_id.value() > kMaxStreamId) {
        return {ErrorCode::InvalidStreamId, 4};
    }
    if (header.payload_length > max_payload) {
        return {ErrorCode::PayloadTooLarge, 8};
    }
    if (IsControlRecord(header.type) != header.stream_id.is_control()) {
        return {ErrorCode::WrongStreamClass, 4};
    }
    return Status::Success();
}

Status EncodeFrameHeader(const FrameHeader& header,
                         std::span<std::uint8_t, kFrameHeaderSize> output,
                         std::uint32_t max_payload) noexcept {
    const Status status = ValidateFrameHeader(header, max_payload);
    if (!status) {
        return status;
    }

    output[0] = kWireVersion;
    output[1] = static_cast<std::uint8_t>(header.type);
    WriteU16(output, 2, header.flags);
    WriteU32(output, 4, header.stream_id.value());
    WriteU32(output, 8, header.payload_length);
    return Status::Success();
}

Result<FrameHeader> DecodeFrameHeader(std::span<const std::uint8_t> input,
                                      std::uint32_t max_payload) noexcept {
    if (input.size() < kFrameHeaderSize) {
        return Result<FrameHeader>::Failure(ErrorCode::Truncated, input.size());
    }
    if (input.size() > kFrameHeaderSize) {
        return Result<FrameHeader>::Failure(ErrorCode::TrailingData,
                                            kFrameHeaderSize);
    }
    if (input[0] != kWireVersion) {
        return Result<FrameHeader>::Failure(ErrorCode::UnsupportedVersion, 0);
    }

    const auto type = static_cast<RecordType>(input[1]);
    if (!IsKnownRecordType(type)) {
        return Result<FrameHeader>::Failure(ErrorCode::UnsupportedRecordType, 1);
    }
    const auto stream_id = StreamId::FromWire(ReadU32(input, 4));
    if (!stream_id) {
        return Result<FrameHeader>::Failure(stream_id.status.code, 4);
    }

    FrameHeader header{
        .type = type,
        .flags = ReadU16(input, 2),
        .stream_id = *stream_id.value,
        .payload_length = ReadU32(input, 8),
    };
    const Status status = ValidateFrameHeader(header, max_payload);
    if (!status) {
        return Result<FrameHeader>::Failure(status.code, status.offset);
    }
    return Result<FrameHeader>::Success(header);
}

Result<RecordView> DecodeRecord(std::span<const std::uint8_t> input,
                                std::uint32_t max_payload) noexcept {
    if (input.size() < kFrameHeaderSize) {
        return Result<RecordView>::Failure(ErrorCode::Truncated, input.size());
    }
    const auto header = DecodeFrameHeader(input.first(kFrameHeaderSize),
                                          max_payload);
    if (!header) {
        return Result<RecordView>::Failure(header.status.code,
                                           header.status.offset);
    }

    const std::size_t expected = kFrameHeaderSize +
                                 static_cast<std::size_t>(header.value->payload_length);
    if (input.size() < expected) {
        return Result<RecordView>::Failure(ErrorCode::Truncated, input.size());
    }
    if (input.size() > expected) {
        return Result<RecordView>::Failure(ErrorCode::TrailingData, expected);
    }
    return Result<RecordView>::Success(
        {*header.value, input.subspan(kFrameHeaderSize)});
}

bool IsValidServiceName(std::string_view name) noexcept {
    return common::valid_service_name(name);
}

Status ValidateDestination(ServiceKind service_kind,
                           const Destination& destination) noexcept {
    if (!IsKnownServiceKind(service_kind) ||
        !IsKnownTransport(destination.transport) ||
        !IsKnownAddressKind(destination.address_kind)) {
        return {ErrorCode::InvalidEnum, 0};
    }

    if (destination.transport == TransportProtocol::None ||
        destination.address_kind == AddressKind::None) {
        if (destination.transport != TransportProtocol::None ||
            destination.address_kind != AddressKind::None ||
            destination.port != 0 || destination.address_length != 0 ||
            !destination.dns_name.empty() || !IsAllZero(destination.address)) {
            return {ErrorCode::InvalidDestination, 0};
        }
        return Status::Success();
    }

    if ((service_kind == ServiceKind::ByteStream &&
         destination.transport != TransportProtocol::Tcp) ||
        (service_kind == ServiceKind::Packet &&
         destination.transport != TransportProtocol::Udp)) {
        return {ErrorCode::InvalidDestination, 0};
    }
    if (destination.port == 0) {
        return {ErrorCode::InvalidPort, 0};
    }

    switch (destination.address_kind) {
    case AddressKind::Ipv4:
        if (destination.address_length != 4 || !destination.dns_name.empty() ||
            !IsAllZero(std::span<const std::uint8_t>(destination.address).subspan(4))) {
            return {ErrorCode::InvalidDestination, 0};
        }
        return Status::Success();
    case AddressKind::Ipv6:
        if (destination.address_length != 16 || !destination.dns_name.empty()) {
            return {ErrorCode::InvalidDestination, 0};
        }
        return Status::Success();
    case AddressKind::Dns:
        if (destination.address_length != 0 ||
            !IsAllZero(destination.address) ||
            !IsCanonicalDnsName(destination.dns_name)) {
            return {ErrorCode::InvalidDestination, 0};
        }
        return Status::Success();
    case AddressKind::None:
        break;
    }
    return {ErrorCode::InvalidDestination, 0};
}

Result<std::vector<std::uint8_t>> EncodeOpen(const OpenRequest& request) {
    if (!IsKnownServiceKind(request.service_kind)) {
        return Result<std::vector<std::uint8_t>>::Failure(ErrorCode::InvalidEnum);
    }
    if (!IsValidServiceName(request.service_name)) {
        return Result<std::vector<std::uint8_t>>::Failure(
            ErrorCode::InvalidServiceName);
    }
    const Status destination_status =
        ValidateDestination(request.service_kind, request.destination);
    if (!destination_status) {
        return Result<std::vector<std::uint8_t>>::Failure(
            destination_status.code);
    }

    std::size_t destination_length = 0;
    switch (request.destination.address_kind) {
    case AddressKind::None:
        break;
    case AddressKind::Ipv4:
        destination_length = 2 + 4;
        break;
    case AddressKind::Ipv6:
        destination_length = 2 + 16;
        break;
    case AddressKind::Dns:
        destination_length = 2 + 1 + request.destination.dns_name.size();
        break;
    }

    const std::size_t total = kOpenPrefixSize + request.service_name.size() +
                              destination_length;
    if (total > kMaxOpenPayload ||
        request.service_name.size() > std::numeric_limits<std::uint16_t>::max() ||
        destination_length > std::numeric_limits<std::uint16_t>::max()) {
        return Result<std::vector<std::uint8_t>>::Failure(
            ErrorCode::PayloadTooLarge);
    }

    std::vector<std::uint8_t> output(total);
    output[0] = kWireVersion;
    output[1] = static_cast<std::uint8_t>(request.service_kind);
    output[2] = static_cast<std::uint8_t>(request.destination.transport);
    output[3] = static_cast<std::uint8_t>(request.destination.address_kind);
    WriteU16(output, 4,
             static_cast<std::uint16_t>(request.service_name.size()));
    WriteU16(output, 6, static_cast<std::uint16_t>(destination_length));
    std::copy(request.service_name.begin(), request.service_name.end(),
              output.begin() + static_cast<std::ptrdiff_t>(kOpenPrefixSize));

    std::size_t offset = kOpenPrefixSize + request.service_name.size();
    if (request.destination.address_kind != AddressKind::None) {
        WriteU16(output, offset, request.destination.port);
        offset += 2;
    }
    switch (request.destination.address_kind) {
    case AddressKind::None:
        break;
    case AddressKind::Ipv4:
    case AddressKind::Ipv6:
        std::copy_n(request.destination.address.begin(),
                    request.destination.address_length,
                    output.begin() + static_cast<std::ptrdiff_t>(offset));
        break;
    case AddressKind::Dns:
        output[offset++] =
            static_cast<std::uint8_t>(request.destination.dns_name.size());
        std::copy(request.destination.dns_name.begin(),
                  request.destination.dns_name.end(),
                  output.begin() + static_cast<std::ptrdiff_t>(offset));
        break;
    }

    return Result<std::vector<std::uint8_t>>::Success(std::move(output));
}

Result<OpenRequest> DecodeOpen(std::span<const std::uint8_t> payload) {
    if (payload.size() > kMaxOpenPayload) {
        return Result<OpenRequest>::Failure(ErrorCode::PayloadTooLarge);
    }
    if (payload.size() < kOpenPrefixSize) {
        return Result<OpenRequest>::Failure(ErrorCode::Truncated, payload.size());
    }
    if (payload[0] != kWireVersion) {
        return Result<OpenRequest>::Failure(ErrorCode::UnsupportedVersion, 0);
    }

    const auto service_kind = static_cast<ServiceKind>(payload[1]);
    const auto transport = static_cast<TransportProtocol>(payload[2]);
    const auto address_kind = static_cast<AddressKind>(payload[3]);
    if (!IsKnownServiceKind(service_kind) || !IsKnownTransport(transport) ||
        !IsKnownAddressKind(address_kind)) {
        return Result<OpenRequest>::Failure(ErrorCode::InvalidEnum, 1);
    }

    const std::size_t service_length = ReadU16(payload, 4);
    const std::size_t destination_length = ReadU16(payload, 6);
    const std::size_t expected = kOpenPrefixSize + service_length +
                                 destination_length;
    if (expected > payload.size()) {
        return Result<OpenRequest>::Failure(ErrorCode::Truncated, payload.size());
    }
    if (expected < payload.size()) {
        return Result<OpenRequest>::Failure(ErrorCode::TrailingData, expected);
    }
    if (service_length == 0 || service_length > kMaxServiceNameBytes) {
        return Result<OpenRequest>::Failure(ErrorCode::InvalidServiceName, 4);
    }

    const auto service_bytes = payload.subspan(kOpenPrefixSize, service_length);
    const std::string_view service_view(
        reinterpret_cast<const char*>(service_bytes.data()), service_bytes.size());
    if (!IsValidServiceName(service_view)) {
        return Result<OpenRequest>::Failure(ErrorCode::InvalidUtf8,
                                            kOpenPrefixSize);
    }

    OpenRequest request;
    request.service_kind = service_kind;
    request.service_name.assign(service_view);
    request.destination.transport = transport;
    request.destination.address_kind = address_kind;

    std::size_t offset = kOpenPrefixSize + service_length;
    if (address_kind == AddressKind::None) {
        if (destination_length != 0) {
            return Result<OpenRequest>::Failure(ErrorCode::InvalidLength, 6);
        }
    } else {
        if (destination_length < 2) {
            return Result<OpenRequest>::Failure(ErrorCode::Truncated, offset);
        }
        request.destination.port = ReadU16(payload, offset);
        offset += 2;
    }

    switch (address_kind) {
    case AddressKind::None:
        break;
    case AddressKind::Ipv4:
        if (destination_length != 6) {
            return Result<OpenRequest>::Failure(ErrorCode::InvalidLength, 6);
        }
        request.destination.address_length = 4;
        std::copy_n(payload.begin() + static_cast<std::ptrdiff_t>(offset), 4,
                    request.destination.address.begin());
        break;
    case AddressKind::Ipv6:
        if (destination_length != 18) {
            return Result<OpenRequest>::Failure(ErrorCode::InvalidLength, 6);
        }
        request.destination.address_length = 16;
        std::copy_n(payload.begin() + static_cast<std::ptrdiff_t>(offset), 16,
                    request.destination.address.begin());
        break;
    case AddressKind::Dns: {
        if (destination_length < 3) {
            return Result<OpenRequest>::Failure(ErrorCode::InvalidLength, 6);
        }
        const std::size_t dns_length = payload[offset++];
        if (dns_length != destination_length - 3) {
            return Result<OpenRequest>::Failure(ErrorCode::InvalidLength,
                                                offset - 1);
        }
        request.destination.dns_name.assign(
            reinterpret_cast<const char*>(payload.data() + offset), dns_length);
        break;
    }
    }

    const Status status = ValidateDestination(service_kind, request.destination);
    if (!status) {
        return Result<OpenRequest>::Failure(status.code, offset);
    }
    return Result<OpenRequest>::Success(std::move(request));
}

Status ValidateCapabilityManifestEncoding(
    std::span<const std::uint8_t> payload) noexcept {
    if (payload.size() > kMaxCapabilityManifestSize) {
        return {ErrorCode::PayloadTooLarge, 0};
    }
    if (payload.size() < kCapabilityPrefixSize) {
        return {ErrorCode::Truncated, payload.size()};
    }
    if (payload[0] != kWireVersion) {
        return {ErrorCode::UnsupportedVersion, 0};
    }
    if (payload[1] != 0) {
        return {ErrorCode::InvalidFlags, 1};
    }

    const std::size_t count = ReadU16(payload, 2);
    if (count > kMaxCapabilities) {
        return {ErrorCode::TooManyFields, 2};
    }
    std::size_t offset = kCapabilityPrefixSize;
    std::string_view previous_name;
    ServiceKind previous_kind = ServiceKind::ByteStream;
    bool have_previous = false;

    for (std::size_t i = 0; i < count; ++i) {
        if (payload.size() - offset < kCapabilityEntryPrefixSize) {
            return {ErrorCode::Truncated, offset};
        }
        const auto kind = static_cast<ServiceKind>(payload[offset]);
        if (!IsKnownServiceKind(kind)) {
            return {ErrorCode::InvalidEnum, offset};
        }
        if (payload[offset + 1] != 0) {
            return {ErrorCode::InvalidFlags, offset + 1};
        }
        const std::size_t name_length = ReadU16(payload, offset + 2);
        const std::uint32_t max_streams = ReadU32(payload, offset + 4);
        offset += kCapabilityEntryPrefixSize;
        if (name_length == 0 || name_length > kMaxServiceNameBytes) {
            return {ErrorCode::InvalidServiceName, offset - 6};
        }
        if (name_length > payload.size() - offset) {
            return {ErrorCode::Truncated, offset};
        }
        if (max_streams == 0 ||
            max_streams > kMaxCapabilityConcurrentStreams) {
            return {ErrorCode::InvalidField, offset - 4};
        }

        const std::string_view name(
            reinterpret_cast<const char*>(payload.data() + offset), name_length);
        if (!IsValidServiceName(name)) {
            return {ErrorCode::InvalidUtf8, offset};
        }
        if (have_previous) {
            const int order = CompareCapabilityKeys(previous_name, previous_kind,
                                                    name, kind);
            if (order == 0) {
                return {ErrorCode::DuplicateField, offset};
            }
            if (order > 0) {
                return {ErrorCode::OutOfOrderField, offset};
            }
        }
        previous_name = name;
        previous_kind = kind;
        have_previous = true;
        offset += name_length;
    }

    if (offset != payload.size()) {
        return {ErrorCode::TrailingData, offset};
    }
    return Status::Success();
}

Result<std::vector<std::uint8_t>> EncodeCapabilityManifest(
    const CapabilityManifest& manifest) {
    if (manifest.entries.size() > kMaxCapabilities) {
        return Result<std::vector<std::uint8_t>>::Failure(
            ErrorCode::TooManyFields);
    }

    std::vector<Capability> entries = manifest.entries;
    for (const Capability& entry : entries) {
        if (!IsKnownServiceKind(entry.service_kind)) {
            return Result<std::vector<std::uint8_t>>::Failure(
                ErrorCode::InvalidEnum);
        }
        if (!IsValidServiceName(entry.service_name)) {
            return Result<std::vector<std::uint8_t>>::Failure(
                ErrorCode::InvalidServiceName);
        }
        if (entry.max_concurrent_streams == 0 ||
            entry.max_concurrent_streams > kMaxCapabilityConcurrentStreams) {
            return Result<std::vector<std::uint8_t>>::Failure(
                ErrorCode::InvalidField);
        }
    }

    std::sort(entries.begin(), entries.end(),
              [](const Capability& lhs, const Capability& rhs) {
                  return CompareCapabilityKeys(lhs.service_name,
                                               lhs.service_kind,
                                               rhs.service_name,
                                               rhs.service_kind) < 0;
              });
    for (std::size_t i = 1; i < entries.size(); ++i) {
        if (CompareCapabilityKeys(entries[i - 1].service_name,
                                  entries[i - 1].service_kind,
                                  entries[i].service_name,
                                  entries[i].service_kind) == 0) {
            return Result<std::vector<std::uint8_t>>::Failure(
                ErrorCode::DuplicateField);
        }
    }

    std::size_t total = kCapabilityPrefixSize;
    for (const Capability& entry : entries) {
        if (total > kMaxCapabilityManifestSize - kCapabilityEntryPrefixSize ||
            entry.service_name.size() >
                kMaxCapabilityManifestSize - total -
                    kCapabilityEntryPrefixSize) {
            return Result<std::vector<std::uint8_t>>::Failure(
                ErrorCode::PayloadTooLarge);
        }
        total += kCapabilityEntryPrefixSize + entry.service_name.size();
    }

    std::vector<std::uint8_t> output(total);
    output[0] = kWireVersion;
    output[1] = 0;
    WriteU16(output, 2, static_cast<std::uint16_t>(entries.size()));
    std::size_t offset = kCapabilityPrefixSize;
    for (const Capability& entry : entries) {
        output[offset] = static_cast<std::uint8_t>(entry.service_kind);
        output[offset + 1] = 0;
        WriteU16(output, offset + 2,
                 static_cast<std::uint16_t>(entry.service_name.size()));
        WriteU32(output, offset + 4, entry.max_concurrent_streams);
        offset += kCapabilityEntryPrefixSize;
        std::copy(entry.service_name.begin(), entry.service_name.end(),
                  output.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += entry.service_name.size();
    }
    return Result<std::vector<std::uint8_t>>::Success(std::move(output));
}

Result<CapabilityManifest> DecodeCapabilityManifest(
    std::span<const std::uint8_t> payload) {
    const Status validation = ValidateCapabilityManifestEncoding(payload);
    if (!validation) {
        return Result<CapabilityManifest>::Failure(validation.code,
                                                   validation.offset);
    }

    CapabilityManifest manifest;
    const std::size_t count = ReadU16(payload, 2);
    manifest.entries.reserve(count);
    std::size_t offset = kCapabilityPrefixSize;
    for (std::size_t i = 0; i < count; ++i) {
        Capability entry;
        entry.service_kind = static_cast<ServiceKind>(payload[offset]);
        const std::size_t name_length = ReadU16(payload, offset + 2);
        entry.max_concurrent_streams = ReadU32(payload, offset + 4);
        offset += kCapabilityEntryPrefixSize;
        entry.service_name.assign(
            reinterpret_cast<const char*>(payload.data() + offset), name_length);
        offset += name_length;
        manifest.entries.push_back(std::move(entry));
    }
    return Result<CapabilityManifest>::Success(std::move(manifest));
}

Result<std::array<std::uint8_t, 4>> EncodeCreditUpdate(
    std::uint32_t increment) noexcept {
    if (increment == 0 || increment > kMaxCreditIncrement) {
        return Result<std::array<std::uint8_t, 4>>::Failure(
            ErrorCode::CreditOutOfRange);
    }
    std::array<std::uint8_t, 4> output{};
    WriteU32(output, 0, increment);
    return Result<std::array<std::uint8_t, 4>>::Success(output);
}

Result<std::uint32_t> DecodeCreditUpdate(
    std::span<const std::uint8_t> payload) noexcept {
    if (payload.size() < 4) {
        return Result<std::uint32_t>::Failure(ErrorCode::Truncated,
                                              payload.size());
    }
    if (payload.size() > 4) {
        return Result<std::uint32_t>::Failure(ErrorCode::TrailingData, 4);
    }
    const std::uint32_t increment = ReadU32(payload, 0);
    if (increment == 0 || increment > kMaxCreditIncrement) {
        return Result<std::uint32_t>::Failure(ErrorCode::CreditOutOfRange);
    }
    return Result<std::uint32_t>::Success(increment);
}

} // namespace yume::ytp1
