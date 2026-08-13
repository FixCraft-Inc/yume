/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/transport/chrome_tls_protocol.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string_view>

namespace yume::client::chrome_tls {
namespace {

constexpr std::array<std::uint8_t, 8> kMagic{
    'Y', 'U', 'M', 'E', 'T', 'L', 'S', 0};
constexpr std::uint16_t kMessageRequest = 1;
constexpr std::uint16_t kMessageReady = 2;
constexpr std::uint16_t kMessageError = 3;
constexpr std::size_t kHeaderBytes = 32;

class Decoder {
public:
    explicit Decoder(std::span<const std::uint8_t> bytes) : bytes_(bytes) {}

    std::span<const std::uint8_t> Take(std::size_t size) {
        if (offset_ > bytes_.size() || size > bytes_.size() - offset_) {
            throw std::runtime_error("truncated Chrome TLS helper IPC message");
        }
        auto result = bytes_.subspan(offset_, size);
        offset_ += size;
        return result;
    }

    std::uint8_t U8() { return Take(1).front(); }

    std::uint16_t U16() {
        const auto value = Take(2);
        return static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(value[0]) << 8U) | value[1]);
    }

    std::uint32_t U32() {
        const auto value = Take(4);
        return (static_cast<std::uint32_t>(value[0]) << 24U) |
               (static_cast<std::uint32_t>(value[1]) << 16U) |
               (static_cast<std::uint32_t>(value[2]) << 8U) |
               static_cast<std::uint32_t>(value[3]);
    }

    std::string String16(std::size_t maximum, std::string_view field) {
        const std::size_t size = U16();
        if (size > maximum) {
            throw std::runtime_error(std::string(field) + " exceeds helper IPC cap");
        }
        const auto value = Take(size);
        return {reinterpret_cast<const char*>(value.data()), value.size()};
    }

    bool Done() const noexcept { return offset_ == bytes_.size(); }

private:
    std::span<const std::uint8_t> bytes_;
    std::size_t offset_{0};
};

void AppendU16(std::vector<std::uint8_t>* output, std::uint16_t value) {
    output->push_back(static_cast<std::uint8_t>(value >> 8U));
    output->push_back(static_cast<std::uint8_t>(value));
}

void AppendU32(std::vector<std::uint8_t>* output, std::uint32_t value) {
    output->push_back(static_cast<std::uint8_t>(value >> 24U));
    output->push_back(static_cast<std::uint8_t>(value >> 16U));
    output->push_back(static_cast<std::uint8_t>(value >> 8U));
    output->push_back(static_cast<std::uint8_t>(value));
}

void AppendString16(std::vector<std::uint8_t>* output,
                    std::string_view value,
                    std::size_t maximum,
                    std::string_view field) {
    if (value.size() > maximum ||
        value.size() > std::numeric_limits<std::uint16_t>::max()) {
        throw std::runtime_error(std::string(field) + " exceeds helper IPC cap");
    }
    AppendU16(output, static_cast<std::uint16_t>(value.size()));
    output->insert(output->end(), value.begin(), value.end());
}

std::vector<std::uint8_t> EncodeMessage(std::uint16_t kind,
                                        const ConnectionId& connection_id,
                                        std::span<const std::uint8_t> payload) {
    if (payload.size() > kMaxPayloadBytes) {
        throw std::runtime_error("Chrome TLS helper IPC payload exceeds cap");
    }
    std::vector<std::uint8_t> output;
    output.reserve(kHeaderBytes + payload.size());
    output.insert(output.end(), kMagic.begin(), kMagic.end());
    AppendU16(&output, kProtocolVersion);
    AppendU16(&output, kind);
    AppendU32(&output, static_cast<std::uint32_t>(payload.size()));
    output.insert(output.end(), connection_id.begin(), connection_id.end());
    output.insert(output.end(), payload.begin(), payload.end());
    return output;
}

struct Header {
    std::uint16_t kind;
    ConnectionId connection_id;
    std::span<const std::uint8_t> payload;
};

Header DecodeHeader(std::span<const std::uint8_t> wire) {
    Decoder decoder(wire);
    const auto magic = decoder.Take(kMagic.size());
    if (!std::equal(magic.begin(), magic.end(), kMagic.begin())) {
        throw std::runtime_error("invalid Chrome TLS helper IPC magic");
    }
    if (decoder.U16() != kProtocolVersion) {
        throw std::runtime_error("Chrome TLS helper IPC version mismatch");
    }
    const std::uint16_t kind = decoder.U16();
    const std::size_t payload_size = decoder.U32();
    if (payload_size > kMaxPayloadBytes) {
        throw std::runtime_error("Chrome TLS helper IPC payload exceeds cap");
    }
    ConnectionId connection_id{};
    const auto id = decoder.Take(connection_id.size());
    std::copy(id.begin(), id.end(), connection_id.begin());
    const auto payload = decoder.Take(payload_size);
    if (!decoder.Done()) {
        throw std::runtime_error("trailing Chrome TLS helper IPC bytes");
    }
    return {kind, connection_id, payload};
}

template <std::size_t Size>
std::array<std::uint8_t, Size> DecodeArray(Decoder* decoder) {
    std::array<std::uint8_t, Size> output{};
    const auto value = decoder->Take(Size);
    std::copy(value.begin(), value.end(), output.begin());
    return output;
}

}  // namespace

std::vector<std::uint8_t> EncodeRequest(const Request& request) {
    if (request.expected_build_id.empty()) {
        throw std::runtime_error("helper build ID must not be empty");
    }
    if (request.server_name.empty() || request.server_name.size() > 253) {
        throw std::runtime_error("TLS server name must contain 1..253 bytes");
    }
    if (!request.leaf_pin.empty() && request.leaf_pin.size() != kSha256Bytes) {
        throw std::runtime_error("TLS leaf pin must be empty or 32 bytes");
    }
    if (request.timeout_ms < 1000 || request.timeout_ms > 120000) {
        throw std::runtime_error("TLS handshake timeout must be in 1000..120000 ms");
    }
    std::vector<std::uint8_t> payload;
    AppendString16(&payload, request.expected_build_id, 256, "helper build ID");
    AppendString16(&payload, request.server_name, 253, "TLS server name");
    AppendString16(&payload, request.ca_path, 4096, "custom CA path");
    payload.push_back(static_cast<std::uint8_t>(request.leaf_pin.size()));
    payload.insert(payload.end(), request.leaf_pin.begin(), request.leaf_pin.end());
    AppendU32(&payload, request.timeout_ms);
    return EncodeMessage(kMessageRequest, request.connection_id, payload);
}

Request DecodeRequest(std::span<const std::uint8_t> wire) {
    const Header header = DecodeHeader(wire);
    if (header.kind != kMessageRequest) {
        throw std::runtime_error("unexpected Chrome TLS helper IPC request type");
    }
    Decoder decoder(header.payload);
    Request request;
    request.connection_id = header.connection_id;
    request.expected_build_id = decoder.String16(256, "helper build ID");
    request.server_name = decoder.String16(253, "TLS server name");
    request.ca_path = decoder.String16(4096, "custom CA path");
    const std::size_t pin_size = decoder.U8();
    if (pin_size != 0 && pin_size != kSha256Bytes) {
        throw std::runtime_error("TLS leaf pin must be empty or 32 bytes");
    }
    const auto pin = decoder.Take(pin_size);
    request.leaf_pin.assign(pin.begin(), pin.end());
    request.timeout_ms = decoder.U32();
    if (!decoder.Done()) {
        throw std::runtime_error("trailing Chrome TLS helper request bytes");
    }
    // Reuse the encoder's complete semantic validation.
    (void)EncodeRequest(request);
    return request;
}

std::vector<std::uint8_t> EncodeReady(const Ready& ready) {
    std::vector<std::uint8_t> payload;
    AppendString16(&payload, ready.build_id, 256, "helper build ID");
    AppendString16(&payload, ready.alpn, 255, "ALPN");
    payload.insert(payload.end(), ready.leaf_fingerprint.begin(),
                   ready.leaf_fingerprint.end());
    payload.insert(payload.end(), ready.exporter.begin(), ready.exporter.end());
    return EncodeMessage(kMessageReady, ready.connection_id, payload);
}

std::vector<std::uint8_t> EncodeError(const HelperError& error) {
    std::vector<std::uint8_t> payload;
    AppendU16(&payload, error.code);
    AppendString16(&payload, error.message, 1024, "helper error");
    return EncodeMessage(kMessageError, error.connection_id, payload);
}

Response DecodeResponse(std::span<const std::uint8_t> wire,
                        const ConnectionId& expected_connection_id,
                        std::string_view expected_build_id) {
    if (expected_build_id.empty() || expected_build_id.size() > 256) {
        throw std::runtime_error("expected helper build ID is invalid");
    }
    const Header header = DecodeHeader(wire);
    if (header.connection_id != expected_connection_id) {
        throw std::runtime_error("Chrome TLS helper connection ID mismatch");
    }
    Decoder decoder(header.payload);
    Response response;
    if (header.kind == kMessageReady) {
        response.kind = ResponseKind::Ready;
        response.ready.connection_id = header.connection_id;
        response.ready.build_id = decoder.String16(256, "helper build ID");
        response.ready.alpn = decoder.String16(255, "ALPN");
        response.ready.leaf_fingerprint = DecodeArray<kSha256Bytes>(&decoder);
        response.ready.exporter = DecodeArray<kExporterBytes>(&decoder);
        if (response.ready.build_id != expected_build_id) {
            throw std::runtime_error("Chrome TLS helper build identity mismatch");
        }
        if (response.ready.alpn != "h2") {
            throw std::runtime_error("Chrome TLS helper did not negotiate h2");
        }
    } else if (header.kind == kMessageError) {
        response.kind = ResponseKind::Error;
        response.error.connection_id = header.connection_id;
        response.error.code = decoder.U16();
        response.error.message = decoder.String16(1024, "helper error");
    } else {
        throw std::runtime_error("unexpected Chrome TLS helper IPC response type");
    }
    if (!decoder.Done()) {
        throw std::runtime_error("trailing Chrome TLS helper response bytes");
    }
    return response;
}

}  // namespace yume::client::chrome_tls
