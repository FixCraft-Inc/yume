/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yume::client::chrome_tls {

inline constexpr std::uint16_t kProtocolVersion = 1;
inline constexpr std::size_t kConnectionIdBytes = 16;
inline constexpr std::size_t kSha256Bytes = 32;
inline constexpr std::size_t kExporterBytes = 32;
inline constexpr std::size_t kMaxPayloadBytes = 64U * 1024U;
inline constexpr std::string_view kBuildId =
    "yume-chrome151-utls-v1.8.2-ipc-v1";

using ConnectionId = std::array<std::uint8_t, kConnectionIdBytes>;
using Sha256 = std::array<std::uint8_t, kSha256Bytes>;
using Exporter = std::array<std::uint8_t, kExporterBytes>;

struct Request {
    ConnectionId connection_id{};
    std::string expected_build_id{std::string(kBuildId)};
    std::string server_name;
    std::string ca_path;
    std::vector<std::uint8_t> leaf_pin;
    std::uint32_t timeout_ms{12000};
};

struct Ready {
    ConnectionId connection_id{};
    std::string build_id;
    std::string alpn;
    Sha256 leaf_fingerprint{};
    Exporter exporter{};
};

struct HelperError {
    ConnectionId connection_id{};
    std::uint16_t code{0};
    std::string message;
};

enum class ResponseKind {
    Ready,
    Error,
};

struct Response {
    ResponseKind kind{ResponseKind::Error};
    Ready ready;
    HelperError error;
};

std::vector<std::uint8_t> EncodeRequest(const Request& request);
Request DecodeRequest(std::span<const std::uint8_t> wire);
Response DecodeResponse(std::span<const std::uint8_t> wire,
                        const ConnectionId& expected_connection_id);

// Test/support encoders also document the wire format independently of the Go
// helper. Production parent code only sends Request and decodes Response.
std::vector<std::uint8_t> EncodeReady(const Ready& ready);
std::vector<std::uint8_t> EncodeError(const HelperError& error);

}  // namespace yume::client::chrome_tls
