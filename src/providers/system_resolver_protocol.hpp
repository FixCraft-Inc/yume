/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

// Private message format between SystemResolver and its helper process over a
// SOCK_SEQPACKET socketpair. Both ends come from one build, and a version
// mismatch fails closed. Nothing here is a network or persistent format.
// Every message fits one datagram, so a truncated receive is a violation.
namespace yume::providers::resolver_protocol {

inline constexpr std::uint8_t kVersion = 1U;
// The helper's descriptor for the socketpair. posix_spawn places it here.
inline constexpr int kHelperDescriptor = 3;
// argv[0] selecting helper mode in a program that also has another role.
inline constexpr std::string_view kHelperArgv0 = "yume-resolver";
inline constexpr std::size_t kMaxHostBytes = 253U;
inline constexpr std::size_t kMaxAddresses = 32U;
// Lookups the helper runs at once. Each has its own thread there, so a
// stalled system lookup occupies only its own slot until the helper is
// replaced.
inline constexpr std::size_t kMaxOutstanding = 64U;

enum class MessageType : std::uint8_t {
    Hello = 1U,
    Request = 2U,
    Response = 3U,
};

enum class LookupStatus : std::uint8_t {
    Ok = 0U,
    NotFound = 1U,
    TemporaryFailure = 2U,
    Failure = 3U,
    Busy = 4U,
};

struct Address final {
    // 4 or 6. An IPv4 address uses the first four bytes.
    std::uint8_t family{0U};
    std::array<std::uint8_t, 16U> bytes{};
    std::uint32_t scope_id{0U};
};

inline constexpr std::size_t kHelloBytes = 8U;
inline constexpr std::size_t kRequestHeaderBytes = 8U;
inline constexpr std::size_t kMaxRequestBytes = kRequestHeaderBytes + kMaxHostBytes;
inline constexpr std::size_t kResponseHeaderBytes = 8U;
inline constexpr std::size_t kAddressBytes = 21U;
inline constexpr std::size_t kMaxResponseBytes =
    kResponseHeaderBytes + kMaxAddresses * kAddressBytes;

namespace detail {
inline void put_u32(std::uint8_t* out, std::uint32_t value) noexcept {
    out[0] = static_cast<std::uint8_t>(value >> 24U);
    out[1] = static_cast<std::uint8_t>(value >> 16U);
    out[2] = static_cast<std::uint8_t>(value >> 8U);
    out[3] = static_cast<std::uint8_t>(value);
}
inline std::uint32_t get_u32(const std::uint8_t* in) noexcept {
    return (static_cast<std::uint32_t>(in[0]) << 24U) |
           (static_cast<std::uint32_t>(in[1]) << 16U) |
           (static_cast<std::uint32_t>(in[2]) << 8U) |
           static_cast<std::uint32_t>(in[3]);
}
}  // namespace detail

// A host is bounded printable ASCII without spaces. getaddrinfo applies the
// system's own name policy. This check only keeps the message unambiguous.
inline bool valid_host(std::string_view host) noexcept {
    if (host.empty() || host.size() > kMaxHostBytes) return false;
    return std::all_of(host.begin(), host.end(), [](char character) {
        const auto byte = static_cast<unsigned char>(character);
        return byte > 0x20U && byte < 0x7fU;
    });
}

inline std::array<std::uint8_t, kHelloBytes> encode_hello() noexcept {
    std::array<std::uint8_t, kHelloBytes> out{};
    out[0] = 'Y';
    out[1] = 'R';
    out[2] = kVersion;
    out[3] = static_cast<std::uint8_t>(MessageType::Hello);
    detail::put_u32(out.data() + 4U, static_cast<std::uint32_t>(kMaxOutstanding));
    return out;
}

inline bool valid_hello(std::span<const std::uint8_t> message) noexcept {
    const auto expected = encode_hello();
    return message.size() == expected.size() &&
           std::equal(message.begin(), message.end(), expected.begin());
}

struct Request final {
    std::uint32_t id{0U};
    std::uint8_t max_addresses{0U};
    std::string_view host;
};

// Returns the encoded length, or zero for an invalid request.
inline std::size_t encode_request(const Request& request,
                                  std::span<std::uint8_t, kMaxRequestBytes> out) noexcept {
    if (request.id == 0U || request.max_addresses == 0U ||
        request.max_addresses > kMaxAddresses || !valid_host(request.host)) {
        return 0U;
    }
    out[0] = kVersion;
    out[1] = static_cast<std::uint8_t>(MessageType::Request);
    out[2] = request.max_addresses;
    out[3] = static_cast<std::uint8_t>(request.host.size());
    detail::put_u32(out.data() + 4U, request.id);
    std::copy(request.host.begin(), request.host.end(), out.begin() + kRequestHeaderBytes);
    return kRequestHeaderBytes + request.host.size();
}

// The returned host is a view into the message.
inline std::optional<Request> decode_request(std::span<const std::uint8_t> message) noexcept {
    if (message.size() <= kRequestHeaderBytes ||
        message[0] != kVersion ||
        message[1] != static_cast<std::uint8_t>(MessageType::Request) ||
        message[2] == 0U || message[2] > kMaxAddresses ||
        message.size() != kRequestHeaderBytes + message[3]) {
        return std::nullopt;
    }
    Request request;
    request.max_addresses = message[2];
    request.id = detail::get_u32(message.data() + 4U);
    request.host = std::string_view(
        reinterpret_cast<const char*>(message.data() + kRequestHeaderBytes), message[3]);
    if (request.id == 0U || !valid_host(request.host)) return std::nullopt;
    return request;
}

struct Response final {
    std::uint32_t id{0U};
    LookupStatus status{LookupStatus::Failure};
    std::uint8_t count{0U};
    std::array<Address, kMaxAddresses> addresses{};
};

// Returns the encoded length, or zero for an invalid response.
inline std::size_t encode_response(const Response& response,
                                   std::span<std::uint8_t, kMaxResponseBytes> out) noexcept {
    if (response.id == 0U || response.count > kMaxAddresses ||
        (response.status != LookupStatus::Ok && response.count != 0U)) {
        return 0U;
    }
    out[0] = kVersion;
    out[1] = static_cast<std::uint8_t>(MessageType::Response);
    out[2] = static_cast<std::uint8_t>(response.status);
    out[3] = response.count;
    detail::put_u32(out.data() + 4U, response.id);
    std::uint8_t* cursor = out.data() + kResponseHeaderBytes;
    for (std::size_t index = 0; index < response.count; ++index) {
        const Address& address = response.addresses[index];
        if (address.family != 4U && address.family != 6U) return 0U;
        cursor[0] = address.family;
        std::copy(address.bytes.begin(), address.bytes.end(), cursor + 1U);
        detail::put_u32(cursor + 17U, address.scope_id);
        cursor += kAddressBytes;
    }
    return kResponseHeaderBytes + response.count * kAddressBytes;
}

// Validates framing, status, count and every address. An IPv4 entry must
// have zero padding and scope, so every value has exactly one encoding.
inline std::optional<Response> decode_response(std::span<const std::uint8_t> message) noexcept {
    if (message.size() < kResponseHeaderBytes ||
        message[0] != kVersion ||
        message[1] != static_cast<std::uint8_t>(MessageType::Response) ||
        message[2] > static_cast<std::uint8_t>(LookupStatus::Busy) ||
        message[3] > kMaxAddresses ||
        message.size() != kResponseHeaderBytes + message[3] * kAddressBytes) {
        return std::nullopt;
    }
    Response response;
    response.status = static_cast<LookupStatus>(message[2]);
    response.count = message[3];
    response.id = detail::get_u32(message.data() + 4U);
    if (response.id == 0U ||
        (response.status != LookupStatus::Ok && response.count != 0U)) {
        return std::nullopt;
    }
    const std::uint8_t* cursor = message.data() + kResponseHeaderBytes;
    for (std::size_t index = 0; index < response.count; ++index) {
        Address& address = response.addresses[index];
        address.family = cursor[0];
        std::copy(cursor + 1U, cursor + 17U, address.bytes.begin());
        address.scope_id = detail::get_u32(cursor + 17U);
        const bool canonical_ipv4 = address.family == 4U && address.scope_id == 0U &&
            std::all_of(address.bytes.begin() + 4, address.bytes.end(),
                        [](std::uint8_t byte) { return byte == 0U; });
        if (!canonical_ipv4 && address.family != 6U) return std::nullopt;
        cursor += kAddressBytes;
    }
    return response;
}

}  // namespace yume::providers::resolver_protocol
