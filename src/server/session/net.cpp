/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * ----------------------------------------------------------------
 * Definitions for the session-private helpers declared in
 * server/session/internal.hpp. These were the free functions of the
 * anonymous namespace formerly at the top of session.cpp; they were
 * promoted to yume::server::detail so the split session_*.cpp TUs can
 * share them. Moved verbatim -- no behavior change.
 * ---------------------------------------------------------------- */

#include "server/session/internal.hpp"

#include "server/runtime/manager.hpp"

namespace yume::server {
namespace detail {

int64_t steady_now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

bool auth_debug_enabled() {
    const char* value = std::getenv("YUME_AUTH_DEBUG");
    if (!value || !*value) {
        return false;
    }
    std::string text(value);
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return text == "1" || text == "true" || text == "yes" || text == "on";
}

bool looks_like_inner_auth_exception(const std::string& message) {
    std::string lower(message);
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return lower.find("pq") != std::string::npos ||
           lower.find("ml-kem") != std::string::npos ||
           lower.find("kem") != std::string::npos ||
           lower.find("oqs") != std::string::npos ||
           lower.find("decapsulation") != std::string::npos ||
           lower.find("inner crypto") != std::string::npos ||
           lower.find("argon2") != std::string::npos ||
           lower.find("kdf") != std::string::npos;
}

bool is_private_ipv4(const boost::asio::ip::address_v4& addr) {
    const auto bytes = addr.to_bytes();
    const uint8_t a = bytes[0];
    const uint8_t b = bytes[1];
    if (a == 10) return true;
    if (a == 127) return true;
    if (a == 0) return true;
    if (a == 169 && b == 254) return true;
    if (a == 172 && (b >= 16 && b <= 31)) return true;
    if (a == 192 && b == 168) return true;
    if (a == 100 && (b >= 64 && b <= 127)) return true;
    if (a == 192 && b == 0) return true;
    if (a == 198 && (b == 18 || b == 19)) return true;
    if (a == 198 && b == 51) return true;
    if (a == 203 && b == 0) return true;
    if (a >= 224) return true;
    return false;
}

bool is_private_ipv6(const boost::asio::ip::address_v6& addr) {
    if (addr.is_loopback() || addr.is_unspecified() || addr.is_multicast()) {
        return true;
    }
    const auto bytes = addr.to_bytes();
    if ((bytes[0] & 0xFE) == 0xFC) {
        return true;
    }
    if (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80) {
        return true;
    }
    if (addr.is_v4_mapped()) {
        boost::asio::ip::address_v4::bytes_type v4bytes{
            {bytes[12], bytes[13], bytes[14], bytes[15]}
        };
        return is_private_ipv4(boost::asio::ip::address_v4(v4bytes));
    }
    return false;
}

bool is_public_address(const boost::asio::ip::address& addr) {
    if (addr.is_v4()) {
        return !is_private_ipv4(addr.to_v4());
    }
    if (addr.is_v6()) {
        return !is_private_ipv6(addr.to_v6());
    }
    return false;
}

bool is_allowed_address(const boost::asio::ip::address& addr, bool allow_local_ip, bool control_full) {
    if (control_full) {
        return true;
    }
    if (is_public_address(addr)) {
        return true;
    }
    return allow_local_ip;
}

bool egress_filter_allows(Manager* manager,
                          const boost::asio::ip::address& address,
                          std::string* reason) {
    if (!manager) {
        return true;
    }
    return manager->egress_allowed(address, reason);
}

bool is_blocked_host_literal(const std::string& host, bool allow_local_ip, bool control_full) {
    if (control_full) {
        return false;
    }
    if ((host == "localhost" || host == "localhost.localdomain") && !allow_local_ip) {
        return true;
    }
    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address(host, ec);
    if (!ec) {
        return !is_allowed_address(addr, allow_local_ip, control_full);
    }
    return false;
}

boost::asio::ip::address canonical_endpoint_address(const boost::asio::ip::address& addr) {
    if (addr.is_v6()) {
        const auto v6 = addr.to_v6();
        if (v6.is_v4_mapped()) {
            const auto bytes = v6.to_bytes();
            boost::asio::ip::address_v4::bytes_type v4bytes{
                {bytes[12], bytes[13], bytes[14], bytes[15]}
            };
            return boost::asio::ip::address_v4(v4bytes);
        }
    }
    return addr;
}

bool addresses_match(const boost::asio::ip::address& lhs, const boost::asio::ip::address& rhs) {
    return canonical_endpoint_address(lhs) == canonical_endpoint_address(rhs);
}

std::optional<boost::asio::ip::address> session_local_address(
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream) {
    boost::system::error_code ec;
    auto local = stream.lowest_layer().local_endpoint(ec);
    if (ec) {
        return std::nullopt;
    }
    return local.address();
}

bool starts_with(std::string_view value, std::string_view prefix) {
    return value.substr(0, prefix.size()) == prefix;
}

bool is_background_probe_close_reason(const std::string& reason) {
    if (reason == "served HTTP disguise response") {
        return true;
    }
    if (reason == "ignored post-TLS HTTP probe") {
        return true;
    }
    if (starts_with(reason, "TLS handshake failed: ")) {
        return true;
    }
    if (starts_with(reason, "preface read failed: ")) {
        return true;
    }
    if (starts_with(reason, "HTTP preface read failed: ")) {
        return true;
    }
    return false;
}

bool is_server_fault_close_reason(const std::string& reason) {
    return starts_with(reason, "AUTH challenge write failed: ") ||
           starts_with(reason, "auth rejection ANON write failed: ") ||
           starts_with(reason, "ANON write failed: ") ||
           starts_with(reason, "write queue overrun");
}

std::string summarize_header_prefix(const std::array<uint8_t, 8>& header) {
    static constexpr char kHexDigits[] = "0123456789abcdef";
    std::string hex;
    hex.reserve((header.size() * 2) + (header.size() - 1));
    for (std::size_t index = 0; index < header.size(); ++index) {
        if (index > 0) {
            hex.push_back(' ');
        }
        const auto byte = header[index];
        hex.push_back(kHexDigits[(byte >> 4) & 0x0F]);
        hex.push_back(kHexDigits[byte & 0x0F]);
    }

    std::string ascii;
    ascii.reserve(header.size());
    for (const auto byte : header) {
        ascii.push_back((byte >= 32 && byte <= 126) ? static_cast<char>(byte) : '.');
    }
    return "header=" + hex + " ascii=" + ascii;
}

bool header_starts_with_ascii(const std::array<uint8_t, 8>& header, std::string_view prefix) {
    if (prefix.size() > header.size()) {
        return false;
    }
    for (std::size_t index = 0; index < prefix.size(); ++index) {
        if (header[index] != static_cast<std::uint8_t>(prefix[index])) {
            return false;
        }
    }
    return true;
}

bool is_http_probe_header(const std::array<uint8_t, 8>& header) {
    return header_starts_with_ascii(header, "GET ") ||
           header_starts_with_ascii(header, "POST ") ||
           header_starts_with_ascii(header, "HEAD ") ||
           header_starts_with_ascii(header, "PUT ") ||
           header_starts_with_ascii(header, "DELETE ") ||
           header_starts_with_ascii(header, "OPTIONS ") ||
           header_starts_with_ascii(header, "CONNECT ") ||
           header_starts_with_ascii(header, "TRACE ") ||
           header_starts_with_ascii(header, "PATCH ") ||
           header_starts_with_ascii(header, "PRI * HT");
}

int random_int_inclusive(int min_value, int max_value) {
    if (min_value >= max_value) {
        return min_value;
    }
    static thread_local std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(min_value, max_value);
    return dist(rng);
}

bool is_expected_close_ec(const boost::system::error_code& ec) {
    return ec == boost::asio::error::eof ||
           ec == boost::asio::error::operation_aborted ||
           ec == boost::asio::ssl::error::stream_truncated;
}

bool is_expected_close_reason(const std::string& reason) {
    return reason == "authentication rejected" ||
           reason == "peer closed the TLS session" ||
           starts_with(reason, "client disconnected before AUTH") ||
           reason == "served HTTP disguise response" ||
           reason == "server closed" ||
           reason == "server closed, kicked" ||
           reason == "session closed";
}

std::string describe_error_code(const boost::system::error_code& ec) {
    std::string description = ec.message();
    const std::string category = ec.category().name();
    if (!category.empty()) {
        description += " [category=" + category + " value=" + std::to_string(ec.value()) + "]";
    }
    return description;
}

bool env_value_enabled(const char* raw) {
    if (!raw || !*raw) {
        return false;
    }
    std::string value(raw);
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value == "1" || value == "true" || value == "yes" || value == "on" ||
           value == "any" || value == "all" || value == "ipv6";
}

bool server_resolve_any_family_enabled() {
    // Default to resolving BOTH A and AAAA records. Pre-fix, this
    // returned false (IPv4-only) and any destination with only AAAA
    // — increasingly common for CDN-hosted services — failed with
    // "DNS response contained no A records", which the SOCKS client
    // surfaces to the browser as REP=0x04 host unreachable.
    //
    // The connect path uses prefer_ipv4_endpoints to sort v4 first,
    // so v4-reachable destinations behave exactly as today; v6 is
    // only attempted when v4 isn't available.
    //
    // Opt-out for operators who explicitly want IPv4-only resolution:
    //   YUME_RESOLVE_FAMILY=ipv4   (also accepts: =v4, =4)
    const char* family = std::getenv("YUME_RESOLVE_FAMILY");
    if (family != nullptr) {
        std::string value(family);
        std::transform(value.begin(), value.end(), value.begin(),
                       [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        if (value == "ipv4" || value == "v4" || value == "4") {
            return false;
        }
    }
    return true;
}

void append_u16(std::vector<uint8_t>* out, std::uint16_t value) {
    out->push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    out->push_back(static_cast<uint8_t>(value & 0xff));
}

std::uint16_t read_u16(const uint8_t* data, std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[offset]) << 8) |
                                      static_cast<std::uint16_t>(data[offset + 1]));
}

bool append_dns_name(std::vector<uint8_t>* out, std::string host) {
    if (!out || host.empty()) {
        return false;
    }
    if (!host.empty() && host.back() == '.') {
        host.pop_back();
    }
    if (host.empty() || host.size() > 253) {
        return false;
    }
    std::size_t start = 0;
    while (start < host.size()) {
        const std::size_t dot = host.find('.', start);
        const std::size_t end = dot == std::string::npos ? host.size() : dot;
        const std::size_t label_len = end - start;
        if (label_len == 0 || label_len > 63) {
            return false;
        }
        out->push_back(static_cast<uint8_t>(label_len));
        out->insert(out->end(), host.begin() + static_cast<std::ptrdiff_t>(start),
                    host.begin() + static_cast<std::ptrdiff_t>(end));
        if (dot == std::string::npos) {
            break;
        }
        start = dot + 1;
    }
    out->push_back(0);
    return true;
}

bool skip_dns_name(const uint8_t* data, std::size_t len, std::size_t* offset) {
    if (!data || !offset) {
        return false;
    }
    std::size_t pos = *offset;
    for (int depth = 0; depth < 128; ++depth) {
        if (pos >= len) {
            return false;
        }
        const uint8_t label_len = data[pos++];
        if ((label_len & 0xc0) == 0xc0) {
            if (pos >= len) {
                return false;
            }
            ++pos;
            *offset = pos;
            return true;
        }
        if ((label_len & 0xc0) != 0) {
            return false;
        }
        if (label_len == 0) {
            *offset = pos;
            return true;
        }
        if (pos + label_len > len) {
            return false;
        }
        pos += label_len;
    }
    return false;
}

bool parse_dns_a_response(const uint8_t* data,
                          std::size_t len,
                          std::uint16_t expected_id,
                          std::vector<boost::asio::ip::address_v4>* out,
                          std::string* error) {
    if (!data || len < 12 || !out) {
        if (error) {
            *error = "short DNS response";
        }
        return false;
    }
    if (read_u16(data, 0) != expected_id) {
        if (error) {
            *error = "DNS response id mismatch";
        }
        return false;
    }
    const std::uint16_t flags = read_u16(data, 2);
    if ((flags & 0x8000) == 0) {
        if (error) {
            *error = "not a DNS response";
        }
        return false;
    }
    const std::uint16_t rcode = static_cast<std::uint16_t>(flags & 0x000f);
    if (rcode != 0) {
        if (error) {
            *error = "DNS rcode " + std::to_string(rcode);
        }
        return false;
    }
    const std::uint16_t qdcount = read_u16(data, 4);
    const std::uint16_t ancount = read_u16(data, 6);
    std::size_t offset = 12;
    for (std::uint16_t i = 0; i < qdcount; ++i) {
        if (!skip_dns_name(data, len, &offset) || offset + 4 > len) {
            if (error) {
                *error = "bad DNS question";
            }
            return false;
        }
        offset += 4;
    }
    for (std::uint16_t i = 0; i < ancount; ++i) {
        if (!skip_dns_name(data, len, &offset) || offset + 10 > len) {
            if (error) {
                *error = "bad DNS answer";
            }
            return false;
        }
        const std::uint16_t type = read_u16(data, offset);
        const std::uint16_t klass = read_u16(data, offset + 2);
        const std::uint16_t rdlen = read_u16(data, offset + 8);
        offset += 10;
        if (offset + rdlen > len) {
            if (error) {
                *error = "bad DNS rdata";
            }
            return false;
        }
        if (type == 1 && klass == 1 && rdlen == 4) {
            boost::asio::ip::address_v4::bytes_type bytes{
                {data[offset], data[offset + 1], data[offset + 2], data[offset + 3]}
            };
            out->push_back(boost::asio::ip::address_v4(bytes));
        }
        offset += rdlen;
    }
    if (out->empty()) {
        if (error) {
            *error = "DNS response contained no A records";
        }
        return false;
    }
    return true;
}

std::uint32_t read_ipv4_be(const std::vector<uint8_t>& packet, std::size_t offset) {
    return (static_cast<std::uint32_t>(packet[offset]) << 24) |
           (static_cast<std::uint32_t>(packet[offset + 1]) << 16) |
           (static_cast<std::uint32_t>(packet[offset + 2]) << 8) |
           static_cast<std::uint32_t>(packet[offset + 3]);
}

bool validate_client_ipv4_packet(const std::vector<uint8_t>& packet,
                                 std::uint32_t expected_source_be,
                                 std::string* reason) {
    auto fail = [&](const std::string& message) {
        if (reason) {
            *reason = message;
        }
        return false;
    };
    if (packet.size() < 20) {
        return fail("short IPv4 packet");
    }
    const auto version = static_cast<std::uint8_t>(packet[0] >> 4);
    if (version != 4) {
        return fail(version == 6 ? "IPv6 packet not supported in packet_bulk_v1" : "not an IPv4 packet");
    }
    const std::size_t ihl = static_cast<std::size_t>(packet[0] & 0x0f) * 4;
    if (ihl < 20 || ihl > packet.size()) {
        return fail("invalid IPv4 header length");
    }
    const std::size_t total_len = read_u16(packet.data(), 2);
    if (total_len != packet.size() || total_len < ihl) {
        return fail("invalid IPv4 total length");
    }
    if (read_ipv4_be(packet, 12) != expected_source_be) {
        return fail("packet source IPv4 does not match assigned tunnel address");
    }
    return true;
}

}  // namespace detail
}  // namespace yume::server
