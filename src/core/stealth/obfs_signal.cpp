/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/stealth/obfs_signal.hpp"

#include "core/version.hpp"

#include <openssl/crypto.h>

#include <cstdio>
#include <ctime>
#include <algorithm>
#include <charconv>
#include <cctype>
#include <optional>
#include <system_error>

#include <boost/asio/ip/address.hpp>

namespace yume::obfs {

namespace {

constexpr char kHexDigits[] = "0123456789abcdef";
constexpr std::int64_t kHourSeconds = 3600;

struct ParsedAuthority {
    std::string host;
    std::optional<std::uint16_t> port;
};

bool is_hex(unsigned char ch) {
    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
}

void append_u16(crypto::Bytes& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xffU));
    out.push_back(static_cast<std::uint8_t>(value & 0xffU));
}

void append_u64(crypto::Bytes& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffU));
    }
}

std::optional<crypto::Bytes> decode_lower_hex(std::string_view text) {
    if ((text.size() & 1U) != 0 || !std::all_of(text.begin(), text.end(), is_hex)) {
        return std::nullopt;
    }
    auto nibble = [](char ch) -> std::uint8_t {
        return ch <= '9' ? static_cast<std::uint8_t>(ch - '0')
                         : static_cast<std::uint8_t>(ch - 'a' + 10);
    };
    crypto::Bytes out(text.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<std::uint8_t>((nibble(text[2 * i]) << 4) |
                                           nibble(text[2 * i + 1]));
    }
    return out;
}

std::optional<std::uint16_t> parse_port(std::string_view text) {
    if (text.empty()) {
        return std::nullopt;
    }
    std::uint32_t port = 0;
    const char* begin = text.data();
    const char* end = begin + text.size();
    const auto [ptr, ec] = std::from_chars(begin, end, port);
    if (ec != std::errc{} || ptr != end || port == 0 || port > 65535) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(port);
}

std::optional<std::string> normalized_authority_host(std::string_view host,
                                                     bool require_ipv6_literal) {
    if (host.empty() || std::any_of(host.begin(), host.end(), [](unsigned char ch) {
            return ch <= 0x20 || ch == 0x7f || ch == '/' || ch == '@';
        })) {
        return std::nullopt;
    }
    std::string normalized(host);
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    while (normalized.size() > 1 && normalized.back() == '.') {
        normalized.pop_back();
    }
    if (require_ipv6_literal) {
        boost::system::error_code ec;
        const auto address = boost::asio::ip::make_address(normalized, ec);
        if (ec || !address.is_v6()) {
            return std::nullopt;
        }
        normalized = address.to_string();
    }
    return normalized;
}

std::optional<ParsedAuthority> parse_authority(std::string_view authority,
                                               bool allow_unbracketed_ipv6) {
    if (authority.empty()) {
        return std::nullopt;
    }

    std::string_view host = authority;
    bool require_ipv6_literal = false;
    std::optional<std::uint16_t> port;
    if (authority.front() == '[') {
        const auto close = authority.find(']');
        if (close == std::string_view::npos) {
            return std::nullopt;
        }
        host = authority.substr(1, close - 1);
        require_ipv6_literal = true;
        const auto suffix = authority.substr(close + 1);
        if (!suffix.empty()) {
            if (suffix.front() != ':') {
                return std::nullopt;
            }
            port = parse_port(suffix.substr(1));
            if (!port.has_value()) {
                return std::nullopt;
            }
        }
    } else {
        const auto first_colon = authority.find(':');
        const auto last_colon = authority.rfind(':');
        if (first_colon != std::string_view::npos && first_colon == last_colon) {
            port = parse_port(authority.substr(first_colon + 1));
            if (!port.has_value()) {
                return std::nullopt;
            }
            host = authority.substr(0, first_colon);
        } else if (first_colon != std::string_view::npos) {
            if (!allow_unbracketed_ipv6) {
                return std::nullopt;
            }
            require_ipv6_literal = true;
        }
    }

    auto normalized = normalized_authority_host(host, require_ipv6_literal);
    if (!normalized.has_value()) {
        return std::nullopt;
    }
    return ParsedAuthority{std::move(*normalized), port};
}

std::string to_hex(const std::uint8_t* data, std::size_t len) {
    std::string out;
    out.resize(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out[2 * i]     = kHexDigits[(data[i] >> 4) & 0x0F];
        out[2 * i + 1] = kHexDigits[data[i] & 0x0F];
    }
    return out;
}

}  // namespace

crypto::Bytes derive_signal_key(std::string_view secret) {
    return crypto::Bytes(secret.begin(), secret.end());
}

std::string derive_path_token(const crypto::Bytes& signal_key,
                              std::string_view sni,
                              std::int64_t hour_epoch,
                              std::string_view nonce_hex) {
    const auto nonce = decode_lower_hex(nonce_hex);
    auto normalized_sni = normalized_authority_host(sni, false);
    if (signal_key.empty() || !normalized_sni.has_value() ||
        !nonce.has_value() || nonce->size() != kH2NonceHexLen / 2) {
        return {};
    }
    crypto::Bytes msg;
    msg.reserve(yume::kTransportVersion.size() + normalized_sni->size() +
                nonce->size() + 20);
    append_u16(msg, static_cast<std::uint16_t>(yume::kTransportVersion.size()));
    msg.insert(msg.end(), yume::kTransportVersion.begin(),
               yume::kTransportVersion.end());
    append_u16(msg, static_cast<std::uint16_t>(normalized_sni->size()));
    msg.insert(msg.end(), normalized_sni->begin(), normalized_sni->end());
    append_u64(msg, static_cast<std::uint64_t>(hour_epoch));
    msg.insert(msg.end(), nonce->begin(), nonce->end());
    crypto::Bytes mac = crypto::hmac_sha256(msg, signal_key);
    return to_hex(mac.data(), mac.size());
}

std::string build_path(const std::string& token, const std::string& nonce_hex) {
    std::string path;
    path.reserve(kH2PathLen);
    path.push_back('/');
    path.append(token);
    path.push_back('/');
    path.append(nonce_hex);
    return path;
}

bool valid_path_shape(std::string_view path) {
    if (path.size() != kH2PathLen ||
        path.front() != '/' ||
        path[1 + kH2TokenHexLen] != '/') {
        return false;
    }
    const auto token = path.substr(1, kH2TokenHexLen);
    const auto nonce = path.substr(2 + kH2TokenHexLen, kH2NonceHexLen);
    return std::all_of(token.begin(), token.end(), is_hex) &&
           std::all_of(nonce.begin(), nonce.end(), is_hex);
}

bool authority_matches_tls_sni(std::string_view authority,
                               std::string_view tls_sni,
                               std::optional<std::uint16_t> listener_port) {
    const auto parsed_authority = parse_authority(authority, false);
    const auto parsed_sni = parse_authority(tls_sni, true);
    if (!parsed_authority.has_value() || !parsed_sni.has_value() ||
        parsed_authority->host != parsed_sni->host) {
        return false;
    }
    if (listener_port.has_value()) {
        if (parsed_authority->port.has_value() &&
            parsed_authority->port != listener_port) {
            return false;
        }
        if (parsed_sni->port.has_value() &&
            parsed_sni->port != listener_port) {
            return false;
        }
    }
    return true;
}

bool carrier_path_admitted(const crypto::Bytes& secret,
                           std::string_view authority,
                           std::string_view tls_sni,
                           std::string_view path,
                           std::int64_t now_seconds,
                           std::optional<std::uint16_t> listener_port) {
    if (!authority_matches_tls_sni(authority, tls_sni, listener_port) ||
        !valid_path_shape(path)) {
        return false;
    }
    if (secret.empty()) return false;
    return verify_path_token({secret}, tls_sni, path, now_seconds);
}

bool verify_path_token(const std::vector<crypto::Bytes>& signal_keys,
                       std::string_view sni,
                       std::string_view path,
                       std::int64_t now_seconds) {
    if (!valid_path_shape(path) || signal_keys.empty() || sni.empty()) {
        return false;
    }
    std::string_view received_token = path.substr(1, kH2TokenHexLen);
    std::string_view nonce = path.substr(2 + kH2TokenHexLen, kH2NonceHexLen);
    std::int64_t hour = now_seconds / kHourSeconds;
    int matched = 0;
    for (std::int64_t bucket : {hour - 1, hour}) {
        for (const auto& key : signal_keys) {
            std::string expected = derive_path_token(key, sni, bucket, nonce);
            if (expected.size() == received_token.size() &&
                CRYPTO_memcmp(expected.data(), received_token.data(), expected.size()) == 0) {
                matched = 1;
            }
        }
    }
    return matched == 1;
}

std::string random_nonce_hex() {
    crypto::Bytes raw = crypto::random_bytes(kH2NonceHexLen / 2);
    return to_hex(raw.data(), raw.size());
}

AdmissionReplayCache::AdmissionReplayCache(std::size_t max_entries,
                                           std::int64_t ttl_seconds)
    : max_entries_(std::max<std::size_t>(1, max_entries)),
      ttl_seconds_(std::max<std::int64_t>(1, ttl_seconds)) {}

bool AdmissionReplayCache::AcceptPath(std::string_view path,
                                      std::int64_t now_seconds) {
    if (!valid_path_shape(path)) return false;
    const std::string nonce(path.substr(2 + kH2TokenHexLen, kH2NonceHexLen));
    std::lock_guard<std::mutex> lock(mutex_);
    Evict(now_seconds);
    const auto found = expiry_by_nonce_.find(nonce);
    if (found != expiry_by_nonce_.end() && found->second > now_seconds) {
        return false;
    }
    const std::int64_t expiry = now_seconds + ttl_seconds_;
    expiry_by_nonce_[nonce] = expiry;
    expiry_order_.emplace_back(nonce, expiry);
    while (expiry_by_nonce_.size() > max_entries_ && !expiry_order_.empty()) {
        const auto oldest = std::move(expiry_order_.front());
        expiry_order_.pop_front();
        const auto it = expiry_by_nonce_.find(oldest.first);
        if (it != expiry_by_nonce_.end() && it->second == oldest.second) {
            expiry_by_nonce_.erase(it);
        }
    }
    return true;
}

std::size_t AdmissionReplayCache::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return expiry_by_nonce_.size();
}

void AdmissionReplayCache::Evict(std::int64_t now_seconds) {
    while (!expiry_order_.empty() && expiry_order_.front().second <= now_seconds) {
        const auto oldest = std::move(expiry_order_.front());
        expiry_order_.pop_front();
        const auto it = expiry_by_nonce_.find(oldest.first);
        if (it != expiry_by_nonce_.end() && it->second == oldest.second) {
            expiry_by_nonce_.erase(it);
        }
    }
}

}  // namespace yume::obfs
