/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/stealth/obfs_signal.hpp"

#include <openssl/crypto.h>

#include <cstdio>
#include <ctime>
#include <algorithm>
#include <cctype>

namespace yume::obfs {

namespace {

constexpr char kHexDigits[] = "0123456789abcdef";
constexpr std::int64_t kHourSeconds = 3600;

bool is_hex(unsigned char ch) {
    return (ch >= '0' && ch <= '9') ||
           (ch >= 'a' && ch <= 'f') ||
           (ch >= 'A' && ch <= 'F');
}

std::string normalized_authority_host(std::string_view authority) {
    if (authority.empty()) {
        return {};
    }

    std::string_view host = authority;
    if (authority.front() == '[') {
        const auto close = authority.find(']');
        if (close == std::string_view::npos) {
            return {};
        }
        host = authority.substr(1, close - 1);
        const auto suffix = authority.substr(close + 1);
        if (!suffix.empty() && suffix.front() != ':') {
            return {};
        }
    } else {
        const auto first_colon = authority.find(':');
        const auto last_colon = authority.rfind(':');
        if (first_colon != std::string_view::npos && first_colon == last_colon) {
            const auto port = authority.substr(first_colon + 1);
            if (port.empty() || !std::all_of(port.begin(), port.end(), [](unsigned char ch) {
                    return ch >= '0' && ch <= '9';
                })) {
                return {};
            }
            host = authority.substr(0, first_colon);
        }
    }

    if (host.empty() || std::any_of(host.begin(), host.end(), [](unsigned char ch) {
            return ch <= 0x20 || ch == 0x7f || ch == '/' || ch == '@';
        })) {
        return {};
    }
    std::string normalized(host);
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    while (normalized.size() > 1 && normalized.back() == '.') {
        normalized.pop_back();
    }
    return normalized;
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
    crypto::Bytes ikm(secret.begin(), secret.end());
    if (ikm.empty()) {
        ikm.push_back(0);
    }
    crypto::Bytes salt{'y', 'u', 'm', 'e', '-', 'o', 'b', 'f', 's', '-', 'p', 'a', 't', 'h'};
    return crypto::hkdf_sha256(ikm, "yume-obfs-v2-K", 32, salt);
}

std::string derive_path_token(const crypto::Bytes& signal_key,
                              std::string_view sni,
                              std::int64_t hour_epoch) {
    crypto::Bytes msg;
    msg.reserve(sni.size() + 32);
    msg.insert(msg.end(), sni.begin(), sni.end());
    msg.push_back('|');
    char hour_buf[32];
    int n = std::snprintf(hour_buf, sizeof(hour_buf), "%lld", static_cast<long long>(hour_epoch));
    if (n > 0) {
        msg.insert(msg.end(), hour_buf, hour_buf + n);
    }
    msg.push_back('|');
    static const char kInfo[] = "yume-obfs-v2";
    msg.insert(msg.end(), kInfo, kInfo + sizeof(kInfo) - 1);
    crypto::Bytes mac = crypto::hmac_sha256(msg, signal_key);
    return to_hex(mac.data(), 16);
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
                               std::string_view tls_sni) {
    const std::string authority_host = normalized_authority_host(authority);
    const std::string sni_host = normalized_authority_host(tls_sni);
    return !authority_host.empty() && authority_host == sni_host;
}

bool carrier_path_admitted(std::string_view secret,
                           std::string_view authority,
                           std::string_view tls_sni,
                           std::string_view path,
                           std::int64_t now_seconds) {
    if (!authority_matches_tls_sni(authority, tls_sni) ||
        !valid_path_shape(path)) {
        return false;
    }
    if (secret.empty()) {
        return true;
    }
    const crypto::Bytes signal_key = derive_signal_key(secret);
    return verify_path_token({signal_key}, tls_sni, path, now_seconds);
}

bool verify_path_token(const std::vector<crypto::Bytes>& signal_keys,
                       std::string_view sni,
                       std::string_view path,
                       std::int64_t now_seconds) {
    if (!valid_path_shape(path) || signal_keys.empty() || sni.empty()) {
        return false;
    }
    std::string_view received_token = path.substr(1, kH2TokenHexLen);
    std::int64_t hour = now_seconds / kHourSeconds;
    int matched = 0;
    for (std::int64_t bucket : {hour - 1, hour, hour + 1}) {
        for (const auto& key : signal_keys) {
            std::string expected = derive_path_token(key, sni, bucket);
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

}  // namespace yume::obfs
