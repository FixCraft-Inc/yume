/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/stealth/obfs_signal.hpp"

#include "core/version.hpp"

#include <openssl/crypto.h>

#include <algorithm>
#include <chrono>
#include <limits>
#include <optional>

namespace yume::obfs {

namespace {

constexpr std::int64_t kHourSeconds = 3600;

void append_u16(crypto::Bytes& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xffU));
    out.push_back(static_cast<std::uint8_t>(value & 0xffU));
}

void append_u64(crypto::Bytes& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffU));
    }
}

std::uint64_t monotonic_seconds() noexcept {
    const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return elapsed < 0 ? 0U : static_cast<std::uint64_t>(elapsed);
}

}  // namespace

crypto::Bytes derive_signal_key(std::string_view secret) {
    return crypto::Bytes(secret.begin(), secret.end());
}

std::string derive_path_token(const crypto::Bytes& signal_key,
                              std::string_view sni,
                              std::int64_t hour_epoch,
                              std::string_view nonce_hex) {
    const auto nonce = admission::parse_nonce_hex(nonce_hex);
    auto normalized_sni = admission::normalize_server_name(sni);
    if (signal_key.empty() || !normalized_sni.has_value() ||
        !nonce.has_value() || nonce->size() != kH2NonceHexLen / 2) {
        return {};
    }
    crypto::Bytes msg;
    msg.reserve(yume::kTransportVersion.size() + yume::kTransportProfile.size() +
                normalized_sni->size() + nonce->size() + 22);
    append_u16(msg, static_cast<std::uint16_t>(yume::kTransportVersion.size()));
    msg.insert(msg.end(), yume::kTransportVersion.begin(),
               yume::kTransportVersion.end());
    append_u16(msg, static_cast<std::uint16_t>(yume::kTransportProfile.size()));
    msg.insert(msg.end(), yume::kTransportProfile.begin(),
               yume::kTransportProfile.end());
    append_u16(msg, static_cast<std::uint16_t>(normalized_sni->size()));
    msg.insert(msg.end(), normalized_sni->begin(), normalized_sni->end());
    append_u64(msg, static_cast<std::uint64_t>(hour_epoch));
    for (const std::byte value : *nonce) {
        msg.push_back(std::to_integer<std::uint8_t>(value));
    }
    const auto mac = admission::hmac_sha256(
        std::as_bytes(std::span(signal_key)), std::as_bytes(std::span(msg)));
    return mac.has_value() ? admission::token_hex(*mac) : std::string{};
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
    return admission::parse_path(path).has_value();
}

bool authority_matches_tls_sni(std::string_view authority,
                               std::string_view tls_sni,
                               std::optional<std::uint16_t> listener_port) {
    return admission::authority_matches_tls_sni(
        authority, tls_sni, listener_port);
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
    const auto nonce = admission::random_nonce();
    return nonce.has_value() ? admission::nonce_hex(*nonce) : std::string{};
}

AdmissionReplayCache::AdmissionReplayCache(std::size_t max_entries,
                                           std::int64_t ttl_seconds)
    : cache_(max_entries, static_cast<std::uint64_t>(
          std::max<std::int64_t>(1, ttl_seconds))) {}

bool AdmissionReplayCache::AcceptPath(std::string_view path) noexcept {
    return AcceptPathAt(path, monotonic_seconds());
}

bool AdmissionReplayCache::AcceptPathAt(
    std::string_view path, std::uint64_t monotonic_seconds_value) noexcept {
    const auto parsed = admission::parse_path(path);
    return parsed.has_value() &&
           cache_.reserve(parsed->nonce, monotonic_seconds_value) ==
               admission::ReplayDecision::Accepted;
}

std::size_t AdmissionReplayCache::size() const noexcept {
    return cache_.size();
}

}  // namespace yume::obfs
