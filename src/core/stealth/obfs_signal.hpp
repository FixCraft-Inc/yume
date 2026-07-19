/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <optional>
#include <deque>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "core/security/crypto.hpp"

namespace yume::obfs {

constexpr std::size_t kH2TokenHexLen = 64;
constexpr std::size_t kH2NonceHexLen = 64;
constexpr std::size_t kH2PathLen = 1 + kH2TokenHexLen + 1 + kH2NonceHexLen;

crypto::Bytes derive_signal_key(std::string_view secret);

std::string derive_path_token(const crypto::Bytes& signal_key,
                              std::string_view sni,
                              std::int64_t hour_epoch,
                              std::string_view nonce_hex);

std::string build_path(const std::string& token, const std::string& nonce_hex);

bool valid_path_shape(std::string_view path);

bool authority_matches_tls_sni(std::string_view authority,
                               std::string_view tls_sni,
                               std::optional<std::uint16_t> listener_port = std::nullopt);

// Complete v2 opening-path decision used by yumed. Empty secrets are never an
// admission mode; startup policy also rejects them earlier.
bool carrier_path_admitted(const crypto::Bytes& secret,
                           std::string_view authority,
                           std::string_view tls_sni,
                           std::string_view path,
                           std::int64_t now_seconds,
                           std::optional<std::uint16_t> listener_port = std::nullopt);

inline bool carrier_path_admitted(std::string_view secret,
                                  std::string_view authority,
                                  std::string_view tls_sni,
                                  std::string_view path,
                                  std::int64_t now_seconds,
                                  std::optional<std::uint16_t> listener_port = std::nullopt) {
    return carrier_path_admitted(derive_signal_key(secret), authority, tls_sni,
                                 path, now_seconds, listener_port);
}

bool verify_path_token(const std::vector<crypto::Bytes>& signal_keys,
                       std::string_view sni,
                       std::string_view path,
                       std::int64_t now_seconds);

std::string random_nonce_hex();

class AdmissionReplayCache {
public:
    explicit AdmissionReplayCache(std::size_t max_entries = 4096,
                                  std::int64_t ttl_seconds = 2 * 3600);

    // Call only after the HMAC and authority checks succeed. Returns false for
    // a live duplicate. The cache is shared across sessions and internally
    // synchronized.
    bool AcceptPath(std::string_view path, std::int64_t now_seconds);
    std::size_t size() const;

private:
    void Evict(std::int64_t now_seconds);

    const std::size_t max_entries_;
    const std::int64_t ttl_seconds_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::int64_t> expiry_by_nonce_;
    std::deque<std::pair<std::string, std::int64_t>> expiry_order_;
};

}  // namespace yume::obfs
