/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "admission/h2_admission.hpp"
#include "core/security/crypto.hpp"

namespace yume::obfs {

constexpr std::size_t kH2TokenHexLen = admission::kH2TokenHexLength;
constexpr std::size_t kH2NonceHexLen = admission::kH2NonceHexLength;
constexpr std::size_t kH2PathLen = admission::kH2PathLength;

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

// Checks the v2 token and authority. Admission also requires the shared replay
// cache to accept the path after this succeeds. Empty secrets are refused.
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
    // a live duplicate or a full cache. Never evict a live nonce to admit a
    // new one. The cache is process-local, shared across sessions and
    // internally synchronized. Expiry uses a monotonic clock independently of
    // the wall-clock hour authenticated by the transport-v2 token.
    bool AcceptPath(std::string_view path) noexcept;
    bool AcceptPathAt(std::string_view path,
                      std::uint64_t monotonic_seconds) noexcept;
    std::size_t size() const noexcept;

private:
    admission::ReplayCache cache_;
};

}  // namespace yume::obfs
