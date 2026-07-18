/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "core/security/crypto.hpp"

namespace yume::obfs {

constexpr std::size_t kH2TokenHexLen = 32;
constexpr std::size_t kH2NonceHexLen = 16;
constexpr std::size_t kH2PathLen = 1 + kH2TokenHexLen + 1 + kH2NonceHexLen;

crypto::Bytes derive_signal_key(std::string_view secret);

std::string derive_path_token(const crypto::Bytes& signal_key,
                              std::string_view sni,
                              std::int64_t hour_epoch);

std::string build_path(const std::string& token, const std::string& nonce_hex);

bool valid_path_shape(std::string_view path);

bool authority_matches_tls_sni(std::string_view authority,
                               std::string_view tls_sni);

// Complete opening-path decision used by yumed. A nonempty secret requires a
// valid HMAC token. Empty-secret structural admission exists only for
// non-public development; public policy rejects that configuration earlier.
bool carrier_path_admitted(std::string_view secret,
                           std::string_view authority,
                           std::string_view tls_sni,
                           std::string_view path,
                           std::int64_t now_seconds);

bool verify_path_token(const std::vector<crypto::Bytes>& signal_keys,
                       std::string_view sni,
                       std::string_view path,
                       std::int64_t now_seconds);

std::string random_nonce_hex();

}  // namespace yume::obfs
