/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace yume::admission {

inline constexpr std::size_t kH2TokenBytes = 32U;
inline constexpr std::size_t kH2NonceBytes = 32U;
inline constexpr std::size_t kH2TokenHexLength = 2U * kH2TokenBytes;
inline constexpr std::size_t kH2NonceHexLength = 2U * kH2NonceBytes;
inline constexpr std::size_t kH2PathLength =
    1U + kH2TokenHexLength + 1U + kH2NonceHexLength;

using Token = std::array<std::byte, kH2TokenBytes>;
using Nonce = std::array<std::byte, kH2NonceBytes>;

struct ParsedPath final {
    Token token{};
    Nonce nonce{};
};

std::optional<Token> parse_token_hex(std::string_view token) noexcept;
std::optional<Nonce> parse_nonce_hex(std::string_view nonce) noexcept;
std::string token_hex(const Token& token);
std::string nonce_hex(const Nonce& nonce);
std::optional<ParsedPath> parse_path(std::string_view path) noexcept;
std::string build_path(const Token& token, const Nonce& nonce);

// Preserves transport-v2 host normalization (case and trailing root dots).
// This is not strict DNS validation; YTP/1 applies its own hostname contract.
std::optional<std::string> normalize_server_name(std::string_view name);

bool authority_matches_tls_sni(
    std::string_view authority,
    std::string_view tls_sni,
    std::optional<std::uint16_t> listener_port = std::nullopt);

// This primitive has its own OpenSSL library context and explicitly fetched
// default-provider HMAC. It never falls back to the process-global context.
std::optional<Token> hmac_sha256(std::span<const std::byte> key,
                                 std::span<const std::byte> input) noexcept;
std::optional<Nonce> random_nonce() noexcept;
bool constant_time_equal(const Token& left, const Token& right) noexcept;

enum class ReplayDecision : std::uint8_t {
    Accepted,
    Rejected,
};

// Process owners share one instance across every admission session. Callers
// supply monotonic ticks in one fixed unit and a TTL in that same unit. A tick
// regression, duplicate, saturation, expiry overflow, or allocation failure
// rejects without evicting a live nonce or leaving a partial reservation.
class ReplayCache final {
public:
    explicit ReplayCache(std::size_t max_entries = 4096U,
                         std::uint64_t ttl_ticks = 2U * 3600U);

    ReplayCache(const ReplayCache&) = delete;
    ReplayCache& operator=(const ReplayCache&) = delete;

    ReplayDecision reserve(const Nonce& nonce,
                           std::uint64_t monotonic_now) noexcept;
    std::size_t size() const noexcept;

private:
    struct NonceHash final {
        std::size_t operator()(const Nonce& nonce) const noexcept;
    };

    void evict(std::uint64_t monotonic_now) noexcept;

    const std::size_t max_entries_;
    const std::uint64_t ttl_ticks_;
    mutable std::mutex mutex_;
    bool has_last_tick_{false};
    std::uint64_t last_tick_{0U};
    std::unordered_map<Nonce, std::uint64_t, NonceHash> expiry_by_nonce_;
    std::deque<std::pair<Nonce, std::uint64_t>> expiry_order_;
};

}  // namespace yume::admission
