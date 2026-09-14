/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "admission/h2_admission.hpp"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

#include <algorithm>
#include <charconv>
#include <cctype>
#include <limits>
#include <memory>
#include <system_error>

#include <boost/asio/ip/address.hpp>

namespace yume::admission {
namespace {

constexpr char kHexDigits[] = "0123456789abcdef";

using LibContext = std::unique_ptr<OSSL_LIB_CTX, decltype(&OSSL_LIB_CTX_free)>;
using Provider = std::unique_ptr<OSSL_PROVIDER, decltype(&OSSL_PROVIDER_unload)>;
using Mac = std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)>;
using MacContext = std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)>;

class OpenSslState final {
public:
    OpenSslState()
        : library_context_(OSSL_LIB_CTX_new(), OSSL_LIB_CTX_free),
          default_provider_(nullptr, OSSL_PROVIDER_unload),
          hmac_(nullptr, EVP_MAC_free) {
        if (!library_context_) {
            return;
        }
        default_provider_.reset(
            OSSL_PROVIDER_load(library_context_.get(), "default"));
        if (!default_provider_ ||
            EVP_set_default_properties(library_context_.get(),
                                       "provider=default") != 1) {
            return;
        }
        hmac_.reset(EVP_MAC_fetch(
            library_context_.get(), "HMAC", "provider=default"));
    }

    OSSL_LIB_CTX* library_context() const noexcept {
        return library_context_.get();
    }
    EVP_MAC* hmac() const noexcept { return hmac_.get(); }

private:
    // Declaration order keeps the library context alive until all objects
    // fetched from its provider have been released.
    LibContext library_context_;
    Provider default_provider_;
    Mac hmac_;
};

const OpenSslState& openssl_state() noexcept {
    static const OpenSslState state;
    return state;
}

bool is_lower_hex(unsigned char ch) noexcept {
    return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
}

std::byte decode_nibble(char ch) noexcept {
    const auto value = ch <= '9' ? static_cast<unsigned int>(ch - '0')
                                 : static_cast<unsigned int>(ch - 'a' + 10);
    return static_cast<std::byte>(value);
}

template <std::size_t Size>
bool decode_lower_hex(std::string_view input,
                      std::array<std::byte, Size>* output) noexcept {
    if (output == nullptr || input.size() != 2U * Size ||
        !std::all_of(input.begin(), input.end(), is_lower_hex)) {
        return false;
    }
    for (std::size_t i = 0; i < Size; ++i) {
        const auto high = std::to_integer<unsigned int>(decode_nibble(input[2U * i]));
        const auto low = std::to_integer<unsigned int>(decode_nibble(input[2U * i + 1U]));
        (*output)[i] = static_cast<std::byte>((high << 4U) | low);
    }
    return true;
}

template <std::size_t Size>
void append_lower_hex(std::string* output,
                      const std::array<std::byte, Size>& input) {
    for (const std::byte value : input) {
        const auto byte = std::to_integer<unsigned int>(value);
        output->push_back(kHexDigits[(byte >> 4U) & 0x0fU]);
        output->push_back(kHexDigits[byte & 0x0fU]);
    }
}

std::optional<std::uint16_t> parse_port(std::string_view text) noexcept {
    if (text.empty()) {
        return std::nullopt;
    }
    std::uint32_t port = 0U;
    const char* const begin = text.data();
    const char* const end = begin + text.size();
    const auto [position, error] = std::from_chars(begin, end, port);
    if (error != std::errc{} || position != end || port == 0U ||
        port > std::numeric_limits<std::uint16_t>::max()) {
        return std::nullopt;
    }
    return static_cast<std::uint16_t>(port);
}

std::optional<std::string> normalize_host(std::string_view host,
                                          bool require_ipv6_literal) {
    if (host.empty() || host.size() > std::numeric_limits<std::uint16_t>::max() ||
        std::any_of(host.begin(), host.end(), [](unsigned char ch) {
            return ch <= 0x20U || ch == 0x7fU || ch == '/' || ch == '@';
        })) {
        return std::nullopt;
    }
    std::string normalized(host);
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                   [](unsigned char ch) {
                       return static_cast<char>(std::tolower(ch));
                   });
    while (normalized.size() > 1U && normalized.back() == '.') {
        normalized.pop_back();
    }
    if (require_ipv6_literal) {
        boost::system::error_code error;
        const auto address = boost::asio::ip::make_address(normalized, error);
        if (error || !address.is_v6()) {
            return std::nullopt;
        }
        normalized = address.to_string();
    }
    return normalized;
}

struct ParsedAuthority final {
    std::string host;
    std::optional<std::uint16_t> port;
};

std::optional<ParsedAuthority> parse_authority(
    std::string_view authority, bool allow_unbracketed_ipv6) {
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
        host = authority.substr(1U, close - 1U);
        require_ipv6_literal = true;
        const auto suffix = authority.substr(close + 1U);
        if (!suffix.empty()) {
            if (suffix.front() != ':') {
                return std::nullopt;
            }
            port = parse_port(suffix.substr(1U));
            if (!port.has_value()) {
                return std::nullopt;
            }
        }
    } else {
        const auto first_colon = authority.find(':');
        const auto last_colon = authority.rfind(':');
        if (first_colon != std::string_view::npos && first_colon == last_colon) {
            port = parse_port(authority.substr(first_colon + 1U));
            if (!port.has_value()) {
                return std::nullopt;
            }
            host = authority.substr(0U, first_colon);
        } else if (first_colon != std::string_view::npos) {
            if (!allow_unbracketed_ipv6) {
                return std::nullopt;
            }
            require_ipv6_literal = true;
        }
    }

    auto normalized = normalize_host(host, require_ipv6_literal);
    if (!normalized.has_value()) {
        return std::nullopt;
    }
    return ParsedAuthority{std::move(*normalized), port};
}

}  // namespace

std::optional<Token> parse_token_hex(std::string_view token) noexcept {
    Token parsed{};
    if (!decode_lower_hex(token, &parsed)) {
        return std::nullopt;
    }
    return parsed;
}

std::optional<Nonce> parse_nonce_hex(std::string_view nonce) noexcept {
    Nonce parsed{};
    if (!decode_lower_hex(nonce, &parsed)) {
        return std::nullopt;
    }
    return parsed;
}

std::string token_hex(const Token& token) {
    std::string encoded;
    encoded.reserve(kH2TokenHexLength);
    append_lower_hex(&encoded, token);
    return encoded;
}

std::string nonce_hex(const Nonce& nonce) {
    std::string encoded;
    encoded.reserve(kH2NonceHexLength);
    append_lower_hex(&encoded, nonce);
    return encoded;
}

std::optional<ParsedPath> parse_path(std::string_view path) noexcept {
    if (path.size() != kH2PathLength || path.front() != '/' ||
        path[1U + kH2TokenHexLength] != '/') {
        return std::nullopt;
    }
    ParsedPath parsed;
    const auto token = path.substr(1U, kH2TokenHexLength);
    const auto nonce = path.substr(2U + kH2TokenHexLength,
                                   kH2NonceHexLength);
    if (!decode_lower_hex(token, &parsed.token) ||
        !decode_lower_hex(nonce, &parsed.nonce)) {
        return std::nullopt;
    }
    return parsed;
}

std::string build_path(const Token& token, const Nonce& nonce) {
    std::string path;
    path.reserve(kH2PathLength);
    path.push_back('/');
    append_lower_hex(&path, token);
    path.push_back('/');
    append_lower_hex(&path, nonce);
    return path;
}

std::optional<std::string> normalize_server_name(std::string_view name) {
    return normalize_host(name, false);
}

bool authority_matches_tls_sni(
    std::string_view authority,
    std::string_view tls_sni,
    std::optional<std::uint16_t> listener_port) {
    const auto parsed_authority = parse_authority(authority, false);
    const auto parsed_sni = parse_authority(tls_sni, true);
    if (!parsed_authority.has_value() || !parsed_sni.has_value() ||
        parsed_authority->host != parsed_sni->host) {
        return false;
    }
    if (listener_port.has_value()) {
        if ((parsed_authority->port.has_value() &&
             parsed_authority->port != listener_port) ||
            (parsed_sni->port.has_value() &&
             parsed_sni->port != listener_port)) {
            return false;
        }
    }
    return true;
}

std::optional<Token> hmac_sha256(std::span<const std::byte> key,
                                 std::span<const std::byte> input) noexcept {
    EVP_MAC* const algorithm = openssl_state().hmac();
    if (algorithm == nullptr || key.empty()) {
        return std::nullopt;
    }
    MacContext context(EVP_MAC_CTX_new(algorithm), EVP_MAC_CTX_free);
    if (!context) {
        return std::nullopt;
    }
    char digest[] = "SHA256";
    char properties[] = "provider=default";
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0U),
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_PROPERTIES, properties, 0U),
        OSSL_PARAM_construct_end(),
    };
    const auto* key_data = reinterpret_cast<const unsigned char*>(key.data());
    const auto* input_data = reinterpret_cast<const unsigned char*>(input.data());
    if (EVP_MAC_init(context.get(), key_data, key.size(), parameters) != 1 ||
        EVP_MAC_update(context.get(), input_data, input.size()) != 1) {
        return std::nullopt;
    }
    Token output{};
    std::size_t written = 0U;
    if (EVP_MAC_final(context.get(),
                      reinterpret_cast<unsigned char*>(output.data()),
                      &written, output.size()) != 1 || written != output.size()) {
        OPENSSL_cleanse(output.data(), output.size());
        return std::nullopt;
    }
    return output;
}

bool constant_time_equal(const Token& left, const Token& right) noexcept {
    return CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0;
}

std::optional<Nonce> random_nonce() noexcept {
    OSSL_LIB_CTX* const library_context = openssl_state().library_context();
    if (library_context == nullptr || openssl_state().hmac() == nullptr) {
        return std::nullopt;
    }
    Nonce nonce{};
    if (RAND_bytes_ex(
            library_context,
            reinterpret_cast<unsigned char*>(nonce.data()),
            nonce.size(), 256U) != 1) {
        OPENSSL_cleanse(nonce.data(), nonce.size());
        return std::nullopt;
    }
    return nonce;
}

ReplayCache::ReplayCache(std::size_t max_entries, std::uint64_t ttl_ticks)
    : max_entries_(std::max<std::size_t>(1U, max_entries)),
      ttl_ticks_(std::max<std::uint64_t>(1U, ttl_ticks)) {}

ReplayDecision ReplayCache::reserve(const Nonce& nonce,
                                    std::uint64_t monotonic_now) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    if ((has_last_tick_ && monotonic_now < last_tick_) ||
        monotonic_now > std::numeric_limits<std::uint64_t>::max() - ttl_ticks_) {
        return ReplayDecision::Rejected;
    }
    has_last_tick_ = true;
    last_tick_ = monotonic_now;
    evict(monotonic_now);
    if (expiry_by_nonce_.contains(nonce) ||
        expiry_by_nonce_.size() >= max_entries_) {
        return ReplayDecision::Rejected;
    }

    const std::uint64_t expiry = monotonic_now + ttl_ticks_;
    try {
        expiry_order_.emplace_back(nonce, expiry);
        try {
            expiry_by_nonce_.emplace(nonce, expiry);
        } catch (...) {
            expiry_order_.pop_back();
            throw;
        }
    } catch (...) {
        return ReplayDecision::Rejected;
    }
    return ReplayDecision::Accepted;
}

std::size_t ReplayCache::size() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return expiry_by_nonce_.size();
}

std::size_t ReplayCache::NonceHash::operator()(
    const Nonce& nonce) const noexcept {
    // Replay keys are already uniformly random. FNV-1a is used only as an
    // in-process table index; equality still compares every nonce byte.
    std::size_t hash = sizeof(std::size_t) == 8U
        ? static_cast<std::size_t>(14695981039346656037ULL)
        : static_cast<std::size_t>(2166136261U);
    const std::size_t prime = sizeof(std::size_t) == 8U
        ? static_cast<std::size_t>(1099511628211ULL)
        : static_cast<std::size_t>(16777619U);
    for (const std::byte value : nonce) {
        hash ^= std::to_integer<std::size_t>(value);
        hash *= prime;
    }
    return hash;
}

void ReplayCache::evict(std::uint64_t monotonic_now) noexcept {
    while (!expiry_order_.empty() &&
           expiry_order_.front().second <= monotonic_now) {
        const auto oldest = std::move(expiry_order_.front());
        expiry_order_.pop_front();
        const auto entry = expiry_by_nonce_.find(oldest.first);
        if (entry != expiry_by_nonce_.end() && entry->second == oldest.second) {
            expiry_by_nonce_.erase(entry);
        }
    }
}

}  // namespace yume::admission
