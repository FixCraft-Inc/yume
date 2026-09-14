/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/ytp1_h2_admission.hpp"

#include <openssl/crypto.h>

#include <algorithm>
#include <limits>

namespace yume::providers {
namespace {

void append_u16(std::vector<std::byte>* output, std::uint16_t value) {
    output->push_back(static_cast<std::byte>((value >> 8U) & 0xffU));
    output->push_back(static_cast<std::byte>(value & 0xffU));
}

void append_text(std::vector<std::byte>* output, std::string_view text) {
    for (const char value : text) {
        output->push_back(static_cast<std::byte>(
            static_cast<unsigned char>(value)));
    }
}

void append_bytes(std::vector<std::byte>* output,
                  std::span<const std::byte> bytes) {
    output->insert(output->end(), bytes.begin(), bytes.end());
}

}  // namespace

std::optional<std::string> canonicalize_ytp1_h2_server_name(
    std::string_view server_name) noexcept {
    if (server_name.empty() ||
        server_name.size() > kYtp1H2AdmissionMaxServerNameBytes ||
        server_name.front() == '.' || server_name.back() == '.') {
        return std::nullopt;
    }
    try {
        std::string canonical(server_name);
        std::transform(canonical.begin(), canonical.end(), canonical.begin(),
                       [](unsigned char ch) {
                           return static_cast<char>(
                               ch >= 'A' && ch <= 'Z' ? ch + ('a' - 'A') : ch);
                       });
        std::size_t label_begin = 0U;
        while (label_begin < canonical.size()) {
            const std::size_t dot = canonical.find('.', label_begin);
            const std::size_t label_end =
                dot == std::string::npos ? canonical.size() : dot;
            const std::size_t label_size = label_end - label_begin;
            if (label_size == 0U || label_size > 63U ||
                canonical[label_begin] == '-' ||
                canonical[label_end - 1U] == '-') {
                return std::nullopt;
            }
            for (std::size_t index = label_begin; index < label_end; ++index) {
                const unsigned char ch = static_cast<unsigned char>(
                    canonical[index]);
                if (!((ch >= 'a' && ch <= 'z') ||
                      (ch >= '0' && ch <= '9') || ch == '-')) {
                    return std::nullopt;
                }
            }
            if (dot == std::string::npos) {
                break;
            }
            label_begin = dot + 1U;
        }
        return canonical;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<std::vector<std::byte>> encode_ytp1_h2_admission_input(
    std::string_view tls_sni,
    std::span<const std::byte> tls_exporter,
    const admission::Nonce& nonce) noexcept {
    if (tls_exporter.size() != kYtp1H2AdmissionExporterBytes ||
        kYtp1H2AdmissionDomain.size() >
            std::numeric_limits<std::uint16_t>::max()) {
        return std::nullopt;
    }
    try {
        auto normalized_sni = canonicalize_ytp1_h2_server_name(tls_sni);
        if (!normalized_sni.has_value()) {
            return std::nullopt;
        }

        std::vector<std::byte> input;
        input.reserve(2U + kYtp1H2AdmissionDomain.size() +
                      2U + normalized_sni->size() +
                      2U + tls_exporter.size() + nonce.size());
        append_u16(&input, static_cast<std::uint16_t>(
                               kYtp1H2AdmissionDomain.size()));
        append_text(&input, kYtp1H2AdmissionDomain);
        append_u16(&input,
                   static_cast<std::uint16_t>(normalized_sni->size()));
        append_text(&input, *normalized_sni);
        append_u16(&input,
                   static_cast<std::uint16_t>(tls_exporter.size()));
        append_bytes(&input, tls_exporter);
        append_bytes(&input, nonce);
        return input;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<admission::Token> derive_ytp1_h2_admission_token(
    std::span<const std::byte> admission_key,
    std::string_view tls_sni,
    std::span<const std::byte> tls_exporter,
    const admission::Nonce& nonce) noexcept {
    if (admission_key.size() != kYtp1H2AdmissionKeyBytes) {
        return std::nullopt;
    }
    auto input = encode_ytp1_h2_admission_input(
        tls_sni, tls_exporter, nonce);
    if (!input.has_value()) {
        return std::nullopt;
    }
    struct InputWiper final {
        std::vector<std::byte>& input;
        ~InputWiper() noexcept { OPENSSL_cleanse(input.data(), input.size()); }
    } input_wiper{*input};
    return admission::hmac_sha256(admission_key, *input);
}

std::optional<std::string> build_ytp1_h2_admission_path(
    std::span<const std::byte> admission_key,
    std::string_view tls_sni,
    std::span<const std::byte> tls_exporter,
    const admission::Nonce& nonce) noexcept {
    auto token = derive_ytp1_h2_admission_token(
        admission_key, tls_sni, tls_exporter, nonce);
    if (!token.has_value()) {
        return std::nullopt;
    }
    try {
        return admission::build_path(*token, nonce);
    } catch (...) {
        return std::nullopt;
    }
}

bool verify_ytp1_h2_admission_path(
    std::span<const std::byte> admission_key,
    std::string_view authority,
    std::string_view tls_sni,
    std::span<const std::byte> tls_exporter,
    std::string_view path,
    std::optional<std::uint16_t> listener_port) noexcept {
    try {
        if (authority.size() > kYtp1H2AdmissionMaxServerNameBytes + 6U ||
            !admission::authority_matches_tls_sni(
                authority, tls_sni, listener_port)) {
            return false;
        }
        const auto parsed = admission::parse_path(path);
        if (!parsed.has_value()) {
            return false;
        }
        const auto expected = derive_ytp1_h2_admission_token(
            admission_key, tls_sni, tls_exporter, parsed->nonce);
        return expected.has_value() &&
               admission::constant_time_equal(*expected, parsed->token);
    } catch (...) {
        return false;
    }
}

}  // namespace yume::providers
