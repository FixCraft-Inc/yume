/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "admission/h2_admission.hpp"

namespace yume::providers {

inline constexpr std::string_view kYtp1H2AdmissionDomain =
    "yume/ytp/1/h2-web/admission/v1";
inline constexpr std::string_view kYtp1H2AdmissionExporterLabel =
    "EXPORTER-yume/ytp/1/h2-web-admission/v1";
inline constexpr std::size_t kYtp1H2AdmissionKeyBytes = 32U;
inline constexpr std::size_t kYtp1H2AdmissionExporterBytes = 32U;
inline constexpr std::size_t kYtp1H2AdmissionMaxServerNameBytes = 253U;

// Lowercases one strict DNS server name. Empty labels, a root dot, non-ASCII,
// underscores, and labels beginning or ending in '-' are rejected.
std::optional<std::string> canonicalize_ytp1_h2_server_name(
    std::string_view server_name) noexcept;

// Canonical YTP/1 admission input:
//   u16be(domain length) || domain
//   u16be(canonical TLS SNI length) || canonical TLS SNI
//   u16be(32) || TLS exporter
//   nonce[32]
// The exporter uses kYtp1H2AdmissionExporterLabel with an empty context.
// Cover-profile geometry and wall-clock time are deliberately absent.
// Consequently each TLS connection may successfully promote at most one
// carrier. A TTL replay cache cannot make a second promotion safe after the
// nonce expires; the front door must retain that irreversible connection
// state independently of process-shared nonce replay protection.
// The returned input contains exporter material; its owner must wipe it when
// finished. Token/path helpers wipe their own encoded temporary input.
std::optional<std::vector<std::byte>> encode_ytp1_h2_admission_input(
    std::string_view tls_sni,
    std::span<const std::byte> tls_exporter,
    const admission::Nonce& nonce) noexcept;

std::optional<admission::Token> derive_ytp1_h2_admission_token(
    std::span<const std::byte> admission_key,
    std::string_view tls_sni,
    std::span<const std::byte> tls_exporter,
    const admission::Nonce& nonce) noexcept;

std::optional<std::string> build_ytp1_h2_admission_path(
    std::span<const std::byte> admission_key,
    std::string_view tls_sni,
    std::span<const std::byte> tls_exporter,
    const admission::Nonce& nonce) noexcept;

bool verify_ytp1_h2_admission_path(
    std::span<const std::byte> admission_key,
    std::string_view authority,
    std::string_view tls_sni,
    std::span<const std::byte> tls_exporter,
    std::string_view path,
    std::optional<std::uint16_t> listener_port = std::nullopt) noexcept;

}  // namespace yume::providers
