/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <chrono>
#include <string>
#include <string_view>
#include <vector>

#include "client/cli/entry.hpp"
#include "core/stealth/tls_fingerprint.hpp"

namespace yume::client {

bool looks_like_endpoint_down(std::string message);
std::string normalize_proof_source(std::string source);
std::string detect_client_platform();
void add_verified_source(std::vector<std::string>* out, std::string_view source);
std::string format_verified_sources(const std::vector<std::string>& sources);

void emit_self_dpi_report(const ClientConfig& cfg,
                          tls_fingerprint::BrowserProfile active_profile,
                          const tls_fingerprint::FingerprintData& fingerprint,
                          bool h2_carrier_active,
                          std::chrono::milliseconds tls_ms);

}  // namespace yume::client
