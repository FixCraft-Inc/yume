/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/connect/diagnostics.hpp"

#include <algorithm>
#include <cctype>

#include "core/protocol/runtime_policy.hpp"
#include "util.hpp"

namespace yume::client {

bool looks_like_endpoint_down(std::string message) {
    std::transform(message.begin(), message.end(), message.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return message.find("server offline") != std::string::npos ||
           message.find("could not reach endpoint") != std::string::npos ||
           message.find("connect timeout") != std::string::npos ||
           message.find("connection refused") != std::string::npos ||
           message.find("network is unreachable") != std::string::npos ||
           message.find("host is unreachable") != std::string::npos ||
           message.find("no route to host") != std::string::npos ||
           message.find("dns resolution failed") != std::string::npos ||
           message.find("proxy timed out") != std::string::npos;
}

std::string normalize_proof_source(std::string source) {
    std::transform(source.begin(), source.end(), source.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return source;
}

std::string detect_client_platform() {
#if defined(_WIN32)
    return "windows";
#elif defined(__APPLE__)
    return "macos";
#elif defined(__ANDROID__)
    return "android";
#elif defined(__linux__)
    return "linux";
#else
    return "unknown";
#endif
}

void add_verified_source(std::vector<std::string>* out, std::string_view source) {
    if (!out || source.empty()) {
        return;
    }
    const std::string value(source);
    if (std::find(out->begin(), out->end(), value) == out->end()) {
        out->push_back(value);
    }
}

std::string format_verified_sources(const std::vector<std::string>& sources) {
    std::vector<std::string> labels;
    labels.reserve(sources.size());
    for (const auto& source : sources) {
        if (source == yume::policy::kAnonymProofSourceSubCa) {
            labels.emplace_back("delegated server certificate");
        } else if (source == yume::policy::kAnonymProofSourceCa) {
            labels.emplace_back("operator CA");
        } else if (source == yume::policy::kAnonymProofSourceFixcraft) {
            labels.emplace_back("FixCraft authority");
        }
    }
    if (labels.empty()) {
        return "FAIL";
    }
    std::string joined;
    for (std::size_t i = 0; i < labels.size(); ++i) {
        if (i != 0) {
            joined += "+";
        }
        joined += labels[i];
    }
    return "PASS [" + joined + "]";
}

void emit_self_dpi_report(const ClientConfig& cfg,
                          tls_fingerprint::BrowserProfile active_profile,
                          const tls_fingerprint::FingerprintData& fingerprint,
                          bool h2_carrier_active,
                          std::chrono::milliseconds tls_ms) {
    if (!cfg.self_dpi) {
        return;
    }
    const std::string profile_name = tls_fingerprint::browser_profile_name(active_profile);
    util::log_info(
        std::string("self-DPI carrier metadata: tls_stealth=") +
        std::string(cfg.tls_stealth_enabled ? "on" : "off") +
        " profile=" + profile_name +
        " carrier=" + std::string(h2_carrier_active ? "http2" : "raw-auth") +
        " port=" + std::to_string(cfg.port) +
        " tls_ms=" + std::to_string(tls_ms.count()) +
        " pad_multiple=" + std::to_string(cfg.obfs_pad_multiple) +
        " jitter_ms=" + std::to_string(cfg.obfs_jitter_ms));

    if (!cfg.tls_stealth_enabled) {
        util::log_warn("self-DPI: TLS stealth is disabled; carrier TLS will not resemble a browser profile.");
    }
    if (!h2_carrier_active) {
        util::log_warn("self-DPI: HTTPS masking is disabled; the AUTH exchange is visible immediately after TLS.");
    }
    if (cfg.port != 443) {
        util::log_warn("self-DPI: non-443 server port weakens browser/CDN cover traffic assumptions.");
    }
    if (cfg.tls_stealth_enabled && !fingerprint.matches_known_browser) {
        util::log_warn("self-DPI: selected TLS profile did not resolve to a known browser fingerprint locally.");
    }
    if (cfg.obfs_pad_multiple == 0 && cfg.obfs_jitter_ms == 0) {
        util::log_info("self-DPI: frame padding and jitter are off; fastest path, weaker size/timing cover.");
    }
}

}  // namespace yume::client
