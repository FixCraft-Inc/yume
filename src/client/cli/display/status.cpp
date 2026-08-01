/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/display/status.hpp"

#include <string>
#include <utility>

#include "client/cli/connect/diagnostics.hpp"
#include "util.hpp"

namespace yume::client {
namespace {

std::string color_wrap(const std::string& text, const char* code) {
    if (!util::stdout_colors_enabled()) {
        return text;
    }
    return std::string("\033[") + code + "m" + text + "\033[0m";
}

std::string format_byte_limit(std::uint64_t bytes) {
    constexpr std::uint64_t kKiB = 1024;
    constexpr std::uint64_t kMiB = 1024 * kKiB;
    constexpr std::uint64_t kGiB = 1024 * kMiB;
    if (bytes != 0 && bytes % kGiB == 0) {
        return std::to_string(bytes / kGiB) + " GiB";
    }
    if (bytes != 0 && bytes % kMiB == 0) {
        return std::to_string(bytes / kMiB) + " MiB";
    }
    if (bytes != 0 && bytes % kKiB == 0) {
        return std::to_string(bytes / kKiB) + " KiB";
    }
    return std::to_string(bytes) + " bytes";
}

std::string format_active_limit(std::uint64_t milliseconds) {
    constexpr std::uint64_t kSecondMs = 1000;
    constexpr std::uint64_t kMinuteMs = 60 * kSecondMs;
    if (milliseconds != 0 && milliseconds % kMinuteMs == 0) {
        return std::to_string(milliseconds / kMinuteMs) + " min";
    }
    if (milliseconds != 0 && milliseconds % kSecondMs == 0) {
        return std::to_string(milliseconds / kSecondMs) + " s";
    }
    return std::to_string(milliseconds) + " ms";
}

std::string format_epoch_policy(const ConnectionStatusSummary& summary) {
    if (summary.epoch_byte_limit == 0 || summary.epoch_frame_limit == 0 ||
        summary.epoch_active_limit_ms == 0) {
        return "UNKNOWN";
    }
    return format_byte_limit(summary.epoch_byte_limit) + " / " +
           std::to_string(summary.epoch_frame_limit) + " frames / " +
           format_active_limit(summary.epoch_active_limit_ms) + " active";
}

std::string build_status_block(const ConnectionStatusSummary& summary) {
    std::string protection_line = "TLS";
    if (summary.inner_established) {
        protection_line = "ML-KEM-1024+X25519/PSK/AES-256-GCM";
    }

    const std::string inner_state =
        (summary.inner_established || summary.server_inner_active) ? "ON" : "OFF";
    std::string inner_line = color_wrap(inner_state, (inner_state == "ON") ? "1;32" : "1;31");
    if (summary.inner_established) {
        inner_line += color_wrap(" (directional ratchet)", "1;35");
    }

    const std::string server_display = color_wrap(summary.server, "1;33");
    const std::string version_value = color_wrap(summary.version.empty() ? "UNKNOWN" : summary.version, "1;35");
    const std::string connection_value = color_wrap("🔒 TLS", "1;32");
    const std::string protection_value = color_wrap(protection_line, "1;35");
    const std::string obfs_value = summary.obfuscation_enabled
        ? color_wrap("ON", "1;32") + color_wrap(" (HTTPS mask)", "1;35")
        : color_wrap("OFF", "1;31");
    const std::string verity_state = summary.verity_applicable
        ? format_verified_sources(summary.verified_proof_sources)
        : "N/A (normal mode)";
    const char* verity_color = summary.verity_applicable
        ? (summary.verity_ok ? "1;32" : "1;31")
        : "1;90";
    const std::string verity_line = color_wrap(verity_state, verity_color);
    const std::string border = color_wrap("------------------------------------------", "1;34");

    return border + "\n" +
           color_wrap("Connected to", "1;36") + " " + server_display + ":\n" +
           color_wrap("VERSION", "1;36") + ": " + version_value + "\n" +
           color_wrap("Connection", "1;36") + ": " + connection_value + "\n" +
           color_wrap("Protection", "1;36") + ": " + protection_value + "\n" +
           color_wrap("Obfuscation", "1;36") + ": " + obfs_value + "\n" +
           color_wrap("Inner", "1;36") + ": " + inner_line + "\n" +
           color_wrap("Epochs", "1;36") + ": " +
               color_wrap(format_epoch_policy(summary), "1;35") + "\n" +
           color_wrap("Operator identity", "1;36") + ": " + verity_line + "\n" +
           border + "\n";
}

}  // namespace

std::function<std::string()> make_connection_status_block(ConnectionStatusSummary summary) {
    return [summary = std::move(summary)]() {
        return build_status_block(summary);
    };
}

}  // namespace yume::client
