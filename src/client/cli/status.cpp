/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "client/cli/status.hpp"

#include <cctype>
#include <iomanip>
#include <sstream>
#include <utility>

#include "client/cli/diagnostics.hpp"
#include "util.hpp"

namespace yume::client {
namespace {

std::string color_wrap(const std::string& text, const char* code) {
    return std::string("\033[") + code + "m" + text + "\033[0m";
}

std::string to_upper(std::string value) {
    for (char& c : value) {
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    return value;
}

std::string hop_status_line(const HopStatusSnapshot& hop) {
    const std::string hop_state = hop.enabled ? "ON" : "OFF";
    const std::string hop_line = color_wrap(hop_state, hop.enabled ? "1;32" : "1;31");

    std::ostringstream hop_freq_stream;
    hop_freq_stream.setf(std::ios::fixed);
    hop_freq_stream << std::setprecision(2)
                    << (hop.enabled && hop.interval_ms > 0
                            ? (1000.0 / static_cast<double>(hop.interval_ms))
                            : 0.0);
    const std::string hop_freq = color_wrap(hop_freq_stream.str() + "Hz", "1;33");

    std::int64_t adjusted = util::now_ms() + hop.offset_ms;
    if (adjusted < 0) {
        adjusted = 0;
    }
    const std::int64_t last_change = (hop.enabled && hop.interval_ms > 0)
                                         ? (adjusted % static_cast<std::int64_t>(hop.interval_ms))
                                         : 0;
    const std::string hop_last = color_wrap(std::to_string(last_change) + "ms", "1;34");
    return color_wrap("Hopping", "1;36") + ": " + hop_line + " - " + hop_freq + " | " + hop_last;
}

std::string build_status_block(const ConnectionStatusSummary& summary) {
    std::string protection_line = "TLS";
    if (summary.inner_established) {
        std::vector<std::string> protections;
        protections.push_back("PQ");
        std::string kdf_name = summary.inner_kdf_name;
        if (kdf_name.empty()) {
            kdf_name = summary.inner_heavy ? "argon2" : "hkdf";
        }
        protections.push_back(to_upper(kdf_name));
        protection_line.clear();
        for (std::size_t i = 0; i < protections.size(); ++i) {
            if (i != 0) {
                protection_line += "/";
            }
            protection_line += protections[i];
        }
    }

    const std::string inner_state =
        (summary.inner_established || summary.server_inner_active) ? "ON" : "OFF";
    std::string inner_line = color_wrap(inner_state, (inner_state == "ON") ? "1;32" : "1;31");
    if (summary.inner_established) {
        inner_line += color_wrap(summary.inner_heavy ? " (heavy)" : " (light)", "1;35");
        if (summary.have_inner_caps && summary.server_inner_dual) {
            inner_line += color_wrap(", dual", "1;35");
        }
    }

    const std::string server_display = color_wrap(summary.server, "1;33");
    const std::string version_value = color_wrap(summary.version.empty() ? "UNKNOWN" : summary.version, "1;35");
    const std::string connection_value = color_wrap("🔒 TLS", "1;32");
    const std::string protection_value = color_wrap(protection_line, "1;35");
    const std::string obfs_value = summary.obfuscation_enabled
        ? color_wrap("ON", "1;32") + color_wrap(" (HTTPS mask)", "1;35")
        : color_wrap("OFF", "1;31");
    const std::string verity_state = format_verified_sources(summary.verified_proof_sources);
    const std::string verity_line = color_wrap(verity_state, summary.verity_ok ? "1;32" : "1;31");
    const std::string border = color_wrap("------------------------------------------", "1;34");

    return border + "\n" +
           color_wrap("Connected to", "1;36") + " " + server_display + ":\n" +
           color_wrap("VERSION", "1;36") + ": " + version_value + "\n" +
           color_wrap("Connection", "1;36") + ": " + connection_value + "\n" +
           color_wrap("Protection", "1;36") + ": " + protection_value + "\n" +
           color_wrap("Obfuscation", "1;36") + ": " + obfs_value + "\n" +
           color_wrap("Inner", "1;36") + ": " + inner_line + "\n" +
           hop_status_line(summary.hop) + "\n" +
           color_wrap("Verity", "1;36") + ": " + verity_line + "\n" +
           border + "\n";
}

}  // namespace

std::function<std::string()> make_connection_status_block(ConnectionStatusSummary summary) {
    return [summary = std::move(summary)]() {
        return build_status_block(summary);
    };
}

}  // namespace yume::client
