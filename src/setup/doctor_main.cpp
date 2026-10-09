/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// yume-doctor: checks a configuration and the files it names. Exit status
// 0 when they are valid, 1 when a check fails and 2 for a usage error.

#include <cstdio>
#include <exception>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

#include <sys/stat.h>

#include "setup/doctor.hpp"
#include "setup/yume_doctor_help_text.hpp"

namespace {

constexpr int kExitInvalid = 1;
constexpr int kExitUsage = 2;

int usage_error(const std::string& message) {
    std::fprintf(stderr, "yume-doctor: %s\n%s", message.c_str(),
                 yume::setup::doctor_cli::kHelpBody);
    return kExitUsage;
}

}  // namespace

int main(int argc, char** argv) {
    ::umask(077);
    std::optional<std::filesystem::path> config;
    bool help = false;
    for (int index = 1; index < argc; ++index) {
        const std::string_view word(argv[index]);
        if (word == "-h" || word == "--help") {
            help = true;
        } else if (word == "--config" || word.starts_with("--config=")) {
            if (config) return usage_error("--config is given more than once");
            if (word != "--config") {
                config = std::filesystem::path(std::string(word.substr(9)));
            } else if (index + 1 < argc &&
                       !std::string_view(argv[index + 1]).starts_with("-")) {
                config = std::filesystem::path(argv[++index]);
            } else {
                return usage_error("--config needs a path");
            }
        } else {
            return usage_error("unknown argument: " + std::string(word));
        }
    }
    if (help) {
        std::fputs(yume::setup::doctor_cli::kHelpBody, stdout);
        return 0;
    }
    if (!config) return usage_error("--config is required");

    yume::setup::DoctorReport report;
    try {
        report = yume::setup::diagnose(*config);
    } catch (const std::exception&) {
        report.diagnostics = {{"/diagnostic", "validation could not complete"}};
    }
    if (!report.diagnostics.empty()) {
        for (const auto& diagnostic : report.diagnostics) {
            std::fprintf(stderr, "yume-doctor: invalid %s: %s\n",
                         diagnostic.pointer.c_str(), diagnostic.detail.c_str());
        }
        return kExitInvalid;
    }
    std::printf(
        "yume-doctor: configuration and credentials valid; no session was "
        "started\n");
    std::printf("yume-doctor: tuning preset %s\n", report.preset.c_str());
    return 0;
}
