/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * CLI help, version, credits, and bash-completion output. The option text
 * itself is generated from the yume(1) manual source, so this file owns
 * presentation and control flow rather than a second list of every option.
 */

#include "client/cli/display/help.hpp"

#include <iostream>

#include "client/cli/display/help_text.hpp"
#include "core/release/terminal.hpp"
#include "util.hpp"

namespace yume::client {

void print_bash_completion() {
    cli::write_bash_completion(std::cout);
}

void print_version() {
    yume::release::print_version_report("Yume");
}

void print_credits() {
    std::cout
        << "YUME credits\n"
        << "Author: F1xGOD - founder, lead developer, and designer of Yume and BaseFWX.\n"
        << "Engineering partners:\n"
        << "  Codex - primary AI engineering partner across architecture, implementation, security hardening, testing, and documentation.\n"
        << "  Claude - supporting contributions to selected reviews, refactors, and bug fixes.\n"
        << "Core open-source components:\n"
        << "  BaseFWX core/runtime - LGPL-3.0-or-later\n"
        << "  liboqs (Open Quantum Safe) - MIT\n"
        << "  OpenSSL - Apache-2.0\n"
        << "  Boost.Asio - Boost Software License 1.0\n"
        << "  nlohmann/json - MIT\n"
        << "  spdlog - MIT\n"
        << "  zstd - BSD-3-Clause\n";
}

void print_help() {
    std::cout << yume::release::render_brand_header(
                     "CLIENT", yume::util::stdout_colors_enabled())
        << "\n";
    cli::write_help_body(std::cout);
}

}  // namespace yume::client
