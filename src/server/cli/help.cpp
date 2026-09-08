/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * yumed help, version, credits, and bash-completion output. The option text
 * itself is generated from the yumed(8) manual source, so this file owns
 * presentation and control flow rather than a second list of every option.
 */

#include "server/cli/help.hpp"

#include <iostream>

#include "core/release/terminal.hpp"
#include "server/cli/help_text.hpp"
#include "util.hpp"

void print_bash_completion() {
    yume::server::cli::write_bash_completion(std::cout);
}

void print_version() {
    yume::release::print_version_report("Yume Server");
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
                     "SERVER", yume::util::stdout_colors_enabled())
        << "\n";
    yume::server::cli::write_help_body(std::cout);
}
