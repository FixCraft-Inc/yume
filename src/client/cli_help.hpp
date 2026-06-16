#pragma once

/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 *
 * CLI help/usage text and version/credits output, extracted from
 * client/cli.cpp to keep that entrypoint file from carrying ~200 lines
 * of static text. No behavior change.
 */

namespace yume::client {

void print_bash_completion();
void print_version();
void print_credits();
void print_help();

}  // namespace yume::client
