#pragma once

/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * CLI help, usage, version, credits, and completion output. Kept separate so
 * the entrypoint owns control flow rather than static presentation text.
 */

namespace yume::client {

void print_bash_completion();
void print_version();
void print_credits();
void print_help();

}  // namespace yume::client
