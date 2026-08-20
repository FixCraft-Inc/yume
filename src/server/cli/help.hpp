#pragma once

/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * yumed CLI help, usage, version, credits, and completion output. The free
 * functions remain at global scope because the executable calls them without
 * namespace qualification.
 */

void print_bash_completion();
void print_version();
void print_credits();
void print_help();
