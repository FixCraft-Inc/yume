#pragma once

/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 *
 * yumed CLI help/usage/version/credits output, extracted from
 * main_server.cpp. Free functions at global scope so the existing
 * unqualified calls in main() resolve unchanged. No behavior change.
 */

void print_bash_completion();
void print_version();
void print_credits();
void print_help();
