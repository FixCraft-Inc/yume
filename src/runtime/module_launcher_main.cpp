/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/module_launcher.hpp"

// A standalone launcher for embedding hosts and tests. yume and yumed launch
// modules by running themselves as yume-module.
int main(int argc, char** argv) { return yume::runtime::run_module_launcher(argc, argv); }
