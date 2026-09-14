/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/native_cli.hpp"

int main(int argc, char** argv) {
    return yume::runtime::run_native_cli(yume::runtime::NativeCliRole::Server, argc, argv);
}
