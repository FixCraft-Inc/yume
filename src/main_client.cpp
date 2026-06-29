/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/entry.hpp"

int main(int argc, char** argv) {
    yume::client::Cli cli;
    return cli.run(argc, argv);
}
