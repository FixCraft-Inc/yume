/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "server/cli/entry.hpp"

int main(int argc, char** argv) {
    yume::server::Server server;
    return server.run(argc, argv);
}
