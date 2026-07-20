/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "util.hpp"

#include <cassert>
#include <cstdlib>

int main() {
    assert(setenv("YUME_RELAY_READ_BUF", "256", 1) == 0);
    assert(yume::util::relay_read_buf_size() == 256U * 1024U);
    assert(yume::util::server_relay_read_buf_size() == 32U * 1024U);
    return 0;
}
