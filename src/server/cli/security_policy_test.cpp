/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/cli/security_policy.hpp"

#include <cassert>
#include <cstdio>

int main() {
    using yume::server::cli::public_obfs_admission_valid;
    assert(public_obfs_admission_valid(false, true, ""));
    assert(public_obfs_admission_valid(false, false, ""));
    assert(public_obfs_admission_valid(true, true, "shared-secret"));
    assert(!public_obfs_admission_valid(true, true, ""));
    assert(!public_obfs_admission_valid(true, false, "shared-secret"));
    std::puts("security_policy_test: all cases passed");
    return 0;
}
