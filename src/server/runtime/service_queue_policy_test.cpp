/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/runtime/service_queue_policy.hpp"

#include <cassert>
#include <cstdio>

int main() {
    using namespace yume::server::service_queue_policy;
    assert(admission_allowed(0, 0));
    assert(admission_allowed(kMaxPendingTotal - 1,
                             kMaxPendingPerService - 1));
    assert(!admission_allowed(kMaxPendingTotal, 0));
    assert(!admission_allowed(0, kMaxPendingPerService));
    std::puts("service_queue_policy_test: all cases passed");
    return 0;
}
