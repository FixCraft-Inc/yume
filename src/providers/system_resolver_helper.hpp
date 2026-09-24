/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

namespace yume::providers {

// True when this process was started as a SystemResolver helper: exactly one
// argument, equal to resolver_protocol::kHelperArgv0. A program that can
// serve as its own helper checks this first in main().
bool is_system_resolver_helper(int argc, const char* const* argv) noexcept;

// Serves lookups on the inherited socketpair descriptor until the parent
// closes it, then ends the process with _Exit. Returns only when the
// descriptor is not a helper socketpair, with a nonzero exit status.
int run_system_resolver_helper() noexcept;

}  // namespace yume::providers
