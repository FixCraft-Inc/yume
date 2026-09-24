/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

namespace yume::providers {

// Best effort for a helper or module that needs no privilege: no new
// privileges on exec, no ambient capabilities and an empty capability set.
// yume and yumed may hold CAP_NET_BIND_SERVICE or CAP_NET_ADMIN, or run as
// root. Where the kernel or a sandbox refuses, the process keeps what it had.
void drop_process_privileges() noexcept;

}  // namespace yume::providers
