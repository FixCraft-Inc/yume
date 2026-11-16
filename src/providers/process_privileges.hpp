/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

namespace yume::providers {

// Drops Linux capability sets and prevents privilege gains on exec. Returns
// true only after read-back verifies the outcome, even if a redundant drop
// syscall was refused. Unsupported platforms return false. This leaves the
// user identity and its file access unchanged. It is not a filesystem sandbox.
[[nodiscard]] bool drop_process_privileges() noexcept;

}  // namespace yume::providers
