/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>

namespace yume::runtime {

enum class NativeCliRole : std::uint8_t {
    Client,
    Server,
};

// Runs the development yume-ytp1 or yumed-ytp1 process. Network and security
// policy come only from the schema-1 configuration. Returns the exit status:
// 0 after a requested stop, 1 for a runtime failure, 2 for usage or
// configuration errors.
int run_native_cli(NativeCliRole role, int argc, char** argv) noexcept;

}  // namespace yume::runtime
