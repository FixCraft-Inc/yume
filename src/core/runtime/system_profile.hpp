/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <cstdint>

namespace yume::runtime {

struct SystemProfile {
    unsigned logical_cpus{1};
    std::uint64_t total_memory_mib{0};
    std::uint64_t available_memory_mib{0};
};

SystemProfile detect_system_profile();

}  // namespace yume::runtime
