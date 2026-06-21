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
std::uint64_t usable_memory_mib(const SystemProfile& profile);
double resource_cap_ratio_from_env(const char* name = "YUME_RESOURCE_CAP", double fallback = 0.84);
unsigned scaled_thread_count(const SystemProfile& profile,
                             double cap_ratio,
                             unsigned fallback,
                             unsigned min_value,
                             unsigned max_value);
std::uint64_t memory_budget_mib(const SystemProfile& profile,
                                double cap_ratio,
                                std::uint64_t fallback_mib,
                                std::uint64_t max_mib);

}  // namespace yume::runtime
