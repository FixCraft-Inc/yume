/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "system_profile.hpp"

#include <algorithm>
#include <thread>

#if !defined(_WIN32)
#include <unistd.h>
#endif

namespace yume::runtime {

namespace {

std::uint64_t pages_to_mib(long pages, long page_size) {
    if (pages <= 0 || page_size <= 0) {
        return 0;
    }
    const auto bytes = static_cast<unsigned long long>(pages) *
                       static_cast<unsigned long long>(page_size);
    return static_cast<std::uint64_t>(bytes / (1024ull * 1024ull));
}

}  // namespace

SystemProfile detect_system_profile() {
    SystemProfile profile;
    profile.logical_cpus = std::max(1u, std::thread::hardware_concurrency());

#if !defined(_WIN32)
    const long page_size = ::sysconf(_SC_PAGESIZE);
    profile.total_memory_mib = pages_to_mib(::sysconf(_SC_PHYS_PAGES), page_size);
#if defined(_SC_AVPHYS_PAGES)
    profile.available_memory_mib = pages_to_mib(::sysconf(_SC_AVPHYS_PAGES), page_size);
#endif
#endif

    if (profile.available_memory_mib == 0 && profile.total_memory_mib > 0) {
        profile.available_memory_mib = profile.total_memory_mib / 2;
    }
    return profile;
}

}  // namespace yume::runtime
