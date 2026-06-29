/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "system_profile.hpp"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <limits>
#include <string>
#include <thread>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__APPLE__)
#include <sys/sysctl.h>
#include <unistd.h>
#else
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

std::uint64_t bytes_to_mib(std::uint64_t bytes) {
    return bytes / (1024ull * 1024ull);
}

}  // namespace

SystemProfile detect_system_profile() {
    SystemProfile profile;
    profile.logical_cpus = std::max(1u, std::thread::hardware_concurrency());

#if defined(_WIN32)
    MEMORYSTATUSEX status{};
    status.dwLength = sizeof(status);
    if (GlobalMemoryStatusEx(&status)) {
        profile.total_memory_mib = bytes_to_mib(static_cast<std::uint64_t>(status.ullTotalPhys));
        profile.available_memory_mib = bytes_to_mib(static_cast<std::uint64_t>(status.ullAvailPhys));
    }
#elif defined(__APPLE__)
    std::uint64_t mem = 0;
    size_t len = sizeof(mem);
    if (sysctlbyname("hw.memsize", &mem, &len, nullptr, 0) == 0) {
        profile.total_memory_mib = bytes_to_mib(mem);
    }
    const long page_size = ::sysconf(_SC_PAGESIZE);
#if defined(_SC_AVPHYS_PAGES)
    profile.available_memory_mib = pages_to_mib(::sysconf(_SC_AVPHYS_PAGES), page_size);
#endif
#else
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

std::uint64_t usable_memory_mib(const SystemProfile& profile) {
    if (profile.available_memory_mib > 0) {
        return profile.available_memory_mib;
    }
    if (profile.total_memory_mib > 0) {
        return profile.total_memory_mib / 2;
    }
    return 0;
}

double resource_cap_ratio_from_env(const char* name, double fallback) {
    const char* raw = std::getenv(name);
    if (!raw || !*raw) {
        return fallback;
    }
    try {
        double parsed = std::stod(raw);
        if (parsed <= 0.0) {
            return fallback;
        }
        if (parsed > 1.0) {
            parsed /= 100.0;
        }
        if (parsed <= 0.0) {
            return fallback;
        }
        return std::min(parsed, 1.0);
    } catch (...) {
        return fallback;
    }
}

unsigned scaled_thread_count(const SystemProfile& profile,
                             double cap_ratio,
                             unsigned fallback,
                             unsigned min_value,
                             unsigned max_value) {
    const unsigned cpus = profile.logical_cpus > 0 ? profile.logical_cpus : fallback;
    unsigned scaled = static_cast<unsigned>(std::floor(static_cast<double>(std::max(1u, cpus)) * cap_ratio));
    if (scaled == 0) {
        scaled = std::max(1u, fallback);
    }
    const unsigned high = max_value > 0 ? max_value : std::numeric_limits<unsigned>::max();
    return std::clamp(scaled, std::max(1u, min_value), high);
}

std::uint64_t memory_budget_mib(const SystemProfile& profile,
                                double cap_ratio,
                                std::uint64_t fallback_mib,
                                std::uint64_t max_mib) {
    const std::uint64_t usable = usable_memory_mib(profile);
    std::uint64_t budget = fallback_mib;
    if (usable > 0) {
        budget = static_cast<std::uint64_t>(std::floor(static_cast<double>(usable) * cap_ratio));
        if (budget == 0) {
            budget = usable;
        }
    }
    if (max_mib > 0) {
        budget = std::min(budget, max_mib);
    }
    return budget;
}

}  // namespace yume::runtime
