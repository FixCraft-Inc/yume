/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/diagnostics/timing.hpp"

#if YUME_ENABLE_DEV_DIAGNOSTICS

#include <atomic>
#include "util.hpp"

namespace yume::diagnostics {
namespace {

std::atomic<bool> g_timing_forced{false};
std::atomic<bool> g_timing_enabled{false};

bool timing_env_enabled() {
    return util::env_flag("YUME_TIMING", false) ||
           util::env_flag("YUME_TRACE_TIMING", false) ||
           util::env_flag("YUME_PROFILE", false);
}

}  // namespace

void set_timing_enabled(bool enabled) noexcept {
    g_timing_enabled.store(enabled, std::memory_order_relaxed);
    g_timing_forced.store(true, std::memory_order_relaxed);
}

bool timing_enabled() noexcept {
    if (g_timing_forced.load(std::memory_order_relaxed)) {
        return g_timing_enabled.load(std::memory_order_relaxed);
    }
    return timing_env_enabled();
}

void log_timing(const std::string& component,
                const std::string& event,
                const std::string& details) {
    if (!timing_enabled()) return;
    std::string message = "timing component=" + component + " event=" + event;
    if (!details.empty()) {
        message += " ";
        message += details;
    }
    util::log_info(message);
}

}  // namespace yume::diagnostics

#endif
