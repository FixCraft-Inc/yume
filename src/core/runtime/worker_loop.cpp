/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/runtime/worker_loop.hpp"

#include <cstdint>
#include <exception>
#include <string>

#include "util.hpp"

namespace yume::runtime {

namespace {

// One log line per role per interval. A peer that can provoke repeated throws
// must not also be able to fill the disk through this path.
constexpr std::int64_t kContainedLogIntervalMs = 5000;

void note_contained(const char* label,
                    std::atomic<std::size_t>* contained,
                    const char* detail) noexcept {
    if (contained) {
        contained->fetch_add(1, std::memory_order_relaxed);
    }
    try {
        util::log_warn_rate_limited(
            std::string("worker-exception:") + label,
            std::string(label) + " worker contained a completion-handler exception; "
                    "session cleanup is not established: " + detail,
            kContainedLogIntervalMs);
    } catch (...) {
        // Logging must never be the reason a worker dies.
    }
}

}  // namespace

void run_worker(boost::asio::io_context& io,
                const char* role,
                std::atomic<std::size_t>* contained) noexcept {
    const char* label = role ? role : "worker";
    for (;;) {
        try {
            io.run();
            return;  // no more work and nothing threw: ordinary exit
        } catch (const std::exception& ex) {
            note_contained(label, contained, ex.what());
        } catch (...) {
            note_contained(label, contained, "non-standard exception");
        }
    }
}

}  // namespace yume::runtime
