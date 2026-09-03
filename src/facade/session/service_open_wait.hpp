/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <string_view>

namespace yume::embed::detail {

// Transport OPEN completion is asynchronous and can race an ABI timeout. This
// state is heap-owned by the callback, and every terminal transition is
// first-wins so a late completion cannot touch or revive the caller's wait.
class ServiceOpenWait final {
public:
    enum class Outcome {
        pending,
        accepted,
        rejected,
        cancelled,
        timed_out,
    };

    struct Result {
        Outcome outcome{Outcome::pending};
        std::string reason;
    };

    void complete(bool accepted, std::string_view reason) noexcept {
        settle(accepted ? Outcome::accepted : Outcome::rejected, reason);
    }

    void cancel(std::string_view reason) noexcept {
        settle(Outcome::cancelled, reason);
    }

    Result wait_for(std::chrono::milliseconds timeout) {
        std::unique_lock<std::mutex> lock(mu_);
        if (!cv_.wait_for(lock, timeout, [this] {
                return outcome_ != Outcome::pending;
            })) {
            // Claim the timeout while holding the same mutex as complete() and
            // cancel(). A callback which was already queued can then only
            // observe the terminal timeout state; it cannot revive the wait.
            outcome_ = Outcome::timed_out;
            reason_.clear();
        }
        return Result{outcome_, reason_};
    }

private:
    void settle(Outcome outcome, std::string_view reason) noexcept {
        bool notify = false;
        try {
            std::lock_guard<std::mutex> lock(mu_);
            if (outcome_ != Outcome::pending) {
                return;
            }
            outcome_ = outcome;
            try {
                if (reason.empty()) {
                    reason_.clear();
                } else {
                    reason_.assign(reason.data(), reason.size());
                }
            } catch (...) {
                // Preserve the terminal outcome even if retaining optional
                // peer diagnostics fails. C++ exceptions must not escape a
                // transport callback into the networking executor.
                reason_.clear();
            }
            notify = true;
        } catch (...) {
            // std::mutex::lock can theoretically report a system error. There
            // is no safe state mutation without the lock; the caller's bounded
            // timeout remains the fail-closed fallback.
        }
        if (notify) {
            cv_.notify_all();
        }
    }

    std::mutex mu_;
    std::condition_variable cv_;
    Outcome outcome_{Outcome::pending};
    std::string reason_;
};

}  // namespace yume::embed::detail
