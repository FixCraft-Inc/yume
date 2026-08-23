/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

#ifndef YUME_ENABLE_DEV_DIAGNOSTICS
#define YUME_ENABLE_DEV_DIAGNOSTICS 0
#endif

namespace yume::diagnostics {

inline constexpr bool kTimingCompiledIn =
    YUME_ENABLE_DEV_DIAGNOSTICS != 0;

#if YUME_ENABLE_DEV_DIAGNOSTICS
void set_timing_enabled(bool enabled) noexcept;
bool timing_enabled() noexcept;
void log_timing(const std::string& component,
                const std::string& event,
                const std::string& details = {});
#else
inline constexpr void set_timing_enabled(bool) noexcept {}
inline constexpr bool timing_enabled() noexcept { return false; }
#endif

// Wall-clock stamps for stream-lifecycle diagnostics.
//
// These exist so a Release binary reads no clock for telemetry it will never
// emit. `YUME_TIMING_LOG` compiles away in Release, but a bare
// `util::now_ms()` feeding it does not -- the call still happens and the
// result is discarded. Route every diagnostics-only stamp through these two
// helpers instead: in Release they are `constexpr` zero, and in a diagnostics
// build they still read nothing until `--timing` / `YUME_TIMING` turns
// collection on.
//
// A stamp of 0 means "never taken", which is what `elapsed_ms_since` reports
// as an elapsed value of 0. Never use these for timeouts, expiry, protocol
// fields, or anything a user can observe -- they legitimately return 0. Real
// functional timestamps keep using `util::now_ms()`.
#if YUME_ENABLE_DEV_DIAGNOSTICS
std::int64_t timing_now_ms() noexcept;
#else
inline constexpr std::int64_t timing_now_ms() noexcept { return 0; }
#endif

inline std::int64_t elapsed_ms_since(std::int64_t started_ms) noexcept {
#if YUME_ENABLE_DEV_DIAGNOSTICS
    if (started_ms <= 0) return 0;
    const std::int64_t now = timing_now_ms();
    return now > started_ms ? now - started_ms : 0;
#else
    (void)started_ms;
    return 0;
#endif
}

class Stopwatch {
public:
    using Clock = std::chrono::steady_clock;

    explicit Stopwatch(bool active) noexcept
#if YUME_ENABLE_DEV_DIAGNOSTICS
        : active_(active), started_(active ? Clock::now() : Clock::time_point{})
#endif
    {
#if !YUME_ENABLE_DEV_DIAGNOSTICS
        (void)active;
#endif
    }

    bool active() const noexcept {
#if YUME_ENABLE_DEV_DIAGNOSTICS
        return active_;
#else
        return false;
#endif
    }

    std::uint64_t elapsed_ns() const noexcept {
#if YUME_ENABLE_DEV_DIAGNOSTICS
        if (!active_) return 0;
        return static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(
                Clock::now() - started_).count());
#else
        return 0;
#endif
    }

private:
#if YUME_ENABLE_DEV_DIAGNOSTICS
    bool active_{false};
    Clock::time_point started_{};
#endif
};

struct TimingSample {
    std::uint64_t count{0};
    std::uint64_t total_ns{0};
};

// Reusable batching for hot-path samples. In production builds the class is
// empty and every method is a compile-time no-op.
class SampleAccumulator {
public:
    explicit SampleAccumulator(bool active = false) noexcept
#if YUME_ENABLE_DEV_DIAGNOSTICS
        : active_(active)
#endif
    {
#if !YUME_ENABLE_DEV_DIAGNOSTICS
        (void)active;
#endif
    }

    void set_active(bool active) noexcept {
#if YUME_ENABLE_DEV_DIAGNOSTICS
        active_ = active;
#else
        (void)active;
#endif
    }

    void record(const Stopwatch& stopwatch) noexcept {
#if YUME_ENABLE_DEV_DIAGNOSTICS
        if (!active_ || !stopwatch.active()) return;
        total_ns_ += stopwatch.elapsed_ns();
        ++count_;
#else
        (void)stopwatch;
#endif
    }

    std::optional<TimingSample> take_if(std::size_t minimum_count,
                                        bool force = false) noexcept {
#if YUME_ENABLE_DEV_DIAGNOSTICS
        if (!active_ || count_ == 0 || (!force && count_ < minimum_count)) {
            return std::nullopt;
        }
        TimingSample sample{count_, total_ns_};
        count_ = 0;
        total_ns_ = 0;
        return sample;
#else
        (void)minimum_count;
        (void)force;
        return std::nullopt;
#endif
    }

    void reset() noexcept {
#if YUME_ENABLE_DEV_DIAGNOSTICS
        count_ = 0;
        total_ns_ = 0;
#endif
    }

private:
#if YUME_ENABLE_DEV_DIAGNOSTICS
    bool active_{false};
    std::uint64_t count_{0};
    std::uint64_t total_ns_{0};
#endif
};

// Tracks an asynchronous wait such as INIT -> ACK without duplicating
// optional<time_point> bookkeeping at each transport boundary.
class IntervalTimer {
public:
    using Clock = std::chrono::steady_clock;

    void start_if(bool active, Clock::time_point now) noexcept {
#if YUME_ENABLE_DEV_DIAGNOSTICS
        if (active && !started_.has_value()) started_ = now;
#else
        (void)active;
        (void)now;
#endif
    }

    std::optional<std::uint64_t> finish_us(Clock::time_point now) noexcept {
#if YUME_ENABLE_DEV_DIAGNOSTICS
        if (!started_.has_value()) return std::nullopt;
        const auto elapsed = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                now - *started_).count());
        started_.reset();
        return elapsed;
#else
        (void)now;
        return std::nullopt;
#endif
    }

    void reset() noexcept {
#if YUME_ENABLE_DEV_DIAGNOSTICS
        started_.reset();
#endif
    }

private:
#if YUME_ENABLE_DEV_DIAGNOSTICS
    std::optional<Clock::time_point> started_;
#endif
};

}  // namespace yume::diagnostics

#if YUME_ENABLE_DEV_DIAGNOSTICS
#define YUME_TIMING_ENABLED() (::yume::diagnostics::timing_enabled())
#define YUME_TIMING_LOG(component, event, details)                         \
    do {                                                                  \
        if (::yume::diagnostics::timing_enabled()) {                      \
            ::yume::diagnostics::log_timing((component), (event),         \
                                             (details));                   \
        }                                                                 \
    } while (false)
#define YUME_TIMING_SINK(sink, component, event, details)                 \
    do {                                                                  \
        if (sink) {                                                       \
            (sink)((component), (event), (details));                      \
        }                                                                 \
    } while (false)
#else
#define YUME_TIMING_ENABLED() false
#define YUME_TIMING_LOG(component, event, details) do { } while (false)
#define YUME_TIMING_SINK(sink, component, event, details) do { } while (false)
#endif
