/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>

#ifndef YUME_ENABLE_DEV_DIAGNOSTICS
#define YUME_ENABLE_DEV_DIAGNOSTICS 0
#endif

#if YUME_ENABLE_DEV_DIAGNOSTICS
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <thread>
#include <unistd.h>
#endif

// Benchmark probes count and time the key rotations and the records that wait
// for them. They exist only in a build configured with
// -DYUME_DEV_DIAGNOSTICS=ON. Every other build compiles each probe to nothing:
// the types below are empty and no clock is read. A probe build records only
// when YUME_BENCH_PROBE_FILE names a file prefix at start. It then appends
// one JSON line of cumulative totals per second, and a last one at exit, to
// PREFIX.PID. The totals hold counts, durations and byte counts, never keys,
// payload or addresses.
namespace yume::bench_probe {

inline constexpr bool kEnabled = YUME_ENABLE_DEV_DIAGNOSTICS != 0;

enum class Count : std::uint8_t {
    // A rotation started because its epoch used half of its bytes, half of
    // its records or half of its send lifetime, or from the endpoint's age
    // timer or a peer's REKEY_INIT (rotate_aged_epoch).
    RotationBytes,
    RotationRecords,
    RotationAge,
    RotationAged,
    // Records and payload bytes that waited for a new epoch.
    DeferredRecords,
    DeferredBytes,
    kSize,
};

enum class Duration : std::uint8_t {
    // Provider work: INIT creation, INIT acceptance with the ACK, and ACK
    // verification on the initiator.
    ProviderBeginRekey,
    ProviderAcceptRekey,
    ProviderFinishRekey,
    // From a rotation's start to its verified ACK.
    RotationRoundTrip,
    // From the first record that had to wait in a rotation to its flush.
    DeferredStall,
    kSize,
};

enum class Amount : std::uint8_t {
    // Payload bytes of the epoch when its rotation started, and when its
    // ACK switched the sender to the next epoch.
    EpochBytesAtStart,
    EpochBytesAtSwitch,
    kSize,
};

#if YUME_ENABLE_DEV_DIAGNOSTICS

inline std::uint64_t now_ns() noexcept {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch())
            .count());
}

namespace detail {

inline constexpr const char* kCountNames[] = {
    "rotation_bytes", "rotation_records", "rotation_age",
    "rotation_aged",  "deferred_records", "deferred_bytes"};
inline constexpr const char* kDurationNames[] = {
    "provider_begin_rekey", "provider_accept_rekey", "provider_finish_rekey",
    "rotation_round_trip", "deferred_stall"};
inline constexpr const char* kAmountNames[] = {"epoch_bytes_at_start",
                                               "epoch_bytes_at_switch"};
static_assert(std::size(kCountNames) == static_cast<std::size_t>(Count::kSize));
static_assert(std::size(kDurationNames) ==
              static_cast<std::size_t>(Duration::kSize));
static_assert(std::size(kAmountNames) ==
              static_cast<std::size_t>(Amount::kSize));

// Count, sum, maximum and a power-of-two histogram: bucket i holds values
// below 2^i, so durations in nanoseconds and byte counts share one shape.
struct Series {
    std::atomic<std::uint64_t> count{0};
    std::atomic<std::uint64_t> sum{0};
    std::atomic<std::uint64_t> max{0};
    std::array<std::atomic<std::uint64_t>, 64> buckets{};

    void add(std::uint64_t value) noexcept {
        count.fetch_add(1, std::memory_order_relaxed);
        sum.fetch_add(value, std::memory_order_relaxed);
        std::uint64_t seen = max.load(std::memory_order_relaxed);
        while (value > seen && !max.compare_exchange_weak(
                                   seen, value, std::memory_order_relaxed)) {
        }
        std::size_t bucket = 0;
        while (bucket < 63 && (value >> bucket) != 0) ++bucket;
        buckets[bucket].fetch_add(1, std::memory_order_relaxed);
    }
};

class Recorder {
public:
    Recorder() {
        const char* prefix = std::getenv("YUME_BENCH_PROBE_FILE");
        if (prefix == nullptr || *prefix == '\0') return;
        const std::string path =
            std::string(prefix) + "." + std::to_string(::getpid());
        file_ = std::fopen(path.c_str(), "a");
        if (file_ == nullptr) return;
        started_ns_ = now_ns();
        writer_ = std::thread([this] { run(); });
    }

    ~Recorder() {
        if (file_ == nullptr) return;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stopping_ = true;
        }
        wake_.notify_all();
        if (writer_.joinable()) writer_.join();
        write_snapshot(true);
        std::fclose(file_);
    }

    Recorder(const Recorder&) = delete;
    Recorder& operator=(const Recorder&) = delete;

    bool active() const noexcept { return file_ != nullptr; }

    void count(Count which, std::uint64_t amount) noexcept {
        counts_[static_cast<std::size_t>(which)].fetch_add(
            amount, std::memory_order_relaxed);
    }
    void duration(Duration which, std::uint64_t ns) noexcept {
        durations_[static_cast<std::size_t>(which)].add(ns);
    }
    void amount(Amount which, std::uint64_t value) noexcept {
        amounts_[static_cast<std::size_t>(which)].add(value);
    }

private:
    void run() {
        std::unique_lock<std::mutex> lock(mutex_);
        while (!wake_.wait_for(lock, std::chrono::seconds(1),
                               [this] { return stopping_; })) {
            lock.unlock();
            write_snapshot(false);
            lock.lock();
        }
    }

    static void write_series(std::FILE* file, const char* name,
                             const Series& series) {
        std::fprintf(file,
                     ",\"%s\":{\"count\":%llu,\"sum\":%llu,\"max\":%llu,"
                     "\"log2\":[",
                     name,
                     static_cast<unsigned long long>(
                         series.count.load(std::memory_order_relaxed)),
                     static_cast<unsigned long long>(
                         series.sum.load(std::memory_order_relaxed)),
                     static_cast<unsigned long long>(
                         series.max.load(std::memory_order_relaxed)));
        std::size_t last = 0;
        for (std::size_t i = 0; i < series.buckets.size(); ++i)
            if (series.buckets[i].load(std::memory_order_relaxed) != 0)
                last = i + 1;
        for (std::size_t i = 0; i < last; ++i)
            std::fprintf(file, "%s%llu", i ? "," : "",
                         static_cast<unsigned long long>(series.buckets[i].load(
                             std::memory_order_relaxed)));
        std::fputs("]}", file);
    }

    void write_snapshot(bool final) {
        std::fprintf(file_, "{\"t_ns\":%llu,\"final\":%s",
                     static_cast<unsigned long long>(now_ns() - started_ns_),
                     final ? "true" : "false");
        for (std::size_t i = 0; i < counts_.size(); ++i)
            std::fprintf(file_, ",\"%s\":%llu", kCountNames[i],
                         static_cast<unsigned long long>(
                             counts_[i].load(std::memory_order_relaxed)));
        for (std::size_t i = 0; i < durations_.size(); ++i)
            write_series(file_, kDurationNames[i], durations_[i]);
        for (std::size_t i = 0; i < amounts_.size(); ++i)
            write_series(file_, kAmountNames[i], amounts_[i]);
        std::fputs("}\n", file_);
        std::fflush(file_);
    }

    std::FILE* file_{nullptr};
    std::uint64_t started_ns_{0};
    std::array<std::atomic<std::uint64_t>,
               static_cast<std::size_t>(Count::kSize)>
        counts_{};
    std::array<Series, static_cast<std::size_t>(Duration::kSize)> durations_{};
    std::array<Series, static_cast<std::size_t>(Amount::kSize)> amounts_{};
    std::mutex mutex_;
    std::condition_variable wake_;
    bool stopping_{false};
    std::thread writer_;
};

inline Recorder& recorder() {
    static Recorder instance;
    return instance;
}

// Opens the file before main, ahead of any privilege change.
inline const bool kRecorderStarted = (recorder(), true);

}  // namespace detail

inline void count(Count which, std::uint64_t amount = 1) noexcept {
    auto& recorder = detail::recorder();
    if (recorder.active()) recorder.count(which, amount);
}

inline void duration(Duration which, std::uint64_t ns) noexcept {
    auto& recorder = detail::recorder();
    if (recorder.active()) recorder.duration(which, ns);
}

inline void amount(Amount which, std::uint64_t value) noexcept {
    auto& recorder = detail::recorder();
    if (recorder.active()) recorder.amount(which, value);
}

// A point in time to measure a later duration from. Empty until set.
class Stamp {
public:
    void set() noexcept { ns_ = now_ns(); }
    void set_if_unset() noexcept {
        if (ns_ == 0) ns_ = now_ns();
    }
    // Records the time since set() and clears the stamp.
    void finish(Duration which) noexcept {
        if (ns_ == 0) return;
        duration(which, now_ns() - ns_);
        ns_ = 0;
    }

private:
    std::uint64_t ns_{0};
};

// Times its own scope.
class ScopedDuration {
public:
    explicit ScopedDuration(Duration which) noexcept
        : which_(which), started_(now_ns()) {}
    ~ScopedDuration() { duration(which_, now_ns() - started_); }
    ScopedDuration(const ScopedDuration&) = delete;
    ScopedDuration& operator=(const ScopedDuration&) = delete;

private:
    Duration which_;
    std::uint64_t started_;
};

#else

inline constexpr void count(Count, std::uint64_t = 1) noexcept {}
inline constexpr void duration(Duration, std::uint64_t) noexcept {}
inline constexpr void amount(Amount, std::uint64_t) noexcept {}

class Stamp {
public:
    constexpr void set() noexcept {}
    constexpr void set_if_unset() noexcept {}
    constexpr void finish(Duration) noexcept {}
};

class ScopedDuration {
public:
    explicit constexpr ScopedDuration(Duration) noexcept {}
    ScopedDuration(const ScopedDuration&) = delete;
    ScopedDuration& operator=(const ScopedDuration&) = delete;
};

#endif

}  // namespace yume::bench_probe
