/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <functional>
#include <mutex>
#include <vector>

#include "facade/status.hpp"

namespace yume::facade {

// Lock-protected ring buffer of recent log entries plus an optional spdlog
// sink that mirrors application logs into the buffer. The first call to
// instance() installs the spdlog sink lazily.
//
// Designed for low-volume diagnostic logs (a few hundred per second peak).
// Snapshots copy into a vector; subscribers are notified synchronously and
// must marshal across threads themselves.
class LogSink {
public:
    static LogSink& instance();

    // Returns up to `max` most recent entries, oldest first.
    std::vector<LogEntry> snapshot(std::size_t max = 1000) const;

    // Number of entries dropped due to ring buffer overflow.
    std::size_t dropped() const noexcept;

    void clear();

    using Subscriber = std::function<void(LogEntry const&)>;

    // Adds a live-tail subscriber. Returns an opaque token used with
    // unsubscribe(). Callbacks run on the emitter thread; subscribers
    // are responsible for marshalling to whichever thread they need.
    int subscribe(Subscriber cb);
    void unsubscribe(int token);

    // Directly push an entry (used by adapters that aren't using spdlog).
    void push(LogEntry entry);

private:
    LogSink();
    LogSink(LogSink const&) = delete;
    LogSink& operator=(LogSink const&) = delete;

    void install_spdlog_sink();

    static constexpr std::size_t kCapacity = 4096;

    mutable std::mutex mtx_;
    std::vector<LogEntry> ring_;
    std::size_t head_{0};
    std::size_t size_{0};
    std::size_t dropped_{0};

    int next_token_{1};
    std::vector<std::pair<int, Subscriber>> subscribers_;
};

}  // namespace yume::facade
