/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <mutex>
#include <vector>

namespace yume::facade {

// Tracks rolling bytes-per-second rates over a sliding window for the
// dashboard's traffic graph. Thread-safe; cheap to record and read.
class TrafficMeter {
public:
    struct Sample {
        std::chrono::steady_clock::time_point t;
        double tx_bps{0.0};
        double rx_bps{0.0};
    };

    explicit TrafficMeter(std::chrono::seconds window = std::chrono::seconds{60});

    void record_tx(std::uint64_t bytes);
    void record_rx(std::uint64_t bytes);

    // Computes the current rate and appends a sample. Call once per UI
    // frame; safe to call from any thread.
    void tick();

    std::vector<Sample> history() const;
    Sample latest() const;

    std::uint64_t total_tx() const noexcept;
    std::uint64_t total_rx() const noexcept;
    void reset();

private:
    mutable std::mutex mtx_;
    std::chrono::seconds window_;
    std::chrono::steady_clock::time_point last_tick_{};

    std::uint64_t total_tx_{0};
    std::uint64_t total_rx_{0};
    std::uint64_t tx_since_tick_{0};
    std::uint64_t rx_since_tick_{0};

    std::deque<Sample> samples_;
};

}  // namespace yume::facade
