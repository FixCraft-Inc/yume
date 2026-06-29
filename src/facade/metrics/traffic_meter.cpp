/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "facade/metrics/traffic_meter.hpp"

namespace yume::facade {

TrafficMeter::TrafficMeter(std::chrono::seconds window)
    : window_(window), last_tick_(std::chrono::steady_clock::now()) {}

void TrafficMeter::record_tx(std::uint64_t bytes) {
    std::lock_guard<std::mutex> lock(mtx_);
    total_tx_ += bytes;
    tx_since_tick_ += bytes;
}

void TrafficMeter::record_rx(std::uint64_t bytes) {
    std::lock_guard<std::mutex> lock(mtx_);
    total_rx_ += bytes;
    rx_since_tick_ += bytes;
}

void TrafficMeter::tick() {
    using namespace std::chrono;
    std::lock_guard<std::mutex> lock(mtx_);
    const auto now = steady_clock::now();
    const auto dt = duration_cast<duration<double>>(now - last_tick_).count();
    if (dt <= 0.0) return;

    Sample s;
    s.t = now;
    s.tx_bps = static_cast<double>(tx_since_tick_) / dt;
    s.rx_bps = static_cast<double>(rx_since_tick_) / dt;
    samples_.push_back(s);

    const auto cutoff = now - window_;
    while (!samples_.empty() && samples_.front().t < cutoff) {
        samples_.pop_front();
    }

    tx_since_tick_ = 0;
    rx_since_tick_ = 0;
    last_tick_ = now;
}

std::vector<TrafficMeter::Sample> TrafficMeter::history() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return {samples_.begin(), samples_.end()};
}

TrafficMeter::Sample TrafficMeter::latest() const {
    std::lock_guard<std::mutex> lock(mtx_);
    if (samples_.empty()) return {};
    return samples_.back();
}

std::uint64_t TrafficMeter::total_tx() const noexcept {
    std::lock_guard<std::mutex> lock(mtx_);
    return total_tx_;
}

std::uint64_t TrafficMeter::total_rx() const noexcept {
    std::lock_guard<std::mutex> lock(mtx_);
    return total_rx_;
}

void TrafficMeter::reset() {
    std::lock_guard<std::mutex> lock(mtx_);
    total_tx_ = total_rx_ = 0;
    tx_since_tick_ = rx_since_tick_ = 0;
    samples_.clear();
    last_tick_ = std::chrono::steady_clock::now();
}

}  // namespace yume::facade
