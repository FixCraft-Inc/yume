/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <thread>
#include <vector>

#include "tools/selftest/hotpath.hpp"

namespace yume::tools::selftest {

struct SystemLoadSample {
    double cpu_percent{-1.0};
    double memory_used_percent{-1.0};
    double temperature_c{-1.0};
};

class SystemLoadSampler {
public:
    SystemLoadSampler() = default;
    ~SystemLoadSampler();

    SystemLoadSampler(const SystemLoadSampler&) = delete;
    SystemLoadSampler& operator=(const SystemLoadSampler&) = delete;

    void start();
    HotPathRow stop();

private:
    void loop();

    std::atomic<bool> running_{false};
    bool started_{false};
    Clock::time_point started_at_{};
    std::thread thread_;
    std::mutex samples_mutex_;
    std::vector<SystemLoadSample> samples_;
};

}  // namespace yume::tools::selftest
