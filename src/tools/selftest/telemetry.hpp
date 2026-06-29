/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
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

// Utilization summary used by the fair "did the machine have headroom to spare"
// scoring component. Under a YUME-bound workload, throughput saturates on the
// engine's own code, so the honest signal of hardware superiority is how much
// CPU/RAM/thermal headroom the machine retained at peak load.
struct LoadProfile {
    bool available{false};
    Stats cpu_percent;        // utilization while the benchmark ran
    Stats memory_percent;
    Stats temperature_c;
    double avg_headroom{0.0};        // headroom averaged over the whole run
    double peak_load_headroom{0.0};  // headroom retained at peak (p95) load
};

class SystemLoadSampler {
public:
    SystemLoadSampler() = default;
    ~SystemLoadSampler();

    SystemLoadSampler(const SystemLoadSampler&) = delete;
    SystemLoadSampler& operator=(const SystemLoadSampler&) = delete;

    void start();
    HotPathRow stop();

    // Valid after stop(); summarizes the samples gathered during the run.
    const LoadProfile& profile() const { return profile_; }

private:
    void loop();

    std::atomic<bool> running_{false};
    bool started_{false};
    Clock::time_point started_at_{};
    std::thread thread_;
    std::mutex samples_mutex_;
    std::vector<SystemLoadSample> samples_;
    LoadProfile profile_;
};

}  // namespace yume::tools::selftest
