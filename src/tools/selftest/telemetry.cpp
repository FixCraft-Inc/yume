/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "tools/selftest/telemetry.hpp"

#include "tools/selftest/runtime.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <numeric>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace yume::tools::selftest {
namespace {
namespace fs = std::filesystem;

struct CpuSnapshot {
    std::uint64_t idle{0};
    std::uint64_t total{0};
};

std::optional<CpuSnapshot> read_cpu_snapshot() {
    std::ifstream in("/proc/stat");
    std::string tag;
    in >> tag;
    if (!in || tag != "cpu") {
        return std::nullopt;
    }
    std::vector<std::uint64_t> fields;
    std::uint64_t value = 0;
    while (in >> value) {
        fields.push_back(value);
        if (fields.size() >= 10) {
            break;
        }
    }
    if (fields.size() < 4) {
        return std::nullopt;
    }
    const std::uint64_t idle = fields[3] + (fields.size() > 4 ? fields[4] : 0);
    const std::uint64_t total = std::accumulate(fields.begin(), fields.end(), std::uint64_t{0});
    if (total == 0) {
        return std::nullopt;
    }
    return CpuSnapshot{idle, total};
}

double cpu_load_percent(const CpuSnapshot& before, const CpuSnapshot& after) {
    if (after.total <= before.total || after.idle < before.idle) {
        return -1.0;
    }
    const double total_delta = static_cast<double>(after.total - before.total);
    const double idle_delta = static_cast<double>(after.idle - before.idle);
    if (total_delta <= 0.0) {
        return -1.0;
    }
    return std::clamp((1.0 - (idle_delta / total_delta)) * 100.0, 0.0, 100.0);
}

std::optional<double> read_memory_used_percent() {
    std::ifstream in("/proc/meminfo");
    std::string key;
    std::uint64_t value_kib = 0;
    std::string unit;
    std::uint64_t total_kib = 0;
    std::uint64_t available_kib = 0;
    while (in >> key >> value_kib >> unit) {
        if (key == "MemTotal:") {
            total_kib = value_kib;
        } else if (key == "MemAvailable:") {
            available_kib = value_kib;
        }
        if (total_kib > 0 && available_kib > 0) {
            break;
        }
    }
    if (total_kib == 0 || available_kib > total_kib) {
        return std::nullopt;
    }
    return (1.0 - (static_cast<double>(available_kib) / static_cast<double>(total_kib))) * 100.0;
}

std::optional<double> read_max_temperature_c() {
    std::error_code ec;
    const fs::path thermal_root = "/sys/class/thermal";
    if (!fs::exists(thermal_root, ec)) {
        return std::nullopt;
    }
    double max_temp = -1.0;
    for (const auto& entry : fs::directory_iterator(thermal_root, ec)) {
        if (ec) {
            break;
        }
        const fs::path temp_path = entry.path() / "temp";
        std::ifstream in(temp_path);
        double raw = 0.0;
        if (!(in >> raw)) {
            continue;
        }
        const double celsius = raw > 1000.0 ? raw / 1000.0 : raw;
        if (celsius >= 1.0 && celsius <= 140.0) {
            max_temp = std::max(max_temp, celsius);
        }
    }
    if (max_temp < 0.0) {
        return std::nullopt;
    }
    return max_temp;
}

Stats stats_for(const std::vector<SystemLoadSample>& samples,
                double SystemLoadSample::*field) {
    std::vector<double> values;
    values.reserve(samples.size());
    for (const auto& sample : samples) {
        const double value = sample.*field;
        if (value >= 0.0) {
            values.push_back(value);
        }
    }
    return compute_stats(std::move(values));
}

void append_stat(std::ostringstream& out,
                 std::string_view name,
                 const Stats& stats,
                 std::string_view unit) {
    if (stats.n == 0) {
        out << name << "=unavailable";
        return;
    }
    out << name << "_min=" << std::fixed << std::setprecision(1) << stats.min << unit
        << " " << name << "_avg=" << stats.mean << unit
        << " " << name << "_max=" << stats.max << unit;
}

double load_headroom_percent(const Stats& cpu, const Stats& memory, const Stats& temp) {
    const double cpu_avg_headroom = cpu.n > 0 ? std::clamp(100.0 - cpu.mean, 0.0, 100.0) : 0.0;
    const double cpu_burst_headroom = cpu.n > 0 ? std::clamp(100.0 - cpu.max, 0.0, 100.0) : cpu_avg_headroom;
    const double mem_headroom = memory.n > 0 ? std::clamp(100.0 - memory.mean, 0.0, 100.0) : 50.0;
    const double temp_headroom = temp.n > 0 ? std::clamp(((90.0 - temp.max) / 60.0) * 100.0, 0.0, 100.0) : 50.0;
    return (cpu_avg_headroom * 0.55) +
           (cpu_burst_headroom * 0.15) +
           (mem_headroom * 0.20) +
           (temp_headroom * 0.10);
}

}  // namespace

SystemLoadSampler::~SystemLoadSampler() {
    if (started_) {
        (void)stop();
    }
}

void SystemLoadSampler::start() {
    if (started_) {
        return;
    }
    started_ = true;
    running_.store(true, std::memory_order_release);
    started_at_ = Clock::now();
    thread_ = std::thread([this] { loop(); });
}

HotPathRow SystemLoadSampler::stop() {
    if (started_) {
        running_.store(false, std::memory_order_release);
        if (thread_.joinable()) {
            thread_.join();
        }
        started_ = false;
    }

    std::vector<SystemLoadSample> samples;
    {
        std::lock_guard<std::mutex> lock(samples_mutex_);
        samples = samples_;
    }

    const Stats cpu = stats_for(samples, &SystemLoadSample::cpu_percent);
    const Stats memory = stats_for(samples, &SystemLoadSample::memory_used_percent);
    const Stats temp = stats_for(samples, &SystemLoadSample::temperature_c);
    const double seconds = elapsed_s(started_at_, Clock::now());

    const double headroom = load_headroom_percent(cpu, memory, temp);

    std::ostringstream metric;
    metric << std::fixed << std::setprecision(1) << headroom << "% headroom";

    std::ostringstream detail;
    detail << "samples=" << samples.size() << " ";
    append_stat(detail, "cpu", cpu, "%");
    detail << " ";
    append_stat(detail, "mem_used", memory, "%");
    detail << " ";
    append_stat(detail, "temp_c", temp, "C");

    return {
        "system-load",
        metric.str(),
        detail.str(),
        !samples.empty(),
        headroom,
        "%",
        0,
        static_cast<std::uint64_t>(samples.size()),
        seconds,
    };
}

void SystemLoadSampler::loop() {
    auto previous_cpu = read_cpu_snapshot();
    while (running_.load(std::memory_order_acquire)) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        SystemLoadSample sample;
        const auto current_cpu = read_cpu_snapshot();
        if (previous_cpu && current_cpu) {
            sample.cpu_percent = cpu_load_percent(*previous_cpu, *current_cpu);
        }
        previous_cpu = current_cpu;
        if (const auto memory = read_memory_used_percent()) {
            sample.memory_used_percent = *memory;
        }
        if (const auto temp = read_max_temperature_c()) {
            sample.temperature_c = *temp;
        }
        std::lock_guard<std::mutex> lock(samples_mutex_);
        samples_.push_back(sample);
    }
}

}  // namespace yume::tools::selftest
