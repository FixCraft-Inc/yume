/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * Benchmark workload sizing.
 */

#include "tools/selftest/sizing.hpp"

#include <algorithm>

namespace yume::tools::selftest {

std::uint64_t mib_to_bytes(std::uint64_t mib) {
    return mib * static_cast<std::uint64_t>(kMiB);
}

std::uint64_t bytes_to_mib(std::uint64_t bytes) {
    return bytes / static_cast<std::uint64_t>(kMiB);
}

std::uint64_t profile_available_mib(const yume::runtime::SystemProfile& profile) {
    const std::uint64_t detected = yume::runtime::usable_memory_mib(profile);
    return detected > 0 ? detected : 4096;
}

BenchmarkSizing compute_benchmark_sizing(const Args& args, const yume::runtime::SystemProfile& profile) {
    BenchmarkSizing sizing;
    if (!args.full_benchmark) {
        return sizing;
    }

    sizing.hot_threads = std::clamp(static_cast<int>(profile.logical_cpus), 1, 256);
    const std::uint64_t available_mib = profile_available_mib(profile);
    const std::uint64_t target_working_set_mib = std::clamp<std::uint64_t>(
        available_mib / 4,
        512,
        16384);
    const std::uint64_t per_thread_chunk_mib = std::clamp<std::uint64_t>(
        target_working_set_mib / static_cast<std::uint64_t>(std::max(1, sizing.hot_threads * 2)),
        2,
        256);
    const std::uint64_t parallel_payload_mib = std::clamp<std::uint64_t>(
        static_cast<std::uint64_t>(sizing.hot_threads) * 256,
        1024,
        16384);

    sizing.copy_bytes = mib_to_bytes(std::clamp<std::uint64_t>(available_mib / 32, 1024, 4096));
    sizing.stream_single_bytes = mib_to_bytes(std::clamp<std::uint64_t>(available_mib / 64, 512, 2048));
    sizing.stream_many_bytes = mib_to_bytes(std::clamp<std::uint64_t>(available_mib / 16, 2048, 8192));
    sizing.memory_bytes = mib_to_bytes(std::clamp<std::uint64_t>(target_working_set_mib * 2, 2048, 32768));
    sizing.memory_chunk_bytes = static_cast<std::size_t>(mib_to_bytes(per_thread_chunk_mib));
    sizing.crypto_bytes = mib_to_bytes(parallel_payload_mib);
    sizing.packet_bytes = mib_to_bytes(parallel_payload_mib);
    sizing.hkdf_ops = std::clamp(sizing.hot_threads * 25000, 250000, 2000000);
    sizing.disk_bytes = mib_to_bytes(std::clamp<std::uint64_t>(available_mib / 64, 1024, 4096));
    sizing.sustained_ms = std::clamp<long>(
        std::max<long>(90000L, static_cast<long>(args.target_duration_sec) * 700L),
        90000L,
        300000L);
    return sizing;
}

void apply_full_benchmark_defaults(Args& args, std::size_t config_count) {
    if (!args.full_benchmark) {
        return;
    }
    const auto profile = yume::runtime::detect_system_profile();
    if (!args.target_duration_override) {
        args.target_duration_sec = 180;
    }
    if (!args.repeat_count_override) {
        args.repeats = 3;
    }
    if (!args.stream_count_override) {
        args.streams = 64;
    }
    if (!args.tunnel_count_override) {
        args.tunnels = 4;
    }
    if (!args.server_threads_override) {
        args.server_threads = std::clamp(static_cast<int>(profile.logical_cpus / 4), 4, 16);
    }
    if (!args.cooldown_ms_override) {
        args.cooldown_ms = 1000;
    }
    if (!args.one_way_override) {
        args.one_way = true;
    }
    if (!args.latency_iters_override) {
        args.latency_iters = 360;
    }
    if (!args.bulk_mib_override) {
        const int divisor = std::max(1, static_cast<int>(config_count) * args.repeats);
        const int mib = (args.target_duration_sec * 1024) / divisor;
        args.bulk_mib = std::clamp(mib, 512, 8192);
    }
}

}  // namespace yume::tools::selftest
