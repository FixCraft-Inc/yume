/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * Scales benchmark byte counts and thread counts to the detected system.
 */

#pragma once

#include <cstddef>
#include <cstdint>

#include "core/runtime/system_profile.hpp"
#include "tools/selftest/runtime.hpp"

namespace yume::tools::selftest {

inline constexpr int kKiB = 1024;
inline constexpr int kMiB = 1024 * kKiB;

struct BenchmarkSizing {
    int hot_threads{1};
    std::uint64_t copy_bytes{64ull * kMiB};
    std::uint64_t stream_single_bytes{32ull * kMiB};
    std::uint64_t stream_many_bytes{256ull * kMiB};
    std::uint64_t memory_bytes{64ull * kMiB};
    std::size_t memory_chunk_bytes{1ull * kMiB};
    std::uint64_t crypto_bytes{32ull * kMiB};
    std::uint64_t packet_bytes{32ull * kMiB};
    int hkdf_ops{5000};
    std::uint64_t disk_bytes{0};
    long sustained_ms{0};
};

std::uint64_t mib_to_bytes(std::uint64_t mib);
std::uint64_t bytes_to_mib(std::uint64_t bytes);
std::uint64_t profile_available_mib(const yume::runtime::SystemProfile& profile);
BenchmarkSizing compute_benchmark_sizing(const Args& args, const yume::runtime::SystemProfile& profile);
void apply_full_benchmark_defaults(Args& args, std::size_t config_count);

}  // namespace yume::tools::selftest
