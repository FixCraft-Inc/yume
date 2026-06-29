/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * Local hot-path micro-benchmarks (memory copy/bandwidth, AES-GCM, packet-bulk
 * codec, hop HKDF, disk, sustained mix) used by the selftest "engine" scoring.
 * Extracted from tools/selftest.cpp. No behavior change.
 */

#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include "tools/selftest/runtime.hpp"

namespace yume::tools::selftest {

struct HotPathRow {
    std::string name;
    std::string metric;
    std::string detail;
    bool ok{true};
    double value{0.0};
    std::string unit;
    std::uint64_t bytes{0};
    std::uint64_t ops{0};
    double seconds{0.0};
};

std::vector<HotPathRow> run_hot_paths(const Args& args,
                                      const std::filesystem::path& workdir,
                                      int& progress_completed,
                                      int progress_total);

}  // namespace yume::tools::selftest
