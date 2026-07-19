/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * JSON report declarations for the local benchmark.
 */

#pragma once

#include <filesystem>
#include <string>
#include <vector>

#include "tools/selftest/hotpath.hpp"
#include "tools/selftest/runtime.hpp"
#include "tools/selftest/scoring.hpp"

namespace yume::tools::selftest {

std::string render_json(const Args& args,
                        const std::vector<Result>& results,
                        const std::vector<HotPathRow>& hot_paths,
                        const std::filesystem::path& workdir,
                        const BenchmarkScore& global_score,
                        const BenchmarkScore& league_score,
                        const BenchmarkScore& engine_league_score,
                        const BenchmarkScore& transport_score);

}  // namespace yume::tools::selftest
