/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 *
 * Selftest/benchmark scoring: maps measured results + hot-path rows to the
 * GLOBAL / engine / transport / desktop-league scores and letter grades.
 * Extracted from tools/selftest.cpp. No behavior change.
 */

#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "tools/selftest/hotpath.hpp"
#include "tools/selftest/runtime.hpp"

namespace yume::tools::selftest {

inline constexpr std::string_view kGlobalScoreModel = "yume-global-v1";
inline constexpr std::string_view kDesktopScoreModel = "yume-desktop-v1";
inline constexpr std::string_view kEngineScoreModel = "yume-engine-v1";
inline constexpr std::string_view kTransportScoreModel = "yume-transport-v1";
inline constexpr double kBenchmarkReferenceScore = 10000000.0;
inline constexpr double kGlobalReferenceMultiplier = 1.5;

struct ScoreComponent {
    std::string name;
    double raw{0.0};
    std::string unit;
    double points{0.0};
    double reference_points{0.0};
};

struct BenchmarkScore {
    bool available{false};
    long long total{0};
    std::string unavailable_reason;
    std::vector<ScoreComponent> components;
};

enum class ScoreTrack {
    Global,
    DesktopLeague,
};

std::string format_integer(long long value);
BenchmarkScore compute_score(const Args& args, const std::vector<Result>& results);
BenchmarkScore compute_hot_path_score(const Args& args,
                                      const std::vector<HotPathRow>& rows,
                                      bool global);
BenchmarkScore compute_desktop_league_score(const Args& args,
                                            const BenchmarkScore& engine_score,
                                            const BenchmarkScore& transport_score);
std::string score_grade(long long score, ScoreTrack track);

}  // namespace yume::tools::selftest
