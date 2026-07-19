/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * Versioned local benchmark scoring.
 */

#include "tools/selftest/scoring.hpp"

#include "tools/selftest/sizing.hpp"
#include "core/runtime/system_profile.hpp"

#include <algorithm>
#include <cmath>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace yume::tools::selftest {

const Result* find_result(const std::vector<Result>& results, std::string_view name) {
    auto it = std::find_if(results.begin(), results.end(), [&](const Result& r) {
        return r.ok && r.config.name == name;
    });
    return it == results.end() ? nullptr : &*it;
}

double score_scale(double ratio) {
    if (ratio <= 0.0) {
        return 0.0;
    }
    if (ratio <= 1.0) {
        return std::pow(ratio, 3.0);
    }
    return 1.0 + std::log2(ratio) * 0.55;
}

double scaled_metric_points(double value, double reference, double reference_points) {
    if (value <= 0.0 || reference <= 0.0 || reference_points <= 0.0) {
        return 0.0;
    }
    return score_scale(value / reference) * reference_points;
}

double scaled_latency_points(double median_ms, double reference_ms, double reference_points) {
    if (median_ms <= 0.0 || reference_ms <= 0.0 || reference_points <= 0.0) {
        return 0.0;
    }
    return score_scale(reference_ms / median_ms) * reference_points;
}

void finalize_score(BenchmarkScore& score) {
    double earned = 0.0;
    double possible = 0.0;
    for (const auto& component : score.components) {
        earned += component.points;
        possible += component.reference_points;
    }
    if (possible <= 0.0) {
        return;
    }
    score.available = true;
    score.total = std::max<long long>(
        0,
        static_cast<long long>(std::llround((earned / possible) * kBenchmarkReferenceScore)));
}

std::string format_integer(long long value) {
    const bool negative = value < 0;
    std::string digits = std::to_string(negative ? -value : value);
    std::string out;
    out.reserve(digits.size() + digits.size() / 3 + 1);
    if (negative) {
        out.push_back('-');
    }
    for (std::size_t i = 0; i < digits.size(); ++i) {
        if (i > 0 && (digits.size() - i) % 3 == 0) {
            out.push_back(',');
        }
        out.push_back(digits[i]);
    }
    return out;
}

BenchmarkScore compute_transport_score(const Args& args,
                                       const std::vector<Result>& results,
                                       bool global) {
    BenchmarkScore score;
    if (!args.full_benchmark) {
        return score;
    }
    const double reference_multiplier = global ? kGlobalTransportReferenceMultiplier : 1.0;

    std::vector<std::string> missing_required;
    auto add_throughput = [&](std::string_view name, double reference, double weight) {
        const Result* result = find_result(results, name);
        if (!result) {
            missing_required.push_back(std::string(name));
            return;
        }
        score.components.push_back({
            std::string(name),
            result->throughput_mib_s,
            "MiB/s",
            scaled_metric_points(result->throughput_mib_s, reference * reference_multiplier, weight),
            weight,
        });
    };

    add_throughput("base-direct", 25000.0, 1000000.0);
    // The versioned 2.0 baseline is not comparable with retired 1.x scores.
    add_throughput("yume-v2", 25.0, 8200000.0);

    const Result* latency_anchor = find_result(results, "yume-v2");
    if (latency_anchor && latency_anchor->latency_ms.median > 0.0) {
        score.components.push_back({
            "latency-anchor",
            latency_anchor->latency_ms.median,
            "ms",
            scaled_latency_points(latency_anchor->latency_ms.median, 1.0 / reference_multiplier, 800000.0),
            800000.0,
        });
    } else {
        missing_required.push_back("latency-anchor");
    }

    if (!missing_required.empty()) {
        score.unavailable_reason = "partial benchmark; run --full without --configs for an overall score";
        return score;
    }

    finalize_score(score);
    return score;
}

BenchmarkScore compute_score(const Args& args, const std::vector<Result>& results) {
    return compute_transport_score(args, results, false);
}


const HotPathRow* find_hot_row(const std::vector<HotPathRow>& rows, std::string_view name) {
    auto it = std::find_if(rows.begin(), rows.end(), [&](const HotPathRow& row) {
        return row.ok && row.name == name;
    });
    return it == rows.end() ? nullptr : &*it;
}

BenchmarkScore compute_hot_path_score(const Args& args,
                                      const std::vector<HotPathRow>& rows,
                                      bool global) {
    BenchmarkScore score;
    if (!args.full_benchmark) {
        return score;
    }

    struct Ref {
        std::string_view name;
        double league_ref;
        double weight;
        bool required{true};
    };
    constexpr Ref refs[] = {
        {"copy-floor", 250000.0, 100000.0},
        {"stream-copy-1", 80000.0, 150000.0},
        {"stream-copy-many", 120000.0, 150000.0},
        {"memory-bandwidth", 180000.0, 600000.0},
        {"aes-gcm-encrypt", 6000.0, 1300000.0},
        {"aes-gcm-decrypt", 6000.0, 1300000.0},
        {"packet-bulk-encode", 12000.0, 1100000.0},
        {"packet-bulk-decode", 12000.0, 1100000.0},
        {"hkdf-sha256", 2500000.0, 800000.0},
        {"ratchet-duplex", 1200.0, 2100000.0},
        {"hybrid-establishment", 200.0, 1300000.0},
        {"directional-rekey", 200.0, 1300000.0},
        {"disk-write", 3500.0, 100000.0},
        {"sustained-mix", 14000.0, 4300000.0},
        // Note: the system-load row is no longer scored here. CPU/RAM headroom
        // is now a first-class global component (compute_utilization_score) so
        // it is not double-counted inside the engine score.
    };
    std::vector<std::string> missing;
    for (const auto& ref : refs) {
        const HotPathRow* row = find_hot_row(rows, ref.name);
        if (!row) {
            if (ref.required) {
                missing.emplace_back(ref.name);
            }
            continue;
        }
        const double reference = global ? ref.league_ref * kGlobalReferenceMultiplier : ref.league_ref;
        score.components.push_back({
            std::string(ref.name),
            row->value,
            row->unit,
            scaled_metric_points(row->value, reference, ref.weight),
            ref.weight,
        });
    }
    if (!missing.empty()) {
        score.unavailable_reason = "missing common hot-path rows";
        return score;
    }
    finalize_score(score);
    return score;
}

BenchmarkScore compute_desktop_league_score(const Args& args,
                                            const BenchmarkScore& engine_score,
                                            const BenchmarkScore& transport_score) {
    BenchmarkScore score;
    if (!args.full_benchmark) {
        return score;
    }
    if (!engine_score.available || !transport_score.available) {
        score.unavailable_reason = "desktop league requires engine and YUME transport scores";
        return score;
    }
    score.components.push_back({
        "engine-hot-paths",
        static_cast<double>(engine_score.total),
        "score",
        static_cast<double>(engine_score.total) * 0.5,
        kBenchmarkReferenceScore * 0.5,
    });
    score.components.push_back({
        "yume-transport",
        static_cast<double>(transport_score.total),
        "score",
        static_cast<double>(transport_score.total) * 0.5,
        kBenchmarkReferenceScore * 0.5,
    });
    finalize_score(score);
    return score;
}

BenchmarkScore compute_system_capacity_score(const Args& args) {
    BenchmarkScore score;
    if (!args.full_benchmark) {
        return score;
    }
    const auto profile = yume::runtime::detect_system_profile();
    score.components.push_back({
        "logical-cpus",
        static_cast<double>(std::max(1u, profile.logical_cpus)),
        "count",
        scaled_metric_points(static_cast<double>(std::max(1u, profile.logical_cpus)), 32.0, 6500000.0),
        6500000.0,
    });
    const std::uint64_t memory_mib = profile.total_memory_mib > 0
        ? profile.total_memory_mib
        : yume::runtime::usable_memory_mib(profile) * 2;
    if (memory_mib > 0) {
        score.components.push_back({
            "memory-capacity",
            static_cast<double>(memory_mib),
            "MiB",
            scaled_metric_points(static_cast<double>(memory_mib), 65536.0, 3500000.0),
            3500000.0,
        });
    }
    finalize_score(score);
    return score;
}

BenchmarkScore compute_utilization_score(const Args& args, const LoadProfile& load) {
    BenchmarkScore score;
    if (!args.full_benchmark) {
        return score;
    }
    if (!load.available) {
        score.unavailable_reason = "system load telemetry unavailable";
        return score;
    }
    // Reward headroom retained at peak load: a machine the benchmark could not
    // saturate has real capacity the YUME-bound workload never reached. 50%
    // peak-load headroom matches the reference; more exceeds it.
    score.components.push_back({
        "peak-load-headroom",
        load.peak_load_headroom,
        "%",
        scaled_metric_points(load.peak_load_headroom, 50.0, 7000000.0),
        7000000.0,
    });
    score.components.push_back({
        "sustained-headroom",
        load.avg_headroom,
        "%",
        scaled_metric_points(load.avg_headroom, 60.0, 3000000.0),
        3000000.0,
    });
    finalize_score(score);
    return score;
}

BenchmarkScore compute_global_score(const Args& args,
                                    const BenchmarkScore& engine_score,
                                    const BenchmarkScore& transport_score,
                                    const BenchmarkScore& capacity_score,
                                    const BenchmarkScore& utilization_score,
                                    double elapsed_seconds) {
    BenchmarkScore score;
    if (!args.full_benchmark) {
        return score;
    }
    if (!engine_score.available || !transport_score.available || !capacity_score.available) {
        score.unavailable_reason = "global score requires engine, YUME transport, and system capacity scores";
        return score;
    }
    // YUME's own code caps throughput, so engine/transport barely separate a
    // monster from a laptop. Weight the hardware-truth signals - raw capacity
    // and headroom retained under load - above the YUME-bound throughput, and
    // let the grade fall out of the data (no per-machine cutoff maps).
    score.components.push_back({
        "engine-hot-paths",
        static_cast<double>(engine_score.total),
        "score",
        static_cast<double>(engine_score.total) * 0.15,
        kBenchmarkReferenceScore * 0.15,
    });
    score.components.push_back({
        "yume-transport",
        static_cast<double>(transport_score.total),
        "score",
        static_cast<double>(transport_score.total) * 0.15,
        kBenchmarkReferenceScore * 0.15,
    });
    score.components.push_back({
        "system-capacity",
        static_cast<double>(capacity_score.total),
        "score",
        static_cast<double>(capacity_score.total) * 0.35,
        kBenchmarkReferenceScore * 0.35,
    });
    if (utilization_score.available) {
        score.components.push_back({
            "utilization-headroom",
            static_cast<double>(utilization_score.total),
            "score",
            static_cast<double>(utilization_score.total) * 0.30,
            kBenchmarkReferenceScore * 0.30,
        });
    }
    if (elapsed_seconds > 0.0) {
        const double reference_seconds = std::max(60.0, static_cast<double>(args.target_duration_sec) * 1.35);
        score.components.push_back({
            "elapsed-time",
            elapsed_seconds,
            "s",
            scaled_latency_points(elapsed_seconds, reference_seconds, kBenchmarkReferenceScore * 0.05),
            kBenchmarkReferenceScore * 0.05,
        });
    }
    finalize_score(score);
    return score;
}
struct GradeCutoff {
    long long league;
    std::string_view grade;
};

// Desktop-league cutoffs are a separate diagnostic track and stay a fixed
// table. The GLOBAL track derives its bands from the reference score instead
// (see global_grade_threshold) so they are never hand-fit to a specific machine.
constexpr GradeCutoff kGradeCutoffs[] = {
    {25000000, "SSS+"},
    {18000000, "SSS"},
    {12000000, "SSS-"},
    {8500000, "SS+"},
    {6000000, "SS"},
    {4200000, "SS-"},
    {3000000, "S+"},
    {2200000, "S"},
    {1600000, "S-"},
    {1150000, "AAA+"},
    {850000, "AAA"},
    {620000, "AAA-"},
    {450000, "A+"},
    {320000, "A"},
    {230000, "A-"},
    {165000, "B+"},
    {115000, "B"},
    {80000, "B-"},
    {55000, "C+"},
    {36000, "C"},
    {23000, "C-"},
    {15000, "D+"},
    {9000, "D"},
    {5000, "D-"},
    {2500, "F+"},
    {1000, "F"},
};

// GLOBAL grade ladder, highest first. The reference machine - one that matches
// every reference value, scoring kBenchmarkReferenceScore - is defined to earn
// kGlobalReferenceGrade; each rung multiplies the threshold by kGlobalGradeRatio.
// This replaces hand-fit per-machine cutoffs: a machine's grade falls out of
// how far above or below the reference it scores. Tune these two knobs (anchor
// grade + ratio) against real hardware, never the individual rungs.
constexpr std::string_view kGlobalGradeLadder[] = {
    "SSS+", "SSS", "SSS-", "SS+", "SS", "SS-", "S+", "S", "S-",
    "AAA+", "AAA", "AAA-", "A+", "A", "A-", "B+", "B", "B-",
    "C+", "C", "C-", "D+", "D", "D-", "F+", "F",
};
constexpr std::size_t kGlobalGradeCount =
    sizeof(kGlobalGradeLadder) / sizeof(kGlobalGradeLadder[0]);
constexpr std::size_t kGlobalReferenceGradeIndex = 4;  // reference machine -> "SS"
constexpr double kGlobalGradeRatio = 1.32;

long long global_grade_threshold(std::size_t index) {
    const int steps = static_cast<int>(kGlobalReferenceGradeIndex) - static_cast<int>(index);
    return std::llround(kBenchmarkReferenceScore * std::pow(kGlobalGradeRatio, steps));
}

std::string score_grade(long long score, ScoreTrack track) {
    if (track == ScoreTrack::Global) {
        for (std::size_t i = 0; i < kGlobalGradeCount; ++i) {
            if (score >= global_grade_threshold(i)) {
                return std::string(kGlobalGradeLadder[i]);
            }
        }
        return "F-";
    }
    for (const auto& cutoff : kGradeCutoffs) {
        if (score >= cutoff.league) {
            return std::string(cutoff.grade);
        }
    }
    return "F-";
}
}  // namespace yume::tools::selftest
