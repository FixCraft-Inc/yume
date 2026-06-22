/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 *
 * Scoring implementations declared in tools/selftest/scoring.hpp.
 * Extracted verbatim from tools/selftest.cpp.
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
    return std::pow(ratio, 1.15);
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

BenchmarkScore compute_score(const Args& args, const std::vector<Result>& results) {
    BenchmarkScore score;
    if (!args.full_benchmark) {
        return score;
    }

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
            scaled_metric_points(result->throughput_mib_s, reference, weight),
            weight,
        });
    };

    add_throughput("base-direct", 25000.0, 300000.0);
    add_throughput("no-inner-raw", 1600.0, 900000.0);
    add_throughput("no-inner-obfs", 1450.0, 1200000.0);
    add_throughput("light-no-hop", 1300.0, 1400000.0);
    add_throughput("light-hop-2hz", 1150.0, 1900000.0);
    add_throughput("heavy-no-hop", 1050.0, 1500000.0);
    add_throughput("heavy-hop-2hz", 950.0, 2000000.0);

    const Result* latency_anchor = find_result(results, "heavy-hop-2hz");
    if (latency_anchor && latency_anchor->latency_ms.median > 0.0) {
        score.components.push_back({
            "latency-anchor",
            latency_anchor->latency_ms.median,
            "ms",
            scaled_latency_points(latency_anchor->latency_ms.median, 0.08, 800000.0),
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
        {"hop-hkdf", 2500000.0, 800000.0},
        {"inner-aead-encrypt", 8000.0, 800000.0},
        {"inner-aead-decrypt", 8000.0, 800000.0},
        {"basefwx-pq-client", 40000.0, 1100000.0},
        {"basefwx-pq-server", 40000.0, 1100000.0},
        {"basefwx-argon2", 750.0, 900000.0},
        {"disk-write", 3500.0, 100000.0},
        {"sustained-mix", 14000.0, 4300000.0},
        {"system-load", 50.0, 400000.0, false},
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
struct GradeCutoff {
    long long global;
    long long league;
    std::string_view grade;
};

constexpr GradeCutoff kGradeCutoffs[] = {
    {40000000, 25000000, "SSS+"},
    {35000000, 18000000, "SSS"},
    {24000000, 12000000, "SSS-"},
    {17000000, 8500000, "SS+"},
    {12000000, 6000000, "SS"},
    {8500000, 4200000, "SS-"},
    {6000000, 3000000, "S+"},
    {4200000, 2200000, "S"},
    {3000000, 1600000, "S-"},
    {2100000, 1150000, "AAA+"},
    {1500000, 850000, "AAA"},
    {1050000, 620000, "AAA-"},
    {750000, 450000, "A+"},
    {520000, 320000, "A"},
    {360000, 230000, "A-"},
    {250000, 165000, "B+"},
    {175000, 115000, "B"},
    {120000, 80000, "B-"},
    {80000, 55000, "C+"},
    {50000, 36000, "C"},
    {32000, 23000, "C-"},
    {20000, 15000, "D+"},
    {12000, 9000, "D"},
    {7000, 5000, "D-"},
    {3500, 2500, "F+"},
    {1500, 1000, "F"},
};

std::string score_grade(long long score, ScoreTrack track) {
    for (const auto& cutoff : kGradeCutoffs) {
        const long long threshold = track == ScoreTrack::DesktopLeague ? cutoff.league : cutoff.global;
        if (score >= threshold) {
            return std::string(cutoff.grade);
        }
    }
    return "F-";
}
}  // namespace yume::tools::selftest
