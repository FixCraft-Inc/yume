/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 *
 * JSON result serialization declared in tools/selftest/json.hpp.
 * Extracted verbatim from tools/selftest.cpp.
 */

#include "tools/selftest/json.hpp"

#include "tools/selftest/sizing.hpp"
#include "core/runtime/system_profile.hpp"

#include <filesystem>
#include <sstream>
#include <string>
#include <vector>

namespace yume::tools::selftest {

namespace fs = std::filesystem;
constexpr int kJsonSchemaVersion = 1;

std::string json_escape(const std::string& value) {
    std::ostringstream out;
    for (char c : value) {
        switch (c) {
        case '\\': out << "\\\\"; break;
        case '"': out << "\\\""; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                out << "\\u" << std::hex << std::setw(4) << std::setfill('0')
                    << static_cast<int>(static_cast<unsigned char>(c));
            } else {
                out << c;
            }
        }
    }
    return out.str();
}

void append_score_json(std::ostringstream& out,
                       const BenchmarkScore& score,
                       std::string_view model,
                       ScoreTrack track,
                       std::string_view indent) {
    if (!score.available) {
        out << "null";
        return;
    }
    out << "{\n";
    out << indent << "  \"model\": \"" << model << "\",\n";
    out << indent << "  \"total\": " << score.total << ",\n";
    out << indent << "  \"grade\": \"" << score_grade(score.total, track) << "\",\n";
    out << indent << "  \"components\": [\n";
    for (std::size_t i = 0; i < score.components.size(); ++i) {
        const auto& c = score.components[i];
        out << indent << "    {\"name\": \"" << json_escape(c.name) << "\", "
            << "\"raw\": " << c.raw << ", "
            << "\"unit\": \"" << json_escape(c.unit) << "\", "
            << "\"points\": " << c.points << ", "
            << "\"reference_points\": " << c.reference_points << "}"
            << (i + 1 == score.components.size() ? "\n" : ",\n");
    }
    out << indent << "  ]\n";
    out << indent << "}";
}

void append_system_profile_json(std::ostringstream& out, const yume::runtime::SystemProfile& profile) {
    out << "{"
        << "\"logical_cpus\": " << profile.logical_cpus << ", "
        << "\"total_memory_mib\": " << profile.total_memory_mib << ", "
        << "\"available_memory_mib\": " << profile.available_memory_mib << ", "
        << "\"usable_memory_mib\": " << profile_available_mib(profile)
        << "}";
}

void append_benchmark_sizing_json(std::ostringstream& out, const BenchmarkSizing& sizing) {
    out << "{"
        << "\"hot_threads\": " << sizing.hot_threads << ", "
        << "\"copy_bytes\": " << sizing.copy_bytes << ", "
        << "\"stream_single_bytes\": " << sizing.stream_single_bytes << ", "
        << "\"stream_many_bytes\": " << sizing.stream_many_bytes << ", "
        << "\"memory_bytes\": " << sizing.memory_bytes << ", "
        << "\"memory_chunk_bytes\": " << sizing.memory_chunk_bytes << ", "
        << "\"crypto_bytes\": " << sizing.crypto_bytes << ", "
        << "\"packet_bytes\": " << sizing.packet_bytes << ", "
        << "\"hkdf_ops\": " << sizing.hkdf_ops << ", "
        << "\"disk_bytes\": " << sizing.disk_bytes << ", "
        << "\"sustained_ms\": " << sizing.sustained_ms
        << "}";
}

std::string render_json(const Args& args,
                        const std::vector<Result>& results,
                        const std::vector<HotPathRow>& hot_paths,
                        const fs::path& workdir,
                        const BenchmarkScore& global_score,
                        const BenchmarkScore& league_score,
                        const BenchmarkScore& engine_league_score,
                        const BenchmarkScore& transport_score) {
    std::ostringstream out;
    const auto profile = yume::runtime::detect_system_profile();
    const auto sizing = compute_benchmark_sizing(args, profile);
    out << "{\n";
    out << "  \"schema_version\": " << kJsonSchemaVersion << ",\n";
    out << "  \"benchmark_mode\": \"" << (args.full_benchmark ? "full" : "quick") << "\",\n";
    out << "  \"workdir\": \"" << json_escape(workdir.string()) << "\",\n";
    out << "  \"system_profile\": ";
    append_system_profile_json(out, profile);
    out << ",\n";
    out << "  \"benchmark_sizing\": ";
    append_benchmark_sizing_json(out, sizing);
    out << ",\n";
    out << "  \"global_score\": ";
    append_score_json(out, global_score, kGlobalScoreModel, ScoreTrack::Global, "  ");
    out << ",\n";
    out << "  \"league_score\": ";
    append_score_json(out, league_score, kDesktopScoreModel, ScoreTrack::DesktopLeague, "  ");
    out << ",\n";
    out << "  \"score\": ";
    append_score_json(out, global_score, kGlobalScoreModel, ScoreTrack::Global, "  ");
    out << ",\n";
    out << "  \"engine_league_score\": ";
    append_score_json(out, engine_league_score, kEngineScoreModel, ScoreTrack::DesktopLeague, "  ");
    out << ",\n";
    out << "  \"transport_score\": ";
    append_score_json(out, transport_score, kTransportScoreModel, ScoreTrack::DesktopLeague, "  ");
    out << ",\n";
    out << "  \"global_score_unavailable_reason\": ";
    if (global_score.available || global_score.unavailable_reason.empty()) {
        out << "null,\n";
    } else {
        out << "\"" << json_escape(global_score.unavailable_reason) << "\",\n";
    }
    out << "  \"league_score_unavailable_reason\": ";
    if (league_score.available || league_score.unavailable_reason.empty()) {
        out << "null,\n";
    } else {
        out << "\"" << json_escape(league_score.unavailable_reason) << "\",\n";
    }
    out << "  \"latency_iters\": " << args.latency_iters << ",\n";
    out << "  \"bulk_mib\": " << args.bulk_mib << ",\n";
    out << "  \"streams\": " << args.streams << ",\n";
    out << "  \"argon_mem_kib\": " << args.argon_mem_kib << ",\n";
    out << "  \"argon_parallelism\": " << args.argon_parallelism << ",\n";
    out << "  \"cooldown_ms\": " << args.cooldown_ms << ",\n";
    out << "  \"repeat\": " << args.repeats << ",\n";
    out << "  \"hot_paths\": [\n";
    for (std::size_t i = 0; i < hot_paths.size(); ++i) {
        const auto& row = hot_paths[i];
        out << "    {\"name\": \"" << json_escape(row.name) << "\", "
            << "\"ok\": " << (row.ok ? "true" : "false") << ", "
            << "\"metric\": \"" << json_escape(row.metric) << "\", "
            << "\"value\": " << row.value << ", "
            << "\"unit\": \"" << json_escape(row.unit) << "\", "
            << "\"bytes\": " << row.bytes << ", "
            << "\"ops\": " << row.ops << ", "
            << "\"seconds\": " << row.seconds << ", "
            << "\"detail\": \"" << json_escape(row.detail) << "\"}"
            << (i + 1 == hot_paths.size() ? "\n" : ",\n");
    }
    out << "  ],\n";
    out << "  \"results\": [\n";
    for (std::size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        out << "    {\n";
        out << "      \"name\": \"" << json_escape(r.config.name) << "\",\n";
        out << "      \"description\": \"" << json_escape(r.config.description) << "\",\n";
        out << "      \"ok\": " << (r.ok ? "true" : "false") << ",\n";
        if (!r.ok) out << "      \"error\": \"" << json_escape(r.error) << "\",\n";
        out << "      \"latency_ms\": {\n";
        out << "        \"n\": " << r.latency_ms.n << ",\n";
        out << "        \"median\": " << r.latency_ms.median << ",\n";
        out << "        \"p95\": " << r.latency_ms.p95 << ",\n";
        out << "        \"p99\": " << r.latency_ms.p99 << ",\n";
        out << "        \"min\": " << r.latency_ms.min << ",\n";
        out << "        \"max\": " << r.latency_ms.max << ",\n";
        out << "        \"mean\": " << r.latency_ms.mean << "\n";
        out << "      },\n";
        out << "      \"throughput_mib_s\": " << r.throughput_mib_s << ",\n";
        out << "      \"repeat_count\": " << r.repeat_count << ",\n";
        out << "      \"throughput_trial_stats\": {\n";
        out << "        \"n\": " << r.throughput_trial_stats.n << ",\n";
        out << "        \"median\": " << r.throughput_trial_stats.median << ",\n";
        out << "        \"p95\": " << r.throughput_trial_stats.p95 << ",\n";
        out << "        \"p99\": " << r.throughput_trial_stats.p99 << ",\n";
        out << "        \"min\": " << r.throughput_trial_stats.min << ",\n";
        out << "        \"max\": " << r.throughput_trial_stats.max << ",\n";
        out << "        \"mean\": " << r.throughput_trial_stats.mean << "\n";
        out << "      },\n";
        out << "      \"throughput_trials_mib_s\": [";
        for (std::size_t j = 0; j < r.throughput_trials_mib_s.size(); ++j) {
            if (j > 0) out << ", ";
            out << r.throughput_trials_mib_s[j];
        }
        out << "],\n";
        out << "      \"breakdown\": {\n";
        out << "        \"server_listen_ms\": " << r.breakdown.server_listen_ms << ",\n";
        out << "        \"pq_ready_ms\": " << r.breakdown.pq_ready_ms << ",\n";
        out << "        \"client_socks_ms\": " << r.breakdown.client_socks_ms << ",\n";
        out << "        \"connect_ms\": " << r.breakdown.connect_ms << ",\n";
        out << "        \"warmup_ms\": " << r.breakdown.warmup_ms << ",\n";
        out << "        \"bulk_streams\": " << r.breakdown.bulk_streams << ",\n";
        out << "        \"bulk_total_s\": " << r.breakdown.bulk_total_s << ",\n";
        out << "        \"bulk_send_s\": " << r.breakdown.bulk_send_s << "\n";
        out << "      },\n";
        out << "      \"wall_s\": " << r.wall_s << "\n";
        out << "    }" << (i + 1 == results.size() ? "\n" : ",\n");
    }
    out << "  ]\n";
    out << "}\n";
    return out.str();
}

}  // namespace

namespace yume::tools::selftest {
}  // namespace yume::tools::selftest
