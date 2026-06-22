/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "tools/selftest/runner.hpp"

#include "core/protocol/packet_bulk.hpp"
#include "core/runtime/system_profile.hpp"
#include "selftest/runtime.hpp"
#include "selftest/render.hpp"
#include "selftest/sizing.hpp"
#include "selftest/hotpath.hpp"
#include "selftest/scoring.hpp"
#include "selftest/json.hpp"
#include "selftest/telemetry.hpp"

#include <basefwx/crypto.hpp>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cctype>
#include <chrono>
#include <cstring>
#include <cmath>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <numeric>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>
#if !defined(_WIN32)
#include <fcntl.h>
#include <unistd.h>
#endif

namespace {

using namespace yume::tools::selftest;
namespace fs = std::filesystem;




const std::vector<Config>& builtin_configs() {
    static const std::vector<Config> configs{
        {
            "base-direct",
            "Direct loopback TCP echo; measures host/kernel floor.",
            true,
            {},
            {},
        },
        {
            "no-inner-raw",
            "YUME SOCKS over plain TLS carrier, no inner crypto or H2 disguise.",
            false,
            {"--no-obfs", "--no-inner"},
            {"--no-obfs", "--no-inner"},
        },
        {
            "no-inner-obfs",
            "YUME SOCKS over TLS/H2 carrier, no inner crypto.",
            false,
            {"--obfs", "--no-inner"},
            {"--obfs", "--no-inner"},
        },
        {
            "light-no-hop",
            "Inner light crypto with hopping disabled.",
            false,
            {"--obfs", "--inner-light", "--inner-required", "--no-hop"},
            {"--obfs", "--inner-light", "--no-hop"},
        },
        {
            "light-hop-2hz",
            "Inner light crypto with live hopping every 500 ms.",
            false,
            {"--obfs", "--inner-light", "--inner-required", "--hop", "--hop-interval", "500"},
            {"--obfs", "--inner-light", "--hop", "--hop-interval", "500"},
        },
        {
            "heavy-hop-2hz",
            "HTTPS/H2 disguise, heavy inner KDF, live hopping every 500 ms.",
            false,
            {"--obfs", "--inner-heavy", "--inner-required", "--hop", "--hop-interval", "500"},
            {"--obfs", "--inner-heavy", "--hop", "--hop-interval", "500"},
        },
        {
            "heavy-no-hop",
            "HTTPS/H2 disguise and inner heavy KDF with hopping disabled.",
            false,
            {"--obfs", "--inner-heavy", "--inner-required", "--no-hop"},
            {"--obfs", "--inner-heavy", "--no-hop"},
        },
    };
    return configs;
}

std::vector<std::string> split_csv(std::string_view value) {
    std::vector<std::string> out;
    std::size_t start = 0;
    while (start <= value.size()) {
        const auto comma = value.find(',', start);
        const auto end = comma == std::string_view::npos ? value.size() : comma;
        std::string item(value.substr(start, end - start));
        item.erase(item.begin(), std::find_if(item.begin(), item.end(), [](unsigned char c) {
            return !std::isspace(c);
        }));
        item.erase(std::find_if(item.rbegin(), item.rend(), [](unsigned char c) {
            return !std::isspace(c);
        }).base(), item.end());
        if (!item.empty()) out.push_back(std::move(item));
        if (comma == std::string_view::npos) break;
        start = comma + 1;
    }
    return out;
}

void print_help() {
    std::cout
        << "yume-selftest - local YUME benchmark harness\n\n"
        << "Usage:\n"
        << "  yume-selftest [options]\n\n"
        << "Options:\n"
        << "  --yume <path>             yume binary (default: sibling ./yume)\n"
        << "  --yumed <path>            yumed binary (default: sibling ./yumed)\n"
        << "  --configs <a,b|all>       Config subset; use --list-configs\n"
        << "  --benchmark <quick|full>  quick keeps smoke-test defaults; full runs a\n"
        << "                            longer score-producing device benchmark\n"
        << "  --quick                   Alias for --benchmark quick\n"
        << "  --full                    Alias for --benchmark full\n"
        << "  --duration-sec <N>        Full-mode target duration hint (30..600,\n"
        << "                            default 180; scales payload size)\n"
        << "  --latency-iters <N>       Echo round trips per config (default 120; full uses 360)\n"
        << "  --bulk-mib <N>            Bulk echo size per config (default 32)\n"
        << "  --argon-mem-kib <N>       Heavy KDF memory cap/env; full mode auto-sizes\n"
        << "                            when this is omitted (quick default 32768)\n"
        << "  --argon-parallelism <N>   Heavy KDF parallelism; full mode auto-sizes\n"
        << "                            when this is omitted (quick default 2)\n"
        << "  --tunnels <N>             Client TLS tunnel count (default 1)\n"
        << "  --streams <N>             Concurrent bulk streams per config (default 1)\n"
        << "  --client-threads <N>      Client io threads (0=auto/hw concurrency)\n"
        << "  --server-threads <N>      Server io threads (default 2)\n"
        << "  --cooldown-ms <N>         Pause between configs for fairer sweeps (default 500)\n"
        << "  --repeat <N>              Run each config N times; report median-throughput trial\n"
        << "  --one-way                 Measure one-way upload (sink+ack), not echo\n"
        << "  --json <path>             Write JSON result file\n"
        << "  --json-stdout             Print JSON to stdout after the table\n"
        << "  --dev                     Show component tables, timings, and row details\n"
        << "  --no-color                Disable ANSI colors in terminal output\n"
        << "  --keep-workdir            Keep temp logs and generated keys\n"
        << "  --list-configs            Print config names and exit\n"
        << "  -h, --help                Show this help\n\n"
        << "Notes:\n"
        << "  Default/no --configs runs every built-in config, including heavy-hop-2hz.\n"
        << "  Config aliases: all expands to the full suite; all-on selects heavy-hop-2hz.\n"
        << "  Quick mode is an unscored smoke test. Full mode prints one GLOBAL\n"
        << "  score for cross-device comparison. --dev also shows the desktop\n"
        << "  profile score and raw component tables for audit/debug use.\n"
        << "  Add --dev when you want raw rows, phase timings, component points,\n"
        << "  and other audit/debug details.\n"
        << "  Routed loopback benchmarks require yumed built with\n"
        << "  -DYUME_FEATURE_LAN_BRIDGE=ON. The tool grants allow_local_ip only\n"
        << "  to its temporary auth key through authorized_keys.json.\n";
}

Args parse_args(int argc, char** argv) {
    Args args;
    const fs::path self = self_path(argc > 0 ? argv[0] : nullptr);
    if (!self.empty()) {
        args.yume = self.parent_path() / "yume";
        args.yumed = self.parent_path() / "yumed";
    }
    auto require_value = [&](int& i, const std::string& opt) -> std::string {
        if (i + 1 >= argc) throw std::runtime_error(opt + " requires a value");
        return argv[++i];
    };
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_help();
            std::exit(0);
        } else if (arg == "--yume") {
            args.yume = require_value(i, arg);
        } else if (arg == "--yumed") {
            args.yumed = require_value(i, arg);
        } else if (arg == "--configs") {
            args.configs = split_csv(require_value(i, arg));
        } else if (arg == "--benchmark") {
            const std::string mode = require_value(i, arg);
            if (mode == "full" || mode == "long") {
                args.full_benchmark = true;
            } else if (mode == "quick" || mode == "smoke") {
                args.full_benchmark = false;
            } else {
                throw std::runtime_error("--benchmark must be quick or full");
            }
        } else if (arg == "--full" || arg == "--long") {
            args.full_benchmark = true;
        } else if (arg == "--quick") {
            args.full_benchmark = false;
        } else if (arg == "--duration-sec") {
            args.target_duration_sec = std::clamp(std::stoi(require_value(i, arg)), 30, 600);
            args.target_duration_override = true;
        } else if (arg == "--latency-iters") {
            args.latency_iters = std::max(1, std::stoi(require_value(i, arg)));
            args.latency_iters_override = true;
        } else if (arg == "--bulk-mib") {
            args.bulk_mib = std::max(1, std::stoi(require_value(i, arg)));
            args.bulk_mib_override = true;
        } else if (arg == "--argon-mem-kib") {
            args.argon_mem_kib = std::max(1024, std::stoi(require_value(i, arg)));
            args.argon_mem_override = true;
        } else if (arg == "--argon-parallelism") {
            args.argon_parallelism = std::max(1, std::stoi(require_value(i, arg)));
            args.argon_parallelism_override = true;
        } else if (arg == "--tunnels") {
            args.tunnels = std::max(1, std::stoi(require_value(i, arg)));
            args.tunnel_count_override = true;
        } else if (arg == "--streams") {
            args.streams = std::max(1, std::stoi(require_value(i, arg)));
            args.stream_count_override = true;
        } else if (arg == "--client-threads") {
            args.client_threads = std::max(0, std::stoi(require_value(i, arg)));
        } else if (arg == "--server-threads") {
            args.server_threads = std::max(1, std::stoi(require_value(i, arg)));
            args.server_threads_override = true;
        } else if (arg == "--cooldown-ms") {
            args.cooldown_ms = std::max(0, std::stoi(require_value(i, arg)));
            args.cooldown_ms_override = true;
        } else if (arg == "--repeat" || arg == "--repeats") {
            args.repeats = std::max(1, std::stoi(require_value(i, arg)));
            args.repeat_count_override = true;
        } else if (arg == "--one-way") {
            args.one_way = true;
            args.one_way_override = true;
        } else if (arg == "--json") {
            args.json_path = require_value(i, arg);
        } else if (arg == "--json-stdout") {
            args.json_stdout = true;
        } else if (arg == "--dev") {
            args.dev_style = true;
        } else if (arg == "--no-color" || arg == "--no-colour") {
            args.color = false;
        } else if (arg == "--color" || arg == "--colour") {
            args.color = true;
        } else if (arg == "--keep-workdir") {
            args.keep_workdir = true;
        } else if (arg == "--list-configs") {
            args.list_configs = true;
        } else {
            throw std::runtime_error("unknown option: " + arg);
        }
    }
    return args;
}

struct Keyset {
    fs::path cert;
    fs::path key;
    fs::path authorized_keys;
    fs::path client_key;
    fs::path pq_public;
};

Keyset generate_keyset(const Args& args, const fs::path& workdir) {
    Keyset ks{
        workdir / "server.crt",
        workdir / "server.key",
        workdir / "authorized_keys",
        workdir / "client.key",
        workdir / ".secrets" / "pq_public.key",
    };

    run_checked({
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", ks.key.string(),
        "-out", ks.cert.string(),
        "-days", "1", "-nodes",
        "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    }, workdir, workdir / "openssl-cert.log");

    const fs::path prefix = workdir / "client";
    run_checked({args.yumed.string(), "--keys-gen", prefix.string()}, workdir, workdir / "keys-gen.log");
    const fs::path client_pub = workdir / "client.pub";
    if (!fs::exists(ks.client_key) || !fs::exists(client_pub)) {
        throw std::runtime_error("yumed --keys-gen did not produce client keypair");
    }
    fs::copy_file(client_pub, ks.authorized_keys, fs::copy_options::overwrite_existing);

    const fs::path der = workdir / "client.pub.der";
    run_checked({
        "openssl", "pkey", "-pubin",
        "-in", client_pub.string(),
        "-outform", "DER",
        "-out", der.string(),
    }, workdir, workdir / "openssl-pubder.log");
    const std::string fp = sha256_hex(read_file(der));
    std::ostringstream meta;
    meta << "{\n"
         << "  \"" << fp << "\": {\n"
         << "    \"alias\": \"selftest\",\n"
         << "    \"permissions\": { \"allow_local_ip\": true }\n"
         << "  }\n"
         << "}\n";
    write_text(ks.authorized_keys.string() + ".json", meta.str());
    return ks;
}

std::vector<std::pair<std::string, std::string>> run_env(const Args& args,
                                                         const fs::path& workdir,
                                                         bool server) {
    const std::string mem = std::to_string(args.argon_mem_kib);
    const std::string par = std::to_string(args.argon_parallelism);
    std::vector<std::pair<std::string, std::string>> env{
        {"HOME", (workdir / "home").string()},
    };
    if (server) {
        env.emplace_back("YUME_ARGON2_MEM_MAX", mem);
        env.emplace_back("YUME_ARGON2_PAR_MAX", par);
    } else {
        env.emplace_back("YUME_ARGON2_MEM", mem);
        env.emplace_back("YUME_ARGON2_PAR", par);
    }
    return env;
}

class YumeStack {
public:
    YumeStack(const Args& args,
              const Keyset& ks,
              const Config& cfg,
              const fs::path& workdir,
              int yumed_port,
              int socks_port)
        : args_(args)
        , ks_(ks)
        , cfg_(cfg)
        , workdir_(workdir)
        , yumed_port_(yumed_port)
        , socks_port_(socks_port) {}

    void start(Breakdown& breakdown) {
        const bool needs_pq_file =
            !has_flag(cfg_.client_flags, "--no-inner") &&
            !has_flag(cfg_.client_flags, "--use-embedded-master");
        std::vector<std::string> server_argv{
            args_.yumed.string(),
            "--listen", "127.0.0.1:" + std::to_string(yumed_port_),
            "--cert", ks_.cert.string(),
            "--key", ks_.key.string(),
            "--auth-keys", ks_.authorized_keys.string(),
            "--allow-local-ip",
            "--threads", std::to_string(args_.server_threads),
            "--boring",
        };
        if (needs_pq_file) {
            server_argv.push_back("--pq-auto-generate");
        }
        server_argv.insert(server_argv.end(), cfg_.server_flags.begin(), cfg_.server_flags.end());
        server_ = std::make_unique<ChildProcess>(
            server_argv,
            workdir_,
            workdir_ / (cfg_.name + "-yumed.log"),
            run_env(args_, workdir_, true));
        const auto server_start = Clock::now();
        server_->start();
        if (!wait_for_port(yumed_port_, std::chrono::seconds(12))) {
            breakdown.server_listen_ms = elapsed_ms(server_start, Clock::now());
            throw std::runtime_error("yumed did not listen; see " + server_->log_path().string());
        }
        breakdown.server_listen_ms = elapsed_ms(server_start, Clock::now());
        if (needs_pq_file && !wait_for_path(ks_.pq_public, std::chrono::seconds(12))) {
            breakdown.pq_ready_ms = elapsed_ms(server_start, Clock::now()) - breakdown.server_listen_ms;
            throw std::runtime_error("server did not generate pq_public.key; see " + server_->log_path().string());
        }
        if (needs_pq_file) {
            breakdown.pq_ready_ms = elapsed_ms(server_start, Clock::now()) - breakdown.server_listen_ms;
        }

        std::vector<std::string> client_argv{
            args_.yume.string(),
            "--server", "127.0.0.1",
            "--port", std::to_string(yumed_port_),
            "--auth", ks_.client_key.string(),
            "--socks", std::to_string(socks_port_),
            "--allow-local-ip",
            "--tunnels", std::to_string(args_.tunnels),
            "--non-interactive",
            "--accept-monitoring",
            "--boring",
            "--tls-ca", ks_.cert.string(),
        };
        if (args_.client_threads > 0) {
            client_argv.push_back("--threads");
            client_argv.push_back(std::to_string(args_.client_threads));
        }
        if (needs_pq_file) {
            client_argv.push_back("--pq-pub");
            client_argv.push_back(ks_.pq_public.string());
        }
        client_argv.insert(client_argv.end(), cfg_.client_flags.begin(), cfg_.client_flags.end());
        client_ = std::make_unique<ChildProcess>(
            client_argv,
            workdir_,
            workdir_ / (cfg_.name + "-yume.log"),
            run_env(args_, workdir_, false));
        const auto client_start = Clock::now();
        client_->start();
        if (!wait_for_port(socks_port_, std::chrono::seconds(20))) {
            breakdown.client_socks_ms = elapsed_ms(client_start, Clock::now());
            throw std::runtime_error("yume did not start SOCKS; see " + client_->log_path().string());
        }
        breakdown.client_socks_ms = elapsed_ms(client_start, Clock::now());
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }

    void stop() {
        client_.reset();
        server_.reset();
    }

private:
    const Args& args_;
    const Keyset& ks_;
    const Config& cfg_;
    fs::path workdir_;
    int yumed_port_{0};
    int socks_port_{0};
    std::unique_ptr<ChildProcess> server_;
    std::unique_ptr<ChildProcess> client_;
};

Result run_config(const Args& args,
                  const Keyset& ks,
                  const Config& cfg,
                  const fs::path& workdir,
                  int echo_port,
                  int sink_port) {
    Result result;
    result.config = cfg;
    const auto start = Clock::now();
    try {
        if (cfg.base_direct) {
            LatencyMeasurement latency = measure_latency(0, echo_port, args.latency_iters, false);
            result.latency_ms = latency.stats;
            result.breakdown.connect_ms = latency.connect_ms;
            result.breakdown.warmup_ms = latency.warmup_ms;
            BulkMeasurement bulk = args.one_way
                ? measure_bulk_one_way(0, sink_port, args.bulk_mib, false, args.streams)
                : measure_bulk(0, echo_port, args.bulk_mib, false, args.streams);
            result.throughput_mib_s = bulk.mib_s;
            result.breakdown.bulk_total_s = bulk.total_s;
            result.breakdown.bulk_send_s = bulk.send_s;
            result.breakdown.bulk_streams = bulk.streams;
        } else {
            const int yumed_port = pick_free_port();
            const int socks_port = pick_free_port();
            YumeStack stack(args, ks, cfg, workdir, yumed_port, socks_port);
            stack.start(result.breakdown);
            LatencyMeasurement latency = measure_latency(socks_port, echo_port, args.latency_iters, true);
            result.latency_ms = latency.stats;
            result.breakdown.connect_ms = latency.connect_ms;
            result.breakdown.warmup_ms = latency.warmup_ms;
            BulkMeasurement bulk = args.one_way
                ? measure_bulk_one_way(socks_port, sink_port, args.bulk_mib, true, args.streams)
                : measure_bulk(socks_port, echo_port, args.bulk_mib, true, args.streams);
            result.throughput_mib_s = bulk.mib_s;
            result.breakdown.bulk_total_s = bulk.total_s;
            result.breakdown.bulk_send_s = bulk.send_s;
            result.breakdown.bulk_streams = bulk.streams;
            stack.stop();
        }
        result.ok = true;
    } catch (const std::exception& ex) {
        result.ok = false;
        result.error = ex.what();
    }
    result.wall_s = std::chrono::duration<double>(Clock::now() - start).count();
    return result;
}

Result run_config_repeated(const Args& args,
                           const Keyset& ks,
                           const Config& cfg,
                           const fs::path& workdir,
                           int echo_port,
                           int sink_port,
                           int& progress_completed,
                           int progress_total) {
    if (!progress_inline_enabled()) {
        std::cerr << kBenchLogPrefix << " " << cfg.name << ": " << cfg.description << "\n";
    }
    if (args.repeats <= 1) {
        render_progress_bar(progress_completed, progress_total, cfg.name);
        Result result = run_config(args, ks, cfg, workdir, echo_port, sink_port);
        ++progress_completed;
        render_progress_bar(progress_completed, progress_total, cfg.name);
        return result;
    }

    std::vector<Result> trials;
    trials.reserve(static_cast<std::size_t>(args.repeats));
    for (int trial = 0; trial < args.repeats; ++trial) {
        if (trial > 0 && args.cooldown_ms > 0) {
            if (!progress_inline_enabled()) {
                std::cerr << kBenchLogPrefix << " cooldown " << args.cooldown_ms
                          << " ms before " << cfg.name << " trial "
                          << (trial + 1) << "/" << args.repeats << "\n";
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(args.cooldown_ms));
        }
        if (!progress_inline_enabled()) {
            std::cerr << kBenchLogPrefix << " " << cfg.name << " trial "
                      << (trial + 1) << "/" << args.repeats << "\n";
        }
        const std::string progress_label = cfg.name + " trial " +
            std::to_string(trial + 1) + "/" + std::to_string(args.repeats);
        render_progress_bar(progress_completed, progress_total, progress_label);
        Result result = run_config(args, ks, cfg, workdir, echo_port, sink_port);
        ++progress_completed;
        render_progress_bar(progress_completed, progress_total, progress_label);
        result.repeat_count = trial + 1;
        if (!result.ok) {
            return result;
        }
        trials.push_back(std::move(result));
    }

    std::vector<double> throughput_trials;
    throughput_trials.reserve(trials.size());
    for (const auto& trial : trials) {
        throughput_trials.push_back(trial.throughput_mib_s);
    }
    const Stats throughput_stats = compute_stats(throughput_trials);

    std::size_t closest = 0;
    auto distance_to_median = [&](std::size_t i) {
        const double value = trials[i].throughput_mib_s;
        return value > throughput_stats.median ? value - throughput_stats.median : throughput_stats.median - value;
    };
    for (std::size_t i = 1; i < trials.size(); ++i) {
        if (distance_to_median(i) < distance_to_median(closest)) {
            closest = i;
        }
    }

    Result summary = trials[closest];
    summary.repeat_count = args.repeats;
    summary.throughput_mib_s = throughput_stats.median;
    summary.throughput_trials_mib_s = std::move(throughput_trials);
    summary.throughput_trial_stats = throughput_stats;
    return summary;
}

std::vector<Config> select_configs(const Args& args) {
    if (args.configs.empty()) return builtin_configs();
    std::vector<Config> selected;
    auto append_once = [&](const Config& cfg) {
        const auto exists = std::any_of(selected.begin(), selected.end(), [&](const Config& existing) {
            return existing.name == cfg.name;
        });
        if (!exists) selected.push_back(cfg);
    };
    for (const auto& name : args.configs) {
        if (name == "all" || name == "*") {
            for (const auto& cfg : builtin_configs()) append_once(cfg);
            continue;
        }
        const std::string resolved = (name == "all-on" || name == "heavy-obfs-2hz" || name == "heavy-obfs-hop-2hz")
            ? "heavy-hop-2hz"
            : name;
        auto it = std::find_if(builtin_configs().begin(), builtin_configs().end(), [&](const Config& cfg) {
            return cfg.name == resolved;
        });
        if (it == builtin_configs().end()) throw std::runtime_error("unknown config: " + name);
        append_once(*it);
    }
    return selected;
}

void render_score(const Args& args,
                  const BenchmarkScore& global_score,
                  const BenchmarkScore& league_score) {
    if (!args.full_benchmark) {
        std::cerr << "\nQuick benchmark complete. Use --fullbench for scored GLOBAL results.\n";
        return;
    }
    if (!global_score.available && !league_score.available) {
        std::cerr << "\nYUME benchmark score: not computed.\n";
        return;
    }
    std::cerr << "\nYUME benchmark\n";
    std::cerr << "--------------------------------------------------------------------------------\n";
    if (global_score.available) {
        const std::string grade = score_grade(global_score.total, ScoreTrack::Global);
        std::cerr << "GLOBAL  " << format_integer(global_score.total)
                  << "  " << color_grade(args, grade, global_score.total);
        if (global_score.total >= kBenchmarkAboveReferenceScore) {
            std::cerr << " (above reference)";
        }
        if (args.dev_style) {
            std::cerr << "  model " << kGlobalScoreModel;
        }
        std::cerr << "\n";
    } else {
        std::cerr << "GLOBAL  not computed";
        if (!global_score.unavailable_reason.empty()) {
            std::cerr << " (" << global_score.unavailable_reason << ")";
        }
        std::cerr << "\n";
    }
    if (args.dev_style && league_score.available) {
        const std::string grade = score_grade(league_score.total, ScoreTrack::DesktopLeague);
        std::cerr << "DESKTOP " << format_integer(league_score.total)
                  << "  " << color_grade(args, grade, league_score.total);
        std::cerr << "  model " << kDesktopScoreModel;
        std::cerr << "\n";
    } else if (args.dev_style) {
        std::cerr << "DESKTOP not computed";
        if (!league_score.unavailable_reason.empty()) {
            std::cerr << " (" << league_score.unavailable_reason << ")";
        }
        std::cerr << "\n";
    }
    std::cerr << "mode: full"
              << "  target=" << args.target_duration_sec << "s"
              << "  bulk=" << args.bulk_mib << "MiB"
              << "  streams=" << args.streams
              << "  repeats=" << args.repeats
              << "  tunnels=" << args.tunnels << "\n";
    if (args.dev_style) {
        const auto profile = yume::runtime::detect_system_profile();
        const auto sizing = compute_benchmark_sizing(args, profile);
        std::cerr << "host: cpus=" << profile.logical_cpus
                  << "  mem=" << profile.total_memory_mib << "MiB"
                  << "  available=" << profile_available_mib(profile) << "MiB\n";
        std::cerr << "workload: threads=" << sizing.hot_threads
                  << "  memory=" << bytes_to_mib(sizing.memory_bytes) << "MiB"
                  << "  crypto=" << bytes_to_mib(sizing.crypto_bytes) << "MiB"
                  << "  packet=" << bytes_to_mib(sizing.packet_bytes) << "MiB"
                  << "  disk=" << bytes_to_mib(sizing.disk_bytes) << "MiB"
                  << "  sustained=" << (sizing.sustained_ms / 1000) << "s\n";
    }
    std::cerr << "GLOBAL: weighted engine, transport/capacity, and efficiency score; no fixed maximum.\n";
    if (args.dev_style) {
        std::cerr << "DESKTOP: diagnostic profile, 50% engine and 50% YUME transport.\n";
    }
    if (!args.dev_style) {
        std::cerr << "Run again with --dev for component tables, load telemetry, and phase timings.\n";
    }
    std::cerr << "--------------------------------------------------------------------------------\n";
    if (!args.dev_style) {
        return;
    }
    auto render_components = [](std::string_view title, const BenchmarkScore& score) {
        if (!score.available) {
            return;
        }
        std::cerr << "\n" << title << " components\n";
        std::cerr << "--------------------------------------------------------------------------------\n";
        std::cerr << std::left << std::setw(20) << "component"
                  << std::right << std::setw(14) << "raw"
                  << std::setw(10) << "unit"
                  << std::setw(12) << "points"
                  << "\n";
        std::cerr << "--------------------------------------------------------------------------------\n";
        for (const auto& component : score.components) {
            std::cerr << std::left << std::setw(20) << component.name
                      << std::right << std::fixed << std::setprecision(component.unit == "ms" ? 3 : 1)
                      << std::setw(14) << component.raw
                      << std::setw(10) << component.unit
                      << std::setprecision(0)
                      << std::setw(12) << component.points
                      << "\n";
        }
        std::cerr << "--------------------------------------------------------------------------------\n";
    };
    render_components("GLOBAL", global_score);
    render_components("DESKTOP", league_score);
}

void render_table(const std::vector<Result>& results) {
    const auto base = std::find_if(results.begin(), results.end(), [](const Result& r) {
        return r.ok && r.config.base_direct;
    });
    const double base_lat = base == results.end() ? 0.0 : base->latency_ms.median;
    const double base_thr = base == results.end() ? 0.0 : base->throughput_mib_s;

    std::cerr << "\nYUME local benchmark details\n";
    std::cerr << "--------------------------------------------------------------------------------\n";
    std::cerr << std::left << std::setw(18) << "config"
              << std::right << std::setw(10) << "med ms"
              << std::setw(10) << "p95"
              << std::setw(12) << "MiB/s"
              << std::setw(12) << "lat delta"
              << std::setw(12) << "thr pct"
              << "  status\n";
    std::cerr << "--------------------------------------------------------------------------------\n";
    for (const auto& r : results) {
        std::cerr << std::left << std::setw(18) << r.config.name << std::right;
        if (!r.ok) {
            std::cerr << "  FAILED: " << r.error << "\n";
            continue;
        }
        const double delta = r.config.base_direct ? 0.0 : r.latency_ms.median - base_lat;
        const double thr_pct = (base_thr > 0.0 && !r.config.base_direct)
            ? (r.throughput_mib_s / base_thr) * 100.0
            : 100.0;
        std::cerr << std::fixed << std::setprecision(3)
                  << std::setw(10) << r.latency_ms.median
                  << std::setw(10) << r.latency_ms.p95
                  << std::setprecision(1)
                  << std::setw(12) << r.throughput_mib_s
                  << std::setprecision(3)
                  << std::setw(12) << delta
                  << std::setprecision(1)
                  << std::setw(11) << thr_pct << "%"
                  << "  ok";
        if (r.repeat_count > 1) {
            std::cerr << " median/" << r.repeat_count;
        }
        std::cerr << "\n";
    }
    std::cerr << "--------------------------------------------------------------------------------\n";
    std::cerr << "lat delta = added median RTT over direct loopback. thr pct = MiB/s vs direct.\n";
    std::cerr << "\nPhase breakdown\n";
    std::cerr << "------------------------------------------------------------------------------------------------\n";
    std::cerr << std::left << std::setw(18) << "config"
              << std::right << std::setw(10) << "srv ms"
              << std::setw(10) << "pq ms"
              << std::setw(10) << "cli ms"
              << std::setw(10) << "conn ms"
              << std::setw(10) << "warm ms"
              << std::setw(8) << "streams"
              << std::setw(10) << "bulk s"
              << std::setw(10) << "send s"
              << std::setw(9) << "send%"
              << "\n";
    std::cerr << "------------------------------------------------------------------------------------------------\n";
    for (const auto& r : results) {
        std::cerr << std::left << std::setw(18) << r.config.name << std::right;
        if (!r.ok) {
            std::cerr << "  skipped\n";
            continue;
        }
        const double send_pct = r.breakdown.bulk_total_s > 0.0
            ? (r.breakdown.bulk_send_s / r.breakdown.bulk_total_s) * 100.0
            : 0.0;
        std::cerr << std::fixed << std::setprecision(1)
                  << std::setw(10) << r.breakdown.server_listen_ms
                  << std::setw(10) << r.breakdown.pq_ready_ms
                  << std::setw(10) << r.breakdown.client_socks_ms
                  << std::setw(10) << r.breakdown.connect_ms
                  << std::setw(10) << r.breakdown.warmup_ms
                  << std::setw(8) << r.breakdown.bulk_streams
                  << std::setprecision(3)
                  << std::setw(10) << r.breakdown.bulk_total_s
                  << std::setw(10) << r.breakdown.bulk_send_s
                  << std::setprecision(0)
                  << std::setw(8) << send_pct << "%"
                  << "\n";
    }
    std::cerr << "------------------------------------------------------------------------------------------------\n";
    std::cerr << "srv/pq/cli are startup waits. conn is TCP+SOCKS connect. warm is first echo.\n";
    std::cerr << "send% near 100 means writes are backpressured for most of the bulk transfer.\n";

    const bool has_repeats = std::any_of(results.begin(), results.end(), [](const Result& r) {
        return r.ok && r.repeat_count > 1;
    });
    if (!has_repeats) return;

    std::cerr << "\nRepeat throughput summary\n";
    std::cerr << "--------------------------------------------------------------------------------\n";
    std::cerr << std::left << std::setw(18) << "config"
              << std::right << std::setw(8) << "runs"
              << std::setw(12) << "min"
              << std::setw(12) << "median"
              << std::setw(12) << "mean"
              << std::setw(12) << "max"
              << std::setw(12) << "reported"
              << "\n";
    std::cerr << "--------------------------------------------------------------------------------\n";
    for (const auto& r : results) {
        if (!r.ok || r.repeat_count <= 1) continue;
        std::cerr << std::left << std::setw(18) << r.config.name << std::right
                  << std::setw(8) << r.repeat_count
                  << std::fixed << std::setprecision(1)
                  << std::setw(12) << r.throughput_trial_stats.min
                  << std::setw(12) << r.throughput_trial_stats.median
                  << std::setw(12) << r.throughput_trial_stats.mean
                  << std::setw(12) << r.throughput_trial_stats.max
                  << std::setw(12) << r.throughput_mib_s
                  << "\n";
    }
    std::cerr << "--------------------------------------------------------------------------------\n";
}

void render_hot_path_table(const std::vector<HotPathRow>& rows) {
    if (rows.empty()) {
        return;
    }
    std::cerr << "\nCommon hot-path details\n";
    std::cerr << "------------------------------------------------------------------------------------------------\n";
    std::cerr << std::left << std::setw(22) << "component"
              << std::right << std::setw(14) << "metric"
              << std::setw(10) << "unit"
              << std::setw(14) << "seconds"
              << "  detail\n";
    std::cerr << "------------------------------------------------------------------------------------------------\n";
    for (const auto& row : rows) {
        if (!row.ok) {
            std::cerr << std::left << std::setw(22) << row.name << "  FAILED: " << row.detail << "\n";
            continue;
        }
        std::cerr << std::left << std::setw(22) << row.name
                  << std::right << std::fixed << std::setprecision(1)
                  << std::setw(14) << row.value
                  << std::setw(10) << row.unit
                  << std::setprecision(6)
                  << std::setw(14) << row.seconds
                  << "  " << row.detail << "\n";
    }
    std::cerr << "------------------------------------------------------------------------------------------------\n";
}

}  // namespace

namespace yume::tools::selftest {

int run_cli(int argc, char** argv) {
    std::unique_ptr<TempDir> tmp;
    try {
        Args args = parse_args(argc, argv);
        if (args.list_configs) {
            for (const auto& cfg : builtin_configs()) {
                std::cout << std::left << std::setw(18) << cfg.name << " " << cfg.description << "\n";
            }
            return 0;
        }
        require_executable(args.yume, "yume");
        require_executable(args.yumed, "yumed");
        args.yume = fs::canonical(args.yume);
        args.yumed = fs::canonical(args.yumed);
        if (find_on_path("openssl").empty()) {
            throw std::runtime_error("openssl is required on PATH for temporary TLS/key material");
        }

        const auto configs = select_configs(args);
        apply_full_benchmark_defaults(args, configs.size());
        const auto benchmark_start = Clock::now();

        tmp = std::make_unique<TempDir>(args.keep_workdir);
        EchoServer echo;
        echo.set_sink(false);
        const int echo_port = echo.start();
        EchoServer sink;
        int sink_port = echo_port;
        if (args.one_way) {
            sink.set_sink(true);
            sink_port = sink.start();
        }
        Keyset ks = generate_keyset(args, tmp->path());
        const int hot_path_steps = args.full_benchmark ? 16 : 9;
        const int progress_total = std::max(
            1,
            static_cast<int>(configs.size()) * std::max(1, args.repeats) + hot_path_steps);
        int progress_completed = 0;
        SystemLoadSampler load_sampler;
        if (args.full_benchmark) {
            load_sampler.start();
        }

        std::vector<Result> results;
        results.reserve(configs.size());
        for (std::size_t i = 0; i < configs.size(); ++i) {
            const auto& cfg = configs[i];
            if (i > 0 && args.cooldown_ms > 0) {
                if (!progress_inline_enabled()) {
                    std::cerr << kBenchLogPrefix << " cooldown " << args.cooldown_ms << " ms before " << cfg.name << "\n";
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(args.cooldown_ms));
            }
            Result result = run_config_repeated(
                args,
                ks,
                cfg,
                tmp->path(),
                echo_port,
                sink_port,
                progress_completed,
                progress_total);
            if (!result.ok) tmp->keep();
            results.push_back(std::move(result));
        }
        sink.stop();
        echo.stop();
        std::vector<HotPathRow> hot_paths = run_hot_paths(
            args,
            tmp->path(),
            progress_completed,
            progress_total);
        if (args.full_benchmark) {
            hot_paths.push_back(load_sampler.stop());
        }

        finish_progress_line();
        const double benchmark_elapsed_seconds = elapsed_s(benchmark_start, Clock::now());
        const BenchmarkScore engine_league_score = compute_hot_path_score(args, hot_paths, false);
        const BenchmarkScore global_engine_score = compute_hot_path_score(args, hot_paths, true);
        const BenchmarkScore transport_score = compute_score(args, results);
        const BenchmarkScore global_transport_score = compute_transport_score(args, results, true);
        const BenchmarkScore capacity_score = compute_system_capacity_score(args);
        const BenchmarkScore global_score = compute_global_score(
            args,
            global_engine_score,
            global_transport_score,
            capacity_score,
            benchmark_elapsed_seconds);
        const BenchmarkScore league_score = compute_desktop_league_score(
            args,
            engine_league_score,
            transport_score);
        if (args.full_benchmark) {
            render_score(args, global_score, league_score);
        }
        if (args.dev_style) {
            render_hot_path_table(hot_paths);
            render_table(results);
        }
        if (!args.full_benchmark) {
            render_score(args, global_score, league_score);
        }
        const std::string json = render_json(
            args,
            results,
            hot_paths,
            tmp->path(),
            global_score,
            league_score,
            engine_league_score,
            transport_score);
        if (!args.json_path.empty()) {
            write_text(args.json_path, json);
            std::cerr << kBenchLogPrefix << " wrote JSON " << args.json_path << "\n";
        }
        if (args.json_stdout) {
            std::cout << json;
        }

        const bool all_ok = std::all_of(results.begin(), results.end(), [](const Result& r) { return r.ok; });
        if (!all_ok) {
            tmp->keep();
            std::cerr << kBenchLogPrefix << " logs kept in " << tmp->path() << "\n";
        }
        return all_ok ? 0 : 1;
    } catch (const std::exception& ex) {
        finish_progress_line();
        const std::string exe_name = (argc > 0 && argv && argv[0])
            ? fs::path(argv[0]).filename().string()
            : std::string{};
        const char* prefix = exe_name == "yume-selftest" ? "yume-selftest" : "yume benchmark";
        std::cerr << prefix << ": " << ex.what() << "\n";
        if (tmp) {
            tmp->keep();
            std::cerr << kBenchLogPrefix << " logs kept in " << tmp->path() << "\n";
        }
        return 2;
    }
}

}  // namespace yume::tools::selftest
