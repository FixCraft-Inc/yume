/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "selftest/runtime.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace {

using namespace yume::tools::selftest;
namespace fs = std::filesystem;

void render_progress_bar(int completed, int total, std::string_view label) {
    total = std::max(1, total);
    completed = std::clamp(completed, 0, total);
    constexpr int kWidth = 28;
    const int filled = static_cast<int>((static_cast<long long>(completed) * kWidth) / total);
    const int percent = static_cast<int>((static_cast<long long>(completed) * 100) / total);
    std::cerr << "[selftest] progress [";
    for (int i = 0; i < kWidth; ++i) {
        std::cerr << (i < filled ? '#' : '.');
    }
    std::cerr << "] " << std::setw(3) << percent << "% "
              << completed << "/" << total << " " << label << "\n";
}


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
        << "                            default 60; scales payload size)\n"
        << "  --latency-iters <N>       Echo round trips per config (default 120)\n"
        << "  --bulk-mib <N>            Bulk echo size per config (default 32)\n"
        << "  --argon-mem-kib <N>       Heavy KDF memory cap/env for this run (default 32768)\n"
        << "  --argon-parallelism <N>   Heavy KDF parallelism cap/env (default 2)\n"
        << "  --tunnels <N>             Client TLS tunnel count (default 1)\n"
        << "  --streams <N>             Concurrent bulk streams per config (default 1)\n"
        << "  --client-threads <N>      Client io threads (0=auto/hw concurrency)\n"
        << "  --server-threads <N>      Server io threads (default 2)\n"
        << "  --cooldown-ms <N>         Pause between configs for fairer sweeps (default 500)\n"
        << "  --repeat <N>              Run each config N times; report median-throughput trial\n"
        << "  --one-way                 Measure one-way upload (sink+ack), not echo\n"
        << "  --json <path>             Write JSON result file\n"
        << "  --json-stdout             Print JSON to stdout after the table\n"
        << "  --keep-workdir            Keep temp logs and generated keys\n"
        << "  --list-configs            Print config names and exit\n"
        << "  -h, --help                Show this help\n\n"
        << "Notes:\n"
        << "  Default/no --configs runs every built-in config, including heavy-hop-2hz.\n"
        << "  Config aliases: all expands to the full suite; all-on selects heavy-hop-2hz.\n"
        << "  Quick mode prints raw tables only. Full mode also prints a normalized\n"
        << "  YUME score from 0..10,000,000 for easy device-to-device comparison.\n"
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
        } else if (arg == "--argon-parallelism") {
            args.argon_parallelism = std::max(1, std::stoi(require_value(i, arg)));
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
    std::cerr << "[selftest] " << cfg.name << ": " << cfg.description << "\n";
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
            std::cerr << "[selftest] cooldown " << args.cooldown_ms
                      << " ms before " << cfg.name << " trial "
                      << (trial + 1) << "/" << args.repeats << "\n";
            std::this_thread::sleep_for(std::chrono::milliseconds(args.cooldown_ms));
        }
        std::cerr << "[selftest] " << cfg.name << " trial "
                  << (trial + 1) << "/" << args.repeats << "\n";
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

void apply_full_benchmark_defaults(Args& args, std::size_t config_count) {
    if (!args.full_benchmark) {
        return;
    }
    if (!args.target_duration_override) {
        args.target_duration_sec = 60;
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
        args.server_threads = 4;
    }
    if (!args.cooldown_ms_override) {
        args.cooldown_ms = 1000;
    }
    if (!args.one_way_override) {
        args.one_way = true;
    }
    if (!args.latency_iters_override) {
        args.latency_iters = 240;
    }
    if (!args.bulk_mib_override) {
        const int divisor = std::max(1, static_cast<int>(config_count) * args.repeats);
        const int mib = (args.target_duration_sec * 1024) / divisor;
        args.bulk_mib = std::clamp(mib, 512, 8192);
    }
}

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

const Result* find_result(const std::vector<Result>& results, std::string_view name) {
    auto it = std::find_if(results.begin(), results.end(), [&](const Result& r) {
        return r.ok && r.config.name == name;
    });
    return it == results.end() ? nullptr : &*it;
}

constexpr double kBenchmarkReferenceScore = 10000000.0;

double score_scale(double ratio) {
    if (ratio <= 0.0) {
        return 0.0;
    }
    if (ratio <= 1.0) {
        return std::pow(ratio, 0.70);
    }
    return 1.0 + std::log1p(ratio - 1.0) * 0.22;
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

std::string format_integer(long long value) {
    const bool negative = value < 0;
    std::string digits = std::to_string(negative ? -value : value);
    std::string out;
    out.reserve(digits.size() + digits.size() / 3 + 1);
    if (negative) {
        out.push_back('-');
    }
    const std::size_t first_group = digits.size() % 3;
    for (std::size_t i = 0; i < digits.size(); ++i) {
        if (i > 0 && (i - first_group) % 3 == 0) {
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

    add_throughput("base-direct", 12000.0, 600000.0);
    add_throughput("no-inner-raw", 1600.0, 1000000.0);
    add_throughput("no-inner-obfs", 1500.0, 1300000.0);
    add_throughput("light-no-hop", 1350.0, 1400000.0);
    add_throughput("light-hop-2hz", 1250.0, 1800000.0);
    add_throughput("heavy-no-hop", 1150.0, 1400000.0);
    add_throughput("heavy-hop-2hz", 1100.0, 1900000.0);

    const Result* latency_anchor = find_result(results, "heavy-hop-2hz");
    if (latency_anchor && latency_anchor->latency_ms.median > 0.0) {
        score.components.push_back({
            "latency-anchor",
            latency_anchor->latency_ms.median,
            "ms",
            scaled_latency_points(latency_anchor->latency_ms.median, 0.05, 600000.0),
            600000.0,
        });
    } else {
        missing_required.push_back("latency-anchor");
    }

    if (!missing_required.empty()) {
        score.unavailable_reason = "partial benchmark; run --full without --configs for an overall score";
        return score;
    }

    double earned = 0.0;
    double possible = 0.0;
    for (const auto& component : score.components) {
        earned += component.points;
        possible += component.reference_points;
    }
    if (possible <= 0.0) {
        return score;
    }
    score.available = true;
    score.total = std::max<long long>(
        0,
        static_cast<long long>(std::llround((earned / possible) * kBenchmarkReferenceScore)));
    return score;
}

std::string score_grade(long long score) {
    if (score >= 60000000) return "SSS+";
    if (score >= 40000000) return "SSS";
    if (score >= 28000000) return "SSS-";
    if (score >= 20000000) return "SS+";
    if (score >= 15000000) return "SS";
    if (score >= 11000000) return "SS-";
    if (score >= 9000000) return "S+";
    if (score >= 7000000) return "S";
    if (score >= 5200000) return "S-";
    if (score >= 3800000) return "AAA+";
    if (score >= 2800000) return "AAA";
    if (score >= 2000000) return "AAA-";
    if (score >= 1500000) return "A+";
    if (score >= 1100000) return "A";
    if (score >= 800000) return "A-";
    if (score >= 580000) return "B+";
    if (score >= 420000) return "B";
    if (score >= 300000) return "B-";
    if (score >= 210000) return "C+";
    if (score >= 150000) return "C";
    if (score >= 100000) return "C-";
    if (score >= 65000) return "D+";
    if (score >= 40000) return "D";
    if (score >= 25000) return "D-";
    if (score >= 12000) return "F+";
    if (score >= 6000) return "F";
    return "F-";
}

void render_score(const Args& args, const BenchmarkScore& score) {
    if (!args.full_benchmark) {
        std::cerr << "\nOverall score: not computed in quick mode. Use --full for the long benchmark score.\n";
        return;
    }
    if (!score.available) {
        std::cerr << "\nYUME benchmark score: not computed";
        if (!score.unavailable_reason.empty()) {
            std::cerr << " (" << score.unavailable_reason << ")";
        }
        std::cerr << ".\n";
        return;
    }
    std::cerr << "\nYUME benchmark score\n";
    std::cerr << "--------------------------------------------------------------------------------\n";
    std::cerr << "score: " << format_integer(score.total)
              << "  grade " << score_grade(score.total) << "\n";
    std::cerr << "mode: full"
              << "  target=" << args.target_duration_sec << "s"
              << "  bulk=" << args.bulk_mib << "MiB"
              << "  streams=" << args.streams
              << "  repeats=" << args.repeats
              << "  tunnels=" << args.tunnels << "\n";
    std::cerr << "reference score: 10,000,000; faster systems can score higher.\n";
    std::cerr << "Use the raw MiB/s and latency rows for exact measurements.\n";
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
}

void render_table(const std::vector<Result>& results) {
    const auto base = std::find_if(results.begin(), results.end(), [](const Result& r) {
        return r.ok && r.config.base_direct;
    });
    const double base_lat = base == results.end() ? 0.0 : base->latency_ms.median;
    const double base_thr = base == results.end() ? 0.0 : base->throughput_mib_s;

    std::cerr << "\nYUME localhost self-test\n";
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
    std::cerr << "\nSelf-test phase breakdown\n";
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

std::string render_json(const Args& args,
                        const std::vector<Result>& results,
                        const fs::path& workdir,
                        const BenchmarkScore& score) {
    std::ostringstream out;
    out << "{\n";
    out << "  \"schema_version\": 7,\n";
    out << "  \"benchmark_mode\": \"" << (args.full_benchmark ? "full" : "quick") << "\",\n";
    out << "  \"workdir\": \"" << json_escape(workdir.string()) << "\",\n";
    out << "  \"score\": ";
    if (score.available) {
        out << "{\n";
        out << "    \"model\": \"yume-bench-v2\",\n";
        out << "    \"total\": " << score.total << ",\n";
        out << "    \"reference\": 10000000,\n";
        out << "    \"grade\": \"" << score_grade(score.total) << "\",\n";
        out << "    \"components\": [\n";
        for (std::size_t i = 0; i < score.components.size(); ++i) {
            const auto& c = score.components[i];
            out << "      {\"name\": \"" << json_escape(c.name) << "\", "
                << "\"raw\": " << c.raw << ", "
                << "\"unit\": \"" << json_escape(c.unit) << "\", "
                << "\"points\": " << c.points << ", "
                << "\"reference_points\": " << c.reference_points << "}"
                << (i + 1 == score.components.size() ? "\n" : ",\n");
        }
        out << "    ]\n";
        out << "  },\n";
    } else {
        out << "null,\n";
    }
    out << "  \"score_unavailable_reason\": ";
    if (score.available || score.unavailable_reason.empty()) {
        out << "null,\n";
    } else {
        out << "\"" << json_escape(score.unavailable_reason) << "\",\n";
    }
    out << "  \"latency_iters\": " << args.latency_iters << ",\n";
    out << "  \"bulk_mib\": " << args.bulk_mib << ",\n";
    out << "  \"streams\": " << args.streams << ",\n";
    out << "  \"argon_mem_kib\": " << args.argon_mem_kib << ",\n";
    out << "  \"argon_parallelism\": " << args.argon_parallelism << ",\n";
    out << "  \"cooldown_ms\": " << args.cooldown_ms << ",\n";
    out << "  \"repeat\": " << args.repeats << ",\n";
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

int main(int argc, char** argv) {
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
        const int progress_total = std::max(1, static_cast<int>(configs.size()) * std::max(1, args.repeats));
        int progress_completed = 0;

        std::vector<Result> results;
        results.reserve(configs.size());
        for (std::size_t i = 0; i < configs.size(); ++i) {
            const auto& cfg = configs[i];
            if (i > 0 && args.cooldown_ms > 0) {
                std::cerr << "[selftest] cooldown " << args.cooldown_ms << " ms before " << cfg.name << "\n";
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

        render_table(results);
        const BenchmarkScore score = compute_score(args, results);
        render_score(args, score);
        const std::string json = render_json(args, results, tmp->path(), score);
        if (!args.json_path.empty()) {
            write_text(args.json_path, json);
            std::cerr << "[selftest] wrote JSON " << args.json_path << "\n";
        }
        if (args.json_stdout) {
            std::cout << json;
        }

        const bool all_ok = std::all_of(results.begin(), results.end(), [](const Result& r) { return r.ok; });
        if (!all_ok) {
            tmp->keep();
            std::cerr << "[selftest] logs kept in " << tmp->path() << "\n";
        }
        return all_ok ? 0 : 1;
    } catch (const std::exception& ex) {
        std::cerr << "yume-selftest: " << ex.what() << "\n";
        if (tmp) {
            tmp->keep();
            std::cerr << "[selftest] logs kept in " << tmp->path() << "\n";
        }
        return 2;
    }
}
