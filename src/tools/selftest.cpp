/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "tools/selftest/runner.hpp"

#include "core/protocol/packet_bulk.hpp"
#include "selftest/runtime.hpp"

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

bool stderr_is_tty() {
#if !defined(_WIN32)
    static const bool enabled = ::isatty(STDERR_FILENO) == 1;
#else
    static const bool enabled = true;
#endif
    return enabled;
}

bool progress_inline_enabled() {
    return stderr_is_tty();
}

bool color_enabled(const Args& args) {
    return args.color && stderr_is_tty() && std::getenv("NO_COLOR") == nullptr;
}

bool& progress_line_active() {
    static bool active = false;
    return active;
}

void finish_progress_line() {
    if (progress_inline_enabled() && progress_line_active()) {
        std::cerr << "\n";
        progress_line_active() = false;
    }
}

std::string ansi_wrap(const Args& args, std::string_view code, std::string value) {
    if (!color_enabled(args)) {
        return value;
    }
    return "\033[" + std::string(code) + "m" + value + "\033[0m";
}

std::string grade_color_code(std::string_view grade, long long score) {
    if (score > 0 && score < 2500) return "30;47;1";      // critical: black on white
    if (grade == "F-") return "38;5;52;1";                 // darkest red
    if (grade == "F") return "38;5;88;1";
    if (grade == "F+") return "38;5;124;1";
    if (grade == "D-") return "38;5;160;1";                // red
    if (grade == "D") return "38;5;196;1";
    if (grade == "D+") return "38;5;202;1";                // dark orange
    if (grade == "C-") return "38;5;208;1";
    if (grade == "C") return "38;5;214;1";                 // orange
    if (grade == "C+") return "38;5;220;1";
    if (grade == "B-") return "38;5;136;1";                // dark yellow
    if (grade == "B") return "38;5;178;1";
    if (grade == "B+") return "38;5;226;1";                // light yellow
    if (grade == "A-") return "38;5;190;1";
    if (grade == "A") return "38;5;154;1";                 // light green
    if (grade == "A+") return "38;5;118;1";
    if (grade == "AAA-") return "38;5;82;1";
    if (grade == "AAA") return "38;5;34;1";                // green
    if (grade == "AAA+") return "38;5;28;1";               // dark green
    if (grade == "S-") return "38;5;24;1";
    if (grade == "S") return "38;5;25;1";                  // dark blue
    if (grade == "S+") return "38;5;26;1";
    if (grade == "SS-") return "38;5;27;1";
    if (grade == "SS") return "38;5;33;1";
    if (grade == "SS+") return "38;5;39;1";
    if (grade == "SSS-") return "38;5;45;1";
    if (grade == "SSS") return "38;5;51;1";
    return "96;1";                                         // SSS+ light blue
}

std::string color_grade(const Args& args, std::string grade, long long score) {
    return ansi_wrap(args, grade_color_code(grade, score), std::move(grade));
}

void render_progress_bar(double completed, int total, std::string_view label) {
    total = std::max(1, total);
    completed = std::clamp(completed, 0.0, static_cast<double>(total));
    constexpr int kWidth = 28;
    const int filled = static_cast<int>((completed * kWidth) / static_cast<double>(total));
    const int percent = static_cast<int>((completed * 100.0) / static_cast<double>(total));
    std::ostringstream line;
    line << "[bench] progress [";
    for (int i = 0; i < kWidth; ++i) {
        line << (i < filled ? '#' : '.');
    }
    line << "] " << std::setw(3) << std::clamp(percent, 0, 100) << "% ";
    const double rounded = std::round(completed);
    if (std::abs(completed - rounded) < 0.05) {
        line << static_cast<int>(rounded);
    } else {
        line << std::fixed << std::setprecision(1) << completed;
    }
    line << "/" << total << " " << label;

    if (progress_inline_enabled()) {
        std::cerr << "\r" << line.str() << "        " << std::flush;
        progress_line_active() = true;
        if (completed >= total) {
            std::cerr << "\n";
            progress_line_active() = false;
        }
        return;
    }

    static int last_bucket = -1;
    const int bucket = std::clamp(percent, 0, 100) / 10;
    if (completed >= total || (percent > 0 && bucket != last_bucket)) {
        std::cerr << line.str() << "\n";
        last_bucket = bucket;
    }
}

void render_progress_bar(int completed, int total, std::string_view label) {
    render_progress_bar(static_cast<double>(completed), total, label);
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
        << "  --dev                     Show component tables, timings, and row details\n"
        << "  --no-color                Disable ANSI colors in terminal output\n"
        << "  --keep-workdir            Keep temp logs and generated keys\n"
        << "  --list-configs            Print config names and exit\n"
        << "  -h, --help                Show this help\n\n"
        << "Notes:\n"
        << "  Default/no --configs runs every built-in config, including heavy-hop-2hz.\n"
        << "  Config aliases: all expands to the full suite; all-on selects heavy-hop-2hz.\n"
        << "  Quick mode is an unscored smoke test. Full mode prints GLOBAL and\n"
        << "  LEAGUE scores. GLOBAL uses rows shared with Android; LEAGUE compares\n"
        << "  desktop YUME transport behavior against desktop baselines.\n"
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
        std::cerr << "[bench] " << cfg.name << ": " << cfg.description << "\n";
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
                std::cerr << "[bench] cooldown " << args.cooldown_ms
                          << " ms before " << cfg.name << " trial "
                          << (trial + 1) << "/" << args.repeats << "\n";
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(args.cooldown_ms));
        }
        if (!progress_inline_enabled()) {
            std::cerr << "[bench] " << cfg.name << " trial "
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

const Result* find_result(const std::vector<Result>& results, std::string_view name) {
    auto it = std::find_if(results.begin(), results.end(), [&](const Result& r) {
        return r.ok && r.config.name == name;
    });
    return it == results.end() ? nullptr : &*it;
}

constexpr double kBenchmarkReferenceScore = 10000000.0;
constexpr int kKiB = 1024;
constexpr int kMiB = 1024 * kKiB;

double score_scale(double ratio) {
    if (ratio <= 0.0) {
        return 0.0;
    }
    if (ratio <= 1.0) {
        return std::pow(ratio, 0.95);
    }
    return 1.0 + std::log1p(ratio - 1.0) * 0.12;
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

    add_throughput("base-direct", 100000.0, 600000.0);
    add_throughput("no-inner-raw", 12000.0, 1000000.0);
    add_throughput("no-inner-obfs", 11000.0, 1300000.0);
    add_throughput("light-no-hop", 10000.0, 1400000.0);
    add_throughput("light-hop-2hz", 9500.0, 1800000.0);
    add_throughput("heavy-no-hop", 9000.0, 1400000.0);
    add_throughput("heavy-hop-2hz", 8500.0, 1900000.0);

    const Result* latency_anchor = find_result(results, "heavy-hop-2hz");
    if (latency_anchor && latency_anchor->latency_ms.median > 0.0) {
        score.components.push_back({
            "latency-anchor",
            latency_anchor->latency_ms.median,
            "ms",
            scaled_latency_points(latency_anchor->latency_ms.median, 0.025, 600000.0),
            600000.0,
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

std::vector<std::uint8_t> patterned_bytes(std::size_t size, int seed = 17) {
    std::vector<std::uint8_t> out(size);
    for (std::size_t i = 0; i < size; ++i) {
        out[i] = static_cast<std::uint8_t>(((i * 31u) + static_cast<unsigned>(seed * 13)) & 0xffu);
    }
    return out;
}

int iterations_for(std::uint64_t total_bytes, std::size_t chunk_bytes) {
    return static_cast<int>(std::max<std::uint64_t>(1, total_bytes / std::max<std::size_t>(1, chunk_bytes)));
}

HotPathRow throughput_row(std::string name,
                          std::uint64_t bytes,
                          double seconds,
                          std::string detail) {
    const double mib_s = (static_cast<double>(bytes) / static_cast<double>(kMiB)) /
                         std::max(seconds, 0.000001);
    std::ostringstream metric;
    metric << std::fixed << std::setprecision(1) << mib_s << " MiB/s";
    return {
        std::move(name),
        metric.str(),
        std::move(detail),
        true,
        mib_s,
        "MiB/s",
        bytes,
        0,
        seconds,
    };
}

HotPathRow run_copy_floor(std::uint64_t total_bytes) {
    const auto src = patterned_bytes(64 * kKiB);
    std::vector<std::uint8_t> dst(src.size());
    const int iterations = iterations_for(total_bytes, src.size());
    int guard = 0;
    const auto start = Clock::now();
    for (int i = 0; i < iterations; ++i) {
        std::copy(src.begin(), src.end(), dst.begin());
        guard ^= dst[static_cast<std::size_t>(i) & (dst.size() - 1)];
    }
    const double seconds = elapsed_s(start, Clock::now());
    return throughput_row("copy-floor",
                          static_cast<std::uint64_t>(iterations) * src.size(),
                          seconds,
                          "64 KiB vector copy, guard=" + std::to_string(guard & 0xff));
}

HotPathRow run_stream_copy(std::uint64_t total_bytes, int streams) {
    const int stream_count = std::max(1, streams);
    std::vector<std::uint64_t> per_stream(static_cast<std::size_t>(stream_count),
                                          total_bytes / static_cast<std::uint64_t>(stream_count));
    std::uint64_t remaining = total_bytes % static_cast<std::uint64_t>(stream_count);
    for (int i = 0; remaining > 0; ++i, --remaining) {
        per_stream[static_cast<std::size_t>(i % stream_count)] += 1;
    }

    const auto src = patterned_bytes(32 * kKiB);
    std::atomic<bool> start_flag{false};
    std::vector<double> stream_seconds(static_cast<std::size_t>(stream_count), 0.0);
    std::vector<int> guards(static_cast<std::size_t>(stream_count), 0);
    std::vector<std::thread> workers;
    workers.reserve(static_cast<std::size_t>(stream_count));
    for (int stream = 0; stream < stream_count; ++stream) {
        workers.emplace_back([&, stream] {
            std::vector<std::uint8_t> dst(src.size());
            while (!start_flag.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            const auto started = Clock::now();
            std::uint64_t copied = 0;
            int guard = 0;
            const auto target = per_stream[static_cast<std::size_t>(stream)];
            while (copied < target) {
                const auto chunk = static_cast<std::size_t>(
                    std::min<std::uint64_t>(src.size(), target - copied));
                std::copy_n(src.begin(), static_cast<std::ptrdiff_t>(chunk), dst.begin());
                guard ^= dst[(copied / std::max<std::size_t>(1, chunk)) & (dst.size() - 1)];
                copied += chunk;
            }
            stream_seconds[static_cast<std::size_t>(stream)] = elapsed_s(started, Clock::now());
            guards[static_cast<std::size_t>(stream)] = guard;
        });
    }
    const auto started = Clock::now();
    start_flag.store(true, std::memory_order_release);
    for (auto& worker : workers) {
        worker.join();
    }
    const double seconds = elapsed_s(started, Clock::now());
    std::vector<double> stream_rates;
    stream_rates.reserve(stream_seconds.size());
    for (std::size_t i = 0; i < stream_seconds.size(); ++i) {
        stream_rates.push_back((static_cast<double>(per_stream[i]) / static_cast<double>(kMiB)) /
                               std::max(stream_seconds[i], 0.000001));
    }
    const Stats stats = compute_stats(stream_rates);
    const double instability = stats.median > 0.0 ? ((stats.max - stats.min) / stats.median) * 100.0 : 0.0;
    const int guard = std::accumulate(guards.begin(), guards.end(), 0, [](int a, int b) { return a ^ b; }) & 0xff;
    std::ostringstream detail;
    detail << "streams=" << stream_count
           << " per_stream_mib_s min=" << std::fixed << std::setprecision(1) << stats.min
           << " median=" << stats.median
           << " p95=" << stats.p95
           << " max=" << stats.max
           << " instability=" << instability << "% guard=" << guard;
    return throughput_row(stream_count == 1 ? "stream-copy-1" : "stream-copy-many",
                          total_bytes,
                          seconds,
                          detail.str());
}

yume::protocol::packet_bulk::Batch packet_batch() {
    yume::protocol::packet_bulk::Batch batch;
    batch.sequence = 1;
    batch.packets.reserve(yume::protocol::packet_bulk::kMaxPacketsPerBatch);
    for (std::size_t i = 0; i < yume::protocol::packet_bulk::kMaxPacketsPerBatch; ++i) {
        auto packet = patterned_bytes(1200, static_cast<int>(i + 1));
        packet[0] = 0x45;
        packet[1] = 0x00;
        batch.packets.push_back(std::move(packet));
    }
    return batch;
}

HotPathRow run_aead_encrypt(std::uint64_t total_bytes) {
    const auto key = patterned_bytes(32, 3);
    const std::vector<std::uint8_t> aad{
        'y', 'u', 'm', 'e', '-', 'd', 'e', 's', 'k', 't', 'o', 'p', '-', 'b', 'e', 'n', 'c', 'h'};
    const auto plaintext = patterned_bytes(64 * kKiB);
    const int iterations = iterations_for(total_bytes, plaintext.size());
    int guard = 0;
    const auto start = Clock::now();
    for (int i = 0; i < iterations; ++i) {
        auto encrypted = basefwx::crypto::AeadEncrypt(key, plaintext, aad);
        guard ^= encrypted.back();
    }
    const double seconds = elapsed_s(start, Clock::now());
    return throughput_row("aes-gcm-encrypt",
                          static_cast<std::uint64_t>(iterations) * plaintext.size(),
                          seconds,
                          "BaseFWX AES-GCM, 64 KiB chunks, guard=" + std::to_string(guard & 0xff));
}

HotPathRow run_aead_decrypt(std::uint64_t total_bytes) {
    const auto key = patterned_bytes(32, 3);
    const std::vector<std::uint8_t> aad{
        'y', 'u', 'm', 'e', '-', 'd', 'e', 's', 'k', 't', 'o', 'p', '-', 'b', 'e', 'n', 'c', 'h'};
    const auto plaintext = patterned_bytes(64 * kKiB);
    const auto encrypted = basefwx::crypto::AeadEncrypt(key, plaintext, aad);
    const int iterations = iterations_for(total_bytes, plaintext.size());
    int guard = 0;
    const auto start = Clock::now();
    for (int i = 0; i < iterations; ++i) {
        auto decrypted = basefwx::crypto::AeadDecrypt(key, encrypted, aad);
        guard ^= decrypted[static_cast<std::size_t>(i) & (decrypted.size() - 1)];
    }
    const double seconds = elapsed_s(start, Clock::now());
    return throughput_row("aes-gcm-decrypt",
                          static_cast<std::uint64_t>(iterations) * plaintext.size(),
                          seconds,
                          "BaseFWX AES-GCM, 64 KiB chunks, guard=" + std::to_string(guard & 0xff));
}

HotPathRow run_packet_bulk_encode(std::uint64_t total_bytes) {
    auto batch = packet_batch();
    const auto encoded_size = yume::protocol::packet_bulk::encoded_size(batch);
    const int iterations = iterations_for(total_bytes, encoded_size);
    int guard = 0;
    const auto start = Clock::now();
    for (int i = 0; i < iterations; ++i) {
        batch.sequence = static_cast<std::uint64_t>(i);
        auto encoded = yume::protocol::packet_bulk::encode_batch(batch);
        guard ^= encoded.back();
    }
    const double seconds = elapsed_s(start, Clock::now());
    return throughput_row("packet-bulk-encode",
                          static_cast<std::uint64_t>(iterations) * encoded_size,
                          seconds,
                          "64 packets/batch, guard=" + std::to_string(guard & 0xff));
}

HotPathRow run_packet_bulk_decode(std::uint64_t total_bytes) {
    const auto batch = packet_batch();
    const auto encoded = yume::protocol::packet_bulk::encode_batch(batch);
    const int iterations = iterations_for(total_bytes, encoded.size());
    int guard = 0;
    const auto start = Clock::now();
    for (int i = 0; i < iterations; ++i) {
        auto decoded = yume::protocol::packet_bulk::decode_batch(encoded);
        if (!decoded.has_value()) {
            throw std::runtime_error("packet bulk decode failed");
        }
        guard ^= decoded->packets.back().back();
    }
    const double seconds = elapsed_s(start, Clock::now());
    return throughput_row("packet-bulk-decode",
                          static_cast<std::uint64_t>(iterations) * encoded.size(),
                          seconds,
                          "64 packets/batch, guard=" + std::to_string(guard & 0xff));
}

HotPathRow run_hop_hkdf(int ops) {
    const auto key = patterned_bytes(32, 9);
    const int count = std::max(1, ops);
    int guard = 0;
    const auto start = Clock::now();
    for (int i = 0; i < count; ++i) {
        const std::string info = "yume-hop-v1:" + std::to_string(i);
        auto derived = basefwx::crypto::HkdfSha256(key, info, 32);
        guard ^= derived.front();
    }
    const double seconds = elapsed_s(start, Clock::now());
    const double ops_s = static_cast<double>(count) / std::max(seconds, 0.000001);
    std::ostringstream metric;
    metric << std::fixed << std::setprecision(1) << ops_s << " ops/s";
    return {
        "hop-hkdf",
        metric.str(),
        std::to_string(count) + " derived hop keys, guard=" + std::to_string(guard & 0xff),
        true,
        ops_s,
        "ops/s",
        0,
        static_cast<std::uint64_t>(count),
        seconds,
    };
}

HotPathRow run_disk_write(const fs::path& workdir, std::uint64_t total_bytes) {
    const fs::path path = workdir / "disk-write.bin";
    const auto chunk = patterned_bytes(64 * kKiB);
    const int iterations = iterations_for(total_bytes, chunk.size());
    int guard = 0;
    const auto start = Clock::now();
#if !defined(_WIN32)
    int fd = ::open(path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0) {
        throw std::runtime_error("open disk benchmark file failed: " + std::string(std::strerror(errno)));
    }
    for (int i = 0; i < iterations; ++i) {
        const std::uint8_t* ptr = chunk.data();
        std::size_t remaining = chunk.size();
        while (remaining > 0) {
            const auto written = ::write(fd, ptr, remaining);
            if (written < 0) {
                ::close(fd);
                throw std::runtime_error("write disk benchmark file failed: " + std::string(std::strerror(errno)));
            }
            ptr += written;
            remaining -= static_cast<std::size_t>(written);
        }
        guard ^= chunk[static_cast<std::size_t>(i) & (chunk.size() - 1)];
    }
    if (::fsync(fd) != 0) {
        ::close(fd);
        throw std::runtime_error("fsync disk benchmark file failed: " + std::string(std::strerror(errno)));
    }
    ::close(fd);
#else
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) {
            throw std::runtime_error("open disk benchmark file failed");
        }
        for (int i = 0; i < iterations; ++i) {
            out.write(reinterpret_cast<const char*>(chunk.data()), static_cast<std::streamsize>(chunk.size()));
            if (!out) {
                throw std::runtime_error("write disk benchmark file failed");
            }
            guard ^= chunk[static_cast<std::size_t>(i) & (chunk.size() - 1)];
        }
        out.flush();
        if (!out) {
            throw std::runtime_error("flush disk benchmark file failed");
        }
    }
#endif
    std::error_code ec;
    fs::remove(path, ec);
    const double seconds = elapsed_s(start, Clock::now());
    return throughput_row("disk-write",
                          static_cast<std::uint64_t>(iterations) * chunk.size(),
                          seconds,
                          "cache file write, 64 KiB chunks, fsync, guard=" + std::to_string(guard & 0xff));
}

HotPathRow run_sustained_mix(long target_ms,
                             const std::function<void(double)>& progress) {
    const auto key = patterned_bytes(32, 11);
    const std::vector<std::uint8_t> aad{
        'y', 'u', 'm', 'e', '-', 'd', 'e', 's', 'k', 't', 'o', 'p', '-', 'b', 'e', 'n', 'c', 'h'};
    const auto plaintext = patterned_bytes(64 * kKiB);
    auto batch = packet_batch();
    const auto encoded_packet_bytes = yume::protocol::packet_bulk::encoded_size(batch);
    const auto started = Clock::now();
    const auto deadline = started + std::chrono::milliseconds(std::max<long>(1, target_ms));
    auto next_progress = started;
    int guard = 0;
    std::uint64_t rounds = 0;
    std::uint64_t bytes = 0;
    auto now = started;
    do {
        auto encrypted = basefwx::crypto::AeadEncrypt(key, plaintext, aad);
        auto decrypted = basefwx::crypto::AeadDecrypt(key, encrypted, aad);
        batch.sequence = rounds;
        auto encoded = yume::protocol::packet_bulk::encode_batch(batch);
        auto decoded = yume::protocol::packet_bulk::decode_batch(encoded);
        const std::string info = "yume-sustain:" + std::to_string(rounds);
        auto derived = basefwx::crypto::HkdfSha256(key, info, 32);
        if (!decoded.has_value()) {
            throw std::runtime_error("packet bulk sustained decode failed");
        }
        guard ^= decrypted[rounds & (decrypted.size() - 1)];
        guard ^= decoded->packets.back().back();
        guard ^= derived.front();
        bytes += static_cast<std::uint64_t>(plaintext.size()) * 2u;
        bytes += static_cast<std::uint64_t>(encoded_packet_bytes) * 2u;
        ++rounds;
        now = Clock::now();
        if (now >= next_progress) {
            progress(std::chrono::duration<double>(now - started).count() /
                     (static_cast<double>(target_ms) / 1000.0));
            next_progress = now + std::chrono::milliseconds(500);
        }
    } while (now < deadline);
    const double seconds = elapsed_s(started, Clock::now());
    return throughput_row("sustained-mix",
                          bytes,
                          seconds,
                          std::to_string(target_ms) + "ms mixed AES-GCM + packet bulk + HKDF, rounds=" +
                              std::to_string(rounds) + ", guard=" + std::to_string(guard & 0xff));
}

std::vector<HotPathRow> run_hot_paths(const Args& args,
                                      const fs::path& workdir,
                                      int& progress_completed,
                                      int progress_total) {
    const bool full = args.full_benchmark;
    const std::uint64_t copy_bytes = static_cast<std::uint64_t>(full ? 512 : 64) * kMiB;
    const std::uint64_t stream_single_bytes = static_cast<std::uint64_t>(full ? 256 : 32) * kMiB;
    const std::uint64_t stream_many_bytes = static_cast<std::uint64_t>(full ? 1024 : 256) * kMiB;
    const std::uint64_t crypto_bytes = static_cast<std::uint64_t>(full ? 512 : 32) * kMiB;
    const std::uint64_t packet_bytes = static_cast<std::uint64_t>(full ? 512 : 32) * kMiB;
    const int hkdf_ops = full ? 100000 : 5000;
    const std::uint64_t disk_bytes = full ? static_cast<std::uint64_t>(256) * kMiB : 0;
    const long sustained_ms = full ? 30000L : 0L;

    std::vector<HotPathRow> rows;
    auto step = [&](std::string_view name, auto&& fn) {
        render_progress_bar(progress_completed, progress_total, std::string("hotpath ") + std::string(name));
        rows.push_back(fn());
        ++progress_completed;
        render_progress_bar(progress_completed, progress_total, std::string("hotpath ") + std::string(name));
    };

    step("copy-floor", [&] { return run_copy_floor(copy_bytes); });
    step("stream-copy-1", [&] { return run_stream_copy(stream_single_bytes, 1); });
    step("stream-copy-many", [&] { return run_stream_copy(stream_many_bytes, 64); });
    step("aes-gcm-encrypt", [&] { return run_aead_encrypt(crypto_bytes); });
    step("aes-gcm-decrypt", [&] { return run_aead_decrypt(crypto_bytes); });
    step("packet-bulk-encode", [&] { return run_packet_bulk_encode(packet_bytes); });
    step("packet-bulk-decode", [&] { return run_packet_bulk_decode(packet_bytes); });
    step("hop-hkdf", [&] { return run_hop_hkdf(hkdf_ops); });
    if (disk_bytes > 0) {
        step("disk-write", [&] { return run_disk_write(workdir, disk_bytes); });
    }
    if (sustained_ms > 0) {
        step("sustained-mix", [&] {
            return run_sustained_mix(sustained_ms, [&](double fraction) {
                const double base = static_cast<double>(progress_completed);
                const double pseudo = std::clamp(
                    base + std::clamp(fraction, 0.0, 0.999),
                    0.0,
                    static_cast<double>(std::max(1, progress_total)));
                render_progress_bar(pseudo, progress_total, "hotpath sustained-mix");
            });
        });
    }
    return rows;
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
    };
    constexpr Ref refs[] = {
        {"copy-floor", 250000.0, 100000.0},
        {"stream-copy-1", 80000.0, 150000.0},
        {"stream-copy-many", 120000.0, 150000.0},
        {"aes-gcm-encrypt", 6000.0, 1300000.0},
        {"aes-gcm-decrypt", 6000.0, 1300000.0},
        {"packet-bulk-encode", 12000.0, 1100000.0},
        {"packet-bulk-decode", 12000.0, 1100000.0},
        {"hop-hkdf", 2500000.0, 800000.0},
        {"disk-write", 3500.0, 100000.0},
        {"sustained-mix", 12000.0, 3900000.0},
    };

    std::vector<std::string> missing;
    for (const auto& ref : refs) {
        const HotPathRow* row = find_hot_row(rows, ref.name);
        if (!row) {
            missing.emplace_back(ref.name);
            continue;
        }
        const double reference = global ? ref.league_ref * 10.0 : ref.league_ref;
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

std::string score_grade(long long score) {
    if (score >= 120000000) return "SSS+";
    if (score >= 80000000) return "SSS";
    if (score >= 55000000) return "SSS-";
    if (score >= 38000000) return "SS+";
    if (score >= 26000000) return "SS";
    if (score >= 18000000) return "SS-";
    if (score >= 12000000) return "S+";
    if (score >= 8000000) return "S";
    if (score >= 5500000) return "S-";
    if (score >= 3800000) return "AAA+";
    if (score >= 3000000) return "AAA";
    if (score >= 2350000) return "AAA-";
    if (score >= 2000000) return "A+";
    if (score >= 1750000) return "A";
    if (score >= 1500000) return "A-";
    if (score >= 1200000) return "B+";
    if (score >= 900000) return "B";
    if (score >= 650000) return "B-";
    if (score >= 460000) return "C+";
    if (score >= 300000) return "C";
    if (score >= 190000) return "C-";
    if (score >= 140000) return "D+";
    if (score >= 85000) return "D";
    if (score >= 50000) return "D-";
    if (score >= 25000) return "F+";
    if (score >= 10000) return "F";
    return "F-";
}

void render_score(const Args& args,
                  const BenchmarkScore& global_score,
                  const BenchmarkScore& league_score) {
    if (!args.full_benchmark) {
        std::cerr << "\nQuick benchmark complete. Use --fullbench for scored GLOBAL and LEAGUE results.\n";
        return;
    }
    if (!global_score.available && !league_score.available) {
        std::cerr << "\nYUME benchmark score: not computed.\n";
        return;
    }
    std::cerr << "\nYUME benchmark\n";
    std::cerr << "--------------------------------------------------------------------------------\n";
    if (global_score.available) {
        const std::string grade = score_grade(global_score.total);
        std::cerr << "GLOBAL  " << format_integer(global_score.total)
                  << "  " << color_grade(args, grade, global_score.total);
        if (args.dev_style) {
            std::cerr << "  model yume-global-v4";
        }
        std::cerr << "\n";
    } else {
        std::cerr << "GLOBAL  not computed";
        if (!global_score.unavailable_reason.empty()) {
            std::cerr << " (" << global_score.unavailable_reason << ")";
        }
        std::cerr << "\n";
    }
    if (league_score.available) {
        const std::string grade = score_grade(league_score.total);
        std::cerr << "LEAGUE  " << format_integer(league_score.total)
                  << "  " << color_grade(args, grade, league_score.total);
        if (args.dev_style) {
            std::cerr << "  model yume-desktop-v4";
        }
        std::cerr << "\n";
    } else {
        std::cerr << "LEAGUE  not computed";
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
    std::cerr << "GLOBAL: shared Android/desktop hot paths.\n";
    std::cerr << "LEAGUE: desktop YUME transport profile.\n";
    if (!args.dev_style) {
        std::cerr << "Run again with --dev for component tables and phase timings.\n";
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
    render_components("LEAGUE", league_score);
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
                       std::string_view indent) {
    if (!score.available) {
        out << "null";
        return;
    }
    out << "{\n";
    out << indent << "  \"model\": \"" << model << "\",\n";
    out << indent << "  \"total\": " << score.total << ",\n";
    out << indent << "  \"grade\": \"" << score_grade(score.total) << "\",\n";
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

std::string render_json(const Args& args,
                        const std::vector<Result>& results,
                        const std::vector<HotPathRow>& hot_paths,
                        const fs::path& workdir,
                        const BenchmarkScore& global_score,
                        const BenchmarkScore& league_score) {
    std::ostringstream out;
    out << "{\n";
    out << "  \"schema_version\": 8,\n";
    out << "  \"benchmark_mode\": \"" << (args.full_benchmark ? "full" : "quick") << "\",\n";
    out << "  \"workdir\": \"" << json_escape(workdir.string()) << "\",\n";
    out << "  \"global_score\": ";
    append_score_json(out, global_score, "yume-global-v4", "  ");
    out << ",\n";
    out << "  \"league_score\": ";
    append_score_json(out, league_score, "yume-desktop-v4", "  ");
    out << ",\n";
    out << "  \"score\": ";
    append_score_json(out, global_score, "yume-global-v4", "  ");
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
        const int hot_path_steps = args.full_benchmark ? 10 : 8;
        const int progress_total = std::max(
            1,
            static_cast<int>(configs.size()) * std::max(1, args.repeats) + hot_path_steps);
        int progress_completed = 0;

        std::vector<Result> results;
        results.reserve(configs.size());
        for (std::size_t i = 0; i < configs.size(); ++i) {
            const auto& cfg = configs[i];
            if (i > 0 && args.cooldown_ms > 0) {
                if (!progress_inline_enabled()) {
                    std::cerr << "[bench] cooldown " << args.cooldown_ms << " ms before " << cfg.name << "\n";
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

        finish_progress_line();
        const BenchmarkScore global_score = compute_hot_path_score(args, hot_paths, true);
        const BenchmarkScore league_score = compute_score(args, results);
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
        const std::string json = render_json(args, results, hot_paths, tmp->path(), global_score, league_score);
        if (!args.json_path.empty()) {
            write_text(args.json_path, json);
            std::cerr << "[bench] wrote JSON " << args.json_path << "\n";
        }
        if (args.json_stdout) {
            std::cout << json;
        }

        const bool all_ok = std::all_of(results.begin(), results.end(), [](const Result& r) { return r.ok; });
        if (!all_ok) {
            tmp->keep();
            std::cerr << "[bench] logs kept in " << tmp->path() << "\n";
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
            std::cerr << "[bench] logs kept in " << tmp->path() << "\n";
        }
        return 2;
    }
}

}  // namespace yume::tools::selftest
