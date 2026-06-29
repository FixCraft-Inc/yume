/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/security/inner_crypto.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <numeric>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#if defined(_WIN32)
#error "yume-basefwx-bench currently supports POSIX desktop hosts only"
#endif

#include <unistd.h>

namespace {

using Clock = std::chrono::steady_clock;
namespace fs = std::filesystem;

double elapsed_ms(Clock::time_point start, Clock::time_point end) {
    return std::chrono::duration<double, std::milli>(end - start).count();
}

double elapsed_s(Clock::time_point start, Clock::time_point end) {
    return std::chrono::duration<double>(end - start).count();
}

struct Args {
    int light_iters{40};
    int heavy_iters{3};
    int hop_iters{100000};
    int bytes_mib{64};
    int chunk_kib{64};
    std::uint32_t argon_mem_kib{32768};
    std::uint32_t argon_parallelism{2};
    bool no_heavy{false};
    bool keep_workdir{false};
};

struct Stats {
    std::size_t n{0};
    double min{0.0};
    double median{0.0};
    double p95{0.0};
    double max{0.0};
    double mean{0.0};
};

struct LatencyRow {
    std::string name;
    std::string detail;
    Stats ms;
};

struct ThroughputRow {
    std::string name;
    std::string detail;
    double total_mib{0.0};
    double chunk_kib{0.0};
    double total_s{0.0};
    double mib_s{0.0};
};

struct OpsRow {
    std::string name;
    std::string detail;
    std::uint64_t ops{0};
    double total_s{0.0};
    double per_op_us{0.0};
    double ops_s{0.0};
};

void print_help() {
    std::cout
        << "yume-basefwx-bench - local YUME inner-crypto microbenchmark\n\n"
        << "Usage:\n"
        << "  yume-basefwx-bench [options]\n\n"
        << "Options:\n"
        << "  --light-iters <N>        Light PQ/HKDF samples (default 40)\n"
        << "  --heavy-iters <N>        Heavy Argon2 samples (default 3)\n"
        << "  --hop-iters <N>          Hop HKDF operations (default 100000)\n"
        << "  --bytes-mib <N>          AEAD bytes per direction (default 64)\n"
        << "  --chunk-kib <N>          AEAD payload chunk size (default 64)\n"
        << "  --argon-mem-kib <N>      Heavy KDF memory cap (default 32768)\n"
        << "  --argon-parallelism <N>  Heavy KDF parallelism cap (default 2)\n"
        << "  --no-heavy              Skip Argon2-heavy handshake timings\n"
        << "  --keep-workdir          Keep temporary PQ keys\n"
        << "  -h, --help              Show this help\n\n"
        << "Notes:\n"
        << "  This measures the YUME inner_crypto path linked to BaseFWX. It does not\n"
        << "  include TLS, H2 obfs, SOCKS, kernel loopback, yume/yumed process startup,\n"
        << "  or packet routing.\n";
}

Args parse_args(int argc, char** argv) {
    Args args;
    auto require_value = [&](int& i, const std::string& opt) -> std::string {
        if (i + 1 >= argc) throw std::runtime_error(opt + " requires a value");
        return argv[++i];
    };
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_help();
            std::exit(0);
        } else if (arg == "--light-iters") {
            args.light_iters = std::max(1, std::stoi(require_value(i, arg)));
        } else if (arg == "--heavy-iters") {
            args.heavy_iters = std::max(1, std::stoi(require_value(i, arg)));
        } else if (arg == "--hop-iters") {
            args.hop_iters = std::max(1, std::stoi(require_value(i, arg)));
        } else if (arg == "--bytes-mib") {
            args.bytes_mib = std::max(1, std::stoi(require_value(i, arg)));
        } else if (arg == "--chunk-kib") {
            args.chunk_kib = std::max(1, std::stoi(require_value(i, arg)));
        } else if (arg == "--argon-mem-kib") {
            args.argon_mem_kib = static_cast<std::uint32_t>(
                std::max(1024, std::stoi(require_value(i, arg))));
        } else if (arg == "--argon-parallelism") {
            args.argon_parallelism = static_cast<std::uint32_t>(
                std::max(1, std::stoi(require_value(i, arg))));
        } else if (arg == "--no-heavy") {
            args.no_heavy = true;
        } else if (arg == "--keep-workdir") {
            args.keep_workdir = true;
        } else {
            throw std::runtime_error("unknown option: " + arg);
        }
    }
    return args;
}

class TempDir {
public:
    explicit TempDir(bool keep) : keep_(keep) {
        fs::path base = fs::temp_directory_path() / "yume-basefwx-bench.XXXXXX";
        std::string pattern = base.string();
        char* raw = ::mkdtemp(pattern.data());
        if (!raw) throw std::runtime_error("mkdtemp failed: " + std::string(std::strerror(errno)));
        path_ = raw;
    }
    ~TempDir() {
        if (!keep_ && !path_.empty()) {
            std::error_code ec;
            fs::remove_all(path_, ec);
        }
    }
    const fs::path& path() const { return path_; }
    void keep() { keep_ = true; }

private:
    fs::path path_;
    bool keep_{false};
};

std::vector<std::uint8_t> random_bytes(std::size_t len) {
    std::vector<std::uint8_t> out(len);
    std::mt19937_64 rng(std::random_device{}());
    for (auto& b : out) b = static_cast<std::uint8_t>(rng() & 0xff);
    return out;
}

Stats compute_stats(std::vector<double> samples) {
    Stats stats;
    stats.n = samples.size();
    if (samples.empty()) return stats;
    std::sort(samples.begin(), samples.end());
    auto pick = [&](double q) {
        const std::size_t idx = std::min<std::size_t>(
            samples.size() - 1,
            static_cast<std::size_t>(std::max<double>(0.0, std::ceil(q * samples.size()) - 1.0)));
        return samples[idx];
    };
    stats.min = samples.front();
    stats.max = samples.back();
    stats.median = samples[samples.size() / 2];
    if (samples.size() % 2 == 0) {
        stats.median = (samples[samples.size() / 2 - 1] + samples[samples.size() / 2]) / 2.0;
    }
    stats.p95 = pick(0.95);
    stats.mean = std::accumulate(samples.begin(), samples.end(), 0.0) /
                 static_cast<double>(samples.size());
    return stats;
}

template <typename Fn>
Stats time_samples(int iters, Fn&& fn) {
    std::vector<double> samples;
    samples.reserve(static_cast<std::size_t>(iters));
    for (int i = 0; i < iters; ++i) {
        const auto start = Clock::now();
        fn(i);
        samples.push_back(elapsed_ms(start, Clock::now()));
    }
    return compute_stats(std::move(samples));
}

void set_env_u32(const char* name, std::uint32_t value) {
    ::setenv(name, std::to_string(value).c_str(), 1);
}

yume::inner::KdfParams params_from_handshake(const yume::inner::ClientHandshake& h) {
    yume::inner::KdfParams params;
    params.name = h.kdf;
    params.argon2_time = h.argon2_time;
    params.argon2_memory = h.argon2_memory;
    params.argon2_parallelism = h.argon2_parallelism;
    params.pbkdf2_iters = h.pbkdf2_iters;
    return params;
}

void require_matching_key(const yume::inner::ClientHandshake& h,
                          const std::optional<yume::inner::DerivedKey>& derived) {
    if (!derived.has_value()) {
        throw std::runtime_error("server derive returned no key");
    }
    if (derived->key != h.key) {
        throw std::runtime_error("client/server derived keys differ");
    }
}

ThroughputRow bench_aead_encrypt(const Args& args, const yume::inner::Bytes& key) {
    const std::size_t chunk = static_cast<std::size_t>(args.chunk_kib) * 1024u;
    const std::size_t total = static_cast<std::size_t>(args.bytes_mib) * 1024u * 1024u;
    const auto payload = random_bytes(chunk);
    std::size_t done = 0;
    std::size_t sink = 0;
    const auto start = Clock::now();
    while (done < total) {
        const std::size_t take = std::min<std::size_t>(chunk, total - done);
        yume::inner::Bytes tail;
        const yume::inner::Bytes* plain = &payload;
        if (take != payload.size()) {
            tail.assign(payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(take));
            plain = &tail;
        }
        auto blob = yume::inner::encrypt_payload(key, 0x02, 7, *plain);
        sink += blob.size();
        done += take;
    }
    const double seconds = elapsed_s(start, Clock::now());
    if (sink == 0) throw std::runtime_error("AEAD encrypt produced no output");
    return {
        "inner-aead-encrypt",
        "AES-GCM payload seal through inner_crypto",
        static_cast<double>(total) / (1024.0 * 1024.0),
        static_cast<double>(chunk) / 1024.0,
        seconds,
        (static_cast<double>(total) / (1024.0 * 1024.0)) / std::max(seconds, 0.000001),
    };
}

ThroughputRow bench_aead_decrypt(const Args& args, const yume::inner::Bytes& key) {
    const std::size_t chunk = static_cast<std::size_t>(args.chunk_kib) * 1024u;
    const std::size_t total = static_cast<std::size_t>(args.bytes_mib) * 1024u * 1024u;
    const auto payload = random_bytes(chunk);
    const auto blob = yume::inner::encrypt_payload(key, 0x02, 7, payload);
    const std::size_t tail_size = total % chunk;
    yume::inner::Bytes tail_payload;
    yume::inner::Bytes tail_blob;
    if (tail_size != 0) {
        tail_payload.assign(payload.begin(), payload.begin() + static_cast<std::ptrdiff_t>(tail_size));
        tail_blob = yume::inner::encrypt_payload(key, 0x02, 7, tail_payload);
    }
    std::size_t done = 0;
    std::size_t sink = 0;
    const auto start = Clock::now();
    while (done < total) {
        const std::size_t take = std::min<std::size_t>(chunk, total - done);
        const auto& expected = take == chunk ? payload : tail_payload;
        const auto& encrypted = take == chunk ? blob : tail_blob;
        auto plain = yume::inner::decrypt_payload(key, 0x02, 7, encrypted);
        if (plain != expected) throw std::runtime_error("AEAD decrypt mismatch");
        sink += take;
        done += take;
    }
    const double seconds = elapsed_s(start, Clock::now());
    if (sink == 0) throw std::runtime_error("AEAD decrypt produced no output");
    return {
        "inner-aead-decrypt",
        "AES-GCM payload open through inner_crypto",
        static_cast<double>(total) / (1024.0 * 1024.0),
        static_cast<double>(chunk) / 1024.0,
        seconds,
        (static_cast<double>(total) / (1024.0 * 1024.0)) / std::max(seconds, 0.000001),
    };
}

OpsRow bench_hop_hkdf(const Args& args, const yume::inner::Bytes& key) {
    std::size_t sink = 0;
    const auto start = Clock::now();
    for (int i = 0; i < args.hop_iters; ++i) {
        auto hop = yume::inner::derive_hop_key(key, static_cast<std::uint64_t>(i));
        sink += hop.empty() ? 0u : hop[0];
    }
    const double seconds = elapsed_s(start, Clock::now());
    if (sink == 0) {
        std::cerr << "[bench] hop sink was zero; continuing\n";
    }
    const double ops = static_cast<double>(args.hop_iters);
    return {
        "hop-hkdf",
        "derive_hop_key() only",
        static_cast<std::uint64_t>(args.hop_iters),
        seconds,
        (seconds * 1000000.0) / std::max(ops, 1.0),
        ops / std::max(seconds, 0.000001),
    };
}

void render_latency_rows(const std::vector<LatencyRow>& rows) {
    std::cerr << "\nHandshake latency\n";
    std::cerr << "--------------------------------------------------------------------------------\n";
    std::cerr << std::left << std::setw(22) << "metric"
              << std::right << std::setw(8) << "n"
              << std::setw(12) << "med ms"
              << std::setw(12) << "p95 ms"
              << std::setw(12) << "mean ms"
              << "  detail\n";
    std::cerr << "--------------------------------------------------------------------------------\n";
    for (const auto& row : rows) {
        std::cerr << std::left << std::setw(22) << row.name << std::right
                  << std::setw(8) << row.ms.n
                  << std::fixed << std::setprecision(3)
                  << std::setw(12) << row.ms.median
                  << std::setw(12) << row.ms.p95
                  << std::setw(12) << row.ms.mean
                  << "  " << row.detail << "\n";
    }
    std::cerr << "--------------------------------------------------------------------------------\n";
}

void render_throughput_rows(const std::vector<ThroughputRow>& rows) {
    std::cerr << "\nPayload crypto throughput\n";
    std::cerr << "--------------------------------------------------------------------------------\n";
    std::cerr << std::left << std::setw(22) << "metric"
              << std::right << std::setw(10) << "MiB"
              << std::setw(10) << "chunk"
              << std::setw(12) << "MiB/s"
              << std::setw(10) << "sec"
              << "  detail\n";
    std::cerr << "--------------------------------------------------------------------------------\n";
    for (const auto& row : rows) {
        std::cerr << std::left << std::setw(22) << row.name << std::right
                  << std::fixed << std::setprecision(1)
                  << std::setw(10) << row.total_mib
                  << std::setw(10) << row.chunk_kib
                  << std::setprecision(1)
                  << std::setw(12) << row.mib_s
                  << std::setprecision(3)
                  << std::setw(10) << row.total_s
                  << "  " << row.detail << "\n";
    }
    std::cerr << "--------------------------------------------------------------------------------\n";
}

void render_ops_rows(const std::vector<OpsRow>& rows) {
    std::cerr << "\nSmall operation throughput\n";
    std::cerr << "--------------------------------------------------------------------------------\n";
    std::cerr << std::left << std::setw(22) << "metric"
              << std::right << std::setw(12) << "ops"
              << std::setw(12) << "ops/s"
              << std::setw(12) << "us/op"
              << std::setw(10) << "sec"
              << "  detail\n";
    std::cerr << "--------------------------------------------------------------------------------\n";
    for (const auto& row : rows) {
        std::cerr << std::left << std::setw(22) << row.name << std::right
                  << std::setw(12) << row.ops
                  << std::fixed << std::setprecision(0)
                  << std::setw(12) << row.ops_s
                  << std::setprecision(3)
                  << std::setw(12) << row.per_op_us
                  << std::setw(10) << row.total_s
                  << "  " << row.detail << "\n";
    }
    std::cerr << "--------------------------------------------------------------------------------\n";
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const Args args = parse_args(argc, argv);
        if (!yume::inner::pq_supported()) {
            std::cerr << "yume-basefwx-bench: PQ/BaseFWX support is unavailable in this build\n";
            return 2;
        }

        set_env_u32("YUME_ARGON2_MEM", args.argon_mem_kib);
        set_env_u32("YUME_ARGON2_MEM_MAX", args.argon_mem_kib);
        set_env_u32("YUME_ARGON2_PAR", args.argon_parallelism);
        set_env_u32("YUME_ARGON2_PAR_MAX", args.argon_parallelism);

        TempDir tmp(args.keep_workdir);
        const fs::path private_key = tmp.path() / "bench_pq_private.key";
        const fs::path public_key = tmp.path() / "bench_pq_public.key";
        std::string err;
        if (!yume::inner::generate_pq_keypair(private_key.string(), public_key.string(), &err)) {
            throw std::runtime_error("PQ key generation failed: " + err);
        }

        yume::inner::Config client_cfg;
        client_cfg.enabled = true;
        client_cfg.pq_public_key = public_key.string();
        client_cfg.argon2_limits.memory_max = args.argon_mem_kib;
        client_cfg.argon2_limits.parallelism_max = args.argon_parallelism;

        yume::inner::Config server_cfg;
        server_cfg.enabled = true;
        server_cfg.pq_private_key = private_key.string();
        server_cfg.argon2_limits.memory_max = args.argon_mem_kib;
        server_cfg.argon2_limits.parallelism_max = args.argon_parallelism;

        std::vector<LatencyRow> latency_rows;
        latency_rows.push_back({
            "pq-client-light",
            "ML-KEM encapsulate + HKDF",
            time_samples(args.light_iters, [&](int) {
                auto h = yume::inner::client_prepare(client_cfg, false);
                if (!h.enabled || h.key.empty()) throw std::runtime_error("light client produced no key");
            }),
        });

        const auto light_handshake = yume::inner::client_prepare(client_cfg, false);
        latency_rows.push_back({
            "pq-server-light",
            "ML-KEM decapsulate + HKDF",
            time_samples(args.light_iters, [&](int) {
                auto derived = yume::inner::server_derive_key(
                    server_cfg,
                    light_handshake.pq_ciphertext,
                    light_handshake.salt,
                    false,
                    std::nullopt);
                require_matching_key(light_handshake, derived);
            }),
        });

        std::vector<ThroughputRow> throughput_rows;
        throughput_rows.push_back(bench_aead_encrypt(args, light_handshake.key));
        throughput_rows.push_back(bench_aead_decrypt(args, light_handshake.key));

        std::vector<OpsRow> ops_rows;
        ops_rows.push_back(bench_hop_hkdf(args, light_handshake.key));

        if (!args.no_heavy) {
            if (!yume::inner::argon2_supported()) {
                std::cerr << "[bench] Argon2 unavailable; skipping heavy rows\n";
            } else {
                latency_rows.push_back({
                    "pq-client-heavy",
                    "ML-KEM encapsulate + " + std::to_string(args.argon_mem_kib) + " KiB Argon2",
                    time_samples(args.heavy_iters, [&](int) {
                        auto h = yume::inner::client_prepare(client_cfg, true);
                        if (!h.enabled || h.key.empty()) throw std::runtime_error("heavy client produced no key");
                    }),
                });

                const auto heavy_handshake = yume::inner::client_prepare(client_cfg, true);
                const auto heavy_params = params_from_handshake(heavy_handshake);
                latency_rows.push_back({
                    "pq-server-heavy",
                    "ML-KEM decapsulate + negotiated " + heavy_handshake.kdf,
                    time_samples(args.heavy_iters, [&](int) {
                        auto derived = yume::inner::server_derive_key(
                            server_cfg,
                            heavy_handshake.pq_ciphertext,
                            heavy_handshake.salt,
                            true,
                            heavy_params);
                        require_matching_key(heavy_handshake, derived);
                    }),
                });
            }
        }

        std::cerr << "YUME BaseFWX/inner crypto microbench\n";
        std::cerr << "PQ backend:     " << yume::inner::pq_backend_version() << "\n";
        std::cerr << "Argon2 backend: " << yume::inner::argon2_backend_version() << "\n";
        std::cerr << "Heavy cap:      " << args.argon_mem_kib << " KiB, parallelism "
                  << args.argon_parallelism << "\n";
        render_latency_rows(latency_rows);
        render_throughput_rows(throughput_rows);
        render_ops_rows(ops_rows);
        if (args.keep_workdir) {
            tmp.keep();
            std::cerr << "[bench] kept workdir " << tmp.path() << "\n";
        }
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "yume-basefwx-bench: " << ex.what() << "\n";
        return 2;
    }
}
