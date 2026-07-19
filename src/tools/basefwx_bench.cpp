/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "tools/benchmark/v2_crypto_bench.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

using Clock = std::chrono::steady_clock;
using yume::tools::benchmark::SessionPair;

struct Args {
    int establishment_samples{20};
    int rekey_samples{20};
    int bytes_mib{64};
    int chunk_kib{64};
};

struct Stats {
    double min{0.0};
    double median{0.0};
    double p95{0.0};
    double max{0.0};
};

double elapsed_ms(Clock::time_point start, Clock::time_point end) {
    return std::chrono::duration<double, std::milli>(end - start).count();
}

Stats summarize(std::vector<double> samples) {
    if (samples.empty()) return {};
    std::sort(samples.begin(), samples.end());
    const std::size_t p95 = std::min<std::size_t>(
        samples.size() - 1,
        static_cast<std::size_t>(std::ceil(samples.size() * 0.95) - 1.0));
    Stats out;
    out.min = samples.front();
    out.max = samples.back();
    out.median = samples[samples.size() / 2];
    if (samples.size() % 2 == 0) {
        out.median = (samples[samples.size() / 2 - 1] +
                      samples[samples.size() / 2]) / 2.0;
    }
    out.p95 = samples[p95];
    return out;
}

template <typename Fn>
Stats time_samples(int count, Fn&& fn) {
    std::vector<double> samples;
    samples.reserve(static_cast<std::size_t>(count));
    for (int i = 0; i < count; ++i) {
        const auto started = Clock::now();
        fn(i);
        samples.push_back(elapsed_ms(started, Clock::now()));
    }
    return summarize(std::move(samples));
}

void print_help() {
    std::cout
        << "yume-basefwx-bench - YUME 2.0 crypto benchmark\n\n"
        << "Usage: yume-basefwx-bench [options]\n\n"
        << "Options:\n"
        << "  --establishment-samples <N>  Hybrid handshake samples (default 20)\n"
        << "  --rekey-samples <N>          Directional rekey samples (default 20)\n"
        << "  --bytes-mib <N>              Ratchet plaintext per direction (default 64)\n"
        << "  --chunk-kib <N>              DATA payload size (default 64)\n"
        << "  -h, --help                   Show this help\n\n"
        << "Measures the production ML-KEM-1024 + X25519 + HKDF establishment,\n"
        << "directional hybrid rekey, and per-message AES-256-GCM ratchet. TLS, H2,\n"
        << "WebSocket, sockets and process startup are intentionally excluded.\n";
}

Args parse_args(int argc, char** argv) {
    Args args;
    auto value = [&](int& index, const std::string& option) {
        if (index + 1 >= argc) {
            throw std::runtime_error(option + " requires a value");
        }
        return std::string(argv[++index]);
    };
    for (int i = 1; i < argc; ++i) {
        const std::string option = argv[i];
        if (option == "-h" || option == "--help") {
            print_help();
            std::exit(0);
        } else if (option == "--establishment-samples") {
            args.establishment_samples = std::max(1, std::stoi(value(i, option)));
        } else if (option == "--rekey-samples") {
            args.rekey_samples = std::max(1, std::stoi(value(i, option)));
        } else if (option == "--bytes-mib") {
            args.bytes_mib = std::max(1, std::stoi(value(i, option)));
        } else if (option == "--chunk-kib") {
            args.chunk_kib = std::clamp(std::stoi(value(i, option)), 1, 256);
        } else {
            throw std::runtime_error("unknown option: " + option);
        }
    }
    return args;
}

void print_latency(std::string_view name, const Stats& stats, int samples) {
    std::cout << std::left << std::setw(24) << name
              << std::right << std::fixed << std::setprecision(3)
              << std::setw(12) << stats.median
              << std::setw(12) << stats.p95
              << std::setw(12) << stats.min
              << std::setw(12) << stats.max
              << std::setw(10) << samples << "\n";
}

void run(const Args& args) {
    std::cout << "YUME 2.0 / CRYPTO BENCHMARK\n"
              << "ML-KEM-1024 + X25519 + HKDF-SHA256 + AES-256-GCM\n\n";

    const Stats establishment = time_samples(
        args.establishment_samples,
        [](int) { yume::tools::benchmark::verify_hybrid_establishment(); });

    SessionPair rekey_pair;
    const Stats rekey = time_samples(args.rekey_samples, [&](int sample) {
        rekey_pair.rekey((sample & 1) == 0
            ? yume::ratchet::Direction::ClientToServer
            : yume::ratchet::Direction::ServerToClient);
    });

    std::cout << std::left << std::setw(24) << "operation"
              << std::right << std::setw(12) << "median ms"
              << std::setw(12) << "p95 ms"
              << std::setw(12) << "min ms"
              << std::setw(12) << "max ms"
              << std::setw(10) << "samples" << "\n"
              << std::string(82, '-') << "\n";
    print_latency("hybrid establishment", establishment,
                  args.establishment_samples);
    print_latency("directional rekey", rekey, args.rekey_samples);

    const std::uint64_t bytes = static_cast<std::uint64_t>(args.bytes_mib) *
                                1024U * 1024U;
    const std::size_t chunk = static_cast<std::size_t>(args.chunk_kib) * 1024U;
    SessionPair pair;
    const auto c2s = pair.transfer(bytes, chunk,
        yume::ratchet::Direction::ClientToServer);
    const auto s2c = pair.transfer(bytes, chunk,
        yume::ratchet::Direction::ServerToClient);

    auto mib_s = [](const yume::tools::benchmark::TransferResult& result) {
        return (static_cast<double>(result.plaintext_bytes) / (1024.0 * 1024.0)) /
               std::max(result.seconds, 0.000001);
    };
    std::cout << "\n" << std::left << std::setw(24) << "direction"
              << std::right << std::setw(14) << "MiB/s"
              << std::setw(14) << "MiB"
              << std::setw(12) << "frames"
              << std::setw(12) << "rekeys" << "\n"
              << std::string(76, '-') << "\n";
    auto print_transfer = [&](std::string_view name,
                              const yume::tools::benchmark::TransferResult& result) {
        std::cout << std::left << std::setw(24) << name
                  << std::right << std::fixed << std::setprecision(2)
                  << std::setw(14) << mib_s(result)
                  << std::setw(14)
                  << (static_cast<double>(result.plaintext_bytes) /
                      (1024.0 * 1024.0))
                  << std::setw(12) << result.frames
                  << std::setw(12) << result.rekeys << "\n";
    };
    print_transfer("client -> server", c2s);
    print_transfer("server -> client", s2c);

    const double total_seconds = c2s.seconds + s2c.seconds;
    const double total_mib = static_cast<double>(
        c2s.plaintext_bytes + s2c.plaintext_bytes) / (1024.0 * 1024.0);
    std::cout << "\nCombined sequential throughput: "
              << std::fixed << std::setprecision(2)
              << total_mib / std::max(total_seconds, 0.000001) << " MiB/s\n";
}

}  // namespace

int main(int argc, char** argv) {
    try {
        run(parse_args(argc, argv));
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "yume-basefwx-bench: " << ex.what() << "\n";
        return 2;
    }
}
