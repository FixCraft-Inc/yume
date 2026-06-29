/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * Hot-path micro-benchmark implementations declared in
 * tools/selftest/hotpath.hpp. Extracted verbatim from tools/selftest.cpp.
 */

#include "tools/selftest/hotpath.hpp"

#include "core/security/inner_crypto.hpp"
#include "tools/selftest/render.hpp"
#include "tools/selftest/sizing.hpp"

#include "core/protocol/packet_bulk.hpp"
#include "core/runtime/system_profile.hpp"
#include <basefwx/crypto.hpp>
#include <basefwx/pq.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <numeric>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <thread>
#include <vector>
#if !defined(_WIN32)
#include <fcntl.h>
#include <unistd.h>
#endif

namespace yume::tools::selftest {

namespace {
namespace fs = std::filesystem;
constexpr std::string_view kHkdfInfoPrefix = "yume-hop-v1:";
constexpr std::string_view kInnerHkdfInfo = "yume-inner-v1";
constexpr std::string_view kBenchmarkAad = "yume-desktop-selftest";
constexpr std::string_view kSustainedHkdfInfoPrefix = "yume-sustain:";
}  // namespace

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

std::vector<std::uint64_t> split_work(std::uint64_t total, int workers) {
    const int count = std::max(1, workers);
    std::vector<std::uint64_t> out(static_cast<std::size_t>(count), total / static_cast<std::uint64_t>(count));
    std::uint64_t remaining = total % static_cast<std::uint64_t>(count);
    for (int i = 0; remaining > 0; ++i, --remaining) {
        out[static_cast<std::size_t>(i % count)] += 1;
    }
    return out;
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

HotPathRow latency_ops_row(std::string name,
                           std::vector<double> samples_ms,
                           std::string detail) {
    const Stats stats = compute_stats(samples_ms);
    const double median_ms = std::max(stats.median, 0.000001);
    const double ops_s = 1000.0 / median_ms;
    std::ostringstream metric;
    metric << std::fixed << std::setprecision(1) << ops_s << " ops/s";
    std::ostringstream full_detail;
    full_detail << detail
                << ", median_ms=" << std::fixed << std::setprecision(3) << stats.median
                << ", p95_ms=" << stats.p95
                << ", samples=" << stats.n;
    return {
        std::move(name),
        metric.str(),
        full_detail.str(),
        stats.n > 0,
        ops_s,
        "ops/s",
        0,
        static_cast<std::uint64_t>(stats.n),
        (stats.mean * static_cast<double>(stats.n)) / 1000.0,
    };
}

template <typename Fn>
std::vector<double> time_samples_ms(int samples, Fn&& fn) {
    const int count = std::max(1, samples);
    std::vector<double> out;
    out.reserve(static_cast<std::size_t>(count));
    for (int i = 0; i < count; ++i) {
        const auto start = Clock::now();
        fn(i);
        out.push_back(elapsed_ms(start, Clock::now()));
    }
    return out;
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
                          "64 KiB vector copy, " + checksum_detail(guard));
}

HotPathRow run_stream_copy(std::uint64_t total_bytes, int streams) {
    const int stream_count = std::max(1, streams);
    const auto per_stream = split_work(total_bytes, stream_count);

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
           << " instability=" << instability << "% " << checksum_detail(guard);
    return throughput_row(stream_count == 1 ? "stream-copy-1" : "stream-copy-many",
                          total_bytes,
                          seconds,
                          detail.str());
}

HotPathRow run_memory_bandwidth(std::uint64_t total_bytes, int thread_count, std::size_t chunk_bytes) {
    const int workers = std::clamp(thread_count, 1, 256);
    const std::size_t chunk = std::clamp<std::size_t>(chunk_bytes, 256 * kKiB, 32 * kMiB);
    const auto per_worker = split_work(total_bytes, workers);

    std::atomic<bool> start_flag{false};
    std::vector<std::uint64_t> copied_by_worker(static_cast<std::size_t>(workers), 0);
    std::vector<int> guards(static_cast<std::size_t>(workers), 0);
    std::vector<std::thread> threads;
    threads.reserve(static_cast<std::size_t>(workers));

    for (int worker = 0; worker < workers; ++worker) {
        threads.emplace_back([&, worker] {
            auto src = patterned_bytes(chunk, 41 + worker);
            std::vector<std::uint8_t> dst(src.size());
            while (!start_flag.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            const auto target = per_worker[static_cast<std::size_t>(worker)];
            std::uint64_t copied = 0;
            int guard = 0;
            while (copied < target) {
                const auto n = static_cast<std::size_t>(std::min<std::uint64_t>(src.size(), target - copied));
                std::copy_n(src.begin(), static_cast<std::ptrdiff_t>(n), dst.begin());
                guard ^= dst[(copied / std::max<std::size_t>(1, n)) & (dst.size() - 1)];
                copied += n;
            }
            copied_by_worker[static_cast<std::size_t>(worker)] = copied;
            guards[static_cast<std::size_t>(worker)] = guard;
        });
    }

    const auto started = Clock::now();
    start_flag.store(true, std::memory_order_release);
    for (auto& thread : threads) {
        thread.join();
    }
    const double seconds = elapsed_s(started, Clock::now());
    const auto copied = std::accumulate(copied_by_worker.begin(), copied_by_worker.end(), std::uint64_t{0});
    const int guard = std::accumulate(guards.begin(), guards.end(), 0, [](int a, int b) { return a ^ b; }) & 0xff;
    return throughput_row("memory-bandwidth",
                          copied,
                          seconds,
                          "parallel memory copy, threads=" + std::to_string(workers) +
                              ", chunk_kib=" + std::to_string(chunk / kKiB) +
                              ", " + checksum_detail(guard));
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

HotPathRow run_aead_encrypt(std::uint64_t total_bytes, int thread_count) {
    const int workers = std::clamp(thread_count, 1, 256);
    const auto per_worker = split_work(total_bytes, workers);
    std::atomic<bool> start_flag{false};
    std::vector<std::uint64_t> bytes_by_worker(static_cast<std::size_t>(workers), 0);
    std::vector<int> guards(static_cast<std::size_t>(workers), 0);
    std::vector<std::thread> threads;
    threads.reserve(static_cast<std::size_t>(workers));

    for (int worker = 0; worker < workers; ++worker) {
        threads.emplace_back([&, worker] {
            const auto key = patterned_bytes(32, 3 + worker);
            const auto aad = ascii_bytes(kBenchmarkAad);
            const auto plaintext = patterned_bytes(64 * kKiB, 21 + worker);
            const int iterations = iterations_for(per_worker[static_cast<std::size_t>(worker)], plaintext.size());
            int guard = 0;
            while (!start_flag.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            for (int i = 0; i < iterations; ++i) {
                auto encrypted = basefwx::crypto::AeadEncrypt(key, plaintext, aad);
                guard ^= encrypted.back();
            }
            bytes_by_worker[static_cast<std::size_t>(worker)] =
                static_cast<std::uint64_t>(iterations) * plaintext.size();
            guards[static_cast<std::size_t>(worker)] = guard;
        });
    }
    const auto start = Clock::now();
    start_flag.store(true, std::memory_order_release);
    for (auto& thread : threads) {
        thread.join();
    }
    const double seconds = elapsed_s(start, Clock::now());
    const auto bytes = std::accumulate(bytes_by_worker.begin(), bytes_by_worker.end(), std::uint64_t{0});
    const int guard = std::accumulate(guards.begin(), guards.end(), 0, [](int a, int b) { return a ^ b; });
    return throughput_row("aes-gcm-encrypt",
                          bytes,
                          seconds,
                          "BaseFWX AES-GCM, 64 KiB chunks, threads=" + std::to_string(workers) +
                              ", " + checksum_detail(guard));
}

HotPathRow run_aead_decrypt(std::uint64_t total_bytes, int thread_count) {
    const int workers = std::clamp(thread_count, 1, 256);
    const auto per_worker = split_work(total_bytes, workers);
    std::atomic<bool> start_flag{false};
    std::vector<std::uint64_t> bytes_by_worker(static_cast<std::size_t>(workers), 0);
    std::vector<int> guards(static_cast<std::size_t>(workers), 0);
    std::vector<std::thread> threads;
    threads.reserve(static_cast<std::size_t>(workers));

    for (int worker = 0; worker < workers; ++worker) {
        threads.emplace_back([&, worker] {
            const auto key = patterned_bytes(32, 3 + worker);
            const auto aad = ascii_bytes(kBenchmarkAad);
            const auto plaintext = patterned_bytes(64 * kKiB, 21 + worker);
            const auto encrypted = basefwx::crypto::AeadEncrypt(key, plaintext, aad);
            const int iterations = iterations_for(per_worker[static_cast<std::size_t>(worker)], plaintext.size());
            int guard = 0;
            while (!start_flag.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            for (int i = 0; i < iterations; ++i) {
                auto decrypted = basefwx::crypto::AeadDecrypt(key, encrypted, aad);
                guard ^= decrypted[static_cast<std::size_t>(i) & (decrypted.size() - 1)];
            }
            bytes_by_worker[static_cast<std::size_t>(worker)] =
                static_cast<std::uint64_t>(iterations) * plaintext.size();
            guards[static_cast<std::size_t>(worker)] = guard;
        });
    }
    const auto start = Clock::now();
    start_flag.store(true, std::memory_order_release);
    for (auto& thread : threads) {
        thread.join();
    }
    const double seconds = elapsed_s(start, Clock::now());
    const auto bytes = std::accumulate(bytes_by_worker.begin(), bytes_by_worker.end(), std::uint64_t{0});
    const int guard = std::accumulate(guards.begin(), guards.end(), 0, [](int a, int b) { return a ^ b; });
    return throughput_row("aes-gcm-decrypt",
                          bytes,
                          seconds,
                          "BaseFWX AES-GCM, 64 KiB chunks, threads=" + std::to_string(workers) +
                              ", " + checksum_detail(guard));
}

HotPathRow run_packet_bulk_encode(std::uint64_t total_bytes, int thread_count) {
    const int workers = std::clamp(thread_count, 1, 256);
    const auto per_worker = split_work(total_bytes, workers);
    std::atomic<bool> start_flag{false};
    std::vector<std::uint64_t> bytes_by_worker(static_cast<std::size_t>(workers), 0);
    std::vector<int> guards(static_cast<std::size_t>(workers), 0);
    std::vector<std::thread> threads;
    threads.reserve(static_cast<std::size_t>(workers));

    for (int worker = 0; worker < workers; ++worker) {
        threads.emplace_back([&, worker] {
            auto batch = packet_batch();
            const auto encoded_size = yume::protocol::packet_bulk::encoded_size(batch);
            const int iterations = iterations_for(per_worker[static_cast<std::size_t>(worker)], encoded_size);
            int guard = 0;
            while (!start_flag.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            for (int i = 0; i < iterations; ++i) {
                batch.sequence = (static_cast<std::uint64_t>(worker) << 48) | static_cast<std::uint64_t>(i);
                auto encoded = yume::protocol::packet_bulk::encode_batch(batch);
                guard ^= encoded.back();
            }
            bytes_by_worker[static_cast<std::size_t>(worker)] =
                static_cast<std::uint64_t>(iterations) * encoded_size;
            guards[static_cast<std::size_t>(worker)] = guard;
        });
    }
    const auto start = Clock::now();
    start_flag.store(true, std::memory_order_release);
    for (auto& thread : threads) {
        thread.join();
    }
    const double seconds = elapsed_s(start, Clock::now());
    const auto bytes = std::accumulate(bytes_by_worker.begin(), bytes_by_worker.end(), std::uint64_t{0});
    const int guard = std::accumulate(guards.begin(), guards.end(), 0, [](int a, int b) { return a ^ b; });
    return throughput_row("packet-bulk-encode",
                          bytes,
                          seconds,
                          "64 packets/batch, threads=" + std::to_string(workers) +
                              ", " + checksum_detail(guard));
}

HotPathRow run_packet_bulk_decode(std::uint64_t total_bytes, int thread_count) {
    const int workers = std::clamp(thread_count, 1, 256);
    const auto per_worker = split_work(total_bytes, workers);
    std::atomic<bool> start_flag{false};
    std::vector<std::uint64_t> bytes_by_worker(static_cast<std::size_t>(workers), 0);
    std::vector<int> guards(static_cast<std::size_t>(workers), 0);
    std::vector<std::string> errors(static_cast<std::size_t>(workers));
    std::vector<std::thread> threads;
    threads.reserve(static_cast<std::size_t>(workers));

    for (int worker = 0; worker < workers; ++worker) {
        threads.emplace_back([&, worker] {
            const auto batch = packet_batch();
            const auto encoded = yume::protocol::packet_bulk::encode_batch(batch);
            const int iterations = iterations_for(per_worker[static_cast<std::size_t>(worker)], encoded.size());
            int guard = 0;
            while (!start_flag.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            for (int i = 0; i < iterations; ++i) {
                auto decoded = yume::protocol::packet_bulk::decode_batch(encoded);
                if (!decoded.has_value()) {
                    errors[static_cast<std::size_t>(worker)] = "packet bulk decode failed";
                    return;
                }
                guard ^= decoded->packets.back().back();
            }
            bytes_by_worker[static_cast<std::size_t>(worker)] =
                static_cast<std::uint64_t>(iterations) * encoded.size();
            guards[static_cast<std::size_t>(worker)] = guard;
        });
    }
    const auto start = Clock::now();
    start_flag.store(true, std::memory_order_release);
    for (auto& thread : threads) {
        thread.join();
    }
    for (const auto& error : errors) {
        if (!error.empty()) {
            throw std::runtime_error(error);
        }
    }
    const double seconds = elapsed_s(start, Clock::now());
    const auto bytes = std::accumulate(bytes_by_worker.begin(), bytes_by_worker.end(), std::uint64_t{0});
    const int guard = std::accumulate(guards.begin(), guards.end(), 0, [](int a, int b) { return a ^ b; });
    return throughput_row("packet-bulk-decode",
                          bytes,
                          seconds,
                          "64 packets/batch, threads=" + std::to_string(workers) +
                              ", " + checksum_detail(guard));
}

HotPathRow run_hop_hkdf(int ops, int thread_count) {
    const int workers = std::clamp(thread_count, 1, 256);
    const auto per_worker = split_work(static_cast<std::uint64_t>(std::max(1, ops)), workers);
    std::atomic<bool> start_flag{false};
    std::vector<std::uint64_t> ops_by_worker(static_cast<std::size_t>(workers), 0);
    std::vector<int> guards(static_cast<std::size_t>(workers), 0);
    std::vector<std::thread> threads;
    threads.reserve(static_cast<std::size_t>(workers));

    for (int worker = 0; worker < workers; ++worker) {
        threads.emplace_back([&, worker] {
            const auto key = patterned_bytes(32, 9 + worker);
            const auto count = per_worker[static_cast<std::size_t>(worker)];
            int guard = 0;
            while (!start_flag.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            for (std::uint64_t i = 0; i < count; ++i) {
                const std::string info = std::string(kHkdfInfoPrefix) + std::to_string(worker) + ":" +
                                         std::to_string(i);
                auto derived = basefwx::crypto::HkdfSha256(key, info, 32);
                guard ^= derived.front();
            }
            ops_by_worker[static_cast<std::size_t>(worker)] = count;
            guards[static_cast<std::size_t>(worker)] = guard;
        });
    }
    const auto start = Clock::now();
    start_flag.store(true, std::memory_order_release);
    for (auto& thread : threads) {
        thread.join();
    }
    const double seconds = elapsed_s(start, Clock::now());
    const auto count = std::accumulate(ops_by_worker.begin(), ops_by_worker.end(), std::uint64_t{0});
    const int guard = std::accumulate(guards.begin(), guards.end(), 0, [](int a, int b) { return a ^ b; });
    const double ops_s = static_cast<double>(count) / std::max(seconds, 0.000001);
    std::ostringstream metric;
    metric << std::fixed << std::setprecision(1) << ops_s << " ops/s";
    return {
        "hop-hkdf",
        metric.str(),
        std::to_string(count) + " derived hop keys, threads=" + std::to_string(workers) +
            ", " + checksum_detail(guard),
        true,
        ops_s,
        "ops/s",
        0,
        static_cast<std::uint64_t>(count),
        seconds,
    };
}

HotPathRow run_inner_aead_encrypt(std::uint64_t total_bytes, int thread_count) {
    const int workers = std::clamp(thread_count, 1, 256);
    const auto per_worker = split_work(total_bytes, workers);
    std::atomic<bool> start_flag{false};
    std::vector<std::uint64_t> bytes_by_worker(static_cast<std::size_t>(workers), 0);
    std::vector<int> guards(static_cast<std::size_t>(workers), 0);
    std::vector<std::thread> threads;
    threads.reserve(static_cast<std::size_t>(workers));

    for (int worker = 0; worker < workers; ++worker) {
        threads.emplace_back([&, worker] {
            const auto key = patterned_bytes(32, 51 + worker);
            const auto plaintext = patterned_bytes(64 * kKiB, 71 + worker);
            const int iterations = iterations_for(per_worker[static_cast<std::size_t>(worker)], plaintext.size());
            int guard = 0;
            while (!start_flag.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            for (int i = 0; i < iterations; ++i) {
                auto encrypted = yume::inner::encrypt_payload(key, 0x02, worker + 1, plaintext);
                guard ^= encrypted.back();
            }
            bytes_by_worker[static_cast<std::size_t>(worker)] =
                static_cast<std::uint64_t>(iterations) * plaintext.size();
            guards[static_cast<std::size_t>(worker)] = guard;
        });
    }
    const auto start = Clock::now();
    start_flag.store(true, std::memory_order_release);
    for (auto& thread : threads) {
        thread.join();
    }
    const double seconds = elapsed_s(start, Clock::now());
    const auto bytes = std::accumulate(bytes_by_worker.begin(), bytes_by_worker.end(), std::uint64_t{0});
    const int guard = std::accumulate(guards.begin(), guards.end(), 0, [](int a, int b) { return a ^ b; });
    return throughput_row("inner-aead-encrypt",
                          bytes,
                          seconds,
                          "YUME inner_crypto AES-GCM seal, threads=" + std::to_string(workers) +
                              ", " + checksum_detail(guard));
}

HotPathRow run_inner_aead_decrypt(std::uint64_t total_bytes, int thread_count) {
    const int workers = std::clamp(thread_count, 1, 256);
    const auto per_worker = split_work(total_bytes, workers);
    std::atomic<bool> start_flag{false};
    std::vector<std::uint64_t> bytes_by_worker(static_cast<std::size_t>(workers), 0);
    std::vector<int> guards(static_cast<std::size_t>(workers), 0);
    std::vector<std::thread> threads;
    threads.reserve(static_cast<std::size_t>(workers));

    for (int worker = 0; worker < workers; ++worker) {
        threads.emplace_back([&, worker] {
            const auto key = patterned_bytes(32, 51 + worker);
            const auto plaintext = patterned_bytes(64 * kKiB, 71 + worker);
            const auto encrypted = yume::inner::encrypt_payload(key, 0x02, worker + 1, plaintext);
            const int iterations = iterations_for(per_worker[static_cast<std::size_t>(worker)], plaintext.size());
            int guard = 0;
            while (!start_flag.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            for (int i = 0; i < iterations; ++i) {
                auto decrypted = yume::inner::decrypt_payload(key, 0x02, worker + 1, encrypted);
                guard ^= decrypted[static_cast<std::size_t>(i) & (decrypted.size() - 1)];
            }
            bytes_by_worker[static_cast<std::size_t>(worker)] =
                static_cast<std::uint64_t>(iterations) * plaintext.size();
            guards[static_cast<std::size_t>(worker)] = guard;
        });
    }
    const auto start = Clock::now();
    start_flag.store(true, std::memory_order_release);
    for (auto& thread : threads) {
        thread.join();
    }
    const double seconds = elapsed_s(start, Clock::now());
    const auto bytes = std::accumulate(bytes_by_worker.begin(), bytes_by_worker.end(), std::uint64_t{0});
    const int guard = std::accumulate(guards.begin(), guards.end(), 0, [](int a, int b) { return a ^ b; });
    return throughput_row("inner-aead-decrypt",
                          bytes,
                          seconds,
                          "YUME inner_crypto AES-GCM open, threads=" + std::to_string(workers) +
                              ", " + checksum_detail(guard));
}

struct InnerBenchContext {
    std::vector<std::uint8_t> public_key;
    std::vector<std::uint8_t> private_key;
};

InnerBenchContext make_inner_bench_context(const fs::path& workdir, const Args& args) {
    (void)args;
    if (!yume::inner::pq_supported()) {
        throw std::runtime_error("PQ/BaseFWX support is unavailable in this build");
    }
    const fs::path private_key = workdir / "selftest_pq_private.key";
    const fs::path public_key = workdir / "selftest_pq_public.key";
    std::string err;
    if (!yume::inner::generate_pq_keypair(private_key.string(), public_key.string(), &err)) {
        throw std::runtime_error("PQ key generation failed: " + err);
    }

    InnerBenchContext ctx;
    ctx.public_key = read_file(public_key);
    ctx.private_key = read_file(private_key);
    return ctx;
}

HotPathRow run_basefwx_pq_client(const InnerBenchContext& ctx, int samples) {
    auto timings = time_samples_ms(samples, [&](int) {
        auto kem = basefwx::pq::KemEncrypt(ctx.public_key);
        auto key = basefwx::crypto::HkdfSha256(kem.shared, kInnerHkdfInfo, 32);
        if (kem.ciphertext.empty() || key.empty()) {
            throw std::runtime_error("PQ client produced no key");
        }
    });
    return latency_ops_row("basefwx-pq-client", std::move(timings), "ML-KEM encapsulate + HKDF");
}

HotPathRow run_basefwx_pq_server(const InnerBenchContext& ctx, int samples) {
    const int count = std::max(1, samples);
    std::vector<std::vector<std::uint8_t>> ciphertexts;
    std::vector<std::vector<std::uint8_t>> expected_keys;
    ciphertexts.reserve(static_cast<std::size_t>(count));
    expected_keys.reserve(static_cast<std::size_t>(count));
    for (int i = 0; i < count; ++i) {
        auto kem = basefwx::pq::KemEncrypt(ctx.public_key);
        expected_keys.push_back(basefwx::crypto::HkdfSha256(kem.shared, kInnerHkdfInfo, 32));
        ciphertexts.push_back(std::move(kem.ciphertext));
    }

    auto timings = time_samples_ms(count, [&](int i) {
        basefwx::crypto::SecureBytes shared{
            basefwx::pq::KemDecrypt(ctx.private_key, ciphertexts[static_cast<std::size_t>(i)])};
        auto derived = basefwx::crypto::HkdfSha256(shared.bytes(), kInnerHkdfInfo, 32);
        if (derived != expected_keys[static_cast<std::size_t>(i)]) {
            throw std::runtime_error("PQ server derived the wrong key");
        }
    });
    return latency_ops_row("basefwx-pq-server", std::move(timings), "ML-KEM decapsulate + HKDF");
}

HotPathRow run_basefwx_argon2(const Args& args) {
#if defined(BASEFWX_HAS_ARGON2) && BASEFWX_HAS_ARGON2
    const auto password = std::string("yume-selftest-basefwx");
    const auto salt = patterned_bytes(16, 91);
    const std::uint32_t memory_kib = static_cast<std::uint32_t>(
        std::clamp(args.argon_mem_kib, 1024, 262144));
    const std::uint32_t parallelism = static_cast<std::uint32_t>(
        std::clamp(args.argon_parallelism, 1, 16));
    const int samples = std::clamp(args.repeats, 1, 3);
    int guard = 0;
    const auto start = Clock::now();
    for (int i = 0; i < samples; ++i) {
        auto out = basefwx::crypto::Argon2idHashRaw(password,
                                                    salt,
                                                    4,
                                                    memory_kib,
                                                    parallelism,
                                                    32);
        guard ^= out.front();
    }
    const double seconds = elapsed_s(start, Clock::now());
    const auto memory_bytes = static_cast<std::uint64_t>(memory_kib) * kKiB * 4u *
                              static_cast<std::uint64_t>(samples);
    return throughput_row("basefwx-argon2",
                          memory_bytes,
                          seconds,
                          "Argon2id raw, time=4, memory_kib=" + std::to_string(memory_kib) +
                              ", parallelism=" + std::to_string(parallelism) +
                              ", samples=" + std::to_string(samples) +
                              ", " + checksum_detail(guard));
#else
    return {"basefwx-argon2", "unavailable", "Argon2 backend unavailable", false, 0.0, "MiB/s", 0, 0, 0.0};
#endif
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
                          "cache file write, 64 KiB chunks, fsync, " + checksum_detail(guard));
}

HotPathRow run_sustained_mix(long target_ms,
                             int thread_count,
                             const std::function<void(double)>& progress) {
    struct WorkerResult {
        std::uint64_t bytes{0};
        std::uint64_t rounds{0};
        int guard{0};
        std::string error;
    };

    const int workers = std::clamp(thread_count, 1, 256);
    std::atomic<bool> start_flag{false};
    std::vector<WorkerResult> results(static_cast<std::size_t>(workers));
    std::vector<std::thread> threads;
    threads.reserve(static_cast<std::size_t>(workers));

    Clock::time_point started;
    Clock::time_point deadline;

    for (int worker = 0; worker < workers; ++worker) {
        threads.emplace_back([&, worker] {
            try {
                const auto key = patterned_bytes(32, 11 + worker);
                const auto aad = ascii_bytes(kBenchmarkAad);
                const auto plaintext = patterned_bytes(64 * kKiB, 31 + worker);
                auto batch = packet_batch();
                const auto encoded_packet_bytes = yume::protocol::packet_bulk::encoded_size(batch);
                WorkerResult local;
                while (!start_flag.load(std::memory_order_acquire)) {
                    std::this_thread::yield();
                }
                while (Clock::now() < deadline) {
                    auto encrypted = basefwx::crypto::AeadEncrypt(key, plaintext, aad);
                    auto decrypted = basefwx::crypto::AeadDecrypt(key, encrypted, aad);
                    batch.sequence = (static_cast<std::uint64_t>(worker) << 48) | local.rounds;
                    auto encoded = yume::protocol::packet_bulk::encode_batch(batch);
                    auto decoded = yume::protocol::packet_bulk::decode_batch(encoded);
                    const std::string info = std::string(kSustainedHkdfInfoPrefix) +
                                             std::to_string(worker) + ":" +
                                             std::to_string(local.rounds);
                    auto derived = basefwx::crypto::HkdfSha256(key, info, 32);
                    if (!decoded.has_value()) {
                        throw std::runtime_error("packet bulk sustained decode failed");
                    }
                    local.guard ^= decrypted[local.rounds & (decrypted.size() - 1)];
                    local.guard ^= decoded->packets.back().back();
                    local.guard ^= derived.front();
                    local.bytes += static_cast<std::uint64_t>(plaintext.size()) * 2u;
                    local.bytes += static_cast<std::uint64_t>(encoded_packet_bytes) * 2u;
                    ++local.rounds;
                }
                results[static_cast<std::size_t>(worker)] = std::move(local);
            } catch (const std::exception& ex) {
                results[static_cast<std::size_t>(worker)].error = ex.what();
            }
        });
    }

    started = Clock::now();
    deadline = started + std::chrono::milliseconds(std::max<long>(1, target_ms));
    start_flag.store(true, std::memory_order_release);
    auto next_progress = started;
    while (Clock::now() < deadline) {
        const auto now = Clock::now();
        if (now >= next_progress) {
            progress(std::chrono::duration<double>(now - started).count() /
                     (static_cast<double>(target_ms) / 1000.0));
            next_progress = now + std::chrono::milliseconds(500);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    for (auto& thread : threads) {
        thread.join();
    }

    std::uint64_t bytes = 0;
    std::uint64_t rounds = 0;
    int guard = 0;
    for (const auto& result : results) {
        if (!result.error.empty()) {
            throw std::runtime_error(result.error);
        }
        bytes += result.bytes;
        rounds += result.rounds;
        guard ^= result.guard;
    }
    const double seconds = elapsed_s(started, Clock::now());
    return throughput_row("sustained-mix",
                          bytes,
                          seconds,
                          std::to_string(target_ms) + "ms mixed AES-GCM + packet bulk + HKDF, rounds=" +
                              std::to_string(rounds) + ", threads=" + std::to_string(workers) +
                              ", " + checksum_detail(guard));
}

std::vector<HotPathRow> run_hot_paths(const Args& args,
                                      const fs::path& workdir,
                                      int& progress_completed,
                                      int progress_total) {
    const BenchmarkSizing sizing = compute_benchmark_sizing(args, yume::runtime::detect_system_profile());
    std::optional<InnerBenchContext> inner_ctx;
    if (args.full_benchmark) {
        inner_ctx = make_inner_bench_context(workdir, args);
    }

    std::vector<HotPathRow> rows;
    auto step = [&](std::string_view name, auto&& fn) {
        render_progress_bar(progress_completed, progress_total, std::string("hotpath ") + std::string(name));
        rows.push_back(fn());
        ++progress_completed;
        render_progress_bar(progress_completed, progress_total, std::string("hotpath ") + std::string(name));
    };

    step("copy-floor", [&] { return run_copy_floor(sizing.copy_bytes); });
    step("stream-copy-1", [&] { return run_stream_copy(sizing.stream_single_bytes, 1); });
    step("stream-copy-many", [&] { return run_stream_copy(sizing.stream_many_bytes, 64); });
    step("memory-bandwidth", [&] {
        return run_memory_bandwidth(sizing.memory_bytes, sizing.hot_threads, sizing.memory_chunk_bytes);
    });
    step("aes-gcm-encrypt", [&] { return run_aead_encrypt(sizing.crypto_bytes, sizing.hot_threads); });
    step("aes-gcm-decrypt", [&] { return run_aead_decrypt(sizing.crypto_bytes, sizing.hot_threads); });
    step("packet-bulk-encode", [&] { return run_packet_bulk_encode(sizing.packet_bytes, sizing.hot_threads); });
    step("packet-bulk-decode", [&] { return run_packet_bulk_decode(sizing.packet_bytes, sizing.hot_threads); });
    step("hop-hkdf", [&] { return run_hop_hkdf(sizing.hkdf_ops, sizing.hot_threads); });
    if (args.full_benchmark && inner_ctx.has_value()) {
        step("inner-aead-encrypt", [&] { return run_inner_aead_encrypt(sizing.crypto_bytes, sizing.hot_threads); });
        step("inner-aead-decrypt", [&] { return run_inner_aead_decrypt(sizing.crypto_bytes, sizing.hot_threads); });
        const int pq_samples = std::clamp(args.latency_iters / 3, 40, 160);
        step("basefwx-pq-client", [&] { return run_basefwx_pq_client(*inner_ctx, pq_samples); });
        step("basefwx-pq-server", [&] { return run_basefwx_pq_server(*inner_ctx, pq_samples); });
        step("basefwx-argon2", [&] { return run_basefwx_argon2(args); });
    }
    if (sizing.disk_bytes > 0) {
        step("disk-write", [&] { return run_disk_write(workdir, sizing.disk_bytes); });
    }
    if (sizing.sustained_ms > 0) {
        step("sustained-mix", [&] {
            return run_sustained_mix(sizing.sustained_ms, sizing.hot_threads, [&](double fraction) {
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
}  // namespace yume::tools::selftest
