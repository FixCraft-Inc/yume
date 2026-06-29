/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/commands/bench.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

#include "client/cli/entry.hpp"
#include "client/transport/tunnel.hpp"
#include "util.hpp"

namespace yume::client {

namespace {

constexpr const char kBenchSinkProto[] = "bench-sink-v1";
constexpr const char kBenchSourceProto[] = "bench-source-v1";
constexpr const char kBenchHost[] = "yume-bench.invalid";
constexpr std::uint64_t kBenchWindowBytes = 8ULL * 1024ULL * 1024ULL;
constexpr auto kBenchOpenTimeout = std::chrono::seconds(30);
constexpr auto kBenchStallTimeout = std::chrono::seconds(60);
constexpr auto kBenchCloseTimeout = std::chrono::seconds(60);

struct EndpointBenchResult {
    bool ok{false};
    std::string error;
    std::uint64_t bytes{0};
    double seconds{0.0};
    std::uint64_t server_bytes{0};
    double server_seconds{0.0};
};

std::vector<std::uint64_t> split_total_bytes(std::uint64_t total, int streams) {
    const auto count = static_cast<std::size_t>(std::max(1, streams));
    std::vector<std::uint64_t> out(count, total / count);
    std::uint64_t remaining = total % count;
    for (auto& item : out) {
        if (remaining == 0) break;
        ++item;
        --remaining;
    }
    return out;
}

double mib_per_second(std::uint64_t bytes, double seconds) {
    if (seconds <= 0.0) {
        return 0.0;
    }
    return (static_cast<double>(bytes) / (1024.0 * 1024.0)) / seconds;
}

double mbit_per_second(std::uint64_t bytes, double seconds) {
    return mib_per_second(bytes, seconds) * 8.388608;
}

std::string format_rate(std::uint64_t bytes, double seconds) {
    std::ostringstream out;
    out.setf(std::ios::fixed);
    out << std::setprecision(1)
        << mib_per_second(bytes, seconds) << " MiB/s / "
        << mbit_per_second(bytes, seconds) << " Mbit/s";
    return out.str();
}

std::string format_mib(std::uint64_t bytes) {
    std::ostringstream out;
    out.setf(std::ios::fixed);
    out << std::setprecision(1)
        << (static_cast<double>(bytes) / (1024.0 * 1024.0));
    return out.str();
}

std::string format_seconds(double seconds) {
    std::ostringstream out;
    out.setf(std::ios::fixed);
    out << std::setprecision(3) << seconds;
    return out.str();
}

void print_result_row(std::string_view label, std::uint64_t bytes, double seconds) {
    std::cout << std::left << std::setw(8) << label
              << std::right << std::setw(12) << format_mib(bytes) << " MiB"
              << std::setw(11) << format_seconds(seconds) << " s  "
              << format_rate(bytes, seconds) << "\n";
}

bool stdout_is_tty() {
#if defined(_WIN32)
    return _isatty(_fileno(stdout)) != 0;
#else
    return ::isatty(fileno(stdout)) != 0;
#endif
}

std::string progress_bar(double pct) {
    constexpr int kWidth = 30;
    pct = std::clamp(pct, 0.0, 100.0);
    const int filled = static_cast<int>((pct / 100.0) * kWidth);
    std::string out;
    out.reserve(kWidth + 2);
    out.push_back('[');
    for (int i = 0; i < kWidth; ++i) {
        out.push_back(i < filled ? '#' : '.');
    }
    out.push_back(']');
    return out;
}

class BenchProgressTicker {
public:
    BenchProgressTicker(std::string label,
                        std::uint64_t total_bytes,
                        const std::atomic<std::uint64_t>& current_bytes)
        : label_(std::move(label)),
          total_bytes_(total_bytes),
          current_bytes_(current_bytes),
          started_(std::chrono::steady_clock::now()),
          tty_(stdout_is_tty()),
          thread_([this] { run(); }) {}

    ~BenchProgressTicker() {
        stop();
    }

    BenchProgressTicker(const BenchProgressTicker&) = delete;
    BenchProgressTicker& operator=(const BenchProgressTicker&) = delete;

    void stop() {
        {
            std::lock_guard<std::mutex> lock(stop_mu_);
            if (stop_) {
                return;
            }
            stop_ = true;
        }
        stop_cv_.notify_all();
        if (thread_.joinable()) {
            thread_.join();
        }
        if (printed_ && tty_) {
            std::cout << "\r\033[2K" << std::flush;
        }
    }

private:
    void print_progress() {
        const auto now = std::chrono::steady_clock::now();
        const double elapsed = std::chrono::duration<double>(now - started_).count();
        const auto bytes = current_bytes_.load(std::memory_order_relaxed);
        const double pct = total_bytes_ > 0
            ? (100.0 * static_cast<double>(bytes) / static_cast<double>(total_bytes_))
            : 0.0;
        if (tty_) {
            std::cout << "\r\033[2K"
                      << label_ << " " << progress_bar(pct) << " "
                      << std::fixed << std::setprecision(1) << std::setw(5) << pct << "%  "
                      << format_mib(bytes) << "/" << format_mib(total_bytes_) << " MiB  "
                      << format_rate(bytes, elapsed)
                      << std::flush;
        } else {
            std::cout << label_ << ": " << format_mib(bytes)
                      << "/" << format_mib(total_bytes_) << " MiB, "
                      << std::fixed << std::setprecision(1) << pct << "%, "
                      << format_rate(bytes, elapsed) << "\n"
                      << std::flush;
        }
        printed_ = true;
    }

    void run() {
        std::unique_lock<std::mutex> lock(stop_mu_);
        while (!stop_) {
            const auto interval = tty_ ? std::chrono::milliseconds(500) : std::chrono::seconds(5);
            if (stop_cv_.wait_for(lock, interval, [this] { return stop_; })) {
                break;
            }
            lock.unlock();
            print_progress();
            lock.lock();
        }
    }

    std::string label_;
    std::uint64_t total_bytes_{0};
    const std::atomic<std::uint64_t>& current_bytes_;
    std::chrono::steady_clock::time_point started_;
    bool tty_{false};
    bool printed_{false};
    std::mutex stop_mu_;
    std::condition_variable stop_cv_;
    bool stop_{false};
    std::thread thread_;
};

EndpointBenchResult run_endpoint_upload_bench(const std::shared_ptr<Tunnel>& tunnel,
                                              std::uint64_t total_bytes,
                                              std::size_t chunk_size,
                                              const char* progress_label = "UP",
                                              std::atomic<std::uint64_t>* aggregate_progress = nullptr) {
    EndpointBenchResult result;
    const uint8_t stream_id = tunnel->reserve_stream_id();
    if (stream_id == 0) {
        result.error = "no stream id available";
        return result;
    }

    std::mutex mu;
    std::condition_variable cv;
    bool open_done = false;
    bool open_ok = false;
    bool closed = false;
    bool write_failed = false;
    std::string error;
    std::string close_reason;
    std::vector<std::uint8_t> summary_bytes;
    std::uint64_t queued_bytes = 0;
    std::uint64_t completed_bytes = 0;
    std::uint64_t in_flight_bytes = 0;
    std::atomic<std::uint64_t> progress_bytes{0};

    tunnel->register_stream(
        stream_id,
        [&](const Tunnel::Bytes& data) {
            std::lock_guard<std::mutex> lock(mu);
            summary_bytes.insert(summary_bytes.end(), data.begin(), data.end());
        },
        [&](const std::string& reason) {
            std::lock_guard<std::mutex> lock(mu);
            close_reason = reason;
            closed = true;
            cv.notify_all();
        });

    nlohmann::json open{
        {"proto", kBenchSinkProto},
        {"host", kBenchHost},
        {"port", 1},
        {"bytes", total_bytes},
    };
    tunnel->open_relay_stream(stream_id, open, [&](bool ok, const std::string& reason) {
        std::lock_guard<std::mutex> lock(mu);
        open_done = true;
        open_ok = ok;
        error = reason;
        cv.notify_all();
    });

    {
        std::unique_lock<std::mutex> lock(mu);
        if (!cv.wait_for(lock, kBenchOpenTimeout, [&] { return open_done || closed; })) {
            result.error = "benchmark upload OPEN timed out";
            tunnel->unregister_stream(stream_id);
            return result;
        }
        if (!open_ok) {
            result.error = error.empty() ? "benchmark upload OPEN failed" : error;
            tunnel->unregister_stream(stream_id);
            return result;
        }
    }

    const auto start = std::chrono::steady_clock::now();
    std::unique_ptr<BenchProgressTicker> progress;
    if (progress_label && *progress_label) {
        progress = std::make_unique<BenchProgressTicker>(progress_label, total_bytes, progress_bytes);
    }
    while (true) {
        std::size_t n = 0;
        std::uint64_t offset = 0;
        {
            std::unique_lock<std::mutex> lock(mu);
            if (!cv.wait_for(lock, kBenchStallTimeout, [&] {
                return write_failed || closed || queued_bytes >= total_bytes ||
                       in_flight_bytes + chunk_size <= kBenchWindowBytes;
            })) {
                result.error = "benchmark upload stalled waiting for the local write window";
                tunnel->send_close(stream_id, "benchmark upload stalled");
                tunnel->unregister_stream(stream_id);
                return result;
            }
            if (write_failed || closed || queued_bytes >= total_bytes) {
                break;
            }
            const std::uint64_t remaining = total_bytes - queued_bytes;
            n = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, chunk_size));
            offset = queued_bytes;
            queued_bytes += n;
            in_flight_bytes += n;
        }

        Tunnel::Bytes payload(n);
        for (std::size_t i = 0; i < n; ++i) {
            payload[i] = static_cast<std::uint8_t>((offset + i) & 0xffu);
        }
        tunnel->send_data(stream_id, std::move(payload), [&, n](bool ok, std::size_t, const std::string& reason) {
            std::lock_guard<std::mutex> lock(mu);
            if (in_flight_bytes >= n) {
                in_flight_bytes -= n;
            } else {
                in_flight_bytes = 0;
            }
            if (!ok) {
                write_failed = true;
                error = reason.empty() ? "benchmark upload write failed" : reason;
            } else {
                completed_bytes += n;
                progress_bytes.store(completed_bytes, std::memory_order_relaxed);
                if (aggregate_progress) {
                    aggregate_progress->fetch_add(n, std::memory_order_relaxed);
                }
            }
            cv.notify_all();
        });
    }

    {
        std::unique_lock<std::mutex> lock(mu);
        if (!cv.wait_for(lock, kBenchStallTimeout, [&] { return write_failed || in_flight_bytes == 0; })) {
            result.error = "benchmark upload stalled waiting for queued writes to finish";
            tunnel->send_close(stream_id, "benchmark upload stalled");
            tunnel->unregister_stream(stream_id);
            return result;
        }
        if (write_failed) {
            result.error = error;
            tunnel->unregister_stream(stream_id);
            return result;
        }
        if (closed && queued_bytes < total_bytes) {
            result.error = close_reason.empty() ? "benchmark upload closed early" : close_reason;
            tunnel->unregister_stream(stream_id);
            return result;
        }
    }

    tunnel->send_close(stream_id, "benchmark upload complete");
    {
        std::unique_lock<std::mutex> lock(mu);
        if (!cv.wait_for(lock, kBenchCloseTimeout, [&] { return closed; })) {
            result.error = "benchmark upload timed out waiting for server summary";
            tunnel->unregister_stream(stream_id);
            return result;
        }
    }
    const auto end = std::chrono::steady_clock::now();
    if (progress) {
        progress->stop();
    }

    result.ok = true;
    result.bytes = queued_bytes;
    result.seconds = std::chrono::duration<double>(end - start).count();
    if (!summary_bytes.empty()) {
        try {
            auto summary = nlohmann::json::parse(std::string(summary_bytes.begin(), summary_bytes.end()));
            result.server_bytes = summary.value("bytes", static_cast<std::uint64_t>(0));
            const auto server_ms = summary.value("server_ms", 0LL);
            if (server_ms > 0) {
                result.server_seconds = static_cast<double>(server_ms) / 1000.0;
            }
        } catch (...) {
        }
    }
    if (!close_reason.empty() && close_reason.find("failed") != std::string::npos) {
        result.ok = false;
        result.error = close_reason;
    }
    if (result.server_bytes > 0 && result.server_bytes != total_bytes) {
        result.ok = false;
        result.error = "benchmark upload byte mismatch: server got " +
                       std::to_string(result.server_bytes) +
                       ", expected " + std::to_string(total_bytes);
    }
    return result;
}

EndpointBenchResult run_endpoint_download_bench(const std::shared_ptr<Tunnel>& tunnel,
                                                std::uint64_t total_bytes,
                                                const char* progress_label = "DOWN",
                                                std::atomic<std::uint64_t>* aggregate_progress = nullptr) {
    EndpointBenchResult result;
    const uint8_t stream_id = tunnel->reserve_stream_id();
    if (stream_id == 0) {
        result.error = "no stream id available";
        return result;
    }

    std::mutex mu;
    std::condition_variable cv;
    bool open_done = false;
    bool open_ok = false;
    bool closed = false;
    std::string error;
    std::string close_reason;
    std::uint64_t received = 0;
    std::atomic<std::uint64_t> progress_bytes{0};

    tunnel->register_stream(
        stream_id,
        [&](const Tunnel::Bytes& data) {
            std::lock_guard<std::mutex> lock(mu);
            received += static_cast<std::uint64_t>(data.size());
            progress_bytes.store(received, std::memory_order_relaxed);
            if (aggregate_progress) {
                aggregate_progress->fetch_add(static_cast<std::uint64_t>(data.size()), std::memory_order_relaxed);
            }
            cv.notify_all();
        },
        [&](const std::string& reason) {
            std::lock_guard<std::mutex> lock(mu);
            close_reason = reason;
            closed = true;
            cv.notify_all();
        });

    nlohmann::json open{
        {"proto", kBenchSourceProto},
        {"host", kBenchHost},
        {"port", 1},
        {"bytes", total_bytes},
    };
    tunnel->open_relay_stream(stream_id, open, [&](bool ok, const std::string& reason) {
        std::lock_guard<std::mutex> lock(mu);
        open_done = true;
        open_ok = ok;
        error = reason;
        cv.notify_all();
    });

    {
        std::unique_lock<std::mutex> lock(mu);
        if (!cv.wait_for(lock, kBenchOpenTimeout, [&] { return open_done || closed; })) {
            result.error = "benchmark download OPEN timed out";
            tunnel->unregister_stream(stream_id);
            return result;
        }
        if (!open_ok) {
            result.error = error.empty() ? "benchmark download OPEN failed" : error;
            tunnel->unregister_stream(stream_id);
            return result;
        }
    }

    const auto start = std::chrono::steady_clock::now();
    std::unique_ptr<BenchProgressTicker> progress;
    if (progress_label && *progress_label) {
        progress = std::make_unique<BenchProgressTicker>(progress_label, total_bytes, progress_bytes);
    }
    {
        std::unique_lock<std::mutex> lock(mu);
        std::uint64_t last_received = received;
        while (!closed) {
            if (!cv.wait_for(lock, kBenchStallTimeout, [&] {
                    return closed || received != last_received;
                })) {
                result.error = "benchmark download stalled after " + format_mib(received) + " MiB";
                tunnel->send_close(stream_id, "benchmark download stalled");
                tunnel->unregister_stream(stream_id);
                return result;
            }
            last_received = received;
        }
    }
    const auto end = std::chrono::steady_clock::now();
    if (progress) {
        progress->stop();
    }

    result.ok = true;
    result.bytes = received;
    result.seconds = std::chrono::duration<double>(end - start).count();
    if (received != total_bytes) {
        result.ok = false;
        result.error = "benchmark download byte mismatch: got " + std::to_string(received) +
                       ", expected " + std::to_string(total_bytes);
    }
    if (!close_reason.empty() && close_reason.find("failed") != std::string::npos) {
        result.ok = false;
        result.error = close_reason;
    }
    return result;
}

EndpointBenchResult run_endpoint_upload_bench_many(const std::shared_ptr<Tunnel>& tunnel,
                                                   std::uint64_t total_bytes,
                                                   std::size_t chunk_size,
                                                   int streams) {
    if (streams <= 1) {
        return run_endpoint_upload_bench(tunnel, total_bytes, chunk_size);
    }

    auto parts = split_total_bytes(total_bytes, streams);
    std::atomic<std::uint64_t> aggregate_progress{0};
    BenchProgressTicker progress("UP", total_bytes, aggregate_progress);
    std::vector<EndpointBenchResult> results(parts.size());
    std::vector<std::thread> workers;
    workers.reserve(parts.size());
    const auto start = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < parts.size(); ++i) {
        workers.emplace_back([&, i] {
            results[i] = run_endpoint_upload_bench(tunnel, parts[i], chunk_size, "", &aggregate_progress);
        });
    }
    for (auto& worker : workers) {
        if (worker.joinable()) worker.join();
    }
    const auto end = std::chrono::steady_clock::now();
    progress.stop();

    EndpointBenchResult aggregate;
    aggregate.ok = true;
    aggregate.seconds = std::chrono::duration<double>(end - start).count();
    for (const auto& result : results) {
        if (!result.ok) {
            aggregate.ok = false;
            aggregate.error = result.error.empty() ? "benchmark upload stream failed" : result.error;
            return aggregate;
        }
        aggregate.bytes += result.bytes;
        aggregate.server_bytes += result.server_bytes;
        aggregate.server_seconds = std::max(aggregate.server_seconds, result.server_seconds);
    }
    return aggregate;
}

EndpointBenchResult run_endpoint_download_bench_many(const std::shared_ptr<Tunnel>& tunnel,
                                                     std::uint64_t total_bytes,
                                                     int streams) {
    if (streams <= 1) {
        return run_endpoint_download_bench(tunnel, total_bytes);
    }

    auto parts = split_total_bytes(total_bytes, streams);
    std::atomic<std::uint64_t> aggregate_progress{0};
    BenchProgressTicker progress("DOWN", total_bytes, aggregate_progress);
    std::vector<EndpointBenchResult> results(parts.size());
    std::vector<std::thread> workers;
    workers.reserve(parts.size());
    const auto start = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < parts.size(); ++i) {
        workers.emplace_back([&, i] {
            results[i] = run_endpoint_download_bench(tunnel, parts[i], "", &aggregate_progress);
        });
    }
    for (auto& worker : workers) {
        if (worker.joinable()) worker.join();
    }
    const auto end = std::chrono::steady_clock::now();
    progress.stop();

    EndpointBenchResult aggregate;
    aggregate.ok = true;
    aggregate.seconds = std::chrono::duration<double>(end - start).count();
    for (const auto& result : results) {
        if (!result.ok) {
            aggregate.ok = false;
            aggregate.error = result.error.empty() ? "benchmark download stream failed" : result.error;
            return aggregate;
        }
        aggregate.bytes += result.bytes;
    }
    return aggregate;
}

}  // namespace

int run_endpoint_benchmark(const std::shared_ptr<Tunnel>& tunnel,
                           const ClientConfig& cfg,
                           const EndpointBenchOptions& options) {
    const std::uint64_t total_bytes =
        static_cast<std::uint64_t>(options.bench_mib) * 1024ULL * 1024ULL;
    const std::size_t chunk_size =
        static_cast<std::size_t>(options.bench_chunk_kib) * 1024U;

    std::cout << "\nYUME Endpoint Benchmark\n"
              << "Target   " << cfg.server << ":" << cfg.port;
    const std::string& tls_name = effective_tls_server_name(cfg);
    if (tls_name != cfg.server) {
        std::cout << "  tls-name=" << tls_name;
    }
    std::cout << "\n"
              << "Profile  " << (options.full_profile ? "bench-full" : "standard")
              << "  direction=" << options.bench_direction
              << "  streams=" << options.bench_streams << "\n"
              << "Payload  " << options.bench_mib << " MiB per direction"
              << "  chunk=" << options.bench_chunk_kib << " KiB\n"
              << "Path     authenticated YUME stream over current TLS/obfs/inner settings\n\n";

    const auto bench_started = std::chrono::steady_clock::now();
    EndpointBenchResult up_result;
    EndpointBenchResult down_result;
    bool ran_up = false;
    bool ran_down = false;
    if (options.bench_direction == "both" || options.bench_direction == "up") {
        std::cout << "Upload\n" << std::flush;
        up_result = run_endpoint_upload_bench_many(tunnel, total_bytes, chunk_size, options.bench_streams);
        if (!up_result.ok) {
            util::log_error("bench upload failed: " + up_result.error);
            return 1;
        }
        ran_up = true;
        std::cout << "UP      complete\n";
    }

    if (options.bench_direction == "both" || options.bench_direction == "down") {
        std::cout << "Download\n" << std::flush;
        down_result = run_endpoint_download_bench_many(tunnel, total_bytes, options.bench_streams);
        if (!down_result.ok) {
            util::log_error("bench download failed: " + down_result.error);
            return 1;
        }
        ran_down = true;
        std::cout << "DOWN    complete\n";
    }
    const auto bench_finished = std::chrono::steady_clock::now();

    const std::uint64_t total_done =
        (ran_up ? up_result.bytes : 0ULL) +
        (ran_down ? down_result.bytes : 0ULL);
    const double total_seconds =
        std::chrono::duration<double>(bench_finished - bench_started).count();

    std::cout << "\nResults\n"
              << "--------------------------------------------------------------------------------\n"
              << std::left << std::setw(8) << "TOTAL"
              << std::right << std::setw(12) << format_mib(total_done) << " MiB"
              << std::setw(11) << format_seconds(total_seconds) << " s  "
              << format_rate(total_done, total_seconds) << "\n";
    if (ran_up) {
        print_result_row("UP", up_result.bytes, up_result.seconds);
    }
    if (ran_down) {
        print_result_row("DOWN", down_result.bytes, down_result.seconds);
    }
    std::cout << "--------------------------------------------------------------------------------\n";

    if (ran_up && up_result.server_bytes > 0 && up_result.server_seconds > 0.0) {
        std::cout << "Server upload drain: "
                  << format_rate(up_result.server_bytes, up_result.server_seconds)
                  << " (" << format_mib(up_result.server_bytes) << " MiB in "
                  << format_seconds(up_result.server_seconds) << " s)\n";
    }
    return 0;
}

}  // namespace yume::client
