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

EndpointBenchWorkload select_endpoint_bench_workload(
        const EndpointBenchOptions& options) noexcept {
    return options.matched_message_echo
        ? EndpointBenchWorkload::MatchedMessageEcho
        : EndpointBenchWorkload::SequentialDirections;
}

bool EndpointEchoReplyContract::Accept(
        const std::vector<std::uint8_t>& data) noexcept {
    if (message_bytes_ == 0 || total_bytes_ == 0 ||
        total_bytes_ % message_bytes_ != 0 ||
        data.size() != message_bytes_ || complete() ||
        data.size() > total_bytes_ ||
        received_bytes_ > total_bytes_ - data.size() ||
        std::any_of(data.begin(), data.end(), [](std::uint8_t value) {
            return value != 0x59U;
        })) {
        return false;
    }
    received_bytes_ += data.size();
    ++received_messages_;
    return true;
}

namespace {

constexpr const char kBenchSinkProto[] = "bench-sink-v1";
constexpr const char kBenchSourceProto[] = "bench-source-v1";
constexpr const char kBenchEchoProto[] = "bench-message-echo-v1";
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

using SharedBenchProgress = std::shared_ptr<std::atomic<std::uint64_t>>;

class BenchWriteWindow {
public:
    bool reserve(std::size_t bytes,
                 const std::atomic<bool>& cancelled,
                 std::chrono::steady_clock::duration timeout) {
        std::unique_lock<std::mutex> lock(mu_);
        if (!cv_.wait_for(lock, timeout, [&] {
                return cancelled.load(std::memory_order_acquire) ||
                       bytes <= kBenchWindowBytes - reserved_bytes_;
            })) {
            return false;
        }
        if (cancelled.load(std::memory_order_acquire)) {
            return false;
        }
        reserved_bytes_ += bytes;
        return true;
    }

    void release(std::size_t bytes) {
        {
            std::lock_guard<std::mutex> lock(mu_);
            reserved_bytes_ = bytes <= reserved_bytes_ ? reserved_bytes_ - bytes : 0;
        }
        cv_.notify_all();
    }

    void wake_waiters() {
        cv_.notify_all();
    }

private:
    std::mutex mu_;
    std::condition_variable cv_;
    std::uint64_t reserved_bytes_{0};
};

struct UploadBenchState {
    std::mutex mu;
    std::condition_variable cv;
    bool open_done{false};
    bool open_ok{false};
    bool closed{false};
    bool write_failed{false};
    std::string error;
    std::string close_reason;
    std::vector<std::uint8_t> summary_bytes;
    std::uint64_t queued_bytes{0};
    std::uint64_t completed_bytes{0};
    std::uint64_t in_flight_bytes{0};
    std::atomic<std::uint64_t> progress_bytes{0};
    std::atomic<bool> cancelled{false};
};

struct DownloadBenchState {
    std::mutex mu;
    std::condition_variable cv;
    bool open_done{false};
    bool open_ok{false};
    bool closed{false};
    std::string error;
    std::string close_reason;
    std::uint64_t received{0};
    std::atomic<std::uint64_t> progress_bytes{0};
    std::atomic<bool> cancelled{false};
};

struct EchoBenchState {
    EchoBenchState(std::uint64_t total_bytes, std::size_t message_bytes)
        : reply_contract(total_bytes, message_bytes) {}

    std::mutex mu;
    std::condition_variable cv;
    bool open_done{false};
    bool open_ok{false};
    bool closed{false};
    bool write_failed{false};
    bool payload_mismatch{false};
    std::string error;
    std::string close_reason;
    std::uint64_t queued_bytes{0};
    std::uint64_t completed_bytes{0};
    std::uint64_t received_bytes{0};
    std::uint64_t in_flight_bytes{0};
    EndpointEchoReplyContract reply_contract;
    std::atomic<std::uint64_t> progress_bytes{0};
    std::atomic<bool> cancelled{false};
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

std::string color(std::string_view text, std::string_view code) {
    if (!util::stdout_colors_enabled()) return std::string(text);
    return "\033[" + std::string(code) + "m" + std::string(text) + "\033[0m";
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
                                              SharedBenchProgress aggregate_progress = {},
                                              std::shared_ptr<BenchWriteWindow> write_window = {}) {
    EndpointBenchResult result;
    const uint8_t stream_id = tunnel->reserve_stream_id();
    if (stream_id == 0) {
        result.error = "no stream id available";
        return result;
    }

    auto state = std::make_shared<UploadBenchState>();
    if (!write_window) {
        write_window = std::make_shared<BenchWriteWindow>();
    }

    const auto cancel = [&] {
        state->cancelled.store(true, std::memory_order_release);
        state->cv.notify_all();
        write_window->wake_waiters();
        tunnel->unregister_stream(stream_id);
    };

    tunnel->register_stream(
        stream_id,
        [state](const Tunnel::Bytes& data) {
            std::lock_guard<std::mutex> lock(state->mu);
            state->summary_bytes.insert(state->summary_bytes.end(), data.begin(), data.end());
        },
        [state, write_window](const std::string& reason) {
            {
                std::lock_guard<std::mutex> lock(state->mu);
                state->close_reason = reason;
                state->closed = true;
            }
            state->cancelled.store(true, std::memory_order_release);
            state->cv.notify_all();
            write_window->wake_waiters();
        });

    nlohmann::json open{
        {"proto", kBenchSinkProto},
        {"host", kBenchHost},
        {"port", 1},
        {"bytes", total_bytes},
    };
    tunnel->open_relay_stream(stream_id, open, [state](bool ok, const std::string& reason) {
        {
            std::lock_guard<std::mutex> lock(state->mu);
            state->open_done = true;
            state->open_ok = ok;
            state->error = reason;
        }
        state->cv.notify_all();
    });

    {
        std::unique_lock<std::mutex> lock(state->mu);
        if (!state->cv.wait_for(lock, kBenchOpenTimeout, [&] {
                return state->open_done || state->closed;
            })) {
            result.error = "benchmark upload OPEN timed out";
            lock.unlock();
            cancel();
            return result;
        }
        if (!state->open_ok) {
            result.error = state->error.empty() ? "benchmark upload OPEN failed" : state->error;
            lock.unlock();
            cancel();
            return result;
        }
    }

    const auto start = std::chrono::steady_clock::now();
    std::unique_ptr<BenchProgressTicker> progress;
    if (progress_label && *progress_label) {
        progress = std::make_unique<BenchProgressTicker>(
            progress_label, total_bytes, state->progress_bytes);
    }
    while (true) {
        std::size_t n = 0;
        std::uint64_t offset = 0;
        {
            std::lock_guard<std::mutex> lock(state->mu);
            if (state->write_failed || state->closed || state->queued_bytes >= total_bytes) {
                break;
            }
            const std::uint64_t remaining = total_bytes - state->queued_bytes;
            n = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, chunk_size));
        }
        if (!write_window->reserve(n, state->cancelled, kBenchStallTimeout)) {
            {
                std::lock_guard<std::mutex> lock(state->mu);
                if (state->write_failed || state->closed) {
                    break;
                }
            }
            result.error = "benchmark upload stalled waiting for the shared write window";
            tunnel->send_close(stream_id, "benchmark upload stalled");
            cancel();
            return result;
        }
        {
            std::lock_guard<std::mutex> lock(state->mu);
            if (state->write_failed || state->closed) {
                write_window->release(n);
                break;
            }
            offset = state->queued_bytes;
            state->queued_bytes += n;
            state->in_flight_bytes += n;
        }

        Tunnel::Bytes payload(n);
        for (std::size_t i = 0; i < n; ++i) {
            payload[i] = static_cast<std::uint8_t>((offset + i) & 0xffu);
        }
        tunnel->send_data(
            stream_id,
            std::move(payload),
            [state, write_window, aggregate_progress, n](
                bool ok, std::size_t, const std::string& reason) {
                write_window->release(n);
                {
                    std::lock_guard<std::mutex> lock(state->mu);
                    state->in_flight_bytes = n <= state->in_flight_bytes
                        ? state->in_flight_bytes - n : 0;
                    if (!ok) {
                        state->write_failed = true;
                        state->error = reason.empty()
                            ? "benchmark upload write failed" : reason;
                    } else {
                        state->completed_bytes += n;
                        state->progress_bytes.store(
                            state->completed_bytes, std::memory_order_relaxed);
                        if (aggregate_progress) {
                            aggregate_progress->fetch_add(n, std::memory_order_relaxed);
                        }
                    }
                }
                if (!ok) {
                    state->cancelled.store(true, std::memory_order_release);
                    write_window->wake_waiters();
                }
                state->cv.notify_all();
            });
    }

    {
        std::unique_lock<std::mutex> lock(state->mu);
        if (!state->cv.wait_for(lock, kBenchStallTimeout, [&] {
                return state->write_failed || state->in_flight_bytes == 0;
            })) {
            result.error = "benchmark upload stalled waiting for queued writes to finish";
            lock.unlock();
            tunnel->send_close(stream_id, "benchmark upload stalled");
            cancel();
            return result;
        }
        if (state->write_failed) {
            result.error = state->error;
            lock.unlock();
            cancel();
            return result;
        }
        if (state->closed && state->queued_bytes < total_bytes) {
            result.error = state->close_reason.empty()
                ? "benchmark upload closed early" : state->close_reason;
            lock.unlock();
            cancel();
            return result;
        }
    }

    tunnel->send_close(stream_id, "benchmark upload complete");
    {
        std::unique_lock<std::mutex> lock(state->mu);
        if (!state->cv.wait_for(lock, kBenchCloseTimeout, [&] { return state->closed; })) {
            result.error = "benchmark upload timed out waiting for server summary";
            lock.unlock();
            cancel();
            return result;
        }
    }
    const auto end = std::chrono::steady_clock::now();
    if (progress) {
        progress->stop();
    }

    result.ok = true;
    result.bytes = state->queued_bytes;
    result.seconds = std::chrono::duration<double>(end - start).count();
    if (!state->summary_bytes.empty()) {
        try {
            auto summary = nlohmann::json::parse(
                std::string(state->summary_bytes.begin(), state->summary_bytes.end()));
            result.server_bytes = summary.value("bytes", static_cast<std::uint64_t>(0));
            const auto server_ms = summary.value("server_ms", 0LL);
            if (server_ms > 0) {
                result.server_seconds = static_cast<double>(server_ms) / 1000.0;
            }
        } catch (...) {
        }
    }
    if (!state->close_reason.empty() &&
        state->close_reason.find("failed") != std::string::npos) {
        result.ok = false;
        result.error = state->close_reason;
    }
    if (result.server_bytes > 0 && result.server_bytes != total_bytes) {
        result.ok = false;
        result.error = "benchmark upload byte mismatch: server got " +
                       std::to_string(result.server_bytes) +
                       ", expected " + std::to_string(total_bytes);
    }
    cancel();
    return result;
}

EndpointBenchResult run_endpoint_download_bench(const std::shared_ptr<Tunnel>& tunnel,
                                                std::uint64_t total_bytes,
                                                const char* progress_label = "DOWN",
                                                SharedBenchProgress aggregate_progress = {}) {
    EndpointBenchResult result;
    const uint8_t stream_id = tunnel->reserve_stream_id();
    if (stream_id == 0) {
        result.error = "no stream id available";
        return result;
    }

    auto state = std::make_shared<DownloadBenchState>();
    const auto cancel = [&] {
        state->cancelled.store(true, std::memory_order_release);
        state->cv.notify_all();
        tunnel->unregister_stream(stream_id);
    };

    tunnel->register_stream(
        stream_id,
        [state, aggregate_progress](const Tunnel::Bytes& data) {
            std::lock_guard<std::mutex> lock(state->mu);
            state->received += static_cast<std::uint64_t>(data.size());
            state->progress_bytes.store(state->received, std::memory_order_relaxed);
            if (aggregate_progress) {
                aggregate_progress->fetch_add(static_cast<std::uint64_t>(data.size()), std::memory_order_relaxed);
            }
            state->cv.notify_all();
        },
        [state](const std::string& reason) {
            {
                std::lock_guard<std::mutex> lock(state->mu);
                state->close_reason = reason;
                state->closed = true;
            }
            state->cancelled.store(true, std::memory_order_release);
            state->cv.notify_all();
        });

    nlohmann::json open{
        {"proto", kBenchSourceProto},
        {"host", kBenchHost},
        {"port", 1},
        {"bytes", total_bytes},
    };
    tunnel->open_relay_stream(stream_id, open, [state](bool ok, const std::string& reason) {
        {
            std::lock_guard<std::mutex> lock(state->mu);
            state->open_done = true;
            state->open_ok = ok;
            state->error = reason;
        }
        state->cv.notify_all();
    });

    {
        std::unique_lock<std::mutex> lock(state->mu);
        if (!state->cv.wait_for(lock, kBenchOpenTimeout, [&] {
                return state->open_done || state->closed;
            })) {
            result.error = "benchmark download OPEN timed out";
            lock.unlock();
            cancel();
            return result;
        }
        if (!state->open_ok) {
            result.error = state->error.empty() ? "benchmark download OPEN failed" : state->error;
            lock.unlock();
            cancel();
            return result;
        }
    }

    const auto start = std::chrono::steady_clock::now();
    std::unique_ptr<BenchProgressTicker> progress;
    if (progress_label && *progress_label) {
        progress = std::make_unique<BenchProgressTicker>(
            progress_label, total_bytes, state->progress_bytes);
    }
    {
        std::unique_lock<std::mutex> lock(state->mu);
        std::uint64_t last_received = state->received;
        while (!state->closed) {
            if (!state->cv.wait_for(lock, kBenchStallTimeout, [&] {
                    return state->closed || state->received != last_received;
                })) {
                result.error = "benchmark download stalled after " +
                               format_mib(state->received) + " MiB";
                lock.unlock();
                tunnel->send_close(stream_id, "benchmark download stalled");
                cancel();
                return result;
            }
            last_received = state->received;
        }
    }
    const auto end = std::chrono::steady_clock::now();
    if (progress) {
        progress->stop();
    }

    result.ok = true;
    result.bytes = state->received;
    result.seconds = std::chrono::duration<double>(end - start).count();
    if (state->received != total_bytes) {
        result.ok = false;
        result.error = "benchmark download byte mismatch: got " +
                       std::to_string(state->received) +
                       ", expected " + std::to_string(total_bytes);
    }
    if (!state->close_reason.empty() &&
        state->close_reason.find("failed") != std::string::npos) {
        result.ok = false;
        result.error = state->close_reason;
    }
    cancel();
    return result;
}

EndpointBenchResult run_endpoint_message_echo_bench(
        const std::shared_ptr<Tunnel>& tunnel,
        std::uint64_t total_bytes,
        std::size_t chunk_size) {
    EndpointBenchResult result;
    const uint8_t stream_id = tunnel->reserve_stream_id();
    if (stream_id == 0) {
        result.error = "no stream id available";
        return result;
    }
    auto state = std::make_shared<EchoBenchState>(total_bytes, chunk_size);
    auto write_window = std::make_shared<BenchWriteWindow>();
    const auto cancel = [&] {
        state->cancelled.store(true, std::memory_order_release);
        state->cv.notify_all();
        write_window->wake_waiters();
        tunnel->unregister_stream(stream_id);
    };

    tunnel->register_stream(
        stream_id,
        [state](const Tunnel::Bytes& data) {
            std::lock_guard<std::mutex> lock(state->mu);
            state->payload_mismatch |= !state->reply_contract.Accept(data);
            state->received_bytes = state->reply_contract.received_bytes();
            state->progress_bytes.store(
                state->received_bytes, std::memory_order_relaxed);
            state->cv.notify_all();
        },
        [state, write_window](const std::string& reason) {
            {
                std::lock_guard<std::mutex> lock(state->mu);
                state->closed = true;
                state->close_reason = reason;
            }
            state->cancelled.store(true, std::memory_order_release);
            state->cv.notify_all();
            write_window->wake_waiters();
        });

    nlohmann::json open{
        {"proto", kBenchEchoProto},
        {"host", kBenchHost},
        {"port", 1},
        {"bytes", total_bytes},
        {"message_bytes", chunk_size},
    };
    tunnel->open_relay_stream(
        stream_id, open, [state](bool ok, const std::string& reason) {
            {
                std::lock_guard<std::mutex> lock(state->mu);
                state->open_done = true;
                state->open_ok = ok;
                state->error = reason;
            }
            state->cv.notify_all();
        });
    {
        std::unique_lock<std::mutex> lock(state->mu);
        if (!state->cv.wait_for(lock, kBenchOpenTimeout, [&] {
                return state->open_done || state->closed;
            })) {
            result.error = "benchmark echo OPEN timed out";
            lock.unlock();
            cancel();
            return result;
        }
        if (!state->open_ok) {
            result.error = state->error.empty()
                ? "benchmark echo OPEN failed" : state->error;
            lock.unlock();
            cancel();
            return result;
        }
    }

    const auto start = std::chrono::steady_clock::now();
    BenchProgressTicker progress("ECHO", total_bytes, state->progress_bytes);
    while (true) {
        std::size_t size = 0;
        {
            std::lock_guard<std::mutex> lock(state->mu);
            if (state->write_failed || state->closed ||
                state->queued_bytes >= total_bytes) {
                break;
            }
            size = static_cast<std::size_t>(std::min<std::uint64_t>(
                total_bytes - state->queued_bytes, chunk_size));
        }
        if (!write_window->reserve(
                size, state->cancelled, kBenchStallTimeout)) {
            result.error = "benchmark echo stalled waiting for the write window";
            tunnel->send_close(stream_id, "benchmark echo stalled");
            cancel();
            return result;
        }
        {
            std::lock_guard<std::mutex> lock(state->mu);
            if (state->write_failed || state->closed) {
                write_window->release(size);
                break;
            }
            state->queued_bytes += size;
            state->in_flight_bytes += size;
        }
        Tunnel::Bytes payload(size, 0x59U);
        tunnel->send_data(
            stream_id, std::move(payload),
            [state, write_window, size](
                bool ok, std::size_t, const std::string& reason) {
                write_window->release(size);
                {
                    std::lock_guard<std::mutex> lock(state->mu);
                    state->in_flight_bytes = size <= state->in_flight_bytes
                        ? state->in_flight_bytes - size : 0;
                    if (ok) {
                        state->completed_bytes += size;
                    } else {
                        state->write_failed = true;
                        state->error = reason.empty()
                            ? "benchmark echo write failed" : reason;
                    }
                }
                state->cv.notify_all();
            });
    }
    {
        std::unique_lock<std::mutex> lock(state->mu);
        if (!state->cv.wait_for(lock, kBenchStallTimeout, [&] {
                return state->write_failed || state->payload_mismatch ||
                    state->closed ||
                    (state->in_flight_bytes == 0 &&
                     state->received_bytes >= total_bytes);
            })) {
            result.error = "benchmark echo timed out waiting for replies";
            lock.unlock();
            tunnel->send_close(stream_id, "benchmark echo stalled");
            cancel();
            return result;
        }
        if (state->write_failed || state->payload_mismatch ||
            state->received_bytes != total_bytes ||
            state->completed_bytes != total_bytes) {
            result.error = state->payload_mismatch
                ? "benchmark echo reply message contract mismatch"
                : (state->error.empty()
                    ? "benchmark echo byte count mismatch" : state->error);
            lock.unlock();
            tunnel->send_close(stream_id, "benchmark echo failed");
            cancel();
            return result;
        }
    }
    const auto end = std::chrono::steady_clock::now();
    progress.stop();
    // Unlike the ordinary throughput benchmark, the capture transaction
    // deliberately leaves its authenticated logical stream open. The caller
    // now holds the same outer WebSocket quiet for 42 seconds and then closes
    // the carrier; an inner CLOSE here would add traffic absent from Chrome's
    // frozen application session immediately before the idle interval.
    result.ok = true;
    result.bytes = total_bytes * 2;
    result.seconds = std::chrono::duration<double>(end - start).count();
    cancel();
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
    auto aggregate_progress = std::make_shared<std::atomic<std::uint64_t>>(0);
    auto write_window = std::make_shared<BenchWriteWindow>();
    BenchProgressTicker progress("UP", total_bytes, *aggregate_progress);
    std::vector<EndpointBenchResult> results(parts.size());
    std::vector<std::thread> workers;
    workers.reserve(parts.size());
    const auto start = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < parts.size(); ++i) {
        workers.emplace_back([&, i] {
            results[i] = run_endpoint_upload_bench(
                tunnel, parts[i], chunk_size, "", aggregate_progress, write_window);
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
    auto aggregate_progress = std::make_shared<std::atomic<std::uint64_t>>(0);
    BenchProgressTicker progress("DOWN", total_bytes, *aggregate_progress);
    std::vector<EndpointBenchResult> results(parts.size());
    std::vector<std::thread> workers;
    workers.reserve(parts.size());
    const auto start = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < parts.size(); ++i) {
        workers.emplace_back([&, i] {
            results[i] = run_endpoint_download_bench(
                tunnel, parts[i], "", aggregate_progress);
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
    const std::size_t relay_chunk_kib = util::relay_read_buf_size() / 1024U;
    const bool production_stream_shape =
        static_cast<std::size_t>(options.bench_chunk_kib) == relay_chunk_kib;

    std::cout << "\n" << color("YUME", "1;35") << " / "
              << color("ENDPOINT BENCHMARK", "1;36") << "\n"
              << "Target   " << cfg.server << ":" << cfg.port;
    const std::string& tls_name = effective_tls_server_name(cfg);
    if (tls_name != cfg.server) {
        std::cout << "  tls-name=" << tls_name;
    }
    std::cout << "\n"
              << "Profile  " << (options.full_profile ? "bench-full" : "standard")
              << "  direction=" << options.bench_direction
              << "  streams=" << options.bench_streams << "\n"
              << "Workload upload="
              << (production_stream_shape ? "production-stream" : "custom-stream")
              << "  download=server-production-stream"
              << "  adapter=authenticated-stream-core\n"
              << "Payload  " << options.bench_mib << " MiB per direction"
              << "  upload-chunk=" << options.bench_chunk_kib << " KiB"
              << "  download-chunk=server-selected\n"
              << "Boundary exact DATA/ratchet/H2/WebSocket/TLS path; excludes local SOCKS"
                 " and target TCP sockets\n"
              << "Security ML-KEM-1024+X25519+PSK ratchet=on  AES-256-GCM=on"
                 "  legacy-hop=off\n"
              << "Carrier  TLS1.3=on  H2/WebSocket=on  padding=off  jitter=off\n";
    if (select_endpoint_bench_workload(options) ==
        EndpointBenchWorkload::MatchedMessageEcho) {
        std::cout << "Capture  authenticated message-echo transaction; each"
                     " application chunk is echoed as parsed\n\n";
        const auto echo = run_endpoint_message_echo_bench(
            tunnel, total_bytes, chunk_size);
        if (!echo.ok) {
            util::log_error("bench echo failed: " + echo.error);
            return 1;
        }
        std::cout << "ECHO    complete\n";
        return 0;
    }
    if (production_stream_shape) {
        std::cout << "Compare  upload DATA geometry matches this process's SOCKS/forward"
                     " relay buffer; download uses yumed target/source policy\n\n";
    } else {
        std::cout << "Compare  custom upload DATA geometry; download uses yumed target/source"
                     " policy; do not label upload SOCKS-equivalent\n\n";
    }

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
