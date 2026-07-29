/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <thread>
#include <utility>
#include <vector>

namespace yume::tools::selftest {

using Clock = std::chrono::steady_clock;

double elapsed_ms(Clock::time_point start, Clock::time_point end);
double elapsed_s(Clock::time_point start, Clock::time_point end);

struct Config {
    std::string name;
    std::string description;
    bool base_direct{false};
    std::vector<std::string> server_flags;
    std::vector<std::string> client_flags;
};

struct Args {
    std::filesystem::path yume;
    std::filesystem::path yumed;
    std::vector<std::string> configs;
    int latency_iters{120};
    int bulk_mib{32};
    int tunnels{1};
    // 0 keeps each binary's own default; any other value is passed to both
    // spawned processes so a run can compare epoch-window depths.
    int rekey_window{0};
    int client_threads{0};
    int server_threads{2};
    int cooldown_ms{500};
    int repeats{1};
    int streams{1};
    int target_duration_sec{60};
    bool one_way{false};
    bool full_benchmark{false};
    bool dev_style{false};
    bool color{true};
    bool list_configs{false};
    bool keep_workdir{false};
    bool json_stdout{false};
    bool latency_iters_override{false};
    bool bulk_mib_override{false};
    bool tunnel_count_override{false};
    bool server_threads_override{false};
    bool cooldown_ms_override{false};
    bool repeat_count_override{false};
    bool stream_count_override{false};
    bool one_way_override{false};
    bool target_duration_override{false};
    std::filesystem::path json_path;
};

struct Stats {
    std::size_t n{0};
    double min{0.0};
    double median{0.0};
    double p95{0.0};
    double p99{0.0};
    double max{0.0};
    double mean{0.0};
};

Stats compute_stats(std::vector<double> samples);

struct Breakdown {
    double server_listen_ms{0.0};
    double client_socks_ms{0.0};
    double connect_ms{0.0};
    double warmup_ms{0.0};
    double bulk_total_s{0.0};
    double bulk_send_s{0.0};
    int bulk_streams{1};
};

struct Result {
    Config config;
    bool ok{false};
    std::string error;
    Stats latency_ms;
    double throughput_mib_s{0.0};
    Stats throughput_trial_stats;
    std::vector<double> throughput_trials_mib_s;
    int repeat_count{1};
    double wall_s{0.0};
    Breakdown breakdown;
};

struct LatencyMeasurement {
    Stats stats;
    double connect_ms{0.0};
    double warmup_ms{0.0};
};

struct BulkMeasurement {
    double mib_s{0.0};
    double total_s{0.0};
    double send_s{0.0};
    int streams{1};
    Stats per_stream_mib_s;
};

class TempDir {
public:
    explicit TempDir(bool keep);
    ~TempDir();
    const std::filesystem::path& path() const;
    void keep();

private:
    std::filesystem::path path_;
    bool keep_{false};
};

class FileDescriptor {
public:
    FileDescriptor() = default;
    explicit FileDescriptor(int fd);
    ~FileDescriptor();
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    FileDescriptor(FileDescriptor&& other) noexcept;
    FileDescriptor& operator=(FileDescriptor&& other) noexcept;

    int get() const;
    int release();
    void reset(int fd = -1);
    explicit operator bool() const;

private:
    int fd_{-1};
};

class ChildProcess {
public:
    ChildProcess() = default;
    ChildProcess(std::vector<std::string> argv,
                 std::filesystem::path cwd,
                 std::filesystem::path log_path,
                 std::vector<std::pair<std::string, std::string>> env = {});
    ~ChildProcess();

    void start();
    int wait();
    void terminate();
    const std::filesystem::path& log_path() const;

private:
    std::vector<std::string> argv_;
    std::filesystem::path cwd_;
    std::filesystem::path log_path_;
    std::vector<std::pair<std::string, std::string>> env_;
    pid_t pid_{-1};
};

class EchoServer {
public:
    EchoServer() = default;
    ~EchoServer();

    void set_sink(bool sink);
    int start();
    void stop();

private:
    void accept_loop();
    static void handle_client(int fd, bool sink);

    FileDescriptor listener_;
    std::atomic<bool> running_{false};
    std::atomic<bool> sink_{false};
    std::thread accept_thread_;
    int port_{0};
};

// Minimal bounded HTTP/1.1 site used only to satisfy yumed's loopback cover
// health check during local benchmarks. Fingerprint capture still uses the
// committed Node fixture; this class is not a Node-behavior substitute.
class CoverServer {
public:
    CoverServer() = default;
    ~CoverServer();

    int start();
    void stop();

private:
    void accept_loop();
    static void handle_client(int fd);

    FileDescriptor listener_;
    std::atomic<bool> running_{false};
    std::thread accept_thread_;
    int port_{0};
};

std::filesystem::path find_on_path(const std::string& name);
std::filesystem::path self_path(const char* argv0);
bool is_executable(const std::filesystem::path& path);
void require_executable(const std::filesystem::path& path, const char* label);
int run_checked(std::vector<std::string> argv,
                const std::filesystem::path& cwd,
                const std::filesystem::path& log_path);
std::vector<std::uint8_t> read_file(const std::filesystem::path& path);
std::string sha256_hex(const std::vector<std::uint8_t>& bytes);
bool wait_for_path(const std::filesystem::path& path, std::chrono::seconds timeout);
bool wait_for_port(int port, std::chrono::seconds timeout);
bool has_flag(const std::vector<std::string>& flags, std::string_view flag);
int pick_free_port();
LatencyMeasurement measure_latency(int connect_port, int echo_port, int iters, bool via_socks);
BulkMeasurement measure_bulk_one_way(int connect_port, int echo_port, int mib, bool via_socks, int streams = 1);
BulkMeasurement measure_bulk(int connect_port, int echo_port, int mib, bool via_socks, int streams = 1);
void write_text(const std::filesystem::path& path, const std::string& text);

}  // namespace yume::tools::selftest
