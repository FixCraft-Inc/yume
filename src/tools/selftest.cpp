/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdint>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#if defined(_WIN32)
#error "yume-selftest currently supports POSIX desktop hosts only"
#endif

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
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

struct Config {
    std::string name;
    std::string description;
    bool base_direct{false};
    std::vector<std::string> server_flags;
    std::vector<std::string> client_flags;
};

struct Args {
    fs::path yume;
    fs::path yumed;
    std::vector<std::string> configs;
    int latency_iters{120};
    int bulk_mib{32};
    int argon_mem_kib{32768};
    int argon_parallelism{2};
    int tunnels{1};
    bool list_configs{false};
    bool keep_workdir{false};
    bool json_stdout{false};
    fs::path json_path;
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

struct Breakdown {
    double server_listen_ms{0.0};
    double pq_ready_ms{0.0};
    double client_socks_ms{0.0};
    double connect_ms{0.0};
    double warmup_ms{0.0};
    double bulk_total_s{0.0};
    double bulk_send_s{0.0};
};

struct Result {
    Config config;
    bool ok{false};
    std::string error;
    Stats latency_ms;
    double throughput_mib_s{0.0};
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
};

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
            "Inner heavy KDF with live hopping every 500 ms.",
            false,
            {"--obfs", "--inner-heavy", "--inner-required", "--hop", "--hop-interval", "500"},
            {"--obfs", "--inner-heavy", "--hop", "--hop-interval", "500"},
        },
        {
            "heavy-no-hop",
            "Inner heavy KDF with hopping disabled.",
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
        << "  --configs <a,b>           Config subset; use --list-configs\n"
        << "  --latency-iters <N>       Echo round trips per config (default 120)\n"
        << "  --bulk-mib <N>            Bulk echo size per config (default 32)\n"
        << "  --argon-mem-kib <N>       Heavy KDF memory cap/env for this run (default 32768)\n"
        << "  --argon-parallelism <N>   Heavy KDF parallelism cap/env (default 2)\n"
        << "  --tunnels <N>             Client TLS tunnel count (default 1)\n"
        << "  --json <path>             Write JSON result file\n"
        << "  --json-stdout             Print JSON to stdout after the table\n"
        << "  --keep-workdir            Keep temp logs and generated keys\n"
        << "  --list-configs            Print config names and exit\n"
        << "  -h, --help                Show this help\n\n"
        << "Notes:\n"
        << "  Routed loopback benchmarks require yumed built with\n"
        << "  -DYUME_FEATURE_LAN_BRIDGE=ON. The tool grants allow_local_ip only\n"
        << "  to its temporary auth key through authorized_keys.json.\n";
}

fs::path find_on_path(const std::string& name) {
    const char* path_env = std::getenv("PATH");
    if (!path_env) return {};
    std::stringstream ss(path_env);
    std::string dir;
    while (std::getline(ss, dir, ':')) {
        fs::path candidate = fs::path(dir) / name;
        if (::access(candidate.c_str(), X_OK) == 0) return candidate;
    }
    return {};
}

fs::path self_path(const char* argv0) {
    std::error_code ec;
    fs::path p;
    if (argv0 && std::strchr(argv0, '/')) {
        p = fs::canonical(argv0, ec);
    } else if (argv0) {
        p = find_on_path(argv0);
        if (!p.empty()) p = fs::canonical(p, ec);
    }
    if (!ec && !p.empty()) return p;
#if defined(__linux__)
    std::array<char, 4096> buf{};
    const auto n = ::readlink("/proc/self/exe", buf.data(), buf.size() - 1);
    if (n > 0) return fs::path(std::string(buf.data(), static_cast<std::size_t>(n)));
#endif
    return {};
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
        } else if (arg == "--latency-iters") {
            args.latency_iters = std::max(1, std::stoi(require_value(i, arg)));
        } else if (arg == "--bulk-mib") {
            args.bulk_mib = std::max(1, std::stoi(require_value(i, arg)));
        } else if (arg == "--argon-mem-kib") {
            args.argon_mem_kib = std::max(1024, std::stoi(require_value(i, arg)));
        } else if (arg == "--argon-parallelism") {
            args.argon_parallelism = std::max(1, std::stoi(require_value(i, arg)));
        } else if (arg == "--tunnels") {
            args.tunnels = std::max(1, std::stoi(require_value(i, arg)));
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

class TempDir {
public:
    explicit TempDir(bool keep) : keep_(keep) {
        fs::path base = fs::temp_directory_path() / "yume-selftest.XXXXXX";
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

class FileDescriptor {
public:
    FileDescriptor() = default;
    explicit FileDescriptor(int fd) : fd_(fd) {}
    ~FileDescriptor() { reset(); }
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    FileDescriptor(FileDescriptor&& other) noexcept : fd_(other.fd_) { other.fd_ = -1; }
    FileDescriptor& operator=(FileDescriptor&& other) noexcept {
        if (this != &other) {
            reset();
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }
    int get() const { return fd_; }
    int release() {
        int out = fd_;
        fd_ = -1;
        return out;
    }
    void reset(int fd = -1) {
        if (fd_ >= 0) ::close(fd_);
        fd_ = fd;
    }
    explicit operator bool() const { return fd_ >= 0; }

private:
    int fd_{-1};
};

int open_log_file(const fs::path& path) {
    int fd = ::open(path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0) throw std::runtime_error("cannot open log " + path.string());
    return fd;
}

class ChildProcess {
public:
    ChildProcess() = default;
    ChildProcess(std::vector<std::string> argv,
                 fs::path cwd,
                 fs::path log_path,
                 std::vector<std::pair<std::string, std::string>> env = {})
        : argv_(std::move(argv))
        , cwd_(std::move(cwd))
        , log_path_(std::move(log_path))
        , env_(std::move(env)) {}

    ~ChildProcess() { terminate(); }

    void start() {
        if (argv_.empty()) throw std::runtime_error("empty argv");
        FileDescriptor log_fd(open_log_file(log_path_));
        pid_ = ::fork();
        if (pid_ < 0) throw std::runtime_error("fork failed");
        if (pid_ == 0) {
            if (!cwd_.empty()) {
                ::chdir(cwd_.c_str());
            }
            for (const auto& [key, value] : env_) {
                ::setenv(key.c_str(), value.c_str(), 1);
            }
            ::dup2(log_fd.get(), STDOUT_FILENO);
            ::dup2(log_fd.get(), STDERR_FILENO);
            std::vector<char*> raw;
            raw.reserve(argv_.size() + 1);
            for (auto& item : argv_) raw.push_back(item.data());
            raw.push_back(nullptr);
            ::execvp(raw[0], raw.data());
            std::cerr << "exec failed: " << raw[0] << ": " << std::strerror(errno) << "\n";
            ::_exit(127);
        }
    }

    int wait() {
        if (pid_ <= 0) return 0;
        int status = 0;
        while (::waitpid(pid_, &status, 0) < 0) {
            if (errno != EINTR) break;
        }
        pid_ = -1;
        if (WIFEXITED(status)) return WEXITSTATUS(status);
        if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
        return 1;
    }

    void terminate() {
        if (pid_ <= 0) return;
        ::kill(pid_, SIGTERM);
        const auto deadline = Clock::now() + std::chrono::seconds(3);
        int status = 0;
        while (Clock::now() < deadline) {
            pid_t got = ::waitpid(pid_, &status, WNOHANG);
            if (got == pid_) {
                pid_ = -1;
                return;
            }
            if (got < 0 && errno != EINTR) {
                pid_ = -1;
                return;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        ::kill(pid_, SIGKILL);
        while (::waitpid(pid_, &status, 0) < 0 && errno == EINTR) {}
        pid_ = -1;
    }

    const fs::path& log_path() const { return log_path_; }

private:
    std::vector<std::string> argv_;
    fs::path cwd_;
    fs::path log_path_;
    std::vector<std::pair<std::string, std::string>> env_;
    pid_t pid_{-1};
};

int run_checked(std::vector<std::string> argv, const fs::path& cwd, const fs::path& log_path) {
    ChildProcess child(std::move(argv), cwd, log_path);
    child.start();
    const int code = child.wait();
    if (code != 0) {
        throw std::runtime_error("command failed with exit " + std::to_string(code) +
                                 " (log " + log_path.string() + ")");
    }
    return code;
}

std::vector<std::uint8_t> read_file(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot read " + path.string());
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

std::string sha256_hex(const std::vector<std::uint8_t>& bytes) {
    unsigned char hash[SHA256_DIGEST_LENGTH]{};
    SHA256(bytes.data(), bytes.size(), hash);
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(SHA256_DIGEST_LENGTH * 2);
    for (unsigned char b : hash) {
        out.push_back(kHex[(b >> 4) & 0x0f]);
        out.push_back(kHex[b & 0x0f]);
    }
    return out;
}

bool wait_for_path(const fs::path& path, std::chrono::seconds timeout) {
    const auto deadline = Clock::now() + timeout;
    while (Clock::now() < deadline) {
        std::error_code ec;
        if (fs::exists(path, ec) && fs::file_size(path, ec) > 0) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return false;
}

bool wait_for_port(int port, std::chrono::seconds timeout) {
    const auto deadline = Clock::now() + timeout;
    while (Clock::now() < deadline) {
        FileDescriptor fd(::socket(AF_INET, SOCK_STREAM, 0));
        if (fd) {
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(static_cast<std::uint16_t>(port));
            ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
            if (::connect(fd.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
                return true;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return false;
}

bool has_flag(const std::vector<std::string>& flags, std::string_view flag) {
    return std::find(flags.begin(), flags.end(), flag) != flags.end();
}

int pick_free_port() {
    FileDescriptor fd(::socket(AF_INET, SOCK_STREAM, 0));
    if (!fd) throw std::runtime_error("socket failed");
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (::bind(fd.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        throw std::runtime_error("bind ephemeral port failed");
    }
    socklen_t len = sizeof(addr);
    if (::getsockname(fd.get(), reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
        throw std::runtime_error("getsockname failed");
    }
    return ntohs(addr.sin_port);
}

void set_reuseaddr(int fd) {
    int yes = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
}

class EchoServer {
public:
    EchoServer() = default;
    ~EchoServer() { stop(); }

    int start() {
        listener_.reset(::socket(AF_INET, SOCK_STREAM, 0));
        if (!listener_) throw std::runtime_error("echo socket failed");
        set_reuseaddr(listener_.get());
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(listener_.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            throw std::runtime_error("echo bind failed");
        }
        if (::listen(listener_.get(), 128) != 0) {
            throw std::runtime_error("echo listen failed");
        }
        socklen_t len = sizeof(addr);
        if (::getsockname(listener_.get(), reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
            throw std::runtime_error("echo getsockname failed");
        }
        port_ = ntohs(addr.sin_port);
        running_.store(true);
        accept_thread_ = std::thread([this] { accept_loop(); });
        return port_;
    }

    void stop() {
        if (!running_.exchange(false)) return;
        if (listener_) {
            ::shutdown(listener_.get(), SHUT_RDWR);
            listener_.reset();
        }
        if (accept_thread_.joinable()) accept_thread_.join();
    }

private:
    void accept_loop() {
        while (running_.load()) {
            fd_set set;
            FD_ZERO(&set);
            const int fd = listener_.get();
            if (fd < 0) break;
            FD_SET(fd, &set);
            timeval tv{};
            tv.tv_sec = 0;
            tv.tv_usec = 250000;
            const int ready = ::select(fd + 1, &set, nullptr, nullptr, &tv);
            if (ready <= 0) continue;
            int client = ::accept(fd, nullptr, nullptr);
            if (client < 0) continue;
            std::thread(&EchoServer::echo_client, client).detach();
        }
    }

    static void echo_client(int fd) {
        FileDescriptor client(fd);
        std::vector<char> buf(64 * 1024);
        while (true) {
            const ssize_t n = ::recv(client.get(), buf.data(), buf.size(), 0);
            if (n <= 0) return;
            std::size_t sent = 0;
            while (sent < static_cast<std::size_t>(n)) {
                const ssize_t w = ::send(client.get(), buf.data() + sent, static_cast<std::size_t>(n) - sent, 0);
                if (w <= 0) return;
                sent += static_cast<std::size_t>(w);
            }
        }
    }

    FileDescriptor listener_;
    std::atomic<bool> running_{false};
    std::thread accept_thread_;
    int port_{0};
};

void send_all(int fd, const void* data, std::size_t len) {
    const char* p = static_cast<const char*>(data);
    std::size_t sent = 0;
    while (sent < len) {
        const ssize_t n = ::send(fd, p + sent, len - sent, 0);
        if (n <= 0) throw std::runtime_error("send failed");
        sent += static_cast<std::size_t>(n);
    }
}

void recv_exact(int fd, void* data, std::size_t len) {
    char* p = static_cast<char*>(data);
    std::size_t got = 0;
    while (got < len) {
        const ssize_t n = ::recv(fd, p + got, len - got, 0);
        if (n <= 0) throw std::runtime_error("recv failed");
        got += static_cast<std::size_t>(n);
    }
}

FileDescriptor tcp_connect(int port) {
    FileDescriptor fd(::socket(AF_INET, SOCK_STREAM, 0));
    if (!fd) throw std::runtime_error("socket failed");
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<std::uint16_t>(port));
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::connect(fd.get(), reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        throw std::runtime_error("connect failed: " + std::string(std::strerror(errno)));
    }
    return fd;
}

FileDescriptor socks5_connect(int socks_port, int target_port) {
    FileDescriptor fd = tcp_connect(socks_port);
    const unsigned char greeting[] = {0x05, 0x01, 0x00};
    send_all(fd.get(), greeting, sizeof(greeting));
    unsigned char gr[2]{};
    recv_exact(fd.get(), gr, sizeof(gr));
    if (gr[0] != 0x05 || gr[1] != 0x00) throw std::runtime_error("SOCKS greeting rejected");

    unsigned char req[10]{};
    req[0] = 0x05;
    req[1] = 0x01;
    req[2] = 0x00;
    req[3] = 0x01;
    req[4] = 127;
    req[5] = 0;
    req[6] = 0;
    req[7] = 1;
    req[8] = static_cast<unsigned char>((target_port >> 8) & 0xff);
    req[9] = static_cast<unsigned char>(target_port & 0xff);
    send_all(fd.get(), req, sizeof(req));
    unsigned char head[4]{};
    recv_exact(fd.get(), head, sizeof(head));
    if (head[0] != 0x05 || head[1] != 0x00) throw std::runtime_error("SOCKS CONNECT rejected");
    if (head[3] == 0x01) {
        unsigned char rest[6]{};
        recv_exact(fd.get(), rest, sizeof(rest));
    } else if (head[3] == 0x03) {
        unsigned char len = 0;
        recv_exact(fd.get(), &len, 1);
        std::vector<unsigned char> rest(static_cast<std::size_t>(len) + 2);
        recv_exact(fd.get(), rest.data(), rest.size());
    } else if (head[3] == 0x04) {
        unsigned char rest[18]{};
        recv_exact(fd.get(), rest, sizeof(rest));
    } else {
        throw std::runtime_error("SOCKS reply has unknown address type");
    }
    return fd;
}

std::vector<unsigned char> random_payload(std::size_t len) {
    std::vector<unsigned char> out(len);
    std::mt19937_64 rng(std::random_device{}());
    for (auto& b : out) b = static_cast<unsigned char>(rng() & 0xff);
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
    stats.p99 = pick(0.99);
    double sum = 0.0;
    for (double v : samples) sum += v;
    stats.mean = sum / static_cast<double>(samples.size());
    return stats;
}

LatencyMeasurement measure_latency(int connect_port, int echo_port, int iters, bool via_socks) {
    LatencyMeasurement measurement;
    const auto connect_start = Clock::now();
    FileDescriptor fd = via_socks ? socks5_connect(connect_port, echo_port) : tcp_connect(echo_port);
    measurement.connect_ms = elapsed_ms(connect_start, Clock::now());
    auto payload = random_payload(64);
    std::vector<unsigned char> reply(payload.size());
    const auto warmup_start = Clock::now();
    send_all(fd.get(), payload.data(), payload.size());
    recv_exact(fd.get(), reply.data(), reply.size());
    measurement.warmup_ms = elapsed_ms(warmup_start, Clock::now());
    if (reply != payload) throw std::runtime_error("latency warmup payload mismatch");

    std::vector<double> out;
    out.reserve(static_cast<std::size_t>(iters));
    for (int i = 0; i < iters; ++i) {
        const auto start = Clock::now();
        send_all(fd.get(), payload.data(), payload.size());
        recv_exact(fd.get(), reply.data(), reply.size());
        const auto end = Clock::now();
        if (reply != payload) throw std::runtime_error("latency payload mismatch");
        out.push_back(std::chrono::duration<double, std::milli>(end - start).count());
    }
    measurement.stats = compute_stats(std::move(out));
    return measurement;
}

BulkMeasurement measure_bulk(int connect_port, int echo_port, int mib, bool via_socks) {
    FileDescriptor fd = via_socks ? socks5_connect(connect_port, echo_port) : tcp_connect(echo_port);
    const std::size_t total = static_cast<std::size_t>(mib) * 1024u * 1024u;
    const auto payload = random_payload(64 * 1024);
    std::atomic<std::size_t> received{0};
    std::atomic<bool> reader_failed{false};
    std::thread reader([&] {
        std::vector<unsigned char> buf(64 * 1024);
        while (received.load() < total) {
            const std::size_t want = std::min<std::size_t>(buf.size(), total - received.load());
            const ssize_t n = ::recv(fd.get(), buf.data(), want, 0);
            if (n <= 0) {
                reader_failed.store(true);
                return;
            }
            received.fetch_add(static_cast<std::size_t>(n));
        }
    });

    const auto start = Clock::now();
    std::size_t sent = 0;
    while (sent < total) {
        const std::size_t chunk = std::min<std::size_t>(payload.size(), total - sent);
        send_all(fd.get(), payload.data(), chunk);
        sent += chunk;
    }
    const auto send_done = Clock::now();
    reader.join();
    const auto end = Clock::now();
    if (reader_failed.load() || received.load() != total) {
        throw std::runtime_error("bulk echo did not complete");
    }
    BulkMeasurement measurement;
    measurement.total_s = elapsed_s(start, end);
    measurement.send_s = elapsed_s(start, send_done);
    measurement.mib_s = (static_cast<double>(total) / (1024.0 * 1024.0)) /
                        std::max(measurement.total_s, 0.000001);
    return measurement;
}

void write_text(const fs::path& path, const std::string& text) {
    std::ofstream out(path);
    if (!out) throw std::runtime_error("cannot write " + path.string());
    out << text;
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
            "--threads", "2",
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
                  int echo_port) {
    Result result;
    result.config = cfg;
    const auto start = Clock::now();
    try {
        if (cfg.base_direct) {
            LatencyMeasurement latency = measure_latency(0, echo_port, args.latency_iters, false);
            result.latency_ms = latency.stats;
            result.breakdown.connect_ms = latency.connect_ms;
            result.breakdown.warmup_ms = latency.warmup_ms;
            BulkMeasurement bulk = measure_bulk(0, echo_port, args.bulk_mib, false);
            result.throughput_mib_s = bulk.mib_s;
            result.breakdown.bulk_total_s = bulk.total_s;
            result.breakdown.bulk_send_s = bulk.send_s;
        } else {
            const int yumed_port = pick_free_port();
            const int socks_port = pick_free_port();
            YumeStack stack(args, ks, cfg, workdir, yumed_port, socks_port);
            stack.start(result.breakdown);
            LatencyMeasurement latency = measure_latency(socks_port, echo_port, args.latency_iters, true);
            result.latency_ms = latency.stats;
            result.breakdown.connect_ms = latency.connect_ms;
            result.breakdown.warmup_ms = latency.warmup_ms;
            BulkMeasurement bulk = measure_bulk(socks_port, echo_port, args.bulk_mib, true);
            result.throughput_mib_s = bulk.mib_s;
            result.breakdown.bulk_total_s = bulk.total_s;
            result.breakdown.bulk_send_s = bulk.send_s;
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

std::vector<Config> select_configs(const Args& args) {
    if (args.configs.empty()) return builtin_configs();
    std::vector<Config> selected;
    for (const auto& name : args.configs) {
        auto it = std::find_if(builtin_configs().begin(), builtin_configs().end(), [&](const Config& cfg) {
            return cfg.name == name;
        });
        if (it == builtin_configs().end()) throw std::runtime_error("unknown config: " + name);
        selected.push_back(*it);
    }
    return selected;
}

void require_executable(const fs::path& path, const char* label) {
    if (path.empty() || ::access(path.c_str(), X_OK) != 0) {
        throw std::runtime_error(std::string(label) + " not executable: " + path.string());
    }
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
                  << "  ok\n";
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

std::string render_json(const Args& args, const std::vector<Result>& results, const fs::path& workdir) {
    std::ostringstream out;
    out << "{\n";
    out << "  \"schema_version\": 2,\n";
    out << "  \"workdir\": \"" << json_escape(workdir.string()) << "\",\n";
    out << "  \"latency_iters\": " << args.latency_iters << ",\n";
    out << "  \"bulk_mib\": " << args.bulk_mib << ",\n";
    out << "  \"argon_mem_kib\": " << args.argon_mem_kib << ",\n";
    out << "  \"argon_parallelism\": " << args.argon_parallelism << ",\n";
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
        out << "      \"breakdown\": {\n";
        out << "        \"server_listen_ms\": " << r.breakdown.server_listen_ms << ",\n";
        out << "        \"pq_ready_ms\": " << r.breakdown.pq_ready_ms << ",\n";
        out << "        \"client_socks_ms\": " << r.breakdown.client_socks_ms << ",\n";
        out << "        \"connect_ms\": " << r.breakdown.connect_ms << ",\n";
        out << "        \"warmup_ms\": " << r.breakdown.warmup_ms << ",\n";
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
        if (::access("openssl", X_OK) != 0 && find_on_path("openssl").empty()) {
            throw std::runtime_error("openssl is required on PATH for temporary TLS/key material");
        }

        TempDir tmp(args.keep_workdir);
        EchoServer echo;
        const int echo_port = echo.start();
        Keyset ks = generate_keyset(args, tmp.path());
        const auto configs = select_configs(args);

        std::vector<Result> results;
        results.reserve(configs.size());
        for (const auto& cfg : configs) {
            std::cerr << "[selftest] " << cfg.name << ": " << cfg.description << "\n";
            Result result = run_config(args, ks, cfg, tmp.path(), echo_port);
            if (!result.ok) tmp.keep();
            results.push_back(std::move(result));
        }
        echo.stop();

        render_table(results);
        const std::string json = render_json(args, results, tmp.path());
        if (!args.json_path.empty()) {
            write_text(args.json_path, json);
            std::cerr << "[selftest] wrote JSON " << args.json_path << "\n";
        }
        if (args.json_stdout) {
            std::cout << json;
        }

        const bool all_ok = std::all_of(results.begin(), results.end(), [](const Result& r) { return r.ok; });
        if (!all_ok) {
            tmp.keep();
            std::cerr << "[selftest] logs kept in " << tmp.path() << "\n";
        }
        return all_ok ? 0 : 1;
    } catch (const std::exception& ex) {
        std::cerr << "yume-selftest: " << ex.what() << "\n";
        return 2;
    }
}
