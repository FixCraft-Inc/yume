/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime.hpp"

#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cmath>
#include <csignal>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <random>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <utility>

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

namespace yume::tools::selftest {
namespace fs = std::filesystem;

double elapsed_ms(Clock::time_point start, Clock::time_point end) {
    return std::chrono::duration<double, std::milli>(end - start).count();
}

double elapsed_s(Clock::time_point start, Clock::time_point end) {
    return std::chrono::duration<double>(end - start).count();
}

TempDir::TempDir(bool keep) : keep_(keep) {
    fs::path base = fs::temp_directory_path() / "yume-selftest.XXXXXX";
    std::string pattern = base.string();
    char* raw = ::mkdtemp(pattern.data());
    if (!raw) {
        throw std::runtime_error("mkdtemp failed: " + std::string(std::strerror(errno)));
    }
    path_ = raw;
}

TempDir::~TempDir() {
    if (!keep_ && !path_.empty()) {
        std::error_code ec;
        fs::remove_all(path_, ec);
    }
}

const fs::path& TempDir::path() const {
    return path_;
}

void TempDir::keep() {
    keep_ = true;
}

FileDescriptor::FileDescriptor(int fd) : fd_(fd) {}

FileDescriptor::~FileDescriptor() {
    reset();
}

FileDescriptor::FileDescriptor(FileDescriptor&& other) noexcept : fd_(other.fd_) {
    other.fd_ = -1;
}

FileDescriptor& FileDescriptor::operator=(FileDescriptor&& other) noexcept {
    if (this != &other) {
        reset();
        fd_ = other.fd_;
        other.fd_ = -1;
    }
    return *this;
}

int FileDescriptor::get() const {
    return fd_;
}

int FileDescriptor::release() {
    int out = fd_;
    fd_ = -1;
    return out;
}

void FileDescriptor::reset(int fd) {
    if (fd_ >= 0) {
        ::close(fd_);
    }
    fd_ = fd;
}

FileDescriptor::operator bool() const {
    return fd_ >= 0;
}

namespace {

int open_log_file(const fs::path& path) {
    int fd = ::open(path.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (fd < 0) {
        throw std::runtime_error("cannot open log " + path.string());
    }
    return fd;
}

void send_all(int fd, const void* data, std::size_t len) {
    const char* p = static_cast<const char*>(data);
    std::size_t sent = 0;
    while (sent < len) {
        const ssize_t n = ::send(fd, p + sent, len - sent, 0);
        if (n <= 0) {
            throw std::runtime_error("send failed");
        }
        sent += static_cast<std::size_t>(n);
    }
}

void recv_exact(int fd, void* data, std::size_t len) {
    char* p = static_cast<char*>(data);
    std::size_t got = 0;
    while (got < len) {
        const ssize_t n = ::recv(fd, p + got, len - got, 0);
        if (n <= 0) {
            throw std::runtime_error("recv failed");
        }
        got += static_cast<std::size_t>(n);
    }
}

FileDescriptor tcp_connect(int port);
FileDescriptor socks5_connect(int socks_port, int target_port);

std::vector<std::size_t> split_total_bytes(std::size_t total, int streams) {
    const int n = std::max(1, streams);
    std::vector<std::size_t> out(static_cast<std::size_t>(n), total / static_cast<std::size_t>(n));
    std::size_t remaining = total % static_cast<std::size_t>(n);
    for (auto& item : out) {
        if (remaining == 0) {
            break;
        }
        ++item;
        --remaining;
    }
    return out;
}

std::vector<FileDescriptor> open_bulk_connections(int connect_port, int echo_port, bool via_socks, int streams) {
    std::vector<FileDescriptor> fds;
    fds.reserve(static_cast<std::size_t>(std::max(1, streams)));
    for (int i = 0; i < std::max(1, streams); ++i) {
        fds.push_back(via_socks ? socks5_connect(connect_port, echo_port) : tcp_connect(echo_port));
    }
    return fds;
}

void store_first_exception(std::exception_ptr ex, std::mutex& mu, std::exception_ptr& first) {
    std::lock_guard<std::mutex> lock(mu);
    if (!first) {
        first = std::move(ex);
    }
}

FileDescriptor tcp_connect(int port) {
    FileDescriptor fd(::socket(AF_INET, SOCK_STREAM, 0));
    if (!fd) {
        throw std::runtime_error("socket failed");
    }
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
    if (gr[0] != 0x05 || gr[1] != 0x00) {
        throw std::runtime_error("SOCKS greeting rejected");
    }

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
    if (head[0] != 0x05 || head[1] != 0x00) {
        throw std::runtime_error("SOCKS CONNECT rejected");
    }
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
    for (auto& b : out) {
        b = static_cast<unsigned char>(rng() & 0xff);
    }
    return out;
}

void set_reuseaddr(int fd) {
    int yes = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
}

}  // namespace

Stats compute_stats(std::vector<double> samples) {
    Stats stats;
    stats.n = samples.size();
    if (samples.empty()) {
        return stats;
    }
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
    for (double v : samples) {
        sum += v;
    }
    stats.mean = sum / static_cast<double>(samples.size());
    return stats;
}

ChildProcess::ChildProcess(std::vector<std::string> argv,
                           fs::path cwd,
                           fs::path log_path,
                           std::vector<std::pair<std::string, std::string>> env)
    : argv_(std::move(argv))
    , cwd_(std::move(cwd))
    , log_path_(std::move(log_path))
    , env_(std::move(env)) {}

ChildProcess::~ChildProcess() {
    terminate();
}

void ChildProcess::start() {
    if (argv_.empty()) {
        throw std::runtime_error("empty argv");
    }
    FileDescriptor log_fd(open_log_file(log_path_));
    pid_ = ::fork();
    if (pid_ < 0) {
        throw std::runtime_error("fork failed");
    }
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
        for (auto& item : argv_) {
            raw.push_back(item.data());
        }
        raw.push_back(nullptr);
        ::execvp(raw[0], raw.data());
        std::cerr << "exec failed: " << raw[0] << ": " << std::strerror(errno) << "\n";
        ::_exit(127);
    }
}

int ChildProcess::wait() {
    if (pid_ <= 0) {
        return 0;
    }
    int status = 0;
    while (::waitpid(pid_, &status, 0) < 0) {
        if (errno != EINTR) {
            break;
        }
    }
    pid_ = -1;
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return 1;
}

void ChildProcess::terminate() {
    if (pid_ <= 0) {
        return;
    }
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
    while (::waitpid(pid_, &status, 0) < 0 && errno == EINTR) {
    }
    pid_ = -1;
}

const fs::path& ChildProcess::log_path() const {
    return log_path_;
}

EchoServer::~EchoServer() {
    stop();
}

void EchoServer::set_sink(bool sink) {
    sink_ = sink;
}

int EchoServer::start() {
    listener_.reset(::socket(AF_INET, SOCK_STREAM, 0));
    if (!listener_) {
        throw std::runtime_error("echo socket failed");
    }
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

void EchoServer::stop() {
    if (!running_.exchange(false)) {
        return;
    }
    if (listener_) {
        ::shutdown(listener_.get(), SHUT_RDWR);
        listener_.reset();
    }
    if (accept_thread_.joinable()) {
        accept_thread_.join();
    }
}

void EchoServer::accept_loop() {
    while (running_.load()) {
        fd_set set;
        FD_ZERO(&set);
        const int fd = listener_.get();
        if (fd < 0) {
            break;
        }
        FD_SET(fd, &set);
        timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = 250000;
        const int ready = ::select(fd + 1, &set, nullptr, nullptr, &tv);
        if (ready <= 0) {
            continue;
        }
        int client = ::accept(fd, nullptr, nullptr);
        if (client < 0) {
            continue;
        }
        std::thread(&EchoServer::handle_client, client, sink_.load()).detach();
    }
}

void EchoServer::handle_client(int fd, bool sink) {
    FileDescriptor client(fd);
    std::vector<char> buf(64 * 1024);
    std::uint64_t received = 0;
    while (true) {
        const ssize_t n = ::recv(client.get(), buf.data(), buf.size(), 0);
        if (n < 0) {
            return;
        }
        if (n == 0) {
            if (sink) {
                unsigned char ack[8];
                for (int i = 0; i < 8; ++i) {
                    ack[i] = static_cast<unsigned char>((received >> (56 - 8 * i)) & 0xFF);
                }
                std::size_t sent = 0;
                while (sent < sizeof(ack)) {
                    const ssize_t w = ::send(client.get(), ack + sent, sizeof(ack) - sent, 0);
                    if (w <= 0) {
                        break;
                    }
                    sent += static_cast<std::size_t>(w);
                }
            }
            return;
        }
        received += static_cast<std::uint64_t>(n);
        if (sink) {
            continue;
        }
        std::size_t sent = 0;
        while (sent < static_cast<std::size_t>(n)) {
            const ssize_t w = ::send(client.get(), buf.data() + sent, static_cast<std::size_t>(n) - sent, 0);
            if (w <= 0) {
                return;
            }
            sent += static_cast<std::size_t>(w);
        }
    }
}

fs::path find_on_path(const std::string& name) {
    const char* path_env = std::getenv("PATH");
    if (!path_env) {
        return {};
    }
    std::stringstream ss(path_env);
    std::string dir;
    while (std::getline(ss, dir, ':')) {
        fs::path candidate = fs::path(dir) / name;
        if (::access(candidate.c_str(), X_OK) == 0) {
            return candidate;
        }
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
        if (!p.empty()) {
            p = fs::canonical(p, ec);
        }
    }
    if (!ec && !p.empty()) {
        return p;
    }
#if defined(__linux__)
    std::array<char, 4096> buf{};
    const auto n = ::readlink("/proc/self/exe", buf.data(), buf.size() - 1);
    if (n > 0) {
        return fs::path(std::string(buf.data(), static_cast<std::size_t>(n)));
    }
#endif
    return {};
}

bool is_executable(const fs::path& path) {
    return !path.empty() && ::access(path.c_str(), X_OK) == 0;
}

void require_executable(const fs::path& path, const char* label) {
    if (!is_executable(path)) {
        throw std::runtime_error(std::string(label) + " not executable: " + path.string());
    }
}

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
    if (!in) {
        throw std::runtime_error("cannot read " + path.string());
    }
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
        if (fs::exists(path, ec) && fs::file_size(path, ec) > 0) {
            return true;
        }
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
    if (!fd) {
        throw std::runtime_error("socket failed");
    }
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
    if (reply != payload) {
        throw std::runtime_error("latency warmup payload mismatch");
    }

    std::vector<double> out;
    out.reserve(static_cast<std::size_t>(iters));
    for (int i = 0; i < iters; ++i) {
        const auto start = Clock::now();
        send_all(fd.get(), payload.data(), payload.size());
        recv_exact(fd.get(), reply.data(), reply.size());
        const auto end = Clock::now();
        if (reply != payload) {
            throw std::runtime_error("latency payload mismatch");
        }
        out.push_back(std::chrono::duration<double, std::milli>(end - start).count());
    }
    measurement.stats = compute_stats(std::move(out));
    return measurement;
}

BulkMeasurement measure_bulk_one_way(int connect_port, int echo_port, int mib, bool via_socks, int streams) {
    if (streams > 1) {
        const std::size_t total = static_cast<std::size_t>(mib) * 1024u * 1024u;
        auto targets = split_total_bytes(total, streams);
        auto fds = open_bulk_connections(connect_port, echo_port, via_socks, streams);
        const auto payload = random_payload(64 * 1024);
        std::atomic<bool> start_flag{false};
        std::vector<double> send_seconds(fds.size(), 0.0);
        std::vector<double> stream_mib_s(fds.size(), 0.0);
        std::mutex exception_mu;
        std::exception_ptr first_exception;
        const auto start = Clock::now();
        std::vector<std::thread> workers;
        workers.reserve(fds.size());
        for (std::size_t i = 0; i < fds.size(); ++i) {
            workers.emplace_back([fd = std::move(fds[i]),
                                  target = targets[i],
                                  i,
                                  &payload,
                                  &start_flag,
                                  start,
                                  &send_seconds,
                                  &stream_mib_s,
                                  &exception_mu,
                                  &first_exception]() mutable {
                try {
                    while (!start_flag.load(std::memory_order_acquire)) {
                        std::this_thread::yield();
                    }
                    std::size_t sent = 0;
                    while (sent < target) {
                        const std::size_t chunk = std::min<std::size_t>(payload.size(), target - sent);
                        send_all(fd.get(), payload.data(), chunk);
                        sent += chunk;
                    }
                    const auto send_done = Clock::now();
                    ::shutdown(fd.get(), SHUT_WR);
                    unsigned char ack[8]{};
                    recv_exact(fd.get(), ack, sizeof(ack));
                    const auto end = Clock::now();
                    std::uint64_t drained = 0;
                    for (int j = 0; j < 8; ++j) {
                        drained = (drained << 8) | ack[j];
                    }
                    if (drained != target) {
                        throw std::runtime_error("one-way stream drained " + std::to_string(drained) +
                                                 " != " + std::to_string(target));
                    }
                    send_seconds[i] = elapsed_s(start, send_done);
                    const double seconds = std::max(elapsed_s(start, end), 0.000001);
                    stream_mib_s[i] = (static_cast<double>(target) / (1024.0 * 1024.0)) / seconds;
                } catch (...) {
                    store_first_exception(std::current_exception(), exception_mu, first_exception);
                }
            });
        }
        start_flag.store(true, std::memory_order_release);
        for (auto& worker : workers) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        if (first_exception) {
            std::rethrow_exception(first_exception);
        }
        const auto end = Clock::now();
        BulkMeasurement measurement;
        measurement.streams = static_cast<int>(fds.size());
        measurement.total_s = elapsed_s(start, end);
        measurement.send_s = send_seconds.empty() ? 0.0 : *std::max_element(send_seconds.begin(), send_seconds.end());
        measurement.mib_s = (static_cast<double>(total) / (1024.0 * 1024.0)) /
                            std::max(measurement.total_s, 0.000001);
        measurement.per_stream_mib_s = compute_stats(std::move(stream_mib_s));
        return measurement;
    }

    FileDescriptor fd = via_socks ? socks5_connect(connect_port, echo_port) : tcp_connect(echo_port);
    const std::size_t total = static_cast<std::size_t>(mib) * 1024u * 1024u;
    const auto payload = random_payload(64 * 1024);

    const auto start = Clock::now();
    std::size_t sent = 0;
    while (sent < total) {
        const std::size_t chunk = std::min<std::size_t>(payload.size(), total - sent);
        send_all(fd.get(), payload.data(), chunk);
        sent += chunk;
    }
    const auto send_done = Clock::now();
    ::shutdown(fd.get(), SHUT_WR);
    unsigned char ack[8]{};
    recv_exact(fd.get(), ack, sizeof(ack));
    const auto end = Clock::now();
    std::uint64_t drained = 0;
    for (int i = 0; i < 8; ++i) {
        drained = (drained << 8) | ack[i];
    }
    if (drained != total) {
        throw std::runtime_error("one-way sink drained " + std::to_string(drained) +
                                 " != " + std::to_string(total));
    }
    BulkMeasurement measurement;
    measurement.total_s = elapsed_s(start, end);
    measurement.send_s = elapsed_s(start, send_done);
    measurement.mib_s = (static_cast<double>(total) / (1024.0 * 1024.0)) /
                        std::max(measurement.total_s, 0.000001);
    measurement.streams = 1;
    measurement.per_stream_mib_s = compute_stats({measurement.mib_s});
    return measurement;
}

BulkMeasurement measure_bulk(int connect_port, int echo_port, int mib, bool via_socks, int streams) {
    if (streams > 1) {
        const std::size_t total = static_cast<std::size_t>(mib) * 1024u * 1024u;
        auto targets = split_total_bytes(total, streams);
        auto fds = open_bulk_connections(connect_port, echo_port, via_socks, streams);
        const auto payload = random_payload(64 * 1024);
        std::atomic<bool> start_flag{false};
        std::vector<double> send_seconds(fds.size(), 0.0);
        std::vector<double> stream_mib_s(fds.size(), 0.0);
        std::mutex exception_mu;
        std::exception_ptr first_exception;
        const auto start = Clock::now();
        std::vector<std::thread> workers;
        workers.reserve(fds.size());
        for (std::size_t i = 0; i < fds.size(); ++i) {
            workers.emplace_back([fd = std::move(fds[i]),
                                  target = targets[i],
                                  i,
                                  &payload,
                                  &start_flag,
                                  start,
                                  &send_seconds,
                                  &stream_mib_s,
                                  &exception_mu,
                                  &first_exception]() mutable {
                try {
                    while (!start_flag.load(std::memory_order_acquire)) {
                        std::this_thread::yield();
                    }
                    std::atomic<std::size_t> received{0};
                    std::atomic<bool> reader_failed{false};
                    std::thread reader([&] {
                        std::vector<unsigned char> buf(64 * 1024);
                        while (received.load() < target) {
                            const std::size_t want = std::min<std::size_t>(buf.size(), target - received.load());
                            const ssize_t n = ::recv(fd.get(), buf.data(), want, 0);
                            if (n <= 0) {
                                reader_failed.store(true);
                                return;
                            }
                            received.fetch_add(static_cast<std::size_t>(n));
                        }
                    });
                    std::size_t sent = 0;
                    while (sent < target) {
                        const std::size_t chunk = std::min<std::size_t>(payload.size(), target - sent);
                        send_all(fd.get(), payload.data(), chunk);
                        sent += chunk;
                    }
                    const auto send_done = Clock::now();
                    reader.join();
                    const auto end = Clock::now();
                    if (reader_failed.load() || received.load() != target) {
                        throw std::runtime_error("bulk echo stream did not complete");
                    }
                    send_seconds[i] = elapsed_s(start, send_done);
                    const double seconds = std::max(elapsed_s(start, end), 0.000001);
                    stream_mib_s[i] = (static_cast<double>(target) / (1024.0 * 1024.0)) / seconds;
                } catch (...) {
                    store_first_exception(std::current_exception(), exception_mu, first_exception);
                }
            });
        }
        start_flag.store(true, std::memory_order_release);
        for (auto& worker : workers) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        if (first_exception) {
            std::rethrow_exception(first_exception);
        }
        const auto end = Clock::now();
        BulkMeasurement measurement;
        measurement.streams = static_cast<int>(fds.size());
        measurement.total_s = elapsed_s(start, end);
        measurement.send_s = send_seconds.empty() ? 0.0 : *std::max_element(send_seconds.begin(), send_seconds.end());
        measurement.mib_s = (static_cast<double>(total) / (1024.0 * 1024.0)) /
                            std::max(measurement.total_s, 0.000001);
        measurement.per_stream_mib_s = compute_stats(std::move(stream_mib_s));
        return measurement;
    }

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
    measurement.streams = 1;
    measurement.per_stream_mib_s = compute_stats({measurement.mib_s});
    return measurement;
}

void write_text(const fs::path& path, const std::string& text) {
    std::ofstream out(path);
    if (!out) {
        throw std::runtime_error("cannot write " + path.string());
    }
    out << text;
}

}  // namespace yume::tools::selftest
