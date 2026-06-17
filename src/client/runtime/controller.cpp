/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "client/runtime/controller.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <cstddef>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#if !defined(_WIN32)
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "client/runtime/local_runtime.hpp"
#include "core/security/identity.hpp"
#include "platform/platform.hpp"

namespace yume::client {

namespace {

std::string default_config_path(std::filesystem::path const& path) {
    return path.empty() ? std::string("config/yume.json") : path.string();
}

bool path_is_executable(std::filesystem::path const& path) {
    if (path.empty()) return false;
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec)) return false;
#if defined(_WIN32)
    return true;
#else
    return ::access(path.c_str(), X_OK) == 0;
#endif
}

std::filesystem::path sibling_executable(char const* name) {
    // Locate a binary that ships next to us (e.g. `yume` finding `yumed`).
    // platform::executable_dir() resolves the running image per-OS — including
    // macOS, where the old /proc/self/exe path did not exist and this returned
    // nothing.
    std::filesystem::path dir = yume::platform::executable_dir();
    if (dir.empty()) {
        return {};
    }
    return dir / name;
}

std::filesystem::path path_lookup(char const* name) {
    char const* raw = std::getenv("PATH");
    if (!raw || !*raw) return {};
    std::string paths(raw);
    std::size_t start = 0;
    while (start <= paths.size()) {
        std::size_t end = paths.find(':', start);
        std::string part = paths.substr(start, end == std::string::npos ? std::string::npos : end - start);
        if (!part.empty()) {
            std::filesystem::path candidate = std::filesystem::path(part) / name;
            if (path_is_executable(candidate)) return candidate;
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return {};
}

#if !defined(_WIN32)
int find_available_loopback_port() {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return -1;
    }

    socklen_t len = sizeof(addr);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
        ::close(fd);
        return -1;
    }

    int port = ntohs(addr.sin_port);
    ::close(fd);
    return port;
}
#endif

void add_arg(std::vector<std::string>& args, char const* key, std::string const& value) {
    if (value.empty()) return;
    args.emplace_back(key);
    args.emplace_back(value);
}

void add_arg(std::vector<std::string>& args, char const* key, int value) {
    args.emplace_back(key);
    args.emplace_back(std::to_string(value));
}

std::vector<std::string> build_args(std::filesystem::path const& exe,
                                    ClientConfig const& cfg,
                                    RuntimeController::StartOptions const& opts) {
    std::vector<std::string> args;
    args.emplace_back(exe.string());
    add_arg(args, "--config", default_config_path(opts.config_path));
    add_arg(args, "--server", cfg.server);
    add_arg(args, "--port", cfg.port);
    add_arg(args, "--auth", cfg.identity);
    add_arg(args, "--socks", cfg.socks_port);
    add_arg(args, "--threads", cfg.io_threads);

    args.emplace_back(cfg.obfuscation ? "--obfs" : "--no-obfs");
    add_arg(args, "--obfs-secret", cfg.obfs_secret);
    if (cfg.inner_crypto) {
        args.emplace_back(cfg.inner_heavy ? "--inner-heavy" : "--inner-light");
        args.emplace_back(cfg.inner_hop ? "--hop" : "--no-hop");
        args.emplace_back("--hop-interval");
        args.emplace_back(std::to_string(cfg.hop_interval_ms));
    } else {
        args.emplace_back("--no-inner");
    }

    args.emplace_back(cfg.allow_udp ? "--udp" : "--tcp");
    if (cfg.allow_local_ip) args.emplace_back("--allow-local-ip");
    if (cfg.server_in_charge) {
        args.emplace_back("--accept-server-control");
        if (cfg.server_in_charge_port > 0) {
            args.emplace_back(std::to_string(cfg.server_in_charge_port));
        }
    }
    if (cfg.allow_exec) args.emplace_back("--allow-exec");
    add_arg(args, "--pq-pub", cfg.pq_public_key);
    args.emplace_back(cfg.allow_embedded_master ? "--use-embedded-master" : "--no-embedded-master");
    add_arg(args, "--anonym-ca-cert", cfg.anonym_ca_cert);
    add_arg(args, "--tls-ca", cfg.tls_ca_cert);
    add_arg(args, "--tls-pin", cfg.tls_pin_sha256);
    add_arg(args, "--proxy", cfg.outbound_proxy_url);
    if (cfg.require_anonym) args.emplace_back("--require-anonym");
    if (cfg.boring) args.emplace_back("--boring");
    args.emplace_back("--non-interactive");
    if (opts.accept_monitoring) args.emplace_back("--accept-monitoring");

    add_arg(args, "--name", cfg.preferred_name);
    add_arg(args, "--client-id", cfg.preferred_id);
    add_arg(args, "--relay-mode", cfg.relay_mode);
    args.emplace_back(cfg.allow_inbound_admin ? "--allow-inbound-admin" : "--deny-inbound-admin");
    args.emplace_back(cfg.allow_outbound_admin ? "--allow-outbound-admin" : "--deny-outbound-admin");
    args.emplace_back(cfg.allow_chat ? "--allow-chat" : "--deny-chat");
    args.emplace_back(cfg.allow_file ? "--allow-file" : "--deny-file");
    args.emplace_back(cfg.allow_bytes ? "--allow-bytes" : "--deny-bytes");
    if (cfg.history_enabled) {
        add_arg(args, "--history-dir", cfg.history_dir);
    } else {
        args.emplace_back("--no-history");
    }
    add_arg(args, "--relay-key-file", cfg.relay_key_file);
    add_arg(args, "--instance", cfg.instance_name);

    if (!cfg.tls_stealth_enabled) {
        args.emplace_back("--no-stealth");
    } else {
        add_arg(args, "--profile", cfg.tls_stealth_profile);
        if (cfg.tls_stealth_rotate) args.emplace_back("--tls-stealth-rotate");
        args.emplace_back("--tls-stealth-rotation-interval");
        args.emplace_back(std::to_string(cfg.tls_stealth_rotation_interval));
        if (cfg.tls_fingerprint_log) args.emplace_back("--tls-fingerprint-log");
        add_arg(args, "--tls-fingerprint-log-path", cfg.tls_fingerprint_log_path);
        if (cfg.tls_fingerprint_verify) args.emplace_back("--tls-fingerprint-verify");
        add_arg(args, "--tls-fingerprint-test-endpoint", cfg.tls_fingerprint_test_endpoint);
    }

    return args;
}

}  // namespace

struct RuntimeController::Impl {
    mutable std::mutex mtx;
    Status status;
    ClientConfig cfg;
    StartOptions opts;
    LogCallback log_cb;
    std::vector<std::string> recent_output;

#if !defined(_WIN32)
    pid_t pid{-1};
    int log_fd{-1};
    std::thread monitor_thread;
    std::thread log_thread;
#endif

#if !defined(_WIN32)
    void join_process_threads_if_stopped() {
        bool stopped = false;
        {
            std::lock_guard<std::mutex> lock(mtx);
            stopped = !status.running;
        }
        if (!stopped) return;

        if (monitor_thread.joinable()) monitor_thread.join();
        if (log_thread.joinable()) log_thread.join();

        std::lock_guard<std::mutex> lock(mtx);
        if (log_fd >= 0) {
            ::close(log_fd);
            log_fd = -1;
        }
    }
#endif

    std::string recent_output_text_locked(std::size_t max_lines = 4) const {
        if (recent_output.empty()) return {};
        std::size_t start = recent_output.size() > max_lines
            ? recent_output.size() - max_lines
            : 0;
        std::ostringstream out;
        for (std::size_t i = start; i < recent_output.size(); ++i) {
            if (i != start) out << " | ";
            out << recent_output[i];
        }
        return out.str();
    }

    void emit(std::string const& line) {
        LogCallback cb;
        {
            std::lock_guard<std::mutex> lock(mtx);
            recent_output.push_back(line);
            if (recent_output.size() > 12) {
                recent_output.erase(recent_output.begin(),
                                    recent_output.begin() + static_cast<std::ptrdiff_t>(recent_output.size() - 12));
            }
            cb = log_cb;
        }
        if (cb) cb(line);
    }
};

RuntimeController::RuntimeController() : impl_(std::make_unique<Impl>()) {}

RuntimeController::~RuntimeController() {
    stop();
}

void RuntimeController::set_log_callback(LogCallback cb) {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->log_cb = std::move(cb);
}

std::string RuntimeController::instance_key(ClientConfig const& cfg,
                                            std::filesystem::path const& config_path) {
    if (!cfg.instance_name.empty()) return cfg.instance_name;
    std::string identity = cfg.identity;
    if (!identity.empty()) {
        std::error_code ec;
        auto abs = std::filesystem::absolute(identity, ec);
        if (!ec) identity = abs.string();
    }
    return yume::identity::derive_instance_key(
        cfg.server + "|" + std::to_string(cfg.port) + "|" +
        identity + "|" + default_config_path(config_path));
}

std::filesystem::path RuntimeController::find_default_executable() {
    if (char const* env = std::getenv("YUME_CLIENT_BIN")) {
        std::filesystem::path p(env);
        if (path_is_executable(p)) return p;
    }
    auto sibling = sibling_executable("yume");
    if (path_is_executable(sibling)) return sibling;
    auto from_path = path_lookup("yume");
    if (!from_path.empty()) return from_path;
    return {};
}

bool RuntimeController::start(ClientConfig cfg, StartOptions opts, std::string* error) {
    if (cfg.server.empty()) {
        if (error) *error = "client server host is required";
        return false;
    }
    if (cfg.identity.empty()) {
        if (error) *error = "client identity key is required";
        return false;
    }
    if (cfg.socks_port < 0 || cfg.socks_port > 65535) {
        if (error) *error = "SOCKS5 port must be 0..65535";
        return false;
    }

#if !defined(_WIN32)
    impl_->join_process_threads_if_stopped();
#endif

    const std::string socket_path =
        LocalRuntime::socket_path_for(instance_key(cfg, opts.config_path));

    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        if (impl_->status.running) {
            if (error) *error = "client runtime is already running";
            return false;
        }
    }

    if (LocalRuntime::available(socket_path)) {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        impl_->cfg = std::move(cfg);
        impl_->opts = std::move(opts);
        impl_->status = Status{};
        impl_->recent_output.clear();
        impl_->status.running = true;
        impl_->status.attached = true;
        impl_->status.ipc_available = true;
        impl_->status.socket_path = socket_path;
        impl_->status.message = "attached to existing yume runtime";
        impl_->status.started = std::chrono::system_clock::now();
        return true;
    }

    if (opts.executable_path.empty()) {
        opts.executable_path = find_default_executable();
    }
    if (!path_is_executable(opts.executable_path)) {
        if (error) *error = "could not find executable yume client; set YUME_CLIENT_BIN";
        return false;
    }

#if defined(_WIN32)
    if (error) *error = "GUI client process control is not implemented on Windows yet";
    return false;
#else
    if (cfg.socks_port == 0) {
        int port = find_available_loopback_port();
        if (port <= 0 || port > 65535) {
            if (error) *error = "could not select an available local SOCKS5 port";
            return false;
        }
        cfg.socks_port = port;
        impl_->emit("Auto-selected SOCKS5 port " + std::to_string(port));
    }

    int pipe_fds[2]{-1, -1};
    if (::pipe(pipe_fds) != 0) {
        if (error) *error = std::string("pipe failed: ") + std::strerror(errno);
        return false;
    }

    std::vector<std::string> args = build_args(opts.executable_path, cfg, opts);
    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (auto& arg : args) argv.push_back(arg.data());
    argv.push_back(nullptr);

    pid_t child = ::fork();
    if (child < 0) {
        int saved = errno;
        ::close(pipe_fds[0]);
        ::close(pipe_fds[1]);
        if (error) *error = std::string("fork failed: ") + std::strerror(saved);
        return false;
    }

    if (child == 0) {
        ::setsid();
        ::close(pipe_fds[0]);
        ::dup2(pipe_fds[1], STDOUT_FILENO);
        ::dup2(pipe_fds[1], STDERR_FILENO);
        int devnull = ::open("/dev/null", O_RDONLY);
        if (devnull >= 0) {
            ::dup2(devnull, STDIN_FILENO);
            ::close(devnull);
        }
        ::execv(opts.executable_path.c_str(), argv.data());
        _exit(127);
    }

    ::close(pipe_fds[1]);
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        impl_->cfg = std::move(cfg);
        impl_->opts = std::move(opts);
        impl_->pid = child;
        impl_->log_fd = pipe_fds[0];
        impl_->status = Status{};
        impl_->recent_output.clear();
        impl_->status.running = true;
        impl_->status.process_id = static_cast<int>(child);
        impl_->status.socket_path = socket_path;
        impl_->status.message = "client process started";
        impl_->status.started = std::chrono::system_clock::now();
    }

    impl_->log_thread = std::thread([this]() {
        int fd = -1;
        {
            std::lock_guard<std::mutex> lock(impl_->mtx);
            fd = impl_->log_fd;
        }
        std::string pending;
        char buf[512];
        for (;;) {
            ssize_t n = ::read(fd, buf, sizeof(buf));
            if (n <= 0) break;
            pending.append(buf, buf + n);
            for (;;) {
                std::size_t nl = pending.find('\n');
                if (nl == std::string::npos) break;
                std::string line = pending.substr(0, nl);
                if (!line.empty() && line.back() == '\r') line.pop_back();
                pending.erase(0, nl + 1);
                if (!line.empty()) impl_->emit(line);
            }
        }
        if (!pending.empty()) impl_->emit(pending);
    });

    impl_->monitor_thread = std::thread([this, child]() {
        int wstatus = 0;
        pid_t rc = ::waitpid(child, &wstatus, 0);
        int exit_code = -1;
        std::string message = "client process exited";
        if (rc == child) {
            if (WIFEXITED(wstatus)) {
                exit_code = WEXITSTATUS(wstatus);
                message = "client process exited with code " + std::to_string(exit_code);
            } else if (WIFSIGNALED(wstatus)) {
                exit_code = 128 + WTERMSIG(wstatus);
                message = "client process terminated by signal " + std::to_string(WTERMSIG(wstatus));
            }
        }
        {
            std::lock_guard<std::mutex> lock(impl_->mtx);
            if (exit_code != 0) {
                auto recent = impl_->recent_output_text_locked();
                if (!recent.empty()) message += ": " + recent;
            }
            impl_->status.running = false;
            impl_->status.ipc_available = false;
            impl_->status.exit_code = exit_code;
            impl_->status.message = message;
            impl_->status.stopped = std::chrono::system_clock::now();
            impl_->pid = -1;
        }
    });

    for (int i = 0; i < 30; ++i) {
        if (LocalRuntime::available(socket_path)) {
            std::lock_guard<std::mutex> lock(impl_->mtx);
            if (impl_->status.running) {
                impl_->status.ipc_available = true;
                impl_->status.message = "client runtime is ready";
            }
            return true;
        }

        bool still_running = true;
        std::string message;
        {
            std::lock_guard<std::mutex> lock(impl_->mtx);
            still_running = impl_->status.running;
            message = impl_->status.message;
        }
        if (!still_running) {
            impl_->join_process_threads_if_stopped();
            {
                std::lock_guard<std::mutex> lock(impl_->mtx);
                message = impl_->status.message;
            }
            if (error) {
                *error = message.empty()
                    ? "client process exited before local IPC became available"
                    : message;
            }
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    return true;
#endif
}

bool RuntimeController::stop(std::string* error) {
#if defined(_WIN32)
    (void)error;
    return true;
#else
    pid_t pid = -1;
    bool attached = false;
    std::string socket_path;
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        pid = impl_->pid;
        attached = impl_->status.attached;
        socket_path = impl_->status.socket_path;
    }

    if (!socket_path.empty() && LocalRuntime::available(socket_path)) {
        std::string ipc_error;
        (void)LocalRuntime::request(
            socket_path,
            nlohmann::json{{"op", "runtime.stop"}, {"args", nlohmann::json::object()}},
            &ipc_error,
            2000);
    }

    if (attached || pid <= 0) {
        if (impl_->monitor_thread.joinable()) impl_->monitor_thread.join();
        if (impl_->log_thread.joinable()) impl_->log_thread.join();
        std::lock_guard<std::mutex> lock(impl_->mtx);
        if (impl_->log_fd >= 0) {
            ::close(impl_->log_fd);
            impl_->log_fd = -1;
        }
        impl_->status.running = false;
        impl_->status.attached = false;
        impl_->status.ipc_available = false;
        impl_->status.message = "client runtime detached";
        impl_->status.stopped = std::chrono::system_clock::now();
        return true;
    }

    for (int i = 0; i < 20; ++i) {
        {
            std::lock_guard<std::mutex> lock(impl_->mtx);
            if (!impl_->status.running) break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        if (impl_->status.running && impl_->pid > 0) {
            ::kill(impl_->pid, SIGTERM);
        }
    }
    for (int i = 0; i < 20; ++i) {
        {
            std::lock_guard<std::mutex> lock(impl_->mtx);
            if (!impl_->status.running) break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        if (impl_->status.running && impl_->pid > 0) {
            ::kill(impl_->pid, SIGKILL);
        }
    }

    if (impl_->monitor_thread.joinable()) impl_->monitor_thread.join();
    if (impl_->log_thread.joinable()) impl_->log_thread.join();
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        if (impl_->log_fd >= 0) {
            ::close(impl_->log_fd);
            impl_->log_fd = -1;
        }
        impl_->status.running = false;
        impl_->pid = -1;
    }
    return true;
#endif
}

bool RuntimeController::running() const {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->status.running;
}

RuntimeController::Status RuntimeController::status() const {
    Status s;
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        s = impl_->status;
    }
    if (s.running && !s.socket_path.empty()) {
        s.ipc_available = LocalRuntime::available(s.socket_path);
        if (s.ipc_available && s.message == "client process started") {
            s.message = "client runtime is ready";
        }
    }
    return s;
}

nlohmann::json RuntimeController::request(std::string const& op,
                                          nlohmann::json const& args,
                                          std::string* error,
                                          int timeout_ms) const {
    std::string socket_path;
    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        socket_path = impl_->status.socket_path;
    }
    if (socket_path.empty()) {
        if (error) *error = "client runtime socket is unavailable";
        return {};
    }
    return LocalRuntime::request(
        socket_path,
        nlohmann::json{{"op", op}, {"args", args}},
        error,
        timeout_ms);
}

}  // namespace yume::client
