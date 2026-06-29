/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/runtime/local_runtime.hpp"

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <system_error>

#if !defined(_WIN32)
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

namespace yume::local_runtime {

namespace {

constexpr size_t kMaxMessageBytes = 1024 * 1024;
constexpr int kDefaultSocketTimeoutMs = 5000;

std::string home_dir() {
    const char* home = std::getenv("HOME");
    return (home && *home) ? std::string(home) : std::string(".");
}

#if !defined(_WIN32)
bool send_all(int fd, const char* data, size_t size) {
    size_t sent = 0;
    while (sent < size) {
        int send_flags = 0;
#ifdef MSG_NOSIGNAL
        send_flags |= MSG_NOSIGNAL;
#endif
        const ssize_t rc = ::send(fd, data + sent, size - sent, send_flags);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (rc == 0) {
            return false;
        }
        sent += static_cast<size_t>(rc);
    }
    return true;
}

bool recv_line(int fd, std::string* out) {
    if (!out) {
        return false;
    }
    out->clear();
    char ch = '\0';
    while (out->size() < kMaxMessageBytes) {
        const ssize_t rc = ::recv(fd, &ch, 1, 0);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (rc == 0) {
            return !out->empty();
        }
        if (ch == '\n') {
            return true;
        }
        out->push_back(ch);
    }
    return false;
}

void set_socket_timeouts(int fd, int timeout_ms) {
    if (fd < 0 || timeout_ms <= 0) {
        return;
    }
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = static_cast<suseconds_t>((timeout_ms % 1000) * 1000);
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

bool connect_socket(const std::string& path, int* fd_out) {
    if (!fd_out) {
        return false;
    }
    *fd_out = -1;
    int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return false;
    }
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (path.size() >= sizeof(addr.sun_path)) {
        ::close(fd);
        errno = ENAMETOOLONG;
        return false;
    }
    std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return false;
    }
    *fd_out = fd;
    return true;
}

void wake_listener(const std::string& path) {
    int fd = -1;
    if (!connect_socket(path, &fd)) {
        return;
    }
    set_socket_timeouts(fd, 100);
    ::close(fd);
}
#endif

}  // namespace

bool supported() {
#if defined(_WIN32)
    return false;
#else
    return true;
#endif
}

std::string runtime_dir() {
    const char* xdg_runtime = std::getenv("XDG_RUNTIME_DIR");
    if (xdg_runtime && *xdg_runtime) {
        return (std::filesystem::path(xdg_runtime) / "yume").string();
    }
    return (std::filesystem::path(home_dir()) / ".cache" / "yume").string();
}

std::string socket_path(const std::string& role, const std::string& instance_key) {
    return (std::filesystem::path(runtime_dir()) / (role + "-" + instance_key + ".sock")).string();
}

Server::Server(std::string path, RequestHandler handler)
    : path_(std::move(path))
    , handler_(std::move(handler)) {}

Server::~Server() {
    stop();
}

bool Server::start(std::string* error) {
#if defined(_WIN32)
    if (error) {
        *error = "local runtime attach is not supported on this platform yet";
    }
    return false;
#else
    if (running_) {
        return true;
    }
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(path_).parent_path(), ec);
    if (ec) {
        if (error) {
            *error = "failed to create runtime directory: " + ec.message();
        }
        return false;
    }

    if (std::filesystem::exists(path_)) {
        if (endpoint_available(path_)) {
            if (error) {
                *error = "runtime already running";
            }
            return false;
        }
        std::filesystem::remove(path_, ec);
    }

    server_fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd_ < 0) {
        if (error) {
            *error = std::string("socket() failed: ") + std::strerror(errno);
        }
        return false;
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (path_.size() >= sizeof(addr.sun_path)) {
        if (error) {
            *error = "runtime socket path is too long";
        }
        ::close(server_fd_);
        server_fd_ = -1;
        return false;
    }
    std::strncpy(addr.sun_path, path_.c_str(), sizeof(addr.sun_path) - 1);
    if (::bind(server_fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        if (error) {
            *error = std::string("bind() failed: ") + std::strerror(errno);
        }
        ::close(server_fd_);
        server_fd_ = -1;
        return false;
    }
    if (::listen(server_fd_, 16) != 0) {
        if (error) {
            *error = std::string("listen() failed: ") + std::strerror(errno);
        }
        ::close(server_fd_);
        server_fd_ = -1;
        cleanup_path();
        return false;
    }
    stopping_ = false;
    running_ = true;
    thread_ = std::thread([this]() { serve_loop(); });
    return true;
#endif
}

void Server::stop() {
#if !defined(_WIN32)
    stopping_ = true;
    if (server_fd_ >= 0) {
        wake_listener(path_);
        ::shutdown(server_fd_, SHUT_RDWR);
        ::close(server_fd_);
        server_fd_ = -1;
    }
    if (thread_.joinable()) {
        thread_.join();
    }
    running_ = false;
    cleanup_path();
#endif
}

bool Server::running() const {
    return running_;
}

const std::string& Server::path() const {
    return path_;
}

bool Server::endpoint_available(const std::string& path) {
#if defined(_WIN32)
    (void)path;
    return false;
#else
    int fd = -1;
    if (!connect_socket(path, &fd)) {
        return false;
    }
    ::close(fd);
    return true;
#endif
}

nlohmann::json Server::request(const std::string& path,
                               const nlohmann::json& request_json,
                               std::string* error,
                               int timeout_ms) {
#if defined(_WIN32)
    (void)path;
    (void)request_json;
    (void)timeout_ms;
    if (error) {
        *error = "local runtime attach is not supported on this platform yet";
    }
    return nlohmann::json::object();
#else
    int fd = -1;
    if (!connect_socket(path, &fd)) {
        if (error) {
            *error = std::string("connect() failed: ") + std::strerror(errno);
        }
        return nlohmann::json::object();
    }
    set_socket_timeouts(fd, timeout_ms);

    std::string payload = request_json.dump();
    payload.push_back('\n');
    if (!send_all(fd, payload.data(), payload.size())) {
        if (error) {
            *error = std::string("send() failed: ") + std::strerror(errno);
        }
        ::close(fd);
        return nlohmann::json::object();
    }
    std::string response_line;
    if (!recv_line(fd, &response_line)) {
        if (error) {
            *error = "failed to read local runtime response";
        }
        ::close(fd);
        return nlohmann::json::object();
    }
    ::close(fd);
    try {
        return nlohmann::json::parse(response_line);
    } catch (const std::exception& ex) {
        if (error) {
            *error = std::string("invalid local runtime response: ") + ex.what();
        }
        return nlohmann::json::object();
    }
#endif
}

void Server::serve_loop() {
#if !defined(_WIN32)
    while (!stopping_) {
        int client_fd = ::accept(server_fd_, nullptr, nullptr);
        if (client_fd < 0) {
            if (stopping_) {
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            if (errno == EBADF || errno == EINVAL) {
                break;
            }
            continue;
        }
        set_socket_timeouts(client_fd, kDefaultSocketTimeoutMs);

        std::string line;
        nlohmann::json response;
        if (!recv_line(client_fd, &line)) {
            response = {{"ok", false}, {"error", "failed to read request"}};
        } else {
            try {
                auto request_json = nlohmann::json::parse(line);
                response = handler_ ? handler_(request_json)
                                    : nlohmann::json{{"ok", false}, {"error", "no handler"}};
            } catch (const std::exception& ex) {
                response = {{"ok", false}, {"error", std::string("request parse failed: ") + ex.what()}};
            }
        }
        std::string encoded = response.dump();
        encoded.push_back('\n');
        send_all(client_fd, encoded.data(), encoded.size());
        ::close(client_fd);
    }
#endif
}

void Server::cleanup_path() {
#if !defined(_WIN32)
    std::error_code ec;
    std::filesystem::remove(path_, ec);
#endif
}

}  // namespace yume::local_runtime
