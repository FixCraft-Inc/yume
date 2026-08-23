/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/transport/chrome_tls_helper.hpp"

#include "client/transport/chrome_tls_protocol.hpp"
#include "core/security/crypto.hpp"
#include "core/security/secure_erase.hpp"
#include "core/stealth/cover_profile.hpp"

#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
#include <basefwx/crypto.hpp>
#endif

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <system_error>
#include <utility>

#if defined(__linux__)
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char** environ;
#endif

namespace yume::client {
namespace {

std::string Hex(std::span<const std::uint8_t> bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string output(bytes.size() * 2U, '0');
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        output[index * 2U] = kHex[bytes[index] >> 4U];
        output[index * 2U + 1U] = kHex[bytes[index] & 0x0FU];
    }
    return output;
}

#if defined(__linux__)

class ScopedFd {
public:
    explicit ScopedFd(int fd = -1) noexcept : fd_(fd) {}
    ~ScopedFd() { Reset(); }
    ScopedFd(const ScopedFd&) = delete;
    ScopedFd& operator=(const ScopedFd&) = delete;
    ScopedFd(ScopedFd&& other) noexcept : fd_(other.Release()) {}
    ScopedFd& operator=(ScopedFd&& other) noexcept {
        if (this != &other) {
            Reset(other.Release());
        }
        return *this;
    }
    int Get() const noexcept { return fd_; }
    int Release() noexcept { return std::exchange(fd_, -1); }
    void Reset(int fd = -1) noexcept {
        if (fd_ >= 0) {
            while (::close(fd_) < 0 && errno == EINTR) {
            }
        }
        fd_ = fd;
    }

private:
    int fd_;
};

class ScopedVectorWiper {
public:
    explicit ScopedVectorWiper(std::vector<std::uint8_t>& bytes) noexcept
        : bytes_(bytes) {}
    ~ScopedVectorWiper() { security::secure_erase(bytes_); }
    ScopedVectorWiper(const ScopedVectorWiper&) = delete;
    ScopedVectorWiper& operator=(const ScopedVectorWiper&) = delete;

private:
    std::vector<std::uint8_t>& bytes_;
};

template <std::size_t Size>
class ScopedArrayWiper {
public:
    explicit ScopedArrayWiper(std::array<std::uint8_t, Size>& bytes) noexcept
        : bytes_(bytes) {}
    ~ScopedArrayWiper() {
        volatile std::uint8_t* cursor = bytes_.data();
        for (std::size_t index = 0; index < bytes_.size(); ++index) {
            cursor[index] = 0;
        }
    }
    ScopedArrayWiper(const ScopedArrayWiper&) = delete;
    ScopedArrayWiper& operator=(const ScopedArrayWiper&) = delete;

private:
    std::array<std::uint8_t, Size>& bytes_;
};

class ChildLifetime final : public HelperProcessLifetime {
public:
    explicit ChildLifetime(pid_t pid) noexcept : pid_(pid) {}
    ~ChildLifetime() override {
        if (pid_ <= 0) {
            return;
        }
        int status = 0;
        const pid_t result = ::waitpid(pid_, &status, WNOHANG);
        if (result == pid_ || (result < 0 && errno == ECHILD)) {
            return;
        }
        (void)::kill(pid_, SIGKILL);
        while (::waitpid(pid_, &status, 0) < 0 && errno == EINTR) {
        }
    }

private:
    pid_t pid_;
};

class SpawnActions {
public:
    SpawnActions() {
        const int error = ::posix_spawn_file_actions_init(&actions_);
        if (error != 0) {
            throw std::system_error(error, std::generic_category(),
                                    "initialize helper spawn actions");
        }
        initialized_ = true;
    }
    ~SpawnActions() {
        if (initialized_) {
            (void)::posix_spawn_file_actions_destroy(&actions_);
        }
    }
    SpawnActions(const SpawnActions&) = delete;
    SpawnActions& operator=(const SpawnActions&) = delete;

    void Dup2(int source, int destination) {
        const int error = ::posix_spawn_file_actions_adddup2(
            &actions_, source, destination);
        if (error != 0) {
            throw std::system_error(error, std::generic_category(),
                                    "configure helper descriptor");
        }
    }
    void CloseFrom(int first) {
        const int error = ::posix_spawn_file_actions_addclosefrom_np(
            &actions_, first);
        if (error != 0) {
            throw std::system_error(error, std::generic_category(),
                                    "close unrelated helper descriptors");
        }
    }
    const posix_spawn_file_actions_t* Get() const noexcept { return &actions_; }

private:
    posix_spawn_file_actions_t actions_{};
    bool initialized_{false};
};

void ValidateHelperFile(const std::filesystem::path& path) {
    if (!path.is_absolute()) {
        throw std::runtime_error("Chrome TLS helper path must be absolute");
    }
    struct stat status {};
    if (::lstat(path.c_str(), &status) != 0) {
        throw std::system_error(errno, std::generic_category(),
                                "inspect Chrome TLS helper");
    }
    if (!S_ISREG(status.st_mode)) {
        throw std::runtime_error("Chrome TLS helper is not a regular file");
    }
    if ((status.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        throw std::runtime_error(
            "Chrome TLS helper must not be group- or world-writable");
    }
    const uid_t effective_uid = ::geteuid();
    if (status.st_uid != 0 && status.st_uid != effective_uid) {
        throw std::runtime_error(
            "Chrome TLS helper must be owned by root or the current user");
    }
    if (::access(path.c_str(), X_OK) != 0) {
        throw std::system_error(errno, std::generic_category(),
                                "execute Chrome TLS helper");
    }
}

void ConfigureSocketpairBuffers(const std::array<int, 2>& pair) {
    constexpr int kBufferBytes = 2 * 1024 * 1024;
    for (const int fd : pair) {
        if (::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &kBufferBytes,
                         sizeof(kBufferBytes)) != 0 ||
            ::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &kBufferBytes,
                         sizeof(kBufferBytes)) != 0) {
            throw std::system_error(errno, std::generic_category(),
                                    "configure Chrome TLS helper IPC buffers");
        }
    }
}

std::chrono::steady_clock::time_point Deadline(
        std::chrono::milliseconds timeout) {
    return std::chrono::steady_clock::now() + timeout;
}

bool StopRequested(const std::function<bool()>& should_stop) {
    if (!should_stop) return false;
    try {
        return should_stop();
    } catch (...) {
        return true;
    }
}

void ThrowIfStopped(const std::function<bool()>& should_stop) {
    if (StopRequested(should_stop)) {
        throw std::runtime_error("Chrome TLS helper IPC cancelled");
    }
}

void WaitFd(int fd, short events,
            std::chrono::steady_clock::time_point deadline,
            const std::function<bool()>& should_stop) {
    for (;;) {
        ThrowIfStopped(should_stop);
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            throw std::runtime_error("Chrome TLS helper IPC timed out");
        }
        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - now);
        std::int64_t timeout_ms =
            std::clamp<std::int64_t>(remaining.count(), 1, 120000);
        if (should_stop) {
            timeout_ms = std::min<std::int64_t>(timeout_ms, 10);
        }
        pollfd descriptor{fd, events, 0};
        const int result = ::poll(
            &descriptor, 1, static_cast<int>(timeout_ms));
        if (result > 0) {
            if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 &&
                (descriptor.revents & events) == 0) {
                throw std::runtime_error("Chrome TLS helper IPC closed early");
            }
            if ((descriptor.revents & events) != 0) {
                return;
            }
        } else if (result == 0) {
            ThrowIfStopped(should_stop);
            if (std::chrono::steady_clock::now() >= deadline) {
                throw std::runtime_error("Chrome TLS helper IPC timed out");
            }
        } else if (errno != EINTR) {
            throw std::system_error(errno, std::generic_category(),
                                    "poll Chrome TLS helper IPC");
        }
    }
}

void WriteAll(int fd, std::span<const std::uint8_t> bytes,
              std::chrono::steady_clock::time_point deadline,
              const std::function<bool()>& should_stop) {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        WaitFd(fd, POLLOUT, deadline, should_stop);
        const ssize_t written = ::write(fd, bytes.data() + offset,
                                        bytes.size() - offset);
        if (written > 0) {
            offset += static_cast<std::size_t>(written);
        } else if (written == 0) {
            throw std::runtime_error("Chrome TLS helper IPC write returned zero");
        } else if (errno != EINTR && errno != EAGAIN) {
            throw std::system_error(errno, std::generic_category(),
                                    "write Chrome TLS helper IPC");
        }
    }
}

void ReadExact(int fd, std::span<std::uint8_t> bytes,
               std::chrono::steady_clock::time_point deadline,
               const std::function<bool()>& should_stop) {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        WaitFd(fd, POLLIN, deadline, should_stop);
        const ssize_t received = ::read(fd, bytes.data() + offset,
                                        bytes.size() - offset);
        if (received > 0) {
            offset += static_cast<std::size_t>(received);
        } else if (received == 0) {
            throw std::runtime_error("Chrome TLS helper IPC closed early");
        } else if (errno != EINTR && errno != EAGAIN) {
            throw std::system_error(errno, std::generic_category(),
                                    "read Chrome TLS helper IPC");
        }
    }
}

std::vector<std::uint8_t> ReadResponse(
        int fd, std::chrono::steady_clock::time_point deadline,
        const std::function<bool()>& should_stop) {
    constexpr std::size_t kHeaderBytes = 32;
    std::vector<std::uint8_t> wire(kHeaderBytes);
    ReadExact(fd, wire, deadline, should_stop);
    const std::uint32_t payload_size =
        (static_cast<std::uint32_t>(wire[12]) << 24U) |
        (static_cast<std::uint32_t>(wire[13]) << 16U) |
        (static_cast<std::uint32_t>(wire[14]) << 8U) |
        static_cast<std::uint32_t>(wire[15]);
    if (payload_size > chrome_tls::kMaxPayloadBytes) {
        throw std::runtime_error("Chrome TLS helper IPC payload exceeds cap");
    }
    wire.resize(kHeaderBytes + payload_size);
    ReadExact(fd, std::span<std::uint8_t>(wire).subspan(kHeaderBytes), deadline,
              should_stop);
    return wire;
}

chrome_tls::ConnectionId RandomConnectionId() {
#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
    auto random = basefwx::crypto::RandomBytes(chrome_tls::kConnectionIdBytes);
#else
    auto random = crypto::random_bytes(chrome_tls::kConnectionIdBytes);
#endif
    ScopedVectorWiper random_wiper(random);
    chrome_tls::ConnectionId connection_id{};
    std::copy(random.begin(), random.end(), connection_id.begin());
    return connection_id;
}

#endif

}  // namespace

std::filesystem::path DiscoverChromeTlsHelper(
        const std::filesystem::path& client_executable) {
    if (client_executable.empty()) {
        throw std::runtime_error("cannot resolve empty yume executable path for TLS helper");
    }
    std::error_code error;
    const auto absolute = std::filesystem::absolute(client_executable, error);
    if (error || absolute.empty()) {
        throw std::runtime_error("cannot resolve yume executable path for TLS helper");
    }
    return absolute.parent_path() / "yume-chrome-tls-helper";
}

ClientTransportStream LaunchChromeTlsHelper(
        boost::asio::io_context& io,
        boost::asio::ip::tcp::socket&& connected_socket,
        const ChromeTlsHelperOptions& options) {
#if !defined(__linux__)
    (void)io;
    (void)connected_socket;
    (void)options;
    throw std::runtime_error("Chrome TLS helper supports Linux desktop only");
#else
    ValidateHelperFile(options.helper_path);
    ThrowIfStopped(options.should_stop);
    if (options.handshake_timeout.count() < 1000 ||
        options.handshake_timeout.count() > 120000) {
        throw std::runtime_error("Chrome TLS handshake timeout is out of range");
    }

    int pair[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) != 0) {
        throw std::system_error(errno, std::generic_category(),
                                "create Chrome TLS helper socketpair");
    }
    ScopedFd parent_ipc(pair[0]);
    ScopedFd child_ipc(pair[1]);
    ConfigureSocketpairBuffers({parent_ipc.Get(), child_ipc.Get()});
    ScopedFd connected_dup(::fcntl(
        connected_socket.native_handle(), F_DUPFD_CLOEXEC, 64));
    if (connected_dup.Get() < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "duplicate connected TLS descriptor");
    }
    ScopedFd ipc_dup(::fcntl(child_ipc.Get(), F_DUPFD_CLOEXEC, 64));
    if (ipc_dup.Get() < 0) {
        throw std::system_error(errno, std::generic_category(),
                                "duplicate helper IPC descriptor");
    }

    SpawnActions actions;
    actions.Dup2(connected_dup.Get(), 3);
    actions.Dup2(ipc_dup.Get(), 4);
    actions.CloseFrom(5);

    std::string helper_path = options.helper_path.string();
    std::array<char*, 2> arguments{helper_path.data(), nullptr};
    pid_t pid = -1;
    const int spawn_error = ::posix_spawn(
        &pid, helper_path.c_str(), actions.Get(), nullptr,
        arguments.data(), environ);
    if (spawn_error != 0) {
        throw std::system_error(spawn_error, std::generic_category(),
                                "start Chrome TLS helper");
    }
    auto lifetime = std::make_shared<ChildLifetime>(pid);
    // posix_spawn has duplicated these descriptors to child fds 3 and 4.
    // Keeping the parent's copies alive would mask child exit: the IPC peer
    // would never reach EOF/HUP and the connected TCP socket would remain
    // artificially open until the full handshake timeout expired.
    connected_dup.Reset();
    ipc_dup.Reset();
    child_ipc.Reset();
    boost::system::error_code close_error;
    connected_socket.close(close_error);

    chrome_tls::Request request;
    request.connection_id = RandomConnectionId();
    request.expected_build_id = std::string(
        cover_profile::active().helper_build_id);
    request.server_name = options.server_name;
    request.ca_path = options.ca_path.string();
    request.leaf_pin = options.leaf_pin;
    request.timeout_ms = static_cast<std::uint32_t>(
        options.handshake_timeout.count());
    const std::vector<std::uint8_t> encoded =
        chrome_tls::EncodeRequest(request);
    const auto deadline = Deadline(options.handshake_timeout +
                                   std::chrono::seconds(3));
    WriteAll(parent_ipc.Get(), encoded, deadline, options.should_stop);
    auto response_wire = ReadResponse(
        parent_ipc.Get(), deadline, options.should_stop);
    ScopedVectorWiper response_wire_wiper(response_wire);
    chrome_tls::Response response = chrome_tls::DecodeResponse(
        response_wire, request.connection_id, request.expected_build_id);
    ScopedArrayWiper response_exporter_wiper(response.ready.exporter);
    if (response.kind == chrome_tls::ResponseKind::Error) {
        throw std::runtime_error(
            "Chrome TLS helper rejected connection (code " +
            std::to_string(response.error.code) + "): " +
            response.error.message);
    }

    TlsConnectionMetadata metadata;
    metadata.alpn = response.ready.alpn;
    metadata.leaf_fingerprint_sha256 = Hex(
        response.ready.leaf_fingerprint);
    metadata.exporter.assign(response.ready.exporter.begin(),
                             response.ready.exporter.end());
    boost::asio::local::stream_protocol::socket socket(io);
    socket.assign(boost::asio::local::stream_protocol(), parent_ipc.Release());
    return ClientTransportStream(
        std::move(socket), std::move(metadata), std::move(lifetime));
#endif
}

}  // namespace yume::client
