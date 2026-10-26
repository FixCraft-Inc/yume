/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// A minimal YUME module. A service manager runs it with a listening UNIX
// socket as descriptor 3, and the daemon connects once per stream of its
// service. Each
// connection starts with the line "yume-module 1 <identity> <service>". This
// module greets the client by identity, then echoes every byte back until
// the client closes its side.

#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <string>
#include <string_view>
#include <thread>

#include <sys/socket.h>
#include <unistd.h>

namespace {

constexpr int kListener = 3;
constexpr std::size_t kMaxHeaderBytes = 256;
constexpr int kMaxConnections = 64;
constexpr std::string_view kPrefix = "yume-module 1 ";

std::atomic<int> connections{0};

bool send_all(int socket, const char* data, std::size_t size) {
    while (size > 0U) {
        const ssize_t sent = ::send(socket, data, size, MSG_NOSIGNAL);
        if (sent < 0 && errno == EINTR) continue;
        if (sent <= 0) return false;
        data += sent;
        size -= static_cast<std::size_t>(sent);
    }
    return true;
}

// Reads the header one byte at a time, so no stream byte is taken with it.
bool read_header(int socket, std::string& identity) {
    std::string line;
    char byte = 0;
    while (line.size() < kMaxHeaderBytes) {
        const ssize_t read = ::recv(socket, &byte, 1, 0);
        if (read < 0 && errno == EINTR) continue;
        if (read != 1) return false;
        if (byte == '\n') break;
        line += byte;
    }
    if (line.compare(0, kPrefix.size(), kPrefix) != 0) return false;
    const auto end = line.find(' ', kPrefix.size());
    if (end == std::string::npos) return false;
    identity = line.substr(kPrefix.size(), end - kPrefix.size());
    return !identity.empty();
}

void echo(int socket) {
    std::string identity;
    if (!read_header(socket, identity)) return;
    const std::string greeting = "hello " + identity + "\n";
    char buffer[16384];
    bool open = send_all(socket, greeting.data(), greeting.size());
    while (open) {
        const ssize_t read = ::recv(socket, buffer, sizeof(buffer), 0);
        if (read < 0 && errno == EINTR) continue;
        open = read > 0 &&
               send_all(socket, buffer, static_cast<std::size_t>(read));
    }
    (void)::shutdown(socket, SHUT_WR);
}

// A thread entry must not throw, or the whole module ends. A failed
// allocation ends only this connection.
void serve(int socket) noexcept {
    try {
        echo(socket);
    } catch (...) {
    }
    ::close(socket);
    connections.fetch_sub(1);
}

}  // namespace

int main() {
    for (;;) {
        const int socket = ::accept4(kListener, nullptr, nullptr, SOCK_CLOEXEC);
        if (socket < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            return 1;
        }
        if (connections.fetch_add(1) >= kMaxConnections) {
            connections.fetch_sub(1);
            ::close(socket);
            continue;
        }
        // A process or pids limit can refuse a new thread. That refuses only
        // this connection, before the thread owns its socket.
        std::thread worker;
        try {
            worker = std::thread(serve, socket);
        } catch (...) {
            ::close(socket);
            connections.fetch_sub(1);
            continue;
        }
        // The process ends only when the daemon stops it, so connection
        // threads are never joined.
        worker.detach();
    }
}
