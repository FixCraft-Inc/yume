/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/commands/proxy.hpp"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#if !defined(_WIN32)
#include <sys/select.h>
#include <unistd.h>
#endif

#include <boost/asio.hpp>

#include "util.hpp"

namespace yume::client {

namespace {

struct EnvGuard {
    struct Entry {
        std::string key;
        std::string value;
        bool had;
    };
    std::vector<Entry> prev;
    ~EnvGuard() {
#if defined(_WIN32)
        for (const auto& e : prev) {
            if (e.had) {
                _putenv_s(e.key.c_str(), e.value.c_str());
            } else {
                _putenv_s(e.key.c_str(), "");
            }
        }
#else
        for (const auto& e : prev) {
            if (e.had) {
                setenv(e.key.c_str(), e.value.c_str(), 1);
            } else {
                unsetenv(e.key.c_str());
            }
        }
#endif
    }
};

void set_env(EnvGuard& guard, const std::string& key, const std::string& value) {
    const char* old = std::getenv(key.c_str());
    if (old) {
        guard.prev.push_back({key, old, true});
    } else {
        guard.prev.push_back({key, "", false});
    }
#if defined(_WIN32)
    _putenv_s(key.c_str(), value.c_str());
#else
    setenv(key.c_str(), value.c_str(), 1);
#endif
}

}  // namespace

int run_local_command_with_proxy(const std::string& cmd, int socks_port, bool ipv4_only) {
    std::string proxy = "socks5h://127.0.0.1:" + std::to_string(socks_port);
    EnvGuard guard;
    set_env(guard, "ALL_PROXY", proxy);
    set_env(guard, "HTTPS_PROXY", proxy);
    set_env(guard, "HTTP_PROXY", proxy);
    set_env(guard, "all_proxy", proxy);
    set_env(guard, "https_proxy", proxy);
    set_env(guard, "http_proxy", proxy);
    if (ipv4_only) {
        set_env(guard, "CURL_IPRESOLVE", "4");
    }
    return std::system(cmd.c_str());
}

std::string maybe_force_ipv4(const std::string& cmd, bool ipv4_only) {
    if (!ipv4_only) {
        return cmd;
    }
    auto starts_with_curl = [](const std::string& s) {
        return s.rfind("curl ", 0) == 0 || s.rfind("curl\t", 0) == 0 || s == "curl";
    };
    if (!starts_with_curl(cmd)) {
        return cmd;
    }
    bool has_v4 = cmd.find(" -4") != std::string::npos || cmd.find("--ipv4") != std::string::npos;
    bool has_http1 = cmd.find("--http1.1") != std::string::npos;
    std::string out = "curl ";
    if (!has_http1) {
        out += "--http1.1 ";
    }
    if (!has_v4) {
        out += "-4 ";
    }
    if (cmd == "curl") {
        return out;
    }
    return out + cmd.substr(5);
}

int run_proxycmd(const std::string& dest_host, int dest_port, int socks_port) {
#if defined(_WIN32)
    (void)dest_host;
    (void)dest_port;
    (void)socks_port;
    util::log_error("proxycmd is not supported on Windows yet");
    return 1;
#else
    if (dest_host.empty() || dest_port <= 0) {
        util::log_error("proxycmd missing destination");
        return 1;
    }
    boost::asio::io_context io;
    boost::asio::ip::tcp::resolver resolver(io);
    boost::asio::ip::tcp::socket sock(io);
    auto endpoints = resolver.resolve("127.0.0.1", std::to_string(socks_port));
    boost::asio::connect(sock, endpoints);

    std::array<uint8_t, 3> hello{{0x05, 0x01, 0x00}};
    boost::asio::write(sock, boost::asio::buffer(hello));
    std::array<uint8_t, 2> reply{};
    boost::asio::read(sock, boost::asio::buffer(reply));
    if (reply[0] != 0x05 || reply[1] != 0x00) {
        util::log_error("SOCKS5 auth failed");
        return 1;
    }

    if (dest_host.size() > 255) {
        util::log_error("SOCKS5 destination too long");
        return 1;
    }
    const size_t host_len = dest_host.size();
    std::vector<uint8_t> req(7 + host_len);
    size_t off = 0;
    req[off++] = 0x05;
    req[off++] = 0x01;
    req[off++] = 0x00;
    req[off++] = 0x03;
    req[off++] = static_cast<uint8_t>(host_len);
    if (host_len > 0) {
        std::memcpy(req.data() + off, dest_host.data(), host_len);
        off += host_len;
    }
    req[off++] = static_cast<uint8_t>((dest_port >> 8) & 0xFF);
    req[off++] = static_cast<uint8_t>(dest_port & 0xFF);
    boost::asio::write(sock, boost::asio::buffer(req));

    std::array<uint8_t, 4> rep{};
    boost::asio::read(sock, boost::asio::buffer(rep));
    if (rep[1] != 0x00) {
        util::log_error("SOCKS5 connect failed");
        return 1;
    }
    size_t to_read = 0;
    if (rep[3] == 0x01) to_read = 4;
    else if (rep[3] == 0x03) {
        uint8_t len = 0;
        boost::asio::read(sock, boost::asio::buffer(&len, 1));
        to_read = len;
    } else if (rep[3] == 0x04) to_read = 16;
    if (to_read > 0) {
        std::vector<uint8_t> discard(to_read);
        boost::asio::read(sock, boost::asio::buffer(discard));
    }
    std::array<uint8_t, 2> discard_port{};
    boost::asio::read(sock, boost::asio::buffer(discard_port));

    int sock_fd = sock.native_handle();
    bool stdin_open = true;
    while (true) {
        fd_set rfds;
        FD_ZERO(&rfds);
        if (stdin_open) {
            FD_SET(STDIN_FILENO, &rfds);
        }
        FD_SET(sock_fd, &rfds);
        int maxfd = sock_fd > STDIN_FILENO ? sock_fd : STDIN_FILENO;
        int rc = select(maxfd + 1, &rfds, nullptr, nullptr, nullptr);
        if (rc <= 0) {
            break;
        }
        if (stdin_open && FD_ISSET(STDIN_FILENO, &rfds)) {
            char buf[4096];
            ssize_t n = ::read(STDIN_FILENO, buf, sizeof(buf));
            if (n <= 0) {
                stdin_open = false;
                boost::system::error_code ec;
                sock.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
            } else {
                boost::asio::write(sock, boost::asio::buffer(buf, static_cast<size_t>(n)));
            }
        }
        if (FD_ISSET(sock_fd, &rfds)) {
            char buf[4096];
            boost::system::error_code ec;
            size_t n = sock.read_some(boost::asio::buffer(buf), ec);
            if (ec || n == 0) {
                break;
            }
            ssize_t w = ::write(STDOUT_FILENO, buf, n);
            (void)w;
        }
    }
    return 0;
#endif
}

std::string wrap_ssh_with_proxy(const std::string& cmd, int socks_port, const std::string& self_path) {
#if defined(_WIN32)
    (void)socks_port;
    (void)self_path;
    return cmd;
#else
    auto starts_with_ssh = [](const std::string& s) {
        return s.rfind("ssh ", 0) == 0 || s.rfind("ssh\t", 0) == 0 || s == "ssh";
    };
    if (!starts_with_ssh(cmd)) {
        return cmd;
    }
    if (cmd.find("ProxyCommand") != std::string::npos) {
        return cmd;
    }
    std::string helper = self_path.empty() ? "yume" : self_path;
    std::string out = "ssh -o ProxyCommand=\"" + helper + " --proxycmd --socks " +
                      std::to_string(socks_port) + " --dest %h --dport %p\"";
    if (cmd == "ssh") {
        return out;
    }
    return out + " " + cmd.substr(4);
#endif
}

}  // namespace yume::client
