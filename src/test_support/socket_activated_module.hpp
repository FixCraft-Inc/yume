/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

// Stands in for a module's socket unit in tests: a listening UNIX socket of
// mode 0600 in a fresh 0700 directory below /tmp, and the module program
// running with it as descriptor 3, the way systemd passes it.

#include <cstdlib>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "providers/child_process.hpp"

namespace yume::test {

class SocketActivatedModule final {
public:
    SocketActivatedModule() {
        std::string pattern = "/tmp/yume-module-test-XXXXXX";
        if (::mkdtemp(pattern.data()) == nullptr) throw std::runtime_error("mkdtemp failed");
        directory = pattern;
        socket = directory / "module.sock";
        sockaddr_un address{};
        const std::string path = socket.string();
        if (path.size() >= sizeof(address.sun_path)) throw std::runtime_error("socket path too long");
        address.sun_family = AF_UNIX;
        path.copy(address.sun_path, path.size());
        listener = providers::Descriptor(::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
        if (listener.get() < 0 ||
            ::bind(listener.get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0 ||
            ::chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0 || ::listen(listener.get(), SOMAXCONN) != 0)
            throw std::runtime_error("the module socket could not open");
    }
    SocketActivatedModule(const SocketActivatedModule&) = delete;
    SocketActivatedModule& operator=(const SocketActivatedModule&) = delete;
    ~SocketActivatedModule() {
        process.kill_and_reap();
        listener.reset();
        std::error_code ignored;
        std::filesystem::remove_all(directory, ignored);
    }

    // Runs program with the socket as descriptor 3, as a service manager
    // does after a restart too: connections still queued reach the new run.
    void run(const std::filesystem::path& program, std::vector<std::string> arguments = {}) {
        arguments.insert(arguments.begin(), program.string());
        auto spawned = providers::ChildProcess::spawn(program, arguments, listener.get());
        if (!spawned.ok()) throw std::runtime_error("the module could not start");
        process = std::move(spawned).take_value();
    }

    std::filesystem::path directory;
    std::filesystem::path socket;
    providers::Descriptor listener;
    providers::ChildProcess process;
};

}  // namespace yume::test
