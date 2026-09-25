/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <functional>
#include <memory>
#include <string_view>

#include <sys/types.h>

#include "config/v1/config.hpp"
#include "engine/stream_handler.hpp"
#include "providers/asio_execution_context.hpp"

namespace yume::runtime {

// The first line of every connection a module accepts, before the stream's
// bytes: "yume-module 1 <identity> <service>\n", where identity is the
// authenticated client's composite fingerprint. It is trustworthy only because
// the module's socket is private to the daemon's user.
inline constexpr std::string_view kModuleHeaderPrefix = "yume-module 1 ";

struct ModuleSupervisorOptions final {
    // Runs a module as kModuleLauncherArgv0: this executable or
    // yume-module-launcher. Required.
    std::filesystem::path launcher;
    std::chrono::milliseconds restart_initial{1'000};
    std::chrono::milliseconds restart_max{30'000};
    // A module that stays up this long restarts from restart_initial.
    std::chrono::milliseconds stable_after{30'000};
    // Close sends SIGTERM, then SIGKILL after this long.
    std::chrono::milliseconds stop_grace{5'000};
    // Bounds connecting one stream to the module and writing its header.
    std::chrono::milliseconds connect_timeout{10'000};
    // Connections the module may hold at once.
    std::size_t max_streams{1024U};
};

// Operator messages about module starts, exits and restarts. Runs on the
// context and must not throw.
using ModuleReport = std::function<void(std::string_view)>;

// Runs one module program for one stream service and hands it the service's
// authorized streams.
//
// start() creates a private directory (mode 0700) holding a listening UNIX
// socket, then runs the program through the launcher, which drops every
// privilege first. The module receives the listening socket as descriptor 3.
// Each OPEN of the service becomes one connection on it: the handler writes
// the header line, accepts the OPEN and joins the connection and the stream
// with the shared route bridge. An OPEN with a destination, or one made while
// the module is down, is refused.
//
// When the module exits, its streams end with its connections, and it is
// started again after a delay that doubles from restart_initial up to
// restart_max. A module that ran for stable_after starts again after
// restart_initial. close() sends SIGTERM, then SIGKILL after stop_grace, and
// removes the socket and its directory once the module has exited. The
// module runs as the daemon's user, so configure only trusted programs.
//
// Creation, start, close and every callback run on the supplied
// single-runner context. The caller closes the supervisor, calls finish()
// and drains.
class ModuleSupervisor final {
public:
    static engine::Result<std::shared_ptr<ModuleSupervisor>> create(
        std::shared_ptr<providers::AsioExecutionContext> context,
        const config::v1::ModuleAdapter& adapter,
        ModuleSupervisorOptions options,
        ModuleReport report = {});

    ModuleSupervisor(const ModuleSupervisor&) = delete;
    ModuleSupervisor& operator=(const ModuleSupervisor&) = delete;
    ~ModuleSupervisor() noexcept;

    engine::Status start();
    // The stream handler to bind to the module's service.
    std::shared_ptr<engine::StreamHandler> handler() const noexcept;
    // The running module's process ID, or -1 while it is down.
    pid_t pid() const noexcept;
    // The private directory holding the module's socket. Empty before start().
    const std::filesystem::path& socket_directory() const noexcept;
    void close() noexcept;

    struct State;

private:
    explicit ModuleSupervisor(std::shared_ptr<State> state) noexcept;
    std::shared_ptr<State> state_;
};

}  // namespace yume::runtime
