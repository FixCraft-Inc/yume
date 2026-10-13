/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <memory>
#include <string_view>

#include "config/v1/config.hpp"
#include "engine/stream_handler.hpp"
#include "providers/asio_execution_context.hpp"

namespace yume::runtime {

// The first line of every connection a module accepts, before the stream's
// bytes: "yume-module 1 <identity> <service>\n", where identity is the
// authenticated client's composite fingerprint. It is trustworthy only because
// no user but the daemon's and root can connect to the module's socket.
inline constexpr std::string_view kModuleHeaderPrefix = "yume-module 1 ";

// Checks that `socket` is a UNIX socket that only this user and root can
// connect to or replace: it belongs to this user with no group or other
// permission, in a real directory owned by root or this user that no one
// else can write. Without that, another user could read the streams or forge
// the header. FailedPrecondition when the socket is missing or not a socket,
// PermissionDenied when it or its directory is unsafe.
engine::Status check_module_socket(const std::filesystem::path& socket) noexcept;

struct ModuleConnectorOptions final {
    // Bounds connecting one stream to the module and writing its header.
    std::chrono::milliseconds connect_timeout{10'000};
    // Connections the module may hold at once.
    std::size_t max_streams{1024U};
};

// Hands one stream service's authorized streams to a module that a service
// manager runs, such as systemd with a socket unit, and that listens on the
// configured UNIX socket.
//
// create() checks the socket with check_module_socket. Each OPEN of the
// service then becomes one connection to it: the handler connects, refuses a
// listener that neither root nor this user created, writes the header line,
// accepts the OPEN and joins the connection and the stream with the shared
// route bridge. An OPEN with a destination is refused, and so is one whose
// connection fails, as when the socket is gone. The module's
// process, user, sandbox and restarts belong to the service manager, so the
// daemon never runs module code or shares its credentials with it.
//
// Creation, close and every callback run on the supplied single-runner
// context. The caller closes the connector, calls finish() and drains.
class ModuleConnector final {
public:
    static engine::Result<std::shared_ptr<ModuleConnector>> create(
        std::shared_ptr<providers::AsioExecutionContext> context,
        const config::v1::ModuleAdapter& adapter,
        ModuleConnectorOptions options = {});

    ModuleConnector(const ModuleConnector&) = delete;
    ModuleConnector& operator=(const ModuleConnector&) = delete;
    ~ModuleConnector() noexcept;

    // The stream handler to bind to the module's service.
    std::shared_ptr<engine::StreamHandler> handler() const noexcept;
    // The handler for sessions on `context`, one of `contexts` a server
    // serves on. It connects each stream to the module's socket and bridges
    // it on `context`, with that context's share of max_streams. A server
    // that serves on several contexts binds one per context, the
    // connector's included, so the shares add up to max_streams. Call on
    // `context`.
    engine::Result<std::shared_ptr<engine::StreamHandler>> handler_for(
        std::shared_ptr<providers::AsioExecutionContext> context,
        std::size_t contexts) const;
    // Refuses further OPENs and ends the streams this connector's own
    // context bridges.
    void close() noexcept;

    struct State;

private:
    explicit ModuleConnector(std::shared_ptr<State> state) noexcept;
    std::shared_ptr<State> state_;
};

}  // namespace yume::runtime
