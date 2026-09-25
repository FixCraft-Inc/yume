/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <filesystem>
#include <functional>
#include <memory>
#include <string_view>
#include <vector>

#include <boost/asio/ip/tcp.hpp>

#include "config/v1/config.hpp"
#include "engine/status.hpp"
#include "providers/asio_execution_context.hpp"

namespace yume::runtime {

struct NativeServerRuntimeOptions final {
    // The SystemResolver helper for destination names of direct adapters.
    // Empty refuses those names, while numeric destinations still work.
    std::filesystem::path resolver_program;
    // Launches configured modules, run as yume-module. Required with a module
    // adapter.
    std::filesystem::path module_launcher;
    // Module starts, exits and restarts, for the operator. Runs on the
    // context and must not throw.
    std::function<void(std::string_view)> report;
};

// Runs one schema-1 server configuration as a standalone daemon. Every
// configured service needs a direct_tcp, direct_udp, module or managed packet
// adapter. Other named services need application handlers from an embedder.
// Each module adapter runs its program under a ModuleSupervisor, which starts
// before the listeners accept and stops with the runtime.
// Destinations are enforced by NativeEgressPolicy for the request and for
// every resolved address. Each packet adapter admits one authenticated stream
// across all sessions and enforces local/peer address policy in both directions.
// The endpoint's accept loop serves every listener.
//
// All calls run on the supplied single-runner context. on_stopped runs once if
// the endpoint stops accepting or managed network cleanup fails. The caller
// closes the runtime, calls finish() and drains managed packet I/O/networking.
class NativeServerRuntime final {
public:
    using Stopped = std::function<void(engine::Status)>;

    static engine::Result<std::shared_ptr<NativeServerRuntime>> create(
        std::shared_ptr<providers::AsioExecutionContext> context,
        const config::v1::Config& config,
        const std::filesystem::path& config_base_directory,
        Stopped on_stopped,
        NativeServerRuntimeOptions options = {});

    NativeServerRuntime(const NativeServerRuntime&) = delete;
    NativeServerRuntime& operator=(const NativeServerRuntime&) = delete;
    ~NativeServerRuntime() noexcept;

    engine::Status start();
    std::vector<boost::asio::ip::tcp::endpoint> listener_endpoints() const;
    // Applies changed credential stores without dropping other sessions. See
    // NativeEndpoint::reload_credentials.
    engine::Status reload();
    void close() noexcept;

private:
    struct State;
    explicit NativeServerRuntime(std::shared_ptr<State> state) noexcept;
    std::shared_ptr<State> state_;
};

}  // namespace yume::runtime
