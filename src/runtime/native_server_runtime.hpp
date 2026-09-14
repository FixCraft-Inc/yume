/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <filesystem>
#include <functional>
#include <memory>
#include <vector>

#include <boost/asio/ip/tcp.hpp>

#include "config/v1/config.hpp"
#include "engine/status.hpp"
#include "providers/asio_execution_context.hpp"

namespace yume::runtime {

// Runs one schema-1 server configuration as a standalone daemon. Every
// configured service needs a direct_tcp or direct_udp adapter, because a
// named service needs an application handler that only an embedder supplies.
// Destinations are enforced by NativeEgressPolicy for the request and for
// every resolved address. The endpoint's accept loop serves every listener.
//
// All calls run on the supplied single-runner context. on_stopped runs once if
// the endpoint stops accepting. The caller closes the runtime, calls finish()
// and drains.
class NativeServerRuntime final {
public:
    using Stopped = std::function<void(engine::Status)>;

    static engine::Result<std::shared_ptr<NativeServerRuntime>> create(
        std::shared_ptr<providers::AsioExecutionContext> context,
        const config::v1::Config& config,
        const std::filesystem::path& config_base_directory,
        Stopped on_stopped);

    NativeServerRuntime(const NativeServerRuntime&) = delete;
    NativeServerRuntime& operator=(const NativeServerRuntime&) = delete;
    ~NativeServerRuntime() noexcept;

    engine::Status start();
    std::vector<boost::asio::ip::tcp::endpoint> listener_endpoints() const;
    void close() noexcept;

private:
    struct State;
    explicit NativeServerRuntime(std::shared_ptr<State> state) noexcept;
    std::shared_ptr<State> state_;
};

}  // namespace yume::runtime
