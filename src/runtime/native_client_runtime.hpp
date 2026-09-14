/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <string_view>
#include <vector>

#include <boost/asio/ip/tcp.hpp>

#include "config/v1/config.hpp"
#include "engine/status.hpp"
#include "providers/asio_execution_context.hpp"
#include "runtime/native_socks5.hpp"

namespace yume::runtime {

struct NativeClientRuntimeOptions final {
    // Dial, TLS, carrier and AUTH for one attempt.
    std::chrono::milliseconds start_timeout{30'000};
    std::chrono::milliseconds reconnect_initial{1'000};
    std::chrono::milliseconds reconnect_max{30'000};
    NativeSocks5Limits socks5;
};

// Runs one schema-1 client configuration: one authenticated session, replaced
// after it ends with exponential backoff, and the configured SOCKS5 listeners
// over it. Server-initiated OPENs are refused. Packet/TUN adapters are not
// implemented and fail creation.
//
// All calls run on the supplied single-runner context. The caller closes the
// runtime, calls finish() and drains. Reports carry no secrets.
class NativeClientRuntime final {
public:
    using Report = std::function<void(std::string_view)>;

    static engine::Result<std::shared_ptr<NativeClientRuntime>> create(
        std::shared_ptr<providers::AsioExecutionContext> context,
        const config::v1::Config& config,
        const std::filesystem::path& config_base_directory,
        Report report,
        NativeClientRuntimeOptions options = {});

    NativeClientRuntime(const NativeClientRuntime&) = delete;
    NativeClientRuntime& operator=(const NativeClientRuntime&) = delete;
    ~NativeClientRuntime() noexcept;

    // Opens the SOCKS5 listeners and makes the first session attempt.
    engine::Status start();
    std::vector<boost::asio::ip::tcp::endpoint> socks5_endpoints() const;
    void close() noexcept;

private:
    struct State;
    explicit NativeClientRuntime(std::shared_ptr<State> state) noexcept;
    std::shared_ptr<State> state_;
};

}  // namespace yume::runtime
