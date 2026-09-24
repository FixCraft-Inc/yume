/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <boost/asio/ip/tcp.hpp>

#include "config/v1/config.hpp"
#include "engine/session_engine.hpp"
#include "engine/status.hpp"
#include "providers/asio_execution_context.hpp"
#include "runtime/native_socks5.hpp"

namespace yume::runtime {

enum class NativeClientState : std::uint8_t {
    Idle,        // created, start() not called yet
    Connecting,  // one dial, TLS, carrier and AUTH attempt is in flight
    Connected,   // a session is authenticated
    Waiting,     // backing off before the next attempt
    Closed,      // closed explicitly or after an unrecoverable failure
};

// A point-in-time view for status displays. It holds no secret material.
struct NativeClientStatus final {
    NativeClientState state{NativeClientState::Idle};
    // The most recent failed attempt, ended session or terminal failure.
    // Success until one occurs.
    engine::Status last_failure;
    // Verified composite fingerprint of the server, set while Connected.
    std::string server_identity;
    // When the current session authenticated, set while Connected.
    std::chrono::steady_clock::time_point connected_since{};
    // Delay before the next attempt, set while Waiting.
    std::chrono::milliseconds retry_delay{0};
    // Sessions authenticated since start, and failed attempts since the most
    // recent authenticated session.
    std::uint64_t sessions{0U};
    std::uint32_t failed_attempts{0U};
    // Totals over every session of this runtime, including the current one.
    engine::SessionTraffic traffic;
};

struct NativeClientRuntimeOptions final {
    // Dial, TLS, carrier and AUTH for one attempt.
    std::chrono::milliseconds start_timeout{30'000};
    std::chrono::milliseconds reconnect_initial{1'000};
    // Also how long a session must stay up before its end resets the backoff
    // and reconnects at once. A shorter session counts as a failed attempt.
    std::chrono::milliseconds reconnect_max{30'000};
    NativeSocks5Limits socks5;
    // SystemResolver helper program for a transport host that is a name.
    // Empty leaves such a host unresolvable, so creation fails.
    std::filesystem::path resolver_program;
    // Runs on the context after each state change, with the new status.
    // Exceptions are contained. Traffic changes do not call it; poll status().
    std::function<void(const NativeClientStatus&)> on_status;
};

// Runs one schema-1 client configuration: one authenticated session, replaced
// when the endpoint reports closure, and the configured SOCKS5 and managed TUN
// adapters over it. Failed attempts and short sessions use exponential backoff.
// Server-initiated OPENs are refused. Each TUN opens one named packet stream;
// its addresses/routes/DNS remain installed during reconnects and are removed
// after packet I/O drains on final close. The transport dial address must be
// numeric so its route can be excluded before changing device networking.
//
// All calls run on the supplied single-runner context. The caller closes the
// runtime, calls finish() and drains. Reports carry no secrets. on_stopped runs
// once after an unrecoverable reconnect or SOCKS listener failure closes the
// runtime, or if managed network cleanup fails. Ordinary connection failures
// retry; a successful explicit close does not notify.
class NativeClientRuntime final {
public:
    using Report = std::function<void(std::string_view)>;
    using Stopped = std::function<void(engine::Status)>;

    static engine::Result<std::shared_ptr<NativeClientRuntime>> create(
        std::shared_ptr<providers::AsioExecutionContext> context,
        const config::v1::Config& config,
        const std::filesystem::path& config_base_directory,
        Report report,
        NativeClientRuntimeOptions options = {},
        Stopped on_stopped = {});

    NativeClientRuntime(const NativeClientRuntime&) = delete;
    NativeClientRuntime& operator=(const NativeClientRuntime&) = delete;
    ~NativeClientRuntime() noexcept;

    // Creates managed TUNs and SOCKS5 listeners, then starts the first session.
    engine::Status start();
    std::vector<boost::asio::ip::tcp::endpoint> socks5_endpoints() const;
    // Callable from any thread, including after close.
    NativeClientStatus status() const;
    void close() noexcept;

private:
    struct State;
    explicit NativeClientRuntime(std::shared_ptr<State> state) noexcept;
    std::shared_ptr<State> state_;
};

}  // namespace yume::runtime
