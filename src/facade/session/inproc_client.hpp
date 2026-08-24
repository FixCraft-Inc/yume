/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * In-process client runtime. Hosts a yume::client::Cli instance on a
 * dedicated worker thread, captures the Tunnel + RelayRuntime it
 * builds, and exposes a request() API that delegates to
 * RelayRuntime::handle_local_request without going through a local
 * IPC socket. This is what facade::ClientSession uses so yume-gui
 * doesn't need a separate yume process at runtime - the same code
 * that the CLI runs is linked into the GUI and driven from a thread.
 */

#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "client/cli/entry.hpp"
#include "core/runtime/operation_status.hpp"
#include "client/transport/runtime_lifetime.hpp"

namespace yume::client {
class Tunnel;
class RelayRuntime;
}

namespace yume::facade {

class InProcClient {
public:
    InProcClient();
    ~InProcClient();

    InProcClient(InProcClient const&) = delete;
    InProcClient& operator=(InProcClient const&) = delete;

    struct Status {
        // True while the Cli worker thread is running, regardless of
        // whether the tunnel is fully up.
        bool running{false};
        // True once the tunnel is authenticated and a RelayRuntime
        // has been constructed - safe to start issuing requests.
        bool ipc_available{false};
        std::string message;
        std::string socket_path;  // empty in-process; kept for API parity
        // Exit code from Cli::run if it has already returned. Zero
        // means the disconnect was clean (tunnel closed gracefully);
        // non-zero is a hard failure. Kept around so the status
        // surface in ClientSession can distinguish Disconnected vs
        // Failed without bookkeeping its own flag.
        int exit_code{0};
        std::string server_tls_fingerprint_sha256;
        std::vector<std::string> server_capabilities;
        std::chrono::system_clock::time_point started{};
    };

    // Boot a Cli worker against the given config. Returns true once the
    // tunnel is fully up (we block here until that happens or the
    // worker thread exits with an error). `*error` is filled when we
    // return false. Subsequent start() calls fail while a generation is
    // starting, running, or stopping. An optional admission token lets a C ABI
    // caller cancel work performed before this method is entered without a
    // stop/start handoff race.
    bool start(client::ClientConfig cfg, std::string* error = nullptr,
               std::chrono::milliseconds wait = std::chrono::seconds{30},
               runtime::OperationStatus* operation_status = nullptr,
               std::shared_ptr<std::atomic<bool>> admission_cancel = nullptr);

    // Tear down: close the tunnel, which trips Cli's io.stop(), which
    // returns from Cli::run(), which lets the worker thread join.
    // Idempotent. Pass an optional reason for logging.
    void stop(std::string* error = nullptr,
              std::string const& reason = "client stopping");

    // Non-blocking half of stop(). It marks every pre-ready I/O phase for
    // cancellation and asks an active tunnel to close, but leaves joining to
    // stop() or the destructor. GUI facades use this on their caller thread.
    void request_stop(std::string const& reason = "client stopping") noexcept;

    bool running() const noexcept;
    Status status() const;

    class RuntimeAccess {
    public:
        RuntimeAccess(RuntimeAccess&&) noexcept = default;
        RuntimeAccess& operator=(RuntimeAccess&&) noexcept = delete;
        RuntimeAccess(const RuntimeAccess&) = delete;
        RuntimeAccess& operator=(const RuntimeAccess&) = delete;

        // The returned objects are executor-bound and are valid only while
        // this RuntimeAccess (and therefore its lifetime lease) remains alive.
        // Long-lived handles must retain gate() and acquire a fresh lease for
        // every operation instead of retaining the Tunnel shared_ptr.
        const std::shared_ptr<client::Tunnel>& tunnel() const noexcept {
            return tunnel_;
        }
        const std::shared_ptr<client::RuntimeLifetimeGate>& gate() const noexcept {
            return gate_;
        }
        const std::vector<std::string>& server_capabilities() const noexcept {
            return server_capabilities_;
        }

    private:
        friend class InProcClient;
        RuntimeAccess(
            client::RuntimeLifetimeGate::Lease lease,
            std::shared_ptr<client::RuntimeLifetimeGate> gate,
            std::shared_ptr<client::Tunnel> tunnel,
            std::shared_ptr<client::RelayRuntime> relay,
            std::vector<std::string> server_capabilities)
            : lease_(std::move(lease))
            , gate_(std::move(gate))
            , tunnel_(std::move(tunnel))
            , relay_(std::move(relay))
            , server_capabilities_(std::move(server_capabilities)) {}

        // Executor-bound shared_ptrs are declared after the lease so reverse
        // destruction releases them before teardown observes quiescence.
        client::RuntimeLifetimeGate::Lease lease_;
        std::shared_ptr<client::RuntimeLifetimeGate> gate_;
        std::shared_ptr<client::Tunnel> tunnel_;
        std::shared_ptr<client::RelayRuntime> relay_;
        std::vector<std::string> server_capabilities_;
    };

    std::optional<RuntimeAccess> acquire_runtime() const;

    // Mirror of LocalRuntime::Server::request() so existing call sites
    // in facade/session/client_session.cpp don't need to change shape. We post
    // the request onto the tunnel's executor (the same thread Cli's
    // io_context drives) so that RelayRuntime sees the call from its
    // own thread and avoids the locking surface a cross-thread call
    // would expose. Synchronous from the caller's view: we wait for
    // the posted work with the given timeout.
    nlohmann::json request(std::string const& op,
                           nlohmann::json const& args,
                           std::string* error = nullptr,
                           int timeout_ms = 5000,
                           runtime::OperationStatus* operation_status = nullptr);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace yume::facade
