/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
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
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include <nlohmann/json.hpp>

#include "client/cli/entry.hpp"

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
        std::chrono::system_clock::time_point started{};
    };

    // Boot a Cli worker against the given config. Returns true once the
    // tunnel is fully up (we block here until that happens or the
    // worker thread exits with an error). `*error` is filled when we
    // return false. Subsequent start() calls are no-ops if already
    // running.
    bool start(client::ClientConfig cfg, std::string* error = nullptr,
               std::chrono::seconds wait = std::chrono::seconds{30});

    // Tear down: close the tunnel, which trips Cli's io.stop(), which
    // returns from Cli::run(), which lets the worker thread join.
    // Idempotent. Pass an optional reason for logging.
    void stop(std::string* error = nullptr,
              std::string const& reason = "client stopping");

    bool running() const noexcept;
    Status status() const;

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
                           int timeout_ms = 5000);

    // Subscribe to log lines emitted by the embedded Cli (useful so
    // the GUI's log viewer mirrors what the CLI would show). Lines
    // are pushed from worker threads; do not block in the callback.
    using LogCallback = std::function<void(std::string const&)>;
    void set_log_callback(LogCallback cb);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace yume::facade
