/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "facade/model/status.hpp"
#include "server/config/config.hpp"

namespace yume::facade {

class TrafficMeter;

// Wraps server::RuntimeController for embedder hosts. Mirrors ClientSession in
// shape: start()/stop() are non-blocking on the caller, while destruction joins
// every owned worker and runtime thread.
class ServerSession {
public:
    explicit ServerSession(server::ServerConfig cfg);
    ~ServerSession();

    ServerSession(ServerSession const&) = delete;
    ServerSession& operator=(ServerSession const&) = delete;

    bool start(std::string* err = nullptr);
    void stop();

    bool running() const noexcept;

    // True while any lifecycle work is in flight, so start() would be
    // refused. See ClientSession::busy(): stop() returns before teardown
    // finishes, so running() alone cannot tell a consumer when a restart
    // will be accepted.
    bool busy() const noexcept;

    ServerStatus status() const;
    TrafficMeter const& traffic() const noexcept;

    void set_config(server::ServerConfig cfg);
    server::ServerConfig config() const;

    struct ConnectedSession {
        std::string endpoint_id;
        std::string display_name;
        std::string state;
        std::string client_platform;
        std::string client_version;
        bool authenticated{false};
    };
    std::vector<ConnectedSession> list_sessions() const;

    using StatusCallback = std::function<void(ServerStatus const&)>;
    // Callbacks are serialized outside lifecycle locks, may re-enter
    // start()/stop(), and cannot unwind through the facade.
    void set_status_callback(StatusCallback cb);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace yume::facade
