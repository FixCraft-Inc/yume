/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
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

// Wraps server::RuntimeController for GUI hosts. Mirrors ClientSession in
// shape: non-blocking, thread-safe, owns its io_context + worker pool.
class ServerSession {
public:
    explicit ServerSession(server::ServerConfig cfg);
    ~ServerSession();

    ServerSession(ServerSession const&) = delete;
    ServerSession& operator=(ServerSession const&) = delete;

    bool start(std::string* err = nullptr);
    void stop();

    bool running() const noexcept;
    ServerStatus status() const;
    TrafficMeter const& traffic() const noexcept;

    void set_config(server::ServerConfig cfg);
    server::ServerConfig config() const;

    struct ConnectedSession {
        std::string endpoint_id;
        std::string display_name;
        std::string peer_address;
        std::chrono::system_clock::time_point connected_since;
        std::uint64_t bytes_in{0};
        std::uint64_t bytes_out{0};
        bool authenticated{false};
    };
    std::vector<ConnectedSession> list_sessions() const;

    using StatusCallback = std::function<void(ServerStatus const&)>;
    void set_status_callback(StatusCallback cb);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace yume::facade
