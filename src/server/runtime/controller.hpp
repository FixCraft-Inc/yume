/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "core/runtime/service_stream.hpp"
#include "core/runtime/operation_status.hpp"
#include "server/config/config.hpp"

namespace yume::server {

class RuntimeController {
public:
    struct SessionSnapshot {
        std::string endpoint_id;
        std::string display_name;
        std::string state;
        std::string client_platform;
        std::string client_version;
    };

    struct Status {
        bool running{false};
        std::string listen_endpoint;
        std::string ipc_path;
        std::string message;
        std::size_t active_sessions{0};
        std::chrono::system_clock::time_point started{};
    };

    RuntimeController();
    ~RuntimeController();

    RuntimeController(RuntimeController const&) = delete;
    RuntimeController& operator=(RuntimeController const&) = delete;

    // Synchronous lifecycle operations. Concurrent start/stop/reload calls are
    // serialized; facade::ServerSession moves them off embedder/UI threads.
    bool start(ServerConfig cfg,
               std::string* error = nullptr,
               runtime::OperationStatus* operation_status = nullptr);
    bool stop();
    bool running() const;
    bool reload_auth(
        std::string* error = nullptr,
        runtime::OperationStatus* operation_status = nullptr);

    Status status() const;
    std::vector<SessionSnapshot> sessions() const;
    ServerConfig config() const;

    // Serves one allowlisted, read-only local-runtime operation in process
    // without requiring IPC. The result keeps the local runtime's
    // {ok,result|error} envelope. Mutating admin-socket operations are not
    // exposed here because this synchronous embedder path has no deadline and
    // lifecycle operations already have typed methods above.
    nlohmann::json request(
        std::string const& op,
        nlohmann::json const& args,
        std::string* error = nullptr,
        runtime::OperationStatus* operation_status = nullptr) const;
    bool register_service(
        const std::string& service,
        std::string* error = nullptr,
        runtime::OperationStatus* operation_status = nullptr);
    std::shared_ptr<runtime::ServiceStream> accept_service_stream(
        const std::string& service,
        std::uint32_t timeout_ms,
        std::string* error = nullptr,
        runtime::OperationStatus* operation_status = nullptr);

    static std::string instance_key_for(ServerConfig const& cfg,
                                        std::string const& config_path = {});
    static std::string local_runtime_path_for(ServerConfig const& cfg,
                                              std::string const& config_path = {});

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace yume::server
