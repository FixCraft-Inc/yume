#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

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

    bool start(ServerConfig cfg, std::string* error = nullptr);
    bool stop();
    bool running() const;

    Status status() const;
    std::vector<SessionSnapshot> sessions() const;
    ServerConfig config() const;

    static std::string instance_key_for(ServerConfig const& cfg,
                                        std::string const& config_path = {});
    static std::string local_runtime_path_for(ServerConfig const& cfg,
                                              std::string const& config_path = {});

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace yume::server
