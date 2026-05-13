/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>

#include <nlohmann/json.hpp>

#include "client/cli.hpp"

namespace yume::client {

class RuntimeController {
public:
    struct StartOptions {
        std::filesystem::path executable_path;
        std::filesystem::path config_path;
        bool accept_monitoring{true};
    };

    struct Status {
        bool running{false};
        bool attached{false};
        bool ipc_available{false};
        int process_id{0};
        int exit_code{-1};
        std::string socket_path;
        std::string message;
        std::chrono::system_clock::time_point started{};
        std::chrono::system_clock::time_point stopped{};
    };

    using LogCallback = std::function<void(std::string const&)>;

    RuntimeController();
    ~RuntimeController();

    RuntimeController(RuntimeController const&) = delete;
    RuntimeController& operator=(RuntimeController const&) = delete;

    void set_log_callback(LogCallback cb);

    bool start(ClientConfig cfg, StartOptions opts, std::string* error = nullptr);
    bool stop(std::string* error = nullptr);

    bool running() const;
    Status status() const;

    nlohmann::json request(std::string const& op,
                           nlohmann::json const& args,
                           std::string* error = nullptr,
                           int timeout_ms = 5000) const;

    static std::string instance_key(ClientConfig const& cfg,
                                    std::filesystem::path const& config_path);
    static std::filesystem::path find_default_executable();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace yume::client
