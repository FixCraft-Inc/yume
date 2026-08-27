/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <atomic>
#include <functional>
#include <string>
#include <thread>

#include <nlohmann/json.hpp>

namespace yume::local_runtime {

using RequestHandler = std::function<nlohmann::json(const nlohmann::json&)>;
using RequestCleanup = std::function<void(nlohmann::json&)>;

bool supported();
std::string runtime_dir();
std::string socket_path(const std::string& role, const std::string& instance_key);

class Server {
public:
    Server(std::string path, RequestHandler handler,
           RequestCleanup cleanup = {});
    ~Server();

    bool start(std::string* error);
    void stop();
    bool running() const;
    const std::string& path() const;

    static bool endpoint_available(const std::string& path);
    static nlohmann::json request(const std::string& path,
                                  const nlohmann::json& request,
                                  std::string* error,
                                  int timeout_ms = 5000);

private:
    void serve_loop();
    void cleanup_path();

    std::string path_;
    RequestHandler handler_;
    RequestCleanup cleanup_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopping_{false};
    int server_fd_{-1};
    std::thread thread_;
};

}  // namespace yume::local_runtime
