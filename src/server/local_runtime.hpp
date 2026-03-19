#pragma once

#include <functional>
#include <string>

#include "core/local_runtime.hpp"

namespace yume::server {

class Manager;

class LocalRuntime {
public:
    LocalRuntime(std::string path, Manager* manager, std::function<void()> stop_callback);

    bool start(std::string* error);
    void stop();
    bool running() const;
    const std::string& path() const;

    static std::string socket_path_for(const std::string& instance_key);
    static bool available(const std::string& path);
    static nlohmann::json request(const std::string& path,
                                  const nlohmann::json& request,
                                  std::string* error,
                                  int timeout_ms = 5000);

private:
    nlohmann::json handle_request(const nlohmann::json& request);

    Manager* manager_{nullptr};
    std::function<void()> stop_callback_;
    yume::local_runtime::Server server_;
};

}  // namespace yume::server
