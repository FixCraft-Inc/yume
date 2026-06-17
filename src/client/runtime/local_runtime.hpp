#pragma once

#include <memory>
#include <string>

#include "client/relay/runtime.hpp"
#include "core/runtime/local_runtime.hpp"

namespace yume::client {

class LocalRuntime {
public:
    LocalRuntime(std::string path, std::shared_ptr<RelayRuntime> relay_runtime);

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
    std::shared_ptr<RelayRuntime> relay_runtime_;
    yume::local_runtime::Server server_;
};

}  // namespace yume::client
