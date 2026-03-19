#include "client/local_runtime.hpp"

namespace yume::client {

LocalRuntime::LocalRuntime(std::string path, std::shared_ptr<RelayRuntime> relay_runtime)
    : relay_runtime_(std::move(relay_runtime))
    , server_(std::move(path), [this](const nlohmann::json& request) {
        if (!relay_runtime_) {
            return nlohmann::json{{"ok", false}, {"error", "relay runtime unavailable"}};
        }
        return relay_runtime_->handle_local_request(request);
    }) {}

bool LocalRuntime::start(std::string* error) {
    return server_.start(error);
}

void LocalRuntime::stop() {
    server_.stop();
}

bool LocalRuntime::running() const {
    return server_.running();
}

const std::string& LocalRuntime::path() const {
    return server_.path();
}

std::string LocalRuntime::socket_path_for(const std::string& instance_key) {
    return yume::local_runtime::socket_path("client", instance_key);
}

bool LocalRuntime::available(const std::string& path) {
    return yume::local_runtime::Server::endpoint_available(path);
}

nlohmann::json LocalRuntime::request(const std::string& path,
                                     const nlohmann::json& request,
                                     std::string* error,
                                     int timeout_ms) {
    return yume::local_runtime::Server::request(path, request, error, timeout_ms);
}

}  // namespace yume::client
