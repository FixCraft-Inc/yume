/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <functional>
#include <string>

#include "core/runtime/local_runtime.hpp"

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

    // Serves one operation directly, without the socket. Embedders reach the
    // same op surface as an admin-socket client through the stable C ABI, and
    // do so even when IPC is disabled.
    //
    // Synchronous, and safe to call from any thread. The caller must keep the
    // Manager this runtime was constructed with alive for the duration: the
    // reference here is non-owning, so the owner holds its Manager handle
    // across the call rather than relying on this object's lifetime alone.
    nlohmann::json handle_request(const nlohmann::json& request);

private:
    Manager* manager_{nullptr};
    std::function<void()> stop_callback_;
    yume::local_runtime::Server server_;
};

}  // namespace yume::server
