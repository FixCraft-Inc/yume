/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <thread>

#include "client/cli/entry.hpp"
#include "client/cli/config/args.hpp"

namespace yume::client {

class RelayRuntime;
class Tunnel;

class InteractiveConsoleSession {
public:
    using StatusBuilder = std::function<std::string()>;
    using DisconnectCallback = std::function<void(const std::string&,
                                                  const std::string&,
                                                  bool)>;

    InteractiveConsoleSession() = default;
    InteractiveConsoleSession(std::shared_ptr<std::atomic<bool>> stop,
                              std::thread worker);
    InteractiveConsoleSession(const InteractiveConsoleSession&) = delete;
    InteractiveConsoleSession& operator=(const InteractiveConsoleSession&) = delete;
    InteractiveConsoleSession(InteractiveConsoleSession&& other) noexcept;
    InteractiveConsoleSession& operator=(InteractiveConsoleSession&& other) noexcept;
    ~InteractiveConsoleSession();

    explicit operator bool() const noexcept;
    void stop();

private:
    std::shared_ptr<std::atomic<bool>> stop_;
    std::thread worker_;
};

bool should_enable_interactive_console(const ClientConfig& cfg,
                                       const ParsedArgs& args,
                                       bool use_reverse);

InteractiveConsoleSession start_interactive_console(
    std::atomic<bool>& stop_requested,
    const ClientConfig& cfg,
    std::shared_ptr<Tunnel> tunnel,
    std::shared_ptr<RelayRuntime> relay_runtime,
    InteractiveConsoleSession::StatusBuilder status_block_builder,
    InteractiveConsoleSession::DisconnectCallback request_disconnect);

}  // namespace yume::client
