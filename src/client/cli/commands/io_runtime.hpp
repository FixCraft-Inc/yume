/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio.hpp>

namespace yume::client {

class RelayRuntime;
class Tunnel;

int resolve_io_threads(int requested);
bool parse_env_bool(const char* name, bool fallback);
std::vector<std::thread> start_io_threads(boost::asio::io_context& io, int requested);

class IoThreadGroup {
public:
    IoThreadGroup(boost::asio::io_context& io, std::vector<std::thread>&& workers);
    ~IoThreadGroup();

    void wait();
    void stop_and_wait();

private:
    boost::asio::io_context& io_;
    std::vector<std::thread> workers_;
    bool joined_{false};
};

class RuntimeStopController {
public:
    explicit RuntimeStopController(bool immediate_benchmark_exit);
    ~RuntimeStopController();

    RuntimeStopController(const RuntimeStopController&) = delete;
    RuntimeStopController& operator=(const RuntimeStopController&) = delete;

    void install_signal_handler();
    void announce_stopping();
    bool stop_requested() const;
    std::atomic<bool>& stop_flag();
    void set_active(boost::asio::io_context* io,
                    const std::shared_ptr<Tunnel>& tunnel,
                    const std::shared_ptr<RelayRuntime>& relay = nullptr,
                    std::function<void(const std::string&)> disconnect = {});
    void clear_active();
    std::shared_ptr<RelayRuntime> active_relay_runtime();

private:
    void request_stop_from_signal();

    const bool immediate_benchmark_exit_{false};
    std::atomic<bool> stop_requested_{false};
    std::atomic<bool> stop_announced_{false};
    std::atomic<bool> force_stop_requested_{false};
#if !defined(_WIN32)
    std::atomic<bool> stdin_closed_for_stop_{false};
#endif
    std::mutex runtime_mu_;
    boost::asio::io_context* active_io_{nullptr};
    std::weak_ptr<Tunnel> active_tunnel_;
    std::weak_ptr<RelayRuntime> active_relay_runtime_;
    std::function<void(const std::string&)> active_disconnect_;
};

}  // namespace yume::client
