/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/commands/io_runtime.hpp"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <utility>

#if !defined(_WIN32)
#include <unistd.h>
#endif

#include "client/cli/config/input.hpp"
#include "client/transport/tunnel.hpp"
#include "util.hpp"
#include <boost/asio/post.hpp>

namespace yume::client {

int resolve_io_threads(int requested) {
    if (requested > 0) {
        return requested;
    }
    unsigned int hw = std::thread::hardware_concurrency();
    int auto_threads = hw > 0 ? static_cast<int>(hw) : 1;
    // Each relay stream is serialized on one asio strand; extra default
    // threads bounce handlers across cores and slow single/few-stream use.
    constexpr int kAutoThreadCap = 4;
    if (auto_threads > kAutoThreadCap) {
        auto_threads = kAutoThreadCap;
    }
    return auto_threads;
}

bool parse_env_bool(const char* name, bool fallback) {
    const char* raw = std::getenv(name);
    if (!raw || !*raw) {
        return fallback;
    }
    std::string value(raw);
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (value == "1" || value == "true" || value == "yes" || value == "on") {
        return true;
    }
    if (value == "0" || value == "false" || value == "no" || value == "off") {
        return false;
    }
    return fallback;
}

std::vector<std::thread> start_io_threads(boost::asio::io_context& io, int requested) {
    io.restart();
    int threads = resolve_io_threads(requested);
    std::vector<std::thread> workers;
    workers.reserve(static_cast<size_t>(threads));
    for (int i = 0; i < threads; ++i) {
        workers.emplace_back([&io]() { io.run(); });
    }
    return workers;
}

IoThreadGroup::IoThreadGroup(boost::asio::io_context& io, std::vector<std::thread>&& workers)
    : io_(io)
    , workers_(std::move(workers)) {}

IoThreadGroup::~IoThreadGroup() {
    stop_and_wait();
}

void IoThreadGroup::wait() {
    if (joined_) {
        return;
    }
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    joined_ = true;
}

void IoThreadGroup::stop_and_wait() {
    if (joined_) {
        return;
    }
    boost::asio::post(io_, [this]() {
        io_.stop();
    });
    io_.stop();
    wait();
}

RuntimeStopController::RuntimeStopController(bool immediate_benchmark_exit)
    : immediate_benchmark_exit_(immediate_benchmark_exit) {}

RuntimeStopController::~RuntimeStopController() {
    // Disabling the registration waits for any dispatcher callback that still
    // owns `this` before the remaining controller state is destroyed.
    signal_handler_.reset();
}

void RuntimeStopController::install_signal_handler() {
    signal_handler_ = std::make_unique<util::SignalHandlerRegistration>(
        [this](int) { request_stop_from_signal(); });
}

void RuntimeStopController::announce_stopping() {
    if (stop_announced_.exchange(true)) {
        return;
    }
    util::clear_status_line();
    std::cerr << "[INFO] Stopping..." << std::endl;
}

bool RuntimeStopController::stop_requested() const {
    return stop_requested_.load();
}

std::atomic<bool>& RuntimeStopController::stop_flag() {
    return stop_requested_;
}

void RuntimeStopController::set_active(boost::asio::io_context* io,
                                       const std::shared_ptr<Tunnel>& tunnel,
                                       const std::shared_ptr<RelayRuntime>& relay,
                                       std::function<void(const std::string&)> disconnect) {
    std::lock_guard<std::mutex> lock(runtime_mu_);
    active_io_ = io;
    active_tunnel_ = tunnel;
    active_relay_runtime_ = relay;
    active_disconnect_ = std::move(disconnect);
}

void RuntimeStopController::clear_active() {
    std::lock_guard<std::mutex> lock(runtime_mu_);
    active_io_ = nullptr;
    active_tunnel_.reset();
    active_relay_runtime_.reset();
    active_disconnect_ = {};
}

std::shared_ptr<RelayRuntime> RuntimeStopController::active_relay_runtime() {
    std::lock_guard<std::mutex> lock(runtime_mu_);
    return active_relay_runtime_.lock();
}

void RuntimeStopController::request_stop_from_signal() {
    const bool already_requested = force_stop_requested_.exchange(true);
    stop_requested_.store(true);
    announce_stopping();

    boost::asio::io_context* io = nullptr;
    std::shared_ptr<Tunnel> tunnel;
    std::function<void(const std::string&)> disconnect;
    {
        std::lock_guard<std::mutex> lock(runtime_mu_);
        io = active_io_;
        tunnel = active_tunnel_.lock();
        disconnect = active_disconnect_;
    }

    if (disconnect) {
        disconnect("interrupt");
    } else {
        if (tunnel) {
            tunnel->stop("interrupt");
        }
        if (io) {
            io->stop();
        }
    }

#if !defined(_WIN32)
    restore_tracked_terminal_mode();
    if (!stdin_closed_for_stop_.exchange(true)) {
        ::close(STDIN_FILENO);
    }
#endif

    if (immediate_benchmark_exit_) {
        std::cerr << "[INFO] Benchmark interrupted. Exiting immediately." << std::endl;
        std::_Exit(130);
    }
    if (already_requested) {
        std::cerr << "[WARN] Force stop requested. Exiting immediately." << std::endl;
        std::_Exit(1);
    }
}

}  // namespace yume::client
