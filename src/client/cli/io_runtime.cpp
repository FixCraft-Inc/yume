/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "client/cli/io_runtime.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>

namespace yume::client {

bool parse_ssh_forward(const std::string& spec, int& lport, std::string& host, int& rport) {
    if (spec.empty()) {
        return false;
    }
    std::vector<std::string> parts;
    size_t start = 0;
    while (true) {
        size_t pos = spec.find(':', start);
        if (pos == std::string::npos) {
            parts.push_back(spec.substr(start));
            break;
        }
        parts.push_back(spec.substr(start, pos - start));
        start = pos + 1;
    }
    if (parts.size() != 3 && parts.size() != 4) {
        return false;
    }
    size_t idx = parts.size() == 4 ? 1 : 0;
    try {
        lport = std::stoi(parts[idx]);
    } catch (...) {
        return false;
    }
    host = parts[idx + 1];
    try {
        rport = std::stoi(parts[idx + 2]);
    } catch (...) {
        return false;
    }
    return lport > 0 && rport > 0 && !host.empty();
}

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
    io_.stop();
    wait();
}

}  // namespace yume::client
