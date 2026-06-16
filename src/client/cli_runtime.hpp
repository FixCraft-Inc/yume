/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <string>
#include <thread>
#include <vector>

#include <boost/asio.hpp>

namespace yume::client {

bool parse_ssh_forward(const std::string& spec, int& lport, std::string& host, int& rport);
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

}  // namespace yume::client
