/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <memory>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include "server/config/config.hpp"
#include "server/host/host_types.hpp"

namespace yume::server {

class Manager;

class ExtraListeners {
public:
    ExtraListeners(boost::asio::io_context& io,
                   boost::asio::ssl::context& ssl_ctx,
                   const ServerConfig& cfg,
                   Manager* manager);
    ~ExtraListeners();

    void start();
    void stop();

private:
    struct PlainListener {
        host::ListenerSpec spec;
        std::unique_ptr<boost::asio::ip::tcp::acceptor> acceptor;
    };

    void start_listener(const host::ListenerSpec& spec);
    void do_accept_plain(std::shared_ptr<PlainListener> listener);
    void handle_plain_connection(host::ListenerSpec spec, boost::asio::ip::tcp::socket socket);

    boost::asio::io_context& io_;
    boost::asio::ssl::context& ssl_ctx_;
    ServerConfig cfg_;
    Manager* manager_{nullptr};
    std::vector<std::shared_ptr<PlainListener>> listeners_;
    bool stopped_{false};
};

}  // namespace yume::server
