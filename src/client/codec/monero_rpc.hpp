/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <memory>
#include <string>

#include <boost/asio.hpp>

#include "client/transport/tunnel.hpp"
#include "core/app_codec/builtin/monero_rpc.hpp"
#include "core/app_codec/codec.hpp"

namespace yume::client::codec {

class MoneroRpcCodecServer {
public:
    MoneroRpcCodecServer(boost::asio::io_context& io,
                         app_codec::Endpoint listen,
                         std::shared_ptr<Tunnel> tunnel);

    void start();

private:
    void do_accept();

    boost::asio::ip::tcp::acceptor acceptor_;
    app_codec::Endpoint listen_;
    std::shared_ptr<Tunnel> tunnel_;
};

}  // namespace yume::client::codec
