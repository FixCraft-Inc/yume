/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <memory>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include "client/cli/entry.hpp"
#include "client/proxy/outbound_proxy.hpp"

namespace yume::client {

class Tunnel;

std::shared_ptr<Tunnel> connect_secondary_tunnel(boost::asio::io_context& io,
                                                 boost::asio::ssl::context& ctx,
                                                 const ClientConfig& cfg,
                                                 const outbound_proxy::Config& proxy_cfg,
                                                 int index);

}  // namespace yume::client
