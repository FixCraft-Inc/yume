/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <boost/asio/ip/tcp.hpp>

#include "server/host/host_types.hpp"

namespace yume::server::host {

void close_socket(DenyAction action, boost::asio::ip::tcp::socket& socket);

}  // namespace yume::server::host
