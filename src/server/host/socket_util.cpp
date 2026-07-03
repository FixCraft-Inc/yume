/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/host/socket_util.hpp"

namespace yume::server::host {

void close_socket(DenyAction action, boost::asio::ip::tcp::socket& socket) {
    boost::system::error_code ec;
    if (action == DenyAction::Reset) {
        boost::asio::socket_base::linger linger_option(true, 0);
        socket.set_option(linger_option, ec);
    }
    socket.close(ec);
}

}  // namespace yume::server::host
