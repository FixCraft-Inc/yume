/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <memory>
#include <string>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

namespace yume::server {

class Manager;

namespace host {

void start_http_reverse_proxy(boost::asio::ssl::stream<boost::asio::ip::tcp::socket> client_stream,
                              std::string initial_request,
                              const std::string& backend_host,
                              int backend_port,
                              Manager* manager);

}  // namespace host
}  // namespace yume::server
