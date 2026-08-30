/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include "client/cli/entry.hpp"
#include "client/proxy/outbound_proxy.hpp"
#include "core/stealth/tls_fingerprint.hpp"
#include "outbound/tunnel_fwd.hpp"

namespace yume::client {

std::shared_ptr<Tunnel> connect_secondary_tunnel(boost::asio::io_context& io,
                                                 boost::asio::ssl::context& ctx,
                                                 const ClientConfig& cfg,
                                                 const outbound_proxy::Config& proxy_cfg,
                                                 int index,
                                                 std::optional<tls_fingerprint::BrowserProfile> profile,
                                                 std::uint64_t* completed_tls_connections,
                                                 const std::function<bool()>& should_stop = {});

}  // namespace yume::client
