/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "server/host/host_types.hpp"

namespace yume::server::host {

struct RouteMatch {
    const HostRoute* route{nullptr};
};

class HostRouteTable {
public:
    void set_routes(std::vector<HostRoute> routes);
    const std::vector<HostRoute>& routes() const { return routes_; }
    bool empty() const { return routes_.empty(); }

    std::optional<RouteMatch> match(const std::string& sni,
                                    const std::string& host_header,
                                    const std::string& path) const;

    static bool parse_routes_json(const nlohmann::json& json,
                                  std::vector<HostRoute>* routes,
                                  std::string* error);
    static bool parse_listeners_json(const nlohmann::json& json,
                                     std::vector<ListenerSpec>* listeners,
                                     std::string* error);

private:
    std::vector<HostRoute> routes_;
};

std::optional<std::pair<std::string, int>> parse_loopback_backend(const std::string& backend);
std::string http_header_value(const std::string& headers, const std::string& name);
std::string tls_sni(void* ssl_native_handle);

}  // namespace yume::server::host
