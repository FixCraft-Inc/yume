/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/host/host_routes.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <string_view>
#include <system_error>

#include <boost/asio/ip/address.hpp>
#include <openssl/ssl.h>

namespace yume::server::host {
namespace {

std::string lower_copy(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

bool host_matches(const std::string& pattern, const std::string& value) {
    if (pattern.empty()) {
        return true;
    }
    return lower_copy(pattern) == lower_copy(value);
}

bool path_matches(const std::string& prefix, const std::string& path) {
    if (prefix.empty()) {
        return true;
    }
    if (path.size() < prefix.size()) {
        return false;
    }
    return path.compare(0, prefix.size(), prefix) == 0;
}

bool parse_port(std::string_view text, int* port) {
    if (text.empty()) {
        return false;
    }
    int value = 0;
    const auto* first = text.data();
    const auto* last = first + text.size();
    const auto result = std::from_chars(first, last, value);
    if (result.ec != std::errc() || result.ptr != last || value < 1 || value > 65535) {
        return false;
    }
    if (port) {
        *port = value;
    }
    return true;
}

bool split_host_port(std::string_view text,
                     std::string* host,
                     int* port,
                     const char* label,
                     std::string* error) {
    if (text.empty()) {
        if (error) {
            *error = std::string(label) + " must be host:port";
        }
        return false;
    }

    std::string_view host_view;
    std::string_view port_view;
    if (text.front() == '[') {
        const auto close = text.find(']');
        if (close == std::string_view::npos || close + 1 >= text.size() || text[close + 1] != ':') {
            if (error) {
                *error = std::string(label) + " IPv6 form must be [addr]:port";
            }
            return false;
        }
        host_view = text.substr(1, close - 1);
        port_view = text.substr(close + 2);
    } else if (text.front() == ':') {
        host_view = {};
        port_view = text.substr(1);
    } else {
        const auto colon = text.rfind(':');
        if (colon == std::string_view::npos) {
            if (error) {
                *error = std::string(label) + " must be host:port or :port";
            }
            return false;
        }
        host_view = text.substr(0, colon);
        port_view = text.substr(colon + 1);
    }

    int parsed_port = 0;
    if (!parse_port(port_view, &parsed_port)) {
        if (error) {
            *error = std::string(label) + " port must be 1..65535";
        }
        return false;
    }
    if (!host_view.empty()) {
        boost::system::error_code ec;
        boost::asio::ip::make_address(std::string(host_view), ec);
        if (ec) {
            if (error) {
                *error = std::string(label) + " address must be an IP literal: " + std::string(host_view);
            }
            return false;
        }
    }
    if (host) {
        *host = std::string(host_view);
    }
    if (port) {
        *port = parsed_port;
    }
    return true;
}

std::optional<std::pair<std::string, int>> parse_loopback_backend_impl(const std::string& backend) {
    if (backend.rfind("loopback://", 0) != 0) {
        return std::nullopt;
    }
    const auto rest = std::string_view(backend).substr(11);
    std::string host;
    int port = 0;
    if (!split_host_port(rest,
                         &host,
                         &port,
                         "loopback backend",
                         nullptr)) {
        return std::nullopt;
    }
    if (!rest.empty() && rest.front() != '[' && host.find(':') != std::string::npos) {
        return std::nullopt;
    }
    boost::system::error_code ec;
    const auto address = boost::asio::ip::make_address(host, ec);
    if (ec || !address.is_loopback()) {
        return std::nullopt;
    }
    return std::make_pair(std::move(host), port);
}

}  // namespace

void HostRouteTable::set_routes(std::vector<HostRoute> routes) {
    routes_ = std::move(routes);
}

std::optional<RouteMatch> HostRouteTable::match(const std::string& sni,
                                                const std::string& host_header,
                                                const std::string& path) const {
    const std::string host = !host_header.empty() ? host_header : sni;
    for (const auto& route : routes_) {
        const bool sni_ok = route.sni.empty() || host_matches(route.sni, sni) || host_matches(route.sni, host);
        const bool host_ok = route.host.empty() || host_matches(route.host, host);
        if (!sni_ok || !host_ok || !path_matches(route.path_prefix, path)) {
            continue;
        }
        return RouteMatch{&route};
    }
    return std::nullopt;
}

bool HostRouteTable::parse_routes_json(const nlohmann::json& json,
                                       std::vector<HostRoute>* routes,
                                       std::string* error) {
    if (!json.is_array()) {
        if (error) {
            *error = "routes must be a JSON array";
        }
        return false;
    }
    routes->clear();
    for (const auto& item : json) {
        if (!item.is_object()) {
            if (error) {
                *error = "each route must be an object";
            }
            return false;
        }
        HostRoute route;
        if (item.contains("sni")) {
            route.sni = item["sni"].get<std::string>();
        }
        if (item.contains("host")) {
            route.host = item["host"].get<std::string>();
        }
        if (item.contains("path_prefix")) {
            route.path_prefix = item["path_prefix"].get<std::string>();
        }
        if (!item.contains("backend")) {
            if (error) {
                *error = "route missing backend";
            }
            return false;
        }
        route.backend = item["backend"].get<std::string>();
        std::string backend_error;
        if (!backend_is_loopback_only(route.backend, &backend_error)) {
            if (error) {
                *error = backend_error;
            }
            return false;
        }
        routes->push_back(std::move(route));
    }
    return true;
}

bool HostRouteTable::parse_listeners_json(const nlohmann::json& json,
                                          std::vector<ListenerSpec>* listeners,
                                          std::string* error) {
    if (!json.is_array()) {
        if (error) {
            *error = "listeners must be a JSON array";
        }
        return false;
    }
    listeners->clear();
    for (const auto& item : json) {
        if (!item.is_object()) {
            if (error) {
                *error = "each listener must be an object";
            }
            return false;
        }
        ListenerSpec spec;
        if (item.contains("bind_address")) {
            spec.bind_address = item["bind_address"].get<std::string>();
        }
        if (!item.contains("bind")) {
            if (error) {
                *error = "listener missing bind";
            }
            return false;
        }
        const std::string bind = item["bind"].get<std::string>();
        if (!split_host_port(bind, &spec.bind_address, &spec.bind_port, "listener bind", error)) {
            return false;
        }
        if (item.contains("mode")) {
            auto mode = parse_listener_mode(item["mode"].get<std::string>());
            if (!mode.has_value()) {
                if (error) {
                    *error = "invalid listener mode";
                }
                return false;
            }
            spec.mode = *mode;
        }
        if (!item.contains("backend")) {
            if (error) {
                *error = "listener missing backend";
            }
            return false;
        }
        spec.backend = item["backend"].get<std::string>();
        std::string backend_error;
        if (!backend_is_loopback_only(spec.backend, &backend_error)) {
            if (error) {
                *error = backend_error;
            }
            return false;
        }
        listeners->push_back(std::move(spec));
    }
    return true;
}

std::optional<std::pair<std::string, int>> parse_loopback_backend(const std::string& backend) {
    return parse_loopback_backend_impl(backend);
}

std::string http_header_value(const std::string& headers, const std::string& name) {
    const std::string wanted = lower_copy(name);
    std::size_t line_start = 0;
    while (line_start < headers.size()) {
        auto line_end = headers.find("\r\n", line_start);
        if (line_end == std::string::npos) {
            line_end = headers.size();
        }
        const auto colon = headers.find(':', line_start);
        if (colon != std::string::npos && colon < line_end) {
            const std::string field = lower_copy(headers.substr(line_start, colon - line_start));
            if (field == wanted) {
                std::size_t value = colon + 1;
                while (value < line_end && (headers[value] == ' ' || headers[value] == '\t')) {
                    ++value;
                }
                return headers.substr(value, line_end - value);
            }
        }
        if (line_end == headers.size()) {
            break;
        }
        line_start = line_end + 2;
    }
    return {};
}

std::string tls_sni(void* ssl_native_handle) {
    if (!ssl_native_handle) {
        return {};
    }
    const char* name = SSL_get_servername(static_cast<SSL*>(ssl_native_handle), TLSEXT_NAMETYPE_host_name);
    return name ? std::string(name) : std::string();
}

}  // namespace yume::server::host
