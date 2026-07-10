/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/parse/endpoints.hpp"

#include <charconv>
#include <cctype>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/asio/ip/address.hpp>

namespace yume::client {

namespace {

std::string trim_ascii(std::string_view value) {
    std::size_t first = 0;
    while (first < value.size() &&
           std::isspace(static_cast<unsigned char>(value[first])) != 0) {
        ++first;
    }
    std::size_t last = value.size();
    while (last > first &&
           std::isspace(static_cast<unsigned char>(value[last - 1])) != 0) {
        --last;
    }
    return std::string(value.substr(first, last - first));
}

bool parse_port_text(std::string_view text, int& out) {
    if (text.empty()) {
        return false;
    }
    int port = 0;
    const char* first = text.data();
    const char* last = first + text.size();
    auto [ptr, ec] = std::from_chars(first, last, port);
    if (ec != std::errc() || ptr != last || port < 1 || port > 65535) {
        return false;
    }
    out = port;
    return true;
}

bool validate_bind_host(const std::string& host, std::string* error) {
    if (host.empty()) {
        return true;
    }
    boost::system::error_code ec;
    boost::asio::ip::make_address(host, ec);
    if (ec) {
        if (error) {
            *error = "bind address must be an IP literal";
        }
        return false;
    }
    return true;
}

std::string bracket_ipv6_if_needed(const std::string& host) {
    if (host.find(':') != std::string::npos) {
        return "[" + host + "]";
    }
    return host;
}

}  // namespace

bool parse_bind_endpoint(const std::string& spec,
                         BindEndpoint& out,
                         std::string* error) {
    const std::string raw = trim_ascii(spec);
    if (raw.empty()) {
        if (error) *error = "bind endpoint is empty";
        return false;
    }

    std::string host;
    std::string_view port_text;
    if (raw.front() == '[') {
        const auto end = raw.find(']');
        if (end == std::string::npos || end + 1 >= raw.size() || raw[end + 1] != ':') {
            if (error) *error = "bind endpoint must be [addr]:port";
            return false;
        }
        host = raw.substr(1, end - 1);
        port_text = std::string_view(raw).substr(end + 2);
    } else {
        const auto colon = raw.rfind(':');
        if (colon == std::string::npos) {
            port_text = std::string_view(raw);
        } else {
            host = raw.substr(0, colon);
            port_text = std::string_view(raw).substr(colon + 1);
            if (host.find(':') != std::string::npos) {
                if (error) *error = "IPv6 bind address must use [addr]:port";
                return false;
            }
        }
    }

    int port = 0;
    if (!parse_port_text(port_text, port)) {
        if (error) *error = "bind port must be 1..65535";
        return false;
    }
    if (!validate_bind_host(host, error)) {
        return false;
    }
    out.host = std::move(host);
    out.port = port;
    return true;
}

bool parse_ssh_forward(const std::string& spec,
                       SshForwardSpec& out,
                       std::string* error) {
    const std::string raw = trim_ascii(spec);
    if (raw.empty()) {
        if (error) *error = "forward spec is empty";
        return false;
    }

    std::vector<std::string> parts;
    std::string bind_host;
    std::size_t start = 0;
    if (raw.front() == '[') {
        const auto end = raw.find(']');
        if (end == std::string::npos || end + 1 >= raw.size() || raw[end + 1] != ':') {
            if (error) *error = "forward bind endpoint must be [addr]:port";
            return false;
        }
        bind_host = raw.substr(1, end - 1);
        start = end + 2;
    }
    while (true) {
        std::size_t pos = raw.find(':', start);
        if (pos == std::string::npos) {
            parts.push_back(raw.substr(start));
            break;
        }
        parts.push_back(raw.substr(start, pos - start));
        start = pos + 1;
    }

    if (!bind_host.empty()) {
        if (parts.size() != 3) {
            if (error) *error = "forward spec must be [bind]:lport:host:port";
            return false;
        }
    } else if (parts.size() == 4) {
        bind_host = parts[0];
        parts.erase(parts.begin());
    } else if (parts.size() != 3) {
        if (error) *error = "forward spec must be [bind:]lport:host:port";
        return false;
    }

    if (!validate_bind_host(bind_host, error)) {
        return false;
    }
    int listen_port = 0;
    if (!parse_port_text(parts[0], listen_port)) {
        if (error) *error = "listen port must be 1..65535";
        return false;
    }
    int target_port = 0;
    if (!parse_port_text(parts[2], target_port)) {
        if (error) *error = "target port must be 1..65535";
        return false;
    }
    if (parts[1].empty()) {
        if (error) *error = "target host is required";
        return false;
    }

    out.bind_host = std::move(bind_host);
    out.listen_port = listen_port;
    out.target_host = std::move(parts[1]);
    out.target_port = target_port;
    return true;
}

bool parse_ssh_forward(const std::string& spec, int& lport, std::string& host, int& rport) {
    SshForwardSpec parsed;
    if (!parse_ssh_forward(spec, parsed)) {
        return false;
    }
    lport = parsed.listen_port;
    host = std::move(parsed.target_host);
    rport = parsed.target_port;
    return true;
}

std::string format_bind_endpoint(const std::string& bind_host, int port) {
    if (bind_host.empty()) {
        return std::to_string(port);
    }
    return bracket_ipv6_if_needed(bind_host) + ":" + std::to_string(port);
}

std::string format_display_bind_endpoint(const std::string& bind_host, int port) {
    const std::string host = bind_host.empty() ? std::string("0.0.0.0") : bind_host;
    return bracket_ipv6_if_needed(host) + ":" + std::to_string(port);
}

}  // namespace yume::client
