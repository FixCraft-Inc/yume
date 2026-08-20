/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/host/host_types.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <string_view>
#include <system_error>

#include <boost/asio/ip/address.hpp>

namespace yume::server::host {
namespace {

std::string lower_copy(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return text;
}

bool is_loopback_host(const std::string& host) {
    boost::system::error_code ec;
    const auto address = boost::asio::ip::make_address(host, ec);
    return !ec && address.is_loopback();
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

bool split_host_port(std::string_view rest, std::string* host, int* port, std::string* error) {
    if (rest.empty()) {
        if (error) {
            *error = "loopback backend must be loopback://host:port";
        }
        return false;
    }

    std::string_view host_view;
    std::string_view port_view;
    if (rest.front() == '[') {
        const auto close = rest.find(']');
        if (close == std::string_view::npos || close + 1 >= rest.size() || rest[close + 1] != ':') {
            if (error) {
                *error = "IPv6 loopback backend must be loopback://[::1]:port";
            }
            return false;
        }
        host_view = rest.substr(1, close - 1);
        port_view = rest.substr(close + 2);
    } else {
        const auto colon = rest.rfind(':');
        if (colon == std::string_view::npos) {
            if (error) {
                *error = "loopback backend must be loopback://host:port";
            }
            return false;
        }
        host_view = rest.substr(0, colon);
        port_view = rest.substr(colon + 1);
        if (host_view.find(':') != std::string_view::npos) {
            if (error) {
                *error = "IPv6 loopback backend must use brackets, for example loopback://[::1]:8080";
            }
            return false;
        }
    }

    if (host_view.empty()) {
        if (error) {
            *error = "loopback backend host is empty";
        }
        return false;
    }
    int parsed_port = 0;
    if (!parse_port(port_view, &parsed_port)) {
        if (error) {
            *error = "loopback backend port must be 1..65535";
        }
        return false;
    }
    if (host) {
        *host = std::string(host_view);
    }
    if (port) {
        *port = parsed_port;
    }
    return true;
}

}  // namespace

std::optional<HostMode> parse_host_mode(const std::string& text) {
    const std::string v = lower_copy(text);
    if (v.empty() || v == "off" || v == "none") {
        return HostMode::Off;
    }
    if (v == "private" || v == "host") {
        return HostMode::Private;
    }
    if (v == "relay" || v == "host_relay") {
        return HostMode::Relay;
    }
    return std::nullopt;
}

std::optional<DenyAction> parse_deny_action(const std::string& text) {
    const std::string v = lower_copy(text);
    if (v.empty() || v == "close" || v == "fin") {
        return DenyAction::Close;
    }
    if (v == "reset" || v == "rst" || v == "tcp_reset") {
        return DenyAction::Reset;
    }
    if (v == "drop" || v == "silent") {
        return DenyAction::Drop;
    }
    return std::nullopt;
}

std::optional<ListenerMode> parse_listener_mode(const std::string& text) {
    const std::string v = lower_copy(text);
    if (v.empty() || v == "tls_terminate" || v == "tls") {
        return ListenerMode::TlsTerminate;
    }
    if (v == "tcp_passthrough" || v == "tcp") {
        return ListenerMode::TcpPassthrough;
    }
    if (v == "starttls_mail" || v == "smtp" || v == "mail") {
        return ListenerMode::StartTlsMail;
    }
    return std::nullopt;
}

const char* to_string(HostMode mode) {
    switch (mode) {
        case HostMode::Off:
            return "off";
        case HostMode::Private:
            return "private";
        case HostMode::Relay:
            return "relay";
    }
    return "off";
}

const char* to_string(DenyAction action) {
    switch (action) {
        case DenyAction::Close:
            return "close";
        case DenyAction::Reset:
            return "reset";
        case DenyAction::Drop:
            return "drop";
    }
    return "close";
}

const char* to_string(ListenerMode mode) {
    switch (mode) {
        case ListenerMode::TlsTerminate:
            return "tls_terminate";
        case ListenerMode::TcpPassthrough:
            return "tcp_passthrough";
        case ListenerMode::StartTlsMail:
            return "starttls_mail";
    }
    return "tls_terminate";
}

const char* to_string(ExposureKind kind) {
    switch (kind) {
        case ExposureKind::Unknown:
            return "unknown";
        case ExposureKind::DirectTcp:
            return "direct_tcp";
        case ExposureKind::CfHttpProxy:
            return "cf_http_proxy";
        case ExposureKind::CfSpectrum:
            return "cf_spectrum";
        case ExposureKind::Blocked:
            return "blocked";
    }
    return "unknown";
}

bool backend_is_loopback_only(const std::string& backend, std::string* error) {
    if (backend.empty()) {
        if (error) {
            *error = "backend is empty";
        }
        return false;
    }
    if (backend.rfind("loopback://", 0) == 0) {
        std::string host;
        int port = 0;
        if (!split_host_port(std::string_view(backend).substr(11), &host, &port, error)) {
            return false;
        }
        if (!is_loopback_host(host)) {
            if (error) {
                *error = "host backend must use a loopback IP literal, got: " + host;
            }
            return false;
        }
        return true;
    }
    if (backend.rfind("unix://", 0) == 0) {
        if (error) {
            *error = "unix:// backends are not implemented by the host controller yet";
        }
        return false;
    }
    if (backend.rfind("codec://", 0) == 0 || backend.rfind("service://", 0) == 0) {
        if (error) {
            *error = "codec:// and service:// host-controller backends are not implemented yet";
        }
        return false;
    }
    if (error) {
        *error = "unsupported backend scheme: " + backend;
    }
    return false;
}

}  // namespace yume::server::host
