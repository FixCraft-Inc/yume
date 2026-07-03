/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace yume::server::host {

enum class HostMode {
    Off,
    Private,
    Relay,
};

enum class DenyAction {
    Close,
    Reset,
    Drop,
};

enum class ListenerMode {
    TlsTerminate,
    TcpPassthrough,
    StartTlsMail,
};

enum class ExposureKind {
    Unknown,
    DirectTcp,
    CfHttpProxy,
    CfSpectrum,
    Blocked,
};

struct ExposureResult {
    ExposureKind kind{ExposureKind::Unknown};
    std::string detail;
    std::string hostname;
};

struct HostRoute {
    std::string sni;
    std::string host;
    std::string path_prefix;
    std::string backend;
};

struct ListenerSpec {
    std::string bind_address;
    int bind_port{0};
    ListenerMode mode{ListenerMode::TlsTerminate};
    std::string backend;
};

std::optional<HostMode> parse_host_mode(const std::string& text);
std::optional<DenyAction> parse_deny_action(const std::string& text);
std::optional<ListenerMode> parse_listener_mode(const std::string& text);
const char* to_string(HostMode mode);
const char* to_string(DenyAction action);
const char* to_string(ListenerMode mode);
const char* to_string(ExposureKind kind);

bool backend_is_loopback_only(const std::string& backend, std::string* error = nullptr);

}  // namespace yume::server::host
