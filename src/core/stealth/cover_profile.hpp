/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "core/stealth/tls_fingerprint.hpp"

namespace yume::cover_profile {

using Headers = std::vector<std::pair<std::string, std::string>>;

struct H2Setting {
    std::uint32_t id;
    std::uint32_t value;
};

struct H2Priority {
    std::int32_t parent_stream_id;
    std::int32_t weight;
    bool exclusive;
};

enum class HeaderValueSource {
    Literal,
    Authority,
    CarrierPath,
    UserAgent,
    ClientHintBrand,
    ClientHintMobile,
    ClientHintPlatform,
    Origin,
    RootReferer,
};

struct HeaderTemplate {
    std::string_view name;
    HeaderValueSource value_source;
    std::string_view literal;
};

struct RequestTemplate {
    std::span<const HeaderTemplate> headers;
    H2Priority priority;
};

struct AssetTemplate {
    std::string_view path;
    RequestTemplate request;
};

struct Profile {
    // Authenticated wire identity and implementation routing metadata. The
    // profile ID is security-sensitive; aliases are presentation-only.
    std::string_view id;
    std::string_view registry_name;
    std::string_view tls_backend;
    std::string_view helper_build_id;
    std::string_view browser_name;
    std::string_view browser_version;
    std::string_view operating_system;
    std::string_view user_agent;
    std::string_view client_hint_brand;
    std::string_view client_hint_mobile;
    std::string_view client_hint_platform;
    tls_fingerprint::BrowserProfile tls_profile;
    std::uint16_t tls_min_version;
    std::uint16_t tls_max_version;

    std::string_view cover_runtime;
    std::string_view cover_runtime_version;
    std::span<const H2Setting> client_settings;
    std::span<const H2Setting> server_settings;
    std::uint32_t connection_window_update;
    RequestTemplate priming_request;
    RequestTemplate extended_connect;
    std::span<const AssetTemplate> assets;
    std::size_t websocket_message_bytes;

    Headers render_headers(const RequestTemplate& request,
                           std::string_view authority,
                           std::string_view carrier_path = {}) const;
};

// Immutable build-time registry generated from committed capture artifacts.
// Production code uses active(); adding a profile must not add browser-specific
// branches to TLS/HTTP/H2 consumers.
std::span<const Profile> all();
const Profile* find_by_id(std::string_view id);
const Profile* find_by_registry_name(std::string_view name);
const Profile& active();

}  // namespace yume::cover_profile
