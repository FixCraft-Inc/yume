/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include <cassert>
#include <fstream>
#include <string>

#include <nlohmann/json.hpp>

#include "core/stealth/cover_profile.hpp"
#include "core/stealth/http_profile.hpp"
#include "core/stealth/tls_fingerprint.hpp"

#if !defined(YUME_COVER_MANIFEST) || !defined(YUME_COVER_HTTP2_PROFILE)
#error "cover-profile tests require registry-selected evidence paths"
#endif

namespace {

using Json = nlohmann::json;

Json ReadJson(const std::string& path) {
    std::ifstream input(path);
    assert(input.is_open());
    Json value;
    input >> value;
    return value;
}

void AssertHeaders(const yume::cover_profile::Headers& actual,
                   const Json& expected) {
    assert(actual.size() == expected.size());
    for (std::size_t i = 0; i < actual.size(); ++i) {
        assert(expected[i].is_array() && expected[i].size() == 2);
        assert(actual[i].first == expected[i][0].get<std::string>());
        assert(actual[i].second == expected[i][1].get<std::string>());
    }
}

}  // namespace

int main() {
    const Json manifest = ReadJson(YUME_COVER_MANIFEST);
    const Json captured = ReadJson(YUME_COVER_HTTP2_PROFILE);
    const auto& profile = yume::cover_profile::active();

    assert(profile.id == manifest["profile_id"].get<std::string>());
    assert(yume::cover_profile::find_by_id(profile.id) == &profile);
    assert(yume::cover_profile::find_by_registry_name(profile.registry_name) ==
           &profile);
    assert(yume::cover_profile::find_by_id("unknown-profile") == nullptr);

    assert(profile.browser_name == manifest["client"]["browser"].get<std::string>());
    assert(profile.browser_version ==
           manifest["client"]["version"].get<std::string>());
    assert(profile.operating_system ==
           manifest["client"]["os"].get<std::string>());
    assert(profile.cover_runtime ==
           manifest["server"]["runtime"].get<std::string>());
    assert(profile.cover_runtime_version ==
           manifest["server"]["version"].get<std::string>());
    // The offered range is browser-shaped: the captured Chrome ClientHello
    // advertises both TLS 1.2 and 1.3, and offering only 1.3 would drop the
    // TLS 1.2 half of the cipher list plus extension 0xff01. Security of the
    // carrier comes from tls_required_version, which is enforced after the
    // handshake and fails closed, not from narrowing the offer.
    assert(profile.tls_min_version == 0x0303);
    assert(profile.tls_max_version == 0x0304);
    assert(profile.tls_required_version == 0x0304);
    assert(captured["tls_observation"]["version"] == "TLS 1.3");

    const auto client = yume::http_profile::transport_client(
        profile.registry_name);
    assert(client.has_value());
    assert(client->user_agent == profile.user_agent);
    assert(client->tls_profile == profile.tls_profile);
    assert(yume::http_profile::active_client_ua() == profile.user_agent);

    const auto tls =
        yume::tls_fingerprint::get_browser_profile_info(profile.tls_profile);
    assert(tls.has_value());
    assert(tls->name == std::string(profile.browser_name) + " " +
                            std::string(profile.browser_version));
    assert(tls->alpn_protocols.size() == 2);
    assert(tls->alpn_protocols[0] ==
           captured["tls_observation"]["alpn"].get<std::string>());

    const Json& captured_settings = captured["client_settings_in_order"];
    assert(profile.client_settings.size() == captured_settings.size());
    for (std::size_t i = 0; i < profile.client_settings.size(); ++i) {
        assert(profile.client_settings[i].id ==
               captured_settings[i][0].get<std::uint32_t>());
        assert(profile.client_settings[i].value ==
               captured_settings[i][1].get<std::uint32_t>());
    }
    assert(profile.connection_window_update ==
           captured["client_connection_window_update"]["delta"]
               .get<std::uint32_t>());

    const Json& server_settings =
        captured["node_non_default_settings_in_order"];
    assert(profile.server_settings.size() == server_settings.size());
    for (std::size_t i = 0; i < profile.server_settings.size(); ++i) {
        assert(profile.server_settings[i].id ==
               server_settings[i][0].get<std::uint32_t>());
        assert(profile.server_settings[i].value ==
               server_settings[i][1].get<std::uint32_t>());
    }

    AssertHeaders(
        profile.render_headers(profile.priming_request, "<cover-authority>"),
        captured["priming_get"]["headers_in_order"]);
    AssertHeaders(
        profile.render_headers(profile.extended_connect, "<cover-authority>",
                               "<authenticated-carrier-path>"),
        captured["extended_connect"]["headers_in_order"]);

    assert(profile.priming_request.priority.parent_stream_id ==
           captured["priming_get"]["parent_stream_id"].get<std::int32_t>());
    assert(profile.priming_request.priority.weight ==
           captured["priming_get"]["weight"].get<std::int32_t>());
    assert(profile.priming_request.priority.exclusive ==
           captured["priming_get"]["exclusive"].get<bool>());
    assert(profile.extended_connect.priority.parent_stream_id ==
           captured["extended_connect"]["parent_stream_id"]
               .get<std::int32_t>());
    assert(profile.extended_connect.priority.weight ==
           captured["extended_connect"]["weight"].get<std::int32_t>());
    assert(profile.extended_connect.priority.exclusive ==
           captured["extended_connect"]["exclusive"].get<bool>());

    const Json& captured_assets = captured["asset_sequence"];
    assert(profile.assets.size() == captured_assets.size());
    for (std::size_t i = 0; i < profile.assets.size(); ++i) {
        assert(profile.assets[i].path ==
               captured_assets[i]["path"].get<std::string>());
        AssertHeaders(profile.render_headers(profile.assets[i].request,
                                             "<cover-authority>"),
                      captured_assets[i]["headers_in_order"]);
    }
    assert(profile.websocket_message_bytes ==
           captured["shaping_policy"]["bulk_websocket_message_bytes"]
               .get<std::size_t>());
    assert(!captured["shaping_policy"]["random_padding"].get<bool>());
    assert(!captured["shaping_policy"]["random_timing_jitter"].get<bool>());

    return 0;
}
