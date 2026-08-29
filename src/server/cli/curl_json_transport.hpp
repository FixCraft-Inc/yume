/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace yume::server::cli::detail {

struct HttpsEndpoint {
    std::string host;
    std::string port;
    std::string target;
};

// Parse the deliberately small operator-proof URL grammar once for both the
// in-process and curl transports. Credentials, fragments, malformed ports,
// controls, and ambiguous unbracketed IPv6 authorities are rejected.
HttpsEndpoint parse_https_endpoint(std::string_view url);
std::string https_authority(const HttpsEndpoint& endpoint);
void validate_http_field_value(std::string_view value,
                               std::string_view field_name);
std::string require_operator_proof_signature(
    const nlohmann::json& response);

bool use_curl_for_anonym_https();

nlohmann::json post_json_https_via_curl(
    const HttpsEndpoint& endpoint,
    const nlohmann::json& payload,
    const std::string& token,
    const std::string& outbound_proxy_url);

}  // namespace yume::server::cli::detail
