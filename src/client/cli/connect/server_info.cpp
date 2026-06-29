/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/connect/server_info.hpp"

#include <string>

#include <nlohmann/json.hpp>

#include "client/cli/connect/diagnostics.hpp"
#include "core/protocol/runtime_policy.hpp"

namespace yume::client {

ServerInfoPayload parse_server_info_payload(const protocol::Frame& frame) {
    std::string payload(frame.payload.begin(), frame.payload.end());
    auto json = nlohmann::json::parse(payload);

    ServerInfoPayload info;
    info.version = json.value("version", "UNKNOWN");
    info.error = json.value("error", "");
    info.mode = json.value("mode", "normal");
    info.hash = json.value("hash", "");
    info.sig = json.value("sig", "");
    info.ts = json.value("ts", "");
    info.nonce = json.value("nonce", "");
    info.certfp = json.value("certfp", "");
    info.ca_sig = json.value("ca_sig", "");
    info.ca_alg = json.value("ca_alg", "");
    info.sub_sig = json.value("sub_sig", "");
    info.sub_alg = json.value("sub_alg", "");
    info.sub_cert_b64 = json.value("sub_cert", "");
    if (json.contains("proof_sources") && json["proof_sources"].is_array()) {
        for (const auto& entry : json["proof_sources"]) {
            if (entry.is_string()) {
                info.announced_proof_sources.push_back(normalize_proof_source(entry.get<std::string>()));
            }
        }
    }
    info.pq_pub_b64 = json.value("pq_pub", "");
    info.pq_sig = json.value("pq_sig", "");
    info.pq_alg = json.value("pq_alg", "");
    info.have_inner_caps = json.contains("inner_supported") || json.contains("inner_required") ||
                           json.contains("inner_dual") || json.contains("inner_mode");
    info.server_inner_supported = json.value("inner_supported", false);
    info.server_inner_required = json.value("inner_required", false);
    info.server_inner_dual = json.value("inner_dual", false);
    info.server_inner_active = json.value("inner_active", false);
    info.server_inner_mode = json.value("inner_mode", "");
    info.server_cap_pq = json.value("cap_pq", false);
    info.server_cap_argon2 = json.value("cap_argon2", false);
    info.server_cap_pbkdf2 = json.value("cap_pbkdf2", false);
    info.server_hop_enabled = json.value("hop_enabled", false);
    info.server_hop_interval_ms = static_cast<std::uint32_t>(json.value("hop_interval_ms", 0));
    info.server_time_ms = json.value("server_time_ms", 0LL);

    if (info.announced_proof_sources.empty()) {
        if (!info.sig.empty()) {
            add_verified_source(&info.announced_proof_sources, yume::policy::kAnonymProofSourceFixcraft);
        }
        if (!info.ca_sig.empty()) {
            add_verified_source(&info.announced_proof_sources, yume::policy::kAnonymProofSourceCa);
        }
        if (!info.sub_sig.empty() || !info.sub_cert_b64.empty()) {
            add_verified_source(&info.announced_proof_sources, yume::policy::kAnonymProofSourceSubCa);
        }
    }

    return info;
}

}  // namespace yume::client
