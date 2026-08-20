/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/session/authorization.hpp"

#include <exception>
#include <string>
#include <unordered_set>

#include <nlohmann/json.hpp>

namespace yume::server::authorization {

bool preauth_service_open_payload(std::string_view payload) {
    try {
        std::unordered_set<std::string> top_level_keys;
        std::size_t top_level_key_events = 0;
        bool duplicate_key = false;
        auto callback = [&](int depth,
                            nlohmann::json::parse_event_t event,
                            nlohmann::json& parsed) {
            if (depth == 1 && event == nlohmann::json::parse_event_t::key) {
                ++top_level_key_events;
                const std::string key = parsed.get<std::string>();
                if (!top_level_keys.insert(key).second) {
                    duplicate_key = true;
                }
            }
            return true;
        };
        const auto json = nlohmann::json::parse(payload, callback);
        return !duplicate_key && top_level_key_events == 2 &&
               json.is_object() && json.size() == 2 &&
               json.contains("proto") && json["proto"].is_string() &&
               json["proto"].get<std::string>() == "service.v1" &&
               json.contains("service") && json["service"].is_string() &&
               !json["service"].get_ref<const std::string&>().empty();
    } catch (const std::exception&) {
        return false;
    }
}

bool post_auth_frame_allowed(SessionTier tier,
                             protocol::FrameType type,
                             const FrameContext& context) {
    if (tier == SessionTier::Authorized) {
        return type != protocol::AUTH;
    }
    if (tier != SessionTier::PreauthServiceOnly) {
        return false;
    }

    switch (type) {
        case protocol::OPEN:
            return context.service_open;
        case protocol::DATA:
        case protocol::CLOSE:
            return context.existing_service_stream;
        case protocol::PING:
        case protocol::PONG:
            return true;
        default:
            return false;
    }
}

bool admin_claim_eligible(bool visitor_signature_valid,
                          bool visitor_authorized) noexcept {
    return visitor_signature_valid && visitor_authorized;
}

bool admin_attach_allowed(bool caller_trusted_relay,
                          bool caller_allow_outbound,
                          bool target_allow_inbound) {
    return caller_trusted_relay && caller_allow_outbound && target_allow_inbound;
}

}  // namespace yume::server::authorization
