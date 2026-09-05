/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace yume::server {

// Daemon loading and key-management edits use the same closed schema.
// Permissions belong under "permissions" so a second spelling cannot mask
// a misspelled or conflicting policy.
inline bool validate_auth_metadata_json_types(const nlohmann::json& metadata,
                                              std::string* error) {
    if (error) error->clear();
    if (!metadata.is_object()) {
        if (error) *error = "auth metadata root must be an object";
        return false;
    }
    constexpr const char* kBooleanKeys[] = {
        "allow_exec",          "allow_local_ip",      "control_full",
        "allow_inbound_admin", "allow_outbound_admin",
        "allow_chat",          "allow_file",          "allow_bytes",
    };
    constexpr const char* kStringArrayKeys[] = {
        "allow_codecs", "allow_services",
    };
    constexpr auto kEntryKeys = std::to_array<std::string_view>({
        "alias", "last_seen", "permissions", "weight", "max_sessions",
        "key_type", "federation_peer_id", "federation_psk_file",
    });

    const auto validate_policy_object = [&](const nlohmann::json& policy,
                                            const std::string& prefix) {
        for (auto it = policy.begin(); it != policy.end(); ++it) {
            const auto matches = [&](const char* key) { return it.key() == key; };
            if (!std::any_of(std::begin(kBooleanKeys), std::end(kBooleanKeys),
                             matches) &&
                !std::any_of(std::begin(kStringArrayKeys),
                             std::end(kStringArrayKeys), matches)) {
                if (error) *error = prefix + "unknown field " + it.key();
                return false;
            }
        }
        for (const char* key : kBooleanKeys) {
            const auto it = policy.find(key);
            if (it != policy.end() && !it->is_boolean()) {
                if (error) *error = prefix + key + " must be a boolean";
                return false;
            }
        }
        for (const char* key : kStringArrayKeys) {
            const auto it = policy.find(key);
            if (it == policy.end()) continue;
            if (!it->is_array()) {
                if (error) *error = prefix + key + " must be an array";
                return false;
            }
            if (!std::all_of(it->begin(), it->end(),
                             [](const nlohmann::json& item) {
                                 return item.is_string();
                             })) {
                if (error) *error = prefix + key + " entries must be strings";
                return false;
            }
        }
        return true;
    };

    for (auto it = metadata.begin(); it != metadata.end(); ++it) {
        const auto& entry = it.value();
        const std::string prefix = "auth metadata entry '" + it.key() + "' ";
        if (!entry.is_object()) {
            if (error) *error = prefix + "must be an object";
            return false;
        }
        for (auto field = entry.begin(); field != entry.end(); ++field) {
            if (std::find(kEntryKeys.begin(), kEntryKeys.end(), field.key()) ==
                kEntryKeys.end()) {
                if (error) *error = prefix + "unknown field " + field.key();
                return false;
            }
        }
        const auto alias = entry.find("alias");
        if (alias != entry.end() && !alias->is_string()) {
            if (error) *error = prefix + "alias must be a string";
            return false;
        }
        const auto last_seen = entry.find("last_seen");
        if (last_seen != entry.end()) {
            bool representable = false;
            if (last_seen->is_number_unsigned()) {
                representable = last_seen->get<std::uint64_t>() <=
                                static_cast<std::uint64_t>(
                                    std::numeric_limits<long long>::max());
            } else if (last_seen->is_number_integer()) {
                (void)last_seen->get<std::int64_t>();
                representable = true;
            }
            if (!representable) {
                if (error) *error = prefix + "last_seen must be an integer";
                return false;
            }
        }
        const auto permissions = entry.find("permissions");
        if (permissions != entry.end() && !permissions->is_object()) {
            if (error) *error = prefix + "permissions must be an object";
            return false;
        }
        if (permissions != entry.end() &&
            !validate_policy_object(*permissions, prefix + "permissions ")) {
            return false;
        }
        const auto weight = entry.find("weight");
        if (weight != entry.end() && !weight->is_number()) {
            if (error) *error = prefix + "weight must be a number";
            return false;
        }
        const auto max_sessions = entry.find("max_sessions");
        if (max_sessions != entry.end() &&
            !max_sessions->is_number_integer() &&
            !max_sessions->is_number_unsigned()) {
            if (error) *error = prefix + "max_sessions must be an integer";
            return false;
        }
        for (const char* key : {"key_type", "federation_peer_id",
                                "federation_psk_file"}) {
            const auto value = entry.find(key);
            if (value != entry.end() && !value->is_string()) {
                if (error) *error = prefix + key + " must be a string";
                return false;
            }
        }
    }
    return true;
}

}  // namespace yume::server
