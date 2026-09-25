/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace yume::relay::json_policy {

// Parsers own field limits, validation order, and diagnostic wording. Keep
// these shared predicates free of mutation so the first-error order is explicit.
template <std::size_t Size>
bool has_only_known_fields(
    const nlohmann::json& json,
    const std::array<std::string_view, Size>& known) {
    if (!json.is_object() || json.size() > known.size()) return false;
    for (auto it = json.begin(); it != json.end(); ++it) {
        if (std::find(known.begin(), known.end(), it.key()) == known.end()) {
            return false;
        }
    }
    return true;
}

// Limits count bytes. C0 controls and DEL are refused, while high bytes used
// by non-ASCII names are preserved. Identifier grammar belongs to each parser.
inline bool is_safe_text(std::string_view value,
                         std::size_t max_bytes,
                         bool allow_empty) noexcept {
    if (value.size() > max_bytes || (!allow_empty && value.empty())) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](unsigned char byte) {
        return byte >= 0x20U && byte != 0x7fU;
    });
}

inline bool required_string(const nlohmann::json& json,
                            const char* key,
                            std::size_t max_bytes,
                            bool allow_empty) {
    return json.contains(key) && json[key].is_string() &&
           is_safe_text(json[key].get_ref<const std::string&>(), max_bytes,
                        allow_empty);
}

inline bool optional_string(const nlohmann::json& json,
                            const char* key,
                            std::size_t max_bytes,
                            bool allow_empty = true) {
    return !json.contains(key) ||
           (json[key].is_string() &&
            is_safe_text(json[key].get_ref<const std::string&>(), max_bytes,
                         allow_empty));
}

inline bool required_bool(const nlohmann::json& json, const char* key) {
    return json.contains(key) && json[key].is_boolean();
}

inline bool optional_bool(const nlohmann::json& json, const char* key) {
    return !json.contains(key) || json[key].is_boolean();
}

inline bool is_known_client_platform(std::string_view value) noexcept {
    return value == "linux" || value == "windows" || value == "macos" ||
           value == "android" || value == "unknown";
}

inline bool is_known_client_variant(std::string_view value) noexcept {
    return value == "cli" || value == "android_vpn" || value == "unknown";
}

// Rejection must remain nonthrowing even if retaining its diagnostic fails.
inline void set_error(std::string* error, std::string_view message) noexcept {
    if (!error) return;
    try {
        error->assign(message);
    } catch (...) {
    }
}

}  // namespace yume::relay::json_policy
