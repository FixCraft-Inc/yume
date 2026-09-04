/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */
#pragma once

#include <algorithm>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

#include "config/document_error.hpp"

namespace yume::config {

// A key that an earlier development wire accepted and that is now refused
// with the reason, so an operator learns what to change instead of reading
// "unknown key". Nothing here is parsed, ignored, or stripped on save.
struct RetiredDocumentKey {
    std::string_view key;
    std::string_view reason;
};

// Returns the first key-set problem in `document`, or nullopt when every key
// is known and current. A non-object root is reported by the caller, which
// owns the wording for its own dialect.
//
// The key set is closed on purpose. An open key set is a silent security
// downgrade: a misspelled "tls_pin" would parse as "no pin" and the client
// would connect unpinned.
inline std::optional<DocumentError> document_key_error(
    const nlohmann::json& document,
    std::span<const std::string_view> known,
    std::span<const RetiredDocumentKey> retired,
    std::string_view dialect) {
    if (!document.is_object()) {
        return std::nullopt;
    }
    for (const auto& item : document.items()) {
        const std::string_view key = item.key();
        const auto match = std::find_if(
            retired.begin(), retired.end(),
            [key](const RetiredDocumentKey& candidate) {
                return candidate.key == key;
            });
        if (match != retired.end()) {
            return member_error(
                key, std::string(key) + ": " + std::string(match->reason));
        }
        if (std::find(known.begin(), known.end(), key) == known.end()) {
            return member_error(key, "unknown " + std::string(dialect) +
                                         " config key: " + std::string(key));
        }
    }
    return std::nullopt;
}

}  // namespace yume::config
