/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */
#pragma once

#include <stdexcept>
#include <string>
#include <string_view>

namespace yume::config {

// Escapes one member name into an RFC 6901 pointer rooted at the document.
// Only "~" and "/" are special, and "~" must be replaced first so an escaped
// "/" is not re-escaped.
inline std::string member_pointer(std::string_view key) {
    std::string pointer = "/";
    for (const char character : key) {
        if (character == '~') {
            pointer += "~0";
        } else if (character == '/') {
            pointer += "~1";
        } else {
            pointer += character;
        }
    }
    return pointer;
}

// A configuration failure attributable to one document member. The pointer is
// the machine-readable half: callers locate the member with it and never by
// parsing the message. Failures that belong to no single member stay ordinary
// std::runtime_error, so an empty pointer is a fact, not a missing field.
class DocumentError : public std::runtime_error {
public:
    DocumentError(std::string json_pointer, const std::string& message)
        : std::runtime_error(message),
          json_pointer_(std::move(json_pointer)) {}

    const std::string& json_pointer() const noexcept { return json_pointer_; }

private:
    std::string json_pointer_;
};

// Convenience for the common case: the failing member is at the document root.
inline DocumentError member_error(std::string_view key,
                                  const std::string& message) {
    return DocumentError(member_pointer(key), message);
}

}  // namespace yume::config
