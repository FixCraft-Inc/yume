/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace yume::relay {

// RFC 4648 base64 with the standard alphabet and padding. Strings carry raw
// bytes here, as the stores that use this keep them.
std::string base64_encode(std::string_view raw);

// Decodes only the canonical encoding base64_encode produces: no whitespace,
// no URL-safe alphabet, exact padding and zero trailing bits. Anything else,
// including a second spelling of the same bytes, returns nullopt.
std::optional<std::string> base64_decode(std::string_view text);

}  // namespace yume::relay
