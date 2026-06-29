/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <string>
#include <string_view>

namespace yume::identity {

std::string generate_endpoint_id();
std::string generate_display_name();
bool is_valid_hex_id(std::string_view value);
std::string sanitize_display_name(std::string_view value);
std::string derive_instance_key(std::string_view material);

}  // namespace yume::identity
