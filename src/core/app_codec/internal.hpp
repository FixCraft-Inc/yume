/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <string>
#include <string_view>

// Shared text helpers for the app-codec core and its built-in codecs. Not part
// of the public codec surface.
namespace yume::app_codec::detail {

std::string lower_ascii(std::string_view value);
std::string trim_ascii(std::string_view value);

}  // namespace yume::app_codec::detail
