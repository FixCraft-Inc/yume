/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <string_view>

#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
#include "basefwx/constants.hpp"
#endif

namespace yume {

constexpr const char kVersion[] = "2.0-dev4";
inline constexpr std::string_view kTransportVersion = kVersion;

#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
inline constexpr std::string_view kBasefwxVersion = basefwx::constants::kEngineVersion;
#else
inline constexpr std::string_view kBasefwxVersion = "disabled";
#endif

}  // namespace yume
