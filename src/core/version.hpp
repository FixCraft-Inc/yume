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

// Current development identity. AUTH, relay, ABI, and helper IPC schema
// versions remain independent constants in their owning modules.
constexpr const char kVersion[] = "0.2.0-dev6";
inline constexpr std::string_view kTransportVersion = kVersion;
// dev6 intentionally supports one evidence-backed outer transport identity.
// This value is authenticated during admission and AUTH and is also bound into
// establishment and per-frame AEAD. Supporting another identity requires a
// deliberate protocol revision rather than a cosmetic configuration alias.
inline constexpr std::string_view kTransportProfile =
    "chrome151-node24-v1";

#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
inline constexpr std::string_view kBasefwxVersion = basefwx::constants::kEngineVersion;
#else
inline constexpr std::string_view kBasefwxVersion = "disabled";
#endif

}  // namespace yume
