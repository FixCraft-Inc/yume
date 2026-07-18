/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <string_view>

namespace yume::server::cli {

inline bool public_obfs_admission_valid(bool public_node,
                                        bool obfuscation,
                                        std::string_view obfs_secret) {
    return !public_node || (obfuscation && !obfs_secret.empty());
}

}  // namespace yume::server::cli
