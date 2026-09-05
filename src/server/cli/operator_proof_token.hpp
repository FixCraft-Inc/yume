/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <string>

namespace yume::server::cli {

inline constexpr std::size_t kMaxOperatorProofTokenBytes = 4096U;

// Loads the optional external proof credential from a descriptor-confined,
// owner-only file. The returned string contains secret material and must be
// wiped by its owner.
std::string load_operator_proof_token_file(const std::string& path);

}  // namespace yume::server::cli
