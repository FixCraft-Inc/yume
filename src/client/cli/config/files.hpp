/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <string>

namespace yume::client {

bool write_file_bytes(const std::string& path, const std::string& data, std::string* err);
bool read_file_bytes(const std::string& path, std::string* out, std::string* err);

}  // namespace yume::client
