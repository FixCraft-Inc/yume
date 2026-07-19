/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <string>
#include <string_view>

#include "core/release/version_report.hpp"

namespace yume::release {

std::string render_brand_header(std::string_view section,
                                bool colors_enabled);
std::string render_version_report(const VersionReport& report,
                                  std::string_view title,
                                  bool colors_enabled);
void print_version_report(std::string_view title);

}  // namespace yume::release
