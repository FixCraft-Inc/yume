/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <string>

#include "server/host/host_types.hpp"

namespace yume::server::host {

ExposureResult probe_exposure(const std::string& hostname, int port);

}  // namespace yume::server::host
