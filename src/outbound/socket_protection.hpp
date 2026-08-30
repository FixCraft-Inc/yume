/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <functional>

namespace yume::outbound {

// Optional embedder hook invoked after an outbound socket is opened and before
// connect(2). Android uses it to call VpnService.protect(fd), preventing the
// carrier connection from being routed back into its own VPN interface.
using SocketProtectCallback = std::function<bool(std::intptr_t)>;

}  // namespace yume::outbound
