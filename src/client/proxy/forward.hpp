/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include "outbound/forward.hpp"

namespace yume::client {

using ForwardSession = outbound::ForwardSession;
using LocalForwardSession = outbound::LocalForwardSession;
using ReverseForwardSession = outbound::ReverseForwardSession;
using ForwardServer = outbound::ForwardServer;
using UdpForwardServer = outbound::UdpForwardServer;

}  // namespace yume::client
