/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include "outbound/stream.hpp"

namespace yume::client {

using HelperProcessLifetime = outbound::HelperProcessLifetime;
using TlsConnectionMetadata = outbound::TlsConnectionMetadata;
using ClientTransportStream = outbound::ClientTransportStream;

}  // namespace yume::client
