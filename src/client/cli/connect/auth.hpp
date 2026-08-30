/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include "client/cli/connect/io.hpp"
#include "outbound/auth.hpp"

namespace yume::client {

using outbound::kAuthChallengeTimeout;
using outbound::kConnectTimeout;
using outbound::kHandshakeTimeout;
using outbound::kServerInfoTimeout;
using outbound::kServerInfoTimeoutInner;
using outbound::kServerInfoTimeoutInnerHeavy;
using outbound::open_auth_ok_v2;
using outbound::perform_h2_carrier_handshake;
using outbound::read_auth_challenge;
using outbound::read_frame_over_h2_with_timeout;
using outbound::require_h2_carrier_alpn;
using outbound::send_auth_v2_response;
using outbound::send_frame_over_h2_with_timeout;

}  // namespace yume::client
