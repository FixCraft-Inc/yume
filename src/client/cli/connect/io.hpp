/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include "outbound/io.hpp"

namespace yume::client {

// Compatibility surface for CLI code. Neutral outbound helpers throw the
// transport-owned type; the CLI retains its established FatalError spelling
// without making neutral or server code depend on a CLI header.
using FatalError = outbound::TransportError;
using outbound::IoOpResult;
using outbound::ResolveOpResult;
using outbound::StopPredicate;
using outbound::ascii_preview;
using outbound::classify_http2_frame_prefix;
using outbound::classify_plaintext_prefix;
using outbound::connect_with_timeout;
using outbound::endpoint_hint_tls;
using outbound::handshake_with_timeout;
using outbound::hex_preview;
using outbound::looks_like_yume_header;
using outbound::read_exact_with_timeout;
using outbound::read_exact_with_timeout_prefetched;
using outbound::read_frame_with_timeout;
using outbound::read_some_with_timeout;
using outbound::read_until_with_timeout;
using outbound::resolve_with_timeout;
using outbound::stop_is_requested;
using outbound::write_all_with_timeout;

}  // namespace yume::client
