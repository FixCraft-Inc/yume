/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

#include <openssl/ssl.h>

#include "core/security/auth_v2.hpp"

namespace yume::security {

// The AUTH codec owns the length; this header owns how the value is produced.
using auth_v2::kChannelBindingLen;

// RFC 8446 section 7.5 exporter label. Versioned like every other YUME domain
// string: changing what the exporter covers means a new label, never an edit
// in place.
inline constexpr std::string_view kAuthChannelBindingLabel =
    "EXPORTER-yume/2.0/auth-channel-binding/v1";

// Derives this endpoint's view of the live TLS 1.3 connection.
//
// Both peers compute the value from their own completed handshake and it is
// never carried on the wire, so a malicious endpoint that terminates TLS with
// the client cannot make its client-facing exporter equal the one on a second
// connection it opens to a real server. Feeding the result into the AUTH
// signature transcript is what stops a live AUTH exchange from being relayed.
//
// Throws when the SSL object is missing, is not TLS 1.3, or has not finished
// its handshake. There is deliberately no unbound fallback: a caller that
// cannot compute the binding must fail the connection.
std::vector<std::uint8_t> ExportChannelBinding(SSL* ssl);

}  // namespace yume::security
