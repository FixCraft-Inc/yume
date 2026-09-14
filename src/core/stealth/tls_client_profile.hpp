/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include "core/stealth/tls_fingerprint.hpp"

#include <openssl/types.h>

#include <string>
#include <vector>

namespace yume::tls_stealth {

// Configures a fresh caller-owned SSL_CTX from the generated cover registry.
// Current callers create SSL_CTX in OpenSSL's process-default library context;
// injected extension entropy uses that same context. This is outer TLS shaping,
// independent of the private-context YTP session-security provider.
// Native mode requires the patched ClientHello support and throws if required
// shaping is unavailable. Diagnostic mode returns divergences on success;
// callers own logging. On failure discard the partially configured context.
// Offering the browser's TLS/ALPN range does not authorize a negotiated
// transport: each caller must enforce its required version and protocol.
// Diagnostic mode serves clienthello_dump and the CLI's explicit diagnostic
// backend, exercised by tests/test_yume_native_tls_wire.py.
std::vector<std::string> configure_client_profile(
    SSL_CTX* context, tls_fingerprint::BrowserProfile profile,
    bool native_chrome_client_hello);

}  // namespace yume::tls_stealth
