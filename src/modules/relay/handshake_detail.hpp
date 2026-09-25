/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <basefwx/crypto.hpp>

#include "modules/relay/handshake.hpp"

namespace yume::relay::detail {

// The handshake computations that take no randomness. They live here so the
// known-answer test can pin every frozen label with public synthetic inputs.
// handshake.cpp is their only other caller.

// "yume/relay/v2/request-signature/v1" || lp(unsigned_request)
basefwx::crypto::SecureBytes BuildRequestSignatureInput(const Bytes& unsigned_request);

// "yume/relay/v2/response-signature/v1" || lp(request) || lp(unsigned_response)
basefwx::crypto::SecureBytes BuildResponseSignatureInput(const Bytes& request,
                                                         const Bytes& unsigned_response);

// SHA-256 over "yume/relay/v2/request-digest/v1" || lp(request).
Bytes RequestDigest(const Bytes& request);

struct DerivedPair {
    basefwx::crypto::SecureBytes initial_root;
    basefwx::crypto::SecureBytes epoch_psk;
};

// The channel's initial root and epoch PSK from both records, the two hybrid
// shared secrets and the relay PSK, which is empty when the policy does not
// require one.
DerivedPair DeriveSecrets(const Bytes& request,
                          const Bytes& response,
                          const Bytes& mlkem_shared,
                          const Bytes& x25519_shared,
                          const Bytes& relay_psk);

}  // namespace yume::relay::detail
