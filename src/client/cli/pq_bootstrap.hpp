/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <string>

#include "core/security/crypto.hpp"

namespace yume::client {

struct PqBootstrapInput {
    bool allow_bootstrap = false;
    bool inner_crypto_requested = false;
    bool pq_not_supported = false;
    bool pq_need_key = false;
    std::string pq_pub_b64;
    std::string pq_sig_b64;
    std::string cert_fingerprint;
    std::string peer_cert_fingerprint;
    std::string sub_cert_b64;
    std::string anonym_ca_cert;
};

struct PqBootstrapState {
    std::string pq_public_key;
    bool pq_reconnect = false;
    bool pq_reconnect_used = false;
    bool sub_ok = false;
    bool ca_ok = false;
    crypto::EVP_PKEY_ptr sub_pub{nullptr, EVP_PKEY_free};
    crypto::EVP_PKEY_ptr ca_pub{nullptr, EVP_PKEY_free};
};

PqBootstrapState maybe_auto_trust_pq(const PqBootstrapInput& input, PqBootstrapState state);

}  // namespace yume::client
