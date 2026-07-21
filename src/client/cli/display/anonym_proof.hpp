/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <string>
#include <vector>

#include "core/security/crypto.hpp"

namespace yume::client {

// The legacy wire/config name is "anonym", but this proof has a deliberately
// narrower security meaning: it authenticates that the endpoint signing key
// is authorized by a CA selected by the client. It cannot establish that the
// server operator does not inspect, retain, or correlate traffic.

struct AnonymProofInput {
    std::vector<std::string> announced_proof_sources;
    std::string hash;
    std::string sig;
    std::string ts;
    std::string nonce;
    std::string certfp;
    std::string ca_sig;
    std::string sub_sig;
    std::string sub_cert_b64;
    std::string anonym_pubkey;
    std::string anonym_ca_cert;
    std::string peer_cert_fingerprint;
    bool initial_sub_ok = false;
    bool initial_ca_ok = false;
};

// Historical type name retained for wire/source compatibility. The result
// proves only that a server key is authorized by a client-selected operator
// CA. It does not prove anonymity, non-monitoring, or non-logging behavior.

struct AnonymProofResult {
    bool fixcraft_ok = false;
    bool sub_ok = false;
    bool ca_ok = false;
    crypto::EVP_PKEY_ptr sub_pub{nullptr, EVP_PKEY_free};
    crypto::EVP_PKEY_ptr ca_pub{nullptr, EVP_PKEY_free};
    std::string operator_ca_subject;
    std::string operator_ca_fingerprint_sha256;
    std::string delegated_subject;
    std::string delegated_issuer;
    std::string delegated_serial;
    std::string delegated_fingerprint_sha256;
    std::vector<std::string> verified_proof_sources;
    std::vector<std::string> error_lines;
};

AnonymProofResult verify_anonym_proof(const AnonymProofInput& input);

}  // namespace yume::client
