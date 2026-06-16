/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <string>
#include <vector>

namespace yume::server_cli {

struct AnonymProof {
    std::string hash;
    std::string sig;
    std::string ts;
    std::string nonce;
    std::string certfp;
    std::string ca_sig;
    std::string ca_alg;
    std::string sub_sig;
    std::string sub_alg;
    std::string sub_cert_b64;
    std::string proof_policy;
    std::vector<std::string> proof_sources;
    std::string pq_pub_b64;
    std::string pq_sig;
    std::string pq_alg;
};

bool anonym_local_sign_default();
std::string derive_pq_public_path(const std::string& pq_private_path);
bool load_pq_public_b64(const std::string& pq_public_path, std::string* out_b64);
bool sign_pq_pub_with_key(const std::string& pq_pub_b64,
                          const std::string& certfp,
                          const std::string& key_path,
                          std::string* out_sig_b64,
                          std::string* out_alg);
long long parse_proof_ts(const std::string& ts, long long fallback);

AnonymProof fetch_anonym_proof(const std::string& hash,
                               const std::string& certfp,
                               const std::string& proof_mode,
                               const std::string& api_url,
                               const std::string& token,
                               const std::string& ca_key_path,
                               const std::string& sub_key_path,
                               const std::string& sub_cert_path,
                               const std::string& pq_public_path,
                               const std::string& pq_sign_key_path,
                               bool enable_local_sign,
                               const std::string& outbound_proxy_url);

}  // namespace yume::server_cli
