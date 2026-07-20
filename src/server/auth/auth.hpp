/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <openssl/evp.h>

#include "core/security/crypto.hpp"

namespace yume::server {

enum class AuthKeyType : std::uint8_t {
    Individual,
    Bulk,
};

struct AuthKeyPolicy {
    std::optional<bool> allow_exec;
    std::optional<bool> allow_local_ip;
    std::optional<bool> control_full;
    std::optional<bool> allow_monero_rpc;
    std::vector<std::string> allowed_codecs;
    std::vector<std::string> allowed_services;
    std::optional<bool> allow_inbound_admin;
    std::optional<bool> allow_outbound_admin;
    std::optional<bool> allow_chat;
    std::optional<bool> allow_file;
    std::optional<bool> allow_bytes;
    std::optional<std::uint32_t> priority;
    std::optional<double> weight;
    std::optional<std::uint32_t> max_sessions;
    AuthKeyType key_type{AuthKeyType::Individual};
    std::string federation_peer_id;

    bool empty() const;
    double effective_weight() const;
};

using AuthKeyPolicyMap = std::unordered_map<std::string, AuthKeyPolicy>;

std::vector<crypto::Bytes> load_authorized_keys(const std::string& path);
AuthKeyPolicyMap load_auth_policies(const std::string& meta_path);

bool is_authorized(EVP_PKEY* pubkey, const std::vector<crypto::Bytes>& authorized);

crypto::Bytes read_field(const crypto::Bytes& payload, size_t& offset);

std::string fingerprint_pubkey(EVP_PKEY* pubkey);
const char* auth_key_type_name(AuthKeyType type);
std::string summarize_auth_policy(const AuthKeyPolicy& policy);
void update_auth_meta(const std::string& meta_path, const std::string& fingerprint, const std::string& alias = "");

}  // namespace yume::server
