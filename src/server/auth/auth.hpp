/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <openssl/evp.h>

#include "core/security/crypto.hpp"
#include "core/security/secret_file.hpp"

namespace yume::server {

enum class AuthKeyType : std::uint8_t {
    Individual,
    Bulk,
};

struct AuthKeyPolicy {
    std::optional<bool> allow_exec;
    std::optional<bool> allow_local_ip;
    std::optional<bool> control_full;
    std::vector<std::string> allowed_codecs;
    std::vector<std::string> allowed_services;
    std::optional<bool> allow_inbound_admin;
    std::optional<bool> allow_outbound_admin;
    std::optional<bool> allow_chat;
    std::optional<bool> allow_file;
    std::optional<bool> allow_bytes;
    std::optional<double> weight;
    std::optional<std::uint32_t> max_sessions;
    AuthKeyType key_type{AuthKeyType::Individual};
    std::string federation_peer_id;
    // Loaded once with the authorization snapshot. Federation AUTH selects
    // this identity-bound PSK after verifying the composite signature, so
    // multiple peers never need to share the daemon's ordinary client PSK.
    std::shared_ptr<const security::Secret32> federation_psk_material;

    bool empty() const;
    double effective_weight() const;
};

using AuthKeyPolicyMap = std::unordered_map<std::string, AuthKeyPolicy>;

std::vector<crypto::Bytes> load_authorized_keys(const std::string& path);
AuthKeyPolicyMap load_auth_policies(const std::string& meta_path);
// Federation peer IDs are topology namespace identities, not display aliases.
// One label must map to exactly one authenticated visitor key across every
// visitor store loaded by a Manager.
void validate_unique_federation_peer_ids(
    const AuthKeyPolicyMap& policies);
void validate_unique_federation_peer_ids(
    const AuthKeyPolicyMap& regular,
    const AuthKeyPolicyMap& operators);

bool is_authorized(EVP_PKEY* pubkey, const std::vector<crypto::Bytes>& authorized);

// Membership test for a composite identity. Both halves must match the same
// stored entry -- matching only the Ed25519 half against one entry and the
// ML-DSA half against another would let two half-compromised keys be combined
// into an identity neither owner holds.
bool is_composite_authorized(const crypto::CompositePublicKey& key,
                             const std::vector<crypto::Bytes>& authorized);

// Loads the admin store. Separate from load_authorized_keys on purpose: the
// two lists must not be merged, because "second key from a separate list" is
// the property that makes accidental admin acquisition impossible.
std::vector<crypto::Bytes> load_admin_keys(const std::string& path);

crypto::Bytes read_field(const crypto::Bytes& payload, size_t& offset);

std::string fingerprint_pubkey(EVP_PKEY* pubkey);
const char* auth_key_type_name(AuthKeyType type);
std::string summarize_auth_policy(const AuthKeyPolicy& policy);
bool update_auth_meta(const std::string& meta_path,
                      const std::string& fingerprint,
                      const std::string& alias = "",
                      std::string* error = nullptr);

}  // namespace yume::server
