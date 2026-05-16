#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include <openssl/evp.h>

#include "core/crypto.hpp"

namespace yume::server {

struct AuthKeyPolicy {
    std::optional<bool> allow_exec;
    std::optional<bool> allow_local_ip;
    std::optional<bool> control_full;
    std::optional<bool> allow_inbound_admin;
    std::optional<bool> allow_outbound_admin;
    std::optional<bool> allow_chat;
    std::optional<bool> allow_file;
    std::optional<bool> allow_bytes;
    std::string federation_peer_id;

    bool empty() const;
};

using AuthKeyPolicyMap = std::unordered_map<std::string, AuthKeyPolicy>;

std::vector<crypto::Bytes> load_authorized_keys(const std::string& path);
AuthKeyPolicyMap load_auth_policies(const std::string& meta_path);

bool is_authorized(EVP_PKEY* pubkey, const std::vector<crypto::Bytes>& authorized);

crypto::Bytes read_field(const crypto::Bytes& payload, size_t& offset);

std::string fingerprint_pubkey(EVP_PKEY* pubkey);
std::string summarize_auth_policy(const AuthKeyPolicy& policy);
void update_auth_meta(const std::string& meta_path, const std::string& fingerprint, const std::string& alias = "");

}  // namespace yume::server
