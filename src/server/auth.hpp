#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include <openssl/evp.h>

#include "core/crypto.hpp"

namespace yume::server {

std::vector<crypto::Bytes> load_authorized_keys(const std::string& path);

bool is_authorized(EVP_PKEY* pubkey, const std::vector<crypto::Bytes>& authorized);

crypto::Bytes read_field(const crypto::Bytes& payload, size_t& offset);

std::string fingerprint_pubkey(EVP_PKEY* pubkey);
void update_auth_meta(const std::string& meta_path, const std::string& fingerprint, const std::string& alias = "");

}  // namespace yume::server
