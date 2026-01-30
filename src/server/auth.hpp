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

}  // namespace yume::server
