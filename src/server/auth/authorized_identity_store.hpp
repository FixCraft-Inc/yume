/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include "core/security/crypto.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yume::server {

// One canonical composite authorization entry. Keeping this record and its
// parser shared prevents the daemon CLI and desktop key manager from assigning
// different identity or fingerprint semantics to the same store.
struct AuthorizedIdentity {
    crypto::Bytes canonical;
    std::string pem;
    std::string fingerprint;
};

bool parse_authorized_identity_store(
    std::string_view contents,
    std::vector<AuthorizedIdentity>* identities,
    std::string* error = nullptr);

std::string serialize_authorized_identity_store(
    const std::vector<AuthorizedIdentity>& identities,
    std::optional<std::size_t> skip = std::nullopt);

}  // namespace yume::server
