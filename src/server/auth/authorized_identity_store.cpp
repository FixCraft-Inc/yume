/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/auth/authorized_identity_store.hpp"

namespace yume::server {

namespace {

bool is_pem_whitespace(char value) noexcept {
    return value == ' ' || value == '\t' || value == '\r' || value == '\n';
}

std::optional<std::string_view> take_public_pem_block(
    std::string_view contents,
    std::size_t* cursor,
    std::string* error) {
    while (*cursor < contents.size() && is_pem_whitespace(contents[*cursor])) {
        ++*cursor;
    }
    if (*cursor == contents.size()) return std::nullopt;

    static constexpr std::string_view kBegin = "-----BEGIN PUBLIC KEY-----";
    static constexpr std::string_view kEnd = "-----END PUBLIC KEY-----";
    if (!contents.substr(*cursor).starts_with(kBegin)) {
        if (error) *error = "authorized key store contains non-PEM data";
        return std::nullopt;
    }
    const std::size_t start = *cursor;
    const std::size_t end = contents.find(kEnd, start + kBegin.size());
    if (end == std::string_view::npos) {
        if (error) {
            *error = "authorized key store contains an unterminated PEM block";
        }
        return std::nullopt;
    }
    *cursor = end + kEnd.size();
    if (*cursor < contents.size() && !is_pem_whitespace(contents[*cursor])) {
        if (error) {
            *error = "authorized key store has trailing data after a PEM block";
        }
        return std::nullopt;
    }
    return contents.substr(start, *cursor - start);
}

}  // namespace

bool parse_authorized_identity_store(
    std::string_view contents,
    std::vector<AuthorizedIdentity>* identities,
    std::string* error) {
    if (!identities) {
        if (error) *error = "authorized identity destination is null";
        return false;
    }
    identities->clear();
    if (error) error->clear();
    std::size_t cursor = 0;
    while (true) {
        const auto classical = take_public_pem_block(contents, &cursor, error);
        if (!classical.has_value()) {
            if (cursor == contents.size()) return true;
            return false;
        }
        const auto pq = take_public_pem_block(contents, &cursor, error);
        if (!pq.has_value()) {
            if (error && error->empty()) {
                *error = "authorized key store contains an incomplete "
                         "composite identity";
            }
            return false;
        }

        crypto::Bytes bundle(classical->begin(), classical->end());
        bundle.push_back('\n');
        bundle.insert(bundle.end(), pq->begin(), pq->end());
        auto composite = crypto::parse_composite_identity(bundle);
        if (!composite.valid()) {
            if (error) {
                *error = "every authorized entry must be an Ed25519 public "
                         "key followed by an ML-DSA-87 public key";
            }
            return false;
        }

        AuthorizedIdentity identity;
        identity.canonical = crypto::composite_canonical_encoding(composite);
        identity.fingerprint =
            crypto::composite_fingerprint_from_canonical(identity.canonical);
        const auto normalized = crypto::encode_composite_identity(
            composite.classical.get(), composite.pq.get());
        identity.pem.assign(normalized.begin(), normalized.end());
        if (identity.pem.empty() || identity.pem.back() != '\n') {
            identity.pem.push_back('\n');
        }
        identities->push_back(std::move(identity));
    }
}

std::string serialize_authorized_identity_store(
    const std::vector<AuthorizedIdentity>& identities,
    std::optional<std::size_t> skip) {
    std::string serialized;
    for (std::size_t index = 0; index < identities.size(); ++index) {
        if (skip.has_value() && *skip == index) continue;
        serialized += identities[index].pem;
    }
    return serialized;
}

}  // namespace yume::server
