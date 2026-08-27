/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace yume::facade::keys {

// A freshly-generated or imported keypair. Files at private_path and
// public_path are written in PEM format. fingerprint is SHA-256 hex over
// the DER-encoded public key (matches server::fingerprint_pubkey output).
struct KeyPair {
    std::filesystem::path private_path;
    std::filesystem::path public_path;
    std::string fingerprint;
    std::string algorithm;  // "composite-ed25519-mldsa87" or "ml-kem-768"
};

// Generates a YUME identity into <dir>/<base_name>.key and
// <dir>/<base_name>.pub. A YUME identity is composite — Ed25519 alongside
// ML-DSA-87, both required — and each file holds the two PEM blocks
// concatenated in that fixed order, which is what the server's
// authorized-key stores expect. Existing files at those paths are NOT
// overwritten; the caller must move/remove them first. Returns nullopt on
// failure with *err populated.
std::optional<KeyPair> generate_identity(std::filesystem::path const& dir,
                                         std::string const& base_name,
                                         std::string* err);

// Wraps yume::inner::generate_pq_keypair() to produce an ML-KEM-768
// keypair at the given paths. Returns nullopt if BaseFWX/PQ support is
// not compiled in or generation fails.
std::optional<KeyPair> generate_ml_kem_768(
    std::filesystem::path const& private_path,
    std::filesystem::path const& public_path,
    std::string* err);

// Computes the SHA-256 fingerprint of an Ed25519 public key PEM. Matches
// the on-the-wire fingerprint used by server::auth.
std::optional<std::string> fingerprint_pubkey_file(
    std::filesystem::path const& pub_path, std::string* err);

// A line of authorized_keys plus its parsed metadata.
struct AuthorizedKeyEntry {
    std::string fingerprint;
    std::string alias;
    std::string algorithm;      // typically "ed25519"
    std::string pem;            // full PEM block (PUBLIC KEY)
    std::string federation_peer_id;
    // Path written to auth_keys.meta. Relative paths are resolved from that
    // metadata file by yumed. Required whenever federation_peer_id is set and
    // must already satisfy yumed's protected 32-byte secret-file contract when
    // an entry is appended or updated.
    std::string federation_psk_file;
    // Update patches preserve both federation strings when they are empty.
    // Set this explicit operation flag to remove both fields atomically; it is
    // invalid on append or together with either non-empty federation field.
    bool clear_federation_enrollment{false};
    // Empty key_type in an update patch means "preserve". Listed/new metadata
    // is normalized to "individual" by the facade implementation.
    std::string key_type;
    std::optional<double> weight;
    std::optional<std::uint32_t> max_sessions;

    // permission overrides; nullopt means "inherit server default"
    std::optional<bool> allow_exec;
    std::optional<bool> allow_local_ip;
    std::optional<bool> control_full;
    std::optional<bool> allow_inbound_admin;
    std::optional<bool> allow_outbound_admin;
    std::optional<bool> allow_chat;
    std::optional<bool> allow_file;
    std::optional<bool> allow_bytes;
    std::vector<std::string> allow_codecs;
    std::vector<std::string> allow_services;
};

// Reads authorized_keys + meta. Lines starting with `#` are comments.
std::vector<AuthorizedKeyEntry> list_authorized(
    std::filesystem::path const& auth_keys_file,
    std::filesystem::path const& meta_file);

// Appends a new authorized key. Validates the PEM, computes the
// fingerprint, refuses duplicates. The alias / permissions are persisted
// to the meta file.
bool append_authorized(std::filesystem::path const& auth_keys_file,
                       std::filesystem::path const& meta_file,
                       std::filesystem::path const& admin_keys_file,
                       std::string const& pem,
                       AuthorizedKeyEntry const& entry_meta,
                       std::string* err);

// Removes the entry whose fingerprint matches. Also strips the
// corresponding meta entry. Returns false if not found.
bool remove_authorized(std::filesystem::path const& auth_keys_file,
                       std::filesystem::path const& meta_file,
                       std::string const& fingerprint,
                       std::string* err);

// Updates metadata for an existing authorized key. Federation enrollment can
// be removed only through patch.clear_federation_enrollment; empty federation
// strings preserve their current values. The PEM file is not modified.
bool update_authorized(std::filesystem::path const& auth_keys_file,
                       std::filesystem::path const& meta_file,
                       std::string const& fingerprint,
                       AuthorizedKeyEntry const& patch,
                       std::string* err);

}  // namespace yume::facade::keys
