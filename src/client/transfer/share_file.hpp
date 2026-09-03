/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace yume::share {

// On-wire structure of a .yss ("yume secure store") file:
//
//   [ 8 bytes ] "YUMESHRE"                 — magic (stable file
//                                             signature; the name is
//                                             historical, the bytes
//                                             never change)
//   [ 1 byte  ] version       (currently 1) — wire format revision
//   [ 1 byte  ] bundle type   (0 = backup)  — semantics of the inner JSON
//   [ 2 bytes ] reserved      (=0)          — for future flags
//   [ N bytes ] FwxAES blob                 — BaseFWX-encrypted JSON
//                                             (Argon2id KDF + AES-GCM,
//                                              same crypto as the rest
//                                              of BaseFWX)
//
// The 12-byte header is the only unencrypted material; anyone who can
// open the file learns it's a .yss blob and nothing else. The
// FwxAES blob carries its own salt + nonce + auth tag, so wrong-
// password attempts fail at the GCM tag check.
constexpr std::uint8_t kFormatVersion = 1;
// BaseFWX FwxAES currently enforces the same minimum. Kept public so every
// YUME exporter can reject weak/invalid input before starting the KDF.
constexpr std::size_t kPasswordMin = 12;
constexpr std::size_t kMaxShareFileBytes = 16U * 1024U * 1024U;

enum class BundleType : std::uint8_t {
    Backup = 0,  // personal backup / device migration; contains the
                 // operator's own private auth key. Recipient becomes
                 // (or stays) the same user on the target server.
};

// Operator-configured/OOB relay-v2 pins only. Learned TOFU state is local
// runtime state and is deliberately not representable in a share bundle.
using RelayPeerPins = std::map<std::string, std::string>;

// All fields are optional except server.host + server.port.
// Anything not set at export time is omitted from the bundle JSON so
// older or future fields don't pollute. Importer ignores unknown fields.
struct ShareBundle {
    ShareBundle() = default;
    ShareBundle(const ShareBundle& other);
    ShareBundle& operator=(const ShareBundle& other);
    ShareBundle(ShareBundle&& other);
    ShareBundle& operator=(ShareBundle&& other);
    ~ShareBundle();

    void clear_secrets() noexcept;

    BundleType type{BundleType::Backup};
    std::string created_at_iso8601;          // e.g. "2026-05-25T10:39:10Z"
    std::string created_by;                  // e.g. "yume 1.1 (linux-x86_64)"
    std::string label;                       // free-text, optional

    // server endpoint
    std::string server_host;                 // required
    int         server_port{443};            // required

    // private auth key — required for Backup type
    std::string auth_private_key_pem;        // Ed25519 PRIVATE KEY PEM

    // stealth knobs
    bool        obfuscation{true};
    std::string obfs_secret;
    std::string inner_psk;
    std::uint16_t obfs_pad_multiple{0};
    std::uint32_t obfs_jitter_ms{0};
    std::string tls_pin_sha256;              // empty = no pin
    std::string tls_stealth_profile;         // empty = default (chrome)
    std::string tls_ca_cert_pem;              // empty = system trust store
    std::string tls_server_name;              // empty = server_host

    // Operator-identity trust material / PQ (legacy serialized field names).
    std::string anonym_ca_cert_pem;          // empty = none
    std::string anonym_pubkey;               // empty = none
    std::string pq_public_key_pem;           // empty = none

    // client behavior recommendations
    bool inner_crypto{true};
    std::uint8_t tunnel_count{1};
    bool require_operator_identity{false};
    bool allow_udp{false};
    bool allow_local_ip{false};

    // End-to-end relay peer trust policy. `relay_trust_dir` is intentionally
    // absent: imports use the platform-local configured/default trust store;
    // neither its path nor learned TOFU records are portable authorization.
    std::string relay_trust_mode{"tofu"};
    RelayPeerPins relay_peer_pins;
};

// Encode + encrypt to bytes ready to write to disk. New exports require
// kPasswordMin characters so validation matches BaseFWX before its KDF runs.
// Returns the full file contents including the 12-byte unencrypted
// magic+version header.
std::vector<std::uint8_t> encode_share(const ShareBundle& bundle,
                                       const std::string& password,
                                       std::string* error);

// Parse + decrypt. Returns nullopt on any failure (wrong magic, wrong
// version, wrong password, malformed JSON). On nullopt, *error is set
// to a single-line user-facing message.
std::optional<ShareBundle> decode_share(const std::vector<std::uint8_t>& blob,
                                        const std::string& password,
                                        std::string* error);

// Inspect the unencrypted header WITHOUT decrypting. Useful for
// "this file is a .yss v1 backup; enter the password" UX
// before prompting. Returns false if magic / version don't validate.
struct ShareFileHeader {
    std::uint8_t version{0};
    BundleType   type{BundleType::Backup};
};
bool peek_share_header(const std::vector<std::uint8_t>& blob,
                       ShareFileHeader* out);

// Shared CLI/GUI persistence boundary. Reads are bounded before allocation and
// never follow the final path component. Writes create a new owner-only file,
// refuse overwrite/reparse targets, flush before success, and clean partials.
bool read_share_file(const std::filesystem::path& path,
                     std::vector<std::uint8_t>* contents,
                     std::string* error);
bool write_share_file_exclusive(const std::filesystem::path& path,
                                std::span<const std::uint8_t> contents,
                                std::string* error);

// ─── orchestration helpers (no UI, sync; shared by CLI + GUI) ──────────────

// Inputs to build_backup_bundle: client-side config fields that map
// directly into the bundle, plus paths to the key/cert files that
// must be slurped at export time. Pass empty strings for any path
// that doesn't apply. Caller fills this from ClientConfig (CLI) or
// from the GUI's working state.
struct BackupInputs {
    BackupInputs() = default;
    BackupInputs(const BackupInputs&) = delete;
    BackupInputs& operator=(const BackupInputs&) = delete;
    BackupInputs(BackupInputs&&) = delete;
    BackupInputs& operator=(BackupInputs&&) = delete;
    ~BackupInputs();

    // Display label + provenance (optional but nice in the summary)
    std::string label;
    std::string created_by;       // e.g. "yume 1.1 (linux-x86_64)"
    // Server endpoint (required)
    std::string server_host;
    int         server_port{443};
    // Paths to files to slurp into the bundle. All are optional; an
    // info-only bundle can intentionally omit the private identity key.
    std::string identity_path;
    std::string anonym_ca_cert_path;
    std::string tls_ca_cert_path;
    std::string pq_public_key_path;
    std::string obfs_secret_path;
    std::string inner_psk_path;
    // Inline legacy value (accepted only when no protected file is set).
    std::string obfs_secret;
    std::string tls_pin_sha256;
    std::string tls_stealth_profile;
    std::string tls_server_name;
    std::string anonym_pubkey;
    // Stealth + client-behavior flags
    bool          obfuscation{true};
    std::uint16_t obfs_pad_multiple{0};
    std::uint32_t obfs_jitter_ms{0};
    bool          inner_crypto{true};
    std::uint8_t tunnel_count{1};
    bool          require_operator_identity{false};
    bool          allow_udp{false};
    bool          allow_local_ip{false};

    // Explicit/OOB pins are portable. The learned TOFU directory/store is not.
    std::string   relay_trust_mode{"tofu"};
    RelayPeerPins relay_peer_pins;
};

// Build a ShareBundle from the inputs above by reading the referenced
// PEM files into memory and copying scalar fields. Returns false if a
// required file (identity_path) is missing or unreadable. On success
// `*out` is the bundle ready to pass to encode_share.
bool build_backup_bundle(const BackupInputs& in, ShareBundle* out, std::string* error);

// Outputs from apply_imported_bundle.
struct ApplyResult {
    std::string target_dir;      // e.g. ~/.yume/imported/<host>
    std::string config_path;     // <target_dir>/config.json
    std::string identity_path;   // <target_dir>/identity.key (if any)
    std::string anonym_ca_path;  // <target_dir>/anonym_ca.pem (if any)
    std::string tls_ca_path;     // <target_dir>/tls_ca.pem (if any)
    std::string pq_public_path;  // <target_dir>/pq_public.key (if any)
    std::string obfs_secret_path;// <target_dir>/admission.hex (if any)
    std::string inner_psk_path;  // <target_dir>/inner-psk.hex (if any)
};

// Transactionally publish extracted bundle contents under the user's home
// (~/.yume/imported/<server-host>/). POSIX persistence walks HOME and all
// managed path components descriptor-relative without following links,
// requires owner-controlled directories, stages 0600 files in a 0700
// directory, fsyncs them, and atomically publishes the complete directory.
// Existing imports are replaced only where an atomic directory exchange is
// supported. Decode/inspection remain portable, but persistence fails closed
// on platforms (including Windows) without the required secure filesystem
// semantics. Always writes a config.json pointing at the published files so
// the operator can `yume --config <config_path>` directly.
bool apply_imported_bundle(const ShareBundle& bundle,
                           ApplyResult* out,
                           std::string* error);

}  // namespace yume::share
