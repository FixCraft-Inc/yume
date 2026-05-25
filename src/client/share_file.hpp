/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace yume::share {

// On-wire structure of a .yume-share file:
//
//   [ 8 bytes ] "YUMESHRE"                 — magic
//   [ 1 byte  ] version       (currently 1) — wire format revision
//   [ 1 byte  ] bundle type   (0 = backup)  — semantics of the inner JSON
//   [ 2 bytes ] reserved      (=0)          — for future flags
//   [ N bytes ] FwxAES blob                 — BaseFWX-encrypted JSON
//                                             (Argon2id KDF + AES-GCM,
//                                              same crypto as the rest
//                                              of BaseFWX)
//
// The 12-byte header is the only unencrypted material; anyone who can
// open the file learns it's a yume-share blob and nothing else. The
// FwxAES blob carries its own salt + nonce + auth tag, so wrong-
// password attempts fail at the GCM tag check.
constexpr std::uint8_t kFormatVersion = 1;

enum class BundleType : std::uint8_t {
    Backup = 0,  // personal backup / device migration; contains the
                 // operator's own private auth key. Recipient becomes
                 // (or stays) the same user on the target server.
};

// All fields are optional EXCEPT server.host + server.port + auth.private_key_pem.
// Anything not set at export time is omitted from the bundle JSON so
// older or future fields don't pollute. Importer ignores unknown fields.
struct ShareBundle {
    BundleType type{BundleType::Backup};
    std::string created_at_iso8601;          // e.g. "2026-05-25T10:39:10Z"
    std::string created_by;                  // e.g. "yume 1.0 (linux-x86_64)"
    std::string label;                       // free-text, optional

    // server endpoint
    std::string server_host;                 // required
    int         server_port{443};            // required

    // private auth key — required for Backup type
    std::string auth_private_key_pem;        // Ed25519 PRIVATE KEY PEM

    // stealth knobs
    bool        obfuscation{true};
    std::string obfs_secret;
    std::uint16_t obfs_pad_multiple{0};
    std::uint32_t obfs_jitter_ms{0};
    std::string tls_pin_sha256;              // empty = no pin
    std::string tls_stealth_profile;         // empty = default (chrome)

    // anonym / PQ
    std::string anonym_ca_cert_pem;          // empty = none
    std::string anonym_pubkey;               // empty = none
    std::string pq_public_key_pem;           // empty = none

    // client behavior recommendations
    bool inner_crypto{true};
    bool inner_heavy{true};
    bool inner_hop{true};
    std::uint32_t hop_interval_ms{500};
    bool allow_udp{false};
    bool allow_local_ip{false};
};

// Encode + encrypt to bytes ready to write to disk. password must be
// non-empty; trivial password validation is the caller's job.
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
// "this file is a yume-share v1 backup; enter the password" UX
// before prompting. Returns false if magic / version don't validate.
struct ShareFileHeader {
    std::uint8_t version{0};
    BundleType   type{BundleType::Backup};
};
bool peek_share_header(const std::vector<std::uint8_t>& blob,
                       ShareFileHeader* out);

}  // namespace yume::share
