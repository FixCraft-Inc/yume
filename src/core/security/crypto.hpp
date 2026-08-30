/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

namespace yume::crypto {

using Bytes = std::vector<uint8_t>;
using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

// Move-only, single-use incremental SHA-256. OpenSSL state stays behind this
// core boundary so streaming callers never open their own EVP path. Finish()
// and FinishHex() consume the state; update/finalize after completion or after
// an internal failure throws rather than silently starting a second digest.
class Sha256Stream {
public:
    Sha256Stream();
    Sha256Stream(const Sha256Stream&) = delete;
    Sha256Stream& operator=(const Sha256Stream&) = delete;
    Sha256Stream(Sha256Stream&& other) noexcept;
    Sha256Stream& operator=(Sha256Stream&& other) noexcept;
    ~Sha256Stream();

    void Update(std::span<const std::uint8_t> input);
    Bytes Finish();
    std::string FinishHex();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// Generic, non-secret SHA-256 identifier. Protocol-specific fingerprints
// should delegate to this helper after constructing their domain-separated
// canonical input rather than duplicating OpenSSL digest/hex code.
Bytes sha256(std::span<const std::uint8_t> input);
Bytes sha256(std::string_view input);
std::string sha256_hex(std::span<const std::uint8_t> input);
std::string sha256_hex(std::string_view input);

struct KeyPair {
    EVP_PKEY_ptr private_key{nullptr, EVP_PKEY_free};
    EVP_PKEY_ptr public_key{nullptr, EVP_PKEY_free};
};

// Load one signing/decryption key through the protected, descriptor-bound
// private-file contract. Unlike load_keypair(path, ""), this does not create
// a redundant public-key reference for a caller that only signs.
EVP_PKEY_ptr load_private_key(const std::string& path_priv);
KeyPair load_keypair(const std::string& path_priv, const std::string& path_pub);

bool verify_key(EVP_PKEY* pubkey, const Bytes& message, const Bytes& signature);
Bytes sign_message(EVP_PKEY* privkey, const Bytes& message);

// Composite (hybrid) identity: Ed25519 alongside ML-DSA-87.
//
// Both halves sign the same message and **both must verify**. This is an AND,
// never an OR -- an OR-composite is weaker than either algorithm on its own,
// because forging either half would be sufficient. The pairing hedges against
// a near-term ML-DSA cryptanalytic or implementation failure at a cost of 64
// bytes on top of ML-DSA-87's 4627, and mirrors what the inner layer already
// does for key exchange with ML-KEM-1024 + X25519.
//
// Note on threat model: unlike key exchange, signatures cannot be broken
// retroactively -- a forgery has to happen while the credential is live. The
// PQ half is therefore about surviving a surprise in one primitive, not about
// harvest-now-decrypt-later.
inline constexpr std::string_view kCompositePqAlgorithm = "ML-DSA-87";
inline constexpr std::size_t kEd25519SignatureLen = 64;
inline constexpr std::size_t kMlDsa87SignatureLen = 4627;
inline constexpr std::size_t kCompositeSignatureLen =
    kEd25519SignatureLen + kMlDsa87SignatureLen;

struct CompositeKeyPair {
    KeyPair classical;  // Ed25519
    KeyPair pq;         // ML-DSA-87
};

CompositeKeyPair generate_composite_keypair();

// Reads a composite private identity: two concatenated PEM private keys,
// Ed25519 first then ML-DSA-87, in one file. Keeping it to a single file means
// `--identity <path>` stays one path and an operator cannot end up with the two
// halves out of sync. Ownership and mode are checked exactly as for a
// single-key identity -- a file another account can read or replace must never
// be able to sign an AUTH transcript.
CompositeKeyPair load_composite_keypair(const std::string& path_priv);

// Serializes both private halves in the order load_composite_keypair expects.
// Caller is responsible for writing it with restrictive permissions.
Bytes encode_composite_private_pem(const CompositeKeyPair& keys);

// Signature layout is fixed-width and order-fixed: Ed25519 (64) then ML-DSA-87
// (4627). Fixed width means parsing cannot be steered by attacker-supplied
// lengths.
Bytes sign_composite(const CompositeKeyPair& keys, const Bytes& message);

// Returns true only when BOTH halves verify. Any length mismatch, missing key,
// or single-half failure returns false.
bool verify_composite(EVP_PKEY* classical_pub, EVP_PKEY* pq_pub,
                      const Bytes& message, const Bytes& signature);

// A composite identity travels as two concatenated PEM public keys, Ed25519
// first then ML-DSA-87. PEM concatenation is used because the AUTH identity
// field already carries a PEM public key, so this stays a widening of the
// existing shape rather than a new container format. Roughly 3.7 KB against the
// codec's 16 KiB identity cap.
struct CompositePublicKey {
    EVP_PKEY_ptr classical{nullptr, EVP_PKEY_free};
    EVP_PKEY_ptr pq{nullptr, EVP_PKEY_free};

    bool valid() const { return classical != nullptr && pq != nullptr; }
};

Bytes encode_public_key_pem(EVP_PKEY* key);
Bytes encode_composite_identity(EVP_PKEY* classical_pub, EVP_PKEY* pq_pub);

// Strict: requires exactly two PEM blocks, the first Ed25519 and the second
// ML-DSA-87, in that order. Anything else -- one block, three blocks, swapped
// order, wrong algorithm -- returns an invalid result rather than a partial
// identity, so a caller cannot be handed a half-composite it might treat as
// whole.
CompositePublicKey parse_composite_identity(const Bytes& pem_bundle);

// Canonical byte encoding of a composite identity: a domain label followed by
// each half's DER under a 32-bit length prefix, Ed25519 then ML-DSA-87.
//
// This is the unit of comparison for authorized-key membership. It matters that
// it is one blob covering both halves: if the two halves were stored and
// matched independently, an attacker holding the Ed25519 half of one identity
// and the ML-DSA half of another could present a pair that matches neither
// owner's actual key. Length prefixes stop a shift between the halves from
// producing the same bytes.
Bytes composite_canonical_encoding(const CompositePublicKey& key);

// Stable identifier for a composite identity: SHA-256 over the canonical
// encoding. Distinct from either half's own fingerprint, so a composite
// identity can never collide with a single-key fingerprint.
std::string composite_fingerprint(const CompositePublicKey& key);
// Same digest, for callers that already hold the canonical encoding -- notably
// the authorized-key store, which keeps identities in that form. Sharing one
// implementation is deliberate: two ways to compute an identity is how the
// classical and composite fingerprints drifted apart in the first place.
std::string composite_fingerprint_from_canonical(const Bytes& canonical);

Bytes encrypt_chacha20(const Bytes& data, const Bytes& key, const Bytes& nonce);
Bytes decrypt_chacha20(const Bytes& data, const Bytes& key, const Bytes& nonce);

Bytes hmac_sha256(const Bytes& data, const Bytes& key);
Bytes random_bytes(size_t len);

}  // namespace yume::crypto
