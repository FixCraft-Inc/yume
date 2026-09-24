/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

namespace yume::relay::identity {

using Bytes = std::vector<std::uint8_t>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

// Move-only, single-use incremental SHA-256. Finish() consumes the state, and
// using it afterwards or after an internal failure throws instead of starting
// a second digest.
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

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

struct KeyPair {
    EvpPkeyPtr private_key{nullptr, EVP_PKEY_free};
    EvpPkeyPtr public_key{nullptr, EVP_PKEY_free};
};

// A composite identity: Ed25519 alongside ML-DSA-87. Both halves sign the same
// message and both must verify. An either-or composite would be weaker than
// either algorithm alone, because forging one half would be enough.
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

// The signature is fixed width and fixed order: Ed25519 (64 bytes), then
// ML-DSA-87 (4627 bytes), so attacker-supplied lengths never steer parsing.
Bytes sign_composite(const CompositeKeyPair& keys, const Bytes& message);

// True only when both halves verify. Any length mismatch, missing key or
// single-half failure returns false.
bool verify_composite(EVP_PKEY* classical_pub, EVP_PKEY* pq_pub,
                      const Bytes& message, const Bytes& signature);

// A composite public identity travels as two concatenated PEM public keys,
// Ed25519 first, then ML-DSA-87.
struct CompositePublicKey {
    EvpPkeyPtr classical{nullptr, EVP_PKEY_free};
    EvpPkeyPtr pq{nullptr, EVP_PKEY_free};

    bool valid() const { return classical != nullptr && pq != nullptr; }
};

Bytes encode_public_key_pem(EVP_PKEY* key);
Bytes encode_composite_identity(EVP_PKEY* classical_pub, EVP_PKEY* pq_pub);

// Strict: exactly two PEM public-key blocks, Ed25519 then ML-DSA-87. Anything
// else returns an invalid result, never half an identity.
CompositePublicKey parse_composite_identity(const Bytes& pem_bundle);

}  // namespace yume::relay::identity
