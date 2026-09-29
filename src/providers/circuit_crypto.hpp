/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include <openssl/types.h>

#include "circuit/protocol.hpp"
#include "engine/status.hpp"
#include "providers/composite_keys.hpp"
#include "providers/ytp1_crypto.hpp"

// Circuit 1 constructions (docs/protocol/CIRCUIT_1.md): the hybrid handshake
// with each hop and the per-hop layer AEAD. The deterministic steps are free
// functions checked against the published vectors. The exchange types add the
// random keys and the composite signatures.
namespace yume::providers::circuit {

inline constexpr std::string_view kTranscriptLabel =
    "yume/circuit/1/transcript/v1";
inline constexpr std::string_view kForwardKeyLabel =
    "yume/circuit/1/forward-key/v1";
inline constexpr std::string_view kBackwardKeyLabel =
    "yume/circuit/1/backward-key/v1";
inline constexpr std::string_view kForwardIvLabel =
    "yume/circuit/1/forward-iv/v1";
inline constexpr std::string_view kBackwardIvLabel =
    "yume/circuit/1/backward-iv/v1";
inline constexpr std::string_view kConfirmationLabel =
    "yume/circuit/1/confirmation/v1";
inline constexpr std::string_view kHopSignatureLabel =
    "yume/circuit/1/hop-signature/v1";
inline constexpr std::string_view kLayerAadLabel =
    "yume/circuit/1/layer-aad/v1";

inline constexpr std::size_t kLayerKeyBytes = 32U;
inline constexpr std::size_t kLayerIvBytes = 12U;
inline constexpr std::size_t kTranscriptBytes = 32U;
// A layer protects at most this many cells in one direction.
inline constexpr std::uint64_t kMaxLayerCells = std::uint64_t{1} << 32U;

using Fingerprint = std::array<std::uint8_t, circuit1::kFingerprintBytes>;
using Transcript = std::array<std::uint8_t, kTranscriptBytes>;
using Confirmation = std::array<std::uint8_t, circuit1::kConfirmationBytes>;

// The two private OpenSSL contexts circuits use: YTP/1's context for digests,
// HMAC, HKDF, AES-GCM, X25519 and ML-KEM, and a key context for composite
// identities. Each key stays in the context that parsed or made it.
// Construction throws when a provider or algorithm is missing. Operations may
// run concurrently on one instance.
class CircuitCrypto final {
public:
    CircuitCrypto() = default;
    CircuitCrypto(const CircuitCrypto&) = delete;
    CircuitCrypto& operator=(const CircuitCrypto&) = delete;

    const ytp1_crypto::CryptoContext& crypto() const noexcept {
        return crypto_;
    }
    const keys::KeyContext& key_context() const noexcept { return keys_; }

private:
    ytp1_crypto::CryptoContext crypto_;
    keys::KeyContext keys_;
};

// The 32 bytes of a composite fingerprint written as 64 lowercase hex
// characters, or nothing for any other text.
std::optional<Fingerprint> fingerprint_bytes(std::string_view hex) noexcept;

Transcript transcript_hash(
    const CircuitCrypto& crypto, const Fingerprint& hop,
    const Fingerprint& predecessor, std::uint8_t depth,
    std::span<const std::uint8_t, circuit1::kClientHandshakeBytes>
        client_handshake,
    std::span<const std::uint8_t, circuit1::kX25519Bytes> hop_x25519_public,
    std::span<const std::uint8_t, circuit1::kMlKemCiphertextBytes>
        mlkem_ciphertext);

// One hop's keys for both directions. The buffers wipe themselves.
struct HopKeys final {
    ytp1_crypto::SecretBytes forward_key;
    ytp1_crypto::SecretBytes backward_key;
    ytp1_crypto::SecretBytes forward_iv;
    ytp1_crypto::SecretBytes backward_iv;
    ytp1_crypto::SecretBytes confirmation_key;
};

HopKeys derive_hop_keys(const CircuitCrypto& crypto,
                        std::span<const std::uint8_t> x25519_shared,
                        std::span<const std::uint8_t> mlkem_shared,
                        const Transcript& transcript);

Confirmation confirmation(const CircuitCrypto& crypto,
                          std::span<const std::uint8_t> confirmation_key,
                          const Transcript& transcript);

// The bytes a hop signs: the signature label, the transcript and the
// confirmation, each behind a four-byte length.
std::vector<std::uint8_t> signed_bytes(const Transcript& transcript,
                                       const Confirmation& confirmation);

std::array<std::uint8_t, kLayerIvBytes> layer_nonce(
    std::span<const std::uint8_t, kLayerIvBytes> iv,
    std::uint64_t counter) noexcept;

std::vector<std::uint8_t> layer_aad(circuit1::Direction direction,
                                    std::size_t bucket);

// One hop's layer in one direction, used either to seal or to open. It counts
// its own cells, so no nonce repeats, refuses once kMaxLayerCells have passed
// and refuses everything after a failed open, which ends the circuit.
class LayerCipher final {
public:
    enum class Mode : std::uint8_t { Seal, Open };

    // Throws on a key or IV of the wrong size and when OpenSSL cannot set up
    // the cipher.
    LayerCipher(const CircuitCrypto& crypto, Mode mode,
                circuit1::Direction direction,
                std::span<const std::uint8_t> key,
                std::span<const std::uint8_t> iv);
    LayerCipher(const LayerCipher&) = delete;
    LayerCipher& operator=(const LayerCipher&) = delete;
    LayerCipher(LayerCipher&& other) noexcept;
    LayerCipher& operator=(LayerCipher&& other) noexcept;
    ~LayerCipher();

    // output holds exactly the plaintext and the 16-byte tag.
    engine::Status seal(std::size_t bucket,
                        std::span<const std::uint8_t> plaintext,
                        std::span<std::uint8_t> output) noexcept;
    // output holds exactly the ciphertext less the tag. A failed tag leaves
    // output wiped and the cipher refusing.
    engine::Status open(std::size_t bucket,
                        std::span<const std::uint8_t> ciphertext,
                        std::span<std::uint8_t> output) noexcept;
    std::uint64_t cells() const noexcept { return cells_; }

private:
    void release() noexcept;

    EVP_CIPHER_CTX* context_{nullptr};
    Mode mode_{Mode::Seal};
    circuit1::Direction direction_{circuit1::Direction::Forward};
    std::array<std::uint8_t, kLayerIvBytes> iv_{};
    std::uint64_t cells_{0U};
    bool failed_{false};
};

// The client's side of one hop's handshake. start makes fresh X25519 and
// ML-KEM-1024 keys and a nonce. finish runs once: it checks the hop's answer
// against the identity the client expects at that position, derives the
// keys, and drops the private keys whatever the outcome.
class ClientExchange final {
public:
    static engine::Result<ClientExchange> start(const CircuitCrypto& crypto);

    ClientExchange(ClientExchange&&) noexcept = default;
    ClientExchange& operator=(ClientExchange&&) noexcept = default;

    std::span<const std::uint8_t, circuit1::kClientHandshakeBytes> message()
        const noexcept {
        return message_;
    }

    // InvalidArgument for a malformed answer or a depth that does not match
    // the predecessor, PermissionDenied when a signature half or the
    // confirmation fails, FailedPrecondition after the first call.
    engine::Result<HopKeys> finish(const CircuitCrypto& crypto,
                                   std::span<const std::uint8_t> hop_handshake,
                                   const keys::CompositePublic& hop,
                                   const Fingerprint& predecessor,
                                   std::uint8_t depth);

private:
    ClientExchange() = default;

    ytp1_crypto::PkeyPtr x25519_;
    ytp1_crypto::PkeyPtr mlkem_;
    std::array<std::uint8_t, circuit1::kClientHandshakeBytes> message_{};
};

// What a hop sends back and keeps.
struct HopAnswer final {
    std::vector<std::uint8_t> message;
    HopKeys keys;
};

// The hop's side: checks the client handshake, depth and predecessor, and
// answers under its own composite identity. InvalidArgument for malformed
// input, a depth that does not match the predecessor, an ML-KEM key that
// fails OpenSSL's check or an all-zero X25519 secret.
engine::Result<HopAnswer> answer(const CircuitCrypto& crypto,
                                 std::span<const std::uint8_t> client_handshake,
                                 const keys::CompositePrivate& self,
                                 const Fingerprint& predecessor,
                                 std::uint8_t depth);

}  // namespace yume::providers::circuit
