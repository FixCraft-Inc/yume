/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/circuit_crypto.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <climits>
#include <new>
#include <stdexcept>
#include <utility>

namespace yume::providers::circuit {
namespace {

using engine::Result;
using engine::Status;
using engine::StatusCode;
using ytp1_crypto::SecretBytes;

// The tagged layer AAD: the label, the direction byte and the bucket as a
// u16, each behind its four-byte length.
constexpr std::size_t kAadBytes =
    4U + kLayerAadLabel.size() + 4U + 1U + 4U + 2U;

std::array<std::uint8_t, kAadBytes> aad_bytes(circuit1::Direction direction,
                                              std::size_t bucket) noexcept {
    std::array<std::uint8_t, kAadBytes> output{};
    std::size_t at = 0U;
    const auto put_length = [&](std::size_t length) {
        output[at++] = 0U;
        output[at++] = 0U;
        output[at++] = 0U;
        output[at++] = static_cast<std::uint8_t>(length);
    };
    put_length(kLayerAadLabel.size());
    for (const char value : kLayerAadLabel) {
        output[at++] = static_cast<std::uint8_t>(value);
    }
    put_length(1U);
    output[at++] = static_cast<std::uint8_t>(direction);
    put_length(2U);
    output[at++] = static_cast<std::uint8_t>(bucket >> 8U);
    output[at++] = static_cast<std::uint8_t>(bucket);
    return output;
}

// Depth 1 is the entry, whose predecessor is a client and written as zeros.
bool valid_position(const Fingerprint& predecessor,
                    std::uint8_t depth) noexcept {
    if (depth < 1U || depth > circuit1::kMaxHops) return false;
    const bool client =
        std::all_of(predecessor.begin(), predecessor.end(),
                    [](std::uint8_t byte) { return byte == 0U; });
    return client == (depth == 1U);
}

std::span<const std::byte> as_bytes_view(
    std::span<const std::uint8_t> bytes) noexcept {
    return std::as_bytes(bytes);
}

Status fixed(StatusCode code, const char* message) {
    return Status::diagnostic(code, message);
}

}  // namespace

std::optional<Fingerprint> fingerprint_bytes(std::string_view hex) noexcept {
    if (hex.size() != 2U * circuit1::kFingerprintBytes) return std::nullopt;
    const auto nibble = [](char value) -> int {
        if (value >= '0' && value <= '9') return value - '0';
        if (value >= 'a' && value <= 'f') return value - 'a' + 10;
        return -1;
    };
    Fingerprint output{};
    for (std::size_t index = 0U; index < output.size(); ++index) {
        const int high = nibble(hex[2U * index]);
        const int low = nibble(hex[2U * index + 1U]);
        if (high < 0 || low < 0) return std::nullopt;
        output[index] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return output;
}

Transcript transcript_hash(
    const CircuitCrypto& crypto, const Fingerprint& hop,
    const Fingerprint& predecessor, std::uint8_t depth,
    std::span<const std::uint8_t, circuit1::kClientHandshakeBytes>
        client_handshake,
    std::span<const std::uint8_t, circuit1::kX25519Bytes> hop_x25519_public,
    std::span<const std::uint8_t, circuit1::kMlKemCiphertextBytes>
        mlkem_ciphertext) {
    const std::array<std::uint8_t, 1> depth_byte{depth};
    const std::array<std::span<const std::uint8_t>, 6> fields{hop,
                                                              predecessor,
                                                              depth_byte,
                                                              client_handshake,
                                                              hop_x25519_public,
                                                              mlkem_ciphertext};
    const auto input =
        ytp1_crypto::canonical_tagged_input(kTranscriptLabel, fields);
    return ytp1_crypto::sha256(crypto.crypto(), {std::span(input)});
}

HopKeys derive_hop_keys(const CircuitCrypto& crypto,
                        std::span<const std::uint8_t> x25519_shared,
                        std::span<const std::uint8_t> mlkem_shared,
                        const Transcript& transcript) {
    if (x25519_shared.size() != circuit1::kX25519Bytes ||
        mlkem_shared.size() != 32U) {
        throw std::invalid_argument("circuit shared secrets have wrong sizes");
    }
    SecretBytes secret(x25519_shared.size() + mlkem_shared.size());
    std::copy(x25519_shared.begin(), x25519_shared.end(), secret.data());
    std::copy(mlkem_shared.begin(), mlkem_shared.end(),
              secret.data() + x25519_shared.size());
    const auto key = [&](std::string_view label, std::size_t size) {
        return ytp1_crypto::hkdf_sha256(crypto.crypto(), secret.span(),
                                        transcript, ytp1_crypto::text_u8(label),
                                        size);
    };
    return {key(kForwardKeyLabel, kLayerKeyBytes),
            key(kBackwardKeyLabel, kLayerKeyBytes),
            key(kForwardIvLabel, kLayerIvBytes),
            key(kBackwardIvLabel, kLayerIvBytes),
            key(kConfirmationLabel, circuit1::kConfirmationBytes)};
}

Confirmation confirmation(const CircuitCrypto& crypto,
                          std::span<const std::uint8_t> confirmation_key,
                          const Transcript& transcript) {
    return ytp1_crypto::hmac_sha256(crypto.crypto(), confirmation_key,
                                    transcript);
}

std::vector<std::uint8_t> signed_bytes(const Transcript& transcript,
                                       const Confirmation& confirmation) {
    const std::array<std::span<const std::uint8_t>, 2> fields{transcript,
                                                              confirmation};
    return ytp1_crypto::canonical_tagged_input(kHopSignatureLabel, fields);
}

std::array<std::uint8_t, kLayerIvBytes> layer_nonce(
    std::span<const std::uint8_t, kLayerIvBytes> iv,
    std::uint64_t counter) noexcept {
    std::array<std::uint8_t, kLayerIvBytes> output{};
    std::copy(iv.begin(), iv.end(), output.begin());
    for (std::size_t index = 0U; index < 8U; ++index) {
        output[kLayerIvBytes - 1U - index] ^=
            static_cast<std::uint8_t>(counter >> (8U * index));
    }
    return output;
}

std::vector<std::uint8_t> layer_aad(circuit1::Direction direction,
                                    std::size_t bucket) {
    const auto bytes = aad_bytes(direction, bucket);
    return {bytes.begin(), bytes.end()};
}

LayerCipher::LayerCipher(const CircuitCrypto& crypto, Mode mode,
                         circuit1::Direction direction,
                         std::span<const std::uint8_t> key,
                         std::span<const std::uint8_t> iv)
    : mode_(mode), direction_(direction) {
    if (key.size() != kLayerKeyBytes || iv.size() != kLayerIvBytes) {
        throw std::invalid_argument("circuit layer key or IV has wrong size");
    }
    std::copy(iv.begin(), iv.end(), iv_.begin());
    context_ = EVP_CIPHER_CTX_new();
    if (context_ == nullptr) throw std::bad_alloc();
    const auto* cipher = crypto.crypto().aes_256_gcm();
    const int initialized =
        mode == Mode::Seal ? EVP_EncryptInit_ex2(context_, cipher, key.data(),
                                                 nullptr, nullptr)
                           : EVP_DecryptInit_ex2(context_, cipher, key.data(),
                                                 nullptr, nullptr);
    if (initialized != 1 || EVP_CIPHER_CTX_get_iv_length(context_) !=
                                static_cast<int>(kLayerIvBytes)) {
        release();
        throw std::runtime_error("circuit layer cipher setup failed");
    }
}

LayerCipher::LayerCipher(LayerCipher&& other) noexcept
    : context_(std::exchange(other.context_, nullptr)),
      mode_(other.mode_),
      direction_(other.direction_),
      iv_(other.iv_),
      cells_(other.cells_),
      failed_(std::exchange(other.failed_, true)) {
    OPENSSL_cleanse(other.iv_.data(), other.iv_.size());
}

LayerCipher& LayerCipher::operator=(LayerCipher&& other) noexcept {
    if (this != &other) {
        release();
        context_ = std::exchange(other.context_, nullptr);
        mode_ = other.mode_;
        direction_ = other.direction_;
        iv_ = other.iv_;
        cells_ = other.cells_;
        failed_ = std::exchange(other.failed_, true);
        OPENSSL_cleanse(other.iv_.data(), other.iv_.size());
    }
    return *this;
}

LayerCipher::~LayerCipher() {
    release();
}

void LayerCipher::release() noexcept {
    EVP_CIPHER_CTX_free(context_);
    context_ = nullptr;
    OPENSSL_cleanse(iv_.data(), iv_.size());
}

Status LayerCipher::seal(std::size_t bucket,
                         std::span<const std::uint8_t> plaintext,
                         std::span<std::uint8_t> output) noexcept {
    if (failed_ || context_ == nullptr || mode_ != Mode::Seal) {
        return Status(StatusCode::FailedPrecondition);
    }
    if (!circuit1::IsBucket(direction_, bucket) || plaintext.size() > INT_MAX ||
        output.size() != plaintext.size() + circuit1::kLayerTagBytes) {
        return Status(StatusCode::InvalidArgument);
    }
    if (cells_ >= kMaxLayerCells) return Status(StatusCode::ResourceExhausted);
    const auto nonce = layer_nonce(iv_, cells_);
    const auto aad = aad_bytes(direction_, bucket);
    int written = 0;
    int finished = 0;
    const bool sealed =
        EVP_EncryptInit_ex2(context_, nullptr, nullptr, nonce.data(),
                            nullptr) == 1 &&
        EVP_EncryptUpdate(context_, nullptr, &written, aad.data(),
                          static_cast<int>(aad.size())) == 1 &&
        EVP_EncryptUpdate(context_, output.data(), &written, plaintext.data(),
                          static_cast<int>(plaintext.size())) == 1 &&
        static_cast<std::size_t>(written) == plaintext.size() &&
        EVP_EncryptFinal_ex(context_, output.data() + written, &finished) ==
            1 &&
        finished == 0 &&
        EVP_CIPHER_CTX_ctrl(context_, EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(circuit1::kLayerTagBytes),
                            output.data() + plaintext.size()) == 1;
    if (!sealed) {
        failed_ = true;
        OPENSSL_cleanse(output.data(), output.size());
        return Status(StatusCode::Internal);
    }
    ++cells_;
    return Status::success();
}

Status LayerCipher::open(std::size_t bucket,
                         std::span<const std::uint8_t> ciphertext,
                         std::span<std::uint8_t> output) noexcept {
    if (failed_ || context_ == nullptr || mode_ != Mode::Open) {
        return Status(StatusCode::FailedPrecondition);
    }
    if (!circuit1::IsBucket(direction_, bucket) ||
        ciphertext.size() < circuit1::kLayerTagBytes ||
        ciphertext.size() > INT_MAX ||
        output.size() != ciphertext.size() - circuit1::kLayerTagBytes) {
        return Status(StatusCode::InvalidArgument);
    }
    if (cells_ >= kMaxLayerCells) return Status(StatusCode::ResourceExhausted);
    const auto nonce = layer_nonce(iv_, cells_);
    const auto aad = aad_bytes(direction_, bucket);
    const auto body = ciphertext.first(output.size());
    std::array<std::uint8_t, circuit1::kLayerTagBytes> tag{};
    std::copy(ciphertext.begin() + static_cast<std::ptrdiff_t>(output.size()),
              ciphertext.end(), tag.begin());
    int written = 0;
    int finished = 0;
    const bool opened =
        EVP_DecryptInit_ex2(context_, nullptr, nullptr, nonce.data(),
                            nullptr) == 1 &&
        EVP_DecryptUpdate(context_, nullptr, &written, aad.data(),
                          static_cast<int>(aad.size())) == 1 &&
        EVP_DecryptUpdate(context_, output.data(), &written, body.data(),
                          static_cast<int>(body.size())) == 1 &&
        static_cast<std::size_t>(written) == body.size() &&
        EVP_CIPHER_CTX_ctrl(context_, EVP_CTRL_GCM_SET_TAG,
                            static_cast<int>(tag.size()), tag.data()) == 1 &&
        EVP_DecryptFinal_ex(context_, output.data() + written, &finished) ==
            1 &&
        finished == 0;
    if (!opened) {
        failed_ = true;
        OPENSSL_cleanse(output.data(), output.size());
        return Status(StatusCode::PermissionDenied);
    }
    ++cells_;
    return Status::success();
}

Result<ClientExchange> ClientExchange::start(const CircuitCrypto& crypto) {
    try {
        ClientExchange exchange;
        auto x25519 = ytp1_crypto::generate_x25519(crypto.crypto());
        exchange.x25519_ = std::move(x25519.private_key);
        exchange.mlkem_ = ytp1_crypto::generate_key(
            crypto.crypto(), ytp1_crypto::kMlKem1024Algorithm);
        const auto mlkem_public =
            ytp1_crypto::ml_kem_public_bytes(exchange.mlkem_.get());
        circuit1::ClientHandshake handshake;
        if (RAND_bytes_ex(crypto.crypto().library_context(),
                          handshake.nonce.data(), handshake.nonce.size(),
                          0U) != 1) {
            return Result<ClientExchange>(
                fixed(StatusCode::Internal, "circuit handshake nonce failed"));
        }
        handshake.x25519_public = x25519.public_key;
        std::copy(mlkem_public.begin(), mlkem_public.end(),
                  handshake.mlkem_public.begin());
        exchange.message_ = circuit1::EncodeClientHandshake(handshake);
        return Result<ClientExchange>(std::move(exchange));
    } catch (const std::bad_alloc&) {
        return Result<ClientExchange>(Status(StatusCode::ResourceExhausted));
    } catch (...) {
        return Result<ClientExchange>(
            fixed(StatusCode::Internal, "circuit handshake keys failed"));
    }
}

Result<HopKeys> ClientExchange::finish(
    const CircuitCrypto& crypto, std::span<const std::uint8_t> hop_handshake,
    const keys::CompositePublic& hop, const Fingerprint& predecessor,
    std::uint8_t depth) {
    // The private keys serve one answer and leave with this call.
    const auto x25519 = std::move(x25519_);
    const auto mlkem = std::move(mlkem_);
    if (!x25519 || !mlkem) {
        return Result<HopKeys>(Status(StatusCode::FailedPrecondition));
    }
    try {
        const auto hop_fingerprint = fingerprint_bytes(hop.fingerprint);
        const auto decoded = circuit1::DecodeHopHandshake(hop_handshake);
        if (!hop_fingerprint || !valid_position(predecessor, depth) ||
            !decoded.ok()) {
            return Result<HopKeys>(fixed(StatusCode::InvalidArgument,
                                         "circuit hop answer is malformed"));
        }
        const auto& reply = *decoded.value;
        const auto x25519_shared = ytp1_crypto::derive_x25519(
            crypto.crypto(), x25519.get(), reply.x25519_public);
        const auto mlkem_shared = ytp1_crypto::decapsulate_ml_kem(
            crypto.crypto(), mlkem.get(), reply.mlkem_ciphertext);
        const auto transcript = transcript_hash(
            crypto, *hop_fingerprint, predecessor, depth, message_,
            reply.x25519_public, reply.mlkem_ciphertext);
        auto hop_keys = derive_hop_keys(crypto, x25519_shared.span(),
                                        mlkem_shared.span(), transcript);
        const auto signed_input = signed_bytes(transcript, reply.confirmation);
        if (!keys::verify_composite(crypto.key_context(), hop,
                                    as_bytes_view(signed_input),
                                    as_bytes_view(reply.signature))) {
            return Result<HopKeys>(fixed(StatusCode::PermissionDenied,
                                         "circuit hop signature failed"));
        }
        const auto expected =
            confirmation(crypto, hop_keys.confirmation_key.span(), transcript);
        if (CRYPTO_memcmp(expected.data(), reply.confirmation.data(),
                          expected.size()) != 0) {
            return Result<HopKeys>(fixed(StatusCode::PermissionDenied,
                                         "circuit hop confirmation failed"));
        }
        return Result<HopKeys>(std::move(hop_keys));
    } catch (const std::bad_alloc&) {
        return Result<HopKeys>(Status(StatusCode::ResourceExhausted));
    } catch (const keys::KeyError&) {
        return Result<HopKeys>(fixed(StatusCode::InvalidArgument,
                                     "circuit hop identity is invalid"));
    } catch (const std::invalid_argument&) {
        return Result<HopKeys>(fixed(StatusCode::InvalidArgument,
                                     "circuit hop answer was rejected"));
    } catch (...) {
        return Result<HopKeys>(
            fixed(StatusCode::Internal, "circuit hop answer failed"));
    }
}

Result<HopAnswer> answer(const CircuitCrypto& crypto,
                         std::span<const std::uint8_t> client_handshake,
                         const keys::CompositePrivate& self,
                         const Fingerprint& predecessor, std::uint8_t depth) {
    try {
        const auto self_fingerprint =
            fingerprint_bytes(self.identity.fingerprint);
        const auto decoded = circuit1::DecodeClientHandshake(client_handshake);
        if (!self_fingerprint || !valid_position(predecessor, depth) ||
            !decoded.ok()) {
            return Result<HopAnswer>(fixed(StatusCode::InvalidArgument,
                                           "circuit handshake is malformed"));
        }
        const auto& request = *decoded.value;
        const auto peer_mlkem = ytp1_crypto::import_ml_kem_public(
            crypto.crypto(), request.mlkem_public);
        auto encapsulation =
            ytp1_crypto::encapsulate_ml_kem(crypto.crypto(), peer_mlkem.get());
        auto x25519 = ytp1_crypto::generate_x25519(crypto.crypto());
        const auto x25519_shared = ytp1_crypto::derive_x25519(
            crypto.crypto(), x25519.private_key.get(), request.x25519_public);
        const auto transcript = transcript_hash(
            crypto, *self_fingerprint, predecessor, depth,
            client_handshake.first<circuit1::kClientHandshakeBytes>(),
            x25519.public_key, encapsulation.ciphertext);
        auto hop_keys =
            derive_hop_keys(crypto, x25519_shared.span(),
                            encapsulation.shared.span(), transcript);
        circuit1::HopHandshake reply;
        reply.x25519_public = x25519.public_key;
        reply.mlkem_ciphertext = encapsulation.ciphertext;
        reply.confirmation =
            confirmation(crypto, hop_keys.confirmation_key.span(), transcript);
        const auto signed_input = signed_bytes(transcript, reply.confirmation);
        const auto signature = keys::sign_composite(
            crypto.key_context(), self, as_bytes_view(signed_input));
        std::transform(
            signature.begin(), signature.end(), reply.signature.begin(),
            [](std::byte value) { return static_cast<std::uint8_t>(value); });
        return Result<HopAnswer>(HopAnswer{circuit1::EncodeHopHandshake(reply),
                                           std::move(hop_keys)});
    } catch (const std::bad_alloc&) {
        return Result<HopAnswer>(Status(StatusCode::ResourceExhausted));
    } catch (const std::invalid_argument&) {
        return Result<HopAnswer>(fixed(StatusCode::InvalidArgument,
                                       "circuit handshake was rejected"));
    } catch (...) {
        return Result<HopAnswer>(
            fixed(StatusCode::Internal, "circuit handshake answer failed"));
    }
}

}  // namespace yume::providers::circuit
