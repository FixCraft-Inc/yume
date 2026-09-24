/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <openssl/crypto.h>
#include <openssl/types.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <memory>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include "engine/session_engine.hpp"
#include "ytp/security.hpp"

// Provider-internal constructions, shared by the session implementation and
// published known-answer tests. This is not an SDK or provider injection API.
namespace yume::providers::ytp1_crypto {

using engine::EndpointRole;
using engine::RecordKeyToken;

inline constexpr std::string_view kOpenSslPropertyQuery = "provider=default";
inline constexpr std::string_view kEd25519Algorithm = "ED25519";
inline constexpr std::string_view kMlDsa87Algorithm = "ML-DSA-87";
inline constexpr std::string_view kMlKem1024Algorithm = "ML-KEM-1024";
inline constexpr std::string_view kX25519Algorithm = "X25519";
inline constexpr std::string_view kSha256Algorithm = "SHA256";
inline constexpr std::string_view kAes256GcmAlgorithm = "AES-256-GCM";
inline constexpr std::string_view kHmacAlgorithm = "HMAC";
inline constexpr std::string_view kHkdfAlgorithm = "HKDF";
inline constexpr std::size_t kSha256Bytes = 32U;
inline constexpr std::size_t kAes256KeyBytes = 32U;
inline constexpr std::size_t kAesGcmNonceBytes = 12U;
inline constexpr std::size_t kAesGcmTagBytes = 16U;
inline constexpr std::size_t kRecordKeyMaterialBytes =
    kAes256KeyBytes + kAesGcmNonceBytes;
inline constexpr std::size_t kMaxTranscriptInputBytes = 256U * 1024U;
inline constexpr std::size_t kMaxRatchetInputBytes = 16U * 1024U;
class SecretBytes final {
public:
    SecretBytes() = default;
    explicit SecretBytes(std::size_t size) : bytes_(size) {}
    explicit SecretBytes(std::vector<std::uint8_t> bytes) noexcept
        : bytes_(std::move(bytes)) {}

    static SecretBytes copy_from(std::span<const std::byte> input) {
        std::vector<std::uint8_t> copy(input.size());
        if (!input.empty()) {
            std::memcpy(copy.data(), input.data(), input.size());
        }
        return SecretBytes(std::move(copy));
    }

    static SecretBytes copy_from(std::span<const std::uint8_t> input) {
        return SecretBytes(
            std::vector<std::uint8_t>(input.begin(), input.end()));
    }

    SecretBytes(const SecretBytes&) = delete;
    SecretBytes& operator=(const SecretBytes&) = delete;

    SecretBytes(SecretBytes&& other) noexcept
        : bytes_(std::move(other.bytes_)) {}

    SecretBytes& operator=(SecretBytes&& other) noexcept {
        if (this != &other) {
            wipe();
            bytes_ = std::move(other.bytes_);
        }
        return *this;
    }

    ~SecretBytes() noexcept { wipe(); }

    void wipe() noexcept {
        if (!bytes_.empty()) {
            OPENSSL_cleanse(bytes_.data(), bytes_.size());
            bytes_.clear();
        }
    }

    void reset(std::vector<std::uint8_t> bytes) noexcept {
        wipe();
        bytes_ = std::move(bytes);
    }

    std::span<const std::uint8_t> span() const noexcept { return bytes_; }
    std::span<std::uint8_t> mutable_span() noexcept { return bytes_; }
    const std::uint8_t* data() const noexcept { return bytes_.data(); }
    std::uint8_t* data() noexcept { return bytes_.data(); }
    std::size_t size() const noexcept { return bytes_.size(); }
    bool empty() const noexcept { return bytes_.empty(); }

private:
    std::vector<std::uint8_t> bytes_;
};

// Each instance owns a private library context and its explicit default
// provider. All fetched algorithms and key operations stay in that context.
class CryptoContext final {
public:
    CryptoContext();
    ~CryptoContext();
    CryptoContext(const CryptoContext&) = delete;
    CryptoContext& operator=(const CryptoContext&) = delete;

    OSSL_LIB_CTX* library_context() const noexcept;
    const EVP_MD* sha256() const noexcept;
    const EVP_CIPHER* aes_256_gcm() const noexcept;
    EVP_MAC* hmac() const noexcept;
    EVP_KDF* hkdf() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

enum class ConfirmationPurpose : std::uint8_t {
    Response = 1U,
    Accepted = 2U,
};

struct HandshakeRoots final {
    SecretBytes master;
    SecretBytes client_to_server;
    SecretBytes server_to_client;
};

std::span<const std::uint8_t> text_u8(std::string_view input) noexcept;

bool any_nonzero(std::span<const std::uint8_t> value) noexcept;

void append_u32(std::vector<std::uint8_t>& output,
                std::uint32_t value);

void append_u64(std::vector<std::uint8_t>& output,
                std::uint64_t value);

void append_length_prefixed(std::vector<std::uint8_t>& output,
                            std::span<const std::uint8_t> value,
                            std::size_t bound);

ytp1::EndpointRole to_ytp_role(EndpointRole role);

std::array<std::uint8_t, kSha256Bytes> sha256(
    const CryptoContext& crypto,
    std::span<const std::span<const std::uint8_t>> parts);

std::array<std::uint8_t, kSha256Bytes> sha256(
    const CryptoContext& crypto,
    std::initializer_list<std::span<const std::uint8_t>> parts);

std::array<std::uint8_t, kSha256Bytes> hmac_sha256(
    const CryptoContext& crypto,
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> message);

SecretBytes hkdf_sha256(const CryptoContext& crypto,
                        std::span<const std::uint8_t> key,
                        std::span<const std::uint8_t> salt,
                        std::span<const std::uint8_t> info,
                        std::size_t output_size);

std::vector<std::uint8_t> canonical_tagged_input(
    std::string_view domain,
    std::span<const std::span<const std::uint8_t>> fields,
    std::size_t bound = kMaxTranscriptInputBytes);

std::array<std::uint8_t, ytp1::kTranscriptHashSize> transcript_hash(
    const CryptoContext& crypto,
    std::span<const std::uint8_t> exporter,
    std::span<const std::span<const std::uint8_t>> messages);

std::vector<std::uint8_t> signature_input(
    EndpointRole sender,
    ytp1::AuthMessageType message_type,
    std::span<const std::uint8_t> exporter,
    std::span<const std::uint8_t> transcript,
    std::span<const std::uint8_t> confirmation = {});

std::vector<std::uint8_t> psk_authenticator_input(
    ConfirmationPurpose purpose,
    std::span<const std::uint8_t> transcript);

std::vector<std::uint8_t> key_confirmation_input(
    ConfirmationPurpose purpose,
    std::span<const std::uint8_t> transcript);

HandshakeRoots derive_initial_roots(
    const CryptoContext& crypto,
    std::span<const std::uint8_t> transcript,
    std::span<const std::uint8_t> exporter,
    std::span<const std::uint8_t> client_identity,
    std::span<const std::uint8_t> server_identity,
    std::span<const std::uint8_t> client_capabilities,
    std::span<const std::uint8_t> server_capabilities,
    std::span<const std::uint8_t> access_psk,
    std::span<const std::uint8_t> client_x25519_public_key,
    std::span<const std::uint8_t> server_x25519_public_key,
    std::span<const std::uint8_t> x25519_shared_secret,
    std::span<const std::uint8_t> ml_kem_public_key,
    std::span<const std::uint8_t> ml_kem_ciphertext,
    std::span<const std::uint8_t> ml_kem_shared_secret);

std::vector<std::uint8_t> record_aad(EndpointRole sender,
                                     RecordKeyToken token);

SecretBytes derive_record_material(
    const CryptoContext& crypto,
    std::span<const std::uint8_t> directional_root,
    EndpointRole sender,
    RecordKeyToken token,
    std::span<const std::uint8_t> session_binding);

std::vector<std::uint8_t> seal_aes_gcm(
    const CryptoContext& crypto,
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> aad,
    std::span<const std::uint8_t> plaintext);

std::vector<std::uint8_t> open_aes_gcm(
    const CryptoContext& crypto,
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> aad,
    std::span<const std::uint8_t> ciphertext);

std::vector<std::uint8_t> challenge_context(
    std::span<const std::uint8_t> exporter,
    std::span<const std::uint8_t> server_identity,
    std::span<const std::uint8_t> ml_kem_public,
    std::span<const std::uint8_t> server_x25519_public,
    std::span<const std::uint8_t> server_capabilities,
    std::span<const std::uint8_t> nonce);

std::vector<std::uint8_t> response_context(
    std::span<const std::uint8_t> canonical_challenge,
    std::span<const std::uint8_t> client_identity,
    std::span<const std::uint8_t> ml_kem_ciphertext,
    std::span<const std::uint8_t> client_x25519_public,
    std::span<const std::uint8_t> client_capabilities);

std::vector<std::uint8_t> rekey_init_auth_input(
    EndpointRole direction,
    std::uint32_t epoch,
    std::span<const std::uint8_t> session_binding,
    std::span<const std::uint8_t> ml_kem_public,
    std::span<const std::uint8_t> x25519_public,
    std::span<const std::uint8_t> nonce);

std::vector<std::uint8_t> rekey_ack_auth_input(
    EndpointRole direction,
    std::uint32_t epoch,
    std::span<const std::uint8_t> session_binding,
    std::span<const std::uint8_t> canonical_init_without_authenticator,
    std::span<const std::uint8_t> ml_kem_ciphertext,
    std::span<const std::uint8_t> x25519_public);

SecretBytes derive_rekey_root(
    const CryptoContext& crypto,
    std::span<const std::uint8_t> old_root,
    EndpointRole direction,
    std::uint32_t epoch,
    std::span<const std::uint8_t> session_binding,
    std::span<const std::uint8_t> canonical_init_without_authenticator,
    std::span<const std::uint8_t> ml_kem_ciphertext,
    std::span<const std::uint8_t> responder_x25519_public,
    std::span<const std::uint8_t> x25519_shared,
    std::span<const std::uint8_t> ml_kem_shared);

} // namespace yume::providers::ytp1_crypto
