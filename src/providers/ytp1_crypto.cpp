/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/ytp1_crypto.hpp"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/provider.h>

#include <algorithm>
#include <climits>
#include <limits>
#include <stdexcept>

namespace yume::providers::ytp1_crypto {
namespace {

using engine::EndpointRole;
using engine::RecordKeyToken;

struct LibCtxDeleter final {
    void operator()(OSSL_LIB_CTX* value) const noexcept {
        OSSL_LIB_CTX_free(value);
    }
};

struct ProviderDeleter final {
    void operator()(OSSL_PROVIDER* value) const noexcept {
        if (value != nullptr) {
            (void)OSSL_PROVIDER_unload(value);
        }
    }
};

struct PkeyCtxDeleter final {
    void operator()(EVP_PKEY_CTX* value) const noexcept {
        EVP_PKEY_CTX_free(value);
    }
};

struct MdDeleter final {
    void operator()(EVP_MD* value) const noexcept { EVP_MD_free(value); }
};

struct MdCtxDeleter final {
    void operator()(EVP_MD_CTX* value) const noexcept {
        EVP_MD_CTX_free(value);
    }
};

struct CipherDeleter final {
    void operator()(EVP_CIPHER* value) const noexcept {
        EVP_CIPHER_free(value);
    }
};

struct CipherCtxDeleter final {
    void operator()(EVP_CIPHER_CTX* value) const noexcept {
        EVP_CIPHER_CTX_free(value);
    }
};

struct MacDeleter final {
    void operator()(EVP_MAC* value) const noexcept { EVP_MAC_free(value); }
};

struct MacCtxDeleter final {
    void operator()(EVP_MAC_CTX* value) const noexcept {
        EVP_MAC_CTX_free(value);
    }
};

struct KdfDeleter final {
    void operator()(EVP_KDF* value) const noexcept { EVP_KDF_free(value); }
};

struct KdfCtxDeleter final {
    void operator()(EVP_KDF_CTX* value) const noexcept {
        EVP_KDF_CTX_free(value);
    }
};

using LibCtxPtr = std::unique_ptr<OSSL_LIB_CTX, LibCtxDeleter>;
using ProviderPtr = std::unique_ptr<OSSL_PROVIDER, ProviderDeleter>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter>;
using MdPtr = std::unique_ptr<EVP_MD, MdDeleter>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, MdCtxDeleter>;
using CipherPtr = std::unique_ptr<EVP_CIPHER, CipherDeleter>;
using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;
using MacPtr = std::unique_ptr<EVP_MAC, MacDeleter>;
using MacCtxPtr = std::unique_ptr<EVP_MAC_CTX, MacCtxDeleter>;
using KdfPtr = std::unique_ptr<EVP_KDF, KdfDeleter>;
using KdfCtxPtr = std::unique_ptr<EVP_KDF_CTX, KdfCtxDeleter>;


} // namespace

struct CryptoContext::Impl final {
public:
    Impl()
        : library_context_(OSSL_LIB_CTX_new()),
          default_provider_(library_context_
                                ? OSSL_PROVIDER_load(library_context_.get(),
                                                     "default")
                                : nullptr),
          sha256_(library_context_
                      ? EVP_MD_fetch(library_context_.get(),
                                     kSha256Algorithm.data(),
                                     kOpenSslPropertyQuery.data())
                      : nullptr),
          aes_256_gcm_(library_context_
                           ? EVP_CIPHER_fetch(library_context_.get(),
                                              kAes256GcmAlgorithm.data(),
                                              kOpenSslPropertyQuery.data())
                           : nullptr),
          hmac_(library_context_
                    ? EVP_MAC_fetch(library_context_.get(),
                                    kHmacAlgorithm.data(),
                                    kOpenSslPropertyQuery.data())
                    : nullptr),
          hkdf_(library_context_
                    ? EVP_KDF_fetch(library_context_.get(),
                                    kHkdfAlgorithm.data(),
                                    kOpenSslPropertyQuery.data())
                    : nullptr) {
        if (!library_context_ || !default_provider_ || !sha256_ ||
            !aes_256_gcm_ || !hmac_ || !hkdf_) {
            throw std::runtime_error(
                "required OpenSSL 3.5 provider algorithms are unavailable");
        }
        probe_key_algorithm(kEd25519Algorithm);
        probe_key_algorithm(kMlDsa87Algorithm);
        probe_key_algorithm(kMlKem1024Algorithm);
        probe_key_algorithm(kX25519Algorithm);
    }

    OSSL_LIB_CTX* library_context() const noexcept {
        return library_context_.get();
    }
    const EVP_MD* sha256() const noexcept { return sha256_.get(); }
    const EVP_CIPHER* aes_256_gcm() const noexcept {
        return aes_256_gcm_.get();
    }
    EVP_MAC* hmac() const noexcept { return hmac_.get(); }
    EVP_KDF* hkdf() const noexcept { return hkdf_.get(); }

private:
    void probe_key_algorithm(std::string_view algorithm) {
        PkeyCtxPtr probe(EVP_PKEY_CTX_new_from_name(
            library_context_.get(), algorithm.data(),
            kOpenSslPropertyQuery.data()));
        if (!probe) {
            throw std::runtime_error("required key algorithm is unavailable");
        }
    }

    // Destruction is reverse declaration order: fetched algorithms, provider,
    // then library context.
    LibCtxPtr library_context_;
    ProviderPtr default_provider_;
    MdPtr sha256_;
    CipherPtr aes_256_gcm_;
    MacPtr hmac_;
    KdfPtr hkdf_;
};

CryptoContext::CryptoContext() : impl_(std::make_unique<Impl>()) {}
CryptoContext::~CryptoContext() = default;
OSSL_LIB_CTX* CryptoContext::library_context() const noexcept {
    return impl_->library_context();
}
const EVP_MD* CryptoContext::sha256() const noexcept { return impl_->sha256(); }
const EVP_CIPHER* CryptoContext::aes_256_gcm() const noexcept {
    return impl_->aes_256_gcm();
}
EVP_MAC* CryptoContext::hmac() const noexcept { return impl_->hmac(); }
EVP_KDF* CryptoContext::hkdf() const noexcept { return impl_->hkdf(); }

std::span<const std::uint8_t> text_u8(std::string_view input) noexcept {
    return {reinterpret_cast<const std::uint8_t*>(input.data()), input.size()};
}

bool any_nonzero(std::span<const std::uint8_t> value) noexcept {
    std::uint8_t aggregate = 0U;
    for (const std::uint8_t byte : value) {
        aggregate |= byte;
    }
    return aggregate != 0U;
}

void append_u32(std::vector<std::uint8_t>& output,
                std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value >> 24U));
    output.push_back(static_cast<std::uint8_t>(value >> 16U));
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value));
}

void append_u64(std::vector<std::uint8_t>& output,
                std::uint64_t value) {
    for (std::size_t index = 0U; index < 8U; ++index) {
        const std::size_t shift = (7U - index) * 8U;
        output.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

void append_length_prefixed(std::vector<std::uint8_t>& output,
                            std::span<const std::uint8_t> value,
                            std::size_t bound) {
    if (value.size() > std::numeric_limits<std::uint32_t>::max() ||
        output.size() > bound || value.size() > bound - output.size() ||
        output.size() + value.size() > bound - 4U) {
        throw std::length_error("bounded canonical input is too large");
    }
    append_u32(output, static_cast<std::uint32_t>(value.size()));
    output.insert(output.end(), value.begin(), value.end());
}

ytp1::EndpointRole to_ytp_role(EndpointRole role) {
    switch (role) {
    case EndpointRole::Client:
        return ytp1::EndpointRole::Client;
    case EndpointRole::Server:
        return ytp1::EndpointRole::Server;
    }
    throw std::invalid_argument("unknown endpoint role");
}

std::array<std::uint8_t, kSha256Bytes> sha256(
    const CryptoContext& crypto,
    std::span<const std::span<const std::uint8_t>> parts) {
    MdCtxPtr context(EVP_MD_CTX_new());
    if (!context ||
        EVP_DigestInit_ex2(context.get(), crypto.sha256(), nullptr) != 1) {
        throw std::runtime_error("SHA-256 initialization failed");
    }
    std::size_t total = 0U;
    for (const auto part : parts) {
        if (part.size() > kMaxTranscriptInputBytes - total) {
            throw std::length_error("transcript input exceeds its bound");
        }
        total += part.size();
        if (!part.empty() &&
            EVP_DigestUpdate(context.get(), part.data(), part.size()) != 1) {
            throw std::runtime_error("SHA-256 update failed");
        }
    }
    std::array<std::uint8_t, kSha256Bytes> digest{};
    unsigned int written = 0U;
    if (EVP_DigestFinal_ex(context.get(), digest.data(), &written) != 1 ||
        written != digest.size()) {
        OPENSSL_cleanse(digest.data(), digest.size());
        throw std::runtime_error("SHA-256 finalization failed");
    }
    return digest;
}

std::array<std::uint8_t, kSha256Bytes> sha256(
    const CryptoContext& crypto,
    std::initializer_list<std::span<const std::uint8_t>> parts) {
    return sha256(crypto,
                  std::span<const std::span<const std::uint8_t>>(
                      parts.begin(), parts.size()));
}

std::array<std::uint8_t, kSha256Bytes> hmac_sha256(
    const CryptoContext& crypto,
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> message) {
    if (key.empty() || message.size() > kMaxTranscriptInputBytes) {
        throw std::invalid_argument("HMAC input is invalid");
    }
    MacCtxPtr context(EVP_MAC_CTX_new(crypto.hmac()));
    if (!context) {
        throw std::runtime_error("HMAC context allocation failed");
    }
    char digest_name[] = "SHA256";
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                         digest_name, 0U),
        OSSL_PARAM_construct_end(),
    };
    if (EVP_MAC_init(context.get(), key.data(), key.size(), parameters) != 1 ||
        (!message.empty() &&
         EVP_MAC_update(context.get(), message.data(), message.size()) != 1)) {
        throw std::runtime_error("HMAC operation failed");
    }
    std::array<std::uint8_t, kSha256Bytes> output{};
    std::size_t written = 0U;
    if (EVP_MAC_final(context.get(), output.data(), &written,
                      output.size()) != 1 ||
        written != output.size()) {
        OPENSSL_cleanse(output.data(), output.size());
        throw std::runtime_error("HMAC finalization failed");
    }
    return output;
}

SecretBytes hkdf_sha256(const CryptoContext& crypto,
                        std::span<const std::uint8_t> key,
                        std::span<const std::uint8_t> salt,
                        std::span<const std::uint8_t> info,
                        std::size_t output_size) {
    if (key.empty() || output_size == 0U ||
        output_size > 255U * kSha256Bytes ||
        info.size() > kMaxTranscriptInputBytes ||
        salt.size() > kMaxTranscriptInputBytes) {
        throw std::invalid_argument("HKDF input is invalid");
    }
    KdfCtxPtr context(EVP_KDF_CTX_new(crypto.hkdf()));
    if (!context) {
        throw std::runtime_error("HKDF context allocation failed");
    }
    char digest_name[] = "SHA256";
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                         digest_name, 0U),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_KEY, const_cast<std::uint8_t*>(key.data()),
            key.size()),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, const_cast<std::uint8_t*>(salt.data()),
            salt.size()),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO, const_cast<std::uint8_t*>(info.data()),
            info.size()),
        OSSL_PARAM_construct_end(),
    };
    SecretBytes output(output_size);
    if (EVP_KDF_derive(context.get(), output.data(), output.size(),
                       parameters) != 1) {
        throw std::runtime_error("HKDF derivation failed");
    }
    return output;
}

std::vector<std::uint8_t> canonical_tagged_input(
    std::string_view domain,
    std::span<const std::span<const std::uint8_t>> fields,
    std::size_t bound) {
    std::vector<std::uint8_t> output;
    output.reserve(256U);
    append_length_prefixed(output, text_u8(domain), bound);
    for (const auto field : fields) {
        append_length_prefixed(output, field, bound);
    }
    return output;
}

std::array<std::uint8_t, ytp1::kTranscriptHashSize> transcript_hash(
    const CryptoContext& crypto,
    std::span<const std::uint8_t> exporter,
    std::span<const std::span<const std::uint8_t>> messages) {
    std::vector<std::span<const std::uint8_t>> fields;
    fields.reserve(messages.size() + 2U);
    fields.push_back(text_u8(ytp1::kSuiteId));
    fields.push_back(exporter);
    fields.insert(fields.end(), messages.begin(), messages.end());
    const std::vector<std::uint8_t> canonical = canonical_tagged_input(
        ytp1::kTranscriptDomain, fields);
    return sha256(crypto, {canonical});
}

std::vector<std::uint8_t> signature_input(
    EndpointRole sender,
    ytp1::AuthMessageType message_type,
    std::span<const std::uint8_t> exporter,
    std::span<const std::uint8_t> transcript,
    std::span<const std::uint8_t> confirmation) {
    const std::array<std::uint8_t, 1> type{
        static_cast<std::uint8_t>(message_type)};
    const std::array<std::uint8_t, 1> role{
        static_cast<std::uint8_t>(to_ytp_role(sender))};
    const std::array<std::span<const std::uint8_t>, 7> fields{
        text_u8(ytp1::kRoleBindingDomain),
        text_u8(ytp1::kSuiteId),
        ytp1::RequiredSecurityParameters(),
        exporter,
        type,
        role,
        transcript,
    };
    std::vector<std::uint8_t> output = canonical_tagged_input(
        ytp1::kAuthSignatureDomain, fields);
    append_length_prefixed(output, confirmation, kMaxTranscriptInputBytes);
    return output;
}

std::vector<std::uint8_t> psk_authenticator_input(
    ConfirmationPurpose purpose,
    std::span<const std::uint8_t> transcript) {
    const std::array<std::uint8_t, 1> purpose_byte{
        static_cast<std::uint8_t>(purpose)};
    const std::array<std::span<const std::uint8_t>, 3> fields{
        text_u8(ytp1::kSuiteId), purpose_byte, transcript};
    return canonical_tagged_input(ytp1::kPskDomain, fields);
}

std::vector<std::uint8_t> key_confirmation_input(
    ConfirmationPurpose purpose,
    std::span<const std::uint8_t> transcript) {
    const std::array<std::uint8_t, 1> purpose_byte{
        static_cast<std::uint8_t>(purpose)};
    const std::array<std::span<const std::uint8_t>, 3> fields{
        text_u8(ytp1::kSuiteId), purpose_byte, transcript};
    return canonical_tagged_input(
        ytp1::kHandshakeConfirmationDomain, fields);
}

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
    std::span<const std::uint8_t> ml_kem_shared_secret) {
    if (!any_nonzero(x25519_shared_secret) ||
        !any_nonzero(ml_kem_shared_secret)) {
        throw std::invalid_argument("hybrid shared contribution is invalid");
    }
    const ytp1::KeyScheduleInput input{
        ytp1::EndpointRole::Client,
        ytp1::EndpointRole::Server,
        transcript,
        exporter,
        client_identity,
        server_identity,
        client_capabilities,
        server_capabilities,
        access_psk,
        client_x25519_public_key,
        server_x25519_public_key,
        x25519_shared_secret,
        ml_kem_public_key,
        ml_kem_ciphertext,
        ml_kem_shared_secret,
    };
    const auto required = ytp1::KeyScheduleInputEncodedSize(input);
    if (!required.ok() || *required.value > ytp1::kMaxKeyScheduleInputSize) {
        throw std::invalid_argument("YTP/1 key-schedule input is invalid");
    }
    SecretBytes canonical(*required.value);
    std::size_t written = 0U;
    const ytp1::Status encoded = ytp1::EncodeKeyScheduleInput(
        input, canonical.mutable_span(), written);
    if (!encoded.ok() || written != canonical.size()) {
        throw std::runtime_error("YTP/1 key-schedule encoding failed");
    }
    SecretBytes root = hkdf_sha256(
        crypto, canonical.span(), transcript, text_u8(ytp1::kRootDomain),
        kSha256Bytes);
    HandshakeRoots output;
    output.client_to_server = hkdf_sha256(
        crypto, root.span(), transcript,
        text_u8(ytp1::kClientToServerDomain), kSha256Bytes);
    output.server_to_client = hkdf_sha256(
        crypto, root.span(), transcript,
        text_u8(ytp1::kServerToClientDomain), kSha256Bytes);
    output.master = std::move(root);
    return output;
}

std::vector<std::uint8_t> record_aad(EndpointRole sender,
                                     RecordKeyToken token) {
    const std::array<std::uint8_t, 1> direction{
        sender == EndpointRole::Client ? std::uint8_t{1U}
                                       : std::uint8_t{2U}};
    std::vector<std::uint8_t> token_bytes;
    token_bytes.reserve(12U);
    append_u32(token_bytes, token.epoch);
    append_u64(token_bytes, token.sequence);
    const std::array<std::span<const std::uint8_t>, 3> fields{
        text_u8(ytp1::kSuiteId), direction, token_bytes};
    return canonical_tagged_input(ytp1::kAadDomain, fields);
}

SecretBytes derive_record_material(
    const CryptoContext& crypto,
    std::span<const std::uint8_t> directional_root,
    EndpointRole sender,
    RecordKeyToken token,
    std::span<const std::uint8_t> session_binding) {
    const std::vector<std::uint8_t> aad = record_aad(sender, token);
    const std::array<std::span<const std::uint8_t>, 3> fields{
        text_u8(ytp1::kMessageDomain), session_binding, aad};
    const std::vector<std::uint8_t> info = canonical_tagged_input(
        ytp1::kMessageDomain, fields);
    return hkdf_sha256(crypto, directional_root, session_binding, info,
                       kRecordKeyMaterialBytes);
}

std::vector<std::uint8_t> seal_aes_gcm(
    const CryptoContext& crypto,
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> aad,
    std::span<const std::uint8_t> plaintext) {
    if (key.size() != kAes256KeyBytes || nonce.size() != kAesGcmNonceBytes ||
        plaintext.size() > static_cast<std::size_t>(INT_MAX) ||
        aad.size() > static_cast<std::size_t>(INT_MAX) ||
        plaintext.size() > engine::kAbsoluteMaxBufferBytes - kAesGcmTagBytes) {
        throw std::invalid_argument("AES-GCM seal input is invalid");
    }
    CipherCtxPtr context(EVP_CIPHER_CTX_new());
    if (!context ||
        EVP_EncryptInit_ex2(context.get(), crypto.aes_256_gcm(), key.data(),
                            nonce.data(), nullptr) != 1) {
        throw std::runtime_error("AES-GCM initialization failed");
    }
    int ignored = 0;
    if ((!aad.empty() &&
         EVP_EncryptUpdate(context.get(), nullptr, &ignored, aad.data(),
                           static_cast<int>(aad.size())) != 1)) {
        throw std::runtime_error("AES-GCM AAD processing failed");
    }
    std::vector<std::uint8_t> output(plaintext.size() + kAesGcmTagBytes);
    int written = 0;
    if ((!plaintext.empty() &&
         EVP_EncryptUpdate(context.get(), output.data(), &written,
                           plaintext.data(),
                           static_cast<int>(plaintext.size())) != 1) ||
        written != static_cast<int>(plaintext.size())) {
        throw std::runtime_error("AES-GCM encryption failed");
    }
    int final_written = 0;
    if (EVP_EncryptFinal_ex(context.get(), output.data() + written,
                            &final_written) != 1 ||
        final_written != 0 ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_GET_TAG,
                            static_cast<int>(kAesGcmTagBytes),
                            output.data() + plaintext.size()) != 1) {
        throw std::runtime_error("AES-GCM finalization failed");
    }
    return output;
}

std::vector<std::uint8_t> open_aes_gcm(
    const CryptoContext& crypto,
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> nonce,
    std::span<const std::uint8_t> aad,
    std::span<const std::uint8_t> ciphertext) {
    if (key.size() != kAes256KeyBytes || nonce.size() != kAesGcmNonceBytes ||
        ciphertext.size() < kAesGcmTagBytes ||
        ciphertext.size() > engine::kAbsoluteMaxBufferBytes ||
        ciphertext.size() - kAesGcmTagBytes >
            static_cast<std::size_t>(INT_MAX) ||
        aad.size() > static_cast<std::size_t>(INT_MAX)) {
        throw std::invalid_argument("AES-GCM open input is invalid");
    }
    const std::size_t plaintext_size = ciphertext.size() - kAesGcmTagBytes;
    const auto body = ciphertext.first(plaintext_size);
    const auto tag = ciphertext.last(kAesGcmTagBytes);
    CipherCtxPtr context(EVP_CIPHER_CTX_new());
    if (!context ||
        EVP_DecryptInit_ex2(context.get(), crypto.aes_256_gcm(), key.data(),
                            nonce.data(), nullptr) != 1) {
        throw std::runtime_error("AES-GCM initialization failed");
    }
    int ignored = 0;
    if ((!aad.empty() &&
         EVP_DecryptUpdate(context.get(), nullptr, &ignored, aad.data(),
                           static_cast<int>(aad.size())) != 1)) {
        throw std::runtime_error("AES-GCM AAD processing failed");
    }
    std::vector<std::uint8_t> plaintext(plaintext_size);
    int written = 0;
    if ((!body.empty() &&
         EVP_DecryptUpdate(context.get(), plaintext.data(), &written,
                           body.data(), static_cast<int>(body.size())) != 1) ||
        written != static_cast<int>(plaintext_size) ||
        EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_AEAD_SET_TAG,
                            static_cast<int>(tag.size()),
                            const_cast<std::uint8_t*>(tag.data())) != 1) {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        throw std::invalid_argument("AES-GCM ciphertext was rejected");
    }
    std::uint8_t empty_output = 0U;
    std::uint8_t* const final_output = plaintext.empty()
        ? &empty_output
        : plaintext.data() + written;
    int final_written = 0;
    if (EVP_DecryptFinal_ex(context.get(), final_output,
                            &final_written) != 1 ||
        final_written != 0) {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        throw std::invalid_argument("AES-GCM ciphertext was rejected");
    }
    return plaintext;
}

std::vector<std::uint8_t> challenge_context(
    std::span<const std::uint8_t> exporter,
    std::span<const std::uint8_t> server_identity,
    std::span<const std::uint8_t> ml_kem_public,
    std::span<const std::uint8_t> server_x25519_public,
    std::span<const std::uint8_t> server_capabilities,
    std::span<const std::uint8_t> nonce) {
    const std::array<std::uint8_t, 1> type{
        static_cast<std::uint8_t>(ytp1::AuthMessageType::Challenge)};
    const std::array<std::uint8_t, 1> role{
        static_cast<std::uint8_t>(ytp1::EndpointRole::Server)};
    const std::array<std::span<const std::uint8_t>, 9> fields{
        type, role, text_u8(ytp1::kSuiteId),
        ytp1::RequiredSecurityParameters(), exporter, server_identity,
        ml_kem_public, server_x25519_public, server_capabilities};
    std::vector<std::uint8_t> context = canonical_tagged_input(
        ytp1::kTranscriptDomain, fields);
    append_length_prefixed(context, nonce, kMaxTranscriptInputBytes);
    return context;
}

std::vector<std::uint8_t> response_context(
    std::span<const std::uint8_t> canonical_challenge,
    std::span<const std::uint8_t> client_identity,
    std::span<const std::uint8_t> ml_kem_ciphertext,
    std::span<const std::uint8_t> client_x25519_public,
    std::span<const std::uint8_t> client_capabilities) {
    const std::array<std::uint8_t, 1> type{
        static_cast<std::uint8_t>(ytp1::AuthMessageType::Response)};
    const std::array<std::uint8_t, 1> role{
        static_cast<std::uint8_t>(ytp1::EndpointRole::Client)};
    const std::array<std::span<const std::uint8_t>, 9> fields{
        type, role, text_u8(ytp1::kSuiteId),
        ytp1::RequiredSecurityParameters(), canonical_challenge,
        client_identity, ml_kem_ciphertext, client_x25519_public,
        client_capabilities};
    return canonical_tagged_input(ytp1::kTranscriptDomain, fields);
}

std::vector<std::uint8_t> rekey_init_auth_input(
    EndpointRole direction,
    std::uint32_t epoch,
    std::span<const std::uint8_t> session_binding,
    std::span<const std::uint8_t> ml_kem_public,
    std::span<const std::uint8_t> x25519_public,
    std::span<const std::uint8_t> nonce) {
    const std::array<std::uint8_t, 1> direction_byte{
        static_cast<std::uint8_t>(to_ytp_role(direction))};
    std::vector<std::uint8_t> epoch_bytes;
    epoch_bytes.reserve(4U);
    append_u32(epoch_bytes, epoch);
    const std::array<std::span<const std::uint8_t>, 7> fields{
        text_u8(ytp1::kSuiteId), session_binding, direction_byte,
        epoch_bytes, ml_kem_public, x25519_public, nonce};
    return canonical_tagged_input(
        ytp1::kRatchetDomain, fields, kMaxRatchetInputBytes);
}

std::vector<std::uint8_t> rekey_ack_auth_input(
    EndpointRole direction,
    std::uint32_t epoch,
    std::span<const std::uint8_t> session_binding,
    std::span<const std::uint8_t> canonical_init_without_authenticator,
    std::span<const std::uint8_t> ml_kem_ciphertext,
    std::span<const std::uint8_t> x25519_public) {
    const std::array<std::uint8_t, 1> direction_byte{
        static_cast<std::uint8_t>(to_ytp_role(direction))};
    std::vector<std::uint8_t> epoch_bytes;
    epoch_bytes.reserve(4U);
    append_u32(epoch_bytes, epoch);
    const std::array<std::span<const std::uint8_t>, 7> fields{
        text_u8(ytp1::kSuiteId), session_binding, direction_byte,
        epoch_bytes, canonical_init_without_authenticator,
        ml_kem_ciphertext, x25519_public};
    return canonical_tagged_input(
        ytp1::kRatchetDomain, fields, kMaxRatchetInputBytes);
}

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
    std::span<const std::uint8_t> ml_kem_shared) {
    if (old_root.size() != kSha256Bytes ||
        !any_nonzero(x25519_shared) || !any_nonzero(ml_kem_shared)) {
        throw std::invalid_argument("ratchet shared contribution is invalid");
    }
    const std::vector<std::uint8_t> public_binding = rekey_ack_auth_input(
        direction, epoch, session_binding,
        canonical_init_without_authenticator, ml_kem_ciphertext,
        responder_x25519_public);
    SecretBytes secret_input(x25519_shared.size() + ml_kem_shared.size());
    std::copy(x25519_shared.begin(), x25519_shared.end(),
              secret_input.mutable_span().begin());
    std::copy(ml_kem_shared.begin(), ml_kem_shared.end(),
              secret_input.mutable_span().begin() +
                  static_cast<std::ptrdiff_t>(x25519_shared.size()));
    return hkdf_sha256(crypto, secret_input.span(), old_root,
                       public_binding, kSha256Bytes);
}

} // namespace yume::providers::ytp1_crypto
