/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "modules/relay/identity.hpp"

#include <algorithm>
#include <stdexcept>
#include <string>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "core/security/secure_erase.hpp"

namespace yume::relay::identity {
namespace {

constexpr std::size_t kSha256Bytes = 32U;
constexpr std::string_view kFingerprintDomain = "yume/ytp/1/composite-identity/v1";
// Well above the roughly 3.7 KB of a composite identity.
constexpr std::size_t kMaxIdentityPemBytes = 64U * 1024U;

std::runtime_error ssl_error(const std::string& message) {
    const unsigned long error = ERR_get_error();
    char buffer[256] = {0};
    ERR_error_string_n(error, buffer, sizeof(buffer));
    return std::runtime_error(message + ": " + buffer);
}

// EdDSA and ML-DSA sign in one shot without a digest. ML-DSA is a provider
// algorithm with no legacy NID, so it is matched by name.
const EVP_MD* select_digest(EVP_PKEY* key) {
    if (!key) return EVP_sha256();
    const int type = EVP_PKEY_base_id(key);
    if (type == EVP_PKEY_ED25519 || type == EVP_PKEY_ED448) return nullptr;
    const char* name = EVP_PKEY_get0_type_name(key);
    if (name != nullptr && std::string_view(name).starts_with("ML-DSA")) return nullptr;
    return EVP_sha256();
}

bool verify_key(EVP_PKEY* public_key, const Bytes& message, const Bytes& signature) {
    if (!public_key) return false;
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(
        EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!context) throw ssl_error("failed to allocate verify context");
    if (EVP_DigestVerifyInit(context.get(), nullptr, select_digest(public_key), nullptr,
                             public_key) != 1) {
        throw ssl_error("verify init failed");
    }
    return EVP_DigestVerify(context.get(), signature.data(), signature.size(),
                            message.data(), message.size()) == 1;
}

Bytes sign_message(EVP_PKEY* private_key, const Bytes& message) {
    if (!private_key) throw std::runtime_error("sign_message: missing private key");
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(
        EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!context) throw ssl_error("failed to allocate sign context");
    if (EVP_DigestSignInit(context.get(), nullptr, select_digest(private_key), nullptr,
                           private_key) != 1) {
        throw ssl_error("sign init failed");
    }
    std::size_t length = 0;
    if (EVP_DigestSign(context.get(), nullptr, &length, message.data(), message.size()) != 1) {
        throw ssl_error("sign size failed");
    }
    Bytes signature(length);
    if (EVP_DigestSign(context.get(), signature.data(), &length, message.data(),
                       message.size()) != 1) {
        throw ssl_error("sign failed");
    }
    signature.resize(length);
    return signature;
}

KeyPair generate_named_keypair(const char* algorithm) {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
        EVP_PKEY_CTX_new_from_name(nullptr, algorithm, nullptr), EVP_PKEY_CTX_free);
    if (!context) throw ssl_error(std::string("no provider for ") + algorithm);
    if (EVP_PKEY_keygen_init(context.get()) != 1) {
        throw ssl_error(std::string("keygen init failed for ") + algorithm);
    }
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(context.get(), &raw) != 1) {
        throw ssl_error(std::string("keygen failed for ") + algorithm);
    }
    KeyPair pair;
    pair.private_key.reset(raw);
    // The generated object holds both halves. The public view is the same
    // object under a second reference.
    if (EVP_PKEY_up_ref(raw) != 1) throw ssl_error("failed to reference generated public key");
    pair.public_key.reset(raw);
    return pair;
}

bool is_pem_whitespace(std::uint8_t value) {
    return value == ' ' || value == '\t' || value == '\r' || value == '\n';
}

bool consume_pem_block(const Bytes& bundle, std::size_t& cursor, std::string_view label) {
    while (cursor < bundle.size() && is_pem_whitespace(bundle[cursor])) ++cursor;
    const std::string begin = "-----BEGIN " + std::string(label) + "-----";
    const std::string end = "-----END " + std::string(label) + "-----";
    if (cursor + begin.size() > bundle.size() ||
        !std::equal(begin.begin(), begin.end(), bundle.begin() + static_cast<std::ptrdiff_t>(cursor))) {
        return false;
    }
    cursor += begin.size();
    const auto end_it = std::search(bundle.begin() + static_cast<std::ptrdiff_t>(cursor),
                                    bundle.end(), end.begin(), end.end());
    if (end_it == bundle.end()) return false;
    cursor = static_cast<std::size_t>(end_it - bundle.begin()) + end.size();
    return cursor >= bundle.size() || is_pem_whitespace(bundle[cursor]);
}

std::string hex_lower(const Bytes& bytes) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2U);
    for (const std::uint8_t byte : bytes) {
        out.push_back(kDigits[byte >> 4U]);
        out.push_back(kDigits[byte & 15U]);
    }
    return out;
}

bool has_exact_pem_sequence(const Bytes& bundle, std::string_view label, std::size_t count) {
    std::size_t cursor = 0;
    for (std::size_t i = 0; i < count; ++i) {
        if (!consume_pem_block(bundle, cursor, label)) return false;
    }
    while (cursor < bundle.size() && is_pem_whitespace(bundle[cursor])) ++cursor;
    return cursor == bundle.size();
}

}  // namespace

struct Sha256Stream::Impl {
    Impl() : context(EVP_MD_CTX_new(), EVP_MD_CTX_free) {
        if (!context || EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
            throw std::runtime_error("SHA-256 stream initialization failed");
        }
    }

    ~Impl() { Invalidate(); }

    void Invalidate() noexcept {
        if (context) (void)EVP_MD_CTX_reset(context.get());
        active = false;
    }

    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context;
    bool active{true};
};

Sha256Stream::Sha256Stream() : impl_(std::make_unique<Impl>()) {}
Sha256Stream::Sha256Stream(Sha256Stream&& other) noexcept = default;
Sha256Stream& Sha256Stream::operator=(Sha256Stream&& other) noexcept = default;
Sha256Stream::~Sha256Stream() = default;

void Sha256Stream::Update(std::span<const std::uint8_t> input) {
    if (!impl_ || !impl_->active) throw std::logic_error("SHA-256 stream is no longer active");
    if (input.empty()) return;
    if (EVP_DigestUpdate(impl_->context.get(), input.data(), input.size()) != 1) {
        impl_->Invalidate();
        throw std::runtime_error("SHA-256 stream update failed");
    }
}

Bytes Sha256Stream::Finish() {
    if (!impl_ || !impl_->active) throw std::logic_error("SHA-256 stream is no longer active");
    Bytes digest(kSha256Bytes);
    unsigned int digest_length = 0;
    const int result = EVP_DigestFinal_ex(impl_->context.get(), digest.data(), &digest_length);
    impl_->Invalidate();
    if (result != 1 || digest_length != kSha256Bytes) {
        security::secure_erase(digest);
        throw std::runtime_error("SHA-256 stream finalization failed");
    }
    return digest;
}

CompositeKeyPair generate_composite_keypair() {
    CompositeKeyPair keys;
    keys.classical = generate_named_keypair("ED25519");
    keys.pq = generate_named_keypair(std::string(kCompositePqAlgorithm).c_str());
    return keys;
}

Bytes sign_composite(const CompositeKeyPair& keys, const Bytes& message) {
    const Bytes classical = sign_message(keys.classical.private_key.get(), message);
    const Bytes pq = sign_message(keys.pq.private_key.get(), message);
    if (classical.size() != kEd25519SignatureLen) {
        throw std::runtime_error("composite: unexpected Ed25519 signature size");
    }
    if (pq.size() != kMlDsa87SignatureLen) {
        throw std::runtime_error("composite: unexpected ML-DSA-87 signature size");
    }
    Bytes signature;
    signature.reserve(kCompositeSignatureLen);
    signature.insert(signature.end(), classical.begin(), classical.end());
    signature.insert(signature.end(), pq.begin(), pq.end());
    return signature;
}

bool verify_composite(EVP_PKEY* classical_pub, EVP_PKEY* pq_pub,
                      const Bytes& message, const Bytes& signature) {
    if (classical_pub == nullptr || pq_pub == nullptr) return false;
    if (signature.size() != kCompositeSignatureLen) return false;
    const Bytes classical(signature.begin(),
                          signature.begin() + static_cast<std::ptrdiff_t>(kEd25519SignatureLen));
    const Bytes pq(signature.begin() + static_cast<std::ptrdiff_t>(kEd25519SignatureLen),
                   signature.end());
    // Always both halves, without short-circuiting, so timing does not show
    // which half failed.
    const bool classical_ok = verify_key(classical_pub, message, classical);
    const bool pq_ok = verify_key(pq_pub, message, pq);
    return classical_ok && pq_ok;
}

Bytes encode_public_key_pem(EVP_PKEY* key) {
    if (key == nullptr) throw std::runtime_error("encode_public_key_pem: null key");
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!bio) throw ssl_error("failed to allocate PEM buffer");
    if (PEM_write_bio_PUBKEY(bio.get(), key) != 1) throw ssl_error("failed to encode public key");
    char* data = nullptr;
    const long length = BIO_get_mem_data(bio.get(), &data);
    if (length <= 0 || data == nullptr) {
        throw std::runtime_error("encode_public_key_pem produced no output");
    }
    return Bytes(data, data + length);
}

Bytes encode_composite_identity(EVP_PKEY* classical_pub, EVP_PKEY* pq_pub) {
    Bytes encoded = encode_public_key_pem(classical_pub);
    const Bytes pq = encode_public_key_pem(pq_pub);
    encoded.insert(encoded.end(), pq.begin(), pq.end());
    return encoded;
}

CompositePublicKey parse_composite_identity(const Bytes& pem_bundle) {
    CompositePublicKey parsed;
    if (pem_bundle.empty() || pem_bundle.size() > kMaxIdentityPemBytes) return parsed;
    if (!has_exact_pem_sequence(pem_bundle, "PUBLIC KEY", 2)) return parsed;
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(
        BIO_new_mem_buf(pem_bundle.data(), static_cast<int>(pem_bundle.size())), BIO_free);
    if (!bio) return parsed;
    EvpPkeyPtr first(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    if (!first) return parsed;
    EvpPkeyPtr second(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    if (!second) return parsed;
    if (EVP_PKEY_base_id(first.get()) != EVP_PKEY_ED25519) return parsed;
    const char* pq_name = EVP_PKEY_get0_type_name(second.get());
    if (pq_name == nullptr || std::string_view(pq_name) != kCompositePqAlgorithm) return parsed;
    parsed.classical = std::move(first);
    parsed.pq = std::move(second);
    return parsed;
}

std::string composite_fingerprint(const CompositePublicKey& key) {
    if (!key.valid()) throw std::runtime_error("composite fingerprint needs a valid key");
    Sha256Stream digest;
    digest.Update(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(kFingerprintDomain.data()),
        kFingerprintDomain.size()));
    for (EVP_PKEY* half : {key.classical.get(), key.pq.get()}) {
        // OPENSSL_free is a macro, so it is wrapped to serve as a deleter.
        const auto free_der = [](unsigned char* pointer) { OPENSSL_free(pointer); };
        unsigned char* der = nullptr;
        const int length = i2d_PUBKEY(half, &der);
        if (length <= 0 || der == nullptr) throw ssl_error("failed to encode identity half");
        std::unique_ptr<unsigned char, decltype(free_der)> owned(der, free_der);
        const auto size = static_cast<std::uint32_t>(length);
        const std::uint8_t prefix[4] = {
            static_cast<std::uint8_t>(size >> 24U), static_cast<std::uint8_t>(size >> 16U),
            static_cast<std::uint8_t>(size >> 8U), static_cast<std::uint8_t>(size)};
        digest.Update(prefix);
        digest.Update(std::span<const std::uint8_t>(der, static_cast<std::size_t>(length)));
    }
    return hex_lower(digest.Finish());
}

std::string sha256_hex(std::string_view input) {
    Sha256Stream digest;
    digest.Update(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(input.data()), input.size()));
    return hex_lower(digest.Finish());
}

}  // namespace yume::relay::identity
