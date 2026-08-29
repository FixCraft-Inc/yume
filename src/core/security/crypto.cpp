/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/security/crypto.hpp"

#include "core/encoding/hex.hpp"
#include "core/security/secret_file.hpp"
#include "core/security/secure_erase.hpp"

#if YUME_USE_BASEFWX
#include <basefwx/crypto.hpp>
#endif

#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>

#include <algorithm>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string_view>

namespace yume::crypto {

namespace {

constexpr std::size_t kSha256Bytes = 32U;
constexpr std::size_t kChaCha20Poly1305TagBytes = 16U;

}  // namespace

struct Sha256Stream::Impl {
    Impl() : context(EVP_MD_CTX_new(), EVP_MD_CTX_free) {
        if (!context ||
            EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) != 1) {
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
    if (!impl_ || !impl_->active) {
        throw std::logic_error("SHA-256 stream is no longer active");
    }
    if (input.empty()) return;
    if (EVP_DigestUpdate(impl_->context.get(), input.data(), input.size()) != 1) {
        impl_->Invalidate();
        throw std::runtime_error("SHA-256 stream update failed");
    }
}

Bytes Sha256Stream::Finish() {
    if (!impl_ || !impl_->active) {
        throw std::logic_error("SHA-256 stream is no longer active");
    }
    Bytes digest(kSha256Bytes);
    unsigned int digest_length = 0;
    const int result = EVP_DigestFinal_ex(
        impl_->context.get(), digest.data(), &digest_length);
    impl_->Invalidate();
    if (result != 1 || digest_length != kSha256Bytes) {
        security::secure_erase(digest);
        throw std::runtime_error("SHA-256 stream finalization failed");
    }
    return digest;
}

std::string Sha256Stream::FinishHex() {
    Bytes digest = Finish();
    try {
        std::string encoded = encoding::hex_lower(digest);
        security::secure_erase(digest);
        return encoded;
    } catch (...) {
        security::secure_erase(digest);
        throw;
    }
}

Bytes sha256(std::span<const std::uint8_t> input) {
    Sha256Stream stream;
    stream.Update(input);
    return stream.Finish();
}

Bytes sha256(std::string_view input) {
    return sha256(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(input.data()), input.size()));
}

std::string sha256_hex(std::span<const std::uint8_t> input) {
    Sha256Stream stream;
    stream.Update(input);
    return stream.FinishHex();
}

std::string sha256_hex(std::string_view input) {
    return sha256_hex(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(input.data()), input.size()));
}

namespace {
std::runtime_error ssl_error(const std::string& msg) {
    unsigned long err = ERR_get_error();
    char buf[256] = {0};
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::runtime_error(msg + ": " + buf);
}

const EVP_MD* select_digest(EVP_PKEY* key) {
    if (!key) {
        return EVP_sha256();
    }
    int type = EVP_PKEY_base_id(key);
    if (type == EVP_PKEY_ED25519 || type == EVP_PKEY_ED448) {
        return nullptr;  // EdDSA is one-shot without a digest
    }
    // ML-DSA is also one-shot, but it is a provider-side algorithm with no
    // legacy NID, so EVP_PKEY_base_id returns 0 and the check above misses it.
    // Handing it EVP_sha256() makes EVP_DigestSignInit fail. Match on the
    // algorithm name instead, which is what OpenSSL 3.5 actually exposes.
    const char* name = EVP_PKEY_get0_type_name(key);
    if (name != nullptr && std::string_view(name).starts_with("ML-DSA")) {
        return nullptr;
    }
    return EVP_sha256();
}

bool is_pem_whitespace(std::uint8_t value) {
    return value == ' ' || value == '\t' || value == '\r' || value == '\n';
}

bool consume_pem_block(const Bytes& bundle, std::size_t& cursor,
                       std::string_view label) {
    while (cursor < bundle.size() && is_pem_whitespace(bundle[cursor])) {
        ++cursor;
    }

    const std::string begin = "-----BEGIN " + std::string(label) + "-----";
    const std::string end = "-----END " + std::string(label) + "-----";
    if (cursor + begin.size() > bundle.size() ||
        !std::equal(begin.begin(), begin.end(), bundle.begin() + cursor)) {
        return false;
    }
    cursor += begin.size();

    const auto end_it = std::search(bundle.begin() + cursor, bundle.end(),
                                    end.begin(), end.end());
    if (end_it == bundle.end()) return false;
    cursor = static_cast<std::size_t>(end_it - bundle.begin()) + end.size();
    if (cursor < bundle.size() && !is_pem_whitespace(bundle[cursor])) {
        return false;
    }
    return true;
}

bool has_exact_pem_sequence(const Bytes& bundle, std::string_view label,
                            std::size_t count) {
    std::size_t cursor = 0;
    for (std::size_t i = 0; i < count; ++i) {
        if (!consume_pem_block(bundle, cursor, label)) return false;
    }
    while (cursor < bundle.size() && is_pem_whitespace(bundle[cursor])) {
        ++cursor;
    }
    return cursor == bundle.size();
}
}  // namespace

EVP_PKEY_ptr load_private_key(const std::string& path_priv) {
    if (path_priv.empty()) {
        throw std::runtime_error("private key path is empty");
    }
    // Ownership and mode are an invariant of loading, not a hint: an
    // identity file another account can read or replace must never be able to
    // sign an AUTH transcript.
    Bytes pem = security::ReadPrivateKeyFileStrict(path_priv);
    std::unique_ptr<BIO, decltype(&BIO_free)> private_bio(
        BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    if (!private_bio) {
        security::secure_erase(pem);
        throw ssl_error("failed to open private key");
    }
    EVP_PKEY_ptr private_key(
        PEM_read_bio_PrivateKey(
            private_bio.get(), nullptr, nullptr, nullptr),
        EVP_PKEY_free);
    security::secure_erase(pem);
    if (!private_key) {
        throw ssl_error("failed to read private key");
    }
    return private_key;
}

KeyPair load_keypair(const std::string& path_priv, const std::string& path_pub) {
    KeyPair kp;

    if (!path_priv.empty()) {
        kp.private_key = load_private_key(path_priv);
    }

    if (!path_pub.empty()) {
        BIO* pub_bio = BIO_new_file(path_pub.c_str(), "r");
        if (!pub_bio) {
            throw ssl_error("failed to open public key");
        }
        EVP_PKEY* pub = PEM_read_bio_PUBKEY(pub_bio, nullptr, nullptr, nullptr);
        BIO_free(pub_bio);
        if (!pub) {
            throw ssl_error("failed to read public key");
        }
        kp.public_key.reset(pub);
    } else if (kp.private_key) {
        EVP_PKEY* pub = EVP_PKEY_dup(kp.private_key.get());
        if (!pub) {
            throw ssl_error("failed to derive public key from private key");
        }
        kp.public_key.reset(pub);
    }

    return kp;
}

bool verify_key(EVP_PKEY* pubkey, const Bytes& message, const Bytes& signature) {
    if (!pubkey) {
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw ssl_error("failed to allocate verify context");
    }

    const EVP_MD* md = select_digest(pubkey);
    int rc = EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, pubkey);
    if (rc != 1) {
        EVP_MD_CTX_free(ctx);
        throw ssl_error("verify init failed");
    }

    rc = EVP_DigestVerify(ctx,
                          signature.data(), signature.size(),
                          message.data(), message.size());
    EVP_MD_CTX_free(ctx);
    return rc == 1;
}

Bytes sign_message(EVP_PKEY* privkey, const Bytes& message) {
    if (!privkey) {
        throw std::runtime_error("sign_message: missing private key");
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw ssl_error("failed to allocate sign context");
    }

    const EVP_MD* md = select_digest(privkey);
    int rc = EVP_DigestSignInit(ctx, nullptr, md, nullptr, privkey);
    if (rc != 1) {
        EVP_MD_CTX_free(ctx);
        throw ssl_error("sign init failed");
    }

    size_t sig_len = 0;
    rc = EVP_DigestSign(ctx, nullptr, &sig_len, message.data(), message.size());
    if (rc != 1) {
        EVP_MD_CTX_free(ctx);
        throw ssl_error("sign size failed");
    }

    Bytes sig(sig_len);
    rc = EVP_DigestSign(ctx, sig.data(), &sig_len, message.data(), message.size());
    EVP_MD_CTX_free(ctx);
    if (rc != 1) {
        throw ssl_error("sign failed");
    }
    sig.resize(sig_len);
    return sig;
}

Bytes encrypt_chacha20(const Bytes& data, const Bytes& key, const Bytes& nonce) {
#if YUME_USE_BASEFWX
    return basefwx::crypto::ChaCha20Poly1305EncryptWithIv(
        key, nonce, data, {});
#else
    if (key.size() != 32) {
        throw std::runtime_error("encrypt_chacha20: key must be 32 bytes");
    }
    if (nonce.size() != 12) {
        throw std::runtime_error("encrypt_chacha20: nonce must be 12 bytes");
    }
    if (data.size() > static_cast<std::size_t>(
                          std::numeric_limits<int>::max())) {
        throw std::runtime_error("encrypt_chacha20: plaintext is too large");
    }

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
        throw ssl_error("cipher ctx alloc failed");
    }

    if (EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr,
                           nullptr, nullptr) != 1) {
        throw ssl_error("encrypt init failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, nonce.size(),
                            nullptr) != 1) {
        throw ssl_error("set ivlen failed");
    }

    if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(),
                           nonce.data()) != 1) {
        throw ssl_error("encrypt key init failed");
    }

    Bytes out(data.size() + kChaCha20Poly1305TagBytes);
    int out_len = 0;
    std::size_t total_len = 0;
    const auto advance = [&out, &total_len](int produced,
                                            const char* message) {
        if (produced < 0 ||
            static_cast<std::size_t>(produced) > out.size() - total_len) {
            throw std::runtime_error(message);
        }
        total_len += static_cast<std::size_t>(produced);
    };
    if (!data.empty()) {
        if (EVP_EncryptUpdate(ctx.get(), out.data(), &out_len, data.data(),
                              static_cast<int>(data.size())) != 1) {
            throw ssl_error("encrypt update failed");
        }
        advance(out_len, "encrypt update overran its buffer");
    }

    if (EVP_EncryptFinal_ex(ctx.get(), out.data() + total_len, &out_len) != 1) {
        throw ssl_error("encrypt final failed");
    }
    advance(out_len, "encrypt final overran its buffer");

    unsigned char tag[kChaCha20Poly1305TagBytes] = {0};
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, sizeof(tag),
                            tag) != 1) {
        throw ssl_error("get tag failed");
    }

    if (total_len > out.size() - sizeof(tag)) {
        throw std::runtime_error("encrypt output has no room for its tag");
    }
    std::memcpy(out.data() + total_len, tag, sizeof(tag));
    total_len += sizeof(tag);
    out.resize(total_len);
    return out;
#endif
}

Bytes decrypt_chacha20(const Bytes& data, const Bytes& key, const Bytes& nonce) {
#if YUME_USE_BASEFWX
    return basefwx::crypto::ChaCha20Poly1305DecryptWithIvOwned(
        key, nonce, data.data(), data.size(), {});
#else
    if (key.size() != 32) {
        throw std::runtime_error("decrypt_chacha20: key must be 32 bytes");
    }
    if (nonce.size() != 12) {
        throw std::runtime_error("decrypt_chacha20: nonce must be 12 bytes");
    }
    if (data.size() < kChaCha20Poly1305TagBytes) {
        throw std::runtime_error("decrypt_chacha20: data too short");
    }

    const size_t cipher_len = data.size() - kChaCha20Poly1305TagBytes;
    if (cipher_len > static_cast<std::size_t>(
                         std::numeric_limits<int>::max())) {
        throw std::runtime_error("decrypt_chacha20: ciphertext is too large");
    }
    const unsigned char* tag = data.data() + cipher_len;

    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) {
        throw ssl_error("cipher ctx alloc failed");
    }

    if (EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr,
                           nullptr, nullptr) != 1) {
        throw ssl_error("decrypt init failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_IVLEN, nonce.size(),
                            nullptr) != 1) {
        throw ssl_error("set ivlen failed");
    }

    if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(),
                           nonce.data()) != 1) {
        throw ssl_error("decrypt key init failed");
    }

    // OpenSSL publishes ChaCha20 plaintext from DecryptUpdate before the
    // Poly1305 tag is checked by DecryptFinal. Keep an armed wipe tied to the
    // staging buffer across every exceptional path and release it only after
    // authentication succeeds.
    // Give Final tag-sized slack before asking OpenSSL to write. The cipher is
    // specified to emit no final plaintext, but that invariant is safe to
    // verify only when the callee has room to violate it.
    Bytes out(data.size());
    struct UnauthenticatedPlaintextWiper {
        Bytes& bytes;
        bool armed{true};
        ~UnauthenticatedPlaintextWiper() {
            if (armed) security::secure_erase(bytes);
        }
        void Release() noexcept { armed = false; }
    } out_wiper{out};
    int out_len = 0;
    std::size_t total_len = 0;
    const auto advance = [&out, &total_len](int produced,
                                            const char* message) {
        if (produced < 0 ||
            static_cast<std::size_t>(produced) > out.size() - total_len) {
            throw std::runtime_error(message);
        }
        total_len += static_cast<std::size_t>(produced);
    };
    if (cipher_len > 0) {
        if (EVP_DecryptUpdate(ctx.get(), out.data(), &out_len, data.data(),
                              static_cast<int>(cipher_len)) != 1) {
            throw ssl_error("decrypt update failed");
        }
        advance(out_len, "decrypt update overran its buffer");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG,
                            static_cast<int>(kChaCha20Poly1305TagBytes),
                            const_cast<unsigned char*>(tag)) != 1) {
        throw ssl_error("set tag failed");
    }

    const int rc = EVP_DecryptFinal_ex(
        ctx.get(), out.data() + total_len, &out_len);
    if (rc != 1) {
        throw std::runtime_error("decrypt failed: authentication check failed");
    }
    advance(out_len, "decrypt final overran its buffer");
    if (total_len != cipher_len) {
        throw std::runtime_error("decrypt plaintext length mismatch");
    }

    out.resize(total_len);
    out_wiper.Release();
    return out;
#endif
}

Bytes hmac_sha256(const Bytes& data, const Bytes& key) {
    unsigned int len = 0;
    Bytes out(EVP_MAX_MD_SIZE);
    unsigned char* res = HMAC(EVP_sha256(),
                              key.data(), key.size(),
                              data.data(), data.size(),
                              out.data(), &len);
    if (!res) {
        throw ssl_error("hmac failed");
    }
    out.resize(len);
    return out;
}

namespace {

KeyPair generate_named_keypair(const char* algorithm) {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new_from_name(nullptr, algorithm, nullptr),
        EVP_PKEY_CTX_free);
    if (!ctx) throw ssl_error(std::string("no provider for ") + algorithm);
    if (EVP_PKEY_keygen_init(ctx.get()) != 1) {
        throw ssl_error(std::string("keygen init failed for ") + algorithm);
    }
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw) != 1) {
        throw ssl_error(std::string("keygen failed for ") + algorithm);
    }
    KeyPair kp;
    kp.private_key.reset(raw);
    // The generated object holds both halves; the public view is the same
    // object with an extra reference rather than a re-derived key.
    if (EVP_PKEY_up_ref(raw) != 1) {
        throw ssl_error("failed to reference generated public key");
    }
    kp.public_key.reset(raw);
    return kp;
}

}  // namespace

CompositeKeyPair generate_composite_keypair() {
    CompositeKeyPair out;
    out.classical = generate_named_keypair("ED25519");
    out.pq = generate_named_keypair(std::string(kCompositePqAlgorithm).c_str());
    return out;
}

Bytes sign_composite(const CompositeKeyPair& keys, const Bytes& message) {
    Bytes classical = sign_message(keys.classical.private_key.get(), message);
    Bytes pq = sign_message(keys.pq.private_key.get(), message);
    if (classical.size() != kEd25519SignatureLen) {
        throw std::runtime_error("composite: unexpected Ed25519 signature size");
    }
    if (pq.size() != kMlDsa87SignatureLen) {
        throw std::runtime_error("composite: unexpected ML-DSA-87 signature size");
    }
    Bytes out;
    out.reserve(kCompositeSignatureLen);
    out.insert(out.end(), classical.begin(), classical.end());
    out.insert(out.end(), pq.begin(), pq.end());
    return out;
}

bool verify_composite(EVP_PKEY* classical_pub, EVP_PKEY* pq_pub,
                      const Bytes& message, const Bytes& signature) {
    if (classical_pub == nullptr || pq_pub == nullptr) return false;
    if (signature.size() != kCompositeSignatureLen) return false;
    const Bytes classical(signature.begin(),
                          signature.begin() + kEd25519SignatureLen);
    const Bytes pq(signature.begin() + kEd25519SignatureLen, signature.end());
    // Both, always. Evaluate both halves rather than short-circuiting so a
    // caller cannot infer which half failed from timing.
    const bool classical_ok = verify_key(classical_pub, message, classical);
    const bool pq_ok = verify_key(pq_pub, message, pq);
    return classical_ok && pq_ok;
}

CompositeKeyPair load_composite_keypair(const std::string& path_priv) {
    if (path_priv.empty()) {
        throw std::runtime_error("load_composite_keypair: empty path");
    }
    Bytes pem = security::ReadPrivateKeyFileStrict(path_priv);
    if (!has_exact_pem_sequence(pem, "PRIVATE KEY", 2)) {
        security::secure_erase(pem);
        throw std::runtime_error(
            "composite identity must contain exactly two PEM private keys "
            "(Ed25519 then " + std::string(kCompositePqAlgorithm) + ")");
    }
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(
        BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    if (!bio) {
        security::secure_erase(pem);
        throw ssl_error("failed to open composite identity");
    }
    EVP_PKEY_ptr classical(
        PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr),
        EVP_PKEY_free);
    EVP_PKEY_ptr pq(
        classical ? PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr)
                  : nullptr,
        EVP_PKEY_free);
    security::secure_erase(pem);
    if (!classical || !pq) {
        throw std::runtime_error(
            "composite identity must contain two PEM private keys "
            "(Ed25519 then " + std::string(kCompositePqAlgorithm) + ")");
    }
    if (EVP_PKEY_base_id(classical.get()) != EVP_PKEY_ED25519) {
        throw std::runtime_error("composite identity: first key must be Ed25519");
    }
    const char* pq_name = EVP_PKEY_get0_type_name(pq.get());
    if (pq_name == nullptr || std::string_view(pq_name) != kCompositePqAlgorithm) {
        throw std::runtime_error("composite identity: second key must be " +
                                 std::string(kCompositePqAlgorithm));
    }
    CompositeKeyPair out;
    for (auto* slot : {&out.classical, &out.pq}) {
        EVP_PKEY* src = (slot == &out.classical) ? classical.get() : pq.get();
        if (EVP_PKEY_up_ref(src) != 1) throw ssl_error("failed to reference identity half");
        slot->private_key.reset(src);
        if (EVP_PKEY_up_ref(src) != 1) throw ssl_error("failed to reference identity half");
        slot->public_key.reset(src);
    }
    return out;
}

Bytes encode_composite_private_pem(const CompositeKeyPair& keys) {
    Bytes out;
    for (EVP_PKEY* half : {keys.classical.private_key.get(),
                           keys.pq.private_key.get()}) {
        if (half == nullptr) {
            throw std::runtime_error("encode_composite_private_pem: missing half");
        }
        std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
        if (!bio) throw ssl_error("failed to allocate PEM buffer");
        if (PEM_write_bio_PrivateKey(bio.get(), half, nullptr, nullptr, 0,
                                     nullptr, nullptr) != 1) {
            throw ssl_error("failed to encode private key");
        }
        char* data = nullptr;
        const long length = BIO_get_mem_data(bio.get(), &data);
        if (length <= 0 || data == nullptr) {
            throw std::runtime_error("encode_composite_private_pem produced no output");
        }
        out.insert(out.end(), data, data + length);
    }
    return out;
}

Bytes encode_public_key_pem(EVP_PKEY* key) {
    if (key == nullptr) throw std::runtime_error("encode_public_key_pem: null key");
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!bio) throw ssl_error("failed to allocate PEM buffer");
    if (PEM_write_bio_PUBKEY(bio.get(), key) != 1) {
        throw ssl_error("failed to encode public key");
    }
    char* data = nullptr;
    const long length = BIO_get_mem_data(bio.get(), &data);
    if (length <= 0 || data == nullptr) {
        throw std::runtime_error("encode_public_key_pem produced no output");
    }
    return Bytes(data, data + length);
}

Bytes encode_composite_identity(EVP_PKEY* classical_pub, EVP_PKEY* pq_pub) {
    Bytes out = encode_public_key_pem(classical_pub);
    const Bytes pq = encode_public_key_pem(pq_pub);
    out.insert(out.end(), pq.begin(), pq.end());
    return out;
}

CompositePublicKey parse_composite_identity(const Bytes& pem_bundle) {
    CompositePublicKey out;
    if (pem_bundle.empty() || pem_bundle.size() > 64U * 1024U) return out;
    if (!has_exact_pem_sequence(pem_bundle, "PUBLIC KEY", 2)) return out;
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(
        BIO_new_mem_buf(pem_bundle.data(), static_cast<int>(pem_bundle.size())),
        BIO_free);
    if (!bio) return out;

    EVP_PKEY_ptr first(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr),
                       EVP_PKEY_free);
    if (!first) return out;
    EVP_PKEY_ptr second(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr),
                        EVP_PKEY_free);
    if (!second) return out;
    if (EVP_PKEY_base_id(first.get()) != EVP_PKEY_ED25519) return out;
    const char* pq_name = EVP_PKEY_get0_type_name(second.get());
    if (pq_name == nullptr || std::string_view(pq_name) != kCompositePqAlgorithm) {
        return out;
    }
    out.classical = std::move(first);
    out.pq = std::move(second);
    return out;
}

Bytes composite_canonical_encoding(const CompositePublicKey& key) {
    if (!key.valid()) return {};
    // The domain label keeps this value in a different space from a bare
    // single-key encoding, so a composite identity can never be confused with a
    // legacy one.
    static constexpr std::string_view kDomain = "yume/2.0/composite-identity/v1";
    Bytes input(kDomain.begin(), kDomain.end());
    for (EVP_PKEY* half : {key.classical.get(), key.pq.get()}) {
        // OPENSSL_free is a macro, so it cannot be a unique_ptr deleter; wrap it.
        const auto free_der = [](unsigned char* p) { OPENSSL_free(p); };
        unsigned char* der = nullptr;
        const int len = i2d_PUBKEY(half, &der);
        if (len <= 0 || der == nullptr) throw ssl_error("failed to encode identity half");
        std::unique_ptr<unsigned char, decltype(free_der)> owned(der, free_der);
        const auto size = static_cast<std::uint32_t>(len);
        input.push_back(static_cast<std::uint8_t>(size >> 24));
        input.push_back(static_cast<std::uint8_t>(size >> 16));
        input.push_back(static_cast<std::uint8_t>(size >> 8));
        input.push_back(static_cast<std::uint8_t>(size));
        input.insert(input.end(), der, der + len);
    }
    return input;
}

std::string composite_fingerprint_from_canonical(const Bytes& canonical) {
    if (canonical.empty()) return {};
    return sha256_hex(canonical);
}

std::string composite_fingerprint(const CompositePublicKey& key) {
    return composite_fingerprint_from_canonical(composite_canonical_encoding(key));
}

Bytes random_bytes(size_t len) {
    Bytes out(len);
    if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
        throw ssl_error("rand bytes failed");
    }
    return out;
}

}  // namespace yume::crypto
