/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/composite_keys.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/x509.h>

#include "fs/secret_file.hpp"
#include "ytp/security.hpp"

namespace yume::providers::keys {
namespace {

using engine::StatusCode;
constexpr const char* kProperties = "provider=default";

using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

bool ascii_space(char value) noexcept {
    return value == ' ' || value == '\t' || value == '\r' || value == '\n';
}

int refuse_password(char*, int, int, void*) noexcept {
    return 0;
}

PkeyPtr parse_public_der(const KeyContext& keys, std::span<const std::byte> der,
                         const char* algorithm) {
    require(der.size() <=
                static_cast<std::size_t>(std::numeric_limits<long>::max()),
            "composite key exceeds parser bounds");
    const auto* cursor = reinterpret_cast<const unsigned char*>(der.data());
    PkeyPtr key(d2i_PUBKEY_ex(nullptr, &cursor, static_cast<long>(der.size()),
                              keys.context(), kProperties));
    require(key &&
                cursor == reinterpret_cast<const unsigned char*>(der.data()) +
                              der.size() &&
                EVP_PKEY_is_a(key.get(), algorithm) == 1,
            "composite key does not match the required algorithm");
    return key;
}

bool verify_one(const KeyContext& keys, EVP_PKEY* key,
                std::span<const std::byte> message,
                std::span<const std::byte> signature) {
    MdCtxPtr context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!context ||
        EVP_DigestVerifyInit_ex(context.get(), nullptr, nullptr, keys.context(),
                                kProperties, key, nullptr) != 1) {
        return false;
    }
    return EVP_DigestVerify(
               context.get(),
               reinterpret_cast<const unsigned char*>(signature.data()),
               signature.size(),
               reinterpret_cast<const unsigned char*>(message.data()),
               message.size()) == 1;
}

}  // namespace

void require(bool condition, const char* message, StatusCode code) {
    if (!condition) throw KeyError(message, code);
}

struct KeyContext::Impl final {
    std::unique_ptr<OSSL_LIB_CTX, decltype(&OSSL_LIB_CTX_free)> context{
        OSSL_LIB_CTX_new(), OSSL_LIB_CTX_free};
    std::unique_ptr<OSSL_PROVIDER, decltype(&OSSL_PROVIDER_unload)> provider{
        context ? OSSL_PROVIDER_load(context.get(), "default") : nullptr,
        OSSL_PROVIDER_unload};
    std::unique_ptr<EVP_MD, decltype(&EVP_MD_free)> sha256{
        context ? EVP_MD_fetch(context.get(), "SHA256", kProperties) : nullptr,
        EVP_MD_free};
};

KeyContext::KeyContext() : impl_(std::make_unique<Impl>()) {
    require(impl_->context && impl_->provider && impl_->sha256,
            "credential OpenSSL default provider is unavailable",
            StatusCode::ProviderMismatch);
}

KeyContext::~KeyContext() = default;

OSSL_LIB_CTX* KeyContext::context() const noexcept {
    return impl_->context.get();
}

std::string KeyContext::fingerprint(
    std::span<const std::byte> classical,
    std::span<const std::byte> post_quantum) const {
    MdCtxPtr digest(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    require(digest &&
                EVP_DigestInit_ex2(digest.get(), impl_->sha256.get(),
                                   nullptr) == 1 &&
                EVP_DigestUpdate(digest.get(),
                                 ytp1::kCompositeIdentityDomain.data(),
                                 ytp1::kCompositeIdentityDomain.size()) == 1,
            "composite fingerprint initialization failed");
    for (const auto bytes : {classical, post_quantum}) {
        require(bytes.size() <= std::numeric_limits<std::uint32_t>::max(),
                "composite identity exceeds its size bound");
        const auto size = static_cast<std::uint32_t>(bytes.size());
        const std::array<unsigned char, 4> length{
            static_cast<unsigned char>(size >> 24U),
            static_cast<unsigned char>(size >> 16U),
            static_cast<unsigned char>(size >> 8U),
            static_cast<unsigned char>(size)};
        require(
            EVP_DigestUpdate(digest.get(), length.data(), length.size()) == 1 &&
                EVP_DigestUpdate(digest.get(), bytes.data(), bytes.size()) == 1,
            "composite fingerprint update failed");
    }
    std::array<unsigned char, 32> hash{};
    unsigned int size = 0;
    require(EVP_DigestFinal_ex(digest.get(), hash.data(), &size) == 1 &&
                size == hash.size(),
            "composite fingerprint failed");
    constexpr char kHex[] = "0123456789abcdef";
    std::string output(64, '0');
    for (std::size_t i = 0; i < hash.size(); ++i) {
        output[i * 2] = kHex[hash[i] >> 4U];
        output[i * 2 + 1] = kHex[hash[i] & 15U];
    }
    return output;
}

void PkeyDeleter::operator()(EVP_PKEY* key) const noexcept {
    EVP_PKEY_free(key);
}

std::vector<std::string_view> pem_blocks(std::string_view text,
                                         bool private_key, std::size_t count) {
    const std::string_view begin = private_key ? "-----BEGIN PRIVATE KEY-----"
                                               : "-----BEGIN PUBLIC KEY-----";
    const std::string_view end =
        private_key ? "-----END PRIVATE KEY-----" : "-----END PUBLIC KEY-----";
    std::vector<std::string_view> output;
    output.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        while (!text.empty() && ascii_space(text.front()))
            text.remove_prefix(1);
        require(text.starts_with(begin),
                "credential PEM block type or order is invalid");
        const auto boundary = text.find(end, begin.size());
        require(boundary != std::string_view::npos,
                "credential PEM block is unterminated");
        const auto body = text.substr(begin.size(), boundary - begin.size());
        require(std::all_of(body.begin(), body.end(),
                            [](unsigned char value) {
                                return ascii_space(static_cast<char>(value)) ||
                                       (value >= 'a' && value <= 'z') ||
                                       (value >= 'A' && value <= 'Z') ||
                                       (value >= '0' && value <= '9') ||
                                       value == '+' || value == '/' ||
                                       value == '=';
                            }),
                "credential PEM contains headers or invalid encoding");
        const auto size = boundary + end.size();
        output.push_back(text.substr(0, size));
        text.remove_prefix(size);
    }
    require(std::all_of(text.begin(), text.end(), ascii_space),
            "credential PEM contains trailing data or extra keys");
    return output;
}

PkeyPtr parse_key(const KeyContext& keys, std::string_view pem,
                  bool private_key, const char* algorithm) {
    require(
        pem.size() <= static_cast<std::size_t>(std::numeric_limits<int>::max()),
        "credential PEM exceeds parser bounds");
    BioPtr input(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())),
                 BIO_free);
    require(static_cast<bool>(input),
            "credential PEM reader allocation failed");
    PkeyPtr key(
        private_key
            ? PEM_read_bio_PrivateKey_ex(input.get(), nullptr, refuse_password,
                                         nullptr, keys.context(), kProperties)
            : PEM_read_bio_PUBKEY_ex(input.get(), nullptr, refuse_password,
                                     nullptr, keys.context(), kProperties));
    require(key && EVP_PKEY_is_a(key.get(), algorithm) == 1,
            "credential key does not match the required algorithm");
    const auto* provider = EVP_PKEY_get0_provider(key.get());
    require(provider && std::string_view(OSSL_PROVIDER_get0_name(provider)) ==
                            "default",
            "credential key uses an unexpected provider");
    return key;
}

std::vector<std::byte> public_der(EVP_PKEY* key) {
    const int size = i2d_PUBKEY(key, nullptr);
    require(size > 0 && static_cast<std::size_t>(size) <=
                            security::kMaxPrivateKeyFileBytes,
            "credential public DER encoding size is invalid");
    std::vector<std::byte> result(static_cast<std::size_t>(size));
    auto* cursor = reinterpret_cast<unsigned char*>(result.data());
    require(i2d_PUBKEY(key, &cursor) == size &&
                cursor == reinterpret_cast<unsigned char*>(result.data()) +
                              result.size(),
            "credential public DER encoding failed");
    return result;
}

CompositePublic composite_public_from_pem(const KeyContext& keys,
                                          std::string_view pem) {
    const auto blocks = pem_blocks(pem, false, 2);
    auto classical = parse_key(keys, blocks[0], false, "ED25519");
    auto post_quantum = parse_key(keys, blocks[1], false, "ML-DSA-87");
    CompositePublic identity{
        public_der(classical.get()), public_der(post_quantum.get()), {}};
    identity.fingerprint =
        keys.fingerprint(identity.classical, identity.post_quantum);
    return identity;
}

bool verify_composite(const KeyContext& keys, const CompositePublic& identity,
                      std::span<const std::byte> message,
                      std::span<const std::byte> signature) {
    if (signature.size() != ytp1::kCompositeSignatureSize) return false;
    const auto classical_key =
        parse_public_der(keys, identity.classical, "ED25519");
    const auto post_quantum_key =
        parse_public_der(keys, identity.post_quantum, "ML-DSA-87");
    // Both halves are evaluated on every correctly sized input, and neither
    // stands in for the other.
    const bool classical_ok =
        verify_one(keys, classical_key.get(), message,
                   signature.first(ytp1::kEd25519SignatureSize));
    const bool post_quantum_ok =
        verify_one(keys, post_quantum_key.get(), message,
                   signature.subspan(ytp1::kEd25519SignatureSize));
    return classical_ok && post_quantum_ok;
}

CompositePrivate composite_private_from_pem(const KeyContext& keys,
                                            std::string_view pem) {
    const auto blocks = pem_blocks(pem, true, 2);
    CompositePrivate identity{parse_key(keys, blocks[0], true, "ED25519"),
                              parse_key(keys, blocks[1], true, "ML-DSA-87"),
                              {}};
    identity.identity.classical = public_der(identity.classical.get());
    identity.identity.post_quantum = public_der(identity.post_quantum.get());
    identity.identity.fingerprint = keys.fingerprint(
        identity.identity.classical, identity.identity.post_quantum);
    return identity;
}

std::vector<std::byte> sign_composite(const KeyContext& keys,
                                      const CompositePrivate& identity,
                                      std::span<const std::byte> message) {
    std::vector<std::byte> signature(ytp1::kCompositeSignatureSize);
    const auto sign_into = [&](EVP_PKEY* key, std::span<std::byte> output) {
        MdCtxPtr context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        std::size_t size = output.size();
        require(context &&
                    EVP_DigestSignInit_ex(context.get(), nullptr, nullptr,
                                          keys.context(), kProperties, key,
                                          nullptr) == 1 &&
                    EVP_DigestSign(
                        context.get(),
                        reinterpret_cast<unsigned char*>(output.data()), &size,
                        reinterpret_cast<const unsigned char*>(message.data()),
                        message.size()) == 1 &&
                    size == output.size(),
                "composite signature failed", StatusCode::Internal);
    };
    const auto span = std::span<std::byte>(signature);
    sign_into(identity.classical.get(),
              span.first(ytp1::kEd25519SignatureSize));
    sign_into(identity.post_quantum.get(),
              span.subspan(ytp1::kEd25519SignatureSize));
    return signature;
}

}  // namespace yume::providers::keys
