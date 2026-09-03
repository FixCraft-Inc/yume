/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/ytp1_security_provider.hpp"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <climits>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "ytp/security.hpp"

namespace yume::providers {
namespace {

using engine::AuthenticationMessageKind;
using engine::AuthenticationOutput;
using engine::Buffer;
using engine::EndpointRole;
using engine::PeerEvidence;
using engine::ProviderDescriptor;
using engine::ProviderKind;
using engine::RecordKeyToken;
using engine::Result;
using engine::SessionAuthenticationContext;
using engine::SessionSecurityProvider;
using engine::Status;
using engine::StatusCode;

constexpr std::string_view kOpenSslPropertyQuery = "provider=default";
constexpr std::string_view kEd25519Algorithm = "ED25519";
constexpr std::string_view kMlDsa87Algorithm = "ML-DSA-87";
constexpr std::string_view kMlKem1024Algorithm = "ML-KEM-1024";
constexpr std::string_view kX25519Algorithm = "X25519";
constexpr std::string_view kSha256Algorithm = "SHA256";
constexpr std::string_view kAes256GcmAlgorithm = "AES-256-GCM";
constexpr std::string_view kHmacAlgorithm = "HMAC";
constexpr std::string_view kHkdfAlgorithm = "HKDF";
constexpr std::string_view kAuthenticationScheme =
    "YTP/1-Ed25519+ML-DSA-87";

constexpr std::size_t kSha256Bytes = 32U;
constexpr std::size_t kAes256KeyBytes = 32U;
constexpr std::size_t kAesGcmNonceBytes = 12U;
constexpr std::size_t kAesGcmTagBytes = 16U;
constexpr std::size_t kRecordKeyMaterialBytes =
    kAes256KeyBytes + kAesGcmNonceBytes;
constexpr std::size_t kMaxDerKeyBytes = 64U * 1024U;
constexpr std::size_t kMaxPeerLabelBytes = 512U;
constexpr std::size_t kMaxTranscriptInputBytes = 256U * 1024U;
constexpr std::size_t kMaxRatchetInputBytes = 16U * 1024U;
constexpr std::uint8_t kRekeySchema = 1U;
constexpr std::uint8_t kRekeyInitKind = 1U;
constexpr std::uint8_t kRekeyAckKind = 2U;
constexpr std::size_t kRekeyPrefixBytes = 8U;
constexpr std::size_t kRekeyInitBytes =
    kRekeyPrefixBytes + ytp1::kMlKem1024PublicKeySize +
    ytp1::kX25519PublicKeySize + 32U + 32U;
constexpr std::size_t kRekeyAckBytes =
    kRekeyPrefixBytes + ytp1::kMlKem1024CiphertextSize +
    ytp1::kX25519PublicKeySize + 32U;

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

struct PkeyDeleter final {
    void operator()(EVP_PKEY* value) const noexcept {
        EVP_PKEY_free(value);
    }
};

struct PkeyCtxDeleter final {
    void operator()(EVP_PKEY_CTX* value) const noexcept {
        EVP_PKEY_CTX_free(value);
    }
};

struct Pkcs8Deleter final {
    void operator()(PKCS8_PRIV_KEY_INFO* value) const noexcept {
        PKCS8_PRIV_KEY_INFO_free(value);
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
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDeleter>;
using PkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter>;
using Pkcs8Ptr = std::unique_ptr<PKCS8_PRIV_KEY_INFO, Pkcs8Deleter>;
using MdPtr = std::unique_ptr<EVP_MD, MdDeleter>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, MdCtxDeleter>;
using CipherPtr = std::unique_ptr<EVP_CIPHER, CipherDeleter>;
using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter>;
using MacPtr = std::unique_ptr<EVP_MAC, MacDeleter>;
using MacCtxPtr = std::unique_ptr<EVP_MAC_CTX, MacCtxDeleter>;
using KdfPtr = std::unique_ptr<EVP_KDF, KdfDeleter>;
using KdfCtxPtr = std::unique_ptr<EVP_KDF_CTX, KdfCtxDeleter>;

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

std::span<const std::uint8_t> as_u8(
    std::span<const std::byte> input) noexcept {
    return {reinterpret_cast<const std::uint8_t*>(input.data()),
            input.size()};
}

std::span<const std::byte> as_bytes(
    std::span<const std::uint8_t> input) noexcept {
    return {reinterpret_cast<const std::byte*>(input.data()), input.size()};
}

std::span<const std::uint8_t> text_u8(std::string_view input) noexcept {
    return {reinterpret_cast<const std::uint8_t*>(input.data()), input.size()};
}

bool constant_time_equal(std::span<const std::uint8_t> left,
                         std::span<const std::uint8_t> right) noexcept {
    if (left.size() != right.size()) {
        return false;
    }
    return left.empty() || CRYPTO_memcmp(left.data(), right.data(),
                                         left.size()) == 0;
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

std::uint32_t read_u32(std::span<const std::uint8_t> input,
                       std::size_t offset) noexcept {
    return (static_cast<std::uint32_t>(input[offset]) << 24U) |
           (static_cast<std::uint32_t>(input[offset + 1U]) << 16U) |
           (static_cast<std::uint32_t>(input[offset + 2U]) << 8U) |
           static_cast<std::uint32_t>(input[offset + 3U]);
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

bool valid_peer_label(std::string_view value) noexcept {
    if (value.empty() || value.size() > kMaxPeerLabelBytes) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](unsigned char byte) {
        return byte >= 0x21U && byte <= 0x7eU;
    });
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

EndpointRole peer_role(EndpointRole role) noexcept {
    return role == EndpointRole::Client ? EndpointRole::Server
                                        : EndpointRole::Client;
}

class CryptoContext final {
public:
    CryptoContext()
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

PkeyPtr parse_private_key(const CryptoContext& crypto,
                          std::span<const std::byte> der,
                          std::string_view expected_algorithm) {
    if (der.empty() || der.size() > kMaxDerKeyBytes ||
        der.size() > static_cast<std::size_t>(LONG_MAX)) {
        throw std::invalid_argument("private key DER has an invalid size");
    }
    SecretBytes private_copy = SecretBytes::copy_from(der);
    const unsigned char* cursor = private_copy.data();
    const unsigned char* const end = cursor + private_copy.size();
    Pkcs8Ptr pkcs8(d2i_PKCS8_PRIV_KEY_INFO(
        nullptr, &cursor, static_cast<long>(private_copy.size())));
    if (!pkcs8 || cursor != end) {
        throw std::invalid_argument(
            "private key is not an exact PKCS#8 DER value");
    }

    PkeyPtr key(EVP_PKCS82PKEY_ex(
        pkcs8.get(), crypto.library_context(),
        kOpenSslPropertyQuery.data()));
    if (!key ||
        EVP_PKEY_is_a(key.get(), expected_algorithm.data()) != 1) {
        throw std::invalid_argument(
            "private key PKCS#8 does not match the required algorithm");
    }

    // Re-export through the parsed key rather than merely re-encoding the
    // ASN.1 wrapper. This also canonicalizes the algorithm-specific private
    // material carried inside PKCS#8 and rejects alternate valid BER forms,
    // attributes, or provider encodings for the same key.
    Pkcs8Ptr canonical_pkcs8(EVP_PKEY2PKCS8(key.get()));
    const int canonical_size = canonical_pkcs8
        ? i2d_PKCS8_PRIV_KEY_INFO(canonical_pkcs8.get(), nullptr)
        : -1;
    if (canonical_size <= 0 ||
        static_cast<std::size_t>(canonical_size) > kMaxDerKeyBytes) {
        throw std::invalid_argument("private key PKCS#8 cannot be encoded");
    }
    SecretBytes canonical(static_cast<std::size_t>(canonical_size));
    unsigned char* canonical_cursor = canonical.data();
    if (i2d_PKCS8_PRIV_KEY_INFO(canonical_pkcs8.get(), &canonical_cursor) !=
            canonical_size ||
        canonical_cursor != canonical.data() + canonical.size() ||
        !constant_time_equal(canonical.span(), private_copy.span())) {
        throw std::invalid_argument("private key PKCS#8 is not canonical DER");
    }
    return key;
}

std::vector<std::uint8_t> public_key_der(EVP_PKEY* key) {
    if (key == nullptr) {
        throw std::invalid_argument("public key is missing");
    }
    const int encoded_size = i2d_PUBKEY(key, nullptr);
    if (encoded_size <= 0 ||
        static_cast<std::size_t>(encoded_size) > kMaxDerKeyBytes) {
        throw std::runtime_error("public key DER size is invalid");
    }
    std::vector<std::uint8_t> encoded(
        static_cast<std::size_t>(encoded_size));
    unsigned char* cursor = encoded.data();
    if (i2d_PUBKEY(key, &cursor) != encoded_size ||
        cursor != encoded.data() + encoded.size()) {
        throw std::runtime_error("public key DER encoding failed");
    }
    return encoded;
}

PkeyPtr parse_public_key(const CryptoContext& crypto,
                         std::span<const std::byte> der,
                         std::string_view expected_algorithm) {
    if (der.empty() || der.size() > kMaxDerKeyBytes ||
        der.size() > static_cast<std::size_t>(LONG_MAX)) {
        throw std::invalid_argument("public key DER has an invalid size");
    }
    const auto bytes = as_u8(der);
    const unsigned char* cursor = bytes.data();
    const unsigned char* const end = cursor + bytes.size();
    PkeyPtr key(d2i_PUBKEY_ex(
        nullptr, &cursor, static_cast<long>(bytes.size()),
        crypto.library_context(), kOpenSslPropertyQuery.data()));
    if (!key || cursor != end ||
        EVP_PKEY_is_a(key.get(), expected_algorithm.data()) != 1) {
        throw std::invalid_argument(
            "public key DER does not match the required algorithm");
    }
    const std::vector<std::uint8_t> canonical = public_key_der(key.get());
    if (!constant_time_equal(canonical, bytes)) {
        throw std::invalid_argument("public key DER is not canonical");
    }
    return key;
}

std::vector<std::uint8_t> encode_composite_identity(
    EVP_PKEY* ed25519,
    EVP_PKEY* ml_dsa_87) {
    const std::vector<std::uint8_t> classical = public_key_der(ed25519);
    const std::vector<std::uint8_t> post_quantum = public_key_der(ml_dsa_87);
    const std::size_t domain_size = ytp1::kCompositeIdentityDomain.size();
    if (classical.size() > std::numeric_limits<std::uint32_t>::max() ||
        post_quantum.size() > std::numeric_limits<std::uint32_t>::max() ||
        domain_size > ytp1::kMaxCompositeIdentitySize ||
        classical.size() > ytp1::kMaxCompositeIdentitySize - domain_size - 8U ||
        post_quantum.size() > ytp1::kMaxCompositeIdentitySize - domain_size -
                                  8U - classical.size()) {
        throw std::length_error("composite identity exceeds the YTP/1 bound");
    }
    std::vector<std::uint8_t> encoded;
    encoded.reserve(domain_size + 8U + classical.size() +
                    post_quantum.size());
    encoded.insert(encoded.end(), ytp1::kCompositeIdentityDomain.begin(),
                   ytp1::kCompositeIdentityDomain.end());
    append_u32(encoded, static_cast<std::uint32_t>(classical.size()));
    encoded.insert(encoded.end(), classical.begin(), classical.end());
    append_u32(encoded, static_cast<std::uint32_t>(post_quantum.size()));
    encoded.insert(encoded.end(), post_quantum.begin(), post_quantum.end());
    return encoded;
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

std::vector<std::uint8_t> random_bytes(const CryptoContext& crypto,
                                       std::size_t size) {
    if (size == 0U || size > static_cast<std::size_t>(INT_MAX)) {
        throw std::invalid_argument("random-byte request is invalid");
    }
    std::vector<std::uint8_t> output(size);
    if (RAND_bytes_ex(crypto.library_context(), output.data(), output.size(),
                      256U) != 1) {
        throw std::runtime_error("random-byte generation failed");
    }
    return output;
}

std::vector<std::uint8_t> sign_one(const CryptoContext& crypto,
                                   EVP_PKEY* key,
                                   std::span<const std::uint8_t> message,
                                   std::size_t expected_size) {
    MdCtxPtr context(EVP_MD_CTX_new());
    if (!context ||
        EVP_DigestSignInit_ex(context.get(), nullptr, nullptr,
                              crypto.library_context(),
                              kOpenSslPropertyQuery.data(), key, nullptr) != 1) {
        throw std::runtime_error("signature initialization failed");
    }
    std::size_t size = 0U;
    if (EVP_DigestSign(context.get(), nullptr, &size, message.data(),
                       message.size()) != 1 ||
        size != expected_size) {
        throw std::runtime_error("signature size query failed");
    }
    std::vector<std::uint8_t> signature(size);
    if (EVP_DigestSign(context.get(), signature.data(), &size,
                       message.data(), message.size()) != 1 ||
        size != expected_size) {
        throw std::runtime_error("signature operation failed");
    }
    return signature;
}

bool verify_one(const CryptoContext& crypto,
                EVP_PKEY* key,
                std::span<const std::uint8_t> message,
                std::span<const std::uint8_t> signature) {
    MdCtxPtr context(EVP_MD_CTX_new());
    if (!context ||
        EVP_DigestVerifyInit_ex(context.get(), nullptr, nullptr,
                                crypto.library_context(),
                                kOpenSslPropertyQuery.data(), key,
                                nullptr) != 1) {
        return false;
    }
    return EVP_DigestVerify(context.get(), signature.data(), signature.size(),
                            message.data(), message.size()) == 1;
}

struct CompositeIdentity final {
    PkeyPtr ed25519;
    PkeyPtr ml_dsa_87;
    std::vector<std::uint8_t> encoded;

    CompositeIdentity() = default;
    CompositeIdentity(PkeyPtr classical,
                      PkeyPtr post_quantum,
                      std::vector<std::uint8_t> canonical) noexcept
        : ed25519(std::move(classical)),
          ml_dsa_87(std::move(post_quantum)),
          encoded(std::move(canonical)) {}

    CompositeIdentity(const CompositeIdentity&) = delete;
    CompositeIdentity& operator=(const CompositeIdentity&) = delete;
    CompositeIdentity(CompositeIdentity&&) noexcept = default;
    CompositeIdentity& operator=(CompositeIdentity&&) noexcept = default;
};

CompositeIdentity load_private_identity(
    const CryptoContext& crypto,
    const CompositePrivateIdentityView& input) {
    PkeyPtr ed25519 = parse_private_key(
        crypto, input.ed25519_private_key_der, kEd25519Algorithm);
    PkeyPtr ml_dsa = parse_private_key(
        crypto, input.ml_dsa_87_private_key_der, kMlDsa87Algorithm);
    std::vector<std::uint8_t> encoded =
        encode_composite_identity(ed25519.get(), ml_dsa.get());
    return CompositeIdentity(std::move(ed25519), std::move(ml_dsa),
                             std::move(encoded));
}

CompositeIdentity load_public_identity(
    const CryptoContext& crypto,
    const CompositePublicIdentityView& input) {
    PkeyPtr ed25519 = parse_public_key(
        crypto, input.ed25519_public_key_der, kEd25519Algorithm);
    PkeyPtr ml_dsa = parse_public_key(
        crypto, input.ml_dsa_87_public_key_der, kMlDsa87Algorithm);
    std::vector<std::uint8_t> encoded =
        encode_composite_identity(ed25519.get(), ml_dsa.get());
    return CompositeIdentity(std::move(ed25519), std::move(ml_dsa),
                             std::move(encoded));
}

std::vector<std::uint8_t> sign_composite(
    const CryptoContext& crypto,
    const CompositeIdentity& identity,
    std::span<const std::uint8_t> message) {
    std::vector<std::uint8_t> classical = sign_one(
        crypto, identity.ed25519.get(), message,
        ytp1::kEd25519SignatureSize);
    std::vector<std::uint8_t> post_quantum = sign_one(
        crypto, identity.ml_dsa_87.get(), message,
        ytp1::kMlDsa87SignatureSize);
    std::vector<std::uint8_t> signature;
    signature.reserve(ytp1::kCompositeSignatureSize);
    signature.insert(signature.end(), classical.begin(), classical.end());
    signature.insert(signature.end(), post_quantum.begin(),
                     post_quantum.end());
    OPENSSL_cleanse(classical.data(), classical.size());
    OPENSSL_cleanse(post_quantum.data(), post_quantum.size());
    return signature;
}

bool verify_composite(const CryptoContext& crypto,
                      const CompositeIdentity& identity,
                      std::span<const std::uint8_t> message,
                      std::span<const std::uint8_t> signature) {
    if (signature.size() != ytp1::kCompositeSignatureSize) {
        return false;
    }
    const auto classical = signature.first(ytp1::kEd25519SignatureSize);
    const auto post_quantum =
        signature.subspan(ytp1::kEd25519SignatureSize);
    // Evaluate both components on every correctly sized input. Authentication
    // is an AND composition and never falls back to one component.
    const bool classical_ok = verify_one(
        crypto, identity.ed25519.get(), message, classical);
    const bool post_quantum_ok = verify_one(
        crypto, identity.ml_dsa_87.get(), message, post_quantum);
    return classical_ok && post_quantum_ok;
}

std::vector<std::uint8_t> ml_kem_public_bytes(EVP_PKEY* key) {
    std::size_t size = 0U;
    if (key == nullptr ||
        EVP_PKEY_get_octet_string_param(
            key, OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0U, &size) != 1 ||
        size != ytp1::kMlKem1024PublicKeySize) {
        throw std::runtime_error("ML-KEM-1024 public-key size is invalid");
    }
    std::vector<std::uint8_t> output(size);
    if (EVP_PKEY_get_octet_string_param(
            key, OSSL_PKEY_PARAM_PUB_KEY, output.data(), output.size(),
            &size) != 1 ||
        size != output.size()) {
        throw std::runtime_error("ML-KEM-1024 public-key export failed");
    }
    return output;
}

PkeyPtr import_ml_kem_public(const CryptoContext& crypto,
                             std::span<const std::uint8_t> encoded) {
    if (encoded.size() != ytp1::kMlKem1024PublicKeySize) {
        throw std::invalid_argument("ML-KEM-1024 public key has wrong size");
    }
    PkeyCtxPtr context(EVP_PKEY_CTX_new_from_name(
        crypto.library_context(), kMlKem1024Algorithm.data(),
        kOpenSslPropertyQuery.data()));
    if (!context || EVP_PKEY_fromdata_init(context.get()) != 1) {
        throw std::runtime_error("ML-KEM-1024 import initialization failed");
    }
    OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY,
            const_cast<std::uint8_t*>(encoded.data()), encoded.size()),
        OSSL_PARAM_construct_end(),
    };
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_fromdata(context.get(), &raw, EVP_PKEY_PUBLIC_KEY,
                          parameters) != 1 ||
        raw == nullptr) {
        throw std::invalid_argument("ML-KEM-1024 public key was rejected");
    }
    PkeyPtr key(raw);
    if (EVP_PKEY_is_a(key.get(), kMlKem1024Algorithm.data()) != 1) {
        throw std::invalid_argument("ML-KEM public-key algorithm mismatch");
    }
    return key;
}

PkeyPtr generate_key(const CryptoContext& crypto,
                     std::string_view algorithm) {
    PkeyCtxPtr context(EVP_PKEY_CTX_new_from_name(
        crypto.library_context(), algorithm.data(),
        kOpenSslPropertyQuery.data()));
    if (!context || EVP_PKEY_keygen_init(context.get()) != 1) {
        throw std::runtime_error("key generation initialization failed");
    }
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_generate(context.get(), &raw) != 1 || raw == nullptr) {
        throw std::runtime_error("key generation failed");
    }
    return PkeyPtr(raw);
}

struct X25519KeyPair final {
    PkeyPtr private_key;
    std::array<std::uint8_t, ytp1::kX25519PublicKeySize> public_key{};
};

X25519KeyPair generate_x25519(const CryptoContext& crypto) {
    X25519KeyPair output;
    output.private_key = generate_key(crypto, kX25519Algorithm);
    std::size_t size = output.public_key.size();
    if (EVP_PKEY_get_raw_public_key(output.private_key.get(),
                                    output.public_key.data(), &size) != 1 ||
        size != output.public_key.size()) {
        throw std::runtime_error("X25519 public-key export failed");
    }
    return output;
}

SecretBytes derive_x25519(const CryptoContext& crypto,
                          EVP_PKEY* private_key,
                          std::span<const std::uint8_t> peer_public) {
    if (private_key == nullptr ||
        peer_public.size() != ytp1::kX25519PublicKeySize) {
        throw std::invalid_argument("X25519 key input is invalid");
    }
    PkeyPtr peer(EVP_PKEY_new_raw_public_key_ex(
        crypto.library_context(), kX25519Algorithm.data(),
        kOpenSslPropertyQuery.data(), peer_public.data(),
        peer_public.size()));
    PkeyCtxPtr context(peer ? EVP_PKEY_CTX_new_from_pkey(
                                  crypto.library_context(), private_key,
                                  kOpenSslPropertyQuery.data())
                              : nullptr);
    if (!peer || !context || EVP_PKEY_derive_init(context.get()) != 1 ||
        EVP_PKEY_derive_set_peer(context.get(), peer.get()) != 1) {
        throw std::invalid_argument("X25519 peer key was rejected");
    }
    std::size_t size = 0U;
    if (EVP_PKEY_derive(context.get(), nullptr, &size) != 1 ||
        size != ytp1::kX25519SharedSecretSize) {
        throw std::runtime_error("X25519 shared-secret size is invalid");
    }
    SecretBytes shared(size);
    if (EVP_PKEY_derive(context.get(), shared.data(), &size) != 1 ||
        size != shared.size() || !any_nonzero(shared.span())) {
        throw std::invalid_argument("X25519 shared secret was rejected");
    }
    return shared;
}

struct MlKemEncapsulation final {
    std::array<std::uint8_t, ytp1::kMlKem1024CiphertextSize> ciphertext{};
    SecretBytes shared;
};

MlKemEncapsulation encapsulate_ml_kem(const CryptoContext& crypto,
                                      EVP_PKEY* public_key) {
    PkeyCtxPtr context(public_key ? EVP_PKEY_CTX_new_from_pkey(
                                       crypto.library_context(), public_key,
                                       kOpenSslPropertyQuery.data())
                                  : nullptr);
    if (!context || EVP_PKEY_encapsulate_init(context.get(), nullptr) != 1) {
        throw std::runtime_error("ML-KEM encapsulation initialization failed");
    }
    std::size_t ciphertext_size = 0U;
    std::size_t shared_size = 0U;
    if (EVP_PKEY_encapsulate(context.get(), nullptr, &ciphertext_size,
                             nullptr, &shared_size) != 1 ||
        ciphertext_size != ytp1::kMlKem1024CiphertextSize ||
        shared_size != ytp1::kMlKem1024SharedSecretSize) {
        throw std::runtime_error("ML-KEM encapsulation sizes are invalid");
    }
    MlKemEncapsulation output;
    output.shared = SecretBytes(shared_size);
    if (EVP_PKEY_encapsulate(context.get(), output.ciphertext.data(),
                             &ciphertext_size, output.shared.data(),
                             &shared_size) != 1 ||
        ciphertext_size != output.ciphertext.size() ||
        shared_size != output.shared.size() ||
        !any_nonzero(output.shared.span())) {
        throw std::runtime_error("ML-KEM encapsulation failed");
    }
    return output;
}

SecretBytes decapsulate_ml_kem(
    const CryptoContext& crypto,
    EVP_PKEY* private_key,
    std::span<const std::uint8_t> ciphertext) {
    if (private_key == nullptr ||
        ciphertext.size() != ytp1::kMlKem1024CiphertextSize) {
        throw std::invalid_argument("ML-KEM decapsulation input is invalid");
    }
    PkeyCtxPtr context(EVP_PKEY_CTX_new_from_pkey(
        crypto.library_context(), private_key,
        kOpenSslPropertyQuery.data()));
    if (!context || EVP_PKEY_decapsulate_init(context.get(), nullptr) != 1) {
        throw std::runtime_error("ML-KEM decapsulation initialization failed");
    }
    std::size_t shared_size = 0U;
    if (EVP_PKEY_decapsulate(context.get(), nullptr, &shared_size,
                             ciphertext.data(), ciphertext.size()) != 1 ||
        shared_size != ytp1::kMlKem1024SharedSecretSize) {
        throw std::runtime_error("ML-KEM shared-secret size is invalid");
    }
    SecretBytes shared(shared_size);
    if (EVP_PKEY_decapsulate(context.get(), shared.data(), &shared_size,
                             ciphertext.data(), ciphertext.size()) != 1 ||
        shared_size != shared.size() || !any_nonzero(shared.span())) {
        throw std::invalid_argument("ML-KEM ciphertext was rejected");
    }
    return shared;
}

ytp1::AuthField auth_field(ytp1::AuthFieldId id,
                           std::span<const std::uint8_t> value) {
    ytp1::AuthField field;
    field.id = static_cast<std::uint16_t>(id);
    field.critical = true;
    field.value.assign(value.begin(), value.end());
    return field;
}

std::vector<std::uint8_t> encode_auth_record(
    ytp1::AuthMessageType type,
    EndpointRole role,
    std::vector<ytp1::AuthField> fields) {
    ytp1::AuthRecord record;
    record.type = type;
    record.sender_role = to_ytp_role(role);
    record.fields = std::move(fields);
    auto encoded = ytp1::EncodeAuthRecord(record);
    if (!encoded.ok()) {
        throw std::invalid_argument("YTP/1 AUTH record cannot be encoded");
    }
    return std::move(*encoded.value);
}

ytp1::AuthRecord decode_auth_record(
    std::span<const std::byte> canonical_message,
    ytp1::AuthMessageType expected_type,
    EndpointRole expected_sender,
    std::span<const std::uint16_t> expected_fields) {
    if (canonical_message.empty() ||
        canonical_message.size() > ytp1::kMaxAuthRecordSize) {
        throw std::invalid_argument("YTP/1 AUTH record size is invalid");
    }
    const auto encoded = as_u8(canonical_message);
    auto decoded = ytp1::DecodeAuthRecord(encoded);
    if (!decoded.ok() || decoded.value->type != expected_type ||
        decoded.value->sender_role != to_ytp_role(expected_sender) ||
        decoded.value->fields.size() != expected_fields.size()) {
        throw std::invalid_argument("YTP/1 AUTH record shape is invalid");
    }
    for (std::size_t index = 0U; index < expected_fields.size(); ++index) {
        const ytp1::AuthField& field = decoded.value->fields[index];
        if (!field.critical || field.id != expected_fields[index]) {
            throw std::invalid_argument("YTP/1 AUTH fields are not exact");
        }
    }
    auto reencoded = ytp1::EncodeAuthRecord(*decoded.value);
    if (!reencoded.ok() ||
        !constant_time_equal(*reencoded.value, encoded)) {
        throw std::invalid_argument("YTP/1 AUTH record is not canonical");
    }
    return std::move(*decoded.value);
}

const ytp1::AuthField& required_field(const ytp1::AuthRecord& record,
                                      ytp1::AuthFieldId id) {
    const std::uint16_t numeric = static_cast<std::uint16_t>(id);
    const auto iterator = std::lower_bound(
        record.fields.begin(), record.fields.end(), numeric,
        [](const ytp1::AuthField& field, std::uint16_t value) {
            return field.id < value;
        });
    if (iterator == record.fields.end() || iterator->id != numeric) {
        throw std::invalid_argument("required YTP/1 AUTH field is missing");
    }
    return *iterator;
}

std::vector<std::uint8_t> canonical_tagged_input(
    std::string_view domain,
    std::span<const std::span<const std::uint8_t>> fields,
    std::size_t bound = kMaxTranscriptInputBytes) {
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
    std::span<const std::uint8_t> confirmation = {}) {
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

enum class ConfirmationPurpose : std::uint8_t {
    Response = 1U,
    Accepted = 2U,
};

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

std::array<std::uint8_t, kSha256Bytes> identity_fingerprint(
    const CryptoContext& crypto,
    std::span<const std::uint8_t> identity) {
    return sha256(crypto, {identity});
}

Result<Buffer> auth_buffer(std::vector<std::uint8_t> encoded) {
    return Buffer::copy_from(as_bytes(encoded), ytp1::kMaxAuthRecordSize);
}

struct HandshakeRoots final {
    SecretBytes master;
    SecretBytes client_to_server;
    SecretBytes server_to_client;
};

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

std::vector<std::byte> fingerprint_evidence(
    const CryptoContext& crypto,
    std::span<const std::uint8_t> identity) {
    const auto fingerprint = identity_fingerprint(crypto, identity);
    std::vector<std::byte> evidence(fingerprint.size());
    std::memcpy(evidence.data(), fingerprint.data(), fingerprint.size());
    return evidence;
}

std::vector<std::byte> byte_vector(
    std::span<const std::uint8_t> input) {
    std::vector<std::byte> output(input.size());
    if (!input.empty()) {
        std::memcpy(output.data(), input.data(), input.size());
    }
    return output;
}

struct AuthorizedIdentity final {
    CompositeIdentity identity;
    SecretBytes psk;
    std::string peer_identity;
};

struct CredentialStore final {
    std::shared_ptr<CryptoContext> crypto;
    EndpointRole role{EndpointRole::Client};
    CompositeIdentity local_identity;

    CompositeIdentity trusted_server_identity;
    PkeyPtr server_ml_kem_key;
    std::vector<std::uint8_t> server_ml_kem_public;
    SecretBytes client_psk;
    std::string server_peer_identity;

    std::vector<AuthorizedIdentity> authorized_identities;
};

const AuthorizedIdentity* find_authorized_identity(
    const CredentialStore& credentials,
    std::span<const std::uint8_t> identity) noexcept {
    const AuthorizedIdentity* match = nullptr;
    for (const AuthorizedIdentity& candidate : credentials.authorized_identities) {
        if (candidate.identity.encoded.size() == identity.size() &&
            constant_time_equal(candidate.identity.encoded, identity)) {
            if (match != nullptr) {
                return nullptr;
            }
            match = &candidate;
        }
    }
    return match;
}

struct RekeyInitiatorState final {
    std::uint32_t epoch{0U};
    PkeyPtr ml_kem_private;
    std::array<std::uint8_t, ytp1::kMlKem1024PublicKeySize>
        ml_kem_public{};
    X25519KeyPair x25519;
    std::array<std::uint8_t, 32U> nonce{};
    std::array<std::uint8_t, 32U> initiation_authenticator{};
    std::vector<std::uint8_t> canonical_without_authenticator;

    RekeyInitiatorState() = default;
    RekeyInitiatorState(const RekeyInitiatorState&) = delete;
    RekeyInitiatorState& operator=(const RekeyInitiatorState&) = delete;

    ~RekeyInitiatorState() noexcept {
        OPENSSL_cleanse(nonce.data(), nonce.size());
        OPENSSL_cleanse(initiation_authenticator.data(),
                        initiation_authenticator.size());
    }
};

enum class ProviderState : std::uint8_t {
    Created,
    Initialized,
    ChallengeSent,
    ResponseSent,
    Established,
    Failed,
    Cancelled,
};

class Ytp1OpenSslSecurityProvider final : public SessionSecurityProvider {
public:
    explicit Ytp1OpenSslSecurityProvider(
        std::shared_ptr<const CredentialStore> credentials) noexcept
        : credentials_(std::move(credentials)), role_(credentials_->role) {}

    ~Ytp1OpenSslSecurityProvider() override { cancel(); }

    std::string_view provider_id() const noexcept override {
        return kYtp1OpenSslSecurityProviderId;
    }

    std::string_view suite_id() const noexcept override {
        return ytp1::kSuiteId;
    }

    std::span<const std::byte> security_parameters() const noexcept override {
        return as_bytes(ytp1::RequiredSecurityParameters());
    }

    std::size_t max_sealed_overhead() const noexcept override {
        return kAesGcmTagBytes;
    }

    Status initialize(const SessionAuthenticationContext& context) override {
        if (state_ == ProviderState::Cancelled) {
            return cancelled_status();
        }
        if (state_ != ProviderState::Created) {
            return Status(StatusCode::FailedPrecondition,
                          "security provider is already initialized");
        }
        if (context.local_role != role_ ||
            context.secure_channel_peer.peer_role() != peer_role(role_)) {
            return Status(StatusCode::ProviderMismatch,
                          "security-provider endpoint role is mismatched");
        }
        if (role_ == EndpointRole::Client &&
            !context.secure_channel_peer.authenticated()) {
            return Status(StatusCode::ProviderMismatch,
                          "client requires authenticated TLS server evidence");
        }
        const auto required_parameters =
            as_bytes(ytp1::RequiredSecurityParameters());
        if (context.suite_id != ytp1::kSuiteId ||
            context.security_parameters.size() !=
                required_parameters.size() ||
            !std::equal(context.security_parameters.begin(),
                        context.security_parameters.end(),
                        required_parameters.begin()) ||
            context.channel_exporter.size() != ytp1::kExporterSize) {
            return Status(StatusCode::ProviderMismatch,
                          "YTP/1 suite, security, or exporter is mismatched");
        }
        const auto capabilities = as_u8(context.local_capability_manifest);
        if (!ytp1::DecodeCapabilityManifest(capabilities).ok()) {
            return Status(StatusCode::InvalidArgument,
                          "local capability manifest is not canonical");
        }
        try {
            exporter_.assign(as_u8(context.channel_exporter).begin(),
                             as_u8(context.channel_exporter).end());
            local_capabilities_.assign(capabilities.begin(),
                                       capabilities.end());
            state_ = ProviderState::Initialized;
            return Status::success();
        } catch (const std::bad_alloc&) {
            wipe_session_state();
            state_ = ProviderState::Failed;
            return Status(StatusCode::ResourceExhausted,
                          "security-provider initialization allocation failed");
        }
    }

    Result<AuthenticationOutput> start_authentication() override {
        if (state_ == ProviderState::Cancelled) {
            return Result<AuthenticationOutput>(cancelled_status());
        }
        if (state_ != ProviderState::Initialized) {
            return Result<AuthenticationOutput>(Status(
                StatusCode::FailedPrecondition,
                "authentication was started in the wrong provider state"));
        }
        if (role_ == EndpointRole::Client) {
            return Result<AuthenticationOutput>(AuthenticationOutput{});
        }
        try {
            return make_server_challenge();
        } catch (const std::bad_alloc&) {
            return fail_auth(StatusCode::ResourceExhausted,
                             "AUTH challenge allocation failed");
        } catch (...) {
            return fail_auth(StatusCode::Internal,
                             "AUTH challenge generation failed");
        }
    }

    Result<AuthenticationOutput> process_authentication(
        AuthenticationMessageKind kind,
        std::span<const std::byte> canonical_message) override {
        if (state_ == ProviderState::Cancelled) {
            return Result<AuthenticationOutput>(cancelled_status());
        }
        try {
            if (role_ == EndpointRole::Client &&
                state_ == ProviderState::Initialized &&
                kind == AuthenticationMessageKind::Challenge) {
                return process_server_challenge(canonical_message);
            }
            if (role_ == EndpointRole::Server &&
                state_ == ProviderState::ChallengeSent &&
                kind == AuthenticationMessageKind::Response) {
                return process_client_response(canonical_message);
            }
            if (role_ == EndpointRole::Client &&
                state_ == ProviderState::ResponseSent &&
                kind == AuthenticationMessageKind::Accepted) {
                return process_server_accepted(canonical_message);
            }
            return fail_auth(
                StatusCode::FailedPrecondition,
                "AUTH message kind or provider state is unexpected");
        } catch (const std::bad_alloc&) {
            return fail_auth(StatusCode::ResourceExhausted,
                             "AUTH processing allocation failed");
        } catch (const std::invalid_argument&) {
            return fail_auth(StatusCode::FailedPrecondition,
                             "AUTH message failed closed");
        } catch (...) {
            return fail_auth(StatusCode::Internal,
                             "AUTH processing failed unexpectedly");
        }
    }

    Result<Buffer> seal_record(
        RecordKeyToken token,
        std::span<const std::byte> plaintext) override {
        if (state_ == ProviderState::Cancelled) {
            return Result<Buffer>(cancelled_status());
        }
        if (state_ != ProviderState::Established) {
            return Result<Buffer>(Status(
                StatusCode::FailedPrecondition,
                "record sealing requires an established provider"));
        }
        if (!valid_outbound_token(token)) {
            return fail_record("outbound record key token is not exact");
        }
        try {
            SecretBytes material = derive_record_material(
                *credentials_->crypto, outbound_root_.span(), role_, token,
                session_binding_);
            const auto aad = record_aad(role_, token);
            std::vector<std::uint8_t> sealed = seal_aes_gcm(
                *credentials_->crypto,
                material.span().first(kAes256KeyBytes),
                material.span().subspan(kAes256KeyBytes), aad,
                as_u8(plaintext));
            auto buffer = Buffer::copy_from(
                as_bytes(sealed), engine::kAbsoluteMaxBufferBytes);
            OPENSSL_cleanse(sealed.data(), sealed.size());
            if (!buffer.ok()) {
                mark_failed();
                return buffer;
            }
            consume_outbound_sequence();
            return buffer;
        } catch (const std::bad_alloc&) {
            mark_failed();
            return Result<Buffer>(Status(
                StatusCode::ResourceExhausted,
                "record sealing allocation failed"));
        } catch (...) {
            mark_failed();
            return Result<Buffer>(Status(StatusCode::Internal,
                                         "record sealing failed"));
        }
    }

    Result<Buffer> open_record(
        RecordKeyToken token,
        std::span<const std::byte> ciphertext) override {
        if (state_ == ProviderState::Cancelled) {
            return Result<Buffer>(cancelled_status());
        }
        if (state_ != ProviderState::Established) {
            return Result<Buffer>(Status(
                StatusCode::FailedPrecondition,
                "record opening requires an established provider"));
        }
        if (!valid_inbound_token(token)) {
            return fail_record("inbound record key token is not exact");
        }
        try {
            SecretBytes material = derive_record_material(
                *credentials_->crypto, inbound_root_.span(),
                peer_role(role_), token, session_binding_);
            const auto aad = record_aad(peer_role(role_), token);
            std::vector<std::uint8_t> plaintext = open_aes_gcm(
                *credentials_->crypto,
                material.span().first(kAes256KeyBytes),
                material.span().subspan(kAes256KeyBytes), aad,
                as_u8(ciphertext));
            auto buffer = Buffer::copy_from(
                as_bytes(plaintext), engine::kAbsoluteMaxBufferBytes);
            OPENSSL_cleanse(plaintext.data(), plaintext.size());
            if (!buffer.ok()) {
                mark_failed();
                return buffer;
            }
            consume_inbound_sequence();
            return buffer;
        } catch (const std::bad_alloc&) {
            mark_failed();
            return Result<Buffer>(Status(
                StatusCode::ResourceExhausted,
                "record opening allocation failed"));
        } catch (...) {
            mark_failed();
            return Result<Buffer>(Status(
                StatusCode::FailedPrecondition,
                "record authentication failed closed"));
        }
    }

    Result<Buffer> begin_outbound_rekey(
        std::uint32_t next_epoch) override {
        if (state_ == ProviderState::Cancelled) {
            return Result<Buffer>(cancelled_status());
        }
        if (state_ != ProviderState::Established || outbound_rekey_ ||
            outbound_epoch_ == std::numeric_limits<std::uint32_t>::max() ||
            next_epoch != outbound_epoch_ + 1U) {
            return Result<Buffer>(Status(
                StatusCode::FailedPrecondition,
                "outbound rekey epoch or state is invalid"));
        }
        try {
            auto pending = std::make_unique<RekeyInitiatorState>();
            pending->epoch = next_epoch;
            pending->ml_kem_private = generate_key(
                *credentials_->crypto, kMlKem1024Algorithm);
            const auto ml_public =
                ml_kem_public_bytes(pending->ml_kem_private.get());
            std::copy(ml_public.begin(), ml_public.end(),
                      pending->ml_kem_public.begin());
            pending->x25519 = generate_x25519(*credentials_->crypto);
            const auto nonce = random_bytes(*credentials_->crypto,
                                            pending->nonce.size());
            std::copy(nonce.begin(), nonce.end(), pending->nonce.begin());

            std::vector<std::uint8_t> message(kRekeyInitBytes, 0U);
            message[0] = kRekeySchema;
            message[1] = kRekeyInitKind;
            message[2] = static_cast<std::uint8_t>(to_ytp_role(role_));
            message[3] = 0U;
            message[4] = static_cast<std::uint8_t>(next_epoch >> 24U);
            message[5] = static_cast<std::uint8_t>(next_epoch >> 16U);
            message[6] = static_cast<std::uint8_t>(next_epoch >> 8U);
            message[7] = static_cast<std::uint8_t>(next_epoch);
            std::size_t offset = kRekeyPrefixBytes;
            std::copy(pending->ml_kem_public.begin(),
                      pending->ml_kem_public.end(), message.begin() +
                          static_cast<std::ptrdiff_t>(offset));
            offset += pending->ml_kem_public.size();
            std::copy(pending->x25519.public_key.begin(),
                      pending->x25519.public_key.end(), message.begin() +
                          static_cast<std::ptrdiff_t>(offset));
            offset += pending->x25519.public_key.size();
            std::copy(pending->nonce.begin(), pending->nonce.end(),
                      message.begin() + static_cast<std::ptrdiff_t>(offset));
            offset += pending->nonce.size();
            pending->canonical_without_authenticator.assign(
                message.begin(), message.begin() +
                    static_cast<std::ptrdiff_t>(offset));
            const auto auth_input = rekey_init_auth_input(
                role_, next_epoch, session_binding_,
                pending->ml_kem_public, pending->x25519.public_key,
                pending->nonce);
            pending->initiation_authenticator = hmac_sha256(
                *credentials_->crypto, outbound_root_.span(), auth_input);
            std::copy(pending->initiation_authenticator.begin(),
                      pending->initiation_authenticator.end(),
                      message.begin() + static_cast<std::ptrdiff_t>(offset));
            auto buffer = Buffer::copy_from(
                as_bytes(message), kRekeyInitBytes);
            if (!buffer.ok()) {
                return buffer;
            }
            outbound_rekey_ = std::move(pending);
            return buffer;
        } catch (const std::bad_alloc&) {
            return Result<Buffer>(Status(
                StatusCode::ResourceExhausted,
                "outbound rekey allocation failed"));
        } catch (...) {
            mark_failed();
            return Result<Buffer>(Status(StatusCode::Internal,
                                         "outbound rekey generation failed"));
        }
    }

    Result<Buffer> accept_inbound_rekey(
        std::uint32_t next_epoch,
        std::span<const std::byte> initiation) override {
        if (state_ == ProviderState::Cancelled) {
            return Result<Buffer>(cancelled_status());
        }
        if (state_ != ProviderState::Established ||
            inbound_epoch_ == std::numeric_limits<std::uint32_t>::max() ||
            next_epoch != inbound_epoch_ + 1U) {
            return Result<Buffer>(Status(
                StatusCode::FailedPrecondition,
                "inbound rekey epoch or state is invalid"));
        }
        try {
            const auto message = as_u8(initiation);
            const EndpointRole direction = peer_role(role_);
            if (message.size() != kRekeyInitBytes ||
                message[0] != kRekeySchema ||
                message[1] != kRekeyInitKind ||
                message[2] !=
                    static_cast<std::uint8_t>(to_ytp_role(direction)) ||
                message[3] != 0U || read_u32(message, 4U) != next_epoch) {
                throw std::invalid_argument("rekey initiation is malformed");
            }
            std::size_t offset = kRekeyPrefixBytes;
            const auto ml_public = message.subspan(
                offset, ytp1::kMlKem1024PublicKeySize);
            offset += ml_public.size();
            const auto peer_x = message.subspan(
                offset, ytp1::kX25519PublicKeySize);
            offset += peer_x.size();
            const auto nonce = message.subspan(offset, 32U);
            offset += nonce.size();
            const auto supplied_auth = message.subspan(offset, 32U);
            const auto auth_input = rekey_init_auth_input(
                direction, next_epoch, session_binding_, ml_public,
                peer_x, nonce);
            const auto expected_auth = hmac_sha256(
                *credentials_->crypto, inbound_root_.span(), auth_input);
            if (!constant_time_equal(expected_auth, supplied_auth)) {
                throw std::invalid_argument(
                    "rekey initiation authentication failed");
            }

            PkeyPtr peer_ml_kem = import_ml_kem_public(
                *credentials_->crypto, ml_public);
            MlKemEncapsulation encapsulation = encapsulate_ml_kem(
                *credentials_->crypto, peer_ml_kem.get());
            X25519KeyPair local_x = generate_x25519(*credentials_->crypto);
            SecretBytes x_shared = derive_x25519(
                *credentials_->crypto, local_x.private_key.get(), peer_x);
            const auto init_without_auth =
                message.first(kRekeyInitBytes - 32U);
            SecretBytes new_root = derive_rekey_root(
                *credentials_->crypto, inbound_root_.span(), direction,
                next_epoch, session_binding_, init_without_auth,
                encapsulation.ciphertext, local_x.public_key,
                x_shared.span(), encapsulation.shared.span());
            const auto ack_input = rekey_ack_auth_input(
                direction, next_epoch, session_binding_, init_without_auth,
                encapsulation.ciphertext, local_x.public_key);
            const auto confirmation = hmac_sha256(
                *credentials_->crypto, new_root.span(), ack_input);

            std::vector<std::uint8_t> acknowledgement(kRekeyAckBytes, 0U);
            acknowledgement[0] = kRekeySchema;
            acknowledgement[1] = kRekeyAckKind;
            acknowledgement[2] =
                static_cast<std::uint8_t>(to_ytp_role(direction));
            acknowledgement[3] = 0U;
            acknowledgement[4] =
                static_cast<std::uint8_t>(next_epoch >> 24U);
            acknowledgement[5] =
                static_cast<std::uint8_t>(next_epoch >> 16U);
            acknowledgement[6] =
                static_cast<std::uint8_t>(next_epoch >> 8U);
            acknowledgement[7] = static_cast<std::uint8_t>(next_epoch);
            offset = kRekeyPrefixBytes;
            std::copy(encapsulation.ciphertext.begin(),
                      encapsulation.ciphertext.end(),
                      acknowledgement.begin() +
                          static_cast<std::ptrdiff_t>(offset));
            offset += encapsulation.ciphertext.size();
            std::copy(local_x.public_key.begin(), local_x.public_key.end(),
                      acknowledgement.begin() +
                          static_cast<std::ptrdiff_t>(offset));
            offset += local_x.public_key.size();
            std::copy(confirmation.begin(), confirmation.end(),
                      acknowledgement.begin() +
                          static_cast<std::ptrdiff_t>(offset));
            auto buffer = Buffer::copy_from(
                as_bytes(acknowledgement), kRekeyAckBytes);
            if (!buffer.ok()) {
                return buffer;
            }
            inbound_root_ = std::move(new_root);
            inbound_epoch_ = next_epoch;
            return buffer;
        } catch (const std::bad_alloc&) {
            mark_failed();
            return Result<Buffer>(Status(
                StatusCode::ResourceExhausted,
                "inbound rekey allocation failed"));
        } catch (...) {
            mark_failed();
            return Result<Buffer>(Status(
                StatusCode::FailedPrecondition,
                "inbound rekey failed closed"));
        }
    }

    Status finish_outbound_rekey(
        std::uint32_t next_epoch,
        std::span<const std::byte> acknowledgement) override {
        if (state_ == ProviderState::Cancelled) {
            return cancelled_status();
        }
        if (state_ != ProviderState::Established || !outbound_rekey_ ||
            outbound_rekey_->epoch != next_epoch) {
            return Status(StatusCode::FailedPrecondition,
                          "outbound rekey acknowledgement is unexpected");
        }
        try {
            const auto message = as_u8(acknowledgement);
            if (message.size() != kRekeyAckBytes ||
                message[0] != kRekeySchema ||
                message[1] != kRekeyAckKind ||
                message[2] !=
                    static_cast<std::uint8_t>(to_ytp_role(role_)) ||
                message[3] != 0U || read_u32(message, 4U) != next_epoch) {
                throw std::invalid_argument(
                    "rekey acknowledgement is malformed");
            }
            std::size_t offset = kRekeyPrefixBytes;
            const auto ciphertext = message.subspan(
                offset, ytp1::kMlKem1024CiphertextSize);
            offset += ciphertext.size();
            const auto peer_x = message.subspan(
                offset, ytp1::kX25519PublicKeySize);
            offset += peer_x.size();
            const auto supplied_confirmation = message.subspan(offset, 32U);
            SecretBytes x_shared = derive_x25519(
                *credentials_->crypto,
                outbound_rekey_->x25519.private_key.get(), peer_x);
            SecretBytes ml_shared = decapsulate_ml_kem(
                *credentials_->crypto,
                outbound_rekey_->ml_kem_private.get(), ciphertext);
            SecretBytes new_root = derive_rekey_root(
                *credentials_->crypto, outbound_root_.span(), role_,
                next_epoch, session_binding_,
                outbound_rekey_->canonical_without_authenticator,
                ciphertext, peer_x, x_shared.span(), ml_shared.span());
            const auto ack_input = rekey_ack_auth_input(
                role_, next_epoch, session_binding_,
                outbound_rekey_->canonical_without_authenticator,
                ciphertext, peer_x);
            const auto expected_confirmation = hmac_sha256(
                *credentials_->crypto, new_root.span(), ack_input);
            if (!constant_time_equal(expected_confirmation,
                                     supplied_confirmation)) {
                throw std::invalid_argument(
                    "rekey acknowledgement authentication failed");
            }
            outbound_root_ = std::move(new_root);
            outbound_epoch_ = next_epoch;
            outbound_rekey_.reset();
            return Status::success();
        } catch (const std::bad_alloc&) {
            mark_failed();
            return Status(StatusCode::ResourceExhausted,
                          "outbound rekey allocation failed");
        } catch (...) {
            mark_failed();
            return Status(StatusCode::FailedPrecondition,
                          "outbound rekey failed closed");
        }
    }

    void cancel() noexcept override {
        if (state_ == ProviderState::Cancelled) {
            return;
        }
        wipe_session_state();
        state_ = ProviderState::Cancelled;
    }

private:
    Result<AuthenticationOutput> make_server_challenge();
    Result<AuthenticationOutput> process_server_challenge(
        std::span<const std::byte> canonical_message);
    Result<AuthenticationOutput> process_client_response(
        std::span<const std::byte> canonical_message);
    Result<AuthenticationOutput> process_server_accepted(
        std::span<const std::byte> canonical_message);

    Status cancelled_status() const {
        return Status(StatusCode::Cancelled,
                      "security provider is cancelled");
    }

    Result<AuthenticationOutput> fail_auth(StatusCode code,
                                           std::string_view message) {
        mark_failed();
        return Result<AuthenticationOutput>(Status(code, message));
    }

    Result<Buffer> fail_record(std::string_view message) {
        mark_failed();
        return Result<Buffer>(Status(StatusCode::FailedPrecondition,
                                     message));
    }

    void mark_failed() noexcept {
        wipe_session_state();
        state_ = ProviderState::Failed;
    }

    void wipe_session_state() noexcept {
        if (!exporter_.empty()) {
            OPENSSL_cleanse(exporter_.data(), exporter_.size());
        }
        exporter_.clear();
        local_capabilities_.clear();
        peer_capabilities_.clear();
        if (!challenge_bytes_.empty()) {
            OPENSSL_cleanse(challenge_bytes_.data(),
                            challenge_bytes_.size());
        }
        challenge_bytes_.clear();
        handshake_x25519_.reset();
        pending_roots_.reset();
        outbound_rekey_.reset();
        outbound_root_.wipe();
        inbound_root_.wipe();
        OPENSSL_cleanse(session_binding_.data(), session_binding_.size());
        session_binding_.fill(0U);
        outbound_epoch_ = 0U;
        inbound_epoch_ = 0U;
        next_outbound_sequence_ = 0U;
        next_inbound_sequence_ = 0U;
        outbound_sequence_exhausted_ = false;
        inbound_sequence_exhausted_ = false;
        selected_identity_ = nullptr;
    }

    bool valid_outbound_token(RecordKeyToken token) const noexcept {
        return !outbound_sequence_exhausted_ &&
               token.epoch == outbound_epoch_ &&
               token.sequence == next_outbound_sequence_;
    }

    bool valid_inbound_token(RecordKeyToken token) const noexcept {
        return !inbound_sequence_exhausted_ &&
               token.epoch == inbound_epoch_ &&
               token.sequence == next_inbound_sequence_;
    }

    void consume_outbound_sequence() noexcept {
        if (next_outbound_sequence_ ==
            std::numeric_limits<std::uint64_t>::max()) {
            outbound_sequence_exhausted_ = true;
        } else {
            ++next_outbound_sequence_;
        }
    }

    void consume_inbound_sequence() noexcept {
        if (next_inbound_sequence_ ==
            std::numeric_limits<std::uint64_t>::max()) {
            inbound_sequence_exhausted_ = true;
        } else {
            ++next_inbound_sequence_;
        }
    }

    void commit_roots(HandshakeRoots roots) {
        if (role_ == EndpointRole::Client) {
            outbound_root_ = std::move(roots.client_to_server);
            inbound_root_ = std::move(roots.server_to_client);
        } else {
            outbound_root_ = std::move(roots.server_to_client);
            inbound_root_ = std::move(roots.client_to_server);
        }
    }

    std::shared_ptr<const CredentialStore> credentials_;
    EndpointRole role_;
    ProviderState state_{ProviderState::Created};
    std::vector<std::uint8_t> exporter_;
    std::vector<std::uint8_t> local_capabilities_;
    std::vector<std::uint8_t> peer_capabilities_;
    std::vector<std::uint8_t> challenge_bytes_;
    std::optional<X25519KeyPair> handshake_x25519_;
    std::optional<HandshakeRoots> pending_roots_;
    const AuthorizedIdentity* selected_identity_{nullptr};
    std::array<std::uint8_t, ytp1::kTranscriptHashSize>
        session_binding_{};
    SecretBytes outbound_root_;
    SecretBytes inbound_root_;
    std::uint32_t outbound_epoch_{0U};
    std::uint32_t inbound_epoch_{0U};
    std::uint64_t next_outbound_sequence_{0U};
    std::uint64_t next_inbound_sequence_{0U};
    bool outbound_sequence_exhausted_{false};
    bool inbound_sequence_exhausted_{false};
    std::unique_ptr<RekeyInitiatorState> outbound_rekey_;
};

Result<AuthenticationOutput>
Ytp1OpenSslSecurityProvider::make_server_challenge() {
    X25519KeyPair server_x = generate_x25519(*credentials_->crypto);
    const std::vector<std::uint8_t> nonce = random_bytes(
        *credentials_->crypto, 32U);
    const std::vector<std::uint8_t> context = challenge_context(
        exporter_, credentials_->local_identity.encoded,
        credentials_->server_ml_kem_public, server_x.public_key,
        local_capabilities_, nonce);
    const auto digest = sha256(*credentials_->crypto, {context});
    const std::vector<std::uint8_t> signed_input = signature_input(
        EndpointRole::Server, ytp1::AuthMessageType::Challenge,
        exporter_, digest);
    std::vector<std::uint8_t> signature = sign_composite(
        *credentials_->crypto, credentials_->local_identity, signed_input);
    std::vector<ytp1::AuthField> fields;
    fields.reserve(7U);
    fields.push_back(auth_field(ytp1::AuthFieldId::TranscriptHash, digest));
    fields.push_back(auth_field(ytp1::AuthFieldId::Identity,
                                credentials_->local_identity.encoded));
    fields.push_back(auth_field(ytp1::AuthFieldId::CompositeSignature,
                                signature));
    fields.push_back(auth_field(ytp1::AuthFieldId::MlKemPublicKey,
                                credentials_->server_ml_kem_public));
    fields.push_back(auth_field(ytp1::AuthFieldId::X25519PublicKey,
                                server_x.public_key));
    fields.push_back(auth_field(ytp1::AuthFieldId::CapabilityManifest,
                                local_capabilities_));
    fields.push_back(auth_field(ytp1::AuthFieldId::Nonce, nonce));
    std::vector<std::uint8_t> encoded = encode_auth_record(
        ytp1::AuthMessageType::Challenge, EndpointRole::Server,
        std::move(fields));
    auto buffer = auth_buffer(encoded);
    if (!buffer.ok()) {
        return Result<AuthenticationOutput>(buffer.status());
    }

    challenge_bytes_ = encoded;
    handshake_x25519_.emplace(std::move(server_x));
    state_ = ProviderState::ChallengeSent;
    AuthenticationOutput output;
    output.outbound_kind = AuthenticationMessageKind::Challenge;
    output.outbound_message = std::move(buffer).take_value();
    return Result<AuthenticationOutput>(std::move(output));
}

Result<AuthenticationOutput>
Ytp1OpenSslSecurityProvider::process_server_challenge(
    std::span<const std::byte> canonical_message) {
    constexpr std::array<std::uint16_t, 7> kExpectedFields{
        static_cast<std::uint16_t>(ytp1::AuthFieldId::TranscriptHash),
        static_cast<std::uint16_t>(ytp1::AuthFieldId::Identity),
        static_cast<std::uint16_t>(ytp1::AuthFieldId::CompositeSignature),
        static_cast<std::uint16_t>(ytp1::AuthFieldId::MlKemPublicKey),
        static_cast<std::uint16_t>(ytp1::AuthFieldId::X25519PublicKey),
        static_cast<std::uint16_t>(ytp1::AuthFieldId::CapabilityManifest),
        static_cast<std::uint16_t>(ytp1::AuthFieldId::Nonce),
    };
    const ytp1::AuthRecord challenge = decode_auth_record(
        canonical_message, ytp1::AuthMessageType::Challenge,
        EndpointRole::Server, kExpectedFields);
    const auto& transcript_field = required_field(
        challenge, ytp1::AuthFieldId::TranscriptHash);
    const auto& identity = required_field(
        challenge, ytp1::AuthFieldId::Identity);
    const auto& signature = required_field(
        challenge, ytp1::AuthFieldId::CompositeSignature);
    const auto& ml_public = required_field(
        challenge, ytp1::AuthFieldId::MlKemPublicKey);
    const auto& server_x = required_field(
        challenge, ytp1::AuthFieldId::X25519PublicKey);
    const auto& capabilities = required_field(
        challenge, ytp1::AuthFieldId::CapabilityManifest);
    const auto& nonce = required_field(challenge, ytp1::AuthFieldId::Nonce);
    if (!constant_time_equal(identity.value,
                             credentials_->trusted_server_identity.encoded) ||
        !constant_time_equal(ml_public.value,
                             credentials_->server_ml_kem_public)) {
        throw std::invalid_argument("server credential does not match trust");
    }
    const std::vector<std::uint8_t> context = challenge_context(
        exporter_, identity.value, ml_public.value, server_x.value,
        capabilities.value, nonce.value);
    const auto expected_digest = sha256(*credentials_->crypto, {context});
    if (!constant_time_equal(expected_digest, transcript_field.value)) {
        throw std::invalid_argument("challenge transcript is invalid");
    }
    const std::vector<std::uint8_t> signed_input = signature_input(
        EndpointRole::Server, ytp1::AuthMessageType::Challenge,
        exporter_, expected_digest);
    if (!verify_composite(*credentials_->crypto,
                          credentials_->trusted_server_identity,
                          signed_input, signature.value)) {
        throw std::invalid_argument("server composite signature failed");
    }

    X25519KeyPair client_x = generate_x25519(*credentials_->crypto);
    SecretBytes x_shared = derive_x25519(
        *credentials_->crypto, client_x.private_key.get(), server_x.value);
    MlKemEncapsulation encapsulation = encapsulate_ml_kem(
        *credentials_->crypto, credentials_->server_ml_kem_key.get());
    const auto challenge_bytes = as_u8(canonical_message);
    const std::vector<std::uint8_t> unsigned_response = response_context(
        challenge_bytes, credentials_->local_identity.encoded,
        encapsulation.ciphertext, client_x.public_key,
        local_capabilities_);
    const std::array<std::span<const std::uint8_t>, 2> transcript_messages{
        challenge_bytes, unsigned_response};
    const auto transcript = transcript_hash(
        *credentials_->crypto, exporter_, transcript_messages);
    HandshakeRoots roots = derive_initial_roots(
        *credentials_->crypto, transcript, exporter_,
        credentials_->local_identity.encoded,
        credentials_->trusted_server_identity.encoded,
        local_capabilities_, capabilities.value,
        credentials_->client_psk.span(), client_x.public_key,
        server_x.value, x_shared.span(), ml_public.value,
        encapsulation.ciphertext, encapsulation.shared.span());
    const auto psk_input = psk_authenticator_input(
        ConfirmationPurpose::Response, transcript);
    const auto psk_authenticator = hmac_sha256(
        *credentials_->crypto, credentials_->client_psk.span(), psk_input);
    const auto confirmation_context = key_confirmation_input(
        ConfirmationPurpose::Response, transcript);
    const auto key_confirmation = hmac_sha256(
        *credentials_->crypto, roots.master.span(), confirmation_context);
    const std::array<std::span<const std::uint8_t>, 2> proof_fields{
        psk_authenticator, key_confirmation};
    const std::vector<std::uint8_t> signed_proofs = canonical_tagged_input(
        ytp1::kAuthSignatureDomain, proof_fields);
    const std::vector<std::uint8_t> response_signature_input = signature_input(
        EndpointRole::Client, ytp1::AuthMessageType::Response,
        exporter_, transcript, signed_proofs);
    std::vector<std::uint8_t> response_signature = sign_composite(
        *credentials_->crypto, credentials_->local_identity,
        response_signature_input);

    std::vector<ytp1::AuthField> fields;
    fields.reserve(8U);
    fields.push_back(auth_field(ytp1::AuthFieldId::TranscriptHash,
                                transcript));
    fields.push_back(auth_field(ytp1::AuthFieldId::Identity,
                                credentials_->local_identity.encoded));
    fields.push_back(auth_field(ytp1::AuthFieldId::CompositeSignature,
                                response_signature));
    fields.push_back(auth_field(ytp1::AuthFieldId::MlKemCiphertext,
                                encapsulation.ciphertext));
    fields.push_back(auth_field(ytp1::AuthFieldId::X25519PublicKey,
                                client_x.public_key));
    fields.push_back(auth_field(ytp1::AuthFieldId::CapabilityManifest,
                                local_capabilities_));
    fields.push_back(auth_field(ytp1::AuthFieldId::PskAuthenticator,
                                psk_authenticator));
    fields.push_back(auth_field(ytp1::AuthFieldId::KeyConfirmation,
                                key_confirmation));
    std::vector<std::uint8_t> encoded = encode_auth_record(
        ytp1::AuthMessageType::Response, EndpointRole::Client,
        std::move(fields));
    auto buffer = auth_buffer(encoded);
    if (!buffer.ok()) {
        return Result<AuthenticationOutput>(buffer.status());
    }

    challenge_bytes_.assign(challenge_bytes.begin(), challenge_bytes.end());
    peer_capabilities_ = capabilities.value;
    session_binding_ = transcript;
    pending_roots_.emplace(std::move(roots));
    state_ = ProviderState::ResponseSent;
    AuthenticationOutput output;
    output.outbound_kind = AuthenticationMessageKind::Response;
    output.outbound_message = std::move(buffer).take_value();
    return Result<AuthenticationOutput>(std::move(output));
}

Result<AuthenticationOutput>
Ytp1OpenSslSecurityProvider::process_client_response(
    std::span<const std::byte> canonical_message) {
    constexpr std::array<std::uint16_t, 8> kExpectedFields{
        static_cast<std::uint16_t>(ytp1::AuthFieldId::TranscriptHash),
        static_cast<std::uint16_t>(ytp1::AuthFieldId::Identity),
        static_cast<std::uint16_t>(ytp1::AuthFieldId::CompositeSignature),
        static_cast<std::uint16_t>(ytp1::AuthFieldId::MlKemCiphertext),
        static_cast<std::uint16_t>(ytp1::AuthFieldId::X25519PublicKey),
        static_cast<std::uint16_t>(ytp1::AuthFieldId::CapabilityManifest),
        static_cast<std::uint16_t>(ytp1::AuthFieldId::PskAuthenticator),
        static_cast<std::uint16_t>(ytp1::AuthFieldId::KeyConfirmation),
    };
    if (!handshake_x25519_.has_value() || challenge_bytes_.empty()) {
        throw std::invalid_argument("server challenge state is missing");
    }
    const ytp1::AuthRecord response = decode_auth_record(
        canonical_message, ytp1::AuthMessageType::Response,
        EndpointRole::Client, kExpectedFields);
    const auto& transcript_field = required_field(
        response, ytp1::AuthFieldId::TranscriptHash);
    const auto& identity = required_field(
        response, ytp1::AuthFieldId::Identity);
    const auto& signature = required_field(
        response, ytp1::AuthFieldId::CompositeSignature);
    const auto& ciphertext = required_field(
        response, ytp1::AuthFieldId::MlKemCiphertext);
    const auto& client_x = required_field(
        response, ytp1::AuthFieldId::X25519PublicKey);
    const auto& capabilities = required_field(
        response, ytp1::AuthFieldId::CapabilityManifest);
    const auto& supplied_psk = required_field(
        response, ytp1::AuthFieldId::PskAuthenticator);
    const auto& supplied_confirmation = required_field(
        response, ytp1::AuthFieldId::KeyConfirmation);

    selected_identity_ = find_authorized_identity(*credentials_, identity.value);
    if (selected_identity_ == nullptr) {
        throw std::invalid_argument("client identity is not authorized");
    }
    const std::vector<std::uint8_t> unsigned_response = response_context(
        challenge_bytes_, identity.value, ciphertext.value,
        client_x.value, capabilities.value);
    const std::array<std::span<const std::uint8_t>, 2> transcript_messages{
        challenge_bytes_, unsigned_response};
    const auto transcript = transcript_hash(
        *credentials_->crypto, exporter_, transcript_messages);
    if (!constant_time_equal(transcript, transcript_field.value)) {
        throw std::invalid_argument("response transcript is invalid");
    }

    // Identity authorization and this fixed-cost PSK check deliberately
    // precede composite verification, X25519, and ML-KEM decapsulation.
    const auto psk_input = psk_authenticator_input(
        ConfirmationPurpose::Response, transcript);
    const auto expected_psk = hmac_sha256(
        *credentials_->crypto, selected_identity_->psk.span(), psk_input);
    if (!constant_time_equal(expected_psk, supplied_psk.value)) {
        throw std::invalid_argument("access PSK authentication failed");
    }

    SecretBytes x_shared = derive_x25519(
        *credentials_->crypto, handshake_x25519_->private_key.get(),
        client_x.value);
    SecretBytes ml_shared = decapsulate_ml_kem(
        *credentials_->crypto, credentials_->server_ml_kem_key.get(),
        ciphertext.value);
    HandshakeRoots roots = derive_initial_roots(
        *credentials_->crypto, transcript, exporter_, identity.value,
        credentials_->local_identity.encoded, capabilities.value,
        local_capabilities_, selected_identity_->psk.span(),
        client_x.value, handshake_x25519_->public_key,
        x_shared.span(), credentials_->server_ml_kem_public,
        ciphertext.value, ml_shared.span());
    const auto confirmation_context = key_confirmation_input(
        ConfirmationPurpose::Response, transcript);
    const auto expected_confirmation = hmac_sha256(
        *credentials_->crypto, roots.master.span(), confirmation_context);
    if (!constant_time_equal(expected_confirmation,
                             supplied_confirmation.value)) {
        throw std::invalid_argument("hybrid key confirmation failed");
    }
    const std::array<std::span<const std::uint8_t>, 2> proof_fields{
        supplied_psk.value, supplied_confirmation.value};
    const std::vector<std::uint8_t> signed_proofs = canonical_tagged_input(
        ytp1::kAuthSignatureDomain, proof_fields);
    const std::vector<std::uint8_t> response_signature_input = signature_input(
        EndpointRole::Client, ytp1::AuthMessageType::Response,
        exporter_, transcript, signed_proofs);
    if (!verify_composite(*credentials_->crypto,
                          selected_identity_->identity,
                          response_signature_input, signature.value)) {
        throw std::invalid_argument("client composite signature failed");
    }

    const auto accepted_context = key_confirmation_input(
        ConfirmationPurpose::Accepted, transcript);
    const auto accepted_confirmation = hmac_sha256(
        *credentials_->crypto, roots.master.span(), accepted_context);
    const std::vector<std::uint8_t> accepted_signature_input = signature_input(
        EndpointRole::Server, ytp1::AuthMessageType::Accepted,
        exporter_, transcript, accepted_confirmation);
    std::vector<std::uint8_t> accepted_signature = sign_composite(
        *credentials_->crypto, credentials_->local_identity,
        accepted_signature_input);
    std::vector<ytp1::AuthField> fields;
    fields.reserve(3U);
    fields.push_back(auth_field(ytp1::AuthFieldId::TranscriptHash,
                                transcript));
    fields.push_back(auth_field(ytp1::AuthFieldId::CompositeSignature,
                                accepted_signature));
    fields.push_back(auth_field(ytp1::AuthFieldId::KeyConfirmation,
                                accepted_confirmation));
    std::vector<std::uint8_t> encoded = encode_auth_record(
        ytp1::AuthMessageType::Accepted, EndpointRole::Server,
        std::move(fields));
    auto buffer = auth_buffer(encoded);
    if (!buffer.ok()) {
        return Result<AuthenticationOutput>(buffer.status());
    }
    auto evidence = PeerEvidence::create(
        EndpointRole::Client, selected_identity_->peer_identity,
        std::string(kAuthenticationScheme),
        fingerprint_evidence(*credentials_->crypto, identity.value));
    if (!evidence.ok()) {
        throw std::runtime_error("authenticated client evidence is invalid");
    }

    session_binding_ = transcript;
    peer_capabilities_ = capabilities.value;
    commit_roots(std::move(roots));
    handshake_x25519_.reset();
    OPENSSL_cleanse(challenge_bytes_.data(), challenge_bytes_.size());
    challenge_bytes_.clear();
    selected_identity_ = nullptr;
    state_ = ProviderState::Established;

    AuthenticationOutput output;
    output.outbound_kind = AuthenticationMessageKind::Accepted;
    output.outbound_message = std::move(buffer).take_value();
    output.established = true;
    output.authenticated_peer = std::move(evidence).take_value();
    output.authenticated_peer_capability_manifest =
        byte_vector(peer_capabilities_);
    return Result<AuthenticationOutput>(std::move(output));
}

Result<AuthenticationOutput>
Ytp1OpenSslSecurityProvider::process_server_accepted(
    std::span<const std::byte> canonical_message) {
    constexpr std::array<std::uint16_t, 3> kExpectedFields{
        static_cast<std::uint16_t>(ytp1::AuthFieldId::TranscriptHash),
        static_cast<std::uint16_t>(ytp1::AuthFieldId::CompositeSignature),
        static_cast<std::uint16_t>(ytp1::AuthFieldId::KeyConfirmation),
    };
    if (!pending_roots_.has_value()) {
        throw std::invalid_argument("client pending root is missing");
    }
    const ytp1::AuthRecord accepted = decode_auth_record(
        canonical_message, ytp1::AuthMessageType::Accepted,
        EndpointRole::Server, kExpectedFields);
    const auto& transcript = required_field(
        accepted, ytp1::AuthFieldId::TranscriptHash);
    const auto& signature = required_field(
        accepted, ytp1::AuthFieldId::CompositeSignature);
    const auto& supplied_confirmation = required_field(
        accepted, ytp1::AuthFieldId::KeyConfirmation);
    if (!constant_time_equal(session_binding_, transcript.value)) {
        throw std::invalid_argument("accepted transcript is invalid");
    }
    const auto accepted_context = key_confirmation_input(
        ConfirmationPurpose::Accepted, session_binding_);
    const auto expected_confirmation = hmac_sha256(
        *credentials_->crypto, pending_roots_->master.span(),
        accepted_context);
    if (!constant_time_equal(expected_confirmation,
                             supplied_confirmation.value)) {
        throw std::invalid_argument("accepted key confirmation failed");
    }
    const std::vector<std::uint8_t> accepted_signature_input = signature_input(
        EndpointRole::Server, ytp1::AuthMessageType::Accepted,
        exporter_, session_binding_, supplied_confirmation.value);
    if (!verify_composite(*credentials_->crypto,
                          credentials_->trusted_server_identity,
                          accepted_signature_input, signature.value)) {
        throw std::invalid_argument("accepted server signature failed");
    }
    auto evidence = PeerEvidence::create(
        EndpointRole::Server, credentials_->server_peer_identity,
        std::string(kAuthenticationScheme),
        fingerprint_evidence(
            *credentials_->crypto,
            credentials_->trusted_server_identity.encoded));
    if (!evidence.ok()) {
        throw std::runtime_error("authenticated server evidence is invalid");
    }

    HandshakeRoots roots = std::move(*pending_roots_);
    pending_roots_.reset();
    commit_roots(std::move(roots));
    OPENSSL_cleanse(challenge_bytes_.data(), challenge_bytes_.size());
    challenge_bytes_.clear();
    state_ = ProviderState::Established;

    AuthenticationOutput output;
    output.established = true;
    output.authenticated_peer = std::move(evidence).take_value();
    output.authenticated_peer_capability_manifest =
        byte_vector(peer_capabilities_);
    return Result<AuthenticationOutput>(std::move(output));
}

}  // namespace

struct Ytp1OpenSslSecurityProviderFactory::Impl final {
    explicit Impl(std::shared_ptr<const CredentialStore> value) noexcept
        : credentials(std::move(value)) {}

    std::shared_ptr<const CredentialStore> credentials;
};

Ytp1OpenSslSecurityProviderFactory::Ytp1OpenSslSecurityProviderFactory(
    ProviderDescriptor descriptor,
    std::shared_ptr<Impl> impl) noexcept
    : descriptor_(std::move(descriptor)), impl_(std::move(impl)) {}

Ytp1OpenSslSecurityProviderFactory::~Ytp1OpenSslSecurityProviderFactory() =
    default;

const ProviderDescriptor&
Ytp1OpenSslSecurityProviderFactory::descriptor() const noexcept {
    return descriptor_;
}

Result<std::shared_ptr<Ytp1OpenSslSecurityProviderFactory>>
Ytp1OpenSslSecurityProviderFactory::create_client(
    const Ytp1ClientCredentialsView& input) {
    if (input.access_psk.size() != ytp1::kPskSize ||
        !any_nonzero(as_u8(input.access_psk)) ||
        !valid_peer_label(input.server_peer_identity)) {
        return Result<std::shared_ptr<Ytp1OpenSslSecurityProviderFactory>>(
            Status(StatusCode::InvalidArgument,
                   "client PSK or server peer label is invalid"));
    }
    try {
        auto crypto = std::make_shared<CryptoContext>();
        auto credentials = std::make_shared<CredentialStore>();
        credentials->crypto = std::move(crypto);
        credentials->role = EndpointRole::Client;
        credentials->local_identity = load_private_identity(
            *credentials->crypto, input.local_identity);
        credentials->trusted_server_identity = load_public_identity(
            *credentials->crypto, input.trusted_server_identity);
        credentials->server_ml_kem_key = parse_public_key(
            *credentials->crypto, input.server_ml_kem_1024_public_key_der,
            kMlKem1024Algorithm);
        credentials->server_ml_kem_public = ml_kem_public_bytes(
            credentials->server_ml_kem_key.get());
        credentials->client_psk = SecretBytes::copy_from(
            input.access_psk);
        credentials->server_peer_identity =
            std::string(input.server_peer_identity);

        auto descriptor = ProviderDescriptor::create(
            std::string(kYtp1OpenSslSecurityProviderId),
            ProviderKind::SessionSecurity,
            kYtp1OpenSslSecurityProviderApiVersion,
            engine::CapabilitySet::of({
                engine::Capability::CompositeAuthentication,
                engine::Capability::HybridEstablishment,
                engine::Capability::DirectionalRatchet,
                engine::Capability::OneUseAeadKeys,
            }));
        if (!descriptor.ok()) {
            return Result<
                std::shared_ptr<Ytp1OpenSslSecurityProviderFactory>>(
                descriptor.status());
        }
        auto impl = std::make_shared<Impl>(credentials);
        auto factory = std::shared_ptr<Ytp1OpenSslSecurityProviderFactory>(
            new Ytp1OpenSslSecurityProviderFactory(
                std::move(descriptor).take_value(), std::move(impl)));
        return Result<
            std::shared_ptr<Ytp1OpenSslSecurityProviderFactory>>(
            std::move(factory));
    } catch (const std::bad_alloc&) {
        return Result<std::shared_ptr<Ytp1OpenSslSecurityProviderFactory>>(
            Status(StatusCode::ResourceExhausted,
                   "client provider-factory allocation failed"));
    } catch (const std::invalid_argument&) {
        return Result<std::shared_ptr<Ytp1OpenSslSecurityProviderFactory>>(
            Status(StatusCode::InvalidArgument,
                   "client credential material is invalid"));
    } catch (...) {
        return Result<std::shared_ptr<Ytp1OpenSslSecurityProviderFactory>>(
            Status(StatusCode::ProviderMismatch,
                   "required OpenSSL 3.5 YTP/1 algorithms are unavailable"));
    }
}

Result<std::shared_ptr<Ytp1OpenSslSecurityProviderFactory>>
Ytp1OpenSslSecurityProviderFactory::create_server(
    const Ytp1ServerCredentialsView& input) {
    if (input.authorized_identities.empty() ||
        input.authorized_identities.size() > kMaxYtp1AuthorizedIdentities) {
        return Result<std::shared_ptr<Ytp1OpenSslSecurityProviderFactory>>(
            Status(StatusCode::InvalidArgument,
                   "server authorized-identity count is outside its bound"));
    }
    try {
        auto crypto = std::make_shared<CryptoContext>();
        auto credentials = std::make_shared<CredentialStore>();
        credentials->crypto = std::move(crypto);
        credentials->role = EndpointRole::Server;
        credentials->local_identity = load_private_identity(
            *credentials->crypto, input.local_identity);
        credentials->server_ml_kem_key = parse_private_key(
            *credentials->crypto, input.ml_kem_1024_private_key_der,
            kMlKem1024Algorithm);
        credentials->server_ml_kem_public = ml_kem_public_bytes(
            credentials->server_ml_kem_key.get());
        credentials->authorized_identities.reserve(input.authorized_identities.size());

        for (const Ytp1AuthorizedIdentityView& authorized :
             input.authorized_identities) {
            if (authorized.access_psk.size() != ytp1::kPskSize ||
                !any_nonzero(as_u8(authorized.access_psk)) ||
                !valid_peer_label(authorized.peer_identity)) {
                throw std::invalid_argument(
                    "authorized-identity fields are invalid");
            }
            AuthorizedIdentity loaded{
                load_public_identity(*credentials->crypto,
                                     authorized.identity),
                SecretBytes::copy_from(authorized.access_psk),
                std::string(authorized.peer_identity),
            };
            for (const AuthorizedIdentity& existing :
                 credentials->authorized_identities) {
                if (constant_time_equal(existing.identity.encoded,
                                        loaded.identity.encoded) ||
                    constant_time_equal(existing.psk.span(),
                                        loaded.psk.span()) ||
                    existing.peer_identity == loaded.peer_identity) {
                    throw std::invalid_argument(
                        "duplicate authorized identity is forbidden");
                }
            }
            credentials->authorized_identities.push_back(std::move(loaded));
        }

        auto descriptor = ProviderDescriptor::create(
            std::string(kYtp1OpenSslSecurityProviderId),
            ProviderKind::SessionSecurity,
            kYtp1OpenSslSecurityProviderApiVersion,
            engine::CapabilitySet::of({
                engine::Capability::CompositeAuthentication,
                engine::Capability::HybridEstablishment,
                engine::Capability::DirectionalRatchet,
                engine::Capability::OneUseAeadKeys,
            }));
        if (!descriptor.ok()) {
            return Result<
                std::shared_ptr<Ytp1OpenSslSecurityProviderFactory>>(
                descriptor.status());
        }
        auto impl = std::make_shared<Impl>(credentials);
        auto factory = std::shared_ptr<Ytp1OpenSslSecurityProviderFactory>(
            new Ytp1OpenSslSecurityProviderFactory(
                std::move(descriptor).take_value(), std::move(impl)));
        return Result<
            std::shared_ptr<Ytp1OpenSslSecurityProviderFactory>>(
            std::move(factory));
    } catch (const std::bad_alloc&) {
        return Result<std::shared_ptr<Ytp1OpenSslSecurityProviderFactory>>(
            Status(StatusCode::ResourceExhausted,
                   "server provider-factory allocation failed"));
    } catch (const std::invalid_argument&) {
        return Result<std::shared_ptr<Ytp1OpenSslSecurityProviderFactory>>(
            Status(StatusCode::InvalidArgument,
                   "server credential material is invalid"));
    } catch (...) {
        return Result<std::shared_ptr<Ytp1OpenSslSecurityProviderFactory>>(
            Status(StatusCode::ProviderMismatch,
                   "required OpenSSL 3.5 YTP/1 algorithms are unavailable"));
    }
}

Result<std::unique_ptr<SessionSecurityProvider>>
Ytp1OpenSslSecurityProviderFactory::create(EndpointRole local_role) {
    if (!impl_ || !impl_->credentials ||
        local_role != impl_->credentials->role) {
        return Result<std::unique_ptr<SessionSecurityProvider>>(Status(
            StatusCode::ProviderMismatch,
            "security-provider factory role is exact and does not match"));
    }
    try {
        std::unique_ptr<SessionSecurityProvider> provider =
            std::make_unique<Ytp1OpenSslSecurityProvider>(
                impl_->credentials);
        return Result<std::unique_ptr<SessionSecurityProvider>>(
            std::move(provider));
    } catch (const std::bad_alloc&) {
        return Result<std::unique_ptr<SessionSecurityProvider>>(Status(
            StatusCode::ResourceExhausted,
            "session security-provider allocation failed"));
    }
}

}  // namespace yume::providers
