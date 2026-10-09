/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "setup/material.hpp"

#include <cstring>
#include <initializer_list>
#include <limits>
#include <utility>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include "providers/ytp1_crypto.hpp"

namespace yume::setup {
namespace {

namespace keys = providers::keys;
namespace crypto = providers::ytp1_crypto;

constexpr const char* kProperties = crypto::kOpenSslPropertyQuery.data();
// The outer TLS certificates follow the browser profile, which offers ECDSA
// on P-256. The composite YTP/1 identities are separate keys.
constexpr const char* kTlsCurve = "prime256v1";
constexpr const char* kCaName = "YUME 0.3 Local Setup CA";
constexpr long kCaDays = 3650;
constexpr long kLeafDays = 825;

using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using PkeyContextPtr =
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
using MdContextPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using BignumPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using ExtensionPtr =
    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)>;
using StorePtr = std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)>;
using StoreContextPtr =
    std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)>;

void require(bool condition, const std::string& message) {
    if (!condition) throw SetupError(message);
}

keys::PkeyPtr generate(const keys::KeyContext& context, const char* algorithm,
                       const char* group = nullptr) {
    PkeyContextPtr generator(
        EVP_PKEY_CTX_new_from_name(context.context(), algorithm, kProperties),
        EVP_PKEY_CTX_free);
    EVP_PKEY* raw = nullptr;
    const bool made = generator && EVP_PKEY_keygen_init(generator.get()) == 1 &&
                      (group == nullptr || EVP_PKEY_CTX_set_group_name(
                                               generator.get(), group) == 1) &&
                      EVP_PKEY_generate(generator.get(), &raw) == 1;
    keys::PkeyPtr key(raw);
    require(
        made && key != nullptr,
        std::string("required OpenSSL algorithm is unavailable or failed: ") +
            (group != nullptr ? group : algorithm));
    return key;
}

BioPtr memory_bio(bool secret) {
    // A secure memory BIO clears its buffer when it grows and when it is
    // freed, so a private key never sits in an unwiped allocation.
    BioPtr bio(BIO_new(secret ? BIO_s_secmem() : BIO_s_mem()), BIO_free);
    require(bio != nullptr, "OpenSSL memory allocation failed");
    return bio;
}

std::string_view bio_text(BIO* bio) {
    char* data = nullptr;
    const long size = BIO_get_mem_data(bio, &data);
    require(size >= 0 && (size == 0 || data != nullptr),
            "OpenSSL PEM encoding failed");
    return {data, static_cast<std::size_t>(size)};
}

BioPtr private_pem(const keys::KeyContext& context, EVP_PKEY* key) {
    auto bio = memory_bio(true);
    require(PEM_write_bio_PrivateKey_ex(bio.get(), key, nullptr, nullptr, 0,
                                        nullptr, nullptr, context.context(),
                                        kProperties) == 1,
            "OpenSSL could not encode a private key");
    return bio;
}

std::string public_pem(const keys::KeyContext& context, EVP_PKEY* key) {
    auto bio = memory_bio(false);
    require(PEM_write_bio_PUBKEY_ex(bio.get(), key, context.context(),
                                    kProperties) == 1,
            "OpenSSL could not encode a public key");
    return std::string(bio_text(bio.get()));
}

// One allocation sized for every staged block before any secret is copied,
// so growth never leaves a copy of the first block behind.
SecretBytes join_secret(std::initializer_list<BIO*> blocks) {
    std::size_t total = 0;
    for (BIO* block : blocks) total += bio_text(block).size();
    SecretBytes joined(total);
    std::size_t offset = 0;
    for (BIO* block : blocks) {
        const auto text = bio_text(block);
        std::memcpy(joined.data() + offset, text.data(), text.size());
        offset += text.size();
    }
    return joined;
}

std::string certificate_pem(X509* certificate) {
    auto bio = memory_bio(false);
    require(PEM_write_bio_X509(bio.get(), certificate) == 1,
            "OpenSSL could not encode a certificate");
    return std::string(bio_text(bio.get()));
}

void add_extension(X509* certificate, X509* issuer, int nid,
                   const char* value) {
    X509V3_CTX context;
    X509V3_set_ctx_nodb(&context);
    X509V3_set_ctx(&context, issuer, certificate, nullptr, nullptr, 0);
    ExtensionPtr extension(X509V3_EXT_nconf_nid(nullptr, &context, nid, value),
                           X509_EXTENSION_free);
    require(extension != nullptr &&
                X509_add_ext(certificate, extension.get(), -1) == 1,
            "OpenSSL could not add a certificate extension");
}

void set_serial(X509* certificate, int bits) {
    BignumPtr serial(BN_new(), BN_free);
    require(serial != nullptr, "OpenSSL memory allocation failed");
    do {
        require(BN_rand(serial.get(), bits, BN_RAND_TOP_ANY,
                        BN_RAND_BOTTOM_ANY) == 1,
                "OpenSSL random generation failed");
    } while (BN_is_zero(serial.get()));
    require(BN_to_ASN1_INTEGER(serial.get(),
                               X509_get_serialNumber(certificate)) != nullptr,
            "OpenSSL could not set a certificate serial");
}

X509Ptr new_certificate(const keys::KeyContext& context,
                        std::string_view common_name, EVP_PKEY* key, long days,
                        int serial_bits) {
    X509Ptr certificate(X509_new_ex(context.context(), kProperties));
    require(certificate != nullptr &&
                X509_set_version(certificate.get(), X509_VERSION_3) == 1,
            "OpenSSL could not create a certificate");
    set_serial(certificate.get(), serial_bits);
    X509_NAME* subject = X509_get_subject_name(certificate.get());
    require(common_name.size() <=
                    static_cast<std::size_t>(std::numeric_limits<int>::max()) &&
                X509_NAME_add_entry_by_txt(
                    subject, "CN", MBSTRING_UTF8,
                    reinterpret_cast<const unsigned char*>(common_name.data()),
                    static_cast<int>(common_name.size()), -1, 0) == 1,
            "OpenSSL could not name a certificate");
    require(
        X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0) != nullptr &&
            X509_time_adj_ex(X509_getm_notAfter(certificate.get()),
                             static_cast<int>(days), 0, nullptr) != nullptr &&
            X509_set_pubkey(certificate.get(), key) == 1,
        "OpenSSL could not fill a certificate");
    return certificate;
}

void sign_certificate(const keys::KeyContext& context, X509* certificate,
                      EVP_PKEY* key) {
    MdContextPtr signer(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    require(signer != nullptr &&
                EVP_DigestSignInit_ex(
                    signer.get(), nullptr, crypto::kSha256Algorithm.data(),
                    context.context(), kProperties, key, nullptr) == 1 &&
                X509_sign_ctx(certificate, signer.get()) > 0,
            "OpenSSL could not sign a certificate");
}

bool is_ip_literal(std::string_view host) {
    // Setup's host text is canonical, so a colon or a dotted quad of digits
    // is an IP literal and anything else a DNS name.
    return host.find(':') != std::string_view::npos ||
           host.find_first_not_of("0123456789.") == std::string_view::npos;
}

}  // namespace

void X509Deleter::operator()(X509* certificate) const noexcept {
    X509_free(certificate);
}

Material::Material() try : keys_() {
} catch (const keys::KeyError&) {
    throw SetupError("the OpenSSL default provider is unavailable");
}

CompositeIdentity Material::composite() const {
    const auto classical = generate(keys_, crypto::kEd25519Algorithm.data());
    const auto post_quantum = generate(keys_, crypto::kMlDsa87Algorithm.data());
    const auto classical_private = private_pem(keys_, classical.get());
    const auto post_quantum_private = private_pem(keys_, post_quantum.get());
    CompositeIdentity identity{
        join_secret({classical_private.get(), post_quantum_private.get()}),
        public_pem(keys_, classical.get()) +
            public_pem(keys_, post_quantum.get()),
        {}};
    // The fingerprint comes from the reader yume and yumed use, and both
    // halves must parse back to the same identity.
    try {
        const auto parsed = keys::composite_private_from_pem(
            keys_, identity.private_pem.text());
        const auto published =
            keys::composite_public_from_pem(keys_, identity.public_pem);
        require(parsed.identity.fingerprint == published.fingerprint,
                "a generated composite identity does not match its public key");
        identity.fingerprint = published.fingerprint;
    } catch (const keys::KeyError& error) {
        throw SetupError(
            std::string("a generated composite identity is unreadable: ") +
            error.what());
    }
    return identity;
}

KemKeys Material::mlkem() const {
    const char* algorithm = crypto::kMlKem1024Algorithm.data();
    const auto key = generate(keys_, algorithm);
    const auto staged = private_pem(keys_, key.get());
    KemKeys pair{join_secret({staged.get()}), public_pem(keys_, key.get())};
    try {
        const auto parsed =
            keys::parse_key(keys_, pair.private_pem.text(), true, algorithm);
        const auto published =
            keys::parse_key(keys_, pair.public_pem, false, algorithm);
        require(
            keys::public_der(parsed.get()) == keys::public_der(published.get()),
            "a generated ML-KEM key does not match its public key");
    } catch (const keys::KeyError& error) {
        throw SetupError(std::string("a generated ML-KEM key is unreadable: ") +
                         error.what());
    }
    return pair;
}

TlsMaterial Material::tls(std::string_view host) const {
    const auto ca_key = generate(keys_, "EC", kTlsCurve);
    auto ca = new_certificate(keys_, kCaName, ca_key.get(), kCaDays, 159);
    X509_set_issuer_name(ca.get(), X509_get_subject_name(ca.get()));
    add_extension(ca.get(), ca.get(), NID_basic_constraints,
                  "critical,CA:TRUE,pathlen:0");
    add_extension(ca.get(), ca.get(), NID_key_usage,
                  "critical,keyCertSign,cRLSign");
    add_extension(ca.get(), ca.get(), NID_subject_key_identifier, "hash");
    add_extension(ca.get(), ca.get(), NID_authority_key_identifier,
                  "keyid:always");
    sign_certificate(keys_, ca.get(), ca_key.get());

    const auto leaf_key = generate(keys_, "EC", kTlsCurve);
    auto leaf = new_certificate(keys_, host, leaf_key.get(), kLeafDays, 128);
    require(
        X509_set_issuer_name(leaf.get(), X509_get_subject_name(ca.get())) == 1,
        "OpenSSL could not fill a certificate");
    const std::string alternative =
        (is_ip_literal(host) ? "IP:" : "DNS:") + std::string(host);
    add_extension(leaf.get(), ca.get(), NID_basic_constraints,
                  "critical,CA:FALSE");
    add_extension(leaf.get(), ca.get(), NID_key_usage,
                  "critical,digitalSignature");
    add_extension(leaf.get(), ca.get(), NID_ext_key_usage, "serverAuth");
    add_extension(leaf.get(), ca.get(), NID_subject_alt_name,
                  alternative.c_str());
    add_extension(leaf.get(), ca.get(), NID_subject_key_identifier, "hash");
    add_extension(leaf.get(), ca.get(), NID_authority_key_identifier,
                  "keyid,issuer");
    sign_certificate(keys_, leaf.get(), ca_key.get());

    // The checks yume-doctor makes of a server's TLS files.
    std::vector<X509Ptr> trust;
    trust.push_back(std::move(ca));
    require(verify_server_certificate(keys_, leaf.get(), trust) &&
                certificate_names(leaf.get(), host),
            "a generated TLS certificate does not verify");
    const auto staged = private_pem(keys_, leaf_key.get());
    return {join_secret({staged.get()}), certificate_pem(leaf.get()),
            certificate_pem(trust.front().get())};
}

void Material::random(std::span<std::uint8_t> output) const {
    require(output.size() <=
                    static_cast<std::size_t>(std::numeric_limits<int>::max()) &&
                RAND_bytes_ex(keys_.context(), output.data(), output.size(),
                              0) == 1,
            "OpenSSL random generation failed");
}

std::vector<X509Ptr> read_certificates(const keys::KeyContext& context,
                                       std::string_view pem) {
    std::vector<X509Ptr> certificates;
    if (pem.size() >
        static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return certificates;
    }
    BioPtr input(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())),
                 BIO_free);
    if (input == nullptr) return certificates;
    for (;;) {
        X509Ptr certificate(X509_new_ex(context.context(), kProperties));
        if (certificate == nullptr) return {};
        X509* raw = certificate.get();
        if (PEM_read_bio_X509(input.get(), &raw, nullptr, nullptr) == nullptr)
            break;
        certificates.push_back(std::move(certificate));
    }
    return certificates;
}

bool certificate_names(X509* certificate, std::string_view host) {
    const std::string text(host);
    if (is_ip_literal(host))
        return X509_check_ip_asc(certificate, text.c_str(), 0) == 1;
    return X509_check_host(certificate, text.data(), text.size(), 0, nullptr) ==
           1;
}

bool verify_server_certificate(const keys::KeyContext& context,
                               X509* certificate,
                               std::span<const X509Ptr> trust) {
    StorePtr store(X509_STORE_new(), X509_STORE_free);
    StoreContextPtr verify(
        X509_STORE_CTX_new_ex(context.context(), kProperties),
        X509_STORE_CTX_free);
    if (store == nullptr || verify == nullptr) return false;
    for (const auto& anchor : trust) {
        if (X509_STORE_add_cert(store.get(), anchor.get()) != 1) return false;
    }
    if (X509_STORE_CTX_init(verify.get(), store.get(), certificate, nullptr) !=
            1 ||
        X509_STORE_CTX_set_purpose(verify.get(), X509_PURPOSE_SSL_SERVER) !=
            1) {
        return false;
    }
    X509_VERIFY_PARAM_set_auth_level(X509_STORE_CTX_get0_param(verify.get()),
                                     2);
    return X509_verify_cert(verify.get()) == 1;
}

bool certificate_current(X509* certificate) {
    return X509_cmp_current_time(X509_get0_notAfter(certificate)) > 0;
}

}  // namespace yume::setup
