/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/types.h>

#include "providers/composite_keys.hpp"
#include "setup/files.hpp"

namespace yume::setup {

// A composite Ed25519 and ML-DSA-87 identity as a kit stores it: two PRIVATE
// KEY blocks, two PUBLIC KEY blocks and the YTP/1 fingerprint.
struct CompositeIdentity final {
    SecretBytes private_pem;
    std::string public_pem;
    std::string fingerprint;
};

// An ML-KEM-1024 key pair as PEM.
struct KemKeys final {
    SecretBytes private_pem;
    std::string public_pem;
};

// The outer TLS material of one server: its P-256 key, its certificate and
// the certificate of the one-off CA that signed it, which clients trust. The
// CA's key is never written anywhere.
struct TlsMaterial final {
    SecretBytes key_pem;
    std::string certificate_pem;
    std::string trust_pem;
};

struct X509Deleter final {
    void operator()(X509* certificate) const noexcept;
};
using X509Ptr = std::unique_ptr<X509, X509Deleter>;

// Every key and certificate setup makes comes from one private OpenSSL
// library context with the default provider, the one the YTP/1 readers use.
// Each generated key is parsed back by those readers before it is returned,
// so a kit never holds material yume or yumed would refuse.
class Material final {
public:
    // Throws SetupError when the provider or an algorithm is missing.
    Material();

    const providers::keys::KeyContext& keys() const noexcept { return keys_; }

    CompositeIdentity composite() const;
    KemKeys mlkem() const;
    // host is the setup's canonical host text, a DNS name or IP literal,
    // which the certificate's subject and only subject alternative name
    // carry.
    TlsMaterial tls(std::string_view host) const;
    void random(std::span<std::uint8_t> output) const;

private:
    providers::keys::KeyContext keys_;
};

// The certificates of a PEM text, in order. Nothing for text that holds
// none or holds anything OpenSSL cannot read.
std::vector<X509Ptr> read_certificates(const providers::keys::KeyContext& keys,
                                       std::string_view pem);
// Whether certificate names host, an IP literal or a DNS name, as a TLS
// client checks it.
bool certificate_names(X509* certificate, std::string_view host);
// Whether certificate chains to one of trust as a TLS server certificate at
// security level 2, now.
bool verify_server_certificate(const providers::keys::KeyContext& keys,
                               X509* certificate,
                               std::span<const X509Ptr> trust);
// Whether a certificate's notAfter is still ahead.
bool certificate_current(X509* certificate);

}  // namespace yume::setup
