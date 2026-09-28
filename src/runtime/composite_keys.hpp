/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <exception>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/types.h>

#include "engine/status.hpp"
#include "providers/openssl_security_provider.hpp"

namespace yume::runtime::keys {

// A key operation that failed. The message is a fixed text that names no
// input, key or path, so callers may publish it.
class KeyError final : public std::exception {
public:
    explicit KeyError(
        const char* message,
        engine::StatusCode code = engine::StatusCode::InvalidArgument) noexcept
        : message_(message), code_(code) {}
    const char* what() const noexcept override { return message_; }
    engine::StatusCode code() const noexcept { return code_; }

private:
    const char* message_;
    engine::StatusCode code_;
};

void require(bool condition, const char* message,
             engine::StatusCode code = engine::StatusCode::InvalidArgument);

// A private OpenSSL library context with the default provider and SHA-256.
// Keys parsed here stay in this context. Creation throws KeyError with
// ProviderMismatch when the provider or digest is missing.
class KeyContext final {
public:
    KeyContext();
    KeyContext(const KeyContext&) = delete;
    KeyContext& operator=(const KeyContext&) = delete;
    ~KeyContext();

    OSSL_LIB_CTX* context() const noexcept;
    // The composite identity fingerprint: SHA-256 over the YTP/1 identity
    // domain and each public key's DER behind its u32 length, as lowercase
    // hex.
    std::string fingerprint(std::span<const std::byte> classical,
                            std::span<const std::byte> post_quantum) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

struct PkeyDeleter final {
    void operator()(EVP_PKEY* key) const noexcept;
};
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDeleter>;

// Splits text into exactly count PEM blocks of one type: "PRIVATE KEY" or
// "PUBLIC KEY". Headers, other block types, bad encoding and trailing data
// fail.
std::vector<std::string_view> pem_blocks(std::string_view text,
                                         bool private_key, std::size_t count);
// Parses one PEM block in the context and requires the named algorithm from
// the default provider. Password-protected keys are refused.
PkeyPtr parse_key(const KeyContext& keys, std::string_view pem,
                  bool private_key, const char* algorithm);
std::vector<std::byte> public_der(EVP_PKEY* key);

// A composite Ed25519 and ML-DSA-87 public identity.
struct CompositePublic final {
    std::vector<std::byte> classical;
    std::vector<std::byte> post_quantum;
    std::string fingerprint;
    providers::CompositePublicIdentityView view() const noexcept {
        return {classical, post_quantum};
    }
};

// Two PUBLIC KEY blocks, Ed25519 then ML-DSA-87.
CompositePublic composite_public_from_pem(const KeyContext& keys,
                                          std::string_view pem);

// A composite signature is an Ed25519 signature (64 bytes) followed by an
// ML-DSA-87 signature (4627 bytes) over the same message. Both halves are
// checked on every correctly sized input, and both must verify.
bool verify_composite(const KeyContext& keys, const CompositePublic& identity,
                      std::span<const std::byte> message,
                      std::span<const std::byte> signature);

}  // namespace yume::runtime::keys
