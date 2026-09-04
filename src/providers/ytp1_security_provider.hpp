/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <memory>
#include <span>
#include <string_view>

#include "engine/session_engine.hpp"

namespace yume::providers {

inline constexpr std::string_view kYtp1OpenSslSecurityProviderId =
    "openssl35.ytp1-security";
inline constexpr std::uint32_t kYtp1OpenSslSecurityProviderApiVersion = 1U;
inline constexpr std::size_t kMaxYtp1AuthorizedIdentities = 1024U;

// Key inputs use one canonical encoding: unencrypted PKCS#8 DER for private
// keys and SubjectPublicKeyInfo DER for public keys. Views are borrowed only
// for factory creation. The factory parses and copies their key state before
// returning and never retains caller storage.
struct CompositePrivateIdentityView final {
    std::span<const std::byte> ed25519_private_key_der;
    std::span<const std::byte> ml_dsa_87_private_key_der;
};

struct CompositePublicIdentityView final {
    std::span<const std::byte> ed25519_public_key_der;
    std::span<const std::byte> ml_dsa_87_public_key_der;
};

struct Ytp1ClientCredentialsView final {
    CompositePrivateIdentityView local_identity;
    CompositePublicIdentityView trusted_server_identity;
    std::span<const std::byte> server_ml_kem_1024_public_key_der;
    std::span<const std::byte> access_psk;
    std::string_view server_peer_identity;
};

struct Ytp1AuthorizedIdentityView final {
    CompositePublicIdentityView identity;
    std::span<const std::byte> access_psk;
    std::string_view peer_identity;
};

struct Ytp1ServerCredentialsView final {
    CompositePrivateIdentityView local_identity;
    std::span<const std::byte> ml_kem_1024_private_key_der;
    std::span<const Ytp1AuthorizedIdentityView> authorized_identities;
};

// One factory is configured for exactly one role. Provider selection is
// instance-local and immutable; create() rejects the other role and never
// performs algorithm or credential fallback.
class Ytp1OpenSslSecurityProviderFactory final
    : public engine::SessionSecurityProviderFactory {
public:
    static engine::Result<
        std::shared_ptr<Ytp1OpenSslSecurityProviderFactory>>
    create_client(const Ytp1ClientCredentialsView& credentials);

    static engine::Result<
        std::shared_ptr<Ytp1OpenSslSecurityProviderFactory>>
    create_server(const Ytp1ServerCredentialsView& credentials);

    Ytp1OpenSslSecurityProviderFactory(
        const Ytp1OpenSslSecurityProviderFactory&) = delete;
    Ytp1OpenSslSecurityProviderFactory& operator=(
        const Ytp1OpenSslSecurityProviderFactory&) = delete;
    ~Ytp1OpenSslSecurityProviderFactory() override;

    const engine::ProviderDescriptor& descriptor() const noexcept override;
    engine::Result<std::unique_ptr<engine::SessionSecurityProvider>> create(
        engine::EndpointRole local_role) override;

private:
    struct Impl;

    Ytp1OpenSslSecurityProviderFactory(
        engine::ProviderDescriptor descriptor,
        std::shared_ptr<Impl> impl) noexcept;

    engine::ProviderDescriptor descriptor_;
    std::shared_ptr<Impl> impl_;
};

}  // namespace yume::providers
