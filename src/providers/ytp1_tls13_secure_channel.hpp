/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

#include "engine/secure_channel.hpp"

namespace yume::providers {

inline constexpr std::string_view kYtp1Tls13SecureChannelProviderId =
    "tls13-native";
inline constexpr std::uint32_t kYtp1Tls13SecureChannelProviderApiVersion = 1U;

struct Ytp1Tls13Limits final {
    std::size_t max_plaintext_bytes{64U * 1024U};
    std::size_t max_encrypted_chunk_bytes{64U * 1024U};
    std::size_t max_credential_pem_bytes{256U * 1024U};
};

// PEM views are borrowed only during create(). OpenSSL parses and owns the
// resulting trust/key objects; the provider never retains caller storage.
struct Ytp1Tls13ClientConfigView final {
    std::string_view server_name;
    std::span<const std::byte> trust_anchors_pem;
    Ytp1Tls13Limits limits{};
    // Optional as a pair. Supplying one without the other fails closed.
    std::span<const std::byte> certificate_chain_pem;
    std::span<const std::byte> private_key_pem;
};

struct Ytp1Tls13ServerConfigView final {
    std::span<const std::byte> certificate_chain_pem;
    std::span<const std::byte> private_key_pem;
    // Empty means ordinary server-authenticated TLS. When non-empty, mutual
    // TLS is mandatory and the verified leaf certificate becomes outer peer
    // evidence; it still is not the inner authenticated transport identity.
    std::span<const std::byte> client_trust_anchors_pem;
    Ytp1Tls13Limits limits{};
};

class Ytp1Tls13SecureChannelProvider final
    : public engine::SecureChannelProvider {
public:
    struct Impl;

    static engine::Result<std::shared_ptr<Ytp1Tls13SecureChannelProvider>>
    create_client(const Ytp1Tls13ClientConfigView& config);

    static engine::Result<std::shared_ptr<Ytp1Tls13SecureChannelProvider>>
    create_server(const Ytp1Tls13ServerConfigView& config);

    Ytp1Tls13SecureChannelProvider(
        const Ytp1Tls13SecureChannelProvider&) = delete;
    Ytp1Tls13SecureChannelProvider& operator=(
        const Ytp1Tls13SecureChannelProvider&) = delete;
    ~Ytp1Tls13SecureChannelProvider() override;

    const engine::ProviderDescriptor& descriptor() const noexcept override;
    void async_wrap(std::unique_ptr<engine::ByteChannel> channel,
                    engine::EndpointRole local_role,
                    engine::CancellationToken cancellation,
                    Completion completion) override;

private:
    Ytp1Tls13SecureChannelProvider(engine::ProviderDescriptor descriptor,
                                   std::shared_ptr<Impl> impl) noexcept;

    engine::ProviderDescriptor descriptor_;
    std::shared_ptr<Impl> impl_;
};

}  // namespace yume::providers
