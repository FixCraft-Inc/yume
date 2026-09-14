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
// Client creation requires the active browser profile and patched OpenSSL.
// Its broader TLS/ALPN offer does not permit a downgrade: only negotiated
// TLS 1.3 plus h2 can produce a SecureChannel.
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

// A completed public-server TLS connection before carrier admission. This is
// deliberately only a ByteChannel: ordinary TLS 1.2 or HTTP/1.1 cover traffic
// must never acquire the TLS 1.3/H2 SecureChannel provider provenance.
// Metadata is read locally from this connection's SSL object after handshake.
// Operations and promotion follow the underlying ByteChannel's executor.
class Ytp1TlsServerConnection : public engine::ByteChannel {
public:
    ~Ytp1TlsServerConnection() override = default;
    virtual std::uint16_t tls_version() const noexcept = 0;
    virtual std::string_view negotiated_protocol() const noexcept = 0;
    virtual std::string_view server_name() const noexcept = 0;
    virtual engine::Result<engine::Buffer> export_keying_material(
        std::string_view label, std::span<const std::byte> context,
        std::size_t output_size) = 0;

    // Transfers the same SSL/BIO/transport state exactly once, only for TLS
    // 1.3 with ALPN h2 and no pending application or transport I/O. The caller
    // owns admission and must first settle its cover operations. A successful
    // transfer leaves this handle inert; destroying it cannot close the new
    // SecureChannel. Refusal leaves cover ownership with this handle.
    virtual engine::Result<std::unique_ptr<engine::SecureChannel>> promote() = 0;
};

class Ytp1Tls13SecureChannelProvider final
    : public engine::SecureChannelProvider {
public:
    struct Impl;
    using ServerCoverCompletion = std::function<void(
        engine::Result<std::unique_ptr<Ytp1TlsServerConnection>>)>;

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
    engine::EndpointRole local_role() const noexcept;
    void async_wrap(std::unique_ptr<engine::ByteChannel> channel,
                    engine::EndpointRole local_role,
                    engine::CancellationToken cancellation,
                    Completion completion) override;

    // Server only. Offers ordinary TLS 1.2/1.3 and h2/HTTP/1.1; clients without
    // ALPN retain an empty negotiated protocol for ordinary HTTP/1 handling.
    // Existing async_wrap remains strict even on the same provider instance.
    void async_wrap_server_cover(std::unique_ptr<engine::ByteChannel> channel,
                                 engine::CancellationToken cancellation,
                                 ServerCoverCompletion completion);

private:
    void async_wrap_impl(std::unique_ptr<engine::ByteChannel> channel,
                         engine::EndpointRole local_role,
                         engine::CancellationToken cancellation,
                         Completion completion,
                         ServerCoverCompletion cover_completion);
    Ytp1Tls13SecureChannelProvider(engine::ProviderDescriptor descriptor,
                                   std::shared_ptr<Impl> impl) noexcept;

    engine::ProviderDescriptor descriptor_;
    std::shared_ptr<Impl> impl_;
};

}  // namespace yume::providers
