/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "engine/byte_channel.hpp"
#include "engine/status.hpp"
#include "providers/asio_execution_context.hpp"

namespace yume::providers {

// RFC 1929 username and password, each 1 to 255 bytes. Moves and destruction
// wipe the storage they leave behind.
class Socks5Credentials final {
public:
    static engine::Result<Socks5Credentials> create(std::string username, std::string password);

    Socks5Credentials(Socks5Credentials&& other) noexcept;
    Socks5Credentials& operator=(Socks5Credentials&& other) noexcept;
    Socks5Credentials(const Socks5Credentials&) = delete;
    Socks5Credentials& operator=(const Socks5Credentials&) = delete;
    ~Socks5Credentials();

    const std::string& username() const noexcept { return username_; }
    const std::string& password() const noexcept { return password_; }

private:
    Socks5Credentials(std::string username, std::string password) noexcept;
    void wipe() noexcept;

    std::string username_;
    std::string password_;
};

struct Socks5UpstreamLimits final {
    // One deadline covers the proxy connection and the whole exchange.
    std::chrono::milliseconds handshake_timeout{10'000};
};

// A byte channel to a target through a SOCKS5 proxy (RFC 1928). The proxy
// provider connects to the proxy, and this provider asks the proxy to CONNECT
// to the target. A host name travels as a name, so the proxy resolves it, and
// an IP literal travels as an address. With credentials only username and
// password authentication is offered, without them only no authentication.
// The returned channel carries the target connection. No byte after the
// proxy's reply is read. RFC 1929 sends the password in the clear, and the
// channel frees that message without wiping it.
class Socks5UpstreamProvider final : public engine::ByteChannelProvider {
public:
    // InvalidArgument without a context or proxy provider, for an empty
    // target or one over 255 bytes, or for port 0.
    static engine::Result<std::shared_ptr<Socks5UpstreamProvider>> create(
        std::shared_ptr<AsioExecutionContext> context,
        std::shared_ptr<engine::ByteChannelProvider> proxy,
        std::string target_host, std::uint16_t target_port,
        std::optional<Socks5Credentials> credentials = std::nullopt,
        Socks5UpstreamLimits limits = {});

    Socks5UpstreamProvider(const Socks5UpstreamProvider&) = delete;
    Socks5UpstreamProvider& operator=(const Socks5UpstreamProvider&) = delete;
    ~Socks5UpstreamProvider() noexcept override;

    // The proxy provider's descriptor. The result is still a TCP byte stream.
    const engine::ProviderDescriptor& descriptor() const noexcept override;
    // Requires the context and completes once on it: the proxy provider's
    // failure as reported, Cancelled after the token, PermissionDenied when
    // the proxy refuses the credentials, and Closed when the proxy does not
    // answer as SOCKS5, refuses the target or misses the deadline.
    void async_create(engine::EndpointRole role, engine::CancellationToken cancellation,
                      Completion completion) override;

    struct Settings;

private:
    Socks5UpstreamProvider(std::shared_ptr<AsioExecutionContext> context,
                           std::shared_ptr<engine::ByteChannelProvider> proxy,
                           std::shared_ptr<const Settings> settings) noexcept;

    std::shared_ptr<AsioExecutionContext> context_;
    std::shared_ptr<engine::ByteChannelProvider> proxy_;
    std::shared_ptr<const Settings> settings_;
};

}  // namespace yume::providers
