/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

#include "core/stealth/h2_carrier.hpp"
#include "engine/carrier.hpp"

namespace yume::providers {

inline constexpr std::string_view kYtp1H2CarrierProviderId = "h2-duplex";
inline constexpr std::uint32_t kYtp1H2CarrierProviderApiVersion = 1U;
inline constexpr std::size_t kYtp1H2CarrierEnvelopeBytes = 12U;

// The supplied executor owns every carrier state transition. It must accept
// work until all carriers and provider operations have settled, invoke tasks
// serially on the declared affinity, and must not throw or silently discard a
// task. Keeping this seam source-level makes the carrier usable with Asio,
// libuv, an application loop, or a deterministic test executor without
// introducing one of them into the dependency-pure engine.
using Ytp1H2PostHandler =
    std::function<void(std::function<void()>)>;

struct Ytp1H2CarrierLimits final {
    // Includes the protected YTP envelope and AEAD output handed to Carrier,
    // but excludes the carrier-private 12-byte record envelope.
    std::size_t max_record_bytes{2U * 1024U * 1024U};
    std::size_t max_buffered_records{64U};
    std::size_t max_retained_receive_bytes{16U * 1024U * 1024U};
    std::size_t max_pending_secure_write_bytes{4U * 1024U * 1024U};
    std::size_t secure_read_bytes{64U * 1024U};
};

struct Ytp1H2ClientConfig final {
    std::string authority;
    std::string carrier_path;
    Ytp1H2CarrierLimits limits{};
};

// Client-side provider. Creation performs the genuine profile priming GET and
// asset exchange, waits for SETTINGS_ENABLE_CONNECT_PROTOCOL, submits RFC 8441
// extended CONNECT, and returns only after the peer accepts it with 200.
class Ytp1H2CarrierProvider final : public engine::CarrierProvider {
public:
    static engine::Result<std::shared_ptr<Ytp1H2CarrierProvider>> create(
        engine::ExecutorAffinity executor_affinity,
        Ytp1H2PostHandler post,
        Ytp1H2ClientConfig config);

    Ytp1H2CarrierProvider(const Ytp1H2CarrierProvider&) = delete;
    Ytp1H2CarrierProvider& operator=(const Ytp1H2CarrierProvider&) = delete;
    ~Ytp1H2CarrierProvider() noexcept override = default;

    const engine::ProviderDescriptor& descriptor() const noexcept override;
    void async_create(std::unique_ptr<engine::SecureChannel> channel,
                      engine::EndpointRole local_role,
                      engine::CancellationToken cancellation,
                      Completion completion) override;

    engine::ExecutorAffinity executor_affinity() const noexcept;
    const Ytp1H2ClientConfig& config() const noexcept;

private:
    Ytp1H2CarrierProvider(
        engine::ProviderDescriptor descriptor,
        engine::ExecutorAffinity executor_affinity,
        Ytp1H2PostHandler post,
        Ytp1H2ClientConfig config) noexcept;

    engine::ProviderDescriptor descriptor_;
    engine::ExecutorAffinity executor_affinity_;
    Ytp1H2PostHandler post_;
    Ytp1H2ClientConfig config_;
};

// Typed promotion seam for a future h2-web FrontDoor. The front door retains
// and validates the live nghttp2 session through admission, calls
// H2Carrier::AcceptCarrier(), writes no further bytes itself, and transfers
// both objects here on its executor. SETTINGS, stream, HPACK, and flow-credit
// state are therefore never reconstructed from raw TLS or hidden in an opaque
// context handle.
engine::Result<std::unique_ptr<engine::Carrier>>
make_ytp1_h2_admitted_server_carrier(
    std::unique_ptr<engine::SecureChannel> channel,
    std::unique_ptr<obfs::H2Carrier> admitted_h2,
    engine::ExecutorAffinity executor_affinity,
    Ytp1H2PostHandler post,
    Ytp1H2CarrierLimits limits = {});

}  // namespace yume::providers
