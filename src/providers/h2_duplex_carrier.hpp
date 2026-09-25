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
#include <span>
#include <string>
#include <string_view>

#include "engine/carrier.hpp"
#include "providers/control_task.hpp"
#include "stealth/h2_carrier.hpp"

namespace yume::providers {

inline constexpr std::string_view kH2DuplexCarrierProviderId = "h2-duplex";
inline constexpr std::uint32_t kH2DuplexCarrierProviderApiVersion = 1U;
inline constexpr std::size_t kH2DuplexEnvelopeBytes = 12U;

// The supplied executor owns every carrier state transition. It must accept
// work until all carriers and provider operations have settled and invoke tasks
// serially on the declared affinity. post may throw before accepting work;
// it must never accept and then throw or discard it. submit retains the owner
// of an embedded control task, coalesces submissions, and MUST NOT allocate,
// throw, invoke inline or discard work. It is used for close, cancellation and
// credit return, including under sustained allocation failure. The caller
// retains and drains the executor after releasing the last open carrier handle.
// Repeated close/cancel, credit return and destruction of a carrier that has
// already closed and drained enqueue no further control work.
struct H2Dispatch final {
    std::function<void(std::function<void()>)> post;
    std::function<void(ControlTask&, std::shared_ptr<void>)> submit;
    explicit operator bool() const noexcept { return post && submit; }
};

// A promoted server keeps serving ordinary streams on the same connection.
// This handler must be bounded, synchronous and retain its cover source. It
// never performs another admission or promotion. False terminates the carrier.
class H2CoverHandler {
public:
    virtual ~H2CoverHandler() = default;
    virtual bool respond(obfs::H2Carrier&, const obfs::H2Request&) = 0;
    virtual void stream_closed(std::int32_t stream_id) noexcept = 0;
};

struct H2DuplexCarrierLimits final {
    // Includes the protected YTP envelope and AEAD output handed to Carrier,
    // but excludes the carrier-private 12-byte record envelope.
    std::size_t max_record_bytes{2U * 1024U * 1024U};
    std::size_t max_buffered_records{64U};
    std::size_t max_retained_receive_bytes{16U * 1024U * 1024U};
    std::size_t max_pending_secure_write_bytes{4U * 1024U * 1024U};
    std::size_t secure_read_bytes{64U * 1024U};
};

engine::Status validate_h2_duplex_carrier_limits(const H2DuplexCarrierLimits& limits);

struct H2DuplexClientConfig final {
    std::string server_name;
    std::uint16_t server_port{443U};
    H2DuplexCarrierLimits limits{};
};

// Client-side provider. Creation performs the genuine profile priming GET and
// asset exchange, waits for SETTINGS_ENABLE_CONNECT_PROTOCOL, submits RFC 8441
// extended CONNECT, and returns only after the peer accepts it with 200.
// The intended server name must match the name authenticated by the TLS
// provider. Each create consumes its SecureChannel once, derives its own
// exporter-bound admission path, and closes on failure without retrying it.
class H2DuplexCarrierProvider final : public engine::CarrierProvider {
public:
    // Key storage is borrowed only for this call. The provider copies exactly
    // 32 bytes into one immutable owner shared with pending creates; its final
    // destruction wipes those bytes. The caller owns wiping its input.
    static engine::Result<std::shared_ptr<H2DuplexCarrierProvider>> create(
        engine::ExecutorAffinity executor_affinity,
        H2Dispatch dispatch,
        H2DuplexClientConfig config,
        std::span<const std::byte> admission_key);

    H2DuplexCarrierProvider(const H2DuplexCarrierProvider&) = delete;
    H2DuplexCarrierProvider& operator=(const H2DuplexCarrierProvider&) = delete;
    ~H2DuplexCarrierProvider() noexcept override = default;

    const engine::ProviderDescriptor& descriptor() const noexcept override;
    void async_create(std::unique_ptr<engine::SecureChannel> channel,
                      engine::EndpointRole local_role,
                      engine::CancellationToken cancellation,
                      Completion completion) override;

    engine::ExecutorAffinity executor_affinity() const noexcept;
    const H2DuplexClientConfig& config() const noexcept;

private:
    struct AdmissionKey;

    H2DuplexCarrierProvider(
        engine::ProviderDescriptor descriptor,
        engine::ExecutorAffinity executor_affinity,
        H2Dispatch dispatch,
        H2DuplexClientConfig config,
        std::shared_ptr<const AdmissionKey> admission_key) noexcept;

    engine::ProviderDescriptor descriptor_;
    engine::ExecutorAffinity executor_affinity_;
    H2Dispatch dispatch_;
    H2DuplexClientConfig config_;
    std::shared_ptr<const AdmissionKey> admission_key_;
};

// Typed promotion seam used by the native h2-web FrontDoor. The front door retains
// and validates the live nghttp2 session through admission, calls
// H2Carrier::AcceptCarrier(), writes no further bytes itself, and transfers
// both objects here on its executor. SETTINGS, stream, HPACK, and flow-credit
// state are therefore never reconstructed from raw TLS or hidden in an opaque
// context handle.
engine::Result<std::unique_ptr<engine::Carrier>>
make_admitted_h2_duplex_server_carrier(
    std::unique_ptr<engine::SecureChannel> channel,
    std::unique_ptr<obfs::H2Carrier> admitted_h2,
    engine::ExecutorAffinity executor_affinity,
    H2Dispatch dispatch,
    H2DuplexCarrierLimits limits = {},
    std::shared_ptr<H2CoverHandler> cover = {});

}  // namespace yume::providers
