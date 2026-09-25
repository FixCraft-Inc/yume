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

inline constexpr std::string_view kYtp1H2CarrierProviderId = "h2-duplex";
inline constexpr std::uint32_t kYtp1H2CarrierProviderApiVersion = 1U;
inline constexpr std::size_t kYtp1H2CarrierEnvelopeBytes = 12U;

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
struct Ytp1H2Dispatch final {
    std::function<void(std::function<void()>)> post;
    std::function<void(ControlTask&, std::shared_ptr<void>)> submit;
    explicit operator bool() const noexcept { return post && submit; }
};

// A promoted server keeps serving ordinary streams on the same connection.
// This handler must be bounded, synchronous and retain its cover source. It
// never performs another admission or promotion. False terminates the carrier.
class Ytp1H2CoverHandler {
public:
    virtual ~Ytp1H2CoverHandler() = default;
    virtual bool respond(obfs::H2Carrier&, const obfs::H2Request&) = 0;
    virtual void stream_closed(std::int32_t stream_id) noexcept = 0;
};

struct Ytp1H2CarrierLimits final {
    // Includes the protected YTP envelope and AEAD output handed to Carrier,
    // but excludes the carrier-private 12-byte record envelope.
    std::size_t max_record_bytes{2U * 1024U * 1024U};
    std::size_t max_buffered_records{64U};
    std::size_t max_retained_receive_bytes{16U * 1024U * 1024U};
    std::size_t max_pending_secure_write_bytes{4U * 1024U * 1024U};
    std::size_t secure_read_bytes{64U * 1024U};
};

engine::Status validate_ytp1_h2_carrier_limits(const Ytp1H2CarrierLimits& limits);

struct Ytp1H2ClientConfig final {
    std::string server_name;
    std::uint16_t server_port{443U};
    Ytp1H2CarrierLimits limits{};
};

// Client-side provider. Creation performs the genuine profile priming GET and
// asset exchange, waits for SETTINGS_ENABLE_CONNECT_PROTOCOL, submits RFC 8441
// extended CONNECT, and returns only after the peer accepts it with 200.
// The intended server name must match the name authenticated by the TLS
// provider. Each create consumes its SecureChannel once, derives its own
// exporter-bound admission path, and closes on failure without retrying it.
class Ytp1H2CarrierProvider final : public engine::CarrierProvider {
public:
    // Key storage is borrowed only for this call. The provider copies exactly
    // 32 bytes into one immutable owner shared with pending creates; its final
    // destruction wipes those bytes. The caller owns wiping its input.
    static engine::Result<std::shared_ptr<Ytp1H2CarrierProvider>> create(
        engine::ExecutorAffinity executor_affinity,
        Ytp1H2Dispatch dispatch,
        Ytp1H2ClientConfig config,
        std::span<const std::byte> admission_key);

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
    struct AdmissionKey;

    Ytp1H2CarrierProvider(
        engine::ProviderDescriptor descriptor,
        engine::ExecutorAffinity executor_affinity,
        Ytp1H2Dispatch dispatch,
        Ytp1H2ClientConfig config,
        std::shared_ptr<const AdmissionKey> admission_key) noexcept;

    engine::ProviderDescriptor descriptor_;
    engine::ExecutorAffinity executor_affinity_;
    Ytp1H2Dispatch dispatch_;
    Ytp1H2ClientConfig config_;
    std::shared_ptr<const AdmissionKey> admission_key_;
};

// Typed promotion seam used by the native h2-web FrontDoor. The front door retains
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
    Ytp1H2Dispatch dispatch,
    Ytp1H2CarrierLimits limits = {},
    std::shared_ptr<Ytp1H2CoverHandler> cover = {});

}  // namespace yume::providers
