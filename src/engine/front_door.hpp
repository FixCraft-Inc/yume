/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <functional>
#include <memory>
#include <utility>

#include "engine/carrier.hpp"

namespace yume::engine {

// A successful admission must retain the application-protocol connection and
// stream state that carried it. In particular, a genuine HTTP/2 front door
// cannot reduce an admitted stream back to raw TLS and reconstruct SETTINGS,
// stream, and flow-credit state later. AcceptedCarrier therefore transfers a
// ready carrier plus its immutable provider provenance without exposing an
// opaque provider context to the dependency-pure engine.
class AcceptedCarrier final {
public:
    static Result<AcceptedCarrier> create(
        ProviderDescriptor descriptor,
        std::unique_ptr<Carrier> carrier) {
        if (!carrier) {
            return Result<AcceptedCarrier>(Status(
                StatusCode::InvalidArgument,
                "accepted carrier must not be null"));
        }
        if (descriptor.kind() != ProviderKind::Carrier) {
            carrier->cancel();
            carrier->close();
            return Result<AcceptedCarrier>(Status(
                StatusCode::ProviderMismatch,
                "accepted transport provenance is not a carrier provider"));
        }
        const ProviderDescriptor& instance_descriptor = carrier->descriptor();
        if (instance_descriptor.kind() != ProviderKind::Carrier ||
            instance_descriptor.provider_id() != descriptor.provider_id() ||
            instance_descriptor.api_version() != descriptor.api_version() ||
            instance_descriptor.capabilities() != descriptor.capabilities()) {
            carrier->cancel();
            carrier->close();
            return Result<AcceptedCarrier>(Status(
                StatusCode::ProviderMismatch,
                "accepted carrier provenance does not match its instance"));
        }
        if (!carrier->executor_affinity().valid() ||
            carrier->secure_channel().executor_affinity() !=
                carrier->executor_affinity()) {
            carrier->cancel();
            carrier->close();
            return Result<AcceptedCarrier>(Status(
                StatusCode::ProviderMismatch,
                "accepted carrier has inconsistent executor affinity"));
        }
        return Result<AcceptedCarrier>(AcceptedCarrier(
            std::move(descriptor), std::move(carrier)));
    }

    AcceptedCarrier(const AcceptedCarrier&) = delete;
    AcceptedCarrier& operator=(const AcceptedCarrier&) = delete;
    AcceptedCarrier(AcceptedCarrier&&) noexcept = default;
    AcceptedCarrier& operator=(AcceptedCarrier&&) noexcept = default;

    const ProviderDescriptor& descriptor() const noexcept {
        return descriptor_;
    }
    Carrier& carrier() noexcept { return *carrier_; }
    const Carrier& carrier() const noexcept { return *carrier_; }
    std::unique_ptr<Carrier> take_carrier() && noexcept {
        return std::move(carrier_);
    }

private:
    AcceptedCarrier(ProviderDescriptor descriptor,
                    std::unique_ptr<Carrier> carrier) noexcept
        : descriptor_(std::move(descriptor)), carrier_(std::move(carrier)) {}

    ProviderDescriptor descriptor_;
    std::unique_ptr<Carrier> carrier_;
};

// A front door owns public ingress and returns only admitted, ready carriers.
// Ordinary cover requests and failed admission remain entirely inside the
// provider; the engine never receives an unauthenticated YUME-shaped failure.
// The front door may retain shared provider-internal HTTP/2 connection state;
// AcceptedCarrier gives the session exclusive ownership of the promoted
// carrier stream without exposing that state through the engine API.
class FrontDoor {
public:
    using AcceptCompletion =
        std::function<void(Result<AcceptedCarrier>)>;

    virtual ~FrontDoor() = default;
    virtual ExecutorAffinity executor_affinity() const noexcept = 0;
    virtual void async_accept(CancellationToken cancellation,
                              AcceptCompletion completion) = 0;
    virtual void cancel() noexcept = 0;
    virtual void close() noexcept = 0;
};

class FrontDoorProvider {
public:
    using Completion =
        std::function<void(Result<std::unique_ptr<FrontDoor>>)>;

    virtual ~FrontDoorProvider() = default;
    virtual const ProviderDescriptor& descriptor() const noexcept = 0;
    virtual void async_create(EndpointRole local_role,
                              CancellationToken cancellation,
                              Completion completion) = 0;
};

}  // namespace yume::engine
