/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/circuit_host.hpp"

#include <algorithm>
#include <array>
#include <new>
#include <optional>
#include <utility>

#include "common/service_name.hpp"
#include "runtime/native_egress_policy.hpp"

namespace yume::runtime::circuit {
namespace {

using engine::Buffer;
using engine::ByteChannel;
using engine::CancellationSource;
using engine::Result;
using engine::RouteDestination;
using engine::Status;
using engine::StatusCode;
using engine::StreamResponder;

// Writes one view in pieces the stream accepts, then waits for the client
// to end.
class RoutesWriter final : public std::enable_shared_from_this<RoutesWriter> {
public:
    RoutesWriter(std::shared_ptr<StreamResponder> stream,
                 std::shared_ptr<const RoutesView> view) noexcept
        : stream_(std::move(stream)), view_(std::move(view)) {}

    void next() noexcept {
        const std::size_t total = view_->signature.size() + view_->view.size();
        if (offset_ == total) {
            if (!stream_->shutdown_write().ok())
                return stream_->close(Status(StatusCode::Closed));
            return wait_for_end();
        }
        // The signature comes first, so one piece never spans both parts.
        const bool signing = offset_ < view_->signature.size();
        const auto& part = signing ? view_->signature : view_->view;
        const std::size_t at =
            signing ? offset_ : offset_ - view_->signature.size();
        const std::size_t size =
            std::min(part.size() - at,
                     std::max<std::size_t>(1U, stream_->max_write_size()));
        try {
            auto piece =
                Buffer::copy_from(std::span(part).subspan(at, size), size);
            if (!piece.ok())
                return stream_->close(Status(piece.status().code()));
            stream_->async_write(
                std::move(piece).take_value(), cancel_.token(),
                [self = shared_from_this(), size](Status status, std::size_t) {
                    if (!status.ok())
                        return self->stream_->close(std::move(status));
                    self->offset_ += size;
                    self->next();
                });
        } catch (...) {
            stream_->close(Status(StatusCode::ResourceExhausted));
        }
    }

private:
    void wait_for_end() noexcept {
        try {
            stream_->async_read(
                cancel_.token(),
                [self = shared_from_this()](Result<engine::ReceivedRecord>) {
                    // The client's end, anything it sends and any failure all
                    // end the stream.
                    self->stream_->close(Status(StatusCode::Closed));
                });
        } catch (...) {
            stream_->close(Status(StatusCode::ResourceExhausted));
        }
    }

    std::shared_ptr<StreamResponder> stream_;
    std::shared_ptr<const RoutesView> view_;
    CancellationSource cancel_;
    std::size_t offset_{0U};
};

// Circuit 1's BEGIN carries a TCP destination (CIRCUIT_1, "Relay messages").
Result<RouteDestination> route_destination(
    const ytp1::Destination& destination) {
    if (destination.transport != ytp1::TransportProtocol::Tcp)
        return Result<RouteDestination>(Status(StatusCode::InvalidArgument));
    switch (destination.address_kind) {
        case ytp1::AddressKind::Ipv4: {
            std::array<std::uint8_t, 4> address{};
            std::copy_n(destination.address.begin(), address.size(),
                        address.begin());
            return RouteDestination::ipv4(engine::NetworkProtocol::Tcp, address,
                                          destination.port);
        }
        case ytp1::AddressKind::Ipv6:
            return RouteDestination::ipv6(engine::NetworkProtocol::Tcp,
                                          destination.address,
                                          destination.port);
        case ytp1::AddressKind::Dns:
            return RouteDestination::dns_name(engine::NetworkProtocol::Tcp,
                                              destination.dns_name,
                                              destination.port);
        case ytp1::AddressKind::None:
            break;
    }
    return Result<RouteDestination>(Status(StatusCode::InvalidArgument));
}

}  // namespace

RoutesService::RoutesService(engine::ProviderDescriptor descriptor,
                             Current current) noexcept
    : descriptor_(std::move(descriptor)), current_(std::move(current)) {}

Result<std::shared_ptr<RoutesService>> RoutesService::create(Current current) {
    using Created = Result<std::shared_ptr<RoutesService>>;
    if (!current) return Created(Status(StatusCode::InvalidArgument));
    auto descriptor = engine::ProviderDescriptor::create(
        std::string(common::kRoutesServiceName),
        engine::ProviderKind::StreamHandler, 1U,
        engine::mandatory_capabilities(engine::ProviderKind::StreamHandler));
    if (!descriptor.ok()) return Created(descriptor.status());
    return Created(std::shared_ptr<RoutesService>(new RoutesService(
        std::move(descriptor).take_value(), std::move(current))));
}

void RoutesService::on_open(engine::StreamOpenContext,
                            std::shared_ptr<StreamResponder> stream) {
    if (!stream) return;
    const auto view = current_();
    if (!view || view->view.empty() || view->signature.empty()) {
        stream->close(Status(StatusCode::FailedPrecondition));
        return;
    }
    std::make_shared<RoutesWriter>(std::move(stream), view)->next();
}

std::function<void(const engine::StreamOpenContext&, const ytp1::Destination&,
                   engine::CancellationToken, ChannelOpened)>
exit_connector(std::string service,
               std::shared_ptr<const NativeEgressPolicy> egress,
               std::shared_ptr<engine::RouteProvider> provider) {
    return [service = std::move(service), egress = std::move(egress),
            provider = std::move(provider)](
               const engine::StreamOpenContext& carried_by,
               const ytp1::Destination& destination,
               engine::CancellationToken cancellation, ChannelOpened done) {
        const auto fail = [&](StatusCode code) {
            done(Result<std::unique_ptr<ByteChannel>>(Status(code)));
        };
        std::optional<engine::AuthorizedRouteRequest> authorized;
        try {
            auto route = route_destination(destination);
            if (!route.ok()) return fail(route.status().code());
            auto context = engine::StreamOpenContext::create(
                carried_by.stream_id(), service,
                engine::ServiceKind::ByteStream, carried_by.peer_evidence(),
                std::move(route).take_value());
            if (!context.ok()) return fail(context.status().code());
            if (!egress->authorize_request(context.value()).ok())
                return fail(StatusCode::PermissionDenied);
            auto request =
                engine::RouteAuthority::after_policy(context.value());
            if (!request.ok()) return fail(request.status().code());
            authorized.emplace(std::move(request).take_value());
        } catch (const std::bad_alloc&) {
            return fail(StatusCode::ResourceExhausted);
        }
        provider->async_open(
            *authorized, std::move(cancellation),
            [done =
                 std::move(done)](Result<engine::RouteConnection> connected) {
                if (!connected.ok()) {
                    done(Result<std::unique_ptr<ByteChannel>>(
                        connected.status()));
                    return;
                }
                auto channel = connected.value().take_byte_channel();
                done(channel ? Result<std::unique_ptr<ByteChannel>>(
                                   std::move(channel))
                             : Result<std::unique_ptr<ByteChannel>>(
                                   Status(StatusCode::ProviderMismatch)));
            });
    };
}

}  // namespace yume::runtime::circuit
