/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/native_packet_adapter.hpp"

#include <algorithm>
#include <array>
#include <new>
#include <utility>

#include "common/egress_address.hpp"
#include "providers/direct_route_handler.hpp"
#include "providers/ip_packet_channel.hpp"

namespace yume::runtime {
namespace {
using engine::Result;
using engine::Status;
using engine::StatusCode;

template <typename Completion, typename... Args>
void complete(Completion& completion, Args&&... args) noexcept {
    try {
        if (completion) completion(std::forward<Args>(args)...);
    } catch (...) {
    }
}

bool valid_network(const common::IpNetwork& network) noexcept {
    if (network.family != common::IpFamily::V4 && network.family != common::IpFamily::V6)
        return false;
    return network.prefix_length <= (network.family == common::IpFamily::V4 ? 32U : 128U) &&
           common::detail::ip_host_bits_zero(network);
}
}  // namespace

struct NativePacketAdapter::State final : std::enable_shared_from_this<State> {
    struct LeaseState;
    class Lease;

    State(std::shared_ptr<providers::AsioExecutionContext> execution,
          const config::v1::PacketAdapter& settings, engine::ProviderDescriptor provider)
        : context(std::move(execution)), config(settings), descriptor(std::move(provider)) {}

    Status available() const noexcept {
        if (closing || !channel) return Status(StatusCode::Closed);
        if (occupied) return Status(StatusCode::ResourceExhausted);
        return Status::success();
    }

    Status authorize_packet(providers::IpPacketDirection direction,
                            const common::IpPacketInfo& info) const noexcept {
        const auto family = info.version == common::IpPacketVersion::Ipv4
            ? common::IpFamily::V4 : common::IpFamily::V6;
        const auto matches = [family](const auto& networks, const auto& bytes) {
            std::array<std::uint8_t, 16U> address{};
            std::transform(bytes.begin(), bytes.end(), address.begin(),
                           [](std::byte value) { return std::to_integer<std::uint8_t>(value); });
            const std::span<const std::uint8_t> view(address.data(),
                family == common::IpFamily::V4 ? 4U : 16U);
            const auto parsed = common::EgressAddress::from_bytes(family, view);
            if (!parsed || parsed->family() != family ||
                common::classify_egress_address(*parsed) == common::EgressAddressClass::NeverAllowed)
                return false;
            // Kernel loopback identities must not cross a remote TUN, even
            // when a configured /0 would otherwise contain the address.
            if ((family == common::IpFamily::V4 && address[0] == 127U) ||
                (family == common::IpFamily::V6 && address[15] == 1U &&
                 std::all_of(address.begin(), address.begin() + 15U,
                             [](std::uint8_t byte) { return byte == 0U; })))
                return false;
            return std::any_of(networks.begin(), networks.end(), [&](const auto& network) {
                return common::ip_network_contains(network, family, view);
            });
        };
        const auto& network = config.network();
        const bool outgoing = direction == providers::IpPacketDirection::ToTunnel;
        if (!matches(outgoing ? network.local_networks : network.peer_networks, info.source) ||
            !matches(outgoing ? network.peer_networks : network.local_networks, info.destination))
            return Status(StatusCode::PermissionDenied);
        return Status::success();
    }

    void close() noexcept;
    void finish_close() noexcept {
        if (!closing || occupied || finished) return;
        finished = true;
        auto completion = std::move(on_closed);
        complete(completion);
        if (channel) channel->close();
        channel.reset();
    }

    std::shared_ptr<providers::AsioExecutionContext> context;
    const config::v1::PacketAdapter config;
    const engine::ProviderDescriptor descriptor;
    std::shared_ptr<engine::PacketChannel> channel;
    std::weak_ptr<LeaseState> active;
    Closed on_closed;
    bool occupied{false};
    bool closing{false};
    bool finished{false};
};

struct NativePacketAdapter::State::LeaseState final : std::enable_shared_from_this<LeaseState> {
    explicit LeaseState(std::shared_ptr<State> state, Ended completion)
        : owner(std::move(state)), on_ended(std::move(completion)) {}

    void settled() noexcept {
        if (!closed || receiving || sending || released) return;
        released = true;
        owner->occupied = false;
        owner->active.reset();
        auto completion = std::move(on_ended);
        if (!owner->closing) complete(completion);
        owner->finish_close();
    }

    void close() noexcept {
        if (closed) return;
        closed = true;
        // This lease remains occupied through both cancellation completions.
        // An old wrapper's later close/cancel cannot reach a replacement lease.
        owner->channel->cancel();
        settled();
    }

    std::shared_ptr<State> owner;
    Ended on_ended;
    bool receiving{false};
    bool sending{false};
    bool closed{false};
    bool released{false};
};

class NativePacketAdapter::State::Lease final : public engine::PacketChannel {
public:
    explicit Lease(std::shared_ptr<LeaseState> state) noexcept : state_(std::move(state)) {}
    ~Lease() noexcept override { close(); }

    engine::ExecutorAffinity executor_affinity() const noexcept override {
        return state_->owner->context->affinity();
    }
    std::size_t max_packet_size() const noexcept override { return state_->owner->config.mtu(); }

    void async_receive(engine::CancellationToken cancellation, ReceiveCompletion completion) override {
        const auto state = state_;
        state->owner->context->require_context();
        if (!completion) return;
        if (state->closed || state->receiving) {
            complete(completion, Result<engine::Buffer>(Status(state->closed
                ? StatusCode::Closed : StatusCode::ResourceExhausted)));
            return;
        }
        // Build the callback before reserving the slot: allocation failure
        // leaves no accepted operation or pending count to drain.
        ReceiveCompletion wrapped = [state, completion = std::move(completion)](
                                        Result<engine::Buffer> result) mutable noexcept {
            state->receiving = false;
            if (state->closed) result = Result<engine::Buffer>(Status(StatusCode::Closed));
            complete(completion, std::move(result));
            state->settled();
        };
        state->receiving = true;
        try {
            state->owner->channel->async_receive(std::move(cancellation), std::move(wrapped));
        } catch (...) {
            state->receiving = false;
            state->close();
            throw;
        }
    }

    void async_send(engine::Buffer packet, engine::CancellationToken cancellation,
                    SendCompletion completion) override {
        const auto state = state_;
        state->owner->context->require_context();
        if (!completion) return;
        if (state->closed || state->sending) {
            complete(completion, Status(state->closed
                ? StatusCode::Closed : StatusCode::ResourceExhausted), 0U);
            return;
        }
        SendCompletion wrapped = [state, completion = std::move(completion)](
                                     Status result, std::size_t size) mutable noexcept {
            state->sending = false;
            if (state->closed) {
                result = Status(StatusCode::Closed);
                size = 0U;
            }
            complete(completion, std::move(result), size);
            state->settled();
        };
        state->sending = true;
        try {
            state->owner->channel->async_send(std::move(packet), std::move(cancellation),
                                             std::move(wrapped));
        } catch (...) {
            state->sending = false;
            state->close();
            throw;
        }
    }

    void cancel() noexcept override {
        if (!state_->closed) state_->owner->channel->cancel();
    }
    void close() noexcept override { state_->close(); }

private:
    std::shared_ptr<LeaseState> state_;
};

void NativePacketAdapter::State::close() noexcept {
    if (closing) return;
    closing = true;
    if (const auto lease = active.lock()) lease->close();
    finish_close();
}

Result<std::shared_ptr<NativePacketAdapter>> NativePacketAdapter::create(
    std::shared_ptr<providers::AsioExecutionContext> context,
    const config::v1::PacketAdapter& adapter) {
    using Created = Result<std::shared_ptr<NativePacketAdapter>>;
    const auto& network = adapter.network();
    if (!context || adapter.service().empty() || adapter.mtu() < 576U ||
        network.local_networks.empty() || network.peer_networks.empty() ||
        !std::all_of(network.local_networks.begin(), network.local_networks.end(), valid_network) ||
        !std::all_of(network.peer_networks.begin(), network.peer_networks.end(), valid_network))
        return Created(Status(StatusCode::InvalidArgument));
    context->require_context();
    try {
        auto descriptor = engine::ProviderDescriptor::create(
            "yume.native-ip", engine::ProviderKind::StreamHandler, 1U,
            engine::mandatory_capabilities(engine::ProviderKind::StreamHandler)
                .with(engine::Capability::PacketChannels));
        if (!descriptor.ok()) return Created(descriptor.status());
        auto state = std::make_shared<State>(context, adapter, std::move(descriptor).take_value());
        return Created(std::shared_ptr<NativePacketAdapter>(new NativePacketAdapter(std::move(state))));
    } catch (const std::bad_alloc&) {
        return Created(Status(StatusCode::ResourceExhausted));
    }
}

NativePacketAdapter::NativePacketAdapter(std::shared_ptr<State> state) noexcept
    : state_(std::move(state)) {}
NativePacketAdapter::~NativePacketAdapter() noexcept { close(); }

Status NativePacketAdapter::start(std::shared_ptr<engine::PacketChannel> channel, Closed on_closed) {
    state_->context->require_context();
    if (state_->channel || state_->closing) return Status(StatusCode::FailedPrecondition);
    if (!channel || channel->executor_affinity() != state_->context->affinity() ||
        channel->max_packet_size() < state_->config.mtu() || !on_closed)
        return Status(StatusCode::InvalidArgument);
    state_->channel = std::move(channel);
    state_->on_closed = std::move(on_closed);
    return Status::success();
}

Status NativePacketAdapter::attach(std::shared_ptr<engine::StreamResponder> stream, Ended on_ended) {
    const auto state = state_;
    state->context->require_context();
    auto status = state->available();
    if (!status.ok()) return status;
    if (!stream || stream->terminated() || stream->service_kind() != service_kind() ||
        stream->executor_affinity() != state->context->affinity() ||
        stream->max_write_size() < state->config.mtu())
        return Status(StatusCode::InvalidArgument);
    try {
        auto lease_state = std::make_shared<State::LeaseState>(state, std::move(on_ended));
        auto lease = std::make_unique<State::Lease>(lease_state);
        state->occupied = true;
        state->active = lease_state;
        auto channel = providers::IpPacketChannel::create(std::move(lease), state->config.mtu(),
            [state](providers::IpPacketDirection direction, const common::IpPacketInfo& info) {
                return state->authorize_packet(direction, info);
            });
        if (!channel.ok()) return channel.status();
        auto route = engine::RouteConnection::packet_channel(std::move(channel).take_value());
        if (!route.ok()) return route.status();
        providers::bridge_established_route(stream, std::move(route).take_value());
        return stream->terminated() ? Status(StatusCode::Closed) : Status::success();
    } catch (const std::bad_alloc&) {
        return Status(StatusCode::ResourceExhausted);
    } catch (...) {
        return Status(StatusCode::Internal);
    }
}

void NativePacketAdapter::close() noexcept { state_->close(); }
const engine::ProviderDescriptor& NativePacketAdapter::descriptor() const noexcept {
    return state_->descriptor;
}
engine::ServiceKind NativePacketAdapter::service_kind() const noexcept {
    return engine::ServiceKind::PacketChannel;
}
Status NativePacketAdapter::authorize(const engine::StreamOpenContext& context) {
    state_->context->require_context();
    if (context.destination_if() || context.service_name() != state_->config.service() ||
        context.service_kind() != service_kind()) return Status(StatusCode::PermissionDenied);
    return state_->available();
}
void NativePacketAdapter::async_open(engine::StreamOpenContext context,
                                     std::shared_ptr<engine::StreamResponder> stream,
                                     AcceptanceCompletion completion) {
    auto status = authorize(context);
    if (status.ok()) status = attach(stream);
    const auto code = status.code();
    complete(completion, std::move(status));
    if (code != StatusCode::Ok && stream) stream->close(Status(code));
}
void NativePacketAdapter::on_open(engine::StreamOpenContext context,
                                  std::shared_ptr<engine::StreamResponder> stream) {
    async_open(std::move(context), std::move(stream), {});
}

}  // namespace yume::runtime
