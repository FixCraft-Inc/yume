/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/ip_packet_channel.hpp"

#include <new>
#include <utility>

namespace yume::providers {
namespace {

using engine::Status;
using engine::StatusCode;

template <typename Completion, typename... Args>
void complete(Completion& completion, Args&&... args) noexcept {
    try {
        if (completion) completion(std::forward<Args>(args)...);
    } catch (...) {
        // Consumer exceptions cannot escape a provider completion boundary.
    }
}

}  // namespace

struct IpPacketChannel::State final {
    State(std::unique_ptr<engine::PacketChannel> channel_value,
          std::size_t mtu_value, AuthorizationPolicy authorization_value)
        : channel(std::move(channel_value)), mtu(mtu_value),
          authorization(std::move(authorization_value)) {}

    ~State() noexcept { channel->close(); }

    Status validate(IpPacketDirection direction,
                    const engine::Buffer& packet) const noexcept {
        if (packet.size() > mtu) return Status(StatusCode::ResourceExhausted);
        const auto info = common::inspect_ip_packet_for_address_policy(packet.bytes());
        if (!info) {
            return Status(StatusCode::InvalidArgument);
        }
        try {
            return authorization(direction, *info);
        } catch (...) {
            return Status(StatusCode::PermissionDenied);
        }
    }

    std::unique_ptr<engine::PacketChannel> channel;
    const std::size_t mtu;
    const AuthorizationPolicy authorization;
};

engine::Result<std::unique_ptr<IpPacketChannel>> IpPacketChannel::create(
    std::unique_ptr<engine::PacketChannel> channel,
    std::size_t mtu,
    AuthorizationPolicy authorization) {
    using Result = engine::Result<std::unique_ptr<IpPacketChannel>>;
    if (!channel || !channel->executor_affinity().valid() || !authorization ||
        mtu < 576U || mtu > 65535U || mtu > channel->max_packet_size()) {
        if (channel) channel->close();
        return Result(Status(StatusCode::InvalidArgument));
    }
    try {
        auto state = std::make_shared<State>(
            std::move(channel), mtu, std::move(authorization));
        return Result(std::unique_ptr<IpPacketChannel>(
            new IpPacketChannel(std::move(state))));
    } catch (const std::bad_alloc&) {
        if (channel) channel->close();
        return Result(Status(StatusCode::ResourceExhausted));
    }
}

IpPacketChannel::IpPacketChannel(std::shared_ptr<State> state) noexcept
    : state_(std::move(state)) {}

IpPacketChannel::~IpPacketChannel() noexcept { close(); }

engine::ExecutorAffinity IpPacketChannel::executor_affinity() const noexcept {
    return state_->channel->executor_affinity();
}

std::size_t IpPacketChannel::max_packet_size() const noexcept { return state_->mtu; }

void IpPacketChannel::async_receive(engine::CancellationToken cancellation,
                                   ReceiveCompletion completion) {
    if (!completion) return;
    state_->channel->async_receive(std::move(cancellation),
        [state = state_, completion = std::move(completion)](
            engine::Result<engine::Buffer> result) mutable noexcept {
            if (result.ok()) {
                auto status = state->validate(
                    IpPacketDirection::ToTunnel, result.value());
                if (!status.ok()) {
                    complete(completion, engine::Result<engine::Buffer>(std::move(status)));
                    return;
                }
            }
            complete(completion, std::move(result));
        });
}

void IpPacketChannel::async_send(engine::Buffer packet,
                                engine::CancellationToken cancellation,
                                SendCompletion completion) {
    if (!completion) return;
    auto status = state_->validate(IpPacketDirection::FromTunnel, packet);
    if (!status.ok()) {
        complete(completion, std::move(status), 0U);
        return;
    }
    state_->channel->async_send(std::move(packet), std::move(cancellation),
        [state = state_, completion = std::move(completion)](Status result,
                                              std::size_t size) mutable noexcept {
            complete(completion, std::move(result), size);
        });
}

void IpPacketChannel::cancel() noexcept { state_->channel->cancel(); }
void IpPacketChannel::close() noexcept { state_->channel->close(); }

}  // namespace yume::providers
