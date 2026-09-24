/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include <algorithm>
#include <cstddef>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

#include "providers/direct_route_handler.hpp"
#include "providers/ip_packet_channel.hpp"
#include "test_support/allocation_failure.hpp"

namespace {

using namespace yume::engine;
using namespace yume::providers;
using yume::common::IpPacketVersion;
using Bytes = std::vector<std::byte>;

#define CHECK(expression)                                                     \
    do {                                                                      \
        if (!(expression)) throw std::runtime_error("check failed: " #expression); \
    } while (false)

template <typename T>
T require(Result<T> result) {
    CHECK(result.ok());
    return std::move(result).take_value();
}

Buffer buffer(const Bytes& bytes) {
    return require(Buffer::copy_from(bytes, kAbsoluteMaxBufferBytes));
}

Bytes ipv4(std::size_t size = 84U) {
    Bytes packet(size, std::byte{0x5a});
    packet[0] = std::byte{0x45};
    packet[2] = static_cast<std::byte>(size >> 8U);
    packet[3] = static_cast<std::byte>(size & 255U);
    packet[6] = packet[7] = std::byte{0};
    packet[8] = std::byte{64};
    packet[9] = std::byte{17};
    packet[12] = std::byte{10};
    packet[13] = std::byte{0};
    packet[14] = std::byte{0};
    packet[15] = std::byte{2};
    packet[16] = std::byte{10};
    packet[17] = std::byte{0};
    packet[18] = std::byte{0};
    packet[19] = std::byte{1};
    return packet;
}

Bytes ipv6(std::size_t size = 104U) {
    Bytes packet(size, std::byte{0x3c});
    packet[0] = std::byte{0x60};
    packet[4] = static_cast<std::byte>((size - 40U) >> 8U);
    packet[5] = static_cast<std::byte>((size - 40U) & 255U);
    packet[6] = std::byte{17};
    packet[7] = std::byte{64};
    return packet;
}

Bytes ipv4_options(std::initializer_list<unsigned> options) {
    CHECK(options.size() <= 40U && options.size() % 4U == 0U);
    auto packet = ipv4(20U + options.size() + 16U);
    packet[0] = static_cast<std::byte>(0x45U + options.size() / 4U);
    std::transform(options.begin(), options.end(), packet.begin() + 20U,
        [](unsigned value) { return static_cast<std::byte>(value); });
    return packet;
}

Bytes ipv6_headers(std::initializer_list<std::pair<unsigned, Bytes>> headers,
                   unsigned upper_layer = 17U, std::size_t payload_size = 16U) {
    std::size_t size = 40U + payload_size;
    for (const auto& header : headers) size += header.second.size();
    auto packet = ipv6(size);
    std::size_t next_offset = 6U;
    std::size_t offset = 40U;
    for (const auto& [type, bytes] : headers) {
        CHECK(!bytes.empty());
        packet[next_offset] = static_cast<std::byte>(type);
        std::copy(bytes.begin(), bytes.end(), packet.begin() + offset);
        next_offset = offset;
        offset += bytes.size();
    }
    packet[next_offset] = static_cast<std::byte>(upper_layer);
    return packet;
}

Bytes fragment_header(unsigned offset_and_flags) {
    Bytes header(8U, std::byte{0});
    header[2] = static_cast<std::byte>(offset_and_flags >> 8U);
    header[3] = static_cast<std::byte>(offset_and_flags & 255U);
    return header;
}

struct DeviceState final {
    PacketChannel::ReceiveCompletion receive;
    PacketChannel::SendCompletion send;
    std::vector<Bytes> writes;
    bool closed{false};
    std::size_t destructions{0U};
    std::size_t receives{0U};

    void deliver(const Bytes& packet) {
        CHECK(receive);
        auto completion = std::exchange(receive, {});
        completion(Result<Buffer>(buffer(packet)));
    }
    void complete_send(std::optional<std::size_t> size = std::nullopt) {
        CHECK(send);
        auto completion = std::exchange(send, {});
        completion(Status::success(), size.value_or(writes.back().size()));
    }
    void settle(StatusCode code) noexcept {
        auto read = std::exchange(receive, {});
        auto write = std::exchange(send, {});
        if (read) read(Result<Buffer>(Status(code)));
        if (write) write(Status(code), 0U);
    }
};

class Device final : public PacketChannel {
public:
    explicit Device(std::shared_ptr<DeviceState> state, std::size_t bound = 1500U)
        : state_(std::move(state)), bound_(bound) {}
    ~Device() noexcept override { ++state_->destructions; }
    ExecutorAffinity executor_affinity() const noexcept override {
        return ExecutorAffinity(1U);
    }
    std::size_t max_packet_size() const noexcept override { return bound_; }
    void async_receive(CancellationToken token, ReceiveCompletion completion) override {
        CHECK(!state_->receive);
        ++state_->receives;
        if (state_->closed || token.is_cancelled()) {
            completion(Result<Buffer>(Status(state_->closed ? StatusCode::Closed
                                                         : StatusCode::Cancelled)));
        } else {
            state_->receive = std::move(completion);
        }
    }
    void async_send(Buffer packet, CancellationToken token,
                    SendCompletion completion) override {
        CHECK(!state_->send);
        if (state_->closed || token.is_cancelled()) {
            completion(Status(state_->closed ? StatusCode::Closed : StatusCode::Cancelled), 0U);
        } else {
            state_->writes.emplace_back(packet.bytes().begin(), packet.bytes().end());
            state_->send = std::move(completion);
        }
    }
    void cancel() noexcept override { state_->settle(StatusCode::Cancelled); }
    void close() noexcept override {
        if (std::exchange(state_->closed, true)) return;
        state_->settle(StatusCode::Closed);
    }

private:
    std::shared_ptr<DeviceState> state_;
    const std::size_t bound_;
};

class Stream final : public StreamResponder {
public:
    ExecutorAffinity executor_affinity() const noexcept override { return ExecutorAffinity(1U); }
    ServiceKind service_kind() const noexcept override { return ServiceKind::PacketChannel; }
    std::size_t max_write_size() const noexcept override { return 1500U; }
    bool terminated() const noexcept override { return closed; }
    void async_read(CancellationToken, ReadCompletion completion) override {
        CHECK(!read);
        ++reads;
        read = std::move(completion);
    }
    void async_write(Buffer packet, CancellationToken, WriteCompletion completion) override {
        CHECK(!write);
        writes.emplace_back(packet.bytes().begin(), packet.bytes().end());
        write = std::move(completion);
    }
    Status shutdown_write() noexcept override { return Status(StatusCode::FailedPrecondition); }
    void close(Status status) noexcept override {
        if (std::exchange(closed, true)) return;
        close_code = status.code();
        auto pending_read = std::exchange(read, {});
        auto pending_write = std::exchange(write, {});
        if (pending_read) pending_read(Result<ReceivedRecord>(Status(close_code)));
        if (pending_write) pending_write(Status(close_code), 0U);
    }
    void deliver(const Bytes& packet, std::size_t& released) {
        CHECK(read);
        auto completion = std::exchange(read, {});
        completion(Result<ReceivedRecord>(ReceivedRecord(buffer(packet),
            CarrierCredit(packet.size(), [&released](std::size_t bytes) { released += bytes; }))));
    }
    void complete_write() {
        CHECK(write);
        auto completion = std::exchange(write, {});
        completion(Status::success(), writes.back().size());
    }

    ReadCompletion read;
    WriteCompletion write;
    std::vector<Bytes> writes;
    std::size_t reads{0U};
    bool closed{false};
    StatusCode close_code{StatusCode::Ok};
};

IpPacketChannel::AuthorizationPolicy allow_packets() {
    return [](IpPacketDirection, const yume::common::IpPacketInfo&) { return Status::success(); };
}

std::unique_ptr<IpPacketChannel> make_channel(
    const std::shared_ptr<DeviceState>& device,
    IpPacketChannel::AuthorizationPolicy policy = allow_packets()) {
    return require(IpPacketChannel::create(std::make_unique<Device>(device), 1500U, std::move(policy)));
}

void inspect_headers() {
    using yume::common::inspect_ip_packet;
    for (const auto& packet : {ipv4(), ipv6()}) {
        const auto info = inspect_ip_packet(packet);
        CHECK(info && info->packet_size == packet.size());
        const auto source_offset = info->version == IpPacketVersion::Ipv4 ? 12U : 8U;
        const auto address_size = info->version == IpPacketVersion::Ipv4 ? 4U : 16U;
        CHECK(std::equal(info->source.begin(), info->source.begin() + address_size,
                         packet.begin() + source_offset));
        const auto destination_offset = info->version == IpPacketVersion::Ipv4 ? 16U : 24U;
        CHECK(std::equal(info->destination.begin(), info->destination.begin() + address_size,
                         packet.begin() + destination_offset));
        for (std::size_t length = 0U; length < packet.size(); ++length) {
            CHECK(!inspect_ip_packet(std::span(packet).first(length)));
        }
        auto padded = packet;
        padded.push_back(std::byte{1});
        CHECK(inspect_ip_packet(padded)->packet_size == packet.size());
    }
    auto options = ipv4(24U);
    options[0] = std::byte{0x46};
    CHECK(inspect_ip_packet(options)->header_size == 24U);
    options[0] = std::byte{0x4f};
    CHECK(!inspect_ip_packet(options));
    options[0] = std::byte{0x44};
    CHECK(!inspect_ip_packet(options));
    CHECK(inspect_ip_packet(ipv4(65535U))->packet_size == 65535U);
    CHECK(inspect_ip_packet(ipv6(40U))->packet_size == 40U);
    options[0] = std::byte{0x70};
    CHECK(!inspect_ip_packet(options));
}

void creation_and_cleanup() {
    for (const auto mtu : {0U, 575U, 1501U, 65536U}) {
        auto state = std::make_shared<DeviceState>();
        const auto result = IpPacketChannel::create(std::make_unique<Device>(state), mtu, allow_packets());
        CHECK(!result.ok() && result.status().code() == StatusCode::InvalidArgument);
        CHECK(state->closed && state->destructions == 1U);
    }
    auto state = std::make_shared<DeviceState>();
    CHECK(!IpPacketChannel::create(std::make_unique<Device>(state), 1500U, {}).ok());
    CHECK(state->closed && state->destructions == 1U);
    CHECK(!IpPacketChannel::create({}, 1500U, allow_packets()).ok());
    for (std::size_t failure = 1U; failure <= 2U; ++failure) {
        state = std::make_shared<DeviceState>();
        auto device = std::make_unique<Device>(state);
        auto policy = allow_packets();
        yume::test::arm_allocation_failure(failure);
        auto result = IpPacketChannel::create(std::move(device), 1500U, std::move(policy));
        const bool fired = yume::test::disarm_allocation_failure();
        CHECK(fired && !result.ok() && result.status().code() == StatusCode::ResourceExhausted);
        CHECK(state->closed && state->destructions == 1U);
    }
    state = std::make_shared<DeviceState>();
    auto channel = make_channel(state);
    CHECK(channel->max_packet_size() == 1500U && channel->executor_affinity() == ExecutorAffinity(1U));
    std::size_t completions = 0U;
    StatusCode code = StatusCode::Ok;
    channel->async_receive({}, [&](Result<Buffer> result) { ++completions; code = result.status().code(); });
    channel.reset();
    CHECK(completions == 1U && code == StatusCode::Closed);
    CHECK(state->closed && state->destructions == 1U);
}

void rejects_invalid_packets() {
    auto trailing = ipv4();
    trailing.push_back(std::byte{0});
    auto trailing_v6 = ipv6();
    trailing_v6.push_back(std::byte{0});
    auto truncated = ipv4();
    truncated.pop_back();
    for (const auto& packet : {Bytes{}, trailing, trailing_v6, truncated, ipv4(1501U)}) {
        auto state = std::make_shared<DeviceState>();
        std::size_t policies = 0U;
        auto channel = make_channel(state, [&](IpPacketDirection, const yume::common::IpPacketInfo&) {
            ++policies;
            return Status::success();
        });
        std::size_t completions = 0U;
        StatusCode code = StatusCode::Ok;
        std::size_t sent = 1U;
        channel->async_send(buffer(packet), {}, [&](Status status, std::size_t size) {
            ++completions; code = status.code(); sent = size;
        });
        const auto expected = packet.size() > 1500U ? StatusCode::ResourceExhausted : StatusCode::InvalidArgument;
        CHECK(completions == 1U && code == expected && sent == 0U && state->writes.empty());
        channel->async_receive({}, [&](Result<Buffer> result) { ++completions; code = result.status().code(); });
        state->deliver(packet);
        CHECK(completions == 2U && code == expected && policies == 0U);
    }
}

void refuses_address_policy_bypasses() {
    const Bytes padding(8U, std::byte{0});
    Bytes home(24U, std::byte{0});
    home[1] = std::byte{2}; // Destination Options length: 24 bytes.
    home[2] = std::byte{201}; home[3] = std::byte{16};
    home[4] = std::byte{0x20}; home[5] = std::byte{1};
    home[6] = std::byte{0x0d}; home[7] = std::byte{0xb8}; home[19] = std::byte{99};
    Bytes authentication(16U, std::byte{0}); authentication[1] = std::byte{2};
    std::vector<Bytes> refused{
        // Both base addresses are permitted by the fixture policy, while the
        // route option requests forwarding to the unlisted 203.0.113.99.
        ipv4_options({131U, 7U, 4U, 203U, 0U, 113U, 99U, 0U}),
        ipv4_options({137U, 7U, 4U, 203U, 0U, 113U, 99U, 0U}),
        ipv4_options({1U, 131U, 7U, 4U, 203U, 0U, 113U, 99U}),
        ipv4_options({0U, 131U, 2U, 0U}), // Source route hidden after EOL.
        ipv4_options({1U, 7U, 1U, 0U}), // Invalid option length.
        ipv4_options({1U, 1U, 1U, 7U}), // Missing option length.
        ipv4_options({7U, 5U, 0U, 0U}), // Option overruns IHL.
        ipv6_headers({{60U, home}}),
        ipv6_headers({{0U, home}}), // Reject Home Address in either TLV header.
        ipv6_headers({{0U, padding}, {51U, authentication}, {60U, home}}),
        ipv6_headers({{44U, fragment_header(0U)}, {60U, home}}),
        ipv6_headers({{44U, fragment_header(8U)}}, 60U), // Hidden fragmented options.
        ipv6_headers({{44U, fragment_header(1U)}}, 60U),
        ipv6_headers({{60U, padding}, {0U, padding}}), // Hop-by-Hop is not first.
        ipv6_headers({{44U, fragment_header(0U)}, {44U, fragment_header(0U)}}),
        ipv6_headers({{60U, padding}, {60U, padding}, {60U, padding}}),
        ipv6_headers({{51U, authentication}, {51U, authentication}}),
        ipv6_headers({{44U, fragment_header(2U)}}), // Fragment reserved bit.
        ipv6_headers({{44U, fragment_header(1U)}}, 17U, 15U),
        ipv6_headers({{44U, fragment_header(8U)}}, 17U, 0U),
        ipv6_headers({}, 0U, 0U), // Missing extension header.
    };
    for (const unsigned routing_type : {0U, 2U, 3U, 4U}) {
        Bytes routing(24U, std::byte{0});
        routing[1] = std::byte{2}; routing[2] = static_cast<std::byte>(routing_type);
        routing[3] = std::byte{1}; // The next hop can replace the base destination.
        routing[8] = std::byte{0x20}; routing[9] = std::byte{1}; routing[23] = std::byte{99};
        refused.push_back(ipv6_headers({{43U, routing}}));
        refused.push_back(ipv6_headers({{0U, padding}, {43U, routing}}));
    }
    for (const unsigned opaque : {50U, 135U, 139U, 140U, 253U, 254U})
        refused.push_back(ipv6_headers({}, opaque));
    for (const auto& malformed : {Bytes{std::byte{17}, std::byte{255}, std::byte{0}, std::byte{0},
                                        std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}},
            Bytes{std::byte{17}, std::byte{0}, std::byte{42}, std::byte{255},
                  std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}},
            Bytes{std::byte{17}, std::byte{0}, std::byte{1}, std::byte{4},
                  std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1}},
            Bytes{std::byte{17}, std::byte{0}, std::byte{0}, std::byte{0},
                  std::byte{0}, std::byte{0}, std::byte{0}, std::byte{42}}}) {
        refused.push_back(ipv6_headers({{60U, malformed}}));
    }
    auto reserved_fragment = fragment_header(0U); reserved_fragment[1] = std::byte{1};
    refused.push_back(ipv6_headers({{44U, reserved_fragment}}));
    auto short_authentication = authentication; short_authentication[1] = std::byte{0};
    refused.push_back(ipv6_headers({{51U, short_authentication}}));
    auto reserved_authentication = authentication; reserved_authentication[2] = std::byte{1};
    refused.push_back(ipv6_headers({{51U, reserved_authentication}}));
    auto jumbo = padding; jumbo[2] = std::byte{194}; jumbo[3] = std::byte{4};
    refused.push_back(ipv6_headers({{0U, jumbo}}));

    for (const auto& packet : refused) {
        // Keep the reference runtime's structural reader contract intact.
        CHECK(yume::common::inspect_ip_packet(packet));
        CHECK(!yume::common::inspect_ip_packet_for_address_policy(packet));
        auto state = std::make_shared<DeviceState>();
        unsigned policies = 0U;
        auto channel = make_channel(state, [&](IpPacketDirection, const yume::common::IpPacketInfo&) {
            ++policies; return Status::success();
        });
        unsigned completions = 0U;
        StatusCode code = StatusCode::Ok;
        std::size_t sent = 1U;
        channel->async_send(buffer(packet), {}, [&](Status status, std::size_t count) {
            ++completions; code = status.code(); sent = count;
        });
        CHECK(completions == 1U && code == StatusCode::InvalidArgument && sent == 0U && state->writes.empty());
        channel->async_receive({}, [&](Result<Buffer> result) {
            ++completions; code = result.status().code();
        });
        state->deliver(packet);
        CHECK(completions == 2U && code == StatusCode::InvalidArgument && policies == 0U);
    }
}

void permits_inspectable_packets() {
    const Bytes padding(8U, std::byte{0});
    Bytes router_alert(8U, std::byte{0}); router_alert[2] = std::byte{5}; router_alert[3] = std::byte{2};
    Bytes authentication(16U, std::byte{0}); authentication[1] = std::byte{2};
    const Bytes opaque_option{std::byte{17}, std::byte{0}, std::byte{42}, std::byte{4},
        std::byte{201}, std::byte{43}, std::byte{131}, std::byte{137}};
    std::vector<Bytes> accepted{
        ipv4_options({0U, 0U, 0U, 0U}), ipv4_options({1U, 1U, 0U, 0U}),
        ipv4_options({7U, 7U, 4U, 0U, 0U, 0U, 0U, 0U}), // Record Route does not rewrite endpoints.
        ipv4_options({148U, 4U, 0U, 0U}), // Router Alert.
        ipv4_options({158U, 4U, 131U, 137U}), // Option data is not another option.
        ipv6_headers({{0U, router_alert}, {60U, padding}}),
        ipv6_headers({{60U, opaque_option}}), // Option data does not name another option.
        ipv6_headers({{0U, padding}, {60U, padding}, {44U, fragment_header(0U)},
                      {51U, authentication}, {60U, padding}}),
        ipv6_headers({}, 59U, 0U), // No Next Header.
    };
    for (const unsigned protocol : {1U, 6U, 17U}) {
        auto packet = ipv4(); packet[9] = static_cast<std::byte>(protocol); accepted.push_back(packet);
        packet[6] = std::byte{0x20}; packet[7] = std::byte{0}; accepted.push_back(packet); // First fragment.
        packet[7] = std::byte{1}; accepted.push_back(packet); // Middle fragment.
        packet[6] = std::byte{0}; accepted.push_back(packet); // Final fragment.
    }
    for (const unsigned protocol : {6U, 17U, 58U}) {
        accepted.push_back(ipv6_headers({}, protocol));
        for (const unsigned fragment : {0U, 1U, 9U, 8U})
            accepted.push_back(ipv6_headers({{0U, padding}, {44U, fragment_header(fragment)}}, protocol));
        accepted.push_back(ipv6_headers({{44U, fragment_header(8U)}}, protocol, 7U));
    }
    for (const auto& packet : accepted) {
        const auto inspected = yume::common::inspect_ip_packet_for_address_policy(packet);
        const auto structural = yume::common::inspect_ip_packet(packet);
        CHECK(inspected && structural && inspected->source == structural->source &&
              inspected->destination == structural->destination && inspected->header_size == structural->header_size);
        auto state = std::make_shared<DeviceState>();
        unsigned policies = 0U;
        auto channel = make_channel(state, [&](IpPacketDirection, const yume::common::IpPacketInfo&) {
            ++policies; return Status::success();
        });
        unsigned completions = 0U;
        channel->async_send(buffer(packet), {}, [&](Status status, std::size_t count) {
            CHECK(status.ok() && count == packet.size()); ++completions;
        });
        CHECK(state->writes.size() == 1U && state->writes.front() == packet); state->complete_send();
        channel->async_receive({}, [&](Result<Buffer> result) {
            CHECK(result.ok() && std::equal(result.value().bytes().begin(), result.value().bytes().end(), packet.begin()));
            ++completions;
        });
        state->deliver(packet);
        CHECK(completions == 2U && policies == 2U);
    }
}

void policy_and_cancellation() {
    for (const bool throws : {false, true}) {
        auto state = std::make_shared<DeviceState>();
        std::vector<IpPacketDirection> directions;
        auto channel = make_channel(state, [&](IpPacketDirection direction, const yume::common::IpPacketInfo& info) {
            directions.push_back(direction);
            if (throws) throw std::runtime_error("policy unavailable");
            return Status(info.source[3] == std::byte{2} ? StatusCode::PermissionDenied : StatusCode::Ok);
        });
        StatusCode code = StatusCode::Ok;
        channel->async_send(buffer(ipv4()), {}, [&](Status status, std::size_t) { code = status.code(); });
        CHECK(code == StatusCode::PermissionDenied && state->writes.empty());
        channel->async_receive({}, [&](Result<Buffer> result) { code = result.status().code(); });
        state->deliver(ipv4());
        CHECK(code == StatusCode::PermissionDenied);
        CHECK((directions == std::vector{IpPacketDirection::FromTunnel, IpPacketDirection::ToTunnel}));
    }
    auto state = std::make_shared<DeviceState>();
    auto channel = make_channel(state);
    CancellationSource cancellation;
    cancellation.cancel();
    StatusCode code = StatusCode::Ok;
    channel->async_receive(cancellation.token(), [&](Result<Buffer> result) { code = result.status().code(); });
    CHECK(code == StatusCode::Cancelled);
    channel->async_send(buffer(ipv4()), cancellation.token(), [&](Status status, std::size_t) { code = status.code(); });
    CHECK(code == StatusCode::Cancelled && state->writes.empty());
    channel->async_receive({}, [&](Result<Buffer> result) { code = result.status().code(); });
    channel->cancel();
    CHECK(code == StatusCode::Cancelled);
    // Exceptions from user completions are contained on every completion path.
    channel->async_send(buffer({}), {}, [](Status, std::size_t) { throw 1; });
    channel->async_receive({}, [](Result<Buffer>) { throw 1; });
    state->deliver(ipv4());
    channel->async_send(buffer(ipv6()), {}, [](Status, std::size_t) { throw 1; });
    state->complete_send();
}

void bridge_preserves_packets_and_credit() {
    auto device = std::make_shared<DeviceState>();
    auto stream = std::make_shared<Stream>();
    auto connection = require(RouteConnection::packet_channel(make_channel(device)));
    bridge_established_route(stream, std::move(connection));
    std::size_t released = 0U;
    for (const auto& packet : {ipv4(), ipv6(), ipv4(1500U)}) {
        const auto before = released;
        const auto stream_reads = stream->reads;
        stream->deliver(packet, released);
        CHECK(device->writes.back() == packet && released == before && stream->reads == stream_reads);
        device->complete_send();
        CHECK(released == before + packet.size() && stream->reads == stream_reads + 1U);
        const auto device_reads = device->receives;
        device->deliver(packet);
        CHECK(stream->writes.back() == packet && device->receives == device_reads);
        stream->complete_write();
        CHECK(device->receives == device_reads + 1U);
    }
    CHECK(!stream->closed && !device->closed);
    stream->close(Status(StatusCode::Closed));
    CHECK(device->closed && device->destructions == 1U);
}

void bridge_failures_close_both_sides() {
    for (const bool from_tunnel : {false, true}) {
        auto device = std::make_shared<DeviceState>();
        auto stream = std::make_shared<Stream>();
        bridge_established_route(stream, require(RouteConnection::packet_channel(make_channel(device))));
        auto packet = ipv4();
        packet.push_back(std::byte{0});
        std::size_t released = 0U;
        if (from_tunnel) stream->deliver(packet, released);
        else device->deliver(packet);
        CHECK(stream->closed && device->closed && stream->close_code == StatusCode::InvalidArgument);
        CHECK(stream->writes.empty() && device->writes.empty());
        CHECK(released == (from_tunnel ? packet.size() : 0U));
        CHECK(device->destructions == 1U);
    }
    auto device = std::make_shared<DeviceState>();
    auto stream = std::make_shared<Stream>();
    bridge_established_route(stream, require(RouteConnection::packet_channel(make_channel(device))));
    std::size_t released = 0U;
    stream->deliver(ipv4(), released);
    device->complete_send(1U);
    CHECK(stream->closed && device->closed && stream->close_code == StatusCode::ProviderMismatch);
    CHECK(released == ipv4().size() && device->destructions == 1U);
}

}  // namespace

int main() {
    try {
        inspect_headers();
        creation_and_cleanup();
        rejects_invalid_packets();
        refuses_address_policy_bypasses();
        permits_inspectable_packets();
        policy_and_cancellation();
        bridge_preserves_packets_and_credit();
        bridge_failures_close_both_sides();
        std::cout << "IP packet channel and native bridge tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
