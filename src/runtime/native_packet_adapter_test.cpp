/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/native_packet_adapter.hpp"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <utility>
#include <vector>

#include <boost/asio/post.hpp>

#include "test_support/allocation_failure.hpp"

namespace {
using namespace yume::engine;
using yume::runtime::NativePacketAdapter;
using yume::providers::AsioExecutionContext;
using Bytes = std::vector<std::byte>;

#define CHECK(value) do { if (!(value)) throw std::runtime_error("check failed: " #value); } while (false)
template <typename T> T require(Result<T> result) {
    CHECK(result.ok());
    return std::move(result).take_value();
}
Buffer buffer(const Bytes& bytes) { return require(Buffer::copy_from(bytes, 1500U)); }

Bytes packet(std::string_view source, std::string_view destination) {
    const auto parse = [](std::string_view text) {
        const auto value = yume::common::parse_canonical_ip_interface(std::string(text) +
            (text.find(':') == std::string_view::npos ? "/32" : "/128"));
        CHECK(value);
        return *value;
    };
    const auto src = parse(source);
    const auto dst = parse(destination);
    CHECK(src.family == dst.family);
    const bool ipv4 = src.family == yume::common::IpFamily::V4;
    Bytes bytes(ipv4 ? 60U : 80U, std::byte{0});
    bytes[0] = ipv4 ? std::byte{0x45} : std::byte{0x60};
    bytes[ipv4 ? 3U : 5U] = std::byte(ipv4 ? 60U : 40U);
    bytes[ipv4 ? 9U : 6U] = std::byte{17U};
    bytes[ipv4 ? 8U : 7U] = std::byte{64U};
    for (std::size_t i = 0; i < (ipv4 ? 4U : 16U); ++i) {
        bytes[(ipv4 ? 12U : 8U) + i] = std::byte(src.address[i]);
        bytes[(ipv4 ? 16U : 24U) + i] = std::byte(dst.address[i]);
    }
    return bytes;
}

class Device final : public PacketChannel {
public:
    ExecutorAffinity executor_affinity() const noexcept override { return ExecutorAffinity(1U); }
    std::size_t max_packet_size() const noexcept override { return 1500U; }
    void async_receive(CancellationToken, ReceiveCompletion completion) override {
        CHECK(!closed && !read);
        read = std::move(completion);
        ++reads;
    }
    void async_send(Buffer bytes, CancellationToken, SendCompletion completion) override {
        CHECK(!closed && !write);
        writes.emplace_back(bytes.bytes().begin(), bytes.bytes().end());
        write = std::move(completion);
    }
    // Cancellation is deliberately deferred. A second session must remain
    // refused until BOTH OS operation callbacks have actually run.
    void cancel() noexcept override { ++cancels; }
    void close() noexcept override { closed = true; }
    void deliver(const Bytes& bytes) {
        CHECK(read);
        auto completion = std::exchange(read, {});
        completion(Result<Buffer>(buffer(bytes)));
    }
    void finish_read(StatusCode code = StatusCode::Cancelled) {
        auto completion = std::exchange(read, {});
        if (completion) completion(Result<Buffer>(Status(code)));
    }
    void finish_write(StatusCode code = StatusCode::Ok) {
        auto completion = std::exchange(write, {});
        if (completion) completion(Status(code), code == StatusCode::Ok ? writes.back().size() : 0U);
    }
    void drain() { finish_read(); finish_write(StatusCode::Cancelled); }
    ReceiveCompletion read;
    SendCompletion write;
    std::vector<Bytes> writes;
    std::size_t reads{0U};
    std::size_t cancels{0U};
    bool closed{false};
};

class Stream final : public StreamResponder {
public:
    ExecutorAffinity executor_affinity() const noexcept override { return ExecutorAffinity(1U); }
    ServiceKind service_kind() const noexcept override { return ServiceKind::PacketChannel; }
    std::size_t max_write_size() const noexcept override { return 1500U; }
    bool terminated() const noexcept override { return closed; }
    void async_read(CancellationToken, ReadCompletion completion) override {
        CHECK(!read);
        if (closed) completion(Result<ReceivedRecord>(Status(StatusCode::Closed)));
        else read = std::move(completion);
    }
    void async_write(Buffer bytes, CancellationToken, WriteCompletion completion) override {
        CHECK(!write);
        if (closed) { completion(Status(StatusCode::Closed), 0U); return; }
        writes.emplace_back(bytes.bytes().begin(), bytes.bytes().end());
        write = std::move(completion);
    }
    Status shutdown_write() noexcept override { return Status(StatusCode::FailedPrecondition); }
    void close(Status reason) noexcept override {
        if (std::exchange(closed, true)) return;
        code = reason.code();
        auto r = std::exchange(read, {});
        auto w = std::exchange(write, {});
        if (r) r(Result<ReceivedRecord>(Status(code)));
        if (w) w(Status(code), 0U);
    }
    void deliver(const Bytes& bytes) {
        CHECK(read);
        auto completion = std::exchange(read, {});
        completion(Result<ReceivedRecord>(ReceivedRecord(buffer(bytes),
            CarrierCredit(bytes.size(), [this](std::size_t size) { released += size; }))));
    }
    void finish_write() {
        CHECK(write);
        auto completion = std::exchange(write, {});
        completion(Status::success(), writes.back().size());
    }
    ReadCompletion read;
    WriteCompletion write;
    std::vector<Bytes> writes;
    std::size_t released{0U};
    StatusCode code{StatusCode::Ok};
    bool closed{false};
};

yume::config::v1::PacketAdapter settings(bool unrestricted = false) {
    yume::config::v1::TunNetwork network;
    for (const auto name : unrestricted ? std::vector{"0.0.0.0/0", "::/0"}
                                        : std::vector{"10.71.0.1/32", "fd71::1/128"})
        network.local_networks.push_back(*yume::common::parse_canonical_ip_network(name));
    for (const auto name : unrestricted ? std::vector{"0.0.0.0/0", "::/0"}
                                        : std::vector{"10.71.0.2/32", "fd71::2/128"})
        network.peer_networks.push_back(*yume::common::parse_canonical_ip_network(name));
    return yume::config::v1::PacketAdapter("ip", "testtun0", 1500U, std::move(network));
}

StreamOpenContext open_context(bool destination = false, std::string name = "ip") {
    auto peer = require(PeerEvidence::create(EndpointRole::Client, "peer", "test",
                                            {std::byte{1}}));
    std::optional<RouteDestination> route;
    if (destination) route.emplace(require(RouteDestination::ipv4(NetworkProtocol::Udp,
                                                                 {10, 71, 0, 1}, 53U)));
    return require(StreamOpenContext::create(require(StreamId::application(1U, EndpointRole::Client)),
        std::move(name), ServiceKind::PacketChannel, std::move(peer), std::move(route)));
}

struct Fixture final {
    Fixture(const std::shared_ptr<AsioExecutionContext>& context, bool unrestricted = false)
        : adapter(require(NativePacketAdapter::create(context, settings(unrestricted)))) {
        CHECK(adapter->start(device, [this] {
            ++cleanups;
            cleanup_before_close = !device->closed && !device->read && !device->write;
        }).ok());
    }
    ~Fixture() {
        adapter->close();
        device->drain();
    }
    std::shared_ptr<Device> device = std::make_shared<Device>();
    std::shared_ptr<NativePacketAdapter> adapter;
    std::size_t cleanups{0U};
    bool cleanup_before_close{false};
};

void authorization(const std::shared_ptr<AsioExecutionContext>& context) {
    auto unstarted = require(NativePacketAdapter::create(context, settings()));
    CHECK(unstarted->authorize(open_context()).code() == StatusCode::Closed);
    Fixture test(context);
    CHECK(test.adapter->authorize(open_context()).ok());
    CHECK(test.adapter->authorize(open_context(true)).code() == StatusCode::PermissionDenied);
    CHECK(test.adapter->authorize(open_context(false, "other")).code() == StatusCode::PermissionDenied);
    auto stream = std::make_shared<Stream>();
    std::size_t accepted = 0U;
    test.adapter->async_open(open_context(), stream, [&](Status status) { CHECK(status.ok()); ++accepted; });
    CHECK(accepted == 1U && test.device->reads == 1U);
    auto second = std::make_shared<Stream>();
    CHECK(test.adapter->attach(second).code() == StatusCode::ResourceExhausted);
    CHECK(!second->closed && test.device->reads == 1U);
    stream->close(Status(StatusCode::Closed));
    CHECK(test.adapter->attach(second).code() == StatusCode::ResourceExhausted);
    test.device->drain();
    CHECK(test.adapter->attach(second).ok());
    second->close(Status(StatusCode::Closed));
}

void roundtrip(const std::shared_ptr<AsioExecutionContext>& context) {
    Fixture test(context);
    auto stream = std::make_shared<Stream>();
    CHECK(test.adapter->attach(stream).ok());
    for (const auto& addresses : {std::pair{"10.71.0.1", "10.71.0.2"}, std::pair{"fd71::1", "fd71::2"}}) {
        const auto outgoing = packet(addresses.first, addresses.second);
        test.device->deliver(outgoing);
        CHECK(stream->writes.back() == outgoing);
        CHECK(!test.device->read); // One packet retained while transport write is pending.
        stream->finish_write();
        CHECK(test.device->read);
        const auto incoming = packet(addresses.second, addresses.first);
        const auto credited = stream->released;
        stream->deliver(incoming);
        CHECK(test.device->writes.back() == incoming && stream->released == credited);
        test.device->finish_write();
        CHECK(stream->released == credited + incoming.size());
    }
    stream->close(Status(StatusCode::Closed));
}

void drained_reconnect(const std::shared_ptr<AsioExecutionContext>& context) {
    Fixture test(context);
    auto old = std::make_shared<Stream>();
    std::size_t ended = 0U;
    CHECK(test.adapter->attach(old, [&] { ++ended; }).ok());
    old->deliver(packet("10.71.0.2", "10.71.0.1"));
    old->close(Status(StatusCode::Closed));
    CHECK(ended == 0U && !test.device->closed);
    auto next = std::make_shared<Stream>();
    test.device->finish_read();
    CHECK(test.adapter->attach(next).code() == StatusCode::ResourceExhausted);
    CHECK(ended == 0U);
    test.device->finish_write(StatusCode::Cancelled);
    CHECK(ended == 1U && test.adapter->attach(next).ok());
    const auto cancels = test.device->cancels;
    old.reset(); // Old wrapper destruction must not cancel the new device read.
    CHECK(test.device->cancels == cancels && test.device->read && !test.device->closed);
    test.device->deliver(packet("10.71.0.1", "10.71.0.2"));
    CHECK(next->writes.size() == 1U);
    next->close(Status(StatusCode::Closed));
}

void policy(const std::shared_ptr<AsioExecutionContext>& context) {
    for (const auto& addresses : {std::pair{"10.71.0.3", "10.71.0.2"},
                                  std::pair{"10.71.0.1", "10.71.0.3"},
                                  std::pair{"fd71::3", "fd71::2"},
                                  std::pair{"fd71::1", "fd71::3"}}) {
        for (const bool outgoing : {false, true}) {
            Fixture test(context);
            auto stream = std::make_shared<Stream>();
            CHECK(test.adapter->attach(stream).ok());
            if (outgoing) test.device->deliver(packet(addresses.first, addresses.second));
            else stream->deliver(packet(addresses.second, addresses.first));
            CHECK(stream->closed && stream->code == StatusCode::PermissionDenied);
            CHECK(test.device->writes.empty() && stream->writes.empty());
        }
    }
    for (const auto forbidden : {"0.0.0.1", "127.0.0.1", "224.0.0.1", "255.255.255.255",
                                  "::", "::1", "ff02::1", "::ffff:a47:2"}) {
        const bool ipv6 = std::string_view(forbidden).find(':') != std::string_view::npos;
        const char* allowed = ipv6 ? "fd71::1" : "10.71.0.1";
        for (const bool outgoing : {false, true}) {
            for (const bool source : {false, true}) {
                Fixture test(context, true);
                auto stream = std::make_shared<Stream>();
                CHECK(test.adapter->attach(stream).ok());
                const auto bytes = packet(source ? forbidden : allowed, source ? allowed : forbidden);
                if (outgoing) test.device->deliver(bytes);
                else stream->deliver(bytes);
                CHECK(stream->closed && stream->code == StatusCode::PermissionDenied);
                CHECK(test.device->writes.empty() && stream->writes.empty());
            }
        }
    }
}

void final_cleanup(const std::shared_ptr<AsioExecutionContext>& context) {
    Fixture test(context);
    auto stream = std::make_shared<Stream>();
    CHECK(test.adapter->attach(stream).ok());
    stream->deliver(packet("10.71.0.2", "10.71.0.1"));
    test.adapter->close();
    CHECK(test.cleanups == 0U && !test.device->closed);
    test.device->finish_read();
    CHECK(test.cleanups == 0U && !test.device->closed);
    test.device->finish_write(StatusCode::Cancelled);
    CHECK(test.cleanups == 1U && test.cleanup_before_close && test.device->closed);
    CHECK(stream->closed);
    test.adapter->close();
    CHECK(test.cleanups == 1U);
}

void callback_reentry(const std::shared_ptr<AsioExecutionContext>& context) {
    Fixture test(context);
    auto old = std::make_shared<Stream>();
    auto next = std::make_shared<Stream>();
    bool attached = false;
    CHECK(test.adapter->attach(old, [&] {
        attached = test.adapter->attach(next).ok();
        throw std::runtime_error("contained ended callback");
    }).ok());
    old->close(Status(StatusCode::Closed));
    test.device->finish_read();
    CHECK(attached && test.device->read && !next->closed);
    test.device->deliver(packet("fd71::1", "fd71::2"));
    CHECK(next->writes.size() == 1U);
    next->close(Status(StatusCode::Closed));

    auto adapter = require(NativePacketAdapter::create(context, settings()));
    auto device = std::make_shared<Device>();
    CHECK(adapter->start(device, [] { throw std::runtime_error("contained cleanup callback"); }).ok());
    adapter->close();
    CHECK(device->closed);
}

void allocation_failures(const std::shared_ptr<AsioExecutionContext>& context) {
    bool exhausted = false;
    for (std::size_t nth = 1U; nth <= 64U; ++nth) {
        Fixture test(context);
        auto stream = std::make_shared<Stream>();
        yume::test::arm_allocation_failure(nth);
        auto status = test.adapter->attach(stream);
        const bool fired = yume::test::disarm_allocation_failure();
        stream->close(Status(StatusCode::Closed));
        test.device->drain();
        auto next = std::make_shared<Stream>();
        CHECK(!test.device->closed && test.adapter->attach(next).ok());
        next->close(Status(StatusCode::Closed));
        test.device->drain();
        if (!fired) { CHECK(status.ok()); exhausted = true; break; }
    }
    CHECK(exhausted);
    Fixture test(context);
    auto stream = std::make_shared<Stream>();
    CHECK(test.adapter->attach(stream).ok());
    yume::test::fail_allocations.store(true);
    test.adapter->close();
    test.device->drain();
    yume::test::fail_allocations.store(false);
    CHECK(test.cleanups == 1U && test.cleanup_before_close && test.device->closed);
}
}  // namespace

int main() {
    try {
        auto context = require(AsioExecutionContext::create(ExecutorAffinity(1U)));
        boost::asio::post(context->executor(), [context] {
            authorization(context);
            roundtrip(context);
            drained_reconnect(context);
            policy(context);
            final_cleanup(context);
            callback_reentry(context);
            allocation_failures(context);
            context->finish();
        });
        context->run();
        std::cout << "native packet adapter: authorization, IPv4/IPv6 policy, flow control, reconnect, drain and allocation failures passed\n";
        return 0;
    } catch (const std::exception& error) {
        yume::test::fail_allocations.store(false);
        yume::test::disarm_allocation_failure();
        std::cerr << error.what() << '\n';
        return 1;
    }
}
