/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/device_bridge.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <deque>
#include <list>
#include <new>
#include <random>
#include <span>
#include <unordered_map>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

#include <boost/asio/basic_socket_acceptor.hpp>
#include <boost/asio/basic_waitable_timer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/asio/posix/basic_stream_descriptor.hpp>
#include <boost/asio/socket_base.hpp>

#include "common/udp_queue_budget.hpp"
#include "engine/buffer.hpp"
#include "engine/byte_channel.hpp"
#include "engine/cancellation.hpp"
#include "engine/carrier.hpp"
#include "engine/route_provider.hpp"
#include "engine/stream_handler.hpp"
#include "providers/asio_tcp_byte_channel_provider.hpp"
#include "providers/direct_route_handler.hpp"

namespace yume::runtime {
namespace {
using engine::Buffer;
using engine::ByteChannel;
using engine::NetworkProtocol;
using engine::ReceivedRecord;
using engine::Result;
using engine::RouteDestination;
using engine::ServiceKind;
using engine::Status;
using engine::StatusCode;
using engine::StreamResponder;
using Clock = std::chrono::steady_clock;
using Executor = providers::AsioExecutionContext::Executor;
using Timer =
    boost::asio::basic_waitable_timer<Clock, boost::asio::wait_traits<Clock>,
                                      Executor>;
using Device = boost::asio::posix::basic_stream_descriptor<Executor>;
using Acceptor =
    boost::asio::basic_socket_acceptor<boost::asio::ip::tcp, Executor>;
using Error = boost::system::error_code;

// Larger than any IP packet, so a device with a larger MTU than the caller
// named is never read short.
constexpr std::size_t kPacketBytes = 65'536U;
// Packets handled before other work on the runner gets its turn.
constexpr std::size_t kPacketsPerTurn = 64U;
constexpr std::chrono::milliseconds kSweepInterval{5'000};
constexpr std::chrono::milliseconds kAcceptRetry{1'000};
// How soon a connection that found the session's streams exhausted asks
// again, when nothing that could free one has happened meanwhile.
constexpr std::chrono::milliseconds kOpenRetry{200};
constexpr std::uint16_t kDnsPort = 53U;
// A DNS message starts with a 12-byte header whose first two are its
// identifier (RFC 1035, 4.1.1).
constexpr std::size_t kDnsHeaderBytes = 12U;
// Queries of one resolver waiting for their reply, and for how long.
constexpr std::size_t kMaxDnsQueries = 1024U;
constexpr std::chrono::milliseconds kDnsQueryLifetime{10'000};

boost::asio::ip::address to_address(bool ipv6, const DeviceAddress& bytes) {
    if (ipv6) return boost::asio::ip::address_v6(bytes);
    return boost::asio::ip::address_v4(
        std::array<unsigned char, 4>{bytes[0], bytes[1], bytes[2], bytes[3]});
}

Result<RouteDestination> to_destination(NetworkProtocol protocol, bool ipv6,
                                        const DeviceAddress& address,
                                        std::uint16_t port) {
    if (ipv6) return RouteDestination::ipv6(protocol, address, port);
    return RouteDestination::ipv4(
        protocol,
        std::array<std::uint8_t, 4>{address[0], address[1], address[2],
                                    address[3]},
        port);
}

// Ends a local connection the bridge will not carry with a reset, so the
// application sees a failure rather than an orderly close.
void reset(providers::AsioTcpSocket& socket) noexcept {
    Error ignored;
    socket.set_option(boost::asio::socket_base::linger(true, 0), ignored);
    socket.close(ignored);
}

// A connection's channel, which tells the bridge once when it ends: at its
// close or at its destruction, whichever comes first. The route bridge owns
// it from the moment the stream is joined.
class TrackedChannel final : public ByteChannel {
public:
    using Ended = std::function<void()>;

    TrackedChannel(std::unique_ptr<ByteChannel> inner, Ended ended) noexcept
        : inner_(std::move(inner)), ended_(std::move(ended)) {}
    ~TrackedChannel() override { notify(); }

    engine::ExecutorAffinity executor_affinity() const noexcept override {
        return inner_->executor_affinity();
    }
    std::size_t max_read_size() const noexcept override {
        return inner_->max_read_size();
    }
    std::size_t max_write_size() const noexcept override {
        return inner_->max_write_size();
    }
    void async_read(std::size_t max_bytes,
                    engine::CancellationToken cancellation,
                    ReadCompletion completion) override {
        inner_->async_read(max_bytes, std::move(cancellation),
                           std::move(completion));
    }
    void async_write(Buffer buffer, engine::CancellationToken cancellation,
                     WriteCompletion completion) override {
        inner_->async_write(std::move(buffer), std::move(cancellation),
                            std::move(completion));
    }
    Status shutdown_write() noexcept override {
        return inner_->shutdown_write();
    }
    void cancel() noexcept override { inner_->cancel(); }
    void close() noexcept override {
        inner_->close();
        notify();
    }

private:
    void notify() noexcept {
        Ended ended = std::move(ended_);
        ended_ = nullptr;
        if (!ended) return;
        try {
            ended();
        } catch (...) {
        }
    }

    std::unique_ptr<ByteChannel> inner_;
    Ended ended_;
};

std::uint32_t port_key(bool ipv6, std::uint16_t port) noexcept {
    return (ipv6 ? 0x10000U : 0U) | port;
}

}  // namespace

namespace device_bridge_detail {

// One application port's datagrams to one destination.
struct FlowKey final {
    bool ipv6{false};
    std::uint16_t source_port{0U};
    std::uint16_t destination_port{0U};
    DeviceAddress destination{};
    friend bool operator==(const FlowKey&, const FlowKey&) = default;
};

struct FlowKeyHash final {
    std::size_t operator()(const FlowKey& key) const noexcept {
        std::uint64_t hash = UINT64_C(0xcbf29ce484222325);
        const auto mix = [&hash](std::uint8_t byte) noexcept {
            hash = (hash ^ byte) * UINT64_C(0x100000001b3);
        };
        mix(key.ipv6 ? 1U : 0U);
        for (const std::uint8_t byte : key.destination) mix(byte);
        mix(static_cast<std::uint8_t>(key.source_port >> 8U));
        mix(static_cast<std::uint8_t>(key.source_port));
        mix(static_cast<std::uint8_t>(key.destination_port >> 8U));
        mix(static_cast<std::uint8_t>(key.destination_port));
        return static_cast<std::size_t>(hash);
    }
};

}  // namespace device_bridge_detail

struct DeviceBridge::State final : std::enable_shared_from_this<State> {
    class Connection;
    using FlowKey = device_bridge_detail::FlowKey;
    using FlowKeyHash = device_bridge_detail::FlowKeyHash;

    struct Listener final {
        Listener(Executor executor, bool family) noexcept
            : acceptor(executor), retry(executor), ipv6(family) {}
        Acceptor acceptor;
        Timer retry;
        boost::asio::ip::address peer;
        bool ipv6;
        bool accepting{false};
        bool retrying{false};
    };

    // A datagram keeps its budget until its stream write completes.
    struct QueuedDatagram final {
        Buffer payload;
        common::UdpQueueBudget::Reservation reservation;
    };

    enum class FlowPhase : std::uint8_t {
        Opening,  // OPEN sent, timer bounds it with open_timeout
        Open,     // stream accepted, timer checks idle expiry
        Holding,  // refused, expired or ended, timer runs the retry delay
        Closed,   // removed from the bridge
    };

    // A name lookup waiting for its reply: who asked, with which identifier.
    struct DnsQuery final {
        std::uint16_t source_port{0U};
        std::uint16_t identifier{0U};
        Clock::time_point expires{};
    };

    struct Flow final {
        Flow(FlowKey flow_key, RouteDestination target, Executor executor)
            : key(flow_key), destination(std::move(target)), timer(executor) {}

        // A resolver's flow has source port zero and serves every local port.
        bool dns() const noexcept { return key.source_port == 0U; }

        FlowKey key;
        std::unordered_map<std::uint16_t, DnsQuery> queries;
        std::deque<std::pair<Clock::time_point, std::uint16_t>> query_order;
        RouteDestination destination;
        Timer timer;
        engine::CancellationSource cancellation;
        std::shared_ptr<StreamResponder> stream;
        std::deque<QueuedDatagram> queued;
        Clock::time_point last_activity{Clock::now()};
        std::uint64_t timer_generation{0U};
        FlowPhase phase{FlowPhase::Opening};
        bool reading{false};
        bool writing{false};
    };
    using FlowPtr = std::shared_ptr<Flow>;

    State(std::shared_ptr<providers::AsioExecutionContext> execution,
          const DeviceBridgeOptions& settings,
          NativeSessionSource session_source,
          std::shared_ptr<providers::AsioTcpAcceptedChannelOwner> owner)
        : context(std::move(execution)),
          options(settings),
          sessions(std::move(session_source)),
          channels(std::move(owner)),
          device(context->executor()),
          sweep_timer(context->executor()),
          open_retry(context->executor()),
          nat(settings.ipv4, settings.ipv6),
          random(std::random_device{}()) {}

    std::shared_ptr<engine::SessionEngine> active_session() const noexcept {
        if (closing || !sessions) return nullptr;
        try {
            return sessions();
        } catch (...) {
            return nullptr;
        }
    }

    // --- device ---------------------------------------------------------

    void wait_device() noexcept {
        if (closing) return;
        try {
            device.async_wait(
                Device::wait_read,
                [self = shared_from_this()](const Error& error) noexcept {
                    self->on_readable(error);
                });
        } catch (const std::bad_alloc&) {
            stop(Status(StatusCode::ResourceExhausted));
        } catch (...) {
            stop(Status(StatusCode::Internal));
        }
    }

    void on_readable(const Error& error) noexcept {
        if (closing) return;
        if (error) {
            stop(Status::diagnostic(StatusCode::Internal,
                                    "the device can no longer be read"));
            return;
        }
        for (std::size_t handled = 0U; handled < kPacketsPerTurn;) {
            const ssize_t size =
                ::read(device.native_handle(), packet_buffer.data(),
                       packet_buffer.size());
            if (size < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                stop(Status::diagnostic(StatusCode::Internal,
                                        "the device can no longer be read"));
                return;
            }
            if (size == 0) {
                stop(Status::diagnostic(StatusCode::Closed,
                                        "the device was closed"));
                return;
            }
            ++handled;
            handle(std::span<std::uint8_t>(packet_buffer)
                       .first(static_cast<std::size_t>(size)));
            if (closing) return;
        }
        wait_device();
    }

    void handle(std::span<std::uint8_t> packet) noexcept {
        try {
            std::span<std::uint8_t> written;
            DeviceDatagram datagram;
            switch (nat.translate(packet, Clock::now(), written, datagram)) {
                case DevicePacket::Write:
                    write_device(written);
                    break;
                case DevicePacket::Datagram:
                    forward(datagram);
                    break;
                case DevicePacket::Drop:
                    break;
            }
        } catch (...) {
            // Allocation failure drops this packet, which IP permits.
        }
    }

    // A packet the device cannot take now is dropped. TCP retransmits it.
    void write_device(std::span<const std::uint8_t> packet) noexcept {
        for (;;) {
            const ssize_t size =
                ::write(device.native_handle(), packet.data(), packet.size());
            if (size >= 0 || errno != EINTR) return;
        }
    }

    // --- TCP ------------------------------------------------------------

    bool full() const noexcept {
        return closing || open_connections >= options.max_connections;
    }

    void accept(Listener& listener) noexcept {
        if (closing || listener.accepting || listener.retrying || full() ||
            !listener.acceptor.is_open()) {
            return;
        }
        listener.accepting = true;
        try {
            listener.acceptor.async_accept(
                [self = shared_from_this(), &listener](
                    const Error& error,
                    providers::AsioTcpSocket socket) noexcept {
                    self->on_accept(listener, error, std::move(socket));
                });
        } catch (const std::bad_alloc&) {
            listener.accepting = false;
            retry_accept(listener);
        } catch (...) {
            listener.accepting = false;
            stop(Status(StatusCode::Internal));
        }
    }

    void on_accept(Listener& listener, const Error& error,
                   providers::AsioTcpSocket socket) noexcept {
        listener.accepting = false;
        if (closing) return;
        if (error) {
            if (error == boost::asio::error::operation_aborted) return;
            // Out of descriptors or memory. The kernel keeps the connections
            // waiting in its queue meanwhile.
            retry_accept(listener);
            return;
        }
        deliver(listener, std::move(socket));
        accept(listener);
    }

    void retry_accept(Listener& listener) noexcept {
        if (closing || listener.retrying) return;
        listener.retrying = true;
        try {
            listener.retry.expires_after(kAcceptRetry);
            listener.retry.async_wait([self = shared_from_this(),
                                       &listener](const Error& error) noexcept {
                listener.retrying = false;
                if (!error) self->accept(listener);
            });
        } catch (...) {
            // Without a retry nothing would ever accept again.
            listener.retrying = false;
            stop(Status(StatusCode::ResourceExhausted));
        }
    }

    void resume_accepting() noexcept {
        for (auto& listener : listeners) accept(*listener);
    }

    // A socket that fails a check is reset when it leaves scope.
    void deliver(const Listener& listener,
                 providers::AsioTcpSocket socket) noexcept;
    void connection_ended(bool ipv6, std::uint16_t peer_port) noexcept;
    void forget(const Connection* connection) noexcept;
    // Starts waiting connections' OPENs while fewer than max_pending_opens
    // are in flight.
    void pump_opens() noexcept;
    void open_finished() noexcept;
    // The session had no stream left for this connection's OPEN. It goes
    // back to the head of the queue until a stream may be free.
    void requeue(std::shared_ptr<Connection> connection) noexcept;

    // --- UDP ------------------------------------------------------------

    void forward(const DeviceDatagram& datagram) noexcept {
        if (options.packet_service.empty() || opener) return;
        const bool dns = datagram.destination_port == kDnsPort;
        if (dns && datagram.payload.size() < kDnsHeaderBytes) return;
        FlowKey key;
        key.ipv6 = datagram.ipv6;
        key.source_port = dns ? std::uint16_t{0U} : datagram.source_port;
        key.destination_port = datagram.destination_port;
        key.destination = datagram.destination;
        try {
            FlowPtr flow;
            if (const auto found = flows.find(key); found != flows.end()) {
                flow = found->second;
            } else {
                flow = open_flow(key);
            }
            if (!flow || (flow->phase != FlowPhase::Opening &&
                          flow->phase != FlowPhase::Open)) {
                return;
            }
            auto reservation =
                pending_budget.try_reserve(datagram.payload.size());
            if (!reservation) return;
            auto buffer = Buffer::copy_from(std::as_bytes(datagram.payload),
                                            datagram.payload.size());
            if (!buffer.ok()) return;
            Buffer payload = std::move(buffer).take_value();
            if (dns) {
                const auto identifier = remember(*flow, datagram);
                if (!identifier) return;
                const auto bytes = payload.mutable_bytes();
                bytes[0] = static_cast<std::byte>(*identifier >> 8U);
                bytes[1] = static_cast<std::byte>(*identifier & 0xffU);
            }
            flow->last_activity = Clock::now();
            flow->queued.push_back(
                {std::move(payload), std::move(*reservation)});
            write_next(flow);
        } catch (...) {
            // Allocation failure drops this datagram, which UDP permits.
        }
    }

    // Gives a query an identifier of the bridge's own for its resolver's
    // shared flow and remembers who asked. Nothing when that many queries
    // already wait for a reply.
    std::optional<std::uint16_t> remember(Flow& flow,
                                          const DeviceDatagram& datagram) {
        const auto now = Clock::now();
        while (!flow.query_order.empty() &&
               flow.query_order.front().first <= now) {
            const auto expired =
                flow.queries.find(flow.query_order.front().second);
            if (expired != flow.queries.end() &&
                expired->second.expires <= now) {
                flow.queries.erase(expired);
            }
            flow.query_order.pop_front();
        }
        if (flow.queries.size() >= kMaxDnsQueries ||
            flow.query_order.size() >= 4U * kMaxDnsQueries) {
            return std::nullopt;
        }
        DnsQuery query;
        query.source_port = datagram.source_port;
        query.identifier = static_cast<std::uint16_t>(
            (std::uint16_t{datagram.payload[0]} << 8U) | datagram.payload[1]);
        query.expires = now + kDnsQueryLifetime;
        // At most a small part of the identifiers is in use, so a free one
        // turns up at once.
        for (;;) {
            const auto identifier = static_cast<std::uint16_t>(random());
            if (!flow.queries.emplace(identifier, query).second) continue;
            try {
                flow.query_order.emplace_back(query.expires, identifier);
            } catch (...) {
                flow.queries.erase(identifier);
                throw;
            }
            return identifier;
        }
    }

    // A resolver's reply goes to the port that asked, with its identifier.
    void deliver_answer(Flow& flow, std::span<const std::byte> payload) {
        if (payload.size() < kDnsHeaderBytes) return;
        const auto identifier = static_cast<std::uint16_t>(
            (std::to_integer<std::uint16_t>(payload[0]) << 8U) |
            std::to_integer<std::uint16_t>(payload[1]));
        const auto asked = flow.queries.find(identifier);
        if (asked == flow.queries.end()) return;
        const DnsQuery query = asked->second;
        flow.queries.erase(asked);
        const auto* bytes =
            reinterpret_cast<const std::uint8_t*>(payload.data());
        std::vector<std::uint8_t> answer(bytes, bytes + payload.size());
        answer[0] = static_cast<std::uint8_t>(query.identifier >> 8U);
        answer[1] = static_cast<std::uint8_t>(query.identifier);
        const std::size_t size = nat.build_reply(
            flow.key.ipv6, flow.key.destination, flow.key.destination_port,
            query.source_port, answer, options.mtu, reply_buffer);
        if (size != 0U) {
            write_device(
                std::span<const std::uint8_t>(reply_buffer).first(size));
        }
    }

    // Throws std::bad_alloc before the flow is published.
    FlowPtr open_flow(const FlowKey& key) {
        if (flows.size() >= options.max_destinations) return nullptr;
        // A resolver's shared flow has port zero, so all resolvers together
        // meet the same bound as one local port's destinations.
        const std::uint32_t port = port_key(key.ipv6, key.source_port);
        if (const auto used = port_flows.find(port);
            used != port_flows.end() &&
            used->second >= options.max_port_destinations) {
            return nullptr;
        }
        const auto session = active_session();
        if (!session) return nullptr;
        auto destination =
            to_destination(NetworkProtocol::Udp, key.ipv6, key.destination,
                           key.destination_port);
        if (!destination.ok()) return nullptr;
        auto flow = std::make_shared<Flow>(
            key, std::move(destination).take_value(), context->executor());
        flows.emplace(key, flow);
        try {
            ++port_flows[port];
        } catch (...) {
            flows.erase(key);
            throw;
        }
        publish_counts();
        arm_timer(flow, options.open_timeout);
        if (flow->phase != FlowPhase::Opening) return flow;
        try {
            session->async_open(
                options.packet_service, ServiceKind::PacketChannel,
                flow->destination, flow->cancellation.token(),
                [self = shared_from_this(), flow](
                    Result<std::shared_ptr<StreamResponder>> result) noexcept {
                    self->on_flow_open(flow, std::move(result));
                });
        } catch (...) {
            hold(flow);
        }
        return flow;
    }

    void on_flow_open(
        const FlowPtr& flow,
        Result<std::shared_ptr<StreamResponder>> result) noexcept {
        if (closing || flow->phase != FlowPhase::Opening) {
            if (result.ok() && result.value()) {
                result.value()->close(Status(StatusCode::Cancelled));
            }
            return;
        }
        if (!result.ok() || !result.value()) {
            hold(flow);
            return;
        }
        flow->stream = std::move(result).take_value();
        flow->phase = FlowPhase::Open;
        flow->last_activity = Clock::now();
        arm_timer(flow, options.udp_idle_timeout);
        read(flow);
        write_next(flow);
    }

    void write_next(const FlowPtr& flow) noexcept {
        while (!closing && flow->phase == FlowPhase::Open && !flow->writing &&
               !flow->queued.empty()) {
            if (flow->queued.front().payload.size() >
                flow->stream->max_write_size()) {
                // Larger than this session's packet bound.
                flow->queued.pop_front();
                continue;
            }
            flow->writing = true;
            try {
                flow->stream->async_write(
                    std::move(flow->queued.front().payload),
                    flow->cancellation.token(),
                    [self = shared_from_this(), flow](Status status,
                                                      std::size_t) noexcept {
                        self->on_written(flow, std::move(status));
                    });
            } catch (...) {
                flow->writing = false;
                hold(flow);
            }
            return;
        }
    }

    void on_written(const FlowPtr& flow, Status status) noexcept {
        flow->writing = false;
        // Releases the datagram's budget. hold() and close() clear the queue.
        if (!flow->queued.empty()) flow->queued.pop_front();
        if (closing || flow->phase != FlowPhase::Open) return;
        if (!status.ok()) {
            hold(flow);
            return;
        }
        write_next(flow);
    }

    void read(const FlowPtr& flow) noexcept {
        if (closing || flow->phase != FlowPhase::Open || flow->reading) return;
        flow->reading = true;
        try {
            flow->stream->async_read(
                flow->cancellation.token(),
                [self = shared_from_this(),
                 flow](Result<ReceivedRecord> result) noexcept {
                    self->on_reply(flow, std::move(result));
                });
        } catch (...) {
            flow->reading = false;
            hold(flow);
        }
    }

    void on_reply(const FlowPtr& flow, Result<ReceivedRecord> result) noexcept {
        flow->reading = false;
        if (closing || flow->phase != FlowPhase::Open) return;
        if (!result.ok()) {
            // End of stream, refusal or a lost session.
            hold(flow);
            return;
        }
        flow->last_activity = Clock::now();
        {
            // The record's receive credit returns when it leaves this scope,
            // whether the device took the reply or not.
            const ReceivedRecord record = std::move(result).take_value();
            const auto payload = record.payload().bytes();
            try {
                if (flow->dns()) {
                    deliver_answer(*flow, payload);
                } else {
                    const std::size_t size = nat.build_reply(
                        flow->key.ipv6, flow->key.destination,
                        flow->key.destination_port, flow->key.source_port,
                        {reinterpret_cast<const std::uint8_t*>(payload.data()),
                         payload.size()},
                        options.mtu, reply_buffer);
                    if (size != 0U) {
                        write_device(std::span<const std::uint8_t>(reply_buffer)
                                         .first(size));
                    }
                }
            } catch (...) {
                // Allocation failure drops this reply, which UDP permits.
            }
        }
        read(flow);
    }

    void arm_timer(const FlowPtr& flow,
                   std::chrono::milliseconds duration) noexcept {
        const std::uint64_t generation = ++flow->timer_generation;
        try {
            flow->timer.expires_after(duration);
            flow->timer.async_wait([self = shared_from_this(), flow,
                                    generation](const Error& error) noexcept {
                if (!error && generation == flow->timer_generation) {
                    self->on_flow_timer(flow);
                }
            });
        } catch (...) {
            remove(flow);
        }
    }

    void on_flow_timer(const FlowPtr& flow) noexcept {
        if (closing) return;
        switch (flow->phase) {
            case FlowPhase::Opening:
                hold(flow);
                return;
            case FlowPhase::Holding:
                remove(flow);
                return;
            case FlowPhase::Open: {
                const auto idle = Clock::now() - flow->last_activity;
                if (idle >= options.udp_idle_timeout) {
                    remove(flow);
                } else {
                    arm_timer(flow,
                              std::chrono::ceil<std::chrono::milliseconds>(
                                  options.udp_idle_timeout - idle));
                }
                return;
            }
            case FlowPhase::Closed:
                return;
        }
    }

    // Keeps the destination's entry so its datagrams are dropped until the
    // retry delay ends, which bounds how often a refused OPEN is repeated.
    void hold(const FlowPtr& flow) noexcept {
        if (flow->phase == FlowPhase::Holding ||
            flow->phase == FlowPhase::Closed) {
            return;
        }
        flow->phase = FlowPhase::Holding;
        release(*flow);
        arm_timer(flow, options.udp_retry_delay);
    }

    void remove(const FlowPtr& flow) noexcept {
        if (flow->phase == FlowPhase::Closed) return;
        const FlowPtr keep = flow;
        keep->phase = FlowPhase::Closed;
        ++keep->timer_generation;
        providers::cancel_timer(keep->timer);
        release(*keep);
        flows.erase(keep->key);
        const auto used =
            port_flows.find(port_key(keep->key.ipv6, keep->key.source_port));
        if (used != port_flows.end() && --used->second == 0U) {
            port_flows.erase(used);
        }
        publish_counts();
    }

    static void release(Flow& flow) noexcept {
        // Cancellation may complete the OPEN, read or write inline. Each of
        // those checks the phase set by the caller.
        flow.cancellation.cancel();
        if (flow.stream) {
            auto stream = std::move(flow.stream);
            stream->close(Status(StatusCode::Cancelled));
        }
        flow.queued.clear();
        flow.queries.clear();
        flow.query_order.clear();
    }

    // --- lifetime -------------------------------------------------------

    void sweep() noexcept {
        if (closing) return;
        nat.sweep(Clock::now());
        try {
            sweep_timer.expires_after(kSweepInterval);
            sweep_timer.async_wait(
                [self = shared_from_this()](const Error& error) noexcept {
                    if (!error) self->sweep();
                });
        } catch (...) {
            // Without the sweep closed connections would keep their ports
            // until the table filled.
            stop(Status(StatusCode::ResourceExhausted));
        }
    }

    void publish_counts() noexcept {
        tcp_count.store(static_cast<std::uint32_t>(open_connections),
                        std::memory_order_relaxed);
        udp_count.store(static_cast<std::uint32_t>(flows.size()),
                        std::memory_order_relaxed);
    }

    void stop(Status status) noexcept {
        if (closing) return;
        auto stopped = std::move(on_stopped);
        close();
        if (stopped) {
            try {
                stopped(std::move(status));
            } catch (...) {
            }
        }
    }

    void close() noexcept;

    std::shared_ptr<providers::AsioExecutionContext> context;
    const DeviceBridgeOptions options;
    NativeSessionSource sessions;
    NativeStreamOpener opener;
    Stopped on_stopped;
    std::shared_ptr<providers::AsioTcpAcceptedChannelOwner> channels;
    Device device;
    Timer sweep_timer;
    Timer open_retry;
    DeviceNat nat;
    // Identifiers for relayed name lookups. Only the resolver's path sees
    // them, as it would see the application's own.
    std::mt19937 random;
    std::vector<std::unique_ptr<Listener>> listeners;
    // Connections not yet joined to a stream: every one of them, and those
    // among them whose OPEN has not started.
    std::list<std::shared_ptr<Connection>> opening;
    std::deque<std::shared_ptr<Connection>> waiting;
    std::size_t opens_in_flight{0U};
    // The session reported no free stream. Waits for one to end or kOpenRetry.
    bool stalled{false};
    bool pumping{false};
    bool pump_again{false};
    // Unjoined connections and the ones joined to a stream.
    std::size_t open_connections{0U};
    std::unordered_map<FlowKey, FlowPtr, FlowKeyHash> flows;
    std::unordered_map<std::uint32_t, std::size_t> port_flows;
    common::UdpQueueBudget pending_budget;
    std::vector<std::uint8_t> packet_buffer;
    std::vector<std::uint8_t> reply_buffer;
    std::atomic<std::uint32_t> tcp_count{0U};
    std::atomic<std::uint32_t> udp_count{0U};
    bool closing{false};
};

// One accepted connection from accept until its stream is joined or it
// closes. Nothing is read from the socket before the OPEN is accepted, so
// early application bytes wait in it for the route bridge.
class DeviceBridge::State::Connection final
    : public std::enable_shared_from_this<Connection> {
public:
    Connection(std::weak_ptr<State> owner, std::unique_ptr<ByteChannel> channel,
               RouteDestination destination, Executor executor)
        : owner_(std::move(owner)),
          channel_(std::move(channel)),
          destination_(std::move(destination)),
          timer_(executor) {}

    // The deadline runs from here, through the wait for a free OPEN.
    void begin(std::chrono::milliseconds limit) noexcept {
        arm_deadline(limit);
    }
    bool done() const noexcept { return done_; }

    // The owner has counted this OPEN as in flight.
    void open() noexcept {
        const auto owner = owner_.lock();
        const auto session = owner ? owner->active_session() : nullptr;
        if (done_ || !owner) return;
        opening_ = true;
        if (!owner->opener && !session) {
            finish();
            return;
        }
        try {
            auto opened =
                [self = shared_from_this()](
                    Result<std::shared_ptr<StreamResponder>> result) noexcept {
                    self->on_open(std::move(result));
                };
            if (owner->opener) {
                owner->opener(destination_, owner->options.stream_service,
                              open_cancellation_.token(), std::move(opened));
                return;
            }
            session->async_open(owner->options.stream_service,
                                ServiceKind::ByteStream, destination_,
                                open_cancellation_.token(), std::move(opened));
        } catch (...) {
            finish();
        }
    }

    void close() noexcept { finish(); }

private:
    void on_open(Result<std::shared_ptr<StreamResponder>> result) noexcept {
        if (done_) {
            if (result.ok() && result.value()) {
                result.value()->close(Status(StatusCode::Cancelled));
            }
            return;
        }
        const auto self = shared_from_this();
        const auto owner = owner_.lock();
        if (!result.ok() || !result.value()) {
            // No stream left in the session is not a refusal: one may be free
            // before this connection's deadline.
            if (owner && !result.ok() &&
                result.status().code() == StatusCode::ResourceExhausted) {
                // Requeued first, so the freed OPEN is not spent on the next
                // connection, which would find the same shortage.
                opening_ = false;
                owner->requeue(self);
                owner->open_finished();
                return;
            }
            finish();
            return;
        }
        done_ = true;
        opening_ = false;
        disarm_deadline();
        auto channel = std::move(channel_);
        if (owner) {
            owner->forget(this);
            owner->open_finished();
        }
        auto stream = std::move(result).take_value();
        auto connection =
            engine::RouteConnection::byte_stream(std::move(channel));
        if (!connection.ok()) {
            stream->close(connection.status());
            return;
        }
        providers::bridge_established_route(std::move(stream),
                                            std::move(connection).take_value());
    }

    void arm_deadline(std::chrono::milliseconds duration) noexcept {
        try {
            timer_.expires_after(duration);
            timer_.async_wait(
                [self = shared_from_this()](const Error& error) noexcept {
                    // Finishing first makes an acceptance that cancellation
                    // delivers inline close its stream instead of joining it.
                    if (!error) self->finish();
                });
        } catch (...) {
            finish();
        }
    }

    void disarm_deadline() noexcept { providers::cancel_timer(timer_); }

    void finish() noexcept {
        if (done_) return;
        done_ = true;
        const auto self = shared_from_this();
        const bool was_opening = std::exchange(opening_, false);
        disarm_deadline();
        open_cancellation_.cancel();
        if (channel_) {
            channel_->cancel();
            channel_->close();
            channel_.reset();
        }
        if (const auto owner = owner_.lock()) {
            owner->forget(this);
            if (was_opening) owner->open_finished();
        }
    }

    std::weak_ptr<State> owner_;
    std::unique_ptr<ByteChannel> channel_;
    RouteDestination destination_;
    Timer timer_;
    engine::CancellationSource open_cancellation_;
    bool done_{false};
    // Its OPEN is counted among the owner's opens in flight.
    bool opening_{false};
};

void DeviceBridge::State::deliver(const Listener& listener,
                                  providers::AsioTcpSocket socket) noexcept {
    Error error;
    const auto peer = socket.remote_endpoint(error);
    // Only a peer the translator named is a connection from the device.
    // Anything else, such as a local process dialling the listener, is not.
    if (error || peer.address() != listener.peer) {
        reset(socket);
        return;
    }
    std::optional<DeviceTcpOrigin> origin;
    try {
        origin = nat.accept(listener.ipv6, peer.port());
    } catch (...) {
        origin.reset();
    }
    if (!origin) {
        reset(socket);
        return;
    }
    const bool ipv6 = listener.ipv6;
    const std::uint16_t peer_port = peer.port();
    if (!opener && !active_session()) {
        reset(socket);
        nat.release(ipv6, peer_port, Clock::now());
        return;
    }
    // Once the tracked channel exists, its end releases the port and count.
    bool tracked_exists = false;
    try {
        auto destination =
            to_destination(NetworkProtocol::Tcp, ipv6, origin->destination,
                           origin->destination_port);
        auto adopted =
            destination.ok()
                ? channels->adopt(std::move(socket))
                : Result<std::unique_ptr<ByteChannel>>(destination.status());
        if (!adopted.ok()) {
            nat.release(ipv6, peer_port, Clock::now());
            return;
        }
        const std::weak_ptr<State> weak = weak_from_this();
        auto tracked = std::make_unique<TrackedChannel>(
            std::move(adopted).take_value(), [weak, ipv6, peer_port] {
                if (const auto self = weak.lock()) {
                    self->connection_ended(ipv6, peer_port);
                }
            });
        tracked_exists = true;
        ++open_connections;
        publish_counts();
        auto connection = std::make_shared<Connection>(
            weak, std::move(tracked), std::move(destination).take_value(),
            context->executor());
        opening.push_back(connection);
        connection->begin(options.open_timeout);
        if (!connection->done()) {
            waiting.push_back(connection);
            pump_opens();
        }
    } catch (...) {
        if (!tracked_exists) nat.release(ipv6, peer_port, Clock::now());
    }
}

void DeviceBridge::State::connection_ended(bool ipv6,
                                           std::uint16_t peer_port) noexcept {
    nat.release(ipv6, peer_port, Clock::now());
    if (open_connections != 0U) --open_connections;
    publish_counts();
    resume_accepting();
    // A stream of the session may be free again.
    stalled = false;
    pump_opens();
}

void DeviceBridge::State::forget(const Connection* connection) noexcept {
    const auto same = [connection](const auto& value) {
        return value.get() == connection;
    };
    opening.remove_if(same);
    waiting.erase(std::remove_if(waiting.begin(), waiting.end(), same),
                  waiting.end());
}

// An OPEN may complete inside the call that starts it, which re-enters here
// through open_finished(). The outer call continues the loop instead.
void DeviceBridge::State::pump_opens() noexcept {
    if (pumping) {
        pump_again = true;
        return;
    }
    pumping = true;
    do {
        pump_again = false;
        while (!closing && !stalled && !waiting.empty() &&
               opens_in_flight < options.max_pending_opens) {
            const auto connection = std::move(waiting.front());
            waiting.pop_front();
            ++opens_in_flight;
            connection->open();
        }
    } while (pump_again);
    pumping = false;
}

void DeviceBridge::State::open_finished() noexcept {
    if (opens_in_flight != 0U) --opens_in_flight;
    pump_opens();
}

void DeviceBridge::State::requeue(
    std::shared_ptr<Connection> connection) noexcept {
    if (closing || connection->done()) return;
    try {
        waiting.push_front(connection);
    } catch (...) {
        connection->close();
        return;
    }
    if (stalled) return;
    stalled = true;
    try {
        open_retry.expires_after(kOpenRetry);
        open_retry.async_wait(
            [self = shared_from_this()](const Error& error) noexcept {
                if (error || self->closing) return;
                self->stalled = false;
                self->pump_opens();
            });
    } catch (...) {
        // The next connection that ends continues the queue. Each waiting
        // connection still has its own deadline.
    }
}

void DeviceBridge::State::close() noexcept {
    if (closing) return;
    closing = true;
    on_stopped = {};
    Error ignored;
    providers::cancel_timer(sweep_timer);
    providers::cancel_timer(open_retry);
    waiting.clear();
    for (const auto& listener : listeners) {
        providers::cancel_timer(listener->retry);
        listener->acceptor.close(ignored);
    }
    device.close(ignored);
    auto waiting = std::move(opening);
    opening.clear();
    for (const auto& connection : waiting) connection->close();
    auto current = std::move(flows);
    flows.clear();
    port_flows.clear();
    for (const auto& [key, flow] : current) {
        flow->phase = FlowPhase::Closed;
        ++flow->timer_generation;
        providers::cancel_timer(flow->timer);
        release(*flow);
    }
    pending_budget.close();
    // Ends the joined connections, whose channels then close.
    channels->cancel();
    publish_counts();
}

engine::Result<std::shared_ptr<DeviceBridge>> DeviceBridge::create(
    std::shared_ptr<providers::AsioExecutionContext> context,
    const DeviceBridgeOptions& options, NativeSessionSource sessions,
    Stopped on_stopped, NativeStreamOpener opener) {
    using Created = engine::Result<std::shared_ptr<DeviceBridge>>;
    const auto distinct = [](const std::optional<DeviceAddressPair>& pair) {
        return !pair || pair->device != pair->peer;
    };
    if (!context || !sessions || options.descriptor < 0 ||
        options.stream_service.empty() || (!options.ipv4 && !options.ipv6) ||
        !distinct(options.ipv4) || !distinct(options.ipv6) ||
        options.mtu < (options.ipv6 ? 1280U : 576U) || options.mtu > 65'535U ||
        options.max_connections == 0U || options.max_connections > 4096U ||
        options.max_pending_opens == 0U || options.max_destinations == 0U ||
        options.max_destinations > 4096U ||
        options.max_port_destinations == 0U ||
        options.open_timeout <= std::chrono::milliseconds::zero() ||
        options.udp_idle_timeout <= std::chrono::milliseconds::zero() ||
        options.udp_retry_delay <= std::chrono::milliseconds::zero()) {
        return Created(Status(StatusCode::InvalidArgument));
    }
    context->require_context();
    try {
        providers::AsioTcpChannelLimits channel_limits;
        channel_limits.max_active_channels = options.max_connections;
        auto channels = providers::AsioTcpAcceptedChannelOwner::create(
            context, channel_limits);
        if (!channels.ok()) return Created(channels.status());
        auto state =
            std::make_shared<State>(context, options, std::move(sessions),
                                    std::move(channels).take_value());
        state->packet_buffer.resize(kPacketBytes);
        state->reply_buffer.resize(options.mtu);

        // The duplicate shares the caller's open device, so the non-blocking
        // flag applies to both.
        const int duplicate = ::fcntl(options.descriptor, F_DUPFD_CLOEXEC, 0);
        if (duplicate < 0) {
            return Created(
                Status::diagnostic(StatusCode::InvalidArgument,
                                   "the device descriptor is not open"));
        }
        Error error;
        state->device.assign(duplicate, error);
        if (error) {
            ::close(duplicate);
            return Created(Status(StatusCode::Internal));
        }
        const int flags = ::fcntl(duplicate, F_GETFL, 0);
        if (flags < 0 || ::fcntl(duplicate, F_SETFL, flags | O_NONBLOCK) < 0) {
            return Created(
                Status::diagnostic(StatusCode::Internal,
                                   "the device cannot be made non-blocking"));
        }

        std::uint16_t ports[2] = {0U, 0U};
        for (const bool ipv6 : {false, true}) {
            const auto& pair = ipv6 ? options.ipv6 : options.ipv4;
            if (!pair) continue;
            auto listener =
                std::make_unique<State::Listener>(context->executor(), ipv6);
            listener->peer = to_address(ipv6, pair->peer);
            const boost::asio::ip::tcp::endpoint local{
                to_address(ipv6, pair->device), 0U};
            listener->acceptor.open(local.protocol(), error);
            if (!error && ipv6) {
                listener->acceptor.set_option(boost::asio::ip::v6_only(true),
                                              error);
            }
            if (!error) listener->acceptor.bind(local, error);
            if (!error) {
                listener->acceptor.listen(
                    boost::asio::socket_base::max_listen_connections, error);
            }
            const auto bound =
                error ? local : listener->acceptor.local_endpoint(error);
            if (error) {
                return Created(Status::diagnostic(
                    StatusCode::InvalidArgument,
                    "the bridge's listener could not open on the device's "
                    "address"));
            }
            ports[ipv6 ? 1U : 0U] = bound.port();
            state->listeners.push_back(std::move(listener));
        }
        state->nat.set_listener_ports(ports[0], ports[1]);

        auto result = std::shared_ptr<DeviceBridge>(new DeviceBridge(state));
        state->opener = std::move(opener);
        state->sweep();
        state->resume_accepting();
        state->wait_device();
        // A failure while arming closed the bridge before any owner existed.
        if (state->closing)
            return Created(Status(StatusCode::ResourceExhausted));
        state->on_stopped = std::move(on_stopped);
        return Created(std::move(result));
    } catch (const std::bad_alloc&) {
        return Created(Status(StatusCode::ResourceExhausted));
    } catch (...) {
        return Created(Status(StatusCode::Internal));
    }
}

DeviceBridge::DeviceBridge(std::shared_ptr<State> state) noexcept
    : state_(std::move(state)) {}

DeviceBridge::~DeviceBridge() noexcept {
    close();
}

std::uint32_t DeviceBridge::tcp_connections() const noexcept {
    return state_->tcp_count.load(std::memory_order_relaxed);
}

std::uint32_t DeviceBridge::udp_destinations() const noexcept {
    return state_->udp_count.load(std::memory_order_relaxed);
}

void DeviceBridge::close() noexcept {
    state_->close();
}

}  // namespace yume::runtime
