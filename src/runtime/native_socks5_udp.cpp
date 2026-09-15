/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/native_socks5_udp.hpp"

#include <algorithm>
#include <deque>
#include <list>
#include <new>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/asio/basic_datagram_socket.hpp>
#include <boost/asio/basic_waitable_timer.hpp>
#include <boost/asio/ip/v6_only.hpp>

#include "common/udp_queue_budget.hpp"
#include "engine/buffer.hpp"
#include "engine/cancellation.hpp"
#include "engine/carrier.hpp"
#include "engine/route_provider.hpp"
#include "engine/stream_handler.hpp"
#include "runtime/socks5_request.hpp"

namespace yume::runtime {
namespace {
using engine::Buffer;
using engine::ReceivedRecord;
using engine::Result;
using engine::RouteDestination;
using engine::ServiceKind;
using engine::Status;
using engine::StatusCode;
using engine::StreamResponder;
using Udp = boost::asio::ip::udp;
using UdpSocket = boost::asio::basic_datagram_socket<Udp, providers::AsioExecutionContext::Executor>;
using Clock = std::chrono::steady_clock;
using Timer = boost::asio::basic_waitable_timer<
    Clock, boost::asio::wait_traits<Clock>, providers::AsioExecutionContext::Executor>;
using Error = boost::system::error_code;

// Larger than any UDP datagram, so nothing a client sends is truncated.
constexpr std::size_t kReceiveBufferBytes = 65'536U;

Status diagnostic(StatusCode code, std::string_view message) noexcept {
    try {
        return Status(code, message);
    } catch (...) {
        return Status(code);
    }
}

bool same_destination(const RouteDestination& left, const RouteDestination& right) noexcept {
    const auto left_address = left.address_bytes();
    const auto right_address = right.address_bytes();
    return left.address_kind() == right.address_kind() && left.port() == right.port() &&
        std::equal(left_address.begin(), left_address.end(),
                   right_address.begin(), right_address.end()) &&
        left.dns_name() == right.dns_name();
}

}  // namespace

struct NativeSocks5UdpAssociation::State final : std::enable_shared_from_this<State> {
    // A client datagram keeps its budget until its stream write completes.
    struct QueuedDatagram final {
        Buffer payload;
        common::UdpQueueBudget::Reservation reservation;
    };
    // A reply keeps its budget and the peer's receive credit until it is sent.
    struct QueuedReply final {
        std::vector<std::uint8_t> datagram;
        common::UdpQueueBudget::Reservation reservation;
        engine::CarrierCredit credit;
    };

    enum class Phase : std::uint8_t {
        Opening,  // OPEN sent, timer bounds it with limits.open_timeout
        Open,     // stream accepted, timer checks idle expiry
        Holding,  // refused, expired or ended, timer runs the retry delay
        Closed,   // removed from the association
    };

    // One destination and its authenticated packet stream.
    struct Flow final {
        Flow(RouteDestination target, std::vector<std::uint8_t> reply_header,
             providers::AsioExecutionContext::Executor executor)
            : destination(std::move(target)),
              header(std::move(reply_header)),
              timer(executor) {}

        RouteDestination destination;
        // Prefix for every reply from this destination.
        std::vector<std::uint8_t> header;
        Timer timer;
        engine::CancellationSource cancellation;
        std::shared_ptr<StreamResponder> stream;
        std::deque<QueuedDatagram> queued;
        Clock::time_point last_activity{Clock::now()};
        std::uint64_t timer_generation{0U};
        Phase phase{Phase::Opening};
        bool reading{false};
        bool writing{false};
    };
    using FlowPtr = std::shared_ptr<Flow>;

    State(std::shared_ptr<providers::AsioExecutionContext> execution, std::string service_name,
          NativeSessionSource session_source, const NativeSocks5Limits& bounds,
          Udp::endpoint client_endpoint)
        : context(std::move(execution)),
          service(std::move(service_name)),
          sessions(std::move(session_source)),
          limits(bounds),
          socket(context->executor()),
          client(std::move(client_endpoint)) {}

    void receive() noexcept {
        if (closed) return;
        try {
            socket.async_receive_from(boost::asio::buffer(receive_buffer), sender,
                [self = shared_from_this()](const Error& error, std::size_t size) noexcept {
                    self->on_receive(error, size);
                });
        } catch (...) {
            close();
        }
    }

    void on_receive(const Error& error, std::size_t size) noexcept {
        if (closed) return;
        if (error) {
            // A loopback relay has no transient receive failure worth a retry,
            // and retrying a persistent one would spin.
            close();
            return;
        }
        forward(std::span<const std::uint8_t>(receive_buffer).first(size));
        receive();
    }

    void forward(std::span<const std::uint8_t> datagram) noexcept {
        if (sender.address() != client.address() ||
            (client.port() != 0U && sender.port() != client.port())) {
            return;
        }
        auto parsed = socks5::parse_udp_datagram(datagram);
        if (!parsed) return;
        const auto payload = datagram.subspan(parsed->payload_offset);
        // A YTP packet record cannot be empty.
        if (payload.empty()) return;
        if (client.port() == 0U) client.port(sender.port());
        try {
            FlowPtr flow = find(parsed->destination);
            if (!flow) flow = open_flow(std::move(parsed->destination));
            if (!flow || (flow->phase != Phase::Opening && flow->phase != Phase::Open)) return;
            auto reservation = pending_budget.try_reserve(payload.size());
            if (!reservation) return;
            auto buffer = Buffer::copy_from(std::as_bytes(payload), payload.size());
            if (!buffer.ok()) return;
            flow->last_activity = Clock::now();
            flow->queued.push_back({std::move(buffer).take_value(), std::move(*reservation)});
            write_next(flow);
        } catch (...) {
            // Allocation failure drops this datagram, which UDP permits.
        }
    }

    FlowPtr find(const RouteDestination& destination) const noexcept {
        for (const auto& flow : flows) {
            if (same_destination(flow->destination, destination)) return flow;
        }
        return nullptr;
    }

    // Throws std::bad_alloc before the flow is published.
    FlowPtr open_flow(RouteDestination destination) {
        if (flows.size() >= limits.max_udp_destinations) return nullptr;
        std::shared_ptr<engine::SessionEngine> session;
        try {
            session = sessions();
        } catch (...) {
            session.reset();
        }
        if (!session) return nullptr;
        auto header = socks5::udp_header(destination);
        auto flow = std::make_shared<Flow>(std::move(destination), std::move(header),
                                           context->executor());
        flows.push_back(flow);
        arm_timer(flow, limits.open_timeout);
        if (flow->phase != Phase::Opening) return flow;
        try {
            session->async_open(service, ServiceKind::PacketChannel, flow->destination,
                flow->cancellation.token(),
                [self = shared_from_this(), flow](Result<std::shared_ptr<StreamResponder>> result) noexcept {
                    self->on_open(flow, std::move(result));
                });
        } catch (...) {
            hold(flow);
        }
        return flow;
    }

    void on_open(const FlowPtr& flow, Result<std::shared_ptr<StreamResponder>> result) noexcept {
        if (closed || flow->phase != Phase::Opening) {
            if (result.ok() && result.value()) result.value()->close(Status(StatusCode::Cancelled));
            return;
        }
        if (!result.ok() || !result.value()) {
            hold(flow);
            return;
        }
        flow->stream = std::move(result).take_value();
        flow->phase = Phase::Open;
        flow->last_activity = Clock::now();
        arm_timer(flow, limits.udp_idle_timeout);
        read(flow);
        write_next(flow);
    }

    void write_next(const FlowPtr& flow) noexcept {
        while (!closed && flow->phase == Phase::Open && !flow->writing && !flow->queued.empty()) {
            if (flow->queued.front().payload.size() > flow->stream->max_write_size()) {
                // Larger than this session's packet bound.
                flow->queued.pop_front();
                continue;
            }
            flow->writing = true;
            try {
                flow->stream->async_write(std::move(flow->queued.front().payload),
                    flow->cancellation.token(),
                    [self = shared_from_this(), flow](Status status, std::size_t) noexcept {
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
        if (closed || flow->phase != Phase::Open) return;
        if (!status.ok()) {
            hold(flow);
            return;
        }
        write_next(flow);
    }

    void read(const FlowPtr& flow) noexcept {
        if (closed || flow->phase != Phase::Open || flow->reading) return;
        flow->reading = true;
        try {
            flow->stream->async_read(flow->cancellation.token(),
                [self = shared_from_this(), flow](Result<ReceivedRecord> result) noexcept {
                    self->on_reply(flow, std::move(result));
                });
        } catch (...) {
            flow->reading = false;
            hold(flow);
        }
    }

    void on_reply(const FlowPtr& flow, Result<ReceivedRecord> result) noexcept {
        flow->reading = false;
        if (closed || flow->phase != Phase::Open) return;
        if (!result.ok()) {
            // End of stream, refusal or a lost session.
            hold(flow);
            return;
        }
        flow->last_activity = Clock::now();
        deliver(*flow, std::move(result).take_value());
        read(flow);
    }

    void deliver(const Flow& flow, ReceivedRecord record) noexcept {
        try {
            const auto payload = record.payload().bytes();
            const std::size_t size = flow.header.size() + payload.size();
            auto reservation = reply_budget.try_reserve(size);
            // Dropping the record returns its receive credit.
            if (!reservation) return;
            std::vector<std::uint8_t> datagram;
            datagram.reserve(size);
            datagram.insert(datagram.end(), flow.header.begin(), flow.header.end());
            const auto* bytes = reinterpret_cast<const std::uint8_t*>(payload.data());
            datagram.insert(datagram.end(), bytes, bytes + payload.size());
            replies.push_back({std::move(datagram), std::move(*reservation), record.take_credit()});
        } catch (...) {
            return;
        }
        send_next();
    }

    void send_next() noexcept {
        if (closed || sending || replies.empty()) return;
        sending = true;
        try {
            socket.async_send_to(boost::asio::buffer(replies.front().datagram), client,
                [self = shared_from_this()](const Error&, std::size_t) noexcept {
                    self->on_sent();
                });
        } catch (...) {
            sending = false;
            replies.pop_front();
        }
    }

    void on_sent() noexcept {
        sending = false;
        // A failed local send loses only this datagram.
        if (!replies.empty()) replies.pop_front();
        send_next();
    }

    void arm_timer(const FlowPtr& flow, std::chrono::milliseconds duration) noexcept {
        const std::uint64_t generation = ++flow->timer_generation;
        try {
            flow->timer.expires_after(duration);
            flow->timer.async_wait([self = shared_from_this(), flow, generation](const Error& error) noexcept {
                if (!error && generation == flow->timer_generation) self->on_timer(flow);
            });
        } catch (...) {
            remove(flow);
        }
    }

    void on_timer(const FlowPtr& flow) noexcept {
        if (closed) return;
        switch (flow->phase) {
        case Phase::Opening:
            hold(flow);
            return;
        case Phase::Holding:
            remove(flow);
            return;
        case Phase::Open: {
            const auto idle = Clock::now() - flow->last_activity;
            if (idle >= limits.udp_idle_timeout) {
                remove(flow);
            } else {
                arm_timer(flow, std::chrono::ceil<std::chrono::milliseconds>(
                    limits.udp_idle_timeout - idle));
            }
            return;
        }
        case Phase::Closed:
            return;
        }
    }

    // Keeps the destination entry so its datagrams are dropped until the retry
    // delay ends, which bounds how often a refused OPEN is repeated.
    void hold(const FlowPtr& flow) noexcept {
        if (flow->phase == Phase::Holding || flow->phase == Phase::Closed) return;
        flow->phase = Phase::Holding;
        release(*flow);
        arm_timer(flow, limits.udp_retry_delay);
    }

    void remove(const FlowPtr& flow) noexcept {
        if (flow->phase == Phase::Closed) return;
        const FlowPtr keep = flow;
        keep->phase = Phase::Closed;
        ++keep->timer_generation;
        Error ignored;
        keep->timer.cancel(ignored);
        release(*keep);
        const Flow* raw = keep.get();
        flows.remove_if([raw](const FlowPtr& value) { return value.get() == raw; });
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
    }

    void close() noexcept {
        if (closed) return;
        closed = true;
        Error ignored;
        socket.close(ignored);
        auto current = std::move(flows);
        flows.clear();
        for (const auto& flow : current) {
            flow->phase = Phase::Closed;
            ++flow->timer_generation;
            flow->timer.cancel(ignored);
            release(*flow);
        }
        pending_budget.close();
        reply_budget.close();
        // An in-flight send still references the front reply until its
        // completion runs.
        while (replies.size() > (sending ? 1U : 0U)) replies.pop_back();
    }

    std::shared_ptr<providers::AsioExecutionContext> context;
    const std::string service;
    const NativeSessionSource sessions;
    const NativeSocks5Limits limits;
    UdpSocket socket;
    Udp::endpoint relay;
    // The TCP peer's address. Its port stays zero until a datagram names it.
    Udp::endpoint client;
    Udp::endpoint sender;
    std::vector<std::uint8_t> receive_buffer;
    std::list<FlowPtr> flows;
    common::UdpQueueBudget pending_budget;
    common::UdpQueueBudget reply_budget;
    std::deque<QueuedReply> replies;
    bool sending{false};
    bool closed{false};
};

engine::Result<std::shared_ptr<NativeSocks5UdpAssociation>> NativeSocks5UdpAssociation::create(
    std::shared_ptr<providers::AsioExecutionContext> context,
    std::string service,
    NativeSessionSource sessions,
    const NativeSocks5Limits& limits,
    const boost::asio::ip::address& relay_address,
    boost::asio::ip::udp::endpoint client) {
    using Created = engine::Result<std::shared_ptr<NativeSocks5UdpAssociation>>;
    if (!context || !sessions || service.empty() || !relay_address.is_loopback() ||
        client.address().is_unspecified() ||
        limits.max_udp_destinations == 0U || limits.max_udp_destinations > 1024U ||
        limits.open_timeout <= std::chrono::milliseconds::zero() ||
        limits.udp_idle_timeout <= std::chrono::milliseconds::zero() ||
        limits.udp_retry_delay <= std::chrono::milliseconds::zero()) {
        return Created(Status(StatusCode::InvalidArgument));
    }
    context->require_context();
    try {
        auto state = std::make_shared<State>(context, std::move(service), std::move(sessions),
                                             limits, std::move(client));
        state->receive_buffer.resize(kReceiveBufferBytes);
        Error error;
        const Udp::endpoint local{relay_address, 0U};
        state->socket.open(local.protocol(), error);
        if (!error && relay_address.is_v6()) {
            state->socket.set_option(boost::asio::ip::v6_only(true), error);
        }
        if (!error) state->socket.bind(local, error);
        if (!error) state->relay = state->socket.local_endpoint(error);
        if (error) {
            return Created(diagnostic(StatusCode::Internal, "SOCKS5 UDP relay socket could not open"));
        }
        state->receive();
        return Created(std::shared_ptr<NativeSocks5UdpAssociation>(
            new NativeSocks5UdpAssociation(std::move(state))));
    } catch (const std::bad_alloc&) {
        return Created(Status(StatusCode::ResourceExhausted));
    } catch (...) {
        return Created(Status(StatusCode::Internal));
    }
}

NativeSocks5UdpAssociation::NativeSocks5UdpAssociation(std::shared_ptr<State> state) noexcept
    : state_(std::move(state)) {}

NativeSocks5UdpAssociation::~NativeSocks5UdpAssociation() noexcept { close(); }

boost::asio::ip::udp::endpoint NativeSocks5UdpAssociation::relay_endpoint() const noexcept {
    return state_->relay;
}

void NativeSocks5UdpAssociation::close() noexcept { state_->close(); }

}  // namespace yume::runtime
