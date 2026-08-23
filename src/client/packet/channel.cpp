/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/packet/channel.hpp"

#include <algorithm>
#include <condition_variable>
#include <mutex>
#include <system_error>

#include <boost/asio/ip/address_v4.hpp>
#include <nlohmann/json.hpp>

#include "client/transport/tunnel.hpp"

namespace yume::client::packet {
namespace {

std::uint16_t read_be16(const Bytes& bytes, std::size_t offset) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes[offset]) << 8) |
        static_cast<std::uint16_t>(bytes[offset + 1]));
}

std::uint32_t read_be32(const Bytes& bytes, std::size_t offset) {
    return (static_cast<std::uint32_t>(bytes[offset]) << 24) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 16) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 8) |
           static_cast<std::uint32_t>(bytes[offset + 3]);
}

struct OpenWaitState {
    std::mutex mu;
    std::condition_variable cv;
    bool done{false};
    bool ok{false};
    bool closed{false};
    std::string payload;
};

QueueResult queue_result(
    TransportCore::DataWriteAdmission admission) noexcept {
    using Admission = TransportCore::DataWriteAdmission;
    switch (admission) {
    case Admission::accepted: return QueueResult::ok;
    case Admission::would_block: return QueueResult::would_block;
    case Admission::timeout: return QueueResult::timeout;
    case Admission::stopped: return QueueResult::stopped;
    case Admission::invalid: return QueueResult::invalid;
    }
    return QueueResult::invalid;
}

}  // namespace

bool has_packet_bulk_capability(
    const std::vector<std::string>& server_capabilities) noexcept {
    return std::find(server_capabilities.begin(), server_capabilities.end(),
                     std::string(protocol::packet_bulk::kCapability)) !=
           server_capabilities.end();
}

bool parse_packet_assignment(const std::string& payload,
                             Assignment* assignment,
                             std::string* error) {
    if (!assignment) {
        if (error) *error = "packet assignment output is null";
        return false;
    }
    try {
        const auto json = nlohmann::json::parse(payload);
        if (json.value("proto", "") != protocol::packet_bulk::kOpenProto ||
            json.value("capability", "") != protocol::packet_bulk::kCapability ||
            !json.contains("dns") || !json["dns"].is_array()) {
            throw std::runtime_error("packet acknowledgement contract mismatch");
        }
        Assignment parsed;
        parsed.ipv4 = json.at("ipv4").get<std::string>();
        parsed.mtu = json.at("mtu").get<std::uint32_t>();
        const auto address = boost::asio::ip::make_address_v4(parsed.ipv4);
        parsed.ipv4_be = address.to_uint();
        if (parsed.mtu < 576 ||
            parsed.mtu > protocol::packet_bulk::kMaxPacketBytes) {
            throw std::runtime_error("packet acknowledgement MTU is invalid");
        }
        for (const auto& dns : json["dns"]) {
            if (!dns.is_string()) {
                throw std::runtime_error("packet acknowledgement DNS is invalid");
            }
            auto dns_text = dns.get<std::string>();
            (void)boost::asio::ip::make_address_v4(dns_text);
            parsed.dns_servers.push_back(std::move(dns_text));
        }
        *assignment = std::move(parsed);
        return true;
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
}

bool validate_assigned_ipv4_packet(const Assignment& assignment,
                                   const Bytes& packet,
                                   bool outbound,
                                   std::string* error) {
    auto fail = [&](const char* reason) {
        if (error) *error = reason;
        return false;
    };
    if (packet.size() < 20 || packet.size() > assignment.mtu) {
        return fail("packet length is outside the assigned MTU");
    }
    const std::uint8_t version = packet[0] >> 4;
    if (version != 4) {
        return fail(version == 6 ? "IPv6 is not supported by packet-bulk-v1"
                                 : "packet is not IPv4");
    }
    const std::size_t ihl = static_cast<std::size_t>(packet[0] & 0x0fU) * 4U;
    if (ihl < 20 || ihl > packet.size() ||
        read_be16(packet, 2) != packet.size()) {
        return fail("IPv4 packet header or total length is invalid");
    }
    const std::uint32_t address = read_be32(packet, outbound ? 12 : 16);
    if (address != assignment.ipv4_be) {
        return fail(outbound
            ? "packet source does not match assigned IPv4"
            : "packet destination does not match assigned IPv4");
    }
    return true;
}

PacketChannel::PacketChannel(
    std::shared_ptr<Tunnel> tunnel,
    std::shared_ptr<RuntimeLifetimeGate> lifetime_gate)
    : tunnel_(std::move(tunnel))
    , lifetime_gate_(std::move(lifetime_gate)) {}

PacketChannel::~PacketChannel() {
    close("packet channel destroyed");
}

std::shared_ptr<PacketChannel> PacketChannel::open(
    std::shared_ptr<Tunnel> tunnel,
    const std::vector<std::string>& server_capabilities,
    std::chrono::milliseconds timeout,
    std::string* error,
    std::shared_ptr<RuntimeLifetimeGate> lifetime_gate,
    OpenResult* open_result) {
    auto fail = [&](OpenStatus status, std::string detail) {
        if (error) *error = detail;
        if (open_result) {
            open_result->status = status;
            open_result->detail = std::move(detail);
        }
        return std::shared_ptr<PacketChannel>{};
    };
    auto succeed = [&] {
        if (error) error->clear();
        if (open_result) {
            open_result->status = OpenStatus::success;
            open_result->detail.clear();
        }
    };

    if (!tunnel) {
        return fail(OpenStatus::invalid_argument,
                    "packet channel requires a tunnel");
    }
    if (timeout.count() < 0) {
        return fail(OpenStatus::invalid_argument,
                    "packet channel OPEN timeout must be non-negative");
    }
    if (!tunnel->is_alive()) {
        return fail(OpenStatus::not_running,
                    "packet transport is not running");
    }
    if (!has_packet_bulk_capability(server_capabilities)) {
        return fail(OpenStatus::capability_unavailable,
                    "server does not advertise packet_bulk_v1");
    }

    struct RuntimeRefs {
        RuntimeLifetimeGate::Lease lease;
        std::shared_ptr<Tunnel> tunnel;
    } runtime;
    if (lifetime_gate) {
        runtime.lease = lifetime_gate->try_acquire();
        if (!runtime.lease) {
            return fail(OpenStatus::not_running,
                        "packet runtime is stopping");
        }
    }
    // RuntimeRefs declares the lease before the executor-bound pointer, so
    // reverse destruction drops Tunnel ownership before teardown can observe
    // the lease count reaching zero. Leave the by-value parameter empty.
    runtime.tunnel = std::move(tunnel);

    auto channel = std::shared_ptr<PacketChannel>(
        new PacketChannel(runtime.tunnel, lifetime_gate));
    channel->stream_id_ = runtime.tunnel->reserve_stream_id();
    if (channel->stream_id_ == 0) {
        if (!runtime.tunnel->is_alive() ||
            (lifetime_gate && !lifetime_gate->active())) {
            return fail(OpenStatus::not_running,
                        "packet transport stopped while reserving a stream");
        }
        return fail(OpenStatus::resource_exhausted,
                    "no stream id available for packet channel");
    }

    auto wait = std::make_shared<OpenWaitState>();
    std::weak_ptr<PacketChannel> weak = channel;
    runtime.tunnel->register_stream(
        channel->stream_id_,
        [weak](const Bytes& payload, Tunnel::InboundCredit credit) {
            if (auto self = weak.lock()) {
                self->on_data(payload, std::move(credit));
            }
        },
        [weak, wait](const std::string& reason) {
            {
                std::lock_guard<std::mutex> lock(wait->mu);
                wait->closed = true;
                if (!wait->done) wait->payload = reason;
            }
            wait->cv.notify_all();
            if (auto self = weak.lock()) self->stop_local(reason);
        });

    nlohmann::json request{
        {"proto", std::string(protocol::packet_bulk::kOpenProto)},
    };
    runtime.tunnel->open_relay_stream(
        channel->stream_id_, request,
        [wait](bool ok, const std::string& payload) {
            {
                std::lock_guard<std::mutex> lock(wait->mu);
                wait->done = true;
                wait->ok = ok;
                wait->payload = payload;
            }
            wait->cv.notify_all();
        });

    std::string ack;
    {
        std::unique_lock<std::mutex> lock(wait->mu);
        if (!wait->cv.wait_for(lock, timeout, [&] {
                return wait->done || wait->closed;
            })) {
            lock.unlock();
            // OPEN crossed the ordered transport but never received a peer
            // disposition. Keep this id tombstoned for the connection so a
            // late ACK or DATA record cannot alias a later packet channel.
            runtime.tunnel->retire_stream_id(channel->stream_id_);
            channel->close("packet channel OPEN timed out");
            return fail(OpenStatus::timeout,
                        "packet channel OPEN timed out");
        }
        if (!wait->done) {
            const std::string detail = wait->payload.empty()
                ? "packet transport closed during OPEN" : wait->payload;
            lock.unlock();
            channel->close(detail);
            return fail(OpenStatus::not_running, detail);
        }
        if (!wait->ok) {
            const std::string detail = wait->payload.empty()
                ? "packet channel OPEN rejected" : wait->payload;
            lock.unlock();
            channel->close(detail);
            return fail(OpenStatus::peer_rejected, detail);
        }
        ack = wait->payload;
    }
    std::string parse_error;
    if (!parse_packet_assignment(
            ack, &channel->assignment_, &parse_error)) {
        channel->close("malformed packet channel acknowledgement");
        return fail(OpenStatus::protocol_error, parse_error.empty()
            ? "malformed packet channel acknowledgement" : parse_error);
    }
    if (lifetime_gate && !lifetime_gate->active()) {
        channel->close("packet runtime stopped during OPEN");
        return fail(OpenStatus::not_running,
                    "packet runtime stopped during OPEN");
    }
    try {
        channel->sender_ = std::thread([self = channel.get()] {
            self->sender_loop();
        });
    } catch (const std::system_error& ex) {
        const std::string detail =
            std::string("packet sender could not start: ") + ex.what();
        channel->close(detail);
        return fail(OpenStatus::resource_exhausted, detail);
    }
    succeed();
    return channel;
}

QueueResult PacketChannel::write_packets(const std::vector<Bytes>& packets,
                                         std::string* error) {
    return write_packets(packets, std::chrono::milliseconds{0}, error);
}

QueueResult PacketChannel::write_packets(
    const std::vector<Bytes>& packets,
    std::chrono::milliseconds timeout,
    std::string* error) {
    if (closed_.load(std::memory_order_acquire)) {
        if (error) *error = "packet channel is closed";
        return QueueResult::stopped;
    }
    for (const auto& packet : packets) {
        if (!validate_assigned_ipv4_packet(assignment_, packet, true, error)) {
            stop_local(error ? *error : "invalid outbound packet");
            return QueueResult::invalid;
        }
    }
    return engine_.enqueue_outbound(packets, timeout, error);
}

QueueResult PacketChannel::read_packets(std::size_t max_packets,
                                        std::size_t max_bytes,
                                        std::chrono::milliseconds timeout,
                                        std::vector<Bytes>* packets,
                                        std::size_t* required_first_bytes) {
    return engine_.read_inbound(max_packets, max_bytes, timeout, packets,
                                required_first_bytes);
}

EngineStats PacketChannel::stats() const {
    return engine_.stats();
}

void PacketChannel::on_data(
    const Bytes& payload,
    runtime::InboundCredit inbound_credit) {
    std::string reason;
    auto batch = protocol::packet_bulk::decode_batch(payload, &reason);
    if (!batch.has_value()) {
        stop_local(reason);
        return;
    }
    for (const auto& packet : batch->packets) {
        if (!validate_assigned_ipv4_packet(
                assignment_, packet, false, &reason)) {
            stop_local(reason);
            return;
        }
    }
    const auto result = engine_.accept_inbound_batch(
        std::move(*batch), &reason, std::move(inbound_credit));
    if (result != QueueResult::ok) {
        stop_local(reason.empty() ? "packet inbound admission failed" : reason);
    }
}

void PacketChannel::sender_loop() {
    while (!closed_.load(std::memory_order_acquire)) {
        Bytes payload;
        std::string reason;
        const auto result = engine_.take_outbound_payload(
            &payload, std::chrono::milliseconds(100), &reason);
        if (result == QueueResult::timeout || result == QueueResult::would_block) {
            continue;
        }
        if (result != QueueResult::ok) {
            stop_local(reason.empty() ? "packet sender stopped" : reason);
            break;
        }
        std::weak_ptr<PacketChannel> weak = weak_from_this();
        RuntimeLifetimeGate::Lease runtime_lease;
        if (lifetime_gate_) {
            runtime_lease = lifetime_gate_->try_acquire();
            if (!runtime_lease) {
                stop_local("packet runtime is stopping");
                break;
            }
        }
        auto tunnel = tunnel_.lock();
        if (!tunnel || !tunnel->is_alive()) {
            stop_local("packet transport is no longer active");
            break;
        }
        auto wait_send =
            [tunnel, stream_id = stream_id_, weak](
                Bytes&& pending,
                std::chrono::milliseconds timeout) {
                return queue_result(tunnel->wait_send_data(
                    stream_id, std::move(pending), timeout,
                    [weak](bool ok, std::size_t,
                           const std::string& error) {
                        if (!ok) {
                            if (auto self = weak.lock()) {
                                self->stop_local(error.empty()
                                    ? "packet transport write failed" : error);
                            }
                        }
                    }));
            };
        const auto admission = wait_for_transport_capacity(
            &payload, wait_send, closed_, &reason);
        if (admission != QueueResult::ok) {
            stop_local(reason.empty()
                ? "packet transport admission failed" : reason);
            break;
        }
    }
}

void PacketChannel::stop_local(const std::string& reason) {
    if (closed_.exchange(true, std::memory_order_acq_rel)) {
        return;
    }
    engine_.stop(reason);
    if (stream_id_ != 0) {
        RuntimeLifetimeGate::Lease runtime_lease;
        if (lifetime_gate_) {
            runtime_lease = lifetime_gate_->try_acquire();
            if (!runtime_lease) {
                return;
            }
        }
        if (auto tunnel = tunnel_.lock(); tunnel && tunnel->is_alive()) {
            tunnel->send_close(stream_id_, reason);
            tunnel->unregister_stream(stream_id_);
        }
    }
}

void PacketChannel::close(const std::string& reason) {
    stop_local(reason);
    std::lock_guard<std::mutex> lock(sender_join_mu_);
    if (sender_.joinable()) {
        // The sender holds a non-owning pointer and never calls close(); its
        // lifetime is controlled by external PacketChannel owners. Joining
        // is therefore the ownership invariant. Detaching here would let the
        // sender continue through a destroyed PacketChannel.
        sender_.join();
    }
}

}  // namespace yume::client::packet
