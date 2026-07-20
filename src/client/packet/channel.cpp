/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/packet/channel.hpp"

#include <algorithm>
#include <condition_variable>
#include <mutex>

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

PacketChannel::PacketChannel(std::shared_ptr<Tunnel> tunnel)
    : tunnel_(std::move(tunnel)) {}

PacketChannel::~PacketChannel() {
    close("packet channel destroyed");
}

std::shared_ptr<PacketChannel> PacketChannel::open(
    std::shared_ptr<Tunnel> tunnel,
    const std::vector<std::string>& server_capabilities,
    std::chrono::milliseconds timeout,
    std::string* error) {
    if (!tunnel) {
        if (error) *error = "packet channel requires a tunnel";
        return {};
    }
    if (!has_packet_bulk_capability(server_capabilities)) {
        if (error) *error = "server does not advertise packet_bulk_v1";
        return {};
    }

    auto channel = std::shared_ptr<PacketChannel>(
        new PacketChannel(std::move(tunnel)));
    channel->stream_id_ = channel->tunnel_->reserve_stream_id();
    if (channel->stream_id_ == 0) {
        if (error) *error = "no stream id available for packet channel";
        return {};
    }

    auto wait = std::make_shared<OpenWaitState>();
    std::weak_ptr<PacketChannel> weak = channel;
    channel->tunnel_->register_stream(
        channel->stream_id_,
        [weak](const Bytes& payload) {
            if (auto self = weak.lock()) self->on_data(payload);
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
    channel->tunnel_->open_relay_stream(
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
            if (error) *error = "packet channel OPEN timed out";
            lock.unlock();
            channel->close("packet channel OPEN timed out");
            return {};
        }
        if (!wait->done || !wait->ok) {
            if (error) {
                *error = wait->payload.empty()
                    ? "packet channel OPEN failed" : wait->payload;
            }
            lock.unlock();
            channel->close("packet channel OPEN failed");
            return {};
        }
        ack = wait->payload;
    }
    if (!parse_packet_assignment(ack, &channel->assignment_, error)) {
        channel->close("malformed packet channel acknowledgement");
        return {};
    }
    channel->sender_ = std::thread([self = channel.get()] {
        self->sender_loop();
    });
    return channel;
}

QueueResult PacketChannel::write_packets(const std::vector<Bytes>& packets,
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
    return engine_.enqueue_outbound(packets, error);
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

void PacketChannel::on_data(const Bytes& payload) {
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
    const auto result = engine_.accept_inbound_batch(std::move(*batch), &reason);
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
        if (!tunnel_->try_send_data(
                stream_id_, std::move(payload),
                [weak](bool ok, std::size_t, const std::string& error) {
                    if (!ok) {
                        if (auto self = weak.lock()) {
                            self->stop_local(error.empty()
                                ? "packet transport write failed" : error);
                        }
                    }
                })) {
            stop_local("packet transport backpressure");
            break;
        }
    }
}

void PacketChannel::stop_local(const std::string& reason) {
    if (closed_.exchange(true, std::memory_order_acq_rel)) {
        return;
    }
    engine_.stop(reason);
    if (tunnel_ && stream_id_ != 0) {
        tunnel_->send_close(stream_id_, reason);
        tunnel_->unregister_stream(stream_id_);
    }
}

void PacketChannel::close(const std::string& reason) {
    stop_local(reason);
    if (sender_.joinable()) {
        if (sender_.get_id() == std::this_thread::get_id()) {
            sender_.detach();
        } else {
            sender_.join();
        }
    }
}

}  // namespace yume::client::packet
