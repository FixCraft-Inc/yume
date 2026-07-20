/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * ----------------------------------------------------------------
 * Session extension channels, extracted verbatim from session.cpp:
 *   - federation relay  (attach_federated_stream, complete_federated_open,
 *                        send_federated_data / send_federated_close)
 *   - packet egress     (handle_packet_open / handle_packet_data,
 *                        queue_packet_downstream, flush_packet_downstream)
 *   - throughput bench  (handle_bench_open / data / close, pump_bench_sources,
 *                        maybe_finish_bench_source)
 *
 * Same Session:: class, same wire output, no behavior change. Shared
 * helpers via server/session/internal.hpp.
 * ---------------------------------------------------------------- */

#include "server/session/session.hpp"
#include "server/runtime/manager.hpp"
#include "server/session/internal.hpp"

#include <stdexcept>

namespace yume::server {

using namespace detail;

bool Session::attach_federated_stream(uint8_t stream_id,
                                      control::ChannelKind channel_kind,
                                      const std::string& channel_id,
                                      const std::string& left_endpoint_id,
                                      const std::string& right_endpoint_id,
                                      std::function<void(const crypto::Bytes&)> on_data,
                                      std::function<void(const std::string&)> on_close) {
    if (stream_id == 0) {
        return false;
    }
    std::lock_guard<std::mutex> lock(control_mutex_);
    if (federated_streams_.find(stream_id) != federated_streams_.end()) {
        return false;
    }
    FederatedStream stream;
    stream.channel_kind = channel_kind;
    stream.channel_id = channel_id;
    stream.left_endpoint_id = left_endpoint_id;
    stream.right_endpoint_id = right_endpoint_id;
    stream.on_data = std::move(on_data);
    stream.on_close = std::move(on_close);
    federated_streams_[stream_id] = std::move(stream);
    return true;
}

void Session::complete_federated_open(uint8_t stream_id, bool ok, const std::string& message) {
    std::string channel_id;
    control::ChannelKind channel_kind{control::ChannelKind::chat};
    std::string left_endpoint_id;
    std::string right_endpoint_id;
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        auto it = federated_streams_.find(stream_id);
        if (it == federated_streams_.end()) {
            return;
        }
        channel_id = it->second.channel_id;
        channel_kind = it->second.channel_kind;
        left_endpoint_id = it->second.left_endpoint_id;
        right_endpoint_id = it->second.right_endpoint_id;
        if (ok) {
            it->second.pending = false;
        } else {
            federated_streams_.erase(it);
        }
    }
    if (ok && manager_ && !channel_id.empty()) {
        control::ActiveRelayChannel channel;
        channel.channel_id = channel_id;
        channel.channel_kind = channel_kind;
        channel.left_endpoint_id = left_endpoint_id;
        channel.right_endpoint_id = right_endpoint_id;
        channel.left_stream_id = stream_id;
        channel.right_stream_id = 0;
        channel.pending = false;
        channel.federated = true;
        channel.route_hops = 1;
        manager_->register_active_channel(channel);
    }
    if (!ok && manager_ && !channel_id.empty()) {
        manager_->unregister_active_channel(channel_id);
    }
    send_open_reply(stream_id, ok, message);
}

void Session::send_federated_data(uint8_t stream_id, const crypto::Bytes& payload) {
    send_control_frame(protocol::DATA, stream_id, payload);
}

void Session::send_federated_close(uint8_t stream_id, const std::string& reason) {
    std::string channel_id;
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        auto it = federated_streams_.find(stream_id);
        if (it != federated_streams_.end()) {
            channel_id = it->second.channel_id;
            federated_streams_.erase(it);
        }
    }
    if (manager_ && !channel_id.empty()) {
        manager_->unregister_active_channel(channel_id);
    }
    send_control_close(stream_id, reason);
}

bool Session::handle_packet_open(uint8_t stream_id) {
    if (!manager_ || !manager_->packet_egress_active()) {
        send_open_reply(stream_id, false, "packet egress unavailable");
        return false;
    }
    if (packet_stream_.has_value()) {
        send_open_reply(stream_id, false, "packet stream already open");
        return false;
    }

    auto weak = weak_from_this();
    auto assignment = manager_->register_packet_client(
        this,
        [weak](crypto::Bytes packet) mutable {
            if (auto self = weak.lock()) {
                boost::asio::post(self->strand_, [self, packet = std::move(packet)]() mutable {
                    self->queue_packet_downstream(std::move(packet));
                });
            }
        });
    if (!assignment.has_value()) {
        send_open_reply(stream_id, false, "packet client address unavailable");
        return false;
    }

    PacketStream packet;
    packet.stream_id = stream_id;
    packet.client_ipv4_be = assignment->ipv4_be;
    packet.client_ipv4 = assignment->ipv4;
    packet.mtu = assignment->mtu;
    packet.dns_servers = assignment->dns_servers;
    packet.downstream_encoded_bytes = protocol::packet_bulk::kHeaderBytes;
    packet.open_started_ms = util::now_ms();
    packet.flush_timer = std::make_unique<boost::asio::steady_timer>(stream_.get_executor());
    packet_stream_ = std::move(packet);

    nlohmann::json ack{
        {"proto", std::string(protocol::packet_bulk::kOpenProto)},
        {"capability", std::string(protocol::packet_bulk::kCapability)},
        {"ipv4", assignment->ipv4},
        {"mtu", assignment->mtu},
        {"dns", assignment->dns_servers},
    };
    send_open_reply(stream_id, true, ack.dump());
    util::log_info("session " + std::to_string(session_id_) +
                   ": packet-bulk stream " + std::to_string(stream_id) +
                   " assigned " + assignment->ipv4 +
                   " mtu=" + std::to_string(assignment->mtu));
    return true;
}

bool Session::handle_packet_data(uint8_t stream_id, const crypto::Bytes& payload) {
    if (!packet_stream_.has_value() || packet_stream_->stream_id != stream_id) {
        return false;
    }
    std::string error;
    auto batch = protocol::packet_bulk::decode_batch(payload, &error);
    if (!batch.has_value()) {
        util::log_warn("session " + std::to_string(session_id_) +
                       ": closing malformed packet-bulk stream " +
                       std::to_string(stream_id) + ": " + error);
        handle_close(stream_id, error);
        send_control_close(stream_id, error);
        return true;
    }
    if (packet_stream_->upstream_sequence_exhausted ||
        batch->sequence != packet_stream_->next_upstream_sequence) {
        const std::string reason = "packet-bulk sequence mismatch";
        handle_close(stream_id, reason);
        send_control_close(stream_id, reason);
        return true;
    }
    if (packet_stream_->next_upstream_sequence == 0x7FFF'FFFF'FFFF'FFFFull) {
        packet_stream_->upstream_sequence_exhausted = true;
    } else {
        packet_stream_->next_upstream_sequence += 1;
    }
    for (const auto& packet : batch->packets) {
        std::string reason;
        if (packet.size() > packet_stream_->mtu) {
            reason = "packet exceeds assigned MTU";
        }
        if (!reason.empty() ||
            !validate_client_ipv4_packet(packet, packet_stream_->client_ipv4_be, &reason)) {
            util::log_warn("session " + std::to_string(session_id_) +
                           ": closing invalid packet-bulk stream " +
                           std::to_string(stream_id) + ": " + reason);
            handle_close(stream_id, reason);
            send_control_close(stream_id, reason);
            return true;
        }
        if (manager_) {
            const std::uint32_t dst_be = read_ipv4_be(packet, 16);
            boost::asio::ip::address_v4::bytes_type dst_bytes{{
                static_cast<unsigned char>((dst_be >> 24) & 0xffu),
                static_cast<unsigned char>((dst_be >> 16) & 0xffu),
                static_cast<unsigned char>((dst_be >> 8) & 0xffu),
                static_cast<unsigned char>(dst_be & 0xffu),
            }};
            const boost::asio::ip::address dst = boost::asio::ip::address_v4(dst_bytes);
            std::string filter_reason;
            if (!manager_->egress_allowed(dst, &filter_reason)) {
                const std::string reason = "packet destination rejected" +
                    (filter_reason.empty() ? std::string{} : ": " + filter_reason);
                util::log_info("session " + std::to_string(session_id_) +
                               ": closing packet-bulk stream for destination " +
                               dst.to_string() + ": " + reason);
                handle_close(stream_id, reason);
                send_control_close(stream_id, reason);
                return true;
            }
        }
    }
    packet_stream_->upstream_batches += 1;
    packet_stream_->upstream_packets += batch->packets.size();
    if (manager_ && !manager_->write_packets_to_egress(
            packet_stream_->client_ipv4_be, std::move(batch->packets))) {
        const std::string reason = "packet egress queue saturated or unavailable";
        handle_close(stream_id, reason);
        send_control_close(stream_id, reason);
        return true;
    }
    return true;
}

void Session::queue_packet_downstream(crypto::Bytes packet) {
    if (!packet_stream_.has_value() || close_state_ != CloseState::Open) {
        return;
    }
    auto& stream = *packet_stream_;
    if (!protocol::packet_bulk::can_append_packet(stream.downstream_encoded_bytes,
                                                  stream.downstream_packets.size(),
                                                  packet.size())) {
        flush_packet_downstream();
    }
    if (!protocol::packet_bulk::can_append_packet(stream.downstream_encoded_bytes,
                                                  stream.downstream_packets.size(),
                                                  packet.size())) {
        return;
    }
    const std::size_t base = stream.downstream_packets.empty()
        ? protocol::packet_bulk::kHeaderBytes
        : stream.downstream_encoded_bytes;
    stream.downstream_encoded_bytes = base + protocol::packet_bulk::kPacketLengthBytes + packet.size();
    stream.downstream_packets.push_back(std::move(packet));
    stream.downstream_packet_count += 1;
    if (stream.downstream_packets.size() >= protocol::packet_bulk::kMaxPacketsPerBatch ||
        stream.downstream_encoded_bytes >= protocol::packet_bulk::kDefaultMaxBatchBytes) {
        flush_packet_downstream();
        return;
    }
    auto* timer = stream.flush_timer.get();
    if (!timer) {
        return;
    }
    timer->expires_after(std::chrono::microseconds(protocol::packet_bulk::kDefaultFlushDelayMicros));
    auto self = shared_from_this();
    timer->async_wait(boost::asio::bind_executor(
        strand_,
        [self](const boost::system::error_code& ec) {
            if (!ec) {
                self->flush_packet_downstream();
            }
        }));
}

void Session::flush_packet_downstream() {
    if (!packet_stream_.has_value() || packet_stream_->downstream_packets.empty()) {
        return;
    }
    auto& stream = *packet_stream_;
    if (stream.flush_timer) {
        boost::system::error_code ec;
        stream.flush_timer->cancel(ec);
    }
    std::vector<crypto::Bytes> packets;
    packets.reserve(stream.downstream_packets.size());
    while (!stream.downstream_packets.empty()) {
        packets.push_back(std::move(stream.downstream_packets.front()));
        stream.downstream_packets.pop_front();
    }
    stream.downstream_encoded_bytes = protocol::packet_bulk::kHeaderBytes;
    protocol::packet_bulk::Batch batch;
    batch.sequence = stream.downstream_sequence++;
    batch.packets = std::move(packets);
    crypto::Bytes payload;
    try {
        payload = protocol::packet_bulk::encode_batch(batch);
    } catch (const std::exception& ex) {
        util::log_warn("session " + std::to_string(session_id_) +
                       ": failed to encode downstream packet batch: " + ex.what());
        return;
    }
    std::uint16_t flags = 0;
    if (inner_key_.has_value()) {
        payload = encrypt_inner_payload(protocol::DATA, stream.stream_id, payload);
        flags |= protocol::kFlagInnerEncrypted;
    }
    stream.downstream_batches += 1;
    protocol::Frame frame{{static_cast<std::uint32_t>(payload.size()), protocol::DATA, stream.stream_id, flags}, payload};
    queue_frame_on_strand(frame);
}

bool Session::handle_bench_open(uint8_t stream_id, const std::string& proto, const nlohmann::json& json) {
    if (!cfg_.benchmark_enable) {
        send_open_reply(stream_id, false, "benchmark disabled on server");
        return true;
    }

    std::uint64_t requested = 0;
    try {
        requested = json.value("bytes", static_cast<std::uint64_t>(0));
    } catch (...) {
        requested = 0;
    }
    if (requested == 0 || requested > kBenchMaxBytes) {
        send_open_reply(stream_id, false, "invalid benchmark byte count");
        return true;
    }

    BenchStream bench;
    bench.mode = (proto == kBenchSourceProto) ? BenchStream::Mode::Source : BenchStream::Mode::Sink;
    bench.requested_bytes = requested;
    bench.open_started_ms = util::now_ms();
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        bench_streams_[stream_id] = bench;
        if (bench.mode == BenchStream::Mode::Source) {
            bench_source_budget_.activate(stream_id);
        }
    }

    send_open_reply(stream_id, true, "");
    util::log_info("session " + std::to_string(session_id_) +
                   ": benchmark stream " + std::to_string(stream_id) +
                   " proto=" + proto +
                   " bytes=" + std::to_string(requested));
    if (bench.mode == BenchStream::Mode::Source) {
        pump_bench_sources();
    }
    return true;
}

bool Session::handle_bench_data(uint8_t stream_id, const crypto::Bytes& payload) {
    std::lock_guard<std::mutex> lock(streams_mutex_);
    auto it = bench_streams_.find(stream_id);
    if (it == bench_streams_.end()) {
        return false;
    }
    if (it->second.mode == BenchStream::Mode::Sink) {
        it->second.upstream_bytes += static_cast<std::uint64_t>(payload.size());
    }
    return true;
}

bool Session::handle_bench_close(uint8_t stream_id, const std::string& reason) {
    BenchStream bench;
    std::size_t reservation_current = 0;
    std::size_t reservation_peak = 0;
    std::size_t reservation_ready_sources = 0;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = bench_streams_.find(stream_id);
        if (it == bench_streams_.end()) {
            return false;
        }
        bench = it->second;
        bench_streams_.erase(it);
        bench_source_budget_.deactivate(stream_id);
        reservation_current = bench_source_budget_.reserved();
        reservation_peak = bench_source_budget_.peak_reserved();
        reservation_ready_sources = bench_source_budget_.ready_sources();
    }

    const int64_t elapsed_ms = bench.open_started_ms > 0 ? (util::now_ms() - bench.open_started_ms) : 0;
    if (bench.mode == BenchStream::Mode::Sink) {
        nlohmann::json summary{
            {"mode", "up"},
            {"bytes", bench.upstream_bytes},
            {"requested_bytes", bench.requested_bytes},
            {"server_ms", elapsed_ms},
        };
        const std::string out = summary.dump();
        send_control_frame(protocol::DATA, stream_id, crypto::Bytes(out.begin(), out.end()));
    }
    send_control_close(stream_id, reason.empty() ? "benchmark complete" : reason);
    util::log_timing("server.stream",
                     "summary",
                     "session=" + std::to_string(session_id_) +
                         " stream=" + std::to_string(stream_id) +
                         " proto=bench " +
                         "mode=" + std::string(bench.mode == BenchStream::Mode::Sink ? "sink" : "source") +
                         " ms=" + std::to_string(elapsed_ms) +
                         " upstream=" + std::to_string(bench.upstream_bytes) +
                         " downstream=" + std::to_string(bench.downstream_bytes) +
                         " requested=" + std::to_string(bench.requested_bytes) +
                         " reservation_current=" + std::to_string(reservation_current) +
                         " reservation_peak=" + std::to_string(reservation_peak) +
                         " reservation_ready_sources=" +
                             std::to_string(reservation_ready_sources));
    return true;
}

void Session::pump_bench_sources() {
    while (true) {
        uint8_t stream_id = 0;
        std::uint64_t offset = 0;
        std::size_t chunk_size = 0;
        {
            std::lock_guard<std::mutex> lock(streams_mutex_);
            if (bench_source_budget_.full()) {
                return;
            }

            // Only a stream head is considered on each pass. Re-queueing the
            // chosen source at the tail makes the aggregate 64-frame window
            // fair even when many sources become active at once.
            const auto next_stream = bench_source_budget_.pop_ready();
            if (!next_stream.has_value()) {
                return;
            }
            stream_id = *next_stream;
            auto it = bench_streams_.find(stream_id);
            if (it == bench_streams_.end() ||
                it->second.mode != BenchStream::Mode::Source ||
                it->second.close_sent) {
                continue;
            }
            auto& bench = it->second;
            if (bench.downstream_bytes >= bench.requested_bytes) {
                continue;
            }
            const std::uint64_t remaining = bench.requested_bytes - bench.downstream_bytes;
            chunk_size = static_cast<std::size_t>(
                std::min<std::uint64_t>(remaining,
                                        util::server_relay_read_buf_size()));
            offset = bench.downstream_bytes;
            bench.downstream_bytes += static_cast<std::uint64_t>(chunk_size);
            bench.in_flight_frames += 1;
            if (!bench_source_budget_.reserve()) {
                throw std::logic_error("benchmark reservation budget raced");
            }
            if (bench.downstream_bytes < bench.requested_bytes) {
                bench_source_budget_.activate(stream_id);
            }
        }

        crypto::Bytes payload(chunk_size);
        for (std::size_t i = 0; i < chunk_size; ++i) {
            payload[i] = static_cast<std::uint8_t>((offset + i) & 0xffu);
        }
        auto self = shared_from_this();
        send_control_frame(
            protocol::DATA,
            stream_id,
            payload,
            0,
            [self, stream_id](const boost::system::error_code& ec, std::size_t) {
                bool stream_exists = false;
                bool should_close = false;
                {
                    std::lock_guard<std::mutex> lock(self->streams_mutex_);
                    self->bench_source_budget_.release();
                    auto it = self->bench_streams_.find(stream_id);
                    if (it != self->bench_streams_.end()) {
                        stream_exists = true;
                        if (it->second.in_flight_frames > 0) {
                            it->second.in_flight_frames -= 1;
                        }
                        if (ec && !it->second.close_sent) {
                            it->second.close_sent = true;
                            should_close = true;
                        }
                    }
                }
                if (should_close) {
                    self->handle_bench_close(stream_id, "benchmark write failed");
                } else if (stream_exists) {
                    self->maybe_finish_bench_source(stream_id);
                }
                self->pump_bench_sources();
            });
    }
}

void Session::maybe_finish_bench_source(uint8_t stream_id) {
    bool done = false;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = bench_streams_.find(stream_id);
        if (it == bench_streams_.end() ||
            it->second.mode != BenchStream::Mode::Source ||
            it->second.close_sent) {
            return;
        }
        auto& bench = it->second;
        done = bench.downstream_bytes >= bench.requested_bytes && bench.in_flight_frames == 0;
        if (done) {
            bench.close_sent = true;
        }
    }
    if (done) {
        handle_bench_close(stream_id, "benchmark complete");
    }
}

}  // namespace yume::server
