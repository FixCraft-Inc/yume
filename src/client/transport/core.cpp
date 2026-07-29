/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/transport/core.hpp"

#include <algorithm>
#include <cstdio>
#include <thread>

#include "core/security/inner_crypto.hpp"
#include "core/security/secure_erase.hpp"
#include "client/transport/internal.hpp"

namespace yume::client {

using namespace detail;

std::optional<uint8_t> TransportCore::select_next_write_locked(
    std::size_t current_batch_bytes,
    const std::unordered_set<uint8_t>& batch_streams) {
    auto select = [&](bool allow_already_selected_stream) -> std::optional<uint8_t> {
        for (std::size_t priority = 0; priority < ready_streams_.size(); ++priority) {
            auto& ready = ready_streams_[priority];
            const std::size_t candidates = ready.size();
            for (std::size_t i = 0; i < candidates; ++i) {
                const uint8_t stream_id = ready.front();
                ready.pop_front();
                if (ready_priority_[stream_id] != static_cast<std::int8_t>(priority) ||
                    write_queues_[stream_id].empty()) {
                    continue;
                }
                const auto& write = write_queues_[stream_id].front();
                const auto& frame = write.frame;
                const std::size_t estimated_size = frame.payload.size() + 8U;
                const bool fits = current_batch_bytes == 0 ||
                    current_batch_bytes + estimated_size <= kMaxWriteBatchBytes;
                const bool new_stream = allow_already_selected_stream ||
                    batch_streams.count(stream_id) == 0;
                if (fits && new_stream) {
                    ready_priority_[stream_id] = -1;
                    return stream_id;
                }
                ready.push_back(stream_id);
            }
        }
        return std::nullopt;
    };

    auto stream_id = select(false);
    if (!stream_id.has_value()) {
        stream_id = select(true);
    }
    return stream_id;
}

TransportCore::TransportCore() {
    ready_priority_.fill(-1);
}

TransportCore::TransportCore(WriteHandler write_handler,
                             std::function<void(const std::string&)> close_transport_handler)
    : write_handler_(std::move(write_handler))
    , close_transport_handler_(std::move(close_transport_handler)) {
    ready_priority_.fill(-1);
}

void TransportCore::set_write_handler(WriteHandler handler) {
    std::lock_guard<std::mutex> lock(state_mu_);
    write_handler_ = std::move(handler);
}

void TransportCore::set_close_transport_handler(std::function<void(const std::string&)> handler) {
    std::lock_guard<std::mutex> lock(state_mu_);
    close_transport_handler_ = std::move(handler);
}

void TransportCore::start(std::chrono::steady_clock::time_point now) {
    std::lock_guard<std::mutex> lock(state_mu_);
    last_pong_ = now;
}

bool TransportCore::handle_keepalive_tick(std::chrono::steady_clock::time_point now, std::string* close_reason) {
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        if (stopped_) {
            if (close_reason) {
                *close_reason = "transport stopped";
            }
            return false;
        }
        if (now - last_pong_ > std::chrono::seconds(60)) {
            if (close_reason) {
                *close_reason = "keepalive timeout";
            }
            return false;
        }
    }

    protocol::Frame ping{{0, protocol::PING, 0, 0}, {}};
    queue_frame(ping);
    return true;
}

bool TransportCore::rekey_timed_out(
    std::chrono::steady_clock::time_point now) const {
    std::lock_guard<std::mutex> lock(state_mu_);
    return ratchet_ && ratchet_->rekey_timed_out(now);
}

std::vector<TransportCore::CloseHandler> TransportCore::shutdown() {
    std::vector<CloseHandler> close_callbacks;
    std::vector<WriteCompletion> write_callbacks;
    {
        std::lock_guard<std::mutex> state_lock(state_mu_);
        if (stopped_) {
            return close_callbacks;
        }
        stopped_ = true;
        close_callbacks.reserve(streams_.size());
        for (auto& entry : streams_) {
            if (entry.second.on_close) {
                close_callbacks.push_back(std::move(entry.second.on_close));
            }
        }
        streams_.clear();
        pending_open_.clear();
        pending_rlisten_.clear();
        reserved_streams_.clear();
        if (incoming_frame_.has_value()) {
            security::secure_erase(incoming_frame_->payload);
            incoming_frame_.reset();
        }
        incoming_header_.fill(0);
        incoming_header_bytes_ = 0;
        incoming_payload_bytes_ = 0;
        if (inner_key_.has_value()) {
            security::secure_erase(*inner_key_);
            inner_key_.reset();
        }
        ratchet_.reset();
#if YUME_ENABLE_DEV_DIAGNOSTICS
        outbound_rekey_wait_.reset();
        timing_open_.reset();
#endif
        clear_hop_key_cache_locked();
    }
    {
        std::lock_guard<std::mutex> write_lock(write_mu_);
        for (auto& queue : write_queues_) {
            while (!queue.empty()) {
                auto write = std::move(queue.front());
                queue.pop_front();
                release_write_reservation_locked(write);
                if (write.handler) {
                    write_callbacks.push_back(std::move(write.handler));
                }
            }
        }
        for (auto& ready : ready_streams_) {
            ready.clear();
        }
        ready_priority_.fill(-1);
        queued_frames_ = 0;
        // An active carrier write retains its reservation until its final
        // completion. Keeping write_in_flight_ set prevents a late callback
        // from starting another dispatch after shutdown.
    }
    for (auto& callback : write_callbacks) {
        callback(false, 0, "transport stopped");
    }
    return close_callbacks;
}

bool TransportCore::is_stopped() const {
    std::lock_guard<std::mutex> lock(state_mu_);
    return stopped_;
}

void TransportCore::clear_hop_key_cache_locked() {
    security::secure_erase(encrypt_hop_key_);
    security::secure_erase(decrypt_hop_key_);
    encrypt_hop_id_.reset();
    decrypt_hop_id_.reset();
}

void TransportCore::set_inner_key(const Bytes& key) {
    std::lock_guard<std::mutex> lock(state_mu_);
    inner_key_ = key;
    clear_hop_key_cache_locked();
}

void TransportCore::set_ratchet(
    std::unique_ptr<ratchet::SessionRatchet> ratchet) {
    if (!ratchet) throw std::invalid_argument("ratchet must not be null");
    std::lock_guard<std::mutex> lock(state_mu_);
    if (inner_key_.has_value()) {
        throw std::runtime_error("legacy inner key and YUME 2.0 ratchet are exclusive");
    }
    ratchet_ = std::move(ratchet);
}

void TransportCore::set_hop(bool enabled, std::uint32_t interval_ms, std::int64_t offset_ms) {
    std::lock_guard<std::mutex> lock(state_mu_);
    hop_enabled_ = enabled;
    hop_interval_ms_ = interval_ms;
    hop_offset_ms_ = offset_ms;
    clear_hop_key_cache_locked();
}

void TransportCore::set_server_in_charge(bool enabled) {
    std::lock_guard<std::mutex> lock(state_mu_);
    server_in_charge_ = enabled;
}

void TransportCore::set_obfs_shape(std::uint16_t pad_multiple, std::uint32_t jitter_ms_max) {
    std::lock_guard<std::mutex> lock(state_mu_);
    obfs_pad_multiple_ = pad_multiple > 256 ? std::uint16_t{256} : pad_multiple;
    obfs_jitter_ms_max_ = jitter_ms_max;
}

std::uint16_t TransportCore::obfs_pad_multiple() const {
    std::lock_guard<std::mutex> lock(state_mu_);
    return obfs_pad_multiple_;
}

std::uint32_t TransportCore::obfs_jitter_ms_max() const {
    std::lock_guard<std::mutex> lock(state_mu_);
    return obfs_jitter_ms_max_;
}

void TransportCore::set_allow_exec(bool enabled) {
    std::lock_guard<std::mutex> lock(state_mu_);
    allow_exec_ = enabled;
}

void TransportCore::set_reverse_handler(ReverseOpenHandler handler) {
    std::lock_guard<std::mutex> lock(state_mu_);
    reverse_handler_ = std::move(handler);
}

void TransportCore::set_control_handler(ControlHandler handler) {
    std::lock_guard<std::mutex> lock(state_mu_);
    control_handler_ = std::move(handler);
}

void TransportCore::set_inbound_open_handler(InboundOpenHandler handler) {
    std::lock_guard<std::mutex> lock(state_mu_);
    inbound_open_handler_ = std::move(handler);
}

void TransportCore::set_activity_handler(ActivityHandler handler) {
    std::lock_guard<std::mutex> lock(state_mu_);
    activity_handler_ = std::move(handler);
}

#if YUME_ENABLE_DEV_DIAGNOSTICS
void TransportCore::set_timing_handler(TimingHandler handler) {
    std::lock_guard<std::mutex> lock(state_mu_);
    timing_handler_ = std::move(handler);
    timing_open_.set_active(static_cast<bool>(timing_handler_));
}
#endif

void TransportCore::set_server_stream_open_handler(ServerStreamOpenHandler handler) {
    std::lock_guard<std::mutex> lock(state_mu_);
    server_stream_open_handler_ = std::move(handler);
}

void TransportCore::set_exec_handler(ExecHandler handler) {
    std::lock_guard<std::mutex> lock(state_mu_);
    exec_handler_ = std::move(handler);
}

bool TransportCore::has_stream_id_locked(uint8_t stream_id) const {
    return streams_.find(stream_id) != streams_.end() ||
           pending_open_.find(stream_id) != pending_open_.end() ||
           pending_rlisten_.find(stream_id) != pending_rlisten_.end() ||
           reserved_streams_.find(stream_id) != reserved_streams_.end();
}

uint8_t TransportCore::reserve_stream_id() {
    std::lock_guard<std::mutex> lock(state_mu_);
    if (stopped_) {
        return 0;
    }
    for (int i = 0; i < 255; ++i) {
        uint8_t candidate = next_stream_id_++;
        if (candidate == 0) {
            candidate = next_stream_id_++;
        }
        if (!has_stream_id_locked(candidate)) {
            reserved_streams_.insert(candidate);
            return candidate;
        }
    }
    return 0;
}

void TransportCore::register_stream(uint8_t stream_id,
                                    DataHandler on_data,
                                    CloseHandler on_close,
                                    HalfCloseHandler on_half_close) {
    std::lock_guard<std::mutex> lock(state_mu_);
    if (stopped_) {
        return;
    }
    reserved_streams_.erase(stream_id);
    streams_[stream_id] = StreamCallbacks{std::move(on_data), std::move(on_close), std::move(on_half_close)};
}

void TransportCore::unregister_stream(uint8_t stream_id) {
    std::lock_guard<std::mutex> lock(state_mu_);
    reserved_streams_.erase(stream_id);
    streams_.erase(stream_id);
    pending_open_.erase(stream_id);
}

void TransportCore::release_reserved_stream(uint8_t stream_id) {
    std::lock_guard<std::mutex> lock(state_mu_);
    reserved_streams_.erase(stream_id);
}

void TransportCore::open_stream(uint8_t stream_id,
                                const std::string& host,
                                int port,
                                OpenHandler handler,
                                const std::string& proto) {
    nlohmann::json json{{"host", host}, {"port", port}, {"proto", proto}};
    const std::string payload_str = json.dump();
    Bytes payload(payload_str.begin(), payload_str.end());
    uint16_t flags = 0;
    bool stopped = false;
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        stopped = stopped_;
        if (inner_key_.has_value()) {
            flags |= protocol::kFlagInnerEncrypted;
        }
        reserved_streams_.erase(stream_id);
        pending_open_[stream_id] = std::move(handler);
    }
    if (stopped) {
        OpenHandler failed_handler;
        {
            std::lock_guard<std::mutex> lock(state_mu_);
            auto it = pending_open_.find(stream_id);
            if (it != pending_open_.end()) {
                failed_handler = std::move(it->second);
                pending_open_.erase(it);
            }
        }
        if (failed_handler) {
            failed_handler(false, "transport stopped");
        }
        return;
    }
    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::OPEN, stream_id, flags}, payload};
    queue_frame(frame);
}

void TransportCore::open_relay_stream(uint8_t stream_id, const nlohmann::json& json, OpenHandler handler) {
    const std::string payload_str = json.dump();
    Bytes payload(payload_str.begin(), payload_str.end());
    uint16_t flags = 0;
    bool stopped = false;
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        stopped = stopped_;
        if (inner_key_.has_value()) {
            flags |= protocol::kFlagInnerEncrypted;
        }
        reserved_streams_.erase(stream_id);
        pending_open_[stream_id] = std::move(handler);
    }
    if (stopped) {
        OpenHandler failed_handler;
        {
            std::lock_guard<std::mutex> lock(state_mu_);
            auto it = pending_open_.find(stream_id);
            if (it != pending_open_.end()) {
                failed_handler = std::move(it->second);
                pending_open_.erase(it);
            }
        }
        if (failed_handler) {
            failed_handler(false, "transport stopped");
        }
        return;
    }
    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::OPEN, stream_id, flags}, payload};
    queue_frame(frame);
}

void TransportCore::request_remote_listen(uint8_t listen_id,
                                          const std::string& bind_host,
                                          int port,
                                          OpenHandler handler,
                                          bool reclaim,
                                          int min_port,
                                          int max_port) {
    nlohmann::json json{{"port", port}, {"reclaim", reclaim}};
    if (!bind_host.empty()) {
        json["bind_host"] = bind_host;
    }
    if (min_port > 0) {
        json["min_port"] = min_port;
    }
    if (max_port > 0) {
        json["max_port"] = max_port;
    }
    const std::string payload_str = json.dump();
    Bytes payload(payload_str.begin(), payload_str.end());
    uint16_t flags = 0;
    bool stopped = false;
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        stopped = stopped_;
        if (inner_key_.has_value()) {
            flags |= protocol::kFlagInnerEncrypted;
        }
        reserved_streams_.erase(listen_id);
        pending_rlisten_[listen_id] = std::move(handler);
    }
    if (stopped) {
        OpenHandler failed_handler;
        {
            std::lock_guard<std::mutex> lock(state_mu_);
            auto it = pending_rlisten_.find(listen_id);
            if (it != pending_rlisten_.end()) {
                failed_handler = std::move(it->second);
                pending_rlisten_.erase(it);
            }
        }
        if (failed_handler) {
            failed_handler(false, "transport stopped");
        }
        return;
    }
    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::RLISTEN, listen_id, flags}, payload};
    queue_frame(frame);
}

void TransportCore::send_data(uint8_t stream_id, const Bytes& data) {
    Bytes payload = data;
    send_data(stream_id, std::move(payload));
}

void TransportCore::send_data(uint8_t stream_id, Bytes&& data) {
    if (!try_send_data(stream_id, std::move(data))) {
        request_transport_close("application write queue full");
    }
}

void TransportCore::send_data(uint8_t stream_id, Bytes&& data, WriteCompletion handler) {
    (void)try_send_data(stream_id, std::move(data), std::move(handler));
}

bool TransportCore::try_send_data(uint8_t stream_id,
                                  Bytes&& data,
                                  WriteCompletion handler) {
    uint16_t flags = 0;
    ActivityHandler activity_handler;
    bool stopped = false;
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        if (stopped_) {
            stopped = true;
        } else {
            if (inner_key_.has_value()) {
                flags |= protocol::kFlagInnerEncrypted;
            }
            if (!data.empty()) {
                activity_handler = activity_handler_;
            }
        }
    }
    if (stopped) {
        if (handler) {
            handler(false, 0, "transport stopped");
        }
        return false;
    }
    protocol::Frame frame{{static_cast<uint32_t>(data.size()), protocol::DATA, stream_id, flags}, std::move(data)};
    const bool accepted = queue_frame(std::move(frame), std::move(handler));
    if (accepted && activity_handler) {
        activity_handler();
    }
    return accepted;
}

void TransportCore::send_close(uint8_t stream_id, const std::string& reason) {
    Bytes payload(reason.begin(), reason.end());
    uint16_t flags = 0;
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        if (stopped_) {
            return;
        }
        if (inner_key_.has_value()) {
            flags |= protocol::kFlagInnerEncrypted;
        }
    }
    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::CLOSE, stream_id, flags}, payload};
    queue_frame(frame);
}

void TransportCore::send_stream_fin(uint8_t stream_id, const std::string& reason) {
    Bytes payload(reason.begin(), reason.end());
    uint16_t flags = protocol::kFlagStreamFin;
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        if (stopped_) {
            return;
        }
        if (inner_key_.has_value()) {
            flags |= protocol::kFlagInnerEncrypted;
        }
    }
    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::CLOSE, stream_id, flags}, payload};
    queue_frame(frame);
}

void TransportCore::send_open_ack(uint8_t stream_id, bool ok, const std::string& reason) {
    Bytes payload(reason.begin(), reason.end());
    uint16_t flags = ok ? protocol::kFlagOpenOk : 0;
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        if (stopped_) {
            return;
        }
        if (inner_key_.has_value()) {
            flags |= protocol::kFlagInnerEncrypted;
        }
    }
    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::OPEN, stream_id, flags}, payload};
    queue_frame(frame);
}

void TransportCore::send_exec(uint8_t stream_id, const std::string& command) {
    Bytes payload(command.begin(), command.end());
    uint16_t flags = 0;
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        if (stopped_) {
            return;
        }
        if (inner_key_.has_value()) {
            flags |= protocol::kFlagInnerEncrypted;
        }
    }
    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::EXEC, stream_id, flags}, payload};
    queue_frame(frame);
}

void TransportCore::send_control_json(const nlohmann::json& json) {
    const std::string payload_str = json.dump();
    Bytes payload(payload_str.begin(), payload_str.end());
    uint16_t flags = 0;
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        if (stopped_) {
            return;
        }
        if (inner_key_.has_value()) {
            flags |= protocol::kFlagInnerEncrypted;
        }
    }
    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::CONTROL, 0, flags}, payload};
    queue_frame(frame);
}

void TransportCore::feed_tls_bytes(const Bytes& data) {
    feed_tls_bytes(data.data(), data.size());
}

void TransportCore::feed_tls_bytes(const uint8_t* data, std::size_t size) {
    if (!data || size == 0) {
        return;
    }

    const std::uint8_t* cursor = data;
    std::size_t remaining = size;
    while (remaining > 0) {
        protocol::Frame frame{};
        bool have_frame = false;
        const char* fatal_reason = nullptr;
        {
            std::lock_guard<std::mutex> lock(state_mu_);
            if (stopped_) {
                return;
            }
            if (!incoming_frame_.has_value()) {
                const std::size_t header_bytes = std::min(
                    remaining, incoming_header_.size() - incoming_header_bytes_);
                std::copy_n(cursor, header_bytes,
                            incoming_header_.begin() +
                                static_cast<std::ptrdiff_t>(incoming_header_bytes_));
                cursor += header_bytes;
                remaining -= header_bytes;
                incoming_header_bytes_ += header_bytes;
                if (incoming_header_bytes_ < incoming_header_.size()) {
                    return;
                }

                const auto header = parse_header(incoming_header_.data());
                incoming_header_bytes_ = 0;
                if (header.len > kMaxFramePayloadBytes) {
                    fatal_reason = "frame too large";
                } else {
                    incoming_frame_.emplace();
                    incoming_frame_->header = header;
                    incoming_frame_->payload.resize(header.len);
                    incoming_payload_bytes_ = 0;
                }
            }

            if (!fatal_reason && incoming_frame_.has_value()) {
                const std::size_t payload_remaining =
                    incoming_frame_->payload.size() - incoming_payload_bytes_;
                const std::size_t payload_bytes =
                    std::min(remaining, payload_remaining);
                if (payload_bytes > 0) {
                    std::copy_n(
                        cursor, payload_bytes,
                        incoming_frame_->payload.begin() +
                            static_cast<std::ptrdiff_t>(incoming_payload_bytes_));
                    cursor += payload_bytes;
                    remaining -= payload_bytes;
                    incoming_payload_bytes_ += payload_bytes;
                }
                if (incoming_payload_bytes_ == incoming_frame_->payload.size()) {
                    frame = std::move(*incoming_frame_);
                    incoming_frame_.reset();
                    incoming_payload_bytes_ = 0;
                    if ((frame.header.flags & protocol::kFlagPadded) != 0 &&
                        !protocol::strip_padding(frame)) {
                        fatal_reason =
                            "malformed padded frame: pad length exceeds payload";
                    } else {
                        have_frame = true;
                    }
                }
            }
        }

        if (fatal_reason) {
            request_transport_close(fatal_reason);
            return;
        }

        if (!have_frame) {
            return;
        }
        std::optional<protocol::Frame> opened_frame;
        std::optional<protocol::Frame> ratchet_response;
        bool rekey_completed = false;
#if YUME_ENABLE_DEV_DIAGNOSTICS
        std::optional<diagnostics::TimingSample> open_timing;
        TimingHandler timing_handler;
        {
            std::lock_guard<std::mutex> lock(state_mu_);
            timing_handler = timing_handler_;
        }
#endif
        try {
            std::lock_guard<std::mutex> lock(state_mu_);
            if (ratchet_) {
#if YUME_ENABLE_DEV_DIAGNOSTICS
                const bool collect_timing = static_cast<bool>(timing_handler);
                diagnostics::Stopwatch open_timer(collect_timing);
#endif
                auto result = ratchet_->Open(
                    frame, std::chrono::steady_clock::now());
                opened_frame = std::move(result.application_frame);
                ratchet_response = std::move(result.control_response);
                rekey_completed = result.outbound_rekey_completed;
#if YUME_ENABLE_DEV_DIAGNOSTICS
                timing_open_.record(open_timer);
                open_timing = timing_open_.take_if(64, rekey_completed);
#endif
            }
        } catch (const std::exception& ex) {
            request_transport_close("ratchet open failed: " +
                                    std::string(ex.what()));
            return;
        }
#if YUME_ENABLE_DEV_DIAGNOSTICS
        if (open_timing.has_value()) {
            YUME_TIMING_SINK(
                timing_handler, "client.transport", "ratchet_open",
                "frames=" + std::to_string(open_timing->count) +
                " us=" + std::to_string(open_timing->total_ns / 1000U));
        }
#endif
        if (ratchet_response.has_value()) {
            // Sealed by the write path, not here: sequence numbers must be
            // assigned in wire order and dispatch_next_write is the only
            // place that seals.
            queue_frame(std::move(*ratchet_response), {}, false);
        }
        if (rekey_completed) {
            resume_writes_after_rekey();
        }
        bool has_ratchet = false;
        {
            std::lock_guard<std::mutex> lock(state_mu_);
            has_ratchet = ratchet_ != nullptr;
        }
        if (has_ratchet) {
            if (!opened_frame.has_value()) {
                continue;
            }
            frame = std::move(*opened_frame);
        }
        handle_frame(frame);
        if (is_stopped()) {
            return;
        }
    }
}

void TransportCore::request_transport_close(const std::string& reason) {
    std::function<void(const std::string&)> close_transport_handler;
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        close_transport_handler = close_transport_handler_;
    }
    if (close_transport_handler) {
        close_transport_handler(reason);
    }
}

}  // namespace yume::client
