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
    const std::unordered_set<uint8_t>& batch_streams,
    bool rekey_blocked) {
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
                const bool allowed_during_rekey =
                    write.already_protected &&
                    (frame.header.type == protocol::REKEY_INIT ||
                     frame.header.type == protocol::REKEY_ACK);
                const std::size_t estimated_size = frame.payload.size() + 8U;
                const bool fits = current_batch_bytes == 0 ||
                    current_batch_bytes + estimated_size <= kMaxWriteBatchBytes;
                const bool new_stream = allow_already_selected_stream ||
                    batch_streams.count(stream_id) == 0;
                if ((!rekey_blocked || allowed_during_rekey) && fits && new_stream) {
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
        security::secure_erase(incoming_bytes_);
        incoming_offset_ = 0;
        if (inner_key_.has_value()) {
            security::secure_erase(*inner_key_);
            inner_key_.reset();
        }
        ratchet_.reset();
        outbound_rekey_wait_started_.reset();
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

void TransportCore::set_timing_handler(TimingHandler handler) {
    std::lock_guard<std::mutex> lock(state_mu_);
    timing_handler_ = std::move(handler);
}

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
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        if (stopped_) {
            return;
        }
        incoming_bytes_.insert(incoming_bytes_.end(), data, data + size);
    }

    while (true) {
        protocol::Frame frame{};
        bool have_frame = false;
        const char* fatal_reason = nullptr;
        {
            std::lock_guard<std::mutex> lock(state_mu_);
            if (stopped_) {
                return;
            }
            const std::size_t available = incoming_bytes_.size() - incoming_offset_;
            if (available < 8) {
                return;
            }
            const auto* frame_start = incoming_bytes_.data() + incoming_offset_;
            const auto header = parse_header(frame_start);
            if (header.len > kMaxFramePayloadBytes) {
                incoming_bytes_.clear();
                incoming_offset_ = 0;
                fatal_reason = "frame too large";
            } else {
                const std::size_t frame_bytes = 8U + static_cast<std::size_t>(header.len);
                if (available < frame_bytes) {
                    return;
                }
                frame.header = header;
                frame.payload.assign(frame_start + 8, frame_start + frame_bytes);
                incoming_offset_ += frame_bytes;
                if (incoming_offset_ == incoming_bytes_.size()) {
                    incoming_bytes_.clear();
                    incoming_offset_ = 0;
                } else if (incoming_offset_ >= 1024 * 1024 ||
                           incoming_offset_ * 2 >= incoming_bytes_.size()) {
                    incoming_bytes_.erase(incoming_bytes_.begin(),
                                          incoming_bytes_.begin() + static_cast<std::ptrdiff_t>(incoming_offset_));
                    incoming_offset_ = 0;
                }
                if ((frame.header.flags & protocol::kFlagPadded) != 0 &&
                    !protocol::strip_padding(frame)) {
                    incoming_bytes_.clear();
                    incoming_offset_ = 0;
                    fatal_reason = "malformed padded frame: pad length exceeds payload";
                } else {
                    have_frame = true;
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
        std::uint64_t open_timing_frames = 0;
        std::uint64_t open_timing_ns = 0;
        TimingHandler timing_handler;
        {
            std::lock_guard<std::mutex> lock(state_mu_);
            timing_handler = timing_handler_;
        }
        try {
            std::lock_guard<std::mutex> lock(state_mu_);
            if (ratchet_) {
                const bool collect_timing = static_cast<bool>(timing_handler);
                const auto open_started = collect_timing
                    ? std::chrono::steady_clock::now()
                    : std::chrono::steady_clock::time_point{};
                auto result = ratchet_->Open(
                    frame, std::chrono::steady_clock::now());
                if (collect_timing) {
                    timing_open_ns_ += static_cast<std::uint64_t>(
                        std::chrono::duration_cast<std::chrono::nanoseconds>(
                            std::chrono::steady_clock::now() - open_started).count());
                    ++timing_open_frames_;
                }
                opened_frame = std::move(result.application_frame);
                ratchet_response = std::move(result.control_response);
                rekey_completed = result.outbound_rekey_completed;
                if (timing_open_frames_ >= 64 || rekey_completed) {
                    open_timing_frames = timing_open_frames_;
                    open_timing_ns = timing_open_ns_;
                    timing_open_frames_ = 0;
                    timing_open_ns_ = 0;
                }
            }
        } catch (const std::exception& ex) {
            request_transport_close("ratchet open failed: " +
                                    std::string(ex.what()));
            return;
        }
        if (open_timing_frames > 0 && timing_handler) {
            timing_handler(
                "client.transport", "ratchet_open",
                "frames=" + std::to_string(open_timing_frames) +
                " us=" + std::to_string(open_timing_ns / 1000U));
        }
        if (ratchet_response.has_value()) {
            queue_frame(std::move(*ratchet_response), {}, true);
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
