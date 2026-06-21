/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "client/transport/core.hpp"

#include <algorithm>
#include <cstdio>
#include <thread>

#include "core/security/inner_crypto.hpp"
#include "client/transport/internal.hpp"

namespace yume::client {

using namespace detail;

std::deque<TransportCore::PendingWrite>::iterator TransportCore::select_next_write_locked(
    std::size_t current_batch_bytes,
    const std::unordered_set<uint8_t>& batch_streams) {
    auto select = [&](bool allow_already_selected_stream) {
        auto best = write_queue_.end();
        int best_priority = 999;
        std::size_t best_size = 0;
        std::size_t best_index = 0;
        std::size_t index = 0;
        for (auto it = write_queue_.begin(); it != write_queue_.end(); ++it, ++index) {
            const auto& frame = it->frame;
            const std::size_t estimated_size = frame.payload.size() + 8U;
            if (current_batch_bytes > 0 && current_batch_bytes + estimated_size > kMaxWriteBatchBytes) {
                continue;
            }
            if (!allow_already_selected_stream && batch_streams.count(frame.header.stream_id) != 0) {
                continue;
            }

            bool blocked_by_same_stream = false;
            for (auto prior = write_queue_.begin(); prior != it; ++prior) {
                if (prior->frame.header.stream_id == frame.header.stream_id) {
                    blocked_by_same_stream = true;
                    break;
                }
            }
            if (blocked_by_same_stream) {
                continue;
            }

            const int priority = frame_write_priority(frame);
            if (best == write_queue_.end() ||
                priority < best_priority ||
                (priority == best_priority && estimated_size < best_size) ||
                (priority == best_priority && estimated_size == best_size && index < best_index)) {
                best = it;
                best_priority = priority;
                best_size = estimated_size;
                best_index = index;
            }
        }
        return best;
    };

    auto it = select(false);
    if (it == write_queue_.end()) {
        it = select(true);
    }
    return it;
}

TransportCore::TransportCore(WriteHandler write_handler,
                             std::function<void(const std::string&)> close_transport_handler)
    : write_handler_(std::move(write_handler))
    , close_transport_handler_(std::move(close_transport_handler)) {}

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

std::vector<TransportCore::CloseHandler> TransportCore::shutdown() {
    std::vector<CloseHandler> close_callbacks;
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
        incoming_bytes_.clear();
        incoming_offset_ = 0;
    }
    {
        std::lock_guard<std::mutex> write_lock(write_mu_);
        write_queue_.clear();
        write_in_flight_ = false;
    }
    return close_callbacks;
}

bool TransportCore::is_stopped() const {
    std::lock_guard<std::mutex> lock(state_mu_);
    return stopped_;
}

void TransportCore::clear_hop_key_cache_locked() {
    std::fill(encrypt_hop_key_.begin(), encrypt_hop_key_.end(), 0);
    std::fill(decrypt_hop_key_.begin(), decrypt_hop_key_.end(), 0);
    encrypt_hop_key_.clear();
    decrypt_hop_key_.clear();
    encrypt_hop_id_.reset();
    decrypt_hop_id_.reset();
}

void TransportCore::set_inner_key(const Bytes& key) {
    std::lock_guard<std::mutex> lock(state_mu_);
    inner_key_ = key;
    clear_hop_key_cache_locked();
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
    streams_[stream_id] = StreamCallbacks{std::move(on_data), std::move(on_close), std::move(on_half_close)};
}

void TransportCore::unregister_stream(uint8_t stream_id) {
    std::lock_guard<std::mutex> lock(state_mu_);
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
                                          int port,
                                          OpenHandler handler,
                                          bool reclaim,
                                          int min_port,
                                          int max_port) {
    nlohmann::json json{{"port", port}, {"reclaim", reclaim}};
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
    send_data(stream_id, std::move(data), {});
}

void TransportCore::send_data(uint8_t stream_id, Bytes&& data, WriteCompletion handler) {
    uint16_t flags = 0;
    ActivityHandler activity_handler;
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        if (stopped_) {
            if (handler) {
                handler(false, 0, "transport stopped");
            }
            return;
        }
        if (inner_key_.has_value()) {
            flags |= protocol::kFlagInnerEncrypted;
        }
        if (!data.empty()) {
            activity_handler = activity_handler_;
        }
    }
    protocol::Frame frame{{static_cast<uint32_t>(data.size()), protocol::DATA, stream_id, flags}, std::move(data)};
    queue_frame(std::move(frame), std::move(handler));
    if (activity_handler) {
        activity_handler();
    }
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
