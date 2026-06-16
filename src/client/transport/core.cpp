/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "client/transport/core.hpp"

#include <cstdio>
#include <thread>

#include "core/inner_crypto.hpp"

namespace yume::client {

namespace {
// Must match the server's tolerance. Under Android/desktop upload
// congestion, encrypted DATA frames can sit behind large batched writes
// long enough to cross many hop ticks; accept the bounded adjacent-hop
// window instead of tearing down the whole transport on a stale frame.
constexpr std::uint64_t kHopDecryptWindow = 120;
constexpr std::size_t kMaxFramePayloadBytes = 16U * 1024U * 1024U;
constexpr std::size_t kMaxWriteBatchFrames = 64;
constexpr std::size_t kMaxWriteBatchBytes = 1024U * 1024U;

std::string payload_to_string(const std::vector<uint8_t>& payload) {
    return std::string(payload.begin(), payload.end());
}

protocol::FrameHeader parse_header(const uint8_t* bytes) {
    protocol::FrameHeader header{};
    header.len = (static_cast<uint32_t>(bytes[0]) << 24) |
                 (static_cast<uint32_t>(bytes[1]) << 16) |
                 (static_cast<uint32_t>(bytes[2]) << 8) |
                 static_cast<uint32_t>(bytes[3]);
    header.type = bytes[4];
    header.stream_id = bytes[5];
    header.flags = static_cast<uint16_t>(bytes[6] << 8) |
                   static_cast<uint16_t>(bytes[7]);
    return header;
}
}  // namespace

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

void TransportCore::set_inner_key(const Bytes& key) {
    std::lock_guard<std::mutex> lock(state_mu_);
    inner_key_ = key;
}

void TransportCore::set_hop(bool enabled, std::uint32_t interval_ms, std::int64_t offset_ms) {
    std::lock_guard<std::mutex> lock(state_mu_);
    hop_enabled_ = enabled;
    hop_interval_ms_ = interval_ms;
    hop_offset_ms_ = offset_ms;
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

void TransportCore::queue_frame(protocol::Frame frame, WriteCompletion handler) {
    bool dispatch = false;
    {
        std::lock_guard<std::mutex> state_lock(state_mu_);
        if (stopped_) {
            if (handler) {
                handler(false, 0, "transport stopped");
            }
            return;
        }
    }
    {
        std::lock_guard<std::mutex> write_lock(write_mu_);
        write_queue_.push_back({std::move(frame), std::move(handler)});
        if (!write_in_flight_) {
            write_in_flight_ = true;
            dispatch = true;
        }
    }
    if (dispatch) {
        dispatch_next_write();
    }
}

std::shared_ptr<TransportCore::Bytes> TransportCore::encode_outgoing_frame(const protocol::Frame& frame) {
    // Avoid copying the payload on the no-inner path: encode_frame and
    // encrypt_inner_payload both take const&, so the source frame's payload
    // can be passed through directly. Only the inner-encrypted path needs a
    // separate buffer to hold the AEAD output.
    const Bytes* eff_payload = &frame.payload;
    Bytes encrypted;
    if ((frame.header.flags & protocol::kFlagInnerEncrypted) != 0) {
        encrypted = encrypt_inner_payload(frame.header.type, frame.header.stream_id, frame.payload);
        eff_payload = &encrypted;
    }
    std::uint16_t pad_multiple = 0;
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        pad_multiple = obfs_pad_multiple_;
    }
    return std::make_shared<Bytes>(protocol::encode_frame(
        static_cast<protocol::FrameType>(frame.header.type),
        frame.header.stream_id,
        frame.header.flags,
        *eff_payload,
        pad_multiple));
}

void TransportCore::dispatch_next_write() {
    std::vector<PendingWrite> batch;
    WriteHandler writer;
    {
        std::lock_guard<std::mutex> write_lock(write_mu_);
        if (write_queue_.empty()) {
            write_in_flight_ = false;
            return;
        }
        std::size_t total_bytes = 0;
        for (auto it = write_queue_.begin();
             it != write_queue_.end() &&
             batch.size() < kMaxWriteBatchFrames &&
             total_bytes < kMaxWriteBatchBytes;
             ++it) {
            batch.push_back(*it);
            total_bytes += it->frame.payload.size() + 8;
        }
    }
    {
        std::lock_guard<std::mutex> state_lock(state_mu_);
        if (stopped_) {
            return;
        }
        writer = write_handler_;
    }
    if (!writer) {
        request_transport_close("transport writer unavailable");
        return;
    }

    std::shared_ptr<Bytes> encoded;
    std::vector<std::size_t> encoded_sizes;
    try {
        encoded_sizes.reserve(batch.size());
        if (batch.size() == 1) {
            encoded = encode_outgoing_frame(batch.front().frame);
            encoded_sizes.push_back(encoded->size());
        } else {
            encoded = std::make_shared<Bytes>();
            encoded->reserve(kMaxWriteBatchBytes);
            for (const auto& item : batch) {
                auto part = encode_outgoing_frame(item.frame);
                encoded_sizes.push_back(part->size());
                encoded->insert(encoded->end(), part->begin(), part->end());
            }
        }
    } catch (const std::exception& ex) {
        for (auto& item : batch) {
            if (item.handler) {
                item.handler(false, 0, ex.what());
            }
        }
        request_transport_close("frame encode failed: " + std::string(ex.what()));
        return;
    } catch (...) {
        for (auto& item : batch) {
            if (item.handler) {
                item.handler(false, 0, "unknown error");
            }
        }
        request_transport_close("frame encode failed: unknown error");
        return;
    }

    writer(encoded, [this, batch = std::move(batch), encoded_sizes = std::move(encoded_sizes)](
                        bool ok,
                        std::size_t bytes,
                        const std::string& error) mutable {
        bool dispatch = false;
        bool queue_empty = true;
        {
            std::lock_guard<std::mutex> write_lock(write_mu_);
            std::size_t popped = 0;
            while (popped < batch.size() && !write_queue_.empty()) {
                write_queue_.pop_front();
                ++popped;
            }
            queue_empty = write_queue_.empty();
            write_in_flight_ = !queue_empty;
        }
        const bool stopped = is_stopped();
        if (queue_empty || !ok || stopped) {
            std::lock_guard<std::mutex> write_lock(write_mu_);
            write_in_flight_ = false;
        } else {
            dispatch = true;
        }
        for (std::size_t i = 0; i < batch.size(); ++i) {
            auto& item = batch[i];
            if (item.handler) {
                const std::size_t item_bytes = ok && i < encoded_sizes.size() ? encoded_sizes[i] : bytes;
                item.handler(ok, item_bytes, error);
            }
        }
        if (!ok) {
            request_transport_close("write failed: " + error);
            return;
        }
        if (dispatch) {
            dispatch_next_write();
        }
    });
}

void TransportCore::handle_frame(const protocol::Frame& frame) {
    const uint8_t stream_id = frame.header.stream_id;
    Bytes decrypted_payload;
    const Bytes* payload = &frame.payload;
    bool inner_encrypted = false;
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        inner_encrypted = inner_key_.has_value() &&
                          ((frame.header.flags & protocol::kFlagInnerEncrypted) != 0);
    }
    if (inner_encrypted) {
        if (!decrypt_inner_payload(frame.header.type, stream_id, frame.payload, &decrypted_payload)) {
            request_transport_close("decrypt failed");
            return;
        }
        payload = &decrypted_payload;
    }

    switch (frame.header.type) {
        case protocol::OPEN: {
            OpenHandler handler;
            ActivityHandler activity_handler;
            bool is_remote_listen = false;
            {
                std::lock_guard<std::mutex> lock(state_mu_);
                auto it_listen = pending_rlisten_.find(stream_id);
                if (it_listen != pending_rlisten_.end()) {
                    handler = std::move(it_listen->second);
                    pending_rlisten_.erase(it_listen);
                    is_remote_listen = true;
                } else {
                    auto it = pending_open_.find(stream_id);
                    if (it != pending_open_.end()) {
                        handler = std::move(it->second);
                        pending_open_.erase(it);
                    }
                }
                if (!is_remote_listen && (frame.header.flags & protocol::kFlagOpenOk) != 0) {
                    activity_handler = activity_handler_;
                }
            }
            if (handler) {
                const bool ok = (frame.header.flags & protocol::kFlagOpenOk) != 0;
                if (ok) {
                    if (activity_handler) {
                        activity_handler();
                    }
                    handler(true, is_remote_listen ? payload_to_string(*payload) : std::string{});
                } else {
                    handler(false, payload_to_string(*payload));
                }
            }
            break;
        }
        case protocol::ROPEN: {
            ReverseOpenHandler reverse_handler;
            {
                std::lock_guard<std::mutex> lock(state_mu_);
                reverse_handler = reverse_handler_;
            }
            if (reverse_handler) {
                try {
                    auto json = nlohmann::json::parse(payload_to_string(*payload));
                    const auto listen_id = static_cast<uint8_t>(json.value("listen_id", 0));
                    if (listen_id != 0) {
                        reverse_handler(listen_id, stream_id);
                    }
                } catch (...) {
                }
            }
            break;
        }
        case protocol::SOPEN: {
            InboundOpenHandler inbound_open_handler;
            ServerStreamOpenHandler server_stream_open_handler;
            bool server_in_charge = false;
            {
                std::lock_guard<std::mutex> lock(state_mu_);
                inbound_open_handler = inbound_open_handler_;
                server_stream_open_handler = server_stream_open_handler_;
                server_in_charge = server_in_charge_;
            }
            try {
                auto json = nlohmann::json::parse(payload_to_string(*payload));
                if (json.contains("channel_kind")) {
                    if (inbound_open_handler) {
                        inbound_open_handler(stream_id, json);
                    } else {
                        send_open_ack(stream_id, false, "inbound control unavailable");
                    }
                    break;
                }
                if (!server_in_charge) {
                    send_open_ack(stream_id, false, "server control disabled");
                    break;
                }
                const std::string host = json.value("host", "");
                const int port = json.value("port", 0);
                const std::string proto = json.value("proto", "tcp");
                if (host.empty() || port <= 0) {
                    send_open_ack(stream_id, false, "invalid control target");
                    break;
                }
                if (proto != "tcp") {
                    send_open_ack(stream_id, false, "unsupported control proto");
                    break;
                }
                if (!server_stream_open_handler) {
                    send_open_ack(stream_id, false, "server control unavailable");
                    break;
                }
                std::string reason;
                if (!server_stream_open_handler(stream_id, host, port, &reason)) {
                    send_open_ack(stream_id, false, reason.empty() ? "local control open failed" : reason);
                    break;
                }
                std::lock_guard<std::mutex> lock(state_mu_);
                reserved_streams_.insert(stream_id);
            } catch (...) {
                send_open_ack(stream_id, false, "invalid control payload");
            }
            break;
        }
        case protocol::CONTROL: {
            ControlHandler control_handler;
            {
                std::lock_guard<std::mutex> lock(state_mu_);
                control_handler = control_handler_;
            }
            if (control_handler) {
                try {
                    auto json = nlohmann::json::parse(payload_to_string(*payload));
                    control_handler(json);
                } catch (...) {
                }
            }
            break;
        }
        case protocol::DATA: {
            DataHandler on_data;
            ActivityHandler activity_handler;
            {
                std::lock_guard<std::mutex> lock(state_mu_);
                auto it = streams_.find(stream_id);
                if (it != streams_.end()) {
                    on_data = it->second.on_data;
                }
                if (!payload->empty()) {
                    activity_handler = activity_handler_;
                }
            }
            if (on_data) {
                if (activity_handler) {
                    activity_handler();
                }
                on_data(*payload);
            }
            break;
        }
        case protocol::EXEC: {
            ExecHandler exec_handler;
            bool allow_exec = false;
            bool in_use = false;
            {
                std::lock_guard<std::mutex> lock(state_mu_);
                allow_exec = allow_exec_;
                exec_handler = exec_handler_;
                in_use = has_stream_id_locked(stream_id);
                if (allow_exec && exec_handler && !in_use) {
                    reserved_streams_.insert(stream_id);
                }
            }
            if (!allow_exec) {
                send_data(stream_id, Bytes({'E', 'X', 'E', 'C', ' ', 'd', 'e', 'n', 'i', 'e', 'd'}));
                send_close(stream_id, "exec denied");
                break;
            }
            if (!exec_handler) {
                send_close(stream_id, "exec unavailable");
                break;
            }
            if (in_use) {
                send_close(stream_id, "exec stream id in use");
                break;
            }
            exec_handler(stream_id, payload_to_string(*payload));
            break;
        }
        case protocol::CLOSE: {
            CloseHandler on_close;
            HalfCloseHandler on_half_close;
            const std::string reason = payload_to_string(*payload);
            const bool is_fin = (frame.header.flags & protocol::kFlagStreamFin) != 0;
            if (stream_id == 0 && !is_fin) {
                request_transport_close(reason.empty() ? "server closed" : reason);
                break;
            }
            {
                std::lock_guard<std::mutex> lock(state_mu_);
                auto it = streams_.find(stream_id);
                if (it != streams_.end()) {
                    if (is_fin && it->second.on_half_close) {
                        on_half_close = it->second.on_half_close;
                    } else {
                        on_close = std::move(it->second.on_close);
                        streams_.erase(it);
                    }
                }
                if (!is_fin || !on_half_close) {
                    pending_open_.erase(stream_id);
                    pending_rlisten_.erase(stream_id);
                    reserved_streams_.erase(stream_id);
                }
            }
            if (on_half_close) {
                on_half_close(reason);
                break;
            }
            if (on_close) {
                on_close(reason);
            }
            break;
        }
        case protocol::PING: {
            protocol::Frame pong{{0, protocol::PONG, 0, 0}, {}};
            queue_frame(pong);
            break;
        }
        case protocol::PONG: {
            std::lock_guard<std::mutex> lock(state_mu_);
            last_pong_ = std::chrono::steady_clock::now();
            break;
        }
        default:
            break;
    }
}

TransportCore::Bytes TransportCore::encrypt_inner_payload(uint8_t frame_type,
                                                          uint8_t stream_id,
                                                          const Bytes& input) {
    std::optional<Bytes> inner_key;
    bool hop_enabled = false;
    std::uint32_t hop_interval_ms = 0;
    std::int64_t hop_offset_ms = 0;
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        inner_key = inner_key_;
        hop_enabled = hop_enabled_;
        hop_interval_ms = hop_interval_ms_;
        hop_offset_ms = hop_offset_ms_;
    }
    if (!inner_key.has_value()) {
        return input;
    }
    if (!hop_enabled || hop_interval_ms == 0) {
        return inner::encrypt_payload(*inner_key, frame_type, stream_id, input);
    }
    const std::uint64_t hop_id = inner::hop_id_from_time_ms(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count(),
        hop_interval_ms,
        hop_offset_ms);
    Bytes hop_key = inner::derive_hop_key(*inner_key, hop_id);
    return inner::encrypt_payload(hop_key, frame_type, stream_id, input);
}

bool TransportCore::decrypt_inner_payload(uint8_t frame_type,
                                          uint8_t stream_id,
                                          const Bytes& input,
                                          Bytes* output) {
    if (!output) {
        return false;
    }
    std::optional<Bytes> inner_key;
    bool hop_enabled = false;
    std::uint32_t hop_interval_ms = 0;
    std::int64_t hop_offset_ms = 0;
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        inner_key = inner_key_;
        hop_enabled = hop_enabled_;
        hop_interval_ms = hop_interval_ms_;
        hop_offset_ms = hop_offset_ms_;
    }
    if (!inner_key.has_value()) {
        *output = input;
        return true;
    }
    try {
        if (!hop_enabled || hop_interval_ms == 0) {
            *output = inner::decrypt_payload(*inner_key, frame_type, stream_id, input);
            return true;
        }
        const std::uint64_t hop_id = inner::hop_id_from_time_ms(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count(),
            hop_interval_ms,
            hop_offset_ms);
        std::uint64_t candidates[1 + (kHopDecryptWindow * 2)];
        std::size_t candidate_count = 0;
        candidates[candidate_count++] = hop_id;
        for (std::uint64_t delta = 1; delta <= kHopDecryptWindow; ++delta) {
            if (hop_id >= delta) {
                candidates[candidate_count++] = hop_id - delta;
            }
            candidates[candidate_count++] = hop_id + delta;
        }
        for (std::size_t i = 0; i < candidate_count; ++i) {
            Bytes hop_key = inner::derive_hop_key(*inner_key, candidates[i]);
            try {
                *output = inner::decrypt_payload(hop_key, frame_type, stream_id, input);
                return true;
            } catch (...) {
            }
        }
    } catch (...) {
    }
    return false;
}

std::uint64_t TransportCore::current_hop_id() const {
    std::lock_guard<std::mutex> lock(state_mu_);
    if (!hop_enabled_ || hop_interval_ms_ == 0) {
        return 0;
    }
    return inner::hop_id_from_time_ms(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count(),
        hop_interval_ms_,
        hop_offset_ms_);
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
