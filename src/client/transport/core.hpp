/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <nlohmann/json.hpp>

#include "core/protocol/protocol.hpp"

namespace yume::client {

class TransportCore {
public:
    using Bytes = std::vector<uint8_t>;
    using WriteCompletion = std::function<void(bool, std::size_t, const std::string&)>;
    using WriteHandler = std::function<void(std::shared_ptr<Bytes>, WriteCompletion)>;
    using OpenHandler = std::function<void(bool, const std::string&)>;
    using DataHandler = std::function<void(const Bytes&)>;
    using CloseHandler = std::function<void(const std::string&)>;
    using HalfCloseHandler = std::function<void(const std::string&)>;
    using ReverseOpenHandler = std::function<void(uint8_t listen_id, uint8_t stream_id)>;
    using ControlHandler = std::function<void(const nlohmann::json&)>;
    using InboundOpenHandler = std::function<void(uint8_t stream_id, const nlohmann::json&)>;
    using ActivityHandler = std::function<void()>;
    using ServerStreamOpenHandler = std::function<bool(uint8_t stream_id,
                                                       const std::string& host,
                                                       int port,
                                                       std::string* reason)>;
    using ExecHandler = std::function<void(uint8_t stream_id, const std::string& command)>;

    TransportCore() = default;
    explicit TransportCore(WriteHandler write_handler,
                           std::function<void(const std::string&)> close_transport_handler);

    void set_write_handler(WriteHandler handler);
    void set_close_transport_handler(std::function<void(const std::string&)> handler);

    void start(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());
    bool handle_keepalive_tick(std::chrono::steady_clock::time_point now, std::string* close_reason);
    std::vector<CloseHandler> shutdown();
    bool is_stopped() const;

    void set_inner_key(const Bytes& key);
    void set_hop(bool enabled, std::uint32_t interval_ms, std::int64_t offset_ms);
    // Send-side traffic-shape obfuscation. `pad_multiple` (clamped to
    // [0, 256]) rounds every outbound frame payload up to that multiple
    // via trailing pad bytes + a length byte (kFlagPadded). 0 = off.
    // `jitter_ms_max` is wired by the writer (Tunnel) — TransportCore
    // only stores it for inspection. Wire compatibility: the peer must
    // know about kFlagPadded too, so enabling padding against an old
    // server is a hard break.
    void set_obfs_shape(std::uint16_t pad_multiple, std::uint32_t jitter_ms_max);
    std::uint16_t obfs_pad_multiple() const;
    std::uint32_t obfs_jitter_ms_max() const;
    void set_server_in_charge(bool enabled);
    void set_allow_exec(bool enabled);
    void set_reverse_handler(ReverseOpenHandler handler);
    void set_control_handler(ControlHandler handler);
    void set_inbound_open_handler(InboundOpenHandler handler);
    void set_activity_handler(ActivityHandler handler);
    void set_server_stream_open_handler(ServerStreamOpenHandler handler);
    void set_exec_handler(ExecHandler handler);

    uint8_t reserve_stream_id();
    void register_stream(uint8_t stream_id,
                         DataHandler on_data,
                         CloseHandler on_close,
                         HalfCloseHandler on_half_close = {});
    void unregister_stream(uint8_t stream_id);
    void release_reserved_stream(uint8_t stream_id);

    void open_stream(uint8_t stream_id,
                     const std::string& host,
                     int port,
                     OpenHandler handler,
                     const std::string& proto = "tcp");
    void open_relay_stream(uint8_t stream_id, const nlohmann::json& json, OpenHandler handler);
    void request_remote_listen(uint8_t listen_id,
                               const std::string& bind_host,
                               int port,
                               OpenHandler handler,
                               bool reclaim = true,
                               int min_port = 0,
                               int max_port = 0);
    void send_data(uint8_t stream_id, const Bytes& data);
    void send_data(uint8_t stream_id, Bytes&& data);
    void send_data(uint8_t stream_id, Bytes&& data, WriteCompletion handler);
    void send_close(uint8_t stream_id, const std::string& reason);
    void send_stream_fin(uint8_t stream_id, const std::string& reason);
    void send_open_ack(uint8_t stream_id, bool ok, const std::string& reason);
    void send_exec(uint8_t stream_id, const std::string& command);
    void send_control_json(const nlohmann::json& json);

    void feed_tls_bytes(const uint8_t* data, std::size_t size);
    void feed_tls_bytes(const Bytes& data);

private:
    struct PendingWrite {
        protocol::Frame frame;
        WriteCompletion handler;
    };

    struct StreamCallbacks {
        DataHandler on_data;
        CloseHandler on_close;
        HalfCloseHandler on_half_close;
    };

    bool has_stream_id_locked(uint8_t stream_id) const;
    void queue_frame(protocol::Frame frame, WriteCompletion handler = {});
    void dispatch_next_write();
    std::deque<PendingWrite>::iterator select_next_write_locked(std::size_t current_batch_bytes,
                                                                const std::unordered_set<uint8_t>& batch_streams);
    std::shared_ptr<Bytes> encode_outgoing_frame(const protocol::Frame& frame);
    void handle_frame(const protocol::Frame& frame);
    Bytes encrypt_inner_payload(uint8_t frame_type, uint8_t stream_id, const Bytes& input);
    bool decrypt_inner_payload(uint8_t frame_type, uint8_t stream_id, const Bytes& input, Bytes* output);
    std::uint64_t current_hop_id() const;
    void request_transport_close(const std::string& reason);
    void clear_hop_key_cache_locked();

    mutable std::mutex state_mu_;
    std::mutex write_mu_;
    WriteHandler write_handler_;
    std::function<void(const std::string&)> close_transport_handler_;
    std::deque<PendingWrite> write_queue_;
    bool write_in_flight_{false};

    std::unordered_map<uint8_t, StreamCallbacks> streams_;
    std::unordered_map<uint8_t, OpenHandler> pending_open_;
    std::unordered_map<uint8_t, OpenHandler> pending_rlisten_;
    std::unordered_set<uint8_t> reserved_streams_;
    ReverseOpenHandler reverse_handler_;
    ControlHandler control_handler_;
    InboundOpenHandler inbound_open_handler_;
    ActivityHandler activity_handler_;
    ServerStreamOpenHandler server_stream_open_handler_;
    ExecHandler exec_handler_;
    uint8_t next_stream_id_{1};
    bool stopped_{false};
    std::optional<Bytes> inner_key_;
    bool hop_enabled_{false};
    std::uint32_t hop_interval_ms_{0};
    std::int64_t hop_offset_ms_{0};
    std::optional<std::uint64_t> encrypt_hop_id_;
    Bytes encrypt_hop_key_;
    std::optional<std::uint64_t> decrypt_hop_id_;
    Bytes decrypt_hop_key_;
    bool server_in_charge_{false};
    bool allow_exec_{false};
    std::uint16_t obfs_pad_multiple_{0};
    std::uint32_t obfs_jitter_ms_max_{0};
    std::chrono::steady_clock::time_point last_pong_{};
    Bytes incoming_bytes_;
    std::size_t incoming_offset_{0};
};

}  // namespace yume::client
