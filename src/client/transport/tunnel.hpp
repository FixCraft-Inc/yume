/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/system/error_code.hpp>
#include <nlohmann/json.hpp>

#include "client/transport/client_stream.hpp"
#include "client/transport/core.hpp"
#include "core/stealth/h2_carrier.hpp"
#include "core/security/session_ratchet.hpp"

namespace yume::client {

struct TunnelCloseStateTestPeer;

class Tunnel : public std::enable_shared_from_this<Tunnel> {
public:
    using Bytes = std::vector<uint8_t>;
    using OpenHandler = std::function<void(bool, const std::string&)>;
    using DataHandler = std::function<void(const Bytes&)>;
    using CloseHandler = std::function<void(const std::string&)>;
    using HalfCloseHandler = std::function<void(const std::string&)>;
    using TunnelCloseHandler = std::function<void(const std::string&)>;
    using ReverseOpenHandler = std::function<void(uint8_t listen_id, uint8_t stream_id)>;
    using ControlHandler = std::function<void(const nlohmann::json&)>;
    using InboundOpenHandler = std::function<void(uint8_t stream_id, const nlohmann::json&)>;
    using ActivityHandler = std::function<void()>;

    explicit Tunnel(
        ClientTransportStream&& stream,
        std::unique_ptr<obfs::H2Carrier> carrier = {},
        Bytes prefetched_carrier_bytes = {},
        std::unique_ptr<ratchet::SessionRatchet> ratchet = {});

    void start();
    void set_inner_key(const Bytes& key);
    void set_hop(bool enabled, std::uint32_t interval_ms, std::int64_t offset_ms);
    // Send-side obfs shape. `pad_multiple` is forwarded to TransportCore
    // for per-frame padding; `jitter_ms_max` is consumed here in the
    // tunnel's write_handler to defer the actual TLS write by a uniform
    // random delay [0, jitter_ms_max]. Both default to 0 (off).
    void set_obfs_shape(std::uint16_t pad_multiple, std::uint32_t jitter_ms_max);
    void set_server_in_charge(bool enabled);
    void set_allow_exec(bool enabled);
    void set_reverse_handler(ReverseOpenHandler handler);
    void set_close_handler(TunnelCloseHandler handler);
    void set_control_handler(ControlHandler handler);
    void set_inbound_open_handler(InboundOpenHandler handler);
    void set_activity_handler(ActivityHandler handler);
    boost::asio::any_io_executor get_executor();

    uint8_t reserve_stream_id();
    void register_stream(uint8_t stream_id,
                         DataHandler on_data,
                         CloseHandler on_close,
                         HalfCloseHandler on_half_close = {});
    void unregister_stream(uint8_t stream_id);

    void open_stream(uint8_t stream_id,
                     const std::string& host,
                     int port,
                     OpenHandler handler,
                     const std::string& proto = "tcp");
    void open_relay_stream(uint8_t stream_id, const nlohmann::json& payload, OpenHandler handler);
    void request_remote_listen(uint8_t listen_id,
                               const std::string& bind_host,
                               int port,
                               OpenHandler handler,
                               bool reclaim = true,
                               int min_port = 0,
                               int max_port = 0);
    void stop(const std::string& reason = "client stopping");
    void send_data(uint8_t stream_id, const Bytes& data);
    void send_data(uint8_t stream_id, Bytes&& data);
    void send_data(uint8_t stream_id,
                   Bytes&& data,
                   TransportCore::WriteCompletion completion);
    bool try_send_data(uint8_t stream_id,
                       Bytes&& data,
                       TransportCore::WriteCompletion completion = {});
    void send_close(uint8_t stream_id, const std::string& reason);
    void send_stream_fin(uint8_t stream_id, const std::string& reason);
    void send_open_ack(uint8_t stream_id, bool ok, const std::string& reason);
    void send_exec(uint8_t stream_id, const std::string& command);
    void send_control_json(const nlohmann::json& json);
    bool is_alive() const noexcept { return !closed_.load(std::memory_order_relaxed); }

    // Cumulative wire-level byte counters since this tunnel was opened.
    // bytes_received() counts TLS reads from the server; bytes_sent()
    // counts payloads written through async_write. Both are atomic so
    // the GUI can read them from a polling thread.
    std::uint64_t bytes_received() const noexcept { return bytes_in_.load(); }
    std::uint64_t bytes_sent()     const noexcept { return bytes_out_.load(); }

private:
    void read_tls();
    void on_read_tls(const boost::system::error_code& ec, std::size_t bytes);
    using WireCompletion = std::function<void(const boost::system::error_code&,
                                              std::size_t)>;
    struct WireWrite {
        std::shared_ptr<Bytes> data;
        WireCompletion completion;
    };
    struct CarrierCompletion {
        TransportCore::WriteCompletion completion;
        std::size_t application_bytes{0};
    };
    void enqueue_wire_write(std::shared_ptr<Bytes> data,
                            WireCompletion completion = {});
    void start_wire_write();
    void flush_carrier_output();
    void complete_carrier_writes(std::size_t count,
                                 bool ok,
                                 const std::string& error);
    void observe_orderly_peer_close();
    void complete_orderly_close_write(
        const boost::system::error_code& error,
        std::size_t written,
        std::size_t expected);
    void handle_orderly_close_timeout(
        const boost::system::error_code& error);
    void record_orderly_close_wire_result(bool completed) noexcept;
    void finish_close(const std::string& reason);
    void start_exec(uint8_t stream_id, std::string command);
    void close_all(const std::string& reason);
    void schedule_keepalive();
    void schedule_ratchet_check();

    ClientTransportStream stream_;
    boost::asio::strand<boost::asio::any_io_executor> strand_;
    boost::asio::steady_timer keepalive_timer_{stream_.get_executor()};
    boost::asio::steady_timer ratchet_timer_{stream_.get_executor()};
    boost::asio::steady_timer close_timer_{stream_.get_executor()};
    std::vector<uint8_t> read_buf_;
    std::unique_ptr<obfs::H2Carrier> carrier_;
    Bytes prefetched_carrier_bytes_;
    std::deque<WireWrite> wire_writes_;
    std::deque<CarrierCompletion> carrier_completions_;
    bool wire_write_active_{false};
    bool orderly_close_pending_{false};
    bool orderly_close_write_complete_{false};
    bool orderly_close_peer_closed_{false};
    bool orderly_close_wire_result_recorded_{false};
    std::string orderly_close_reason_;
    TransportCore core_;
    TunnelCloseHandler close_handler_;
    std::mutex close_handler_mu_;
    std::atomic<std::uint64_t> bytes_in_{0};
    std::atomic<std::uint64_t> bytes_out_{0};
    std::atomic<std::uint32_t> obfs_jitter_ms_max_{0};
    std::atomic<std::uint32_t> active_execs_{0};
    std::atomic<bool> closed_{false};
    static constexpr std::uint32_t kMaxConcurrentExecs = 4;

    friend struct TunnelCloseStateTestPeer;
};

}  // namespace yume::client
