#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include <nlohmann/json.hpp>

#include "client/transport_core.hpp"

namespace yume::client {

class Tunnel : public std::enable_shared_from_this<Tunnel> {
public:
    using Bytes = std::vector<uint8_t>;
    using OpenHandler = std::function<void(bool, const std::string&)>;
    using DataHandler = std::function<void(const Bytes&)>;
    using CloseHandler = std::function<void(const std::string&)>;
    using TunnelCloseHandler = std::function<void(const std::string&)>;
    using ReverseOpenHandler = std::function<void(uint8_t listen_id, uint8_t stream_id)>;
    using ControlHandler = std::function<void(const nlohmann::json&)>;
    using InboundOpenHandler = std::function<void(uint8_t stream_id, const nlohmann::json&)>;
    using ActivityHandler = std::function<void()>;

    explicit Tunnel(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>&& stream);

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
    void register_stream(uint8_t stream_id, DataHandler on_data, CloseHandler on_close);
    void unregister_stream(uint8_t stream_id);

    void open_stream(uint8_t stream_id,
                     const std::string& host,
                     int port,
                     OpenHandler handler,
                     const std::string& proto = "tcp");
    void open_relay_stream(uint8_t stream_id, const nlohmann::json& payload, OpenHandler handler);
    void request_remote_listen(uint8_t listen_id,
                               int port,
                               OpenHandler handler,
                               bool reclaim = true,
                               int min_port = 0,
                               int max_port = 0);
    void stop(const std::string& reason = "client stopping");
    void send_data(uint8_t stream_id, const Bytes& data);
    void send_close(uint8_t stream_id, const std::string& reason);
    void send_open_ack(uint8_t stream_id, bool ok, const std::string& reason);
    void send_exec(uint8_t stream_id, const std::string& command);
    void send_control_json(const nlohmann::json& json);

    // Cumulative wire-level byte counters since this tunnel was opened.
    // bytes_received() counts TLS reads from the server; bytes_sent()
    // counts payloads written through async_write. Both are atomic so
    // the GUI can read them from a polling thread.
    std::uint64_t bytes_received() const noexcept { return bytes_in_.load(); }
    std::uint64_t bytes_sent()     const noexcept { return bytes_out_.load(); }

private:
    void read_tls();
    void on_read_tls(const boost::system::error_code& ec, std::size_t bytes);
    void start_exec(uint8_t stream_id, std::string command);
    void close_all(const std::string& reason);
    void schedule_keepalive();

    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream_;
    boost::asio::strand<boost::asio::any_io_executor> strand_;
    boost::asio::steady_timer keepalive_timer_{stream_.get_executor()};
    std::array<uint8_t, 65536> read_buf_{};
    TransportCore core_;
    TunnelCloseHandler close_handler_;
    std::mutex close_handler_mu_;
    std::atomic<std::uint64_t> bytes_in_{0};
    std::atomic<std::uint64_t> bytes_out_{0};
    std::atomic<std::uint32_t> obfs_jitter_ms_max_{0};
    bool closed_{false};
};

}  // namespace yume::client
