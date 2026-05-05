#pragma once

#include <array>
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
#include "core/obfs_h2.hpp"

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
    void enable_h2_carrier(const std::string& sni,
                           const std::string& secret,
                           const std::string& user_agent);
    void set_inner_key(const Bytes& key);
    void set_hop(bool enabled, std::uint32_t interval_ms, std::int64_t offset_ms);
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

private:
    void read_tls();
    void on_read_tls(const boost::system::error_code& ec, std::size_t bytes);
    void start_exec(uint8_t stream_id, std::string command);
    void close_all(const std::string& reason);
    void schedule_keepalive();
    void send_h2_client_handshake_then_start();

    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream_;
    boost::asio::strand<boost::asio::any_io_executor> strand_;
    boost::asio::steady_timer keepalive_timer_{stream_.get_executor()};
    std::array<uint8_t, 8192> read_buf_{};
    TransportCore core_;
    TunnelCloseHandler close_handler_;
    std::mutex close_handler_mu_;
    bool closed_{false};
    bool h2_carrier_enabled_{false};
    std::string h2_sni_;
    std::string h2_secret_;
    std::string h2_user_agent_;
    std::unique_ptr<obfs::H2InboundDecoder> h2_decoder_;
    bool h2_handshake_done_{false};
};

}  // namespace yume::client
