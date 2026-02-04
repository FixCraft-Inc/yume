#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include "core/protocol.hpp"

namespace yume::client {

class ReverseForwardSession;

class Tunnel : public std::enable_shared_from_this<Tunnel> {
public:
    using Bytes = std::vector<uint8_t>;
    using OpenHandler = std::function<void(bool, const std::string&)>;
    using DataHandler = std::function<void(const Bytes&)>;
    using CloseHandler = std::function<void()>;
    using TunnelCloseHandler = std::function<void(const std::string&)>;
    using ReverseOpenHandler = std::function<void(uint8_t listen_id, uint8_t stream_id)>;

    explicit Tunnel(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>&& stream);

    void start();
    void set_inner_key(const Bytes& key);
    void set_server_in_charge(bool enabled);
    void set_allow_exec(bool enabled);
    void set_reverse_handler(ReverseOpenHandler handler);
    void set_close_handler(TunnelCloseHandler handler);
    boost::asio::any_io_executor get_executor();

    uint8_t reserve_stream_id();
    void register_stream(uint8_t stream_id, DataHandler on_data, CloseHandler on_close);
    void unregister_stream(uint8_t stream_id);

    void open_stream(uint8_t stream_id, const std::string& host, int port, OpenHandler handler,
                     const std::string& proto = "tcp");
    void request_remote_listen(uint8_t listen_id, int port, OpenHandler handler);
    void send_data(uint8_t stream_id, const Bytes& data);
    void send_close(uint8_t stream_id, const std::string& reason);
    void send_open_ack(uint8_t stream_id, bool ok, const std::string& reason);
    void send_exec(uint8_t stream_id, const std::string& command);

private:
    struct PendingWrite {
        std::shared_ptr<std::vector<uint8_t>> data;
        std::function<void(const boost::system::error_code&, std::size_t)> handler;
    };

    struct StreamCallbacks {
        DataHandler on_data;
        CloseHandler on_close;
    };

    void read_header();
    void on_read_header(const boost::system::error_code& ec, std::size_t bytes);
    void on_read_payload(const boost::system::error_code& ec, std::size_t bytes);
    void handle_frame(const protocol::Frame& frame);

    void async_write_frame(const protocol::Frame& frame,
                           std::function<void(const boost::system::error_code&, std::size_t)> handler = {});
    void do_write();

    void close_all(const std::string& reason);
    void schedule_keepalive();

    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream_;
    boost::asio::strand<boost::asio::any_io_executor> strand_;
    boost::asio::steady_timer keepalive_timer_{stream_.get_executor()};
    std::chrono::steady_clock::time_point last_pong_{};

    std::array<uint8_t, 8> header_buf_{};
    protocol::FrameHeader current_header_{};
    std::vector<uint8_t> payload_buf_;

    std::deque<PendingWrite> write_queue_;
    bool write_in_flight_{false};

    std::unordered_map<uint8_t, StreamCallbacks> streams_;
    std::unordered_map<uint8_t, OpenHandler> pending_open_;
    std::unordered_map<uint8_t, OpenHandler> pending_rlisten_;
    ReverseOpenHandler reverse_handler_;
    TunnelCloseHandler close_handler_;
    uint8_t next_stream_id_{1};
    bool closed_{false};
    std::optional<Bytes> inner_key_;
    bool server_in_charge_{false};
    bool allow_exec_{false};
    std::unordered_map<uint8_t, std::shared_ptr<ReverseForwardSession>> control_sessions_;
    std::unordered_set<uint8_t> control_exec_;
};

}  // namespace yume::client
