#pragma once

#include <array>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <unordered_map>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include "core/protocol.hpp"

namespace yume::client {

class Tunnel : public std::enable_shared_from_this<Tunnel> {
public:
    using Bytes = std::vector<uint8_t>;
    using OpenHandler = std::function<void(bool, const std::string&)>;
    using DataHandler = std::function<void(const Bytes&)>;
    using CloseHandler = std::function<void()>;

    explicit Tunnel(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>&& stream);

    void start();
    void set_inner_key(const Bytes& key);

    uint8_t reserve_stream_id();
    void register_stream(uint8_t stream_id, DataHandler on_data, CloseHandler on_close);
    void unregister_stream(uint8_t stream_id);

    void open_stream(uint8_t stream_id, const std::string& host, int port, OpenHandler handler);
    void send_data(uint8_t stream_id, const Bytes& data);
    void send_close(uint8_t stream_id, const std::string& reason);

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

    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream_;
    boost::asio::strand<boost::asio::any_io_executor> strand_;

    std::array<uint8_t, 8> header_buf_{};
    protocol::FrameHeader current_header_{};
    std::vector<uint8_t> payload_buf_;

    std::deque<PendingWrite> write_queue_;
    bool write_in_flight_{false};

    std::unordered_map<uint8_t, StreamCallbacks> streams_;
    std::unordered_map<uint8_t, OpenHandler> pending_open_;
    uint8_t next_stream_id_{1};
    std::optional<Bytes> inner_key_;
};

}  // namespace yume::client
