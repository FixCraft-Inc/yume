#pragma once

#include <array>
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio.hpp>

#include "client/tunnel.hpp"

namespace yume::client {

class ForwardSession : public std::enable_shared_from_this<ForwardSession> {
public:
    ForwardSession(boost::asio::ip::tcp::socket socket,
                   std::shared_ptr<Tunnel> tunnel,
                   std::string target_host,
                   int target_port);

    void start();

private:
    void start_tunnel();
    void start_client_read();
    void on_client_read(const boost::system::error_code& ec, std::size_t bytes);

    void deliver_from_tunnel(const Tunnel::Bytes& data);
    void close_from_tunnel();

    void enqueue_write(std::shared_ptr<std::vector<uint8_t>> data);
    void do_write();

    void close();

    boost::asio::ip::tcp::socket socket_;
    std::shared_ptr<Tunnel> tunnel_;
    boost::asio::strand<boost::asio::any_io_executor> strand_;

    std::array<uint8_t, 4096> read_buf_{};
    std::deque<std::shared_ptr<std::vector<uint8_t>>> write_queue_;
    bool write_in_flight_{false};

    std::string target_host_;
    int target_port_{0};
    uint8_t stream_id_{0};
    bool open_confirmed_{false};
};

class ForwardServer {
public:
    ForwardServer(boost::asio::io_context& io,
                  int listen_port,
                  std::string target_host,
                  int target_port,
                  std::shared_ptr<Tunnel> tunnel);

    void start();

private:
    void do_accept();

    boost::asio::ip::tcp::acceptor acceptor_;
    std::string target_host_;
    int target_port_{0};
    std::shared_ptr<Tunnel> tunnel_;
};

}  // namespace yume::client
