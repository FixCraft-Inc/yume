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

class SocksSession : public std::enable_shared_from_this<SocksSession> {
public:
    SocksSession(boost::asio::ip::tcp::socket socket, std::shared_ptr<Tunnel> tunnel);

    void start();

private:
    void read_greeting();
    void on_read_greeting(const boost::system::error_code& ec, std::size_t bytes);
    void on_read_methods(const boost::system::error_code& ec, std::size_t bytes);

    void read_request_header();
    void on_read_request_header(const boost::system::error_code& ec, std::size_t bytes);
    void read_request_address(uint8_t atyp);
    void on_read_request_address(uint8_t atyp, const boost::system::error_code& ec, std::size_t bytes);
    void on_read_request_port(const boost::system::error_code& ec, std::size_t bytes);

    void send_reply(uint8_t reply, std::function<void()> on_done = {});
    void start_tunnel();

    void start_client_read();
    void on_client_read(const boost::system::error_code& ec, std::size_t bytes);

    void deliver_from_tunnel(const Tunnel::Bytes& data);
    void close_from_tunnel();

    void enqueue_write(std::shared_ptr<std::vector<uint8_t>> data, std::function<void()> on_done = {});
    void do_write();

    void close();

    boost::asio::ip::tcp::socket socket_;
    std::shared_ptr<Tunnel> tunnel_;
    boost::asio::strand<boost::asio::any_io_executor> strand_;

    std::array<uint8_t, 2> greeting_hdr_{};
    std::vector<uint8_t> methods_;
    std::array<uint8_t, 4> request_hdr_{};
    std::vector<uint8_t> addr_buf_;
    std::array<uint8_t, 2> port_buf_{};

    std::array<uint8_t, 4096> read_buf_{};

    std::deque<std::pair<std::shared_ptr<std::vector<uint8_t>>, std::function<void()>>> write_queue_;
    bool write_in_flight_{false};

    std::string target_host_;
    int target_port_{0};
    uint8_t stream_id_{0};
    bool open_confirmed_{false};
    bool awaiting_domain_len_{false};
};

class SocksServer {
public:
    SocksServer(boost::asio::io_context& io, int port, std::shared_ptr<Tunnel> tunnel);

    void start();
    int port() const;

private:
    void do_accept();

    boost::asio::ip::tcp::acceptor acceptor_;
    std::shared_ptr<Tunnel> tunnel_;
};

}  // namespace yume::client
