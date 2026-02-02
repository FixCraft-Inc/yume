#pragma once

#include <array>
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <utility>
#include <unordered_map>
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

class LocalForwardSession : public std::enable_shared_from_this<LocalForwardSession> {
public:
    LocalForwardSession(boost::asio::ip::tcp::socket socket,
                        std::string target_host,
                        int target_port);

    void start();

private:
    void start_connect();
    void start_client_read();
    void start_remote_read();
    void on_client_read(const boost::system::error_code& ec, std::size_t bytes);
    void on_remote_read(const boost::system::error_code& ec, std::size_t bytes);
    void close();

    boost::asio::ip::tcp::socket socket_;
    boost::asio::ip::tcp::socket remote_;
    boost::asio::ip::tcp::resolver resolver_;
    boost::asio::strand<boost::asio::any_io_executor> strand_;

    std::array<uint8_t, 4096> client_buf_{};
    std::array<uint8_t, 4096> remote_buf_{};

    std::string target_host_;
    int target_port_{0};
};

class ReverseForwardSession : public std::enable_shared_from_this<ReverseForwardSession> {
public:
    ReverseForwardSession(std::shared_ptr<Tunnel> tunnel,
                          uint8_t stream_id,
                          std::string target_host,
                          int target_port);

    void start();

private:
    void start_connect();
    void start_local_read();
    void on_local_read(const boost::system::error_code& ec, std::size_t bytes);
    void deliver_from_tunnel(const Tunnel::Bytes& data);
    void close_from_tunnel();
    void close();

    std::shared_ptr<Tunnel> tunnel_;
    uint8_t stream_id_{0};

    boost::asio::ip::tcp::socket local_;
    boost::asio::ip::tcp::resolver resolver_;
    boost::asio::strand<boost::asio::any_io_executor> strand_;
    std::array<uint8_t, 4096> read_buf_{};

    std::string target_host_;
    int target_port_{0};
    bool open_confirmed_{false};
};

class ForwardServer {
public:
    ForwardServer(boost::asio::io_context& io,
                  int listen_port,
                  std::string target_host,
                  int target_port,
                  std::shared_ptr<Tunnel> tunnel,
                  bool allow_local_ip);
    ~ForwardServer();

    void start();

private:
    void do_accept();
    bool is_local_target() const;

    boost::asio::ip::tcp::acceptor acceptor_;
    int listen_port_{0};
    std::string pid_path_;
    std::string target_host_;
    int target_port_{0};
    std::shared_ptr<Tunnel> tunnel_;
    bool allow_local_ip_{false};
};

class UdpForwardServer : public std::enable_shared_from_this<UdpForwardServer> {
public:
    UdpForwardServer(boost::asio::io_context& io,
                     int listen_port,
                     std::string target_host,
                     int target_port,
                     std::shared_ptr<Tunnel> tunnel,
                     bool allow_local_ip);
    ~UdpForwardServer();

    void start();

private:
    struct UdpMapping {
        boost::asio::ip::udp::endpoint client;
        uint8_t stream_id{0};
        bool open_confirmed{false};
        std::deque<Tunnel::Bytes> pending;
    };

    void do_receive();
    void handle_datagram(const boost::asio::ip::udp::endpoint& client, const Tunnel::Bytes& data);
    void on_open_result(uint8_t stream_id, bool ok, const std::string& reason);
    void deliver_from_tunnel(uint8_t stream_id, const Tunnel::Bytes& data);
    void close_stream(uint8_t stream_id, const std::string& reason);

    boost::asio::ip::udp::socket socket_;
    boost::asio::strand<boost::asio::any_io_executor> strand_;
    std::shared_ptr<Tunnel> tunnel_;
    int listen_port_{0};
    std::string pid_path_;
    std::string target_host_;
    int target_port_{0};
    bool allow_local_ip_{false};
    bool blocked_local_warned_{false};
    std::array<uint8_t, 65535> read_buf_{};
    boost::asio::ip::udp::endpoint sender_{};
    std::unordered_map<std::string, std::shared_ptr<UdpMapping>> by_client_;
    std::unordered_map<uint8_t, std::shared_ptr<UdpMapping>> by_stream_;
};

}  // namespace yume::client
