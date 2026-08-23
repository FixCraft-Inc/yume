/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <array>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <unordered_map>
#include <vector>

#include <boost/asio.hpp>

#include "client/proxy/udp_queue.hpp"
#include "client/transport/tunnel.hpp"
#include "core/runtime/stream_queue_limits.hpp"

namespace yume::client {

class TunnelPool;
struct SocksSessionTestPeer;

class SocksSession : public std::enable_shared_from_this<SocksSession> {
public:
    SocksSession(boost::asio::ip::tcp::socket socket,
                 std::shared_ptr<Tunnel> tunnel,
                 bool allow_udp,
                 std::shared_ptr<TunnelPool> pool = nullptr);

    void start();

private:
    using WriteReservation =
        runtime::ConcurrentInboundQueueBudget::Reservation;
    struct PendingLocalWrite {
        std::shared_ptr<std::vector<uint8_t>> data;
        std::function<void()> on_done;
        WriteReservation reservation;
        Tunnel::InboundCredit inbound_credit;
    };

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
    void start_udp_associate();
    void start_udp_read();
    void on_udp_read(const boost::system::error_code& ec, std::size_t bytes);
    void deliver_udp(uint8_t stream_id,
                     const Tunnel::Bytes& data,
                     Tunnel::InboundCredit inbound_credit);
    void deliver_udp_on_strand(
        uint8_t stream_id,
        std::shared_ptr<std::vector<uint8_t>> data,
        detail::UdpQueueBudget::Reservation reservation,
        Tunnel::InboundCredit inbound_credit);
    void enqueue_udp_send(
        uint8_t stream_id,
        std::shared_ptr<std::vector<uint8_t>> data,
        detail::UdpQueueBudget::Reservation reservation,
        Tunnel::InboundCredit inbound_credit);
    void do_udp_send();
    void on_udp_open_result(uint8_t stream_id,
                            bool ok,
                            const std::string& reason);
    void close_udp_assoc(uint8_t stream_id, const std::string& reason);

    void start_client_read();
    void on_client_read(const boost::system::error_code& ec, std::size_t bytes);
    void send_client_fin();

    void deliver_from_tunnel(const Tunnel::Bytes& data,
                             Tunnel::InboundCredit inbound_credit);
    void close_from_tunnel();
    void remote_fin_from_tunnel(const std::string& reason);

    void enqueue_write(std::shared_ptr<std::vector<uint8_t>> data, std::function<void()> on_done = {});
    void enqueue_write_on_strand(std::shared_ptr<std::vector<uint8_t>> data,
                                 std::function<void()> on_done,
                                 WriteReservation reservation,
                                 Tunnel::InboundCredit inbound_credit = {});
    void do_write();
    void request_socket_send_shutdown();
    void maybe_finish_cleanly();
    void release_pool_session();
    void log_summary_once();

    void close();

    boost::asio::ip::tcp::socket socket_;
    std::shared_ptr<Tunnel> tunnel_;
    std::shared_ptr<TunnelPool> pool_;
    boost::asio::strand<boost::asio::any_io_executor> strand_;
    bool allow_udp_{false};
    bool udp_active_{false};
    boost::asio::ip::udp::socket udp_socket_{socket_.get_executor()};
    boost::asio::ip::udp::endpoint udp_client_endpoint_{};
    std::array<uint8_t, 65535> udp_buf_{};
    boost::asio::ip::udp::endpoint udp_sender_{};

    std::array<uint8_t, 2> greeting_hdr_{};
    std::vector<uint8_t> methods_;
    std::array<uint8_t, 4> request_hdr_{};
    std::vector<uint8_t> addr_buf_;
    std::array<uint8_t, 2> port_buf_{};

    std::vector<uint8_t> read_buf_;

    std::deque<PendingLocalWrite> write_queue_;
    runtime::ConcurrentInboundQueueBudget write_budget_;
    bool write_in_flight_{false};

    std::string target_host_;
    int target_port_{0};
    uint8_t stream_id_{0};
    bool open_result_received_{false};
    bool open_confirmed_{false};
    bool awaiting_domain_len_{false};
    uint8_t pending_cmd_{0};
    int64_t opened_started_ms_{0};
    int64_t first_upload_ms_{0};
    int64_t first_download_ms_{0};
    std::uint64_t upload_bytes_{0};
    std::uint64_t download_bytes_{0};
    bool close_summary_logged_{false};
    bool pool_session_released_{false};
    bool closed_{false};
    bool local_fin_sent_{false};
    bool remote_fin_received_{false};
    bool socket_send_shutdown_pending_{false};
    bool socket_send_shutdown_done_{false};

    struct UdpAssoc {
        explicit UdpAssoc(detail::UdpQueueBudget& pending_budget)
            : pending(pending_budget) {}

        std::string host;
        int port{0};
        uint8_t stream_id{0};
        bool open_result_received{false};
        bool open_confirmed{false};
        detail::BudgetedUdpDatagramQueue pending;
    };
    struct PendingUdpSend {
        uint8_t stream_id{0};
        std::shared_ptr<std::vector<uint8_t>> data;
        detail::UdpQueueBudget::Reservation reservation;
        Tunnel::InboundCredit inbound_credit;
    };
    detail::UdpQueueBudget udp_pending_budget_;
    detail::UdpQueueBudget udp_local_send_budget_;
    std::deque<PendingUdpSend> udp_send_queue_;
    bool udp_send_in_flight_{false};
    std::unordered_map<std::string, std::shared_ptr<UdpAssoc>> udp_assoc_;
    std::unordered_map<uint8_t, std::shared_ptr<UdpAssoc>> udp_assoc_by_stream_;

    friend struct SocksSessionTestPeer;
};

class SocksServer {
public:
    // Single-tunnel constructor — every accepted SOCKS session binds
    // to the same tunnel. Kept for compatibility with embedders that
    // don't (yet) use the multi-tunnel path.
    SocksServer(boost::asio::io_context& io, int port, std::shared_ptr<Tunnel> tunnel, bool allow_udp);
    SocksServer(boost::asio::io_context& io,
                std::string bind_host,
                int port,
                std::shared_ptr<Tunnel> tunnel,
                bool allow_udp);

    // Pool-based constructor — each accepted SOCKS session picks a
    // tunnel from the pool at accept time and is bound to it for the
    // session's lifetime. This lifts the single-TLS-connection
    // throughput cap that a multiplexed tunnel hits at high
    // concurrency.
    SocksServer(boost::asio::io_context& io,
                int port,
                std::shared_ptr<TunnelPool> pool,
                bool allow_udp);
    SocksServer(boost::asio::io_context& io,
                std::string bind_host,
                int port,
                std::shared_ptr<TunnelPool> pool,
                bool allow_udp);

    void start();
    int port() const;

private:
    void do_accept();
    std::shared_ptr<Tunnel> pick_tunnel_for_new_session();

    boost::asio::ip::tcp::acceptor acceptor_;
    // Single-tunnel path: tunnel_ is set, pool_ is null.
    // Pool path: pool_ is set, tunnel_ is null and the picker is
    // consulted on every accept.
    std::shared_ptr<Tunnel> tunnel_;
    std::shared_ptr<TunnelPool> pool_;
    bool allow_udp_{false};
};

}  // namespace yume::client
