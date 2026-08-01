/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/session/session.hpp"
#include "server/session/internal.hpp"

namespace yume::server {

using namespace detail;

void Session::start_udp_open(uint8_t stream_id, const std::string& host, int port) {
    util::log_info("session " + std::to_string(session_id_) + ": OPEN udp stream " +
                   std::to_string(stream_id) + " -> " + host + ":" + std::to_string(port));
    auto udp = std::make_shared<UdpStream>(stream_.get_executor());
    udp->host = host;
    udp->port = port;
    udp->open_started_ms = util::now_ms();
    udp->resolve_started_ms = udp->open_started_ms;
    const bool resolve_any_family = server_resolve_any_family_enabled();
    const std::string resolve_family = resolve_any_family ? "any" : "ipv4";
    YUME_TIMING_LOG("server.open",
                    "start",
                    "session=" + std::to_string(session_id_) +
                        " stream=" + std::to_string(stream_id) +
                        " proto=udp family=" + resolve_family +
                        " target=" + host + ":" + std::to_string(port));

    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        udp_streams_[stream_id] = udp;
    }

    auto self = shared_from_this();
    const auto self_local_addr = session_local_address(stream_);

    auto resolver_timer =
        std::make_shared<boost::asio::deadline_timer>(stream_.get_executor());
    auto resolve_timed_out = std::make_shared<bool>(false);
    resolver_timer->expires_from_now(
        boost::posix_time::milliseconds(kResolverTimeoutMs));

    auto resolver_handler =
        [self,
         stream_id,
         udp,
         self_local_addr,
         resolver_timer,
         resolve_timed_out](
            const boost::system::error_code& ec,
            const boost::asio::ip::udp::resolver::results_type& results) {
            resolver_timer->cancel();
            [[maybe_unused]] const int64_t resolve_ms =
                udp->resolve_started_ms > 0
                    ? (util::now_ms() - udp->resolve_started_ms)
                    : 0;
            {
                std::lock_guard<std::mutex> lock(self->streams_mutex_);
                if (self->udp_streams_.find(stream_id) ==
                    self->udp_streams_.end()) {
                    return;
                }
            }

            if (ec) {
                if (ec == boost::asio::error::operation_aborted &&
                    self->close_state_ != CloseState::Open) {
                    return;
                }
                const std::string reason =
                    *resolve_timed_out ? "resolve timeout"
                                       : ("resolve failed: " + ec.message());
                YUME_TIMING_LOG(
                    "server.open",
                    "resolve_failed",
                    "session=" + std::to_string(self->session_id_) +
                        " stream=" + std::to_string(stream_id) +
                        " proto=udp ms=" + std::to_string(resolve_ms) +
                        " reason=" + reason);
                self->send_open_reply(stream_id, false, reason);
                std::lock_guard<std::mutex> lock(self->streams_mutex_);
                self->udp_streams_.erase(stream_id);
                return;
            }
            std::size_t result_count = 0;
            for (const auto& result : results) {
                (void)result;
                ++result_count;
            }
            YUME_TIMING_LOG(
                "server.open",
                "resolve_ok",
                "session=" + std::to_string(self->session_id_) +
                    " stream=" + std::to_string(stream_id) +
                    " proto=udp ms=" + std::to_string(resolve_ms) +
                    " results=" + std::to_string(result_count));

            std::vector<boost::asio::ip::udp::endpoint> allowed;
            bool blocked_active_server = false;
            bool blocked_egress_filter = false;
            std::string egress_filter_reason;
            for (const auto& entry : results) {
                if (is_active_server_endpoint(
                        entry.endpoint(), self->cfg_, self_local_addr)) {
                    blocked_active_server = true;
                    continue;
                }
                if (is_allowed_address(entry.endpoint().address(),
                                       self->session_allow_local_ip_,
                                       self->session_control_full_)) {
                    std::string reason;
                    if (!egress_filter_allows(
                            self->manager_, entry.endpoint().address(), &reason)) {
                        blocked_egress_filter = true;
                        if (egress_filter_reason.empty()) {
                            egress_filter_reason = std::move(reason);
                        }
                        continue;
                    }
                    allowed.push_back(entry.endpoint());
                }
            }

            if (allowed.empty()) {
                self->send_open_reply(
                    stream_id,
                    false,
                    blocked_active_server
                        ? "blocked destination: active server endpoint"
                        : (blocked_egress_filter
                               ? "blocked destination: egress filter"
                               : "blocked destination"));
                if (blocked_egress_filter) {
                    util::log_info_rate_limited(
                        "server-open-egress-filter",
                        "egress filter blocked UDP OPEN target " + udp->host +
                            ":" + std::to_string(udp->port) +
                            (egress_filter_reason.empty()
                                 ? ""
                                 : " (" + egress_filter_reason + ")"),
                        30000);
                }
                std::lock_guard<std::mutex> lock(self->streams_mutex_);
                self->udp_streams_.erase(stream_id);
                return;
            }

            prefer_ipv4_endpoints(&allowed);
            udp->remote = allowed.front();
            boost::system::error_code ec2;
            udp->socket.open(udp->remote.protocol(), ec2);
            if (ec2) {
                self->send_open_reply(
                    stream_id, false, "udp open failed: " + ec2.message());
                std::lock_guard<std::mutex> lock(self->streams_mutex_);
                self->udp_streams_.erase(stream_id);
                return;
            }

            udp->socket.connect(udp->remote, ec2);
            if (ec2) {
                self->send_open_reply(
                    stream_id, false, "connect failed: " + ec2.message());
                std::lock_guard<std::mutex> lock(self->streams_mutex_);
                self->udp_streams_.erase(stream_id);
                return;
            }

            self->send_open_reply(stream_id, true, "");
            YUME_TIMING_LOG(
                "server.open",
                "done",
                "session=" + std::to_string(self->session_id_) +
                    " stream=" + std::to_string(stream_id) +
                    " proto=udp ok=1 ms=" +
                    std::to_string(util::now_ms() - udp->open_started_ms));
            self->start_udp_read(stream_id);
        };

    const auto resolver_flags =
        boost::asio::ip::resolver_base::numeric_service;
    if (!cfg_.dns_server.empty() && !resolve_any_family) {
        auto direct_dns = std::make_shared<DirectDnsAQuery>(
            strand_,
            cfg_.dns_server,
            host,
            [self, stream_id, udp, self_local_addr, port](
                bool ok,
                const std::vector<boost::asio::ip::address_v4>& addresses,
                const std::string& reason,
                [[maybe_unused]] int64_t resolve_ms) {
                {
                    std::lock_guard<std::mutex> lock(self->streams_mutex_);
                    if (self->udp_streams_.find(stream_id) ==
                        self->udp_streams_.end()) {
                        return;
                    }
                }
                if (!ok) {
                    YUME_TIMING_LOG(
                        "server.open",
                        "resolve_failed",
                        "session=" + std::to_string(self->session_id_) +
                            " stream=" + std::to_string(stream_id) +
                            " proto=udp direct_dns=1 ms=" +
                            std::to_string(resolve_ms) + " reason=" + reason);
                    self->send_open_reply(
                        stream_id, false, "resolve failed: " + reason);
                    std::lock_guard<std::mutex> lock(self->streams_mutex_);
                    self->udp_streams_.erase(stream_id);
                    return;
                }
                YUME_TIMING_LOG(
                    "server.open",
                    "resolve_ok",
                    "session=" + std::to_string(self->session_id_) +
                        " stream=" + std::to_string(stream_id) +
                        " proto=udp direct_dns=1 ms=" +
                        std::to_string(resolve_ms) +
                        " results=" + std::to_string(addresses.size()));

                std::vector<boost::asio::ip::udp::endpoint> allowed;
                bool blocked_active_server = false;
                bool blocked_egress_filter = false;
                std::string egress_filter_reason;
                for (const auto& address : addresses) {
                    boost::asio::ip::udp::endpoint endpoint(
                        address, static_cast<unsigned short>(port));
                    if (is_active_server_endpoint(
                            endpoint, self->cfg_, self_local_addr)) {
                        blocked_active_server = true;
                        continue;
                    }
                    if (is_allowed_address(endpoint.address(),
                                           self->session_allow_local_ip_,
                                           self->session_control_full_)) {
                        std::string filter_reason;
                        if (!egress_filter_allows(
                                self->manager_,
                                endpoint.address(),
                                &filter_reason)) {
                            blocked_egress_filter = true;
                            if (egress_filter_reason.empty()) {
                                egress_filter_reason = std::move(filter_reason);
                            }
                            continue;
                        }
                        allowed.push_back(endpoint);
                    }
                }

                if (allowed.empty()) {
                    self->send_open_reply(
                        stream_id,
                        false,
                        blocked_active_server
                            ? "blocked destination: active server endpoint"
                            : (blocked_egress_filter
                                   ? "blocked destination: egress filter"
                                   : "blocked destination"));
                    if (blocked_egress_filter) {
                        util::log_info_rate_limited(
                            "server-open-egress-filter",
                            "egress filter blocked UDP OPEN target " +
                                udp->host + ":" + std::to_string(udp->port) +
                                (egress_filter_reason.empty()
                                     ? ""
                                     : " (" + egress_filter_reason + ")"),
                            30000);
                    }
                    std::lock_guard<std::mutex> lock(self->streams_mutex_);
                    self->udp_streams_.erase(stream_id);
                    return;
                }

                udp->remote = allowed.front();
                boost::system::error_code ec2;
                udp->socket.open(udp->remote.protocol(), ec2);
                if (ec2) {
                    self->send_open_reply(
                        stream_id,
                        false,
                        "udp open failed: " + ec2.message());
                    std::lock_guard<std::mutex> lock(self->streams_mutex_);
                    self->udp_streams_.erase(stream_id);
                    return;
                }

                udp->socket.connect(udp->remote, ec2);
                if (ec2) {
                    self->send_open_reply(
                        stream_id,
                        false,
                        "connect failed: " + ec2.message());
                    std::lock_guard<std::mutex> lock(self->streams_mutex_);
                    self->udp_streams_.erase(stream_id);
                    return;
                }

                self->send_open_reply(stream_id, true, "");
                YUME_TIMING_LOG(
                    "server.open",
                    "done",
                    "session=" + std::to_string(self->session_id_) +
                        " stream=" + std::to_string(stream_id) +
                        " proto=udp ok=1 ms=" +
                        std::to_string(util::now_ms() -
                                       udp->open_started_ms));
                self->start_udp_read(stream_id);
            });
        direct_dns->start();
    } else if (resolve_any_family) {
        udp->resolver.async_resolve(
            host,
            std::to_string(port),
            resolver_flags,
            boost::asio::bind_executor(strand_, resolver_handler));
        resolver_timer->async_wait(boost::asio::bind_executor(
            strand_,
            [udp, resolve_timed_out](const boost::system::error_code& ec) {
                if (ec) {
                    return;
                }
                *resolve_timed_out = true;
                udp->resolver.cancel();
            }));
    } else {
        udp->resolver.async_resolve(
            boost::asio::ip::udp::v4(),
            host,
            std::to_string(port),
            resolver_flags,
            boost::asio::bind_executor(strand_, resolver_handler));
        resolver_timer->async_wait(boost::asio::bind_executor(
            strand_,
            [udp, resolve_timed_out](const boost::system::error_code& ec) {
                if (ec) {
                    return;
                }
                *resolve_timed_out = true;
                udp->resolver.cancel();
            }));
    }
}

void Session::start_tcp_open(uint8_t stream_id, const std::string& host, int port) {
    util::log_info("session " + std::to_string(session_id_) + ": OPEN tcp stream " +
                   std::to_string(stream_id) + " -> " + host + ":" + std::to_string(port));
    auto remote = std::make_shared<RemoteStream>(stream_.get_executor());
    remote->host = host;
    remote->port = port;
    remote->open_started_ms = util::now_ms();
    remote->resolve_started_ms = remote->open_started_ms;
    const bool resolve_any_family = server_resolve_any_family_enabled();
    const std::string resolve_family = resolve_any_family ? "any" : "ipv4";
    YUME_TIMING_LOG("server.open",
                    "start",
                    "session=" + std::to_string(session_id_) +
                        " stream=" + std::to_string(stream_id) +
                        " proto=tcp family=" + resolve_family +
                        " target=" + host + ":" + std::to_string(port));
    boost::system::error_code keep_ec;
    remote->socket.set_option(
        boost::asio::socket_base::keep_alive(true), keep_ec);

    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        streams_[stream_id] = remote;
    }

    auto self = shared_from_this();
    const auto self_local_addr = session_local_address(stream_);

    auto resolver_timer =
        std::make_shared<boost::asio::deadline_timer>(stream_.get_executor());
    auto resolve_timed_out = std::make_shared<bool>(false);
    resolver_timer->expires_from_now(
        boost::posix_time::milliseconds(kResolverTimeoutMs));

    auto continue_tcp_open =
        [self, stream_id, remote, self_local_addr](
            std::vector<boost::asio::ip::tcp::endpoint> resolved,
            [[maybe_unused]] std::size_t result_count,
            [[maybe_unused]] int64_t resolve_ms,
            [[maybe_unused]] bool direct_dns) {
            YUME_TIMING_LOG(
                "server.open",
                "resolve_ok",
                "session=" + std::to_string(self->session_id_) +
                    " stream=" + std::to_string(stream_id) + " proto=tcp" +
                    (direct_dns ? std::string(" direct_dns=1")
                                : std::string{}) +
                    " ms=" + std::to_string(resolve_ms) +
                    " results=" + std::to_string(result_count));

            std::vector<boost::asio::ip::tcp::endpoint> allowed;
            bool blocked_active_server = false;
            bool blocked_egress_filter = false;
            std::string egress_filter_reason;
            for (const auto& endpoint : resolved) {
                if (is_active_server_endpoint(
                        endpoint, self->cfg_, self_local_addr)) {
                    blocked_active_server = true;
                    continue;
                }
                if (is_allowed_address(endpoint.address(),
                                       self->session_allow_local_ip_,
                                       self->session_control_full_)) {
                    std::string reason;
                    if (!egress_filter_allows(
                            self->manager_, endpoint.address(), &reason)) {
                        blocked_egress_filter = true;
                        if (egress_filter_reason.empty()) {
                            egress_filter_reason = std::move(reason);
                        }
                        continue;
                    }
                    allowed.push_back(endpoint);
                }
            }

            if (allowed.empty()) {
                self->send_open_reply(
                    stream_id,
                    false,
                    blocked_active_server
                        ? "blocked destination: active server endpoint"
                        : (blocked_egress_filter
                               ? "blocked destination: egress filter"
                               : "blocked destination"));
                if (blocked_egress_filter) {
                    util::log_info_rate_limited(
                        "server-open-egress-filter",
                        "egress filter blocked TCP OPEN target " + remote->host +
                            ":" + std::to_string(remote->port) +
                            (egress_filter_reason.empty()
                                 ? ""
                                 : " (" + egress_filter_reason + ")"),
                        30000);
                }
                std::lock_guard<std::mutex> lock(self->streams_mutex_);
                self->streams_.erase(stream_id);
                return;
            }

            prefer_ipv4_endpoints(&allowed);

            auto connect_timer =
                std::make_shared<boost::asio::deadline_timer>(
                    self->stream_.get_executor());
            auto connect_timed_out = std::make_shared<bool>(false);
            remote->connect_started_ms = util::now_ms();
            connect_timer->expires_from_now(
                boost::posix_time::milliseconds(kConnectTimeoutMs));

            // Capture default `=` so mingw gcc 14 can resolve the nested
            // shared_ptr captures from continue_tcp_open's body.
            boost::asio::async_connect(
                remote->socket,
                allowed,
                boost::asio::bind_executor(
                    self->strand_,
                    [=](const boost::system::error_code& ec2,
                        const boost::asio::ip::tcp::endpoint&) {
                        connect_timer->cancel();
                        [[maybe_unused]] const int64_t connect_ms =
                            remote->connect_started_ms > 0
                                ? (util::now_ms() -
                                   remote->connect_started_ms)
                                : 0;
                        {
                            std::lock_guard<std::mutex> lock(
                                self->streams_mutex_);
                            if (self->streams_.find(stream_id) ==
                                self->streams_.end()) {
                                return;
                            }
                        }
                        if (ec2) {
                            if (ec2 ==
                                    boost::asio::error::operation_aborted &&
                                self->close_state_ != CloseState::Open) {
                                return;
                            }
                            const std::string reason =
                                *connect_timed_out
                                    ? "connect timeout"
                                    : ("connect failed: " + ec2.message());
                            YUME_TIMING_LOG(
                                "server.open",
                                "connect_failed",
                                "session=" +
                                    std::to_string(self->session_id_) +
                                    " stream=" +
                                    std::to_string(stream_id) +
                                    " proto=tcp ms=" +
                                    std::to_string(connect_ms) +
                                    " reason=" + reason);
                            self->send_open_reply(stream_id, false, reason);
                            std::lock_guard<std::mutex> lock(
                                self->streams_mutex_);
                            self->streams_.erase(stream_id);
                            return;
                        }
                        boost::system::error_code nodelay_ec;
                        remote->socket.set_option(
                            boost::asio::ip::tcp::no_delay(true),
                            nodelay_ec);
                        boost::system::error_code remote_recvbuf_ec;
                        remote->socket.set_option(
                            boost::asio::socket_base::receive_buffer_size(
                                kSocketBufferBytes),
                            remote_recvbuf_ec);
                        boost::system::error_code remote_sendbuf_ec;
                        remote->socket.set_option(
                            boost::asio::socket_base::send_buffer_size(
                                kSocketBufferBytes),
                            remote_sendbuf_ec);
                        remote->connected = true;
                        self->send_open_reply(stream_id, true, "");
                        YUME_TIMING_LOG(
                            "server.open",
                            "done",
                            "session=" +
                                std::to_string(self->session_id_) +
                                " stream=" + std::to_string(stream_id) +
                                " proto=tcp ok=1 connect_ms=" +
                                std::to_string(connect_ms) +
                                " total_ms=" +
                                std::to_string(util::now_ms() -
                                               remote->open_started_ms));
                        self->start_remote_read(stream_id);
                        self->do_remote_write(stream_id);
                    }));

            connect_timer->async_wait(boost::asio::bind_executor(
                self->strand_,
                [self, stream_id, remote, connect_timed_out](
                    const boost::system::error_code& ec) {
                    if (ec) {
                        return;
                    }
                    *connect_timed_out = true;
                    boost::system::error_code ignore_ec;
                    remote->socket.close(ignore_ec);
                }));
        };

    auto resolver_handler =
        [=](const boost::system::error_code& ec,
            const boost::asio::ip::tcp::resolver::results_type& results) {
            resolver_timer->cancel();
            const int64_t resolve_ms =
                remote->resolve_started_ms > 0
                    ? (util::now_ms() - remote->resolve_started_ms)
                    : 0;
            {
                std::lock_guard<std::mutex> lock(self->streams_mutex_);
                if (self->streams_.find(stream_id) ==
                    self->streams_.end()) {
                    return;
                }
            }

            if (ec) {
                if (ec == boost::asio::error::operation_aborted &&
                    self->close_state_ != CloseState::Open) {
                    return;
                }
                const std::string reason =
                    *resolve_timed_out ? "resolve timeout"
                                       : ("resolve failed: " + ec.message());
                YUME_TIMING_LOG(
                    "server.open",
                    "resolve_failed",
                    "session=" + std::to_string(self->session_id_) +
                        " stream=" + std::to_string(stream_id) +
                        " proto=tcp ms=" + std::to_string(resolve_ms) +
                        " reason=" + reason);
                self->send_open_reply(stream_id, false, reason);
                std::lock_guard<std::mutex> lock(self->streams_mutex_);
                self->streams_.erase(stream_id);
                return;
            }
            std::size_t result_count = 0;
            std::vector<boost::asio::ip::tcp::endpoint> resolved;
            for (const auto& result : results) {
                resolved.push_back(result.endpoint());
                ++result_count;
            }
            continue_tcp_open(
                std::move(resolved), result_count, resolve_ms, false);
        };

    const auto resolver_flags =
        boost::asio::ip::resolver_base::numeric_service;
    if (!cfg_.dns_server.empty() && !resolve_any_family) {
        auto direct_dns = std::make_shared<DirectDnsAQuery>(
            strand_,
            cfg_.dns_server,
            host,
            [self, stream_id, remote, port, continue_tcp_open](
                bool ok,
                const std::vector<boost::asio::ip::address_v4>& addresses,
                const std::string& reason,
                int64_t resolve_ms) {
                {
                    std::lock_guard<std::mutex> lock(self->streams_mutex_);
                    if (self->streams_.find(stream_id) ==
                        self->streams_.end()) {
                        return;
                    }
                }
                if (!ok) {
                    YUME_TIMING_LOG(
                        "server.open",
                        "resolve_failed",
                        "session=" + std::to_string(self->session_id_) +
                            " stream=" + std::to_string(stream_id) +
                            " proto=tcp direct_dns=1 ms=" +
                            std::to_string(resolve_ms) + " reason=" + reason);
                    self->send_open_reply(
                        stream_id, false, "resolve failed: " + reason);
                    std::lock_guard<std::mutex> lock(self->streams_mutex_);
                    self->streams_.erase(stream_id);
                    return;
                }
                std::vector<boost::asio::ip::tcp::endpoint> resolved;
                resolved.reserve(addresses.size());
                for (const auto& address : addresses) {
                    resolved.emplace_back(
                        address, static_cast<unsigned short>(port));
                }
                continue_tcp_open(
                    std::move(resolved), addresses.size(), resolve_ms, true);
            });
        direct_dns->start();
    } else if (resolve_any_family) {
        remote->resolver.async_resolve(
            host,
            std::to_string(port),
            resolver_flags,
            boost::asio::bind_executor(strand_, resolver_handler));
        resolver_timer->async_wait(boost::asio::bind_executor(
            strand_,
            [self, stream_id, remote, resolve_timed_out](
                const boost::system::error_code& ec) {
                if (ec) {
                    return;
                }
                *resolve_timed_out = true;
                remote->resolver.cancel();
            }));
    } else {
        remote->resolver.async_resolve(
            boost::asio::ip::tcp::v4(),
            host,
            std::to_string(port),
            resolver_flags,
            boost::asio::bind_executor(strand_, resolver_handler));
        resolver_timer->async_wait(boost::asio::bind_executor(
            strand_,
            [self, stream_id, remote, resolve_timed_out](
                const boost::system::error_code& ec) {
                if (ec) {
                    return;
                }
                *resolve_timed_out = true;
                remote->resolver.cancel();
            }));
    }
}

}  // namespace yume::server
