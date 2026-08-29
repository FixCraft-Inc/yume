/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/session/session.hpp"
#include "server/session/internal.hpp"

namespace yume::server {

using namespace detail;

namespace {

struct ResolveClassification {
    bool ignore_{false};
    std::string error_;
};

ResolveClassification classify_resolve_result(
    const boost::system::error_code& error,
    bool timed_out,
    bool session_closing) {
    if (!error) return {};
    if (error == boost::asio::error::operation_aborted && session_closing) {
        return {true, {}};
    }
    return {false, timed_out ? "resolve timeout"
                             : "resolve failed: " + error.message()};
}

template <typename Executor, typename Cancel>
void arm_resolver_timeout(
    const std::shared_ptr<boost::asio::deadline_timer>& timer,
    Executor executor,
    const std::shared_ptr<bool>& timed_out,
    Cancel cancel) {
    timer->async_wait(boost::asio::bind_executor(
        std::move(executor),
        [timed_out, cancel = std::move(cancel)](
            const boost::system::error_code& error) mutable {
            if (error) return;
            *timed_out = true;
            cancel();
        }));
}

template <typename Endpoint>
struct EndpointFilterResult {
    std::vector<Endpoint> allowed_;
    bool blocked_active_server_{false};
    bool blocked_egress_filter_{false};
    std::string egress_filter_reason_;

    std::string rejection_reason() const {
        if (blocked_active_server_) {
            return "blocked destination: active server endpoint";
        }
        if (blocked_egress_filter_) {
            return "blocked destination: egress filter";
        }
        return "blocked destination";
    }
};

template <typename Endpoint, typename Config, typename LocalAddress>
EndpointFilterResult<Endpoint> filter_open_endpoints(
    std::vector<Endpoint> resolved,
    const Config& config,
    const LocalAddress& session_local_address,
    bool allow_local_ip,
    bool full_control,
    Manager* manager) {
    EndpointFilterResult<Endpoint> result;
    result.allowed_.reserve(resolved.size());
    for (auto& endpoint : resolved) {
        if (is_active_server_endpoint(
                endpoint, config, session_local_address)) {
            result.blocked_active_server_ = true;
            continue;
        }
        if (!is_allowed_address(endpoint.address(), allow_local_ip,
                                full_control)) {
            continue;
        }
        std::string reason;
        if (!egress_filter_allows(manager, endpoint.address(), &reason)) {
            result.blocked_egress_filter_ = true;
            if (result.egress_filter_reason_.empty()) {
                result.egress_filter_reason_ = std::move(reason);
            }
            continue;
        }
        result.allowed_.push_back(std::move(endpoint));
    }
    return result;
}

}  // namespace

void Session::start_udp_open(uint8_t stream_id, const std::string& host, int port) {
    util::log_info("session " + std::to_string(session_id_) + ": OPEN udp stream " +
                   std::to_string(stream_id) + " -> " + host + ":" + std::to_string(port));
    auto udp = std::make_shared<UdpStream>(stream_.get_executor());
    udp->host = host;
    udp->port = port;
    udp->open_started_ms = diagnostics::timing_now_ms();
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
                diagnostics::elapsed_ms_since(udp->resolve_started_ms);
            {
                std::lock_guard<std::mutex> lock(self->streams_mutex_);
                if (self->udp_streams_.find(stream_id) ==
                    self->udp_streams_.end()) {
                    return;
                }
            }

            const ResolveClassification resolve = classify_resolve_result(
                ec, *resolve_timed_out,
                self->close_state_ != CloseState::Open);
            if (resolve.ignore_) {
                return;
            }
            if (!resolve.error_.empty()) {
                YUME_TIMING_LOG(
                    "server.open",
                    "resolve_failed",
                    "session=" + std::to_string(self->session_id_) +
                        " stream=" + std::to_string(stream_id) +
                        " proto=udp ms=" + std::to_string(resolve_ms) +
                        " reason=" + resolve.error_);
                self->send_open_reply(stream_id, false, resolve.error_);
                std::lock_guard<std::mutex> lock(self->streams_mutex_);
                self->udp_streams_.erase(stream_id);
                return;
            }

            std::vector<boost::asio::ip::udp::endpoint> resolved;
            for (const auto& result : results) {
                resolved.push_back(result.endpoint());
            }
            YUME_TIMING_LOG(
                "server.open",
                "resolve_ok",
                "session=" + std::to_string(self->session_id_) +
                    " stream=" + std::to_string(stream_id) +
                    " proto=udp ms=" + std::to_string(resolve_ms) +
                    " results=" + std::to_string(resolved.size()));

            auto filtered = filter_open_endpoints(
                std::move(resolved), self->cfg_, self_local_addr,
                self->session_allow_local_ip_, self->session_control_full_,
                self->manager_);
            if (filtered.allowed_.empty()) {
                self->send_open_reply(stream_id, false,
                                      filtered.rejection_reason());
                if (filtered.blocked_egress_filter_) {
                    util::log_info_rate_limited(
                        "server-open-egress-filter",
                        "egress filter blocked UDP OPEN target " + udp->host +
                            ":" + std::to_string(udp->port) +
                            (filtered.egress_filter_reason_.empty()
                                 ? ""
                                 : " (" + filtered.egress_filter_reason_ + ")"),
                        30000);
                }
                std::lock_guard<std::mutex> lock(self->streams_mutex_);
                self->udp_streams_.erase(stream_id);
                return;
            }

            prefer_ipv4_endpoints(&filtered.allowed_);
            udp->remote = filtered.allowed_.front();
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
                    std::to_string(diagnostics::elapsed_ms_since(udp->open_started_ms)));
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

                std::vector<boost::asio::ip::udp::endpoint> resolved;
                resolved.reserve(addresses.size());
                for (const auto& address : addresses) {
                    resolved.emplace_back(
                        address, static_cast<unsigned short>(port));
                }
                auto filtered = filter_open_endpoints(
                    std::move(resolved), self->cfg_, self_local_addr,
                    self->session_allow_local_ip_,
                    self->session_control_full_, self->manager_);
                if (filtered.allowed_.empty()) {
                    self->send_open_reply(stream_id, false,
                                          filtered.rejection_reason());
                    if (filtered.blocked_egress_filter_) {
                        util::log_info_rate_limited(
                            "server-open-egress-filter",
                            "egress filter blocked UDP OPEN target " +
                                udp->host + ":" + std::to_string(udp->port) +
                                (filtered.egress_filter_reason_.empty()
                                     ? ""
                                     : " (" +
                                           filtered.egress_filter_reason_ +
                                           ")"),
                            30000);
                    }
                    std::lock_guard<std::mutex> lock(self->streams_mutex_);
                    self->udp_streams_.erase(stream_id);
                    return;
                }

                udp->remote = filtered.allowed_.front();
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
                        std::to_string(diagnostics::elapsed_ms_since(udp->open_started_ms)));
                self->start_udp_read(stream_id);
            });
        direct_dns->start();
    } else if (resolve_any_family) {
        udp->resolver.async_resolve(
            host,
            std::to_string(port),
            resolver_flags,
            boost::asio::bind_executor(strand_, resolver_handler));
        arm_resolver_timeout(resolver_timer, strand_, resolve_timed_out,
                             [udp] { udp->resolver.cancel(); });
    } else {
        udp->resolver.async_resolve(
            boost::asio::ip::udp::v4(),
            host,
            std::to_string(port),
            resolver_flags,
            boost::asio::bind_executor(strand_, resolver_handler));
        arm_resolver_timeout(resolver_timer, strand_, resolve_timed_out,
                             [udp] { udp->resolver.cancel(); });
    }
}

void Session::start_tcp_open(uint8_t stream_id, const std::string& host, int port) {
    util::log_info("session " + std::to_string(session_id_) + ": OPEN tcp stream " +
                   std::to_string(stream_id) + " -> " + host + ":" + std::to_string(port));
    auto remote = std::make_shared<RemoteStream>(stream_.get_executor());
    remote->host = host;
    remote->port = port;
    remote->open_started_ms = diagnostics::timing_now_ms();
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

            auto filtered = filter_open_endpoints(
                std::move(resolved), self->cfg_, self_local_addr,
                self->session_allow_local_ip_, self->session_control_full_,
                self->manager_);
            if (filtered.allowed_.empty()) {
                self->send_open_reply(stream_id, false,
                                      filtered.rejection_reason());
                if (filtered.blocked_egress_filter_) {
                    util::log_info_rate_limited(
                        "server-open-egress-filter",
                        "egress filter blocked TCP OPEN target " + remote->host +
                            ":" + std::to_string(remote->port) +
                            (filtered.egress_filter_reason_.empty()
                                 ? ""
                                 : " (" +
                                       filtered.egress_filter_reason_ + ")"),
                        30000);
                }
                std::lock_guard<std::mutex> lock(self->streams_mutex_);
                self->streams_.erase(stream_id);
                return;
            }

            prefer_ipv4_endpoints(&filtered.allowed_);

            auto connect_timer =
                std::make_shared<boost::asio::deadline_timer>(
                    self->stream_.get_executor());
            auto connect_timed_out = std::make_shared<bool>(false);
            remote->connect_started_ms = diagnostics::timing_now_ms();
            connect_timer->expires_from_now(
                boost::posix_time::milliseconds(kConnectTimeoutMs));

            // Capture default `=` so mingw gcc 14 can resolve the nested
            // shared_ptr captures from continue_tcp_open's body.
            boost::asio::async_connect(
                remote->socket,
                filtered.allowed_,
                boost::asio::bind_executor(
                    self->strand_,
                    [=](const boost::system::error_code& ec2,
                        const boost::asio::ip::tcp::endpoint&) {
                        connect_timer->cancel();
                        [[maybe_unused]] const int64_t connect_ms =
                            diagnostics::elapsed_ms_since(remote->connect_started_ms);
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
                        // Buffers left to the kernel: an explicit
                        // SO_RCVBUF/SO_SNDBUF disables Linux window
                        // autotuning for the connection's lifetime. This is
                        // the exit leg to the target, frequently the longest
                        // path in a deployment, so it is exactly where the
                        // window has to grow into the bandwidth-delay
                        // product. Same reasoning as the tunnel socket in
                        // session.cpp.
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
                                std::to_string(diagnostics::elapsed_ms_since(remote->open_started_ms)));
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
                diagnostics::elapsed_ms_since(remote->resolve_started_ms);
            {
                std::lock_guard<std::mutex> lock(self->streams_mutex_);
                if (self->streams_.find(stream_id) ==
                    self->streams_.end()) {
                    return;
                }
            }

            const ResolveClassification resolve = classify_resolve_result(
                ec, *resolve_timed_out,
                self->close_state_ != CloseState::Open);
            if (resolve.ignore_) {
                return;
            }
            if (!resolve.error_.empty()) {
                YUME_TIMING_LOG(
                    "server.open",
                    "resolve_failed",
                    "session=" + std::to_string(self->session_id_) +
                        " stream=" + std::to_string(stream_id) +
                        " proto=tcp ms=" + std::to_string(resolve_ms) +
                        " reason=" + resolve.error_);
                self->send_open_reply(stream_id, false, resolve.error_);
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
        arm_resolver_timeout(resolver_timer, strand_, resolve_timed_out,
                             [remote] { remote->resolver.cancel(); });
    } else {
        remote->resolver.async_resolve(
            boost::asio::ip::tcp::v4(),
            host,
            std::to_string(port),
            resolver_flags,
            boost::asio::bind_executor(strand_, resolver_handler));
        arm_resolver_timeout(resolver_timer, strand_, resolve_timed_out,
                             [remote] { remote->resolver.cancel(); });
    }
}

}  // namespace yume::server
