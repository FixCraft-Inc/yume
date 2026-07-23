/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * ----------------------------------------------------------------
 * Session stream-open routing, extracted verbatim from session.cpp:
 *   - handle_open       — inbound OPEN dispatch: target validation,
 *                         egress filtering, DNS resolve + upstream connect
 *                         (TCP/UDP), reverse-listen and federation routing
 *   - reserve_stream_id — server-initiated stream id allocation
 *   - handle_rlisten    — reverse-listener (RLISTEN) accept loop
 *
 * Same Session:: class, same wire output, no behavior change. Shared
 * helpers (DNS / address classification / DirectDnsAQuery) via
 * server/session/internal.hpp.
 * ---------------------------------------------------------------- */

#include "server/session/session.hpp"
#include "server/runtime/manager.hpp"
#include "server/session/internal.hpp"

namespace yume::server {

using namespace detail;

void Session::handle_open(const protocol::Frame& frame) {
    if (frame.header.stream_id == 0) {
        send_open_reply(frame.header.stream_id, false, "invalid stream id");
        return;
    }
    if (pending_reverse_.find(frame.header.stream_id) != pending_reverse_.end()) {
        bool ok = (frame.header.flags & protocol::kFlagOpenOk) != 0;
        crypto::Bytes payload = frame.payload;
        if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
            crypto::Bytes decrypted;
            if (decrypt_inner_payload(frame.header.type, frame.header.stream_id, frame.payload, &decrypted)) {
                payload = std::move(decrypted);
            } else {
                ok = false;
            }
        }
        if (!ok) {
            std::string reason(payload.begin(), payload.end());
            util::log_warn("reverse open failed: " + reason);
            handle_close(frame.header.stream_id, "reverse open failed");
        } else {
            std::shared_ptr<RemoteStream> remote;
            {
                std::lock_guard<std::mutex> lock(streams_mutex_);
                auto it = streams_.find(frame.header.stream_id);
                if (it != streams_.end()) {
                    remote = it->second;
                }
            }
            if (remote && remote->open_timer) {
                boost::system::error_code timer_ec;
                remote->open_timer->cancel(timer_ec);
                remote->open_timer.reset();
            }
            start_remote_read(frame.header.stream_id);
        }
        pending_reverse_.erase(frame.header.stream_id);
        return;
    }
    bool stream_id_in_use = false;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        stream_id_in_use = stream_id_in_use_locked(frame.header.stream_id);
    }
    if (stream_id_in_use) {
        send_open_reply(frame.header.stream_id, false, "stream already exists");
        return;
    }
    bool control_stream_id_in_use = false;
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        control_stream_id_in_use =
            control_outbound_.find(frame.header.stream_id) != control_outbound_.end() ||
            control_inbound_.find(frame.header.stream_id) != control_inbound_.end() ||
            federated_streams_.find(frame.header.stream_id) != federated_streams_.end();
    }
    if (control_stream_id_in_use) {
        send_open_reply(frame.header.stream_id, false, "stream already exists");
        return;
    }

    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        crypto::Bytes decrypted;
        if (decrypt_inner_payload(frame.header.type, frame.header.stream_id, frame.payload, &decrypted)) {
            payload = std::move(decrypted);
        } else {
            util::log_warn("session " + std::to_string(session_id_) + ": OPEN decrypt failed for stream " +
                           std::to_string(frame.header.stream_id));
            close_with_reason("OPEN decrypt failed for stream " + std::to_string(frame.header.stream_id));
            return;
        }
    }
    std::string payload_str(payload.begin(), payload.end());
    std::string host;
    int port = 0;
    std::string proto;
    nlohmann::json open_json;

    try {
        open_json = nlohmann::json::parse(payload_str);
        // Service routing must precede every generic/relay interpretation.
        // Preauth admits only the exact {proto, service} shape, while normal
        // authorized callers may carry future service metadata without ever
        // falling into a different OPEN branch.
        if (handle_service_open(frame.header.stream_id, open_json)) {
            return;
        }
        if (open_json.contains("target_id") && open_json.contains("channel_kind") && open_json.contains("channel_id")) {
            const std::string target_id = open_json.value("target_id", "");
            const std::string from_id = open_json.value("from_id", client_id_);
            const std::string channel_id = open_json.value("channel_id", "");
            const auto channel_kind = control::channel_kind_from_string(open_json.value("channel_kind", "chat"));
            if (!cfg_.relay_enable) {
                send_open_reply(frame.header.stream_id, false, "relay disabled");
                return;
            }
            if (target_id.empty() || channel_id.empty() || from_id.empty()) {
                send_open_reply(frame.header.stream_id, false, "invalid relay open");
                return;
            }
            if (!is_federation_authenticated() && from_id != client_id_) {
                send_open_reply(frame.header.stream_id, false, "relay origin mismatch");
                return;
            }
            std::string federated_error;
            if (manager_ && manager_->open_federated_channel(shared_from_this(), frame.header.stream_id, open_json, &federated_error)) {
                if (!federated_error.empty()) {
                    send_open_reply(frame.header.stream_id, false, federated_error);
                }
                return;
            }
            std::shared_ptr<Session> target;
            control::PendingInvite invite;
            std::string error;
            if (!manager_ || !manager_->can_open_channel(channel_id, from_id, target_id, channel_kind, &target, &invite, &error)) {
                send_open_reply(frame.header.stream_id, false, error.empty() ? "invite invalid" : error);
                return;
            }
            if (channel_kind == control::ChannelKind::admin && client_relay_mode_ != control::RelayMode::trusted) {
                send_open_reply(frame.header.stream_id, false, "admin requires trusted relay mode");
                return;
            }
            if (channel_kind == control::ChannelKind::chat && !client_allow_chat_) {
                send_open_reply(frame.header.stream_id, false, "chat disabled");
                return;
            }
            if (channel_kind == control::ChannelKind::file && !client_allow_file_) {
                send_open_reply(frame.header.stream_id, false, "file relay disabled");
                return;
            }
            if (channel_kind == control::ChannelKind::bytes && !client_allow_bytes_) {
                send_open_reply(frame.header.stream_id, false, "byte relay disabled");
                return;
            }
            if (target.get() == this) {
                send_open_reply(frame.header.stream_id, false, "invalid relay target");
                return;
            }
            uint8_t target_stream = target->reserve_stream_id();
            if (target_stream == 0) {
                send_open_reply(frame.header.stream_id, false, "no stream ids available");
                return;
            }
            {
                std::lock_guard<std::mutex> lock(control_mutex_);
                control_outbound_[frame.header.stream_id] = ControlLink{
                    target,
                    target_stream,
                    true,
                    false,
                    channel_kind,
                    channel_id,
                    from_id,
                    target_id};
            }
            {
                std::lock_guard<std::mutex> lock(target->control_mutex_);
                target->control_inbound_[target_stream] = ControlLink{
                    shared_from_this(),
                    frame.header.stream_id,
                    true,
                    false,
                    channel_kind,
                    channel_id,
                    from_id,
                    target_id};
            }
            if (manager_) {
                control::ActiveRelayChannel channel;
                channel.channel_id = channel_id;
                channel.channel_kind = channel_kind;
                channel.left_endpoint_id = from_id;
                channel.right_endpoint_id = target_id;
                channel.left_stream_id = frame.header.stream_id;
                channel.right_stream_id = target_stream;
                channel.pending = true;
                manager_->register_active_channel(channel);
                if (channel_kind == control::ChannelKind::admin) {
                    manager_->add_admin_relationship(from_id, target_id);
                }
            }
            target->send_control_frame(protocol::SOPEN, target_stream, payload);
            return;
        }
        host = open_json.value("host", "");
        port = open_json.value("port", 0);
        proto = open_json.value("proto", "");
    } catch (const std::exception&) {
        send_open_reply(frame.header.stream_id, false, "invalid OPEN payload");
        return;
    }

    if (proto == std::string(protocol::packet_bulk::kOpenProto)) {
        if (!handle_packet_open(frame.header.stream_id)) {
            return;
        }
        return;
    }

    if (proto == kBenchSinkProto || proto == kBenchSourceProto) {
        handle_bench_open(frame.header.stream_id, proto, open_json);
        return;
    }

    if (proto == std::string(app_codec::kOpenProto)) {
        handle_codec_open(frame.header.stream_id, open_json);
        return;
    }

    if (host.empty() || port <= 0) {
        send_open_reply(frame.header.stream_id, false, "missing host/port");
        return;
    }
    if (is_blocked_host_literal(host, session_allow_local_ip_, session_control_full_)) {
        send_open_reply(frame.header.stream_id, false, "blocked destination");
        return;
    }

    if (proto.empty()) {
        proto = "tcp";
    }
    if (proto != "tcp" && proto != "udp") {
        send_open_reply(frame.header.stream_id, false, "proto not supported");
        return;
    }

    if (proto == "udp") {
        util::log_info("session " + std::to_string(session_id_) + ": OPEN udp stream " +
                       std::to_string(frame.header.stream_id) + " -> " + host + ":" + std::to_string(port));
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
                             " stream=" + std::to_string(frame.header.stream_id) +
                             " proto=udp family=" + resolve_family +
                             " target=" + host + ":" + std::to_string(port));

        {
            std::lock_guard<std::mutex> lock(streams_mutex_);
            udp_streams_[frame.header.stream_id] = udp;
        }

        auto self = shared_from_this();
        const auto self_local_addr = session_local_address(stream_);

        auto resolver_timer = std::make_shared<boost::asio::deadline_timer>(stream_.get_executor());
        auto resolve_timed_out = std::make_shared<bool>(false);
        resolver_timer->expires_from_now(boost::posix_time::milliseconds(kResolverTimeoutMs));

        auto resolver_handler = [self, stream_id = frame.header.stream_id, udp, self_local_addr, resolver_timer, resolve_timed_out](const boost::system::error_code& ec,
                                                                                                                                   const boost::asio::ip::udp::resolver::results_type& results) {
            resolver_timer->cancel();
            const int64_t resolve_ms = udp->resolve_started_ms > 0 ? (util::now_ms() - udp->resolve_started_ms) : 0;
            {
                std::lock_guard<std::mutex> lock(self->streams_mutex_);
                if (self->udp_streams_.find(stream_id) == self->udp_streams_.end()) {
                    return;
                }
            }

            if (ec) {
                if (ec == boost::asio::error::operation_aborted &&
                    self->close_state_ != CloseState::Open) {
                    return;
                }
                const std::string reason = *resolve_timed_out
                    ? "resolve timeout"
                    : ("resolve failed: " + ec.message());
                YUME_TIMING_LOG("server.open",
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
            YUME_TIMING_LOG("server.open",
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
                if (is_active_server_endpoint(entry.endpoint(), self->cfg_, self_local_addr)) {
                    blocked_active_server = true;
                    continue;
                }
                if (is_allowed_address(entry.endpoint().address(),
                                       self->session_allow_local_ip_,
                                       self->session_control_full_)) {
                    std::string reason;
                    if (!egress_filter_allows(self->manager_, entry.endpoint().address(), &reason)) {
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
                self->send_open_reply(stream_id,
                                     false,
                                     blocked_active_server
                                         ? "blocked destination: active server endpoint"
                                         : (blocked_egress_filter
                                             ? "blocked destination: egress filter"
                                             : "blocked destination"));
                if (blocked_egress_filter) {
                    util::log_info_rate_limited(
                        "server-open-egress-filter",
                        "egress filter blocked UDP OPEN target " + udp->host + ":" +
                            std::to_string(udp->port) +
                            (egress_filter_reason.empty() ? "" : " (" + egress_filter_reason + ")"),
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
                self->send_open_reply(stream_id, false, "udp open failed: " + ec2.message());
                std::lock_guard<std::mutex> lock(self->streams_mutex_);
                self->udp_streams_.erase(stream_id);
                return;
            }

            udp->socket.connect(udp->remote, ec2);
            if (ec2) {
                self->send_open_reply(stream_id, false, "connect failed: " + ec2.message());
                std::lock_guard<std::mutex> lock(self->streams_mutex_);
                self->udp_streams_.erase(stream_id);
                return;
            }

            self->send_open_reply(stream_id, true, "");
            YUME_TIMING_LOG("server.open",
                             "done",
                             "session=" + std::to_string(self->session_id_) +
                                 " stream=" + std::to_string(stream_id) +
                                 " proto=udp ok=1 ms=" +
                                 std::to_string(util::now_ms() - udp->open_started_ms));
            self->start_udp_read(stream_id);
        };

        const auto resolver_flags = boost::asio::ip::resolver_base::numeric_service;
        if (!cfg_.dns_server.empty() && !resolve_any_family) {
            auto direct_dns = std::make_shared<DirectDnsAQuery>(
                strand_,
                cfg_.dns_server,
                host,
                [self, stream_id = frame.header.stream_id, udp, self_local_addr, port](
                    bool ok,
                    const std::vector<boost::asio::ip::address_v4>& addresses,
                    const std::string& reason,
                    int64_t resolve_ms) {
                    {
                        std::lock_guard<std::mutex> lock(self->streams_mutex_);
                        if (self->udp_streams_.find(stream_id) == self->udp_streams_.end()) {
                            return;
                        }
                    }
                    if (!ok) {
                        YUME_TIMING_LOG("server.open",
                                         "resolve_failed",
                                         "session=" + std::to_string(self->session_id_) +
                                             " stream=" + std::to_string(stream_id) +
                                             " proto=udp direct_dns=1 ms=" + std::to_string(resolve_ms) +
                                             " reason=" + reason);
                        self->send_open_reply(stream_id, false, "resolve failed: " + reason);
                        std::lock_guard<std::mutex> lock(self->streams_mutex_);
                        self->udp_streams_.erase(stream_id);
                        return;
                    }
                    YUME_TIMING_LOG("server.open",
                                     "resolve_ok",
                                     "session=" + std::to_string(self->session_id_) +
                                         " stream=" + std::to_string(stream_id) +
                                         " proto=udp direct_dns=1 ms=" + std::to_string(resolve_ms) +
                                         " results=" + std::to_string(addresses.size()));

                    std::vector<boost::asio::ip::udp::endpoint> allowed;
                    bool blocked_active_server = false;
                    bool blocked_egress_filter = false;
                    std::string egress_filter_reason;
                    for (const auto& address : addresses) {
                        boost::asio::ip::udp::endpoint endpoint(address, static_cast<unsigned short>(port));
                        if (is_active_server_endpoint(endpoint, self->cfg_, self_local_addr)) {
                            blocked_active_server = true;
                            continue;
                        }
                        if (is_allowed_address(endpoint.address(),
                                               self->session_allow_local_ip_,
                                               self->session_control_full_)) {
                            std::string reason;
                            if (!egress_filter_allows(self->manager_, endpoint.address(), &reason)) {
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
                        self->send_open_reply(stream_id,
                                             false,
                                             blocked_active_server
                                                 ? "blocked destination: active server endpoint"
                                                 : (blocked_egress_filter
                                                     ? "blocked destination: egress filter"
                                                     : "blocked destination"));
                        if (blocked_egress_filter) {
                            util::log_info_rate_limited(
                                "server-open-egress-filter",
                                "egress filter blocked UDP OPEN target " + udp->host + ":" +
                                    std::to_string(udp->port) +
                                    (egress_filter_reason.empty() ? "" : " (" + egress_filter_reason + ")"),
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
                        self->send_open_reply(stream_id, false, "udp open failed: " + ec2.message());
                        std::lock_guard<std::mutex> lock(self->streams_mutex_);
                        self->udp_streams_.erase(stream_id);
                        return;
                    }

                    udp->socket.connect(udp->remote, ec2);
                    if (ec2) {
                        self->send_open_reply(stream_id, false, "connect failed: " + ec2.message());
                        std::lock_guard<std::mutex> lock(self->streams_mutex_);
                        self->udp_streams_.erase(stream_id);
                        return;
                    }

                    self->send_open_reply(stream_id, true, "");
                    YUME_TIMING_LOG("server.open",
                                     "done",
                                     "session=" + std::to_string(self->session_id_) +
                                         " stream=" + std::to_string(stream_id) +
                                         " proto=udp ok=1 ms=" +
                                         std::to_string(util::now_ms() - udp->open_started_ms));
                    self->start_udp_read(stream_id);
                });
            direct_dns->start();
        } else if (resolve_any_family) {
            udp->resolver.async_resolve(host, std::to_string(port), resolver_flags,
                                        boost::asio::bind_executor(strand_, resolver_handler));
            resolver_timer->async_wait(boost::asio::bind_executor(strand_,
                [udp, resolve_timed_out](const boost::system::error_code& ec) {
                    if (ec) {
                        return;
                    }
                    *resolve_timed_out = true;
                    udp->resolver.cancel();
                }));
        } else {
            udp->resolver.async_resolve(boost::asio::ip::udp::v4(), host, std::to_string(port), resolver_flags,
                                        boost::asio::bind_executor(strand_, resolver_handler));
            resolver_timer->async_wait(boost::asio::bind_executor(strand_,
                [udp, resolve_timed_out](const boost::system::error_code& ec) {
                    if (ec) {
                        return;
                    }
                    *resolve_timed_out = true;
                    udp->resolver.cancel();
                }));
        }

        return;
    }

    util::log_info("session " + std::to_string(session_id_) + ": OPEN tcp stream " +
                   std::to_string(frame.header.stream_id) + " -> " + host + ":" + std::to_string(port));
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
                         " stream=" + std::to_string(frame.header.stream_id) +
                         " proto=tcp family=" + resolve_family +
                         " target=" + host + ":" + std::to_string(port));
    boost::system::error_code keep_ec;
    remote->socket.set_option(boost::asio::socket_base::keep_alive(true), keep_ec);

    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        streams_[frame.header.stream_id] = remote;
    }

    auto self = shared_from_this();
    const auto self_local_addr = session_local_address(stream_);

    auto resolver_timer = std::make_shared<boost::asio::deadline_timer>(stream_.get_executor());
    auto resolve_timed_out = std::make_shared<bool>(false);
    resolver_timer->expires_from_now(boost::posix_time::milliseconds(kResolverTimeoutMs));

    auto continue_tcp_open = [self,
                              stream_id = frame.header.stream_id,
                              remote,
                              self_local_addr](std::vector<boost::asio::ip::tcp::endpoint> resolved,
                                               std::size_t result_count,
                                               int64_t resolve_ms,
                                               bool direct_dns) {
        YUME_TIMING_LOG("server.open",
                         "resolve_ok",
                         "session=" + std::to_string(self->session_id_) +
                             " stream=" + std::to_string(stream_id) +
                             " proto=tcp" +
                             (direct_dns ? std::string(" direct_dns=1") : std::string{}) +
                             " ms=" + std::to_string(resolve_ms) +
                             " results=" + std::to_string(result_count));

        std::vector<boost::asio::ip::tcp::endpoint> allowed;
        bool blocked_active_server = false;
        bool blocked_egress_filter = false;
        std::string egress_filter_reason;
        for (const auto& endpoint : resolved) {
            if (is_active_server_endpoint(endpoint, self->cfg_, self_local_addr)) {
                blocked_active_server = true;
                continue;
            }
            if (is_allowed_address(endpoint.address(),
                                   self->session_allow_local_ip_,
                                   self->session_control_full_)) {
                std::string reason;
                if (!egress_filter_allows(self->manager_, endpoint.address(), &reason)) {
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
            self->send_open_reply(stream_id,
                                  false,
                                  blocked_active_server
                                      ? "blocked destination: active server endpoint"
                                      : (blocked_egress_filter
                                          ? "blocked destination: egress filter"
                                          : "blocked destination"));
            if (blocked_egress_filter) {
                util::log_info_rate_limited(
                    "server-open-egress-filter",
                    "egress filter blocked TCP OPEN target " + remote->host + ":" +
                        std::to_string(remote->port) +
                        (egress_filter_reason.empty() ? "" : " (" + egress_filter_reason + ")"),
                    30000);
            }
            std::lock_guard<std::mutex> lock(self->streams_mutex_);
            self->streams_.erase(stream_id);
            return;
        }

        prefer_ipv4_endpoints(&allowed);

        auto connect_timer = std::make_shared<boost::asio::deadline_timer>(self->stream_.get_executor());
        auto connect_timed_out = std::make_shared<bool>(false);
        remote->connect_started_ms = util::now_ms();
        connect_timer->expires_from_now(boost::posix_time::milliseconds(kConnectTimeoutMs));

        // Capture default `=` so mingw gcc 14 can resolve the nested
        // shared_ptr captures (`connect_timer`, `connect_timed_out`)
        // from continue_tcp_open's body. With explicit-only captures,
        // mingw gcc reports "not captured" even though they're listed;
        // Linux gcc accepts the same source. Same applies to the
        // resolver_handler below.
        boost::asio::async_connect(remote->socket, allowed,
                                   boost::asio::bind_executor(self->strand_,
                                                              [=](const boost::system::error_code& ec2,
                                                                                                                          const boost::asio::ip::tcp::endpoint&) {
                                                                  connect_timer->cancel();
                                                                  const int64_t connect_ms = remote->connect_started_ms > 0
                                                                      ? (util::now_ms() - remote->connect_started_ms)
                                                                      : 0;
                                                                  {
                                                                      std::lock_guard<std::mutex> lock(self->streams_mutex_);
                                                                      if (self->streams_.find(stream_id) == self->streams_.end()) {
                                                                          return;
                                                                      }
                                                                  }
                                                                  if (ec2) {
                                                                      if (ec2 == boost::asio::error::operation_aborted &&
                                                                          self->close_state_ != CloseState::Open) {
                                                                          return;
                                                                      }
                                                                      const std::string reason = *connect_timed_out
                                                                          ? "connect timeout"
                                                                          : ("connect failed: " + ec2.message());
                                                                      YUME_TIMING_LOG("server.open",
                                                                                       "connect_failed",
                                                                                       "session=" + std::to_string(self->session_id_) +
                                                                                           " stream=" + std::to_string(stream_id) +
                                                                                           " proto=tcp ms=" + std::to_string(connect_ms) +
                                                                                           " reason=" + reason);
                                                                      self->send_open_reply(stream_id, false, reason);
                                                                      std::lock_guard<std::mutex> lock(self->streams_mutex_);
                                                                      self->streams_.erase(stream_id);
                                                                      return;
                                                                  }
                                                                  boost::system::error_code nodelay_ec;
                                                                  remote->socket.set_option(boost::asio::ip::tcp::no_delay(true), nodelay_ec);
                                                                  boost::system::error_code remote_recvbuf_ec;
                                                                  remote->socket.set_option(boost::asio::socket_base::receive_buffer_size(kSocketBufferBytes), remote_recvbuf_ec);
                                                                  boost::system::error_code remote_sendbuf_ec;
                                                                  remote->socket.set_option(boost::asio::socket_base::send_buffer_size(kSocketBufferBytes), remote_sendbuf_ec);
                                                                  remote->connected = true;
                                                                  self->send_open_reply(stream_id, true, "");
                                                                  YUME_TIMING_LOG("server.open",
                                                                                   "done",
                                                                                   "session=" + std::to_string(self->session_id_) +
                                                                                       " stream=" + std::to_string(stream_id) +
                                                                                       " proto=tcp ok=1 connect_ms=" +
                                                                                       std::to_string(connect_ms) +
                                                                                       " total_ms=" +
                                                                                       std::to_string(util::now_ms() - remote->open_started_ms));
                                                                  self->start_remote_read(stream_id);
                                                                  self->do_remote_write(stream_id);
                                                                  }));

        connect_timer->async_wait(boost::asio::bind_executor(self->strand_,
            [self, stream_id, remote, connect_timed_out](const boost::system::error_code& ec) {
                if (ec) {
                    return;
                }
                *connect_timed_out = true;
                boost::system::error_code ignore_ec;
                remote->socket.close(ignore_ec);
            }));
    };

    auto resolver_handler = [=, stream_id = frame.header.stream_id](const boost::system::error_code& ec,
                                                                                                                                    const boost::asio::ip::tcp::resolver::results_type& results) {
        resolver_timer->cancel();
        const int64_t resolve_ms = remote->resolve_started_ms > 0 ? (util::now_ms() - remote->resolve_started_ms) : 0;
        {
            std::lock_guard<std::mutex> lock(self->streams_mutex_);
            if (self->streams_.find(stream_id) == self->streams_.end()) {
                return;
            }
        }

        if (ec) {
            if (ec == boost::asio::error::operation_aborted &&
                self->close_state_ != CloseState::Open) {
                return;
            }
            const std::string reason = *resolve_timed_out
                ? "resolve timeout"
                : ("resolve failed: " + ec.message());
            YUME_TIMING_LOG("server.open",
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
        continue_tcp_open(std::move(resolved), result_count, resolve_ms, false);
    };

    const auto resolver_flags = boost::asio::ip::resolver_base::numeric_service;
    if (!cfg_.dns_server.empty() && !resolve_any_family) {
        auto direct_dns = std::make_shared<DirectDnsAQuery>(
            strand_,
            cfg_.dns_server,
            host,
            [self, stream_id = frame.header.stream_id, remote, port, continue_tcp_open](
                bool ok,
                const std::vector<boost::asio::ip::address_v4>& addresses,
                const std::string& reason,
                int64_t resolve_ms) {
                {
                    std::lock_guard<std::mutex> lock(self->streams_mutex_);
                    if (self->streams_.find(stream_id) == self->streams_.end()) {
                        return;
                    }
                }
                if (!ok) {
                    YUME_TIMING_LOG("server.open",
                                     "resolve_failed",
                                     "session=" + std::to_string(self->session_id_) +
                                         " stream=" + std::to_string(stream_id) +
                                         " proto=tcp direct_dns=1 ms=" + std::to_string(resolve_ms) +
                                         " reason=" + reason);
                    self->send_open_reply(stream_id, false, "resolve failed: " + reason);
                    std::lock_guard<std::mutex> lock(self->streams_mutex_);
                    self->streams_.erase(stream_id);
                    return;
                }
                std::vector<boost::asio::ip::tcp::endpoint> resolved;
                resolved.reserve(addresses.size());
                for (const auto& address : addresses) {
                    resolved.emplace_back(address, static_cast<unsigned short>(port));
                }
                continue_tcp_open(std::move(resolved), addresses.size(), resolve_ms, true);
            });
        direct_dns->start();
    } else if (resolve_any_family) {
        remote->resolver.async_resolve(host, std::to_string(port), resolver_flags,
                                       boost::asio::bind_executor(strand_, resolver_handler));
        resolver_timer->async_wait(boost::asio::bind_executor(strand_,
            [self, stream_id = frame.header.stream_id, remote, resolve_timed_out](const boost::system::error_code& ec) {
                if (ec) {
                    return;
                }
                *resolve_timed_out = true;
                remote->resolver.cancel();
            }));
    } else {
        remote->resolver.async_resolve(boost::asio::ip::tcp::v4(), host, std::to_string(port), resolver_flags,
                                       boost::asio::bind_executor(strand_, resolver_handler));
        resolver_timer->async_wait(boost::asio::bind_executor(strand_,
            [self, stream_id = frame.header.stream_id, remote, resolve_timed_out](const boost::system::error_code& ec) {
                if (ec) {
                    return;
                }
                *resolve_timed_out = true;
                remote->resolver.cancel();
            }));
    }
}

bool Session::stream_id_in_use_locked(uint8_t stream_id) const {
    return stream_id == 0 ||
           streams_.find(stream_id) != streams_.end() ||
           udp_streams_.find(stream_id) != udp_streams_.end() ||
           codec_streams_.find(stream_id) != codec_streams_.end() ||
           service_streams_.find(stream_id) != service_streams_.end() ||
           bench_streams_.find(stream_id) != bench_streams_.end() ||
           reverse_listeners_.find(stream_id) != reverse_listeners_.end() ||
           pending_reverse_.find(stream_id) != pending_reverse_.end() ||
           (packet_stream_.has_value() && packet_stream_->stream_id == stream_id);
}

uint8_t Session::reserve_stream_id() {
    for (int i = 1; i < 255; ++i) {
        uint8_t candidate = static_cast<uint8_t>(i);
        bool streams_free = false;
        {
            std::lock_guard<std::mutex> lock(streams_mutex_);
            streams_free = !stream_id_in_use_locked(candidate);
        }
        if (!streams_free) {
            continue;
        }
        {
            std::lock_guard<std::mutex> lock(control_mutex_);
            if (control_outbound_.find(candidate) != control_outbound_.end() ||
                control_inbound_.find(candidate) != control_inbound_.end() ||
                federated_streams_.find(candidate) != federated_streams_.end()) {
                continue;
            }
        }
        return candidate;
    }
    return 0;
}

void Session::handle_rlisten(const protocol::Frame& frame) {
    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        crypto::Bytes decrypted;
        if (decrypt_inner_payload(frame.header.type, frame.header.stream_id, frame.payload, &decrypted)) {
            payload = std::move(decrypted);
        } else {
            send_open_reply(frame.header.stream_id, false, "RLISTEN decrypt failed");
            return;
        }
    }
    std::string payload_str(payload.begin(), payload.end());
    int listen_port = 0;
    std::string bind_host;
    bool reclaim = false;
    int min_port = 0;
    int max_port = 0;
    try {
        auto json = nlohmann::json::parse(payload_str);
        listen_port = json.value("port", 0);
        bind_host = json.value("bind_host", std::string{});
        reclaim = json.value("reclaim", false);
        min_port = json.value("min_port", 0);
        max_port = json.value("max_port", 0);
    } catch (...) {
        send_open_reply(frame.header.stream_id, false, "invalid RLISTEN payload");
        return;
    }
    const bool auto_select_port = (listen_port <= 0) && (min_port > 0) && (max_port > 0);
    if (!auto_select_port) {
        if (listen_port <= 0) {
            send_open_reply(frame.header.stream_id, false, "invalid listen port");
            return;
        }
        if (listen_port < cfg_.reverse_port_min || listen_port > cfg_.reverse_port_max) {
            send_open_reply(frame.header.stream_id, false,
                            "listen port must be " + std::to_string(cfg_.reverse_port_min) + "-" +
                                std::to_string(cfg_.reverse_port_max));
            return;
        }
    } else {
        if (min_port > max_port) {
            std::swap(min_port, max_port);
        }
        min_port = std::max(min_port, cfg_.reverse_port_min);
        max_port = std::min(max_port, cfg_.reverse_port_max);
        if (min_port > max_port) {
            min_port = cfg_.reverse_port_min;
            max_port = cfg_.reverse_port_max;
        }
    }
    if (reverse_listeners_.find(frame.header.stream_id) != reverse_listeners_.end()) {
        send_open_reply(frame.header.stream_id, false, "listener exists");
        return;
    }

    boost::asio::ip::address bind_address;
    bool has_bind_address = false;
    if (!bind_host.empty()) {
        boost::system::error_code ec;
        bind_address = boost::asio::ip::make_address(bind_host, ec);
        if (ec) {
            send_open_reply(frame.header.stream_id, false, "bind address must be an IP literal");
            return;
        }
        has_bind_address = true;
    }

    bool reclaimed = false;
    std::string bind_error;
    auto try_bind_listener = [&](int candidate_port,
                                 std::shared_ptr<boost::asio::ip::tcp::acceptor>* out_acceptor) -> bool {
        if (reclaim && manager_) {
            reclaimed = manager_->reclaim_reverse_listener(candidate_port, this);
        }
        auto candidate = std::make_shared<boost::asio::ip::tcp::acceptor>(stream_.get_executor());
        boost::system::error_code ec;
        boost::asio::ip::tcp::endpoint ep =
            has_bind_address
                ? boost::asio::ip::tcp::endpoint(bind_address, static_cast<unsigned short>(candidate_port))
                : boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(),
                                                 static_cast<unsigned short>(candidate_port));
        candidate->open(ep.protocol(), ec);
        if (ec) {
            bind_error = "listen failed: " + ec.message();
            return false;
        }
        candidate->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
        candidate->bind(ep, ec);
        if (ec == boost::asio::error::address_in_use && reclaim && manager_ && !reclaimed) {
            if (manager_->reclaim_reverse_listener(candidate_port, this)) {
                ec.clear();
                candidate->bind(ep, ec);
            }
        }
        if (ec) {
            bind_error = "bind failed: " + ec.message();
            return false;
        }
        candidate->listen(boost::asio::socket_base::max_listen_connections, ec);
        if (ec) {
            bind_error = "listen failed: " + ec.message();
            return false;
        }
        *out_acceptor = std::move(candidate);
        return true;
    };

    std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor;
    if (auto_select_port) {
        const int range_size = max_port - min_port + 1;
        const int start_port = random_int_inclusive(min_port, max_port);
        bool found_port = false;
        for (int offset = 0; offset < range_size; ++offset) {
            int candidate = min_port + ((start_port - min_port + offset) % range_size);
            if (try_bind_listener(candidate, &acceptor)) {
                listen_port = candidate;
                found_port = true;
                break;
            }
        }
        if (!found_port) {
            send_open_reply(frame.header.stream_id, false,
                            "no available listen port in range " + std::to_string(min_port) + "-" +
                                std::to_string(max_port));
            return;
        }
    } else {
        if (!try_bind_listener(listen_port, &acceptor)) {
            send_open_reply(frame.header.stream_id, false, bind_error);
            return;
        }
    }
    reverse_listeners_[frame.header.stream_id] = acceptor;
    reverse_listener_ports_[frame.header.stream_id] = listen_port;
    reverse_port_streams_[listen_port] = frame.header.stream_id;
    if (manager_) {
        manager_->register_reverse_listener(listen_port, shared_from_this());
    }
    send_open_reply(frame.header.stream_id, true, std::to_string(listen_port));

    auto self = shared_from_this();
    auto do_accept = std::make_shared<std::function<void()>>();
    *do_accept = [self, acceptor, listen_id = frame.header.stream_id, do_accept]() {
        acceptor->async_accept(boost::asio::bind_executor(
            self->strand_,
            [self, acceptor, listen_id, do_accept](const boost::system::error_code& ec2,
                                                   boost::asio::ip::tcp::socket socket) {
            if (!ec2) {
                uint8_t stream_id = self->reserve_stream_id();
                if (stream_id == 0) {
                    boost::system::error_code close_ec;
                    socket.close(close_ec);
                } else {
                    auto remote = std::make_shared<RemoteStream>(self->stream_.get_executor());
                    remote->socket = std::move(socket);
                    remote->open_started_ms = util::now_ms();
                    remote->connected = true;
                    boost::system::error_code keep_ec;
                    remote->socket.set_option(boost::asio::socket_base::keep_alive(true), keep_ec);
                    boost::system::error_code nodelay_ec;
                    remote->socket.set_option(boost::asio::ip::tcp::no_delay(true), nodelay_ec);
                    boost::system::error_code recvbuf_ec;
                    remote->socket.set_option(boost::asio::socket_base::receive_buffer_size(kSocketBufferBytes), recvbuf_ec);
                    boost::system::error_code sendbuf_ec;
                    remote->socket.set_option(boost::asio::socket_base::send_buffer_size(kSocketBufferBytes), sendbuf_ec);
                    {
                        std::lock_guard<std::mutex> lock(self->streams_mutex_);
                        self->streams_[stream_id] = remote;
                    }
                    self->pending_reverse_.insert(stream_id);
                    remote->open_timer = std::make_unique<boost::asio::steady_timer>(self->strand_);
                    remote->open_timer->expires_after(std::chrono::milliseconds(kReverseAcceptTimeoutMs));
                    remote->open_timer->async_wait(boost::asio::bind_executor(
                        self->strand_,
                        [self, stream_id](const boost::system::error_code& timer_ec) {
                            if (timer_ec || self->close_state_ != CloseState::Open) {
                                return;
                            }
                            if (self->pending_reverse_.erase(stream_id) == 0) {
                                return;
                            }
                            util::log_warn("session " + std::to_string(self->session_id_) +
                                           ": reverse open timeout for stream " +
                                           std::to_string(stream_id));
                            self->send_control_close(stream_id, "reverse open timeout");
                            self->handle_close(stream_id, "reverse open timeout");
                        }));

                    nlohmann::json json{{"listen_id", listen_id}};
                    std::string payload_str = json.dump();
                    std::vector<uint8_t> payload(payload_str.begin(), payload_str.end());
                    uint16_t flags = 0;
                    if (self->inner_key_.has_value()) {
                        payload = self->encrypt_inner_payload(protocol::ROPEN, stream_id, payload);
                        flags |= protocol::kFlagInnerEncrypted;
                    }
                    protocol::Frame notify{{static_cast<uint32_t>(payload.size()), protocol::ROPEN, stream_id, flags},
                                           payload};
                    self->async_write_frame(notify);
                }
            }
            (*do_accept)();
        }));
    };
    (*do_accept)();
}
}  // namespace yume::server
