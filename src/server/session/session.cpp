/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "server/session/session.hpp"
#include "server/runtime/manager.hpp"
#include "server/session/internal.hpp"

namespace yume::server {

using namespace detail;

std::int64_t epoch_now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

Session::Session(boost::asio::ip::tcp::socket socket,
                 boost::asio::ssl::context& ssl_ctx,
                 const ServerConfig& cfg,
                 std::shared_ptr<const std::vector<crypto::Bytes>> authorized_keys,
                 uint64_t session_id,
                 Manager* manager)
    : stream_(std::move(socket), ssl_ctx)
    , cfg_(cfg)
    , authorized_keys_(std::move(authorized_keys))
    , session_id_(session_id)
    , manager_(manager)
    , strand_(stream_.get_executor())
    , preface_timer_(stream_.get_executor())
    , tls_handshake_timer_(stream_.get_executor())
    , idle_timer_(stream_.get_executor()) {
    last_activity_ms_.store(steady_now_ms(), std::memory_order_relaxed);
    session_allow_exec_policy_ = false;
    session_allow_local_ip_ = false;
    session_control_full_ = false;
    session_allowed_codecs_.clear();
    session_allow_monero_rpc_policy_ = false;
}

void Session::start() {
    touch_activity();
    schedule_idle_check();
    auto self = shared_from_this();
    boost::system::error_code keep_ec;
    stream_.lowest_layer().set_option(boost::asio::socket_base::keep_alive(true), keep_ec);
    boost::system::error_code recvbuf_ec;
    stream_.lowest_layer().set_option(boost::asio::socket_base::receive_buffer_size(kSocketBufferBytes), recvbuf_ec);
    boost::system::error_code sendbuf_ec;
    stream_.lowest_layer().set_option(boost::asio::socket_base::send_buffer_size(kSocketBufferBytes), sendbuf_ec);

    // Arm the TLS-handshake deadline before kicking off async_handshake.
    // If the timer fires before on_handshake completes, we close the
    // lowest-layer socket — the pending async_handshake then reports
    // operation_aborted and on_handshake closes the session normally.
    if (cfg_.tls_handshake_timeout_ms > 0) {
        tls_handshake_timer_.expires_after(
            std::chrono::milliseconds(cfg_.tls_handshake_timeout_ms));
        tls_handshake_timer_.async_wait(boost::asio::bind_executor(strand_,
            [self](const boost::system::error_code& ec) {
                if (ec) return;  // cancelled by on_handshake
                boost::system::error_code close_ec;
                self->stream_.lowest_layer().close(close_ec);
                if (self->close_state_ == CloseState::Open) {
                    self->close_with_reason("TLS handshake deadline exceeded");
                }
            }));
    }

    stream_.async_handshake(boost::asio::ssl::stream_base::server,
                            boost::asio::bind_executor(strand_,
                                                       [self](const boost::system::error_code& ec) {
                                                           self->on_handshake(ec);
                                                       }));
}

void Session::stop() {
    boost::asio::post(strand_, [self = shared_from_this()]() { self->close(); });
}

void Session::notify_server_shutdown(const std::string& reason) {
    boost::asio::post(strand_, [self = shared_from_this(), reason]() {
        if (self->close_state_ != CloseState::Open) {
            return;
        }
        if (self->authenticated_) {
            nlohmann::json notice{
                {"cmd", "server.closing"},
                {"reason", reason},
                {"message", reason},
            };
            std::string payload_text = notice.dump();
            crypto::Bytes payload(payload_text.begin(), payload_text.end());
            uint16_t flags = 0;
            if (self->inner_key_.has_value()) {
                payload = self->encrypt_inner_payload(protocol::CONTROL, 0, payload);
                flags |= protocol::kFlagInnerEncrypted;
            }
            auto data = std::make_shared<std::vector<uint8_t>>(protocol::encode_frame(
                protocol::CONTROL,
                0,
                flags,
                payload,
                self->cfg_.obfs_pad_multiple));
            self->queue_encoded_write_on_strand(data, protocol::CONTROL, 0, payload.size());

            crypto::Bytes close_payload(reason.begin(), reason.end());
            uint16_t close_flags = 0;
            if (self->inner_key_.has_value()) {
                close_payload = self->encrypt_inner_payload(protocol::CLOSE, 0, close_payload);
                close_flags |= protocol::kFlagInnerEncrypted;
            }
            auto close_frame = std::make_shared<std::vector<uint8_t>>(protocol::encode_frame(
                protocol::CLOSE,
                0,
                close_flags,
                close_payload,
                self->cfg_.obfs_pad_multiple));
            self->queue_encoded_write_on_strand(close_frame, protocol::CLOSE, 0, close_payload.size());
        }
        self->close_with_reason(reason);
    });
}

void Session::on_handshake(const boost::system::error_code& ec) {
    // Deadline served its purpose; cancel regardless of handshake
    // outcome so it doesn't try to close an already-handled stream.
    // No-arg cancel(): the error_code overload of basic_waitable_timer::cancel
    // was removed in Boost.Asio 1.87 (vcpkg arm64-osx). The no-arg form works on
    // every Boost version and does not throw for an ordinary timer cancellation.
    tls_handshake_timer_.cancel();
    if (ec) {
        close_with_reason("TLS handshake failed: " + ec.message());
        return;
    }
    boost::system::error_code ep_ec;
    auto ep = stream_.lowest_layer().remote_endpoint(ep_ec);
    if (!ep_ec && !cfg_.anonym) {
        client_wan_ip_ = ep.address().to_string();
    }
    boost::system::error_code nodelay_ec;
    stream_.lowest_layer().set_option(boost::asio::ip::tcp::no_delay(true), nodelay_ec);
    if (cfg_.obfuscation) {
        const std::string negotiated = obfs::selected_alpn(stream_.native_handle());
        util::log_info("session " + std::to_string(session_id_) +
                       ": TLS ALPN selected: " +
                       (negotiated.empty() ? std::string("(none)") : negotiated));
    }

    // Preface inspection lets us serve an HTTP disguise (real cover
    // page with --real, or profile-driven 404 otherwise) instead of
    // closing on non-yume probes. Activated by --real, --obfs, or
    // --hide-in-the-crowd / --public-node (which sets http_profile).
    // Cost: ~200 ms preface_timer wait on the first byte from
    // legitimate yume clients, which they already eat under --real
    // and --obfs. Without any of these, fall through to the fast
    // AUTH-challenge path (preserves pre-1.0 latency for operators
    // who haven't opted in to stealth).
    if (cfg_.real_http || cfg_.robots_deny || cfg_.obfuscation || !cfg_.http_profile.empty()
        || !cfg_.upstream_response_bytes.empty()
        || !cfg_.upstream_response_dir.empty()) {
        start_preface_read();
        return;
    }

    send_auth_challenge();
}

void Session::read_header() {
    if (close_state_ != CloseState::Open) {
        return;
    }
    if (header_prefetched_) {
        header_prefetched_ = false;
        on_read_header({}, header_buf_.size());
        return;
    }
    auto self = shared_from_this();
    boost::asio::async_read(stream_, boost::asio::buffer(header_buf_),
                            boost::asio::bind_executor(strand_,
                                                       [self](const boost::system::error_code& ec,
                                                              std::size_t bytes) {
                                                           self->on_read_header(ec, bytes);
                                                       }));
}

void Session::on_read_header(const boost::system::error_code& ec, std::size_t) {
    if (ec) {
        if (close_state_ != CloseState::Open && is_expected_close_ec(ec)) {
            maybe_finish_close();
            return;
        }
        if (authenticated_ &&
            latest_lifecycle_state_ == "disconnecting" &&
            (ec == boost::asio::error::eof || ec == boost::asio::ssl::error::stream_truncated)) {
            close_with_reason("peer closed the TLS session");
            return;
        }
        if (ec == boost::asio::ssl::error::stream_truncated ||
            ec.category().name() == std::string("ssl")) {
            close_with_reason("SSL/TLS error: " + describe_error_code(ec) +
                            " [client must reconnect]");
            return;
        }
        if (authenticated_ &&
            (ec == boost::asio::error::eof || ec == boost::asio::ssl::error::stream_truncated)) {
            close_with_reason("peer closed the TLS session");
            return;
        }
        if (!authenticated_ &&
            (ec == boost::asio::error::eof ||
             ec == boost::asio::error::connection_reset ||
             ec == boost::asio::error::operation_aborted)) {
            close_with_reason("client disconnected before AUTH: " + describe_error_code(ec));
            return;
        }
        close_with_reason("read header failed: " + describe_error_code(ec));
        return;
    }

    uint32_t len = (static_cast<uint32_t>(header_buf_[0]) << 24) |
                   (static_cast<uint32_t>(header_buf_[1]) << 16) |
                   (static_cast<uint32_t>(header_buf_[2]) << 8) |
                   (static_cast<uint32_t>(header_buf_[3]));

    if (len > kMaxFrameSize) {
        if (!authenticated_ && is_http_probe_header(header_buf_)) {
            close_with_reason("ignored post-TLS HTTP probe");
            return;
        }
        const std::string detail =
            "session " + std::to_string(session_id_) + ": frame too large (" + summarize_header_prefix(header_buf_) + ")";
        if (util::is_logging_enabled()) {
            util::log_warn(detail);
        } else {
            std::cerr << "[warn] " << detail << std::endl;
        }
        close_with_reason("frame too large");
        return;
    }

    uint8_t type = header_buf_[4];
    if (type < kMinFrameType || type > kMaxFrameType) {
        if (!authenticated_ && is_http_probe_header(header_buf_)) {
            close_with_reason("ignored post-TLS HTTP probe");
            return;
        }
        const std::string detail =
            "session " + std::to_string(session_id_) + ": invalid frame type " +
            std::to_string(static_cast<int>(type)) + " (header=" + summarize_header_prefix(header_buf_) + ")";
        if (util::is_logging_enabled()) {
            util::log_warn(detail);
        } else {
            std::cerr << "[warn] " << detail << std::endl;
        }
        close_with_reason("invalid frame type");
        return;
    }

    current_header_.len = len;
    current_header_.type = type;
    current_header_.stream_id = header_buf_[5];
    current_header_.flags = static_cast<uint16_t>(header_buf_[6] << 8) |
                            static_cast<uint16_t>(header_buf_[7]);

    // resize, not assign(len, 0): the async_read below fully overwrites
    // [0, len), so zero-filling every frame is pure memset waste. In steady
    // state (constant frame size) resize is a no-op and keeps capacity;
    // only a grow touches the new tail, which the read then overwrites.
    payload_buf_.resize(len);
    if (len == 0) {
        if ((current_header_.flags & protocol::kFlagPadded) != 0) {
            // kFlagPadded with zero payload is malformed: a padded frame
            // always carries at least the 1-byte length, so len >= 1.
            close_with_reason("malformed padded frame: zero-length payload");
            return;
        }
        protocol::Frame frame{current_header_, {}};
        handle_frame(frame);
        return;
    }

    auto self = shared_from_this();
    boost::asio::async_read(stream_, boost::asio::buffer(payload_buf_),
                            boost::asio::bind_executor(strand_,
                                                       [self](const boost::system::error_code& e,
                                                              std::size_t bytes) {
                                                           self->on_read_payload(e, bytes);
                                                       }));
}

void Session::on_read_payload(const boost::system::error_code& ec, std::size_t) {
    if (ec) {
        if (close_state_ != CloseState::Open && is_expected_close_ec(ec)) {
            maybe_finish_close();
            return;
        }
        std::string error_msg = "read payload failed: " + describe_error_code(ec);
        if (ec.category().name() == std::string("ssl") ||
            ec == boost::asio::ssl::error::stream_truncated) {
            error_msg = "SSL/TLS payload read error: " + error_msg +
                       " [SSL stream may be corrupted; client must reconnect]";
            util::log_error("session " + std::to_string(session_id_) + ": " + error_msg);
        }
        close_with_reason(error_msg);
        return;
    }

    protocol::Frame frame{current_header_, {}};
    frame.payload.swap(payload_buf_);
    if ((frame.header.flags & protocol::kFlagPadded) != 0 && !protocol::strip_padding(frame)) {
        payload_buf_.swap(frame.payload);
        close_with_reason("malformed padded frame: pad length exceeds payload");
        return;
    }
    handle_frame(frame);
    payload_buf_.swap(frame.payload);
}

void Session::handle_frame(const protocol::Frame& frame) {
    if (close_state_ != CloseState::Open) {
        return;
    }
    touch_activity();
    if (!authenticated_) {
        if (frame.header.type != protocol::AUTH) {
            util::log_warn("session " + std::to_string(session_id_) + ": expected AUTH");
            close_with_reason("expected AUTH frame before authentication");
            return;
        }

            if (!handle_auth(frame)) {
                util::log_warn("session " + std::to_string(session_id_) + ": auth failed");
                std::string reason = auth_error_.empty() ? "access denied: invalid key" : auth_error_;
                nlohmann::json anon_error = {
                    {"error", reason},
                    {"version", yume::kVersion}
                };
                if (!cfg_.anonym_certfp.empty()) {
                    anon_error["certfp"] = cfg_.anonym_certfp;
                }
                if (!cfg_.anonym_sub_cert_b64.empty()) {
                    anon_error["sub_cert"] = cfg_.anonym_sub_cert_b64;
                }
                if (!cfg_.pq_pub_b64.empty()) {
                    anon_error["pq_pub"] = cfg_.pq_pub_b64;
                }
                if (!cfg_.pq_sig.empty()) {
                    anon_error["pq_sig"] = cfg_.pq_sig;
                }
                if (!cfg_.pq_alg.empty()) {
                    anon_error["pq_alg"] = cfg_.pq_alg;
                }
                std::string payload_str = anon_error.dump();
                crypto::Bytes payload(payload_str.begin(), payload_str.end());
                protocol::Frame anon_frame{{static_cast<uint32_t>(payload.size()), protocol::ANON, 0, 0}, payload};
            async_write_frame(anon_frame, [self = shared_from_this()](const boost::system::error_code& ec, std::size_t) {
                self->close_with_reason(ec ? "auth rejection ANON write failed: " + ec.message()
                                           : "authentication rejected");
            });
            return;
        }

        authenticated_ = true;
        if (!cfg_.anonym) {
            util::log_info("session " + std::to_string(session_id_) + ": authenticated");
        }
        nlohmann::json anon = {
            {"version", yume::kVersion},
            {"mode", cfg_.anonym ? "anonym" : "normal"},
            {"hash", cfg_.anonym_hash},
            {"sig", cfg_.anonym_sig},
            {"ts", cfg_.anonym_ts},
            {"nonce", cfg_.anonym_nonce},
            {"certfp", cfg_.anonym_certfp},
            {"algo", "ed25519"},
            {"proof_policy", cfg_.anonym_proof_mode},
            {"proof_sources", cfg_.anonym_proof_sources},
            {"ca_sig", cfg_.anonym_ca_sig},
            {"ca_alg", cfg_.anonym_ca_alg},
            {"sub_sig", cfg_.anonym_sub_sig},
            {"sub_alg", cfg_.anonym_sub_alg},
            {"sub_cert", cfg_.anonym_sub_cert_b64},
            {"pq_pub", cfg_.pq_pub_b64},
            {"pq_sig", cfg_.pq_sig},
            {"pq_alg", cfg_.pq_alg}
        };
        std::string inner_mode = "off";
        if (inner_key_.has_value()) {
            inner_mode = inner_mode_.empty() ? (cfg_.inner_heavy ? "heavy" : "light") : inner_mode_;
        } else if (cfg_.inner_crypto) {
            inner_mode = cfg_.inner_heavy ? "heavy" : "light";
        }
        anon["inner_supported"] = cfg_.inner_crypto;
        anon["inner_required"] = cfg_.inner_required;
        anon["inner_dual"] = cfg_.inner_dual;
        anon["inner_active"] = inner_key_.has_value();
        anon["inner_mode"] = inner_mode;
        if (!inner_kdf_.empty()) {
            anon["inner_kdf"] = inner_kdf_;
        }
        anon["hop_enabled"] = hop_enabled_;
        anon["hop_interval_ms"] = cfg_.hop_interval_ms;
        anon["server_time_ms"] = epoch_now_ms();
        anon["cap_pq"] = inner::pq_supported();
        anon["cap_argon2"] = inner::argon2_supported();
        anon["cap_pbkdf2"] = inner::pbkdf2_supported();
        if (manager_ && manager_->packet_egress_active()) {
            anon["capabilities"] = nlohmann::json::array({std::string(protocol::packet_bulk::kCapability)});
        }
        std::string payload_str = anon.dump();
        crypto::Bytes payload(payload_str.begin(), payload_str.end());
        protocol::Frame anon_frame{{static_cast<uint32_t>(payload.size()), protocol::ANON, 0, 0}, payload};
        async_write_frame(anon_frame, [self = shared_from_this()](const boost::system::error_code& ec, std::size_t) {
            if (ec) {
                self->close_with_reason("ANON write failed: " + ec.message());
                return;
            }
            self->read_header();
        });
        return;
    }

    if (inner_key_.has_value() &&
        (frame.header.type == protocol::OPEN || frame.header.type == protocol::DATA ||
         frame.header.type == protocol::EXEC || frame.header.type == protocol::CLOSE ||
         frame.header.type == protocol::RLISTEN || frame.header.type == protocol::CONTROL)) {
        if ((frame.header.flags & protocol::kFlagInnerEncrypted) == 0) {
            util::log_warn("session " + std::to_string(session_id_) + ": missing inner encryption flag");
            close_with_reason("missing inner encryption flag on authenticated frame type " +
                              std::to_string(frame.header.type));
            return;
        }
    }

    switch (frame.header.type) {
        case protocol::OPEN:
            if (!handle_control_open_request(frame) && !handle_control_open_ack(frame)) {
                handle_open(frame);
            }
            break;
        case protocol::DATA:
            if (!handle_control_data(frame)) {
                handle_data(frame);
            }
            break;
        case protocol::EXEC: {
            if (!handle_control_exec(frame)) {
                handle_exec(frame);
            }
            break;
        }
        case protocol::RLISTEN: {
            handle_rlisten(frame);
            break;
        }
        case protocol::CONTROL: {
            handle_control(frame);
            break;
        }
        case protocol::PING: {
            protocol::Frame pong{{0, protocol::PONG, 0, 0}, {}};
            async_write_frame(pong);
            break;
        }
        case protocol::PONG:
            break;
        case protocol::CLOSE:
            if (!handle_control_close(frame)) {
                bool ok = true;
                std::string reason = decode_close_reason(frame, &ok);
                if (!ok) {
                    close_with_reason("CLOSE decrypt failed for stream " +
                                      std::to_string(frame.header.stream_id));
                    return;
                }
                if (reason.empty()) {
                    reason = "client closed";
                }
                if ((frame.header.flags & protocol::kFlagStreamFin) != 0) {
                    handle_stream_fin(frame.header.stream_id, reason);
                } else {
                    handle_close(frame.header.stream_id, reason);
                }
            }
            break;
        default:
            util::log_warn("session " + std::to_string(session_id_) + ": unknown frame");
            break;
    }

    if (close_state_ == CloseState::Open) {
        read_header();
    }
}


// handle_control + 5 sub-handlers (open_request / open_ack /
// data / close / exec) and the 3 send_control_* helpers moved
// to session_control.cpp in 1.0.x. Same Session:: methods,
// same signatures — different translation unit so neither
// file gets bigger.

void Session::handle_data(const protocol::Frame& frame) {
    crypto::Bytes decrypted_payload;
    const crypto::Bytes* payload = &frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        if (!decrypt_inner_payload(frame.header.type, frame.header.stream_id, frame.payload, &decrypted_payload)) {
            util::log_warn("session " + std::to_string(session_id_) + ": DATA decrypt failed for stream " +
                           std::to_string(frame.header.stream_id));
            close_with_reason("DATA decrypt failed for stream " + std::to_string(frame.header.stream_id));
            return;
        }
        payload = &decrypted_payload;
    }
    std::function<void(const crypto::Bytes&)> federated_data;
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        auto it = federated_streams_.find(frame.header.stream_id);
        if (it != federated_streams_.end()) {
            federated_data = it->second.on_data;
        }
    }
    if (federated_data) {
        federated_data(*payload);
        return;
    }
    if (handle_packet_data(frame.header.stream_id, *payload)) {
        return;
    }
    if (handle_bench_data(frame.header.stream_id, *payload)) {
        return;
    }
    if (handle_codec_data(frame.header.stream_id, *payload)) {
        return;
    }
    auto it_udp = udp_streams_.find(frame.header.stream_id);
    if (it_udp != udp_streams_.end()) {
        enqueue_udp_write(frame.header.stream_id, *payload);
        return;
    }
    enqueue_remote_write(frame.header.stream_id, *payload);
}

std::string Session::decode_close_reason(const protocol::Frame& frame, bool* ok) {
    if (ok) {
        *ok = true;
    }
    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        if (!decrypt_inner_payload(protocol::CLOSE, frame.header.stream_id, frame.payload, &payload)) {
            if (ok) {
                *ok = false;
            }
            return {};
        }
    }
    return std::string(payload.begin(), payload.end());
}

void Session::handle_stream_fin(uint8_t stream_id, const std::string& reason) {
    if (handle_bench_close(stream_id, reason)) {
        return;
    }
    std::shared_ptr<RemoteStream> remote;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }
        remote = it->second;
        if (remote->client_fin_received) {
            return;
        }
        remote->client_fin_received = true;
        remote->write_shutdown_pending = true;
    }
    util::log_info("session " + std::to_string(session_id_) + ": stream " +
                   std::to_string(stream_id) + " client FIN: " + reason);
    shutdown_remote_send_if_ready(stream_id);
    finish_remote_stream_if_done(stream_id);
}

void Session::handle_close(uint8_t stream_id, const std::string& reason) {
    std::function<void(const std::string&)> federated_close;
    std::string federated_channel_id;
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        auto it = federated_streams_.find(stream_id);
        if (it != federated_streams_.end()) {
            federated_close = it->second.on_close;
            federated_channel_id = it->second.channel_id;
            federated_streams_.erase(it);
        }
    }
    if (federated_close) {
        if (manager_ && !federated_channel_id.empty()) {
            manager_->unregister_active_channel(federated_channel_id);
        }
        federated_close(reason);
        return;
    }
    if (packet_stream_.has_value() && packet_stream_->stream_id == stream_id) {
        flush_packet_downstream();
        auto& packet = *packet_stream_;
        if (!packet.close_summary_logged) {
            packet.close_summary_logged = true;
            const int64_t elapsed = packet.open_started_ms > 0 ? (util::now_ms() - packet.open_started_ms) : 0;
            util::log_timing("server.stream",
                             "summary",
                             "session=" + std::to_string(session_id_) +
                                 " stream=" + std::to_string(stream_id) +
                                 " proto=packet-bulk-v1 ms=" + std::to_string(elapsed) +
                                 " client_ipv4=" + packet.client_ipv4 +
                                 " upstream_batches=" + std::to_string(packet.upstream_batches) +
                                 " upstream_packets=" + std::to_string(packet.upstream_packets) +
                                 " downstream_batches=" + std::to_string(packet.downstream_batches) +
                                 " downstream_packets=" + std::to_string(packet.downstream_packet_count) +
                                 " reason=" + reason);
        }
        if (packet.flush_timer) {
            boost::system::error_code ec;
            packet.flush_timer->cancel(ec);
        }
        if (manager_) {
            manager_->unregister_packet_client(this, packet.client_ipv4_be);
        }
        packet_stream_.reset();
        return;
    }
    if (handle_bench_close(stream_id, reason)) {
        return;
    }
    if (handle_codec_close(stream_id, reason)) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);

        auto it_listener = reverse_listeners_.find(stream_id);
        if (it_listener != reverse_listeners_.end()) {
            boost::system::error_code ec;
            int listen_port = 0;
            auto it_port = reverse_listener_ports_.find(stream_id);
            if (it_port != reverse_listener_ports_.end()) {
                listen_port = it_port->second;
                reverse_listener_ports_.erase(it_port);
                reverse_port_streams_.erase(listen_port);
            }
            if (manager_ && listen_port > 0) {
                manager_->unregister_reverse_listener(listen_port, this);
            }
            it_listener->second->close(ec);
            reverse_listeners_.erase(it_listener);
            return;
        }

        auto it_udp = udp_streams_.find(stream_id);
        if (it_udp != udp_streams_.end()) {
            util::log_info("session " + std::to_string(session_id_) + ": udp stream " + std::to_string(stream_id) +
                           " closed: " + reason);
            auto udp = it_udp->second;
            if (!udp->close_summary_logged) {
                udp->close_summary_logged = true;
                const int64_t elapsed = udp->open_started_ms > 0 ? (util::now_ms() - udp->open_started_ms) : 0;
                util::log_timing("server.stream",
                                 "summary",
                                 "session=" + std::to_string(session_id_) +
                                     " stream=" + std::to_string(stream_id) +
                                     " proto=udp ms=" + std::to_string(elapsed) +
                                     " upstream=" + std::to_string(udp->upstream_bytes) +
                                     " downstream=" + std::to_string(udp->downstream_bytes) +
                                     " target=" + udp->host + ":" + std::to_string(udp->port) +
                                     " reason=" + reason);
            }
            boost::system::error_code ec;
            udp->resolver.cancel();
            udp->socket.close(ec);
            udp_streams_.erase(it_udp);
            return;
        }

        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }

        util::log_info("session " + std::to_string(session_id_) + ": stream " + std::to_string(stream_id) + " closed: " + reason);
        auto remote = it->second;
        if (!remote->close_summary_logged) {
            remote->close_summary_logged = true;
            const int64_t elapsed = remote->open_started_ms > 0 ? (util::now_ms() - remote->open_started_ms) : 0;
            util::log_timing("server.stream",
                             "summary",
                             "session=" + std::to_string(session_id_) +
                                 " stream=" + std::to_string(stream_id) +
                                 " proto=tcp ms=" + std::to_string(elapsed) +
                                 " upstream=" + std::to_string(remote->upstream_bytes) +
                                 " downstream=" + std::to_string(remote->downstream_bytes) +
                                 " target=" + remote->host + ":" + std::to_string(remote->port) +
                                 " reason=" + reason);
        }
        boost::system::error_code ec;
        remote->resolver.cancel();
        remote->socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        remote->socket.close(ec);
        streams_.erase(it);
    }
}

void Session::handle_exec(const protocol::Frame& frame) {
    const std::string msg = "EXEC disabled for safety";
    crypto::Bytes payload(msg.begin(), msg.end());
    uint16_t flags = 0;
            if (inner_key_.has_value()) {
                payload = encrypt_inner_payload(protocol::DATA, frame.header.stream_id, payload);
                flags |= protocol::kFlagInnerEncrypted;
            }
    protocol::Frame resp{{static_cast<uint32_t>(payload.size()), protocol::DATA, frame.header.stream_id, flags}, payload};
    async_write_frame(resp);
    send_control_close(frame.header.stream_id, "");
}

void Session::send_open_reply(uint8_t stream_id, bool ok, const std::string& message) {
    crypto::Bytes payload(message.begin(), message.end());
    uint16_t flags = ok ? protocol::kFlagOpenOk : 0;
    if (inner_key_.has_value()) {
        payload = encrypt_inner_payload(protocol::OPEN, stream_id, payload);
        flags |= protocol::kFlagInnerEncrypted;
    }
    protocol::Frame resp{{static_cast<uint32_t>(payload.size()), protocol::OPEN, stream_id, flags}, payload};
    async_write_frame(resp);
}

void Session::touch_activity() {
    last_activity_ms_.store(steady_now_ms(), std::memory_order_relaxed);
}

bool Session::is_stale() const {
    const int64_t last = last_activity_ms_.load(std::memory_order_relaxed);
    return last > 0 && (steady_now_ms() - last) > kIdleTimeoutMs;
}

void Session::force_close_reverse_port(int port) {
    boost::asio::post(strand_, [self = shared_from_this(), port]() {
        auto it = self->reverse_port_streams_.find(port);
        if (it == self->reverse_port_streams_.end()) {
            return;
        }
        self->handle_close(it->second, "listener reclaimed");
    });
}

void Session::schedule_idle_check() {
    idle_timer_.expires_after(std::chrono::milliseconds(kIdleCheckIntervalMs));
    auto self = shared_from_this();
    idle_timer_.async_wait(boost::asio::bind_executor(
        strand_,
        [self](const boost::system::error_code& ec) {
            if (ec) {
                return;
            }
            if (self->is_stale()) {
                util::log_warn("session " + std::to_string(self->session_id_) + ": idle timeout");
                self->close_with_reason("idle timeout");
                return;
            }
            self->schedule_idle_check();
        }));
}

void Session::close_with_reason(const std::string& reason) {
    if (!reason.empty() && close_reason_.empty()) {
        close_reason_ = reason;
    }
    if (close_state_ == CloseState::Open) {
        begin_close();
        return;
    }
    maybe_finish_close();
}

void Session::begin_close() {
    if (close_state_ != CloseState::Open) {
        maybe_finish_close();
        return;
    }
    close_state_ = CloseState::Closing;
    if (close_reason_.empty()) {
        close_reason_ = "session closed";
    }
    const bool suppress_log =
        is_expected_close_reason(close_reason_) ||
        (!authenticated_ && is_background_probe_close_reason(close_reason_));
    if (!suppress_log) {
        const std::string closing_message =
            "session " + std::to_string(session_id_) +
            (authenticated_ ? " [auth]" : " [pre-auth]") +
            " closing: " + close_reason_;
        if (util::is_logging_enabled()) {
            util::log_warn(closing_message);
        } else if (is_server_fault_close_reason(close_reason_)) {
            std::cerr << "[critical] server session issue: " << close_reason_ << std::endl;
        }
    }
    boost::system::error_code ec;
    idle_timer_.cancel();
    preface_timer_.cancel();
    if (manager_) {
        manager_->unregister_session(this);
        if (packet_stream_.has_value()) {
            manager_->unregister_packet_client(this, packet_stream_->client_ipv4_be);
        }
        for (const auto& entry : reverse_listener_ports_) {
            manager_->unregister_reverse_listener(entry.second, this);
        }
        manager_->unregister_controlled_client(this);
        manager_->unregister_endpoint(this);
    }
    reverse_listener_ports_.clear();
    reverse_port_streams_.clear();
    if (packet_stream_.has_value()) {
        if (packet_stream_->flush_timer) {
            packet_stream_->flush_timer->cancel(ec);
        }
        packet_stream_.reset();
    }

    std::vector<std::pair<std::shared_ptr<Session>, uint8_t>> control_peers;
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        for (const auto& entry : control_outbound_) {
            if (auto peer = entry.second.peer.lock()) {
                control_peers.emplace_back(peer, entry.second.peer_stream_id);
            }
        }
        for (const auto& entry : control_inbound_) {
            if (auto peer = entry.second.peer.lock()) {
                control_peers.emplace_back(peer, entry.second.peer_stream_id);
            }
        }
        control_outbound_.clear();
        control_inbound_.clear();
    }
    for (const auto& entry : control_peers) {
        entry.first->send_control_close(entry.second, "control peer closed");
    }

    for (auto& entry : streams_) {
        entry.second->socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        entry.second->socket.close(ec);
    }
    for (auto& entry : udp_streams_) {
        entry.second->socket.close(ec);
    }
    streams_.clear();
    for (auto& entry : reverse_listeners_) {
        entry.second->close(ec);
    }
    reverse_listeners_.clear();

    maybe_finish_close();
}

void Session::maybe_finish_close() {
    if (close_state_ != CloseState::Closing || transport_shutdown_in_flight_) {
        return;
    }
    if (write_in_flight_ || !write_queue_.empty()) {
        return;
    }
    shutdown_transport();
}

void Session::shutdown_transport() {
    if (transport_shutdown_in_flight_ || close_state_ == CloseState::Closed) {
        return;
    }
    transport_shutdown_in_flight_ = true;
    auto self = shared_from_this();
    stream_.async_shutdown(boost::asio::bind_executor(
        strand_,
        [self](const boost::system::error_code&) {
            boost::system::error_code ec;
            self->closed_ = true;
            self->close_state_ = CloseState::Closed;
            self->stream_.lowest_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            self->stream_.lowest_layer().close(ec);
        }));
}

void Session::close() {
    close_with_reason("");
}

}  // namespace yume::server
