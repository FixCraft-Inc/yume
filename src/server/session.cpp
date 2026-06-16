/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "server/session.hpp"
#include "server/manager.hpp"
#include "server/session_internal.hpp"

#include <openssl/pem.h>

// vcpkg's modularised Boost (x64-mingw-dynamic) doesn't drag these in
// via <boost/asio.hpp> the way a system Boost on Debian does. Pull
// them in explicitly so cross-compiling for Windows doesn't fail with
// "deadline_timer is not a member" / "posix_time::milliseconds is not
// a member".
#include <boost/asio/deadline_timer.hpp>
#include <boost/date_time/posix_time/posix_time_duration.hpp>

#include <chrono>
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <ctime>
#include <iostream>
#include <random>
#include <string>
#include <string_view>

#include "core/http_profile.hpp"
#include "core/inner_crypto.hpp"
#include "core/obfs_h2.hpp"
#include "core/obfs_signal.hpp"
#include "core/packet_bulk.hpp"
#include "core/protocol.hpp"
#include "core/runtime_policy.hpp"
#include "core/version.hpp"
#include "server/auth.hpp"
#include "util.hpp"
#include <nlohmann/json.hpp>
#if YUME_USE_BASEFWX
#include <basefwx/base64.hpp>
#include <basefwx/crypto.hpp>
#include <basefwx/constants.hpp>
#endif

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
            self->queue_encoded_write_on_strand(data);

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
            self->queue_encoded_write_on_strand(close_frame);
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

void Session::send_auth_challenge() {
    challenge_ = crypto::random_bytes(32);
    if (cfg_.inner_crypto) {
        inner::Argon2Limits limits = inner::argon2_env_limits();
        nlohmann::json meta{
            {"challenge_meta", 1}
        };
        if (limits.time_max > 0) {
            meta["argon2_time_max"] = limits.time_max;
        }
        if (limits.memory_max > 0) {
            meta["argon2_mem_max"] = limits.memory_max;
        }
        if (limits.parallelism_max > 0) {
            meta["argon2_par_max"] = limits.parallelism_max;
        }
        std::string meta_text = meta.dump();
        challenge_.insert(challenge_.end(), meta_text.begin(), meta_text.end());
    }
    protocol::Frame frame{{static_cast<uint32_t>(challenge_.size()), protocol::AUTH, 0, 0}, challenge_};
    auto self = shared_from_this();
    auto do_write = [self, frame]() {
        self->async_write_frame(frame, [self](const boost::system::error_code& ec, std::size_t) {
            if (ec) {
                self->close_with_reason("AUTH challenge write failed: " + ec.message());
                return;
            }
            self->read_header();
        });
    };

    // Optional opt-in send-side jitter on the AUTH challenge. Read the
    // env once per call (cheap; getenv is fast and there's exactly one
    // AUTH per session). YUME_AUTH_JITTER_MS=N adds a uniform random
    // 0..N ms delay before writing AUTH, which breaks the
    // "server always emits AUTH at exactly T ms after TLS finish"
    // ML signature without costing latency for operators who don't
    // care. Default 0 = no delay.
    int jitter_max = 0;
    if (const char* raw = std::getenv("YUME_AUTH_JITTER_MS")) {
        try { jitter_max = std::max(0, std::stoi(raw)); }
        catch (const std::exception&) { jitter_max = 0; }
    }
    if (jitter_max == 0) {
        do_write();
        return;
    }
    thread_local std::mt19937 rng{std::random_device{}()};
    std::uniform_int_distribution<int> dist(0, jitter_max);
    int delay_ms = dist(rng);
    auto timer = std::make_shared<boost::asio::steady_timer>(strand_);
    timer->expires_after(std::chrono::milliseconds(delay_ms));
    timer->async_wait([timer, do_write](const boost::system::error_code& ec) {
        if (!ec) do_write();
    });
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

    protocol::Frame frame{current_header_, payload_buf_};
    if ((frame.header.flags & protocol::kFlagPadded) != 0 && !protocol::strip_padding(frame)) {
        close_with_reason("malformed padded frame: pad length exceeds payload");
        return;
    }
    handle_frame(frame);
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

bool Session::decrypt_inner_payload(uint8_t frame_type,
                                    uint8_t stream_id,
                                    const crypto::Bytes& input,
                                    crypto::Bytes* output) {
    if (!output) {
        return false;
    }
    if (!inner_key_.has_value()) {
        *output = input;
        return true;
    }
    auto try_decrypt = [&](const crypto::Bytes& key) -> bool {
        try {
            if (!hop_enabled_ || hop_interval_ms_ == 0) {
                *output = inner::decrypt_payload(key, frame_type, stream_id, input);
                return true;
            }
            std::uint64_t hop_id = current_hop_id();
            std::uint64_t candidates[1 + (kHopDecryptWindow * 2)];
            std::size_t candidate_count = 0;
            candidates[candidate_count++] = hop_id;
            for (std::uint64_t delta = 1; delta <= kHopDecryptWindow; ++delta) {
                if (hop_id >= delta) {
                    candidates[candidate_count++] = hop_id - delta;
                }
                candidates[candidate_count++] = hop_id + delta;
            }
            for (std::size_t i = 0; i < candidate_count; ++i) {
                std::uint64_t id = candidates[i];
                crypto::Bytes hop_key = inner::derive_hop_key(key, id);
                try {
                    *output = inner::decrypt_payload(hop_key, frame_type, stream_id, input);
                    return true;
                } catch (...) {
                }
            }
            return false;
        } catch (...) {
            return false;
        }
    };

    if (try_decrypt(*inner_key_)) {
        return true;
    }
    if (!inner_key_alt_.has_value()) {
        return false;
    }
    if (try_decrypt(*inner_key_alt_)) {
        inner_key_ = inner_key_alt_;
        inner_key_alt_.reset();
        if (!inner_alt_mode_.empty()) {
            inner_mode_ = inner_alt_mode_;
        }
        inner_alt_mode_.clear();
        if (!inner_alt_kdf_.empty()) {
            inner_kdf_ = inner_alt_kdf_;
        }
        inner_alt_kdf_.clear();
        return true;
    }
    return false;
}

crypto::Bytes Session::encrypt_inner_payload(uint8_t frame_type,
                                             uint8_t stream_id,
                                             const crypto::Bytes& input) {
    if (!inner_key_.has_value()) {
        return input;
    }
    if (!hop_enabled_ || hop_interval_ms_ == 0) {
        return inner::encrypt_payload(*inner_key_, frame_type, stream_id, input);
    }
    std::uint64_t hop_id = current_hop_id();
    crypto::Bytes hop_key = inner::derive_hop_key(*inner_key_, hop_id);
    return inner::encrypt_payload(hop_key, frame_type, stream_id, input);
}

std::uint64_t Session::current_hop_id() const {
    if (!hop_enabled_ || hop_interval_ms_ == 0) {
        return 0;
    }
    return inner::hop_id_from_time_ms(epoch_now_ms(), hop_interval_ms_, hop_offset_ms_);
}

bool Session::handle_auth(const protocol::Frame& frame) {
    auth_error_.clear();
    try {
        size_t offset = 0;
        crypto::Bytes pub_pem = read_field(frame.payload, offset);
        crypto::Bytes sig = read_field(frame.payload, offset);
        std::optional<crypto::Bytes> pq_ciphertext;
        std::optional<crypto::Bytes> pq_salt;
        std::optional<std::string> inner_mode;
        std::optional<bool> inner_hop;
        std::optional<inner::KdfParams> inner_kdf;
        if (offset < frame.payload.size()) {
            pq_ciphertext = read_field(frame.payload, offset);
        }
        if (offset < frame.payload.size()) {
            pq_salt = read_field(frame.payload, offset);
        }
        if (offset < frame.payload.size()) {
            crypto::Bytes mode_bytes = read_field(frame.payload, offset);
            if (!mode_bytes.empty()) {
                inner_mode.emplace(mode_bytes.begin(), mode_bytes.end());
            }
        }
        if (offset < frame.payload.size()) {
            crypto::Bytes hop_bytes = read_field(frame.payload, offset);
            if (!hop_bytes.empty()) {
                inner_hop = (hop_bytes[0] != static_cast<uint8_t>('0'));
            } else {
                inner_hop = false;
            }
        }
        if (offset < frame.payload.size()) {
            crypto::Bytes kdf_bytes = read_field(frame.payload, offset);
            if (!kdf_bytes.empty()) {
                inner::KdfParams params;
                params.name.assign(kdf_bytes.begin(), kdf_bytes.end());
                if (offset < frame.payload.size()) {
                    crypto::Bytes param_bytes = read_field(frame.payload, offset);
                    if (param_bytes.size() == 16) {
                        auto read_u32 = [&](size_t off) -> std::uint32_t {
                            if (off + 4 > param_bytes.size()) {
                                return 0;
                            }
                            return (static_cast<std::uint32_t>(param_bytes[off]) << 24) |
                                   (static_cast<std::uint32_t>(param_bytes[off + 1]) << 16) |
                                   (static_cast<std::uint32_t>(param_bytes[off + 2]) << 8) |
                                   static_cast<std::uint32_t>(param_bytes[off + 3]);
                        };
                        params.argon2_time = read_u32(0);
                        params.argon2_memory = read_u32(4);
                        params.argon2_parallelism = read_u32(8);
                        params.pbkdf2_iters = read_u32(12);
                    }
                }
                inner_kdf = params;
            }
        }

        BIO* pub_bio = BIO_new_mem_buf(pub_pem.data(), static_cast<int>(pub_pem.size()));
        if (!pub_bio) {
            auth_error_ = "access denied: invalid key";
            return false;
        }
        EVP_PKEY* pubkey = PEM_read_bio_PUBKEY(pub_bio, nullptr, nullptr, nullptr);
        BIO_free(pub_bio);
        if (!pubkey) {
            auth_error_ = "access denied: invalid key";
            return false;
        }

        bool sig_ok = crypto::verify_key(pubkey, challenge_, sig);
        bool auth_ok = authorized_keys_ ? is_authorized(pubkey, *authorized_keys_) : false;
        std::string fingerprint = fingerprint_pubkey(pubkey);
        client_id_ = fingerprint;
        auth_fingerprint_ = fingerprint;
        client_auth_pubkey_b64_ = yume::util::base64_encode(std::string(pub_pem.begin(), pub_pem.end()));
        EVP_PKEY_free(pubkey);

        if (!sig_ok || !auth_ok) {
            if (!cfg_.anonym || auth_debug_enabled()) {
                const std::size_t loaded_keys = authorized_keys_ ? authorized_keys_->size() : 0;
                util::log_warn("session " + std::to_string(session_id_) +
                               ": auth rejected fingerprint=" + (fingerprint.empty() ? std::string("<unknown>") : fingerprint) +
                               " signature=" + (sig_ok ? "ok" : "bad") +
                               " authorized=" + (auth_ok ? "yes" : "no") +
                               " loaded_keys=" + std::to_string(loaded_keys) +
                               " auth_keys=" + (cfg_.auth_keys.empty() ? std::string("<unset>") : cfg_.auth_keys));
            }
            if (!sig_ok) {
                auth_error_ = "access denied: bad signature";
            } else {
                auth_error_ = "access denied: invalid key";
            }
            return false;
        }

        AuthKeyPolicy auth_policy;
        if (!cfg_.auth_keys_meta.empty()) {
            try {
                AuthKeyPolicyMap auth_policies = load_auth_policies(cfg_.auth_keys_meta);
                auto it = auth_policies.find(fingerprint);
                if (it != auth_policies.end()) {
                    auth_policy = std::move(it->second);
                }
            } catch (const std::exception& ex) {
                auth_error_ = std::string("server auth policy load failed: ") + ex.what();
                return false;
            }
        }
        bandwidth_fair_key_ = fingerprint;
        bandwidth_priority_ = std::clamp(auth_policy.priority.value_or(kDefaultBandwidthPriority),
                                         kMinBandwidthPriority,
                                         kMaxBandwidthPriority);
        const bool key_exec = auth_policy.allow_exec.value_or(false);
        const bool key_local_ip = auth_policy.allow_local_ip.value_or(false);
        const bool key_control_full = auth_policy.control_full.value_or(false);
#if YUME_FEATURE_EXEC
        session_allow_exec_policy_ = key_exec && cfg_.allow_exec;
#else
        session_allow_exec_policy_ = false;
        if (key_exec || cfg_.allow_exec) {
            util::log_warn("session " + std::to_string(session_id_) +
                          ": exec requested but YUME_FEATURE_EXEC is OFF at build time");
        }
#endif
#if YUME_FEATURE_LAN_BRIDGE
        session_allow_local_ip_ = key_local_ip && cfg_.allow_local_ip;
#else
        session_allow_local_ip_ = false;
        if (key_local_ip || cfg_.allow_local_ip) {
            util::log_warn("session " + std::to_string(session_id_) +
                          ": LAN bridging requested but YUME_FEATURE_LAN_BRIDGE is OFF at build time");
        }
#endif
#if YUME_FEATURE_FULL_CONTROL
        session_control_full_ = key_control_full && cfg_.control_full;
#else
        session_control_full_ = false;
        if (key_control_full || cfg_.control_full) {
            util::log_warn("session " + std::to_string(session_id_) +
                          ": full control requested but YUME_FEATURE_FULL_CONTROL is OFF at build time");
        }
#endif
        session_allow_inbound_admin_policy_ = auth_policy.allow_inbound_admin.value_or(false);
        session_allow_outbound_admin_policy_ = auth_policy.allow_outbound_admin.value_or(false);
        session_allow_chat_policy_ = auth_policy.allow_chat.value_or(true);
        session_allow_file_policy_ = auth_policy.allow_file.value_or(true);
        session_allow_bytes_policy_ = auth_policy.allow_bytes.value_or(true);
        federation_peer_id_ = auth_policy.federation_peer_id;
        if (!auth_policy.empty()) {
            util::log_info("session " + std::to_string(session_id_) + ": auth policy " +
                           summarize_auth_policy(auth_policy));
        }

        if (cfg_.inner_crypto) {
            if (!pq_ciphertext.has_value() || !pq_salt.has_value()) {
                if (cfg_.inner_required) {
                    auth_error_ = "server requires inner crypto";
                    return false;
                }
                util::log_warn("session " + std::to_string(session_id_) + ": missing PQ fields; inner crypto disabled for this session");
            } else if (pq_salt->empty()) {
                if (cfg_.inner_required) {
                    auth_error_ = "server requires inner crypto";
                    return false;
                }
                util::log_warn("session " + std::to_string(session_id_) + ": missing PQ salt; inner crypto disabled for this session");
            } else {
                if (inner_mode.has_value() && !cfg_.inner_dual) {
                    bool wants_heavy = (*inner_mode == "heavy");
                    bool wants_light = (*inner_mode == "light");
                    if ((wants_heavy && !cfg_.inner_heavy) || (wants_light && cfg_.inner_heavy)) {
                        auth_error_ = "server does not support requested inner mode";
                        return false;
                    }
                }
                if (inner_kdf.has_value() && !inner_kdf->name.empty()) {
                    if (inner_kdf->name == "argon2") {
                        if (!inner::argon2_supported()) {
                            auth_error_ = "server does not support argon2";
                            return false;
                        }
                        std::string cap_reason;
                        if (inner::argon2_params_exceed_limits(
                                *inner_kdf, inner::argon2_env_limits(), &cap_reason)) {
                            auth_error_ = "client argon2 params exceed server cap: " + cap_reason;
                            return false;
                        }
                    } else if (inner_kdf->name == "pbkdf2") {
                        if (!inner::pbkdf2_supported()) {
                            auth_error_ = "server does not support pbkdf2";
                            return false;
                        }
                    } else if (inner_kdf->name == "hkdf") {
                        if (!inner_mode.has_value() || *inner_mode != "light") {
                            auth_error_ = "invalid kdf request";
                            return false;
                        }
                    } else {
                        auth_error_ = "invalid kdf request";
                        return false;
                    }
                }
                inner::Config inner_cfg;
                inner_cfg.enabled = cfg_.inner_crypto;
                inner_cfg.pq_private_key = cfg_.pq_private_key;
                inner_cfg.allow_embedded_master = cfg_.allow_embedded_master;
                auto server_inner_start = std::chrono::steady_clock::now();
                if (cfg_.inner_dual) {
                    std::optional<inner::KdfParams> heavy_kdf;
                    if (inner_kdf.has_value() && !inner_kdf->name.empty() && inner_kdf->name != "hkdf") {
                        heavy_kdf = inner_kdf;
                    }
                    auto heavy = inner::server_derive_key(inner_cfg, *pq_ciphertext, *pq_salt, true, heavy_kdf);
                    auto light = inner::server_derive_key(inner_cfg, *pq_ciphertext, *pq_salt, false, std::nullopt);
                    if ((!heavy.has_value() || heavy->key.empty()) && (!light.has_value() || light->key.empty())) {
                        util::log_warn("session " + std::to_string(session_id_) + ": PQ key derivation failed");
                        auth_error_ = "access denied: pq key derivation failed";
                        return false;
                    }
                    bool prefer_light = (inner_mode.has_value() && *inner_mode == "light");
                    bool prefer_heavy = (inner_mode.has_value() && *inner_mode == "heavy");
                    if (prefer_light && light.has_value() && !light->key.empty()) {
                        inner_key_ = light->key;
                        inner_mode_ = "light";
                        inner_kdf_ = light->kdf;
                        if (heavy.has_value() && !heavy->key.empty()) {
                            inner_key_alt_ = heavy->key;
                            inner_alt_mode_ = "heavy";
                            inner_alt_kdf_ = heavy->kdf;
                        }
                    } else if (prefer_heavy && heavy.has_value() && !heavy->key.empty()) {
                        inner_key_ = heavy->key;
                        inner_mode_ = "heavy";
                        inner_kdf_ = heavy->kdf;
                        if (light.has_value() && !light->key.empty()) {
                            inner_key_alt_ = light->key;
                            inner_alt_mode_ = "light";
                            inner_alt_kdf_ = light->kdf;
                        }
                    } else if (cfg_.inner_heavy && heavy.has_value() && !heavy->key.empty()) {
                        inner_key_ = heavy->key;
                        inner_mode_ = "heavy";
                        inner_kdf_ = heavy->kdf;
                        if (light.has_value() && !light->key.empty()) {
                            inner_key_alt_ = light->key;
                            inner_alt_mode_ = "light";
                            inner_alt_kdf_ = light->kdf;
                        }
                    } else if (light.has_value() && !light->key.empty()) {
                        inner_key_ = light->key;
                        inner_mode_ = "light";
                        inner_kdf_ = light->kdf;
                        if (heavy.has_value() && !heavy->key.empty()) {
                            inner_key_alt_ = heavy->key;
                            inner_alt_mode_ = "heavy";
                            inner_alt_kdf_ = heavy->kdf;
                        }
                    }
                } else {
                    auto derived = inner::server_derive_key(inner_cfg, *pq_ciphertext, *pq_salt, cfg_.inner_heavy, inner_kdf);
                    if (!derived.has_value() || derived->key.empty()) {
                        util::log_warn("session " + std::to_string(session_id_) + ": PQ key derivation failed");
                        auth_error_ = "access denied: pq key derivation failed";
                        return false;
                    }
                    inner_key_ = derived->key;
                    inner_mode_ = cfg_.inner_heavy ? "heavy" : "light";
                    inner_kdf_ = derived->kdf;
                }
                auto server_inner_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - server_inner_start).count();
                util::log_timing("server.auth",
                                 "inner_prepare",
                                 "session=" + std::to_string(session_id_) +
                                     " ms=" + std::to_string(server_inner_ms) +
                                     " mode=" + (inner_mode_.empty() ? std::string("none") : inner_mode_) +
                                     " kdf=" + (inner_kdf_.empty() ? std::string("unknown") : inner_kdf_) +
                                     " alt_mode=" + (inner_alt_mode_.empty() ? std::string("none") : inner_alt_mode_) +
                                     " alt_kdf=" + (inner_alt_kdf_.empty() ? std::string("none") : inner_alt_kdf_));
            }
        } else if (pq_ciphertext.has_value()) {
            auth_error_ = "server does not support inner crypto";
            return false;
        }

        bool client_hop = inner_hop.value_or(false);
        if (cfg_.inner_hop) {
            if (!client_hop) {
                auth_error_ = "server requires hopping";
                return false;
            }
        } else if (client_hop) {
            auth_error_ = "server does not support hopping";
            return false;
        }
        hop_enabled_ = (cfg_.inner_hop && client_hop && inner_key_.has_value());
        hop_interval_ms_ = cfg_.hop_interval_ms;
        hop_offset_ms_ = 0;

        if (!cfg_.anonym) {
            update_auth_meta(cfg_.auth_keys_meta, fingerprint);
        }
        return true;
    } catch (const std::exception& ex) {
        const std::string detail = ex.what();
        const bool post_key_auth = !auth_fingerprint_.empty();
        if (!cfg_.anonym || auth_debug_enabled()) {
            util::log_warn("session " + std::to_string(session_id_) +
                           ": auth exception fingerprint=" +
                           (auth_fingerprint_.empty() ? std::string("<unknown>") : auth_fingerprint_) +
                           " detail=" + detail);
        }
        if (post_key_auth && looks_like_inner_auth_exception(detail)) {
            auth_error_ = "access denied: pq key derivation failed";
        } else {
            auth_error_ = "access denied: invalid key";
        }
        return false;
    }
}

void Session::handle_open(const protocol::Frame& frame) {
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
            start_remote_read(frame.header.stream_id);
        }
        pending_reverse_.erase(frame.header.stream_id);
        return;
    }
    if (streams_.find(frame.header.stream_id) != streams_.end() ||
        udp_streams_.find(frame.header.stream_id) != udp_streams_.end() ||
        bench_streams_.find(frame.header.stream_id) != bench_streams_.end() ||
        (packet_stream_.has_value() && packet_stream_->stream_id == frame.header.stream_id)) {
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
            if (frame.header.stream_id == 0 || target.get() == this) {
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
        util::log_timing("server.open",
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
                util::log_timing("server.open",
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
            util::log_timing("server.open",
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
            util::log_timing("server.open",
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
                        util::log_timing("server.open",
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
                    util::log_timing("server.open",
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
                    util::log_timing("server.open",
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
    util::log_timing("server.open",
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
        util::log_timing("server.open",
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
                                                                      util::log_timing("server.open",
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
                                                                  util::log_timing("server.open",
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
            util::log_timing("server.open",
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
                    util::log_timing("server.open",
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

uint8_t Session::reserve_stream_id() {
    std::lock_guard<std::mutex> lock(streams_mutex_);
    for (int i = 1; i < 255; ++i) {
        uint8_t candidate = static_cast<uint8_t>(i);
        if (streams_.find(candidate) == streams_.end() &&
            udp_streams_.find(candidate) == udp_streams_.end() &&
            pending_reverse_.find(candidate) == pending_reverse_.end() &&
            reverse_listeners_.find(candidate) == reverse_listeners_.end()) {
            return candidate;
        }
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
    bool reclaim = false;
    int min_port = 0;
    int max_port = 0;
    try {
        auto json = nlohmann::json::parse(payload_str);
        listen_port = json.value("port", 0);
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

    bool reclaimed = false;
    std::string bind_error;
    auto try_bind_listener = [&](int candidate_port,
                                 std::shared_ptr<boost::asio::ip::tcp::acceptor>* out_acceptor) -> bool {
        if (reclaim && manager_) {
            reclaimed = manager_->reclaim_reverse_listener(candidate_port);
        }
        auto candidate = std::make_shared<boost::asio::ip::tcp::acceptor>(stream_.get_executor());
        boost::system::error_code ec;
        boost::asio::ip::tcp::endpoint ep(boost::asio::ip::tcp::v4(), candidate_port);
        candidate->open(ep.protocol(), ec);
        if (ec) {
            bind_error = "listen failed: " + ec.message();
            return false;
        }
        candidate->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
        candidate->bind(ep, ec);
        if (ec == boost::asio::error::address_in_use && reclaim && manager_ && !reclaimed) {
            if (manager_->reclaim_reverse_listener(candidate_port)) {
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
        acceptor->async_accept([self, acceptor, listen_id, do_accept](const boost::system::error_code& ec2,
                                                                      boost::asio::ip::tcp::socket socket) {
            if (!ec2) {
                uint8_t stream_id = self->reserve_stream_id();
                if (stream_id == 0) {
                    boost::system::error_code close_ec;
                    socket.close(close_ec);
                } else {
                    auto remote = std::make_shared<RemoteStream>(self->stream_.get_executor());
                    remote->socket = std::move(socket);
                    boost::system::error_code keep_ec;
                    remote->socket.set_option(boost::asio::socket_base::keep_alive(true), keep_ec);
                    self->streams_[stream_id] = remote;
                    self->pending_reverse_.insert(stream_id);

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
        });
    };
    (*do_accept)();
}

// handle_control + 5 sub-handlers (open_request / open_ack /
// data / close / exec) and the 3 send_control_* helpers moved
// to session_control.cpp in 1.0.x. Same Session:: methods,
// same signatures — different translation unit so neither
// file gets bigger.

bool Session::attach_federated_stream(uint8_t stream_id,
                                      control::ChannelKind channel_kind,
                                      const std::string& channel_id,
                                      const std::string& left_endpoint_id,
                                      const std::string& right_endpoint_id,
                                      std::function<void(const crypto::Bytes&)> on_data,
                                      std::function<void(const std::string&)> on_close) {
    if (stream_id == 0) {
        return false;
    }
    std::lock_guard<std::mutex> lock(control_mutex_);
    if (federated_streams_.find(stream_id) != federated_streams_.end()) {
        return false;
    }
    FederatedStream stream;
    stream.channel_kind = channel_kind;
    stream.channel_id = channel_id;
    stream.left_endpoint_id = left_endpoint_id;
    stream.right_endpoint_id = right_endpoint_id;
    stream.on_data = std::move(on_data);
    stream.on_close = std::move(on_close);
    federated_streams_[stream_id] = std::move(stream);
    return true;
}

void Session::complete_federated_open(uint8_t stream_id, bool ok, const std::string& message) {
    std::string channel_id;
    control::ChannelKind channel_kind{control::ChannelKind::chat};
    std::string left_endpoint_id;
    std::string right_endpoint_id;
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        auto it = federated_streams_.find(stream_id);
        if (it == federated_streams_.end()) {
            return;
        }
        channel_id = it->second.channel_id;
        channel_kind = it->second.channel_kind;
        left_endpoint_id = it->second.left_endpoint_id;
        right_endpoint_id = it->second.right_endpoint_id;
        if (ok) {
            it->second.pending = false;
        } else {
            federated_streams_.erase(it);
        }
    }
    if (ok && manager_ && !channel_id.empty()) {
        control::ActiveRelayChannel channel;
        channel.channel_id = channel_id;
        channel.channel_kind = channel_kind;
        channel.left_endpoint_id = left_endpoint_id;
        channel.right_endpoint_id = right_endpoint_id;
        channel.left_stream_id = stream_id;
        channel.right_stream_id = 0;
        channel.pending = false;
        channel.federated = true;
        channel.route_hops = 1;
        manager_->register_active_channel(channel);
    }
    if (!ok && manager_ && !channel_id.empty()) {
        manager_->unregister_active_channel(channel_id);
    }
    send_open_reply(stream_id, ok, message);
}

void Session::send_federated_data(uint8_t stream_id, const crypto::Bytes& payload) {
    send_control_frame(protocol::DATA, stream_id, payload);
}

void Session::send_federated_close(uint8_t stream_id, const std::string& reason) {
    std::string channel_id;
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        auto it = federated_streams_.find(stream_id);
        if (it != federated_streams_.end()) {
            channel_id = it->second.channel_id;
            federated_streams_.erase(it);
        }
    }
    if (manager_ && !channel_id.empty()) {
        manager_->unregister_active_channel(channel_id);
    }
    send_control_close(stream_id, reason);
}

bool Session::handle_packet_open(uint8_t stream_id) {
    if (!manager_ || !manager_->packet_egress_active()) {
        send_open_reply(stream_id, false, "packet egress unavailable");
        return false;
    }
    if (packet_stream_.has_value()) {
        send_open_reply(stream_id, false, "packet stream already open");
        return false;
    }

    auto weak = weak_from_this();
    auto assignment = manager_->register_packet_client(
        this,
        [weak](crypto::Bytes packet) mutable {
            if (auto self = weak.lock()) {
                boost::asio::post(self->strand_, [self, packet = std::move(packet)]() mutable {
                    self->queue_packet_downstream(std::move(packet));
                });
            }
        });
    if (!assignment.has_value()) {
        send_open_reply(stream_id, false, "packet client address unavailable");
        return false;
    }

    PacketStream packet;
    packet.stream_id = stream_id;
    packet.client_ipv4_be = assignment->ipv4_be;
    packet.client_ipv4 = assignment->ipv4;
    packet.mtu = assignment->mtu;
    packet.dns_servers = assignment->dns_servers;
    packet.downstream_encoded_bytes = protocol::packet_bulk::kHeaderBytes;
    packet.open_started_ms = util::now_ms();
    packet.flush_timer = std::make_unique<boost::asio::steady_timer>(stream_.get_executor());
    packet_stream_ = std::move(packet);

    nlohmann::json ack{
        {"proto", std::string(protocol::packet_bulk::kOpenProto)},
        {"capability", std::string(protocol::packet_bulk::kCapability)},
        {"ipv4", assignment->ipv4},
        {"mtu", assignment->mtu},
        {"dns", assignment->dns_servers},
    };
    send_open_reply(stream_id, true, ack.dump());
    util::log_info("session " + std::to_string(session_id_) +
                   ": packet-bulk stream " + std::to_string(stream_id) +
                   " assigned " + assignment->ipv4 +
                   " mtu=" + std::to_string(assignment->mtu));
    return true;
}

bool Session::handle_packet_data(uint8_t stream_id, const crypto::Bytes& payload) {
    if (!packet_stream_.has_value() || packet_stream_->stream_id != stream_id) {
        return false;
    }
    std::string error;
    auto batch = protocol::packet_bulk::decode_batch(payload, &error);
    if (!batch.has_value()) {
        util::log_warn("session " + std::to_string(session_id_) +
                       ": dropped malformed packet-bulk DATA on stream " +
                       std::to_string(stream_id) + ": " + error);
        return true;
    }
    packet_stream_->upstream_batches += 1;
    for (auto& packet : batch->packets) {
        std::string reason;
        if (!validate_client_ipv4_packet(packet, packet_stream_->client_ipv4_be, &reason)) {
            util::log_warn("session " + std::to_string(session_id_) +
                           ": dropped packet-bulk packet on stream " +
                           std::to_string(stream_id) + ": " + reason);
            continue;
        }
        if (manager_) {
            const std::uint32_t dst_be = read_ipv4_be(packet, 16);
            boost::asio::ip::address_v4::bytes_type dst_bytes{{
                static_cast<unsigned char>((dst_be >> 24) & 0xffu),
                static_cast<unsigned char>((dst_be >> 16) & 0xffu),
                static_cast<unsigned char>((dst_be >> 8) & 0xffu),
                static_cast<unsigned char>(dst_be & 0xffu),
            }};
            const boost::asio::ip::address dst = boost::asio::ip::address_v4(dst_bytes);
            std::string filter_reason;
            if (!manager_->egress_allowed(dst, &filter_reason)) {
                util::log_info_rate_limited(
                    "packet-egress-filter",
                    "egress filter dropped packet-native IPv4 packet to " +
                        dst.to_string() +
                        (filter_reason.empty() ? "" : " (" + filter_reason + ")"),
                    30000);
                continue;
            }
        }
        packet_stream_->upstream_packets += 1;
        if (manager_) {
            manager_->write_packet_to_egress(packet_stream_->client_ipv4_be, std::move(packet));
        }
    }
    return true;
}

void Session::queue_packet_downstream(crypto::Bytes packet) {
    if (!packet_stream_.has_value() || close_state_ != CloseState::Open) {
        return;
    }
    auto& stream = *packet_stream_;
    if (!protocol::packet_bulk::can_append_packet(stream.downstream_encoded_bytes,
                                                  stream.downstream_packets.size(),
                                                  packet.size())) {
        flush_packet_downstream();
    }
    if (!protocol::packet_bulk::can_append_packet(stream.downstream_encoded_bytes,
                                                  stream.downstream_packets.size(),
                                                  packet.size())) {
        return;
    }
    const std::size_t base = stream.downstream_packets.empty()
        ? protocol::packet_bulk::kHeaderBytes
        : stream.downstream_encoded_bytes;
    stream.downstream_encoded_bytes = base + protocol::packet_bulk::kPacketLengthBytes + packet.size();
    stream.downstream_packets.push_back(std::move(packet));
    stream.downstream_packet_count += 1;
    if (stream.downstream_packets.size() >= protocol::packet_bulk::kMaxPacketsPerBatch ||
        stream.downstream_encoded_bytes >= protocol::packet_bulk::kDefaultMaxBatchBytes) {
        flush_packet_downstream();
        return;
    }
    auto* timer = stream.flush_timer.get();
    if (!timer) {
        return;
    }
    timer->expires_after(std::chrono::microseconds(protocol::packet_bulk::kDefaultFlushDelayMicros));
    auto self = shared_from_this();
    timer->async_wait(boost::asio::bind_executor(
        strand_,
        [self](const boost::system::error_code& ec) {
            if (!ec) {
                self->flush_packet_downstream();
            }
        }));
}

void Session::flush_packet_downstream() {
    if (!packet_stream_.has_value() || packet_stream_->downstream_packets.empty()) {
        return;
    }
    auto& stream = *packet_stream_;
    if (stream.flush_timer) {
        boost::system::error_code ec;
        stream.flush_timer->cancel(ec);
    }
    std::vector<crypto::Bytes> packets;
    packets.reserve(stream.downstream_packets.size());
    while (!stream.downstream_packets.empty()) {
        packets.push_back(std::move(stream.downstream_packets.front()));
        stream.downstream_packets.pop_front();
    }
    stream.downstream_encoded_bytes = protocol::packet_bulk::kHeaderBytes;
    protocol::packet_bulk::Batch batch;
    batch.sequence = stream.downstream_sequence++;
    batch.packets = std::move(packets);
    crypto::Bytes payload;
    try {
        payload = protocol::packet_bulk::encode_batch(batch);
    } catch (const std::exception& ex) {
        util::log_warn("session " + std::to_string(session_id_) +
                       ": failed to encode downstream packet batch: " + ex.what());
        return;
    }
    std::uint16_t flags = 0;
    if (inner_key_.has_value()) {
        payload = encrypt_inner_payload(protocol::DATA, stream.stream_id, payload);
        flags |= protocol::kFlagInnerEncrypted;
    }
    stream.downstream_batches += 1;
    protocol::Frame frame{{static_cast<std::uint32_t>(payload.size()), protocol::DATA, stream.stream_id, flags}, payload};
    queue_frame_on_strand(frame);
}

bool Session::handle_bench_open(uint8_t stream_id, const std::string& proto, const nlohmann::json& json) {
    if (!cfg_.benchmark_enable) {
        send_open_reply(stream_id, false, "benchmark disabled on server");
        return true;
    }

    std::uint64_t requested = 0;
    try {
        requested = json.value("bytes", static_cast<std::uint64_t>(0));
    } catch (...) {
        requested = 0;
    }
    if (requested == 0 || requested > kBenchMaxBytes) {
        send_open_reply(stream_id, false, "invalid benchmark byte count");
        return true;
    }

    BenchStream bench;
    bench.mode = (proto == kBenchSourceProto) ? BenchStream::Mode::Source : BenchStream::Mode::Sink;
    bench.requested_bytes = requested;
    bench.open_started_ms = util::now_ms();
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        bench_streams_[stream_id] = bench;
    }

    send_open_reply(stream_id, true, "");
    util::log_info("session " + std::to_string(session_id_) +
                   ": benchmark stream " + std::to_string(stream_id) +
                   " proto=" + proto +
                   " bytes=" + std::to_string(requested));
    if (bench.mode == BenchStream::Mode::Source) {
        pump_bench_source(stream_id);
    }
    return true;
}

bool Session::handle_bench_data(uint8_t stream_id, const crypto::Bytes& payload) {
    std::lock_guard<std::mutex> lock(streams_mutex_);
    auto it = bench_streams_.find(stream_id);
    if (it == bench_streams_.end()) {
        return false;
    }
    if (it->second.mode == BenchStream::Mode::Sink) {
        it->second.upstream_bytes += static_cast<std::uint64_t>(payload.size());
    }
    return true;
}

bool Session::handle_bench_close(uint8_t stream_id, const std::string& reason) {
    BenchStream bench;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = bench_streams_.find(stream_id);
        if (it == bench_streams_.end()) {
            return false;
        }
        bench = it->second;
        bench_streams_.erase(it);
    }

    const int64_t elapsed_ms = bench.open_started_ms > 0 ? (util::now_ms() - bench.open_started_ms) : 0;
    if (bench.mode == BenchStream::Mode::Sink) {
        nlohmann::json summary{
            {"mode", "up"},
            {"bytes", bench.upstream_bytes},
            {"requested_bytes", bench.requested_bytes},
            {"server_ms", elapsed_ms},
        };
        const std::string out = summary.dump();
        send_control_frame(protocol::DATA, stream_id, crypto::Bytes(out.begin(), out.end()));
    }
    send_control_close(stream_id, reason.empty() ? "benchmark complete" : reason);
    util::log_timing("server.stream",
                     "summary",
                     "session=" + std::to_string(session_id_) +
                         " stream=" + std::to_string(stream_id) +
                         " proto=bench " +
                         "mode=" + std::string(bench.mode == BenchStream::Mode::Sink ? "sink" : "source") +
                         " ms=" + std::to_string(elapsed_ms) +
                         " upstream=" + std::to_string(bench.upstream_bytes) +
                         " downstream=" + std::to_string(bench.downstream_bytes) +
                         " requested=" + std::to_string(bench.requested_bytes));
    return true;
}

void Session::pump_bench_source(uint8_t stream_id) {
    for (;;) {
        std::uint64_t offset = 0;
        std::size_t chunk_size = 0;
        {
            std::lock_guard<std::mutex> lock(streams_mutex_);
            auto it = bench_streams_.find(stream_id);
            if (it == bench_streams_.end() ||
                it->second.mode != BenchStream::Mode::Source ||
                it->second.close_sent) {
                return;
            }
            auto& bench = it->second;
            if (bench.downstream_bytes >= bench.requested_bytes ||
                bench.in_flight_frames >= kBenchSourceWindowFrames ||
                write_queue_depth_ >= kWriteQueueHighWatermark) {
                break;
            }
            const std::uint64_t remaining = bench.requested_bytes - bench.downstream_bytes;
            chunk_size = static_cast<std::size_t>(
                std::min<std::uint64_t>(remaining, util::relay_read_buf_size()));
            offset = bench.downstream_bytes;
            bench.downstream_bytes += static_cast<std::uint64_t>(chunk_size);
            bench.in_flight_frames += 1;
        }

        crypto::Bytes payload(chunk_size);
        for (std::size_t i = 0; i < chunk_size; ++i) {
            payload[i] = static_cast<std::uint8_t>((offset + i) & 0xffu);
        }
        auto self = shared_from_this();
        send_control_frame(
            protocol::DATA,
            stream_id,
            payload,
            0,
            [self, stream_id](const boost::system::error_code& ec, std::size_t) {
                bool should_continue = false;
                {
                    std::lock_guard<std::mutex> lock(self->streams_mutex_);
                    auto it = self->bench_streams_.find(stream_id);
                    if (it == self->bench_streams_.end()) {
                        return;
                    }
                    if (it->second.in_flight_frames > 0) {
                        it->second.in_flight_frames -= 1;
                    }
                    should_continue = !ec;
                }
                if (!should_continue) {
                    self->handle_bench_close(stream_id, "benchmark write failed");
                    return;
                }
                self->maybe_finish_bench_source(stream_id);
                self->pump_bench_source(stream_id);
            });
    }
    maybe_finish_bench_source(stream_id);
}

void Session::maybe_finish_bench_source(uint8_t stream_id) {
    bool done = false;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = bench_streams_.find(stream_id);
        if (it == bench_streams_.end() ||
            it->second.mode != BenchStream::Mode::Source ||
            it->second.close_sent) {
            return;
        }
        auto& bench = it->second;
        done = bench.downstream_bytes >= bench.requested_bytes && bench.in_flight_frames == 0;
        if (done) {
            bench.close_sent = true;
        }
    }
    if (done) {
        handle_bench_close(stream_id, "benchmark complete");
    }
}

void Session::handle_data(const protocol::Frame& frame) {
    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        if (!decrypt_inner_payload(frame.header.type, frame.header.stream_id, frame.payload, &payload)) {
            util::log_warn("session " + std::to_string(session_id_) + ": DATA decrypt failed for stream " +
                           std::to_string(frame.header.stream_id));
            close_with_reason("DATA decrypt failed for stream " + std::to_string(frame.header.stream_id));
            return;
        }
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
        federated_data(payload);
        return;
    }
    if (handle_packet_data(frame.header.stream_id, payload)) {
        return;
    }
    if (handle_bench_data(frame.header.stream_id, payload)) {
        return;
    }
    auto it_udp = udp_streams_.find(frame.header.stream_id);
    if (it_udp != udp_streams_.end()) {
        enqueue_udp_write(frame.header.stream_id, payload);
        return;
    }
    enqueue_remote_write(frame.header.stream_id, payload);
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

void Session::start_remote_read(uint8_t stream_id) {
    std::shared_ptr<RemoteStream> remote;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }
        remote = it->second;
        if (close_state_ != CloseState::Open) {
            remote->read_paused = true;
            return;
        }
        if (remote->read_in_flight) {
            return;
        }
        if (should_pause_inbound_reads_on_strand()) {
            remote->read_paused = true;
            return;
        }
        remote->read_paused = false;
        remote->read_in_flight = true;
    }

    auto self = shared_from_this();
    remote->socket.async_read_some(boost::asio::buffer(remote->read_buf),
                                   boost::asio::bind_executor(strand_,
                                                              [self, stream_id](const boost::system::error_code& ec, std::size_t bytes) {
                                                                  self->on_remote_read(stream_id, ec, bytes);
                                                              }));
}

void Session::on_remote_read(uint8_t stream_id, const boost::system::error_code& ec, std::size_t bytes) {
    std::shared_ptr<RemoteStream> remote;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }
        remote = it->second;
        remote->read_in_flight = false;
    }

    if (ec) {
        if (ec == boost::asio::error::eof) {
            bool send_fin = false;
            {
                std::lock_guard<std::mutex> lock(streams_mutex_);
                auto it = streams_.find(stream_id);
                if (it == streams_.end()) {
                    return;
                }
                if (!it->second->remote_fin_sent) {
                    it->second->remote_fin_sent = true;
                    send_fin = true;
                }
            }
            if (send_fin) {
                send_control_fin(stream_id, "remote closed");
            }
            finish_remote_stream_if_done(stream_id);
            return;
        }
        handle_close(stream_id, "remote read failed: " + ec.message());
        send_control_close(stream_id, "remote read failed");
        return;
    }
    remote->downstream_bytes += static_cast<std::uint64_t>(bytes);
    if (remote->first_downstream_ms == 0) {
        remote->first_downstream_ms = util::now_ms();
        util::log_timing("server.stream",
                         "first_downstream",
                         "session=" + std::to_string(session_id_) +
                             " stream=" + std::to_string(stream_id) +
                             " proto=tcp ms=" +
                             std::to_string(remote->first_downstream_ms - remote->open_started_ms) +
                             " bytes=" + std::to_string(bytes));
    }

    crypto::Bytes payload(remote->read_buf.data(), remote->read_buf.data() + bytes);
    uint16_t flags = 0;
    if (inner_key_.has_value()) {
        payload = encrypt_inner_payload(protocol::DATA, stream_id, payload);
        flags |= protocol::kFlagInnerEncrypted;
    }

    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::DATA, stream_id, flags}, std::move(payload)};
    queue_frame_on_strand(frame);
    start_remote_read(stream_id);
}

void Session::start_udp_read(uint8_t stream_id) {
    std::shared_ptr<UdpStream> udp;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = udp_streams_.find(stream_id);
        if (it == udp_streams_.end()) {
            return;
        }
        udp = it->second;
        if (close_state_ != CloseState::Open) {
            udp->read_paused = true;
            return;
        }
        if (udp->read_in_flight) {
            return;
        }
        if (should_pause_inbound_reads_on_strand()) {
            udp->read_paused = true;
            return;
        }
        udp->read_paused = false;
        udp->read_in_flight = true;
    }

    auto self = shared_from_this();
    udp->socket.async_receive(boost::asio::buffer(udp->read_buf),
                              boost::asio::bind_executor(strand_,
                                                         [self, stream_id](const boost::system::error_code& ec, std::size_t bytes) {
                                                             self->on_udp_read(stream_id, ec, bytes);
                                                         }));
}

void Session::on_udp_read(uint8_t stream_id, const boost::system::error_code& ec, std::size_t bytes) {
    std::shared_ptr<UdpStream> udp;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = udp_streams_.find(stream_id);
        if (it == udp_streams_.end()) {
            return;
        }
        udp = it->second;
        udp->read_in_flight = false;
    }

    if (ec) {
        handle_close(stream_id, "udp remote closed");
        send_control_close(stream_id, "");
        return;
    }
    udp->downstream_bytes += static_cast<std::uint64_t>(bytes);
    if (udp->first_downstream_ms == 0) {
        udp->first_downstream_ms = util::now_ms();
        util::log_timing("server.stream",
                         "first_downstream",
                         "session=" + std::to_string(session_id_) +
                             " stream=" + std::to_string(stream_id) +
                             " proto=udp ms=" +
                             std::to_string(udp->first_downstream_ms - udp->open_started_ms) +
                             " bytes=" + std::to_string(bytes));
    }

    crypto::Bytes payload(udp->read_buf.data(), udp->read_buf.data() + bytes);
    uint16_t flags = 0;
    if (inner_key_.has_value()) {
        payload = encrypt_inner_payload(protocol::DATA, stream_id, payload);
        flags |= protocol::kFlagInnerEncrypted;
    }

    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::DATA, stream_id, flags}, std::move(payload)};
    queue_frame_on_strand(frame);
    start_udp_read(stream_id);
}

void Session::enqueue_udp_write(uint8_t stream_id, const crypto::Bytes& data) {
    std::shared_ptr<UdpStream> udp;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = udp_streams_.find(stream_id);
        if (it == udp_streams_.end()) {
            return;
        }
        udp = it->second;
    }
    udp->upstream_bytes += static_cast<std::uint64_t>(data.size());
    if (udp->first_upstream_ms == 0) {
        udp->first_upstream_ms = util::now_ms();
        util::log_timing("server.stream",
                         "first_upstream",
                         "session=" + std::to_string(session_id_) +
                             " stream=" + std::to_string(stream_id) +
                             " proto=udp ms=" +
                             std::to_string(udp->first_upstream_ms - udp->open_started_ms) +
                             " bytes=" + std::to_string(data.size()));
    }
    udp->write_queue.push_back(data);
    if (!udp->write_in_flight) {
        do_udp_write(stream_id);
    }
}

std::chrono::milliseconds Session::reserve_egress_delay(std::size_t bytes) const {
    if (!authenticated_ || !manager_ || bandwidth_fair_key_.empty() || bytes == 0) {
        return std::chrono::milliseconds(0);
    }
    return manager_->reserve_egress_write(bandwidth_fair_key_, bandwidth_priority_, bytes);
}

void Session::do_udp_write(uint8_t stream_id) {
    std::shared_ptr<UdpStream> udp;
    crypto::Bytes data_to_write;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = udp_streams_.find(stream_id);
        if (it == udp_streams_.end()) {
            return;
        }
        udp = it->second;
        if (udp->write_queue.empty()) {
            udp->write_in_flight = false;
            return;
        }
        udp->write_in_flight = true;
        data_to_write = std::move(udp->write_queue.front());
        udp->write_queue.pop_front();
    }
    auto buffer = std::make_shared<crypto::Bytes>(std::move(data_to_write));
    auto self = shared_from_this();
    auto fire_write = [self, udp, buffer, stream_id]() {
        udp->socket.async_send(
            boost::asio::buffer(*buffer),
            boost::asio::bind_executor(
                self->strand_,
                [self, buffer, stream_id](const boost::system::error_code& ec, std::size_t) {
                    if (ec) {
                        self->handle_close(stream_id, "udp send failed");
                        self->send_control_close(stream_id, "");
                        return;
                    }
                    self->do_udp_write(stream_id);
                }));
    };
    const auto delay_ms = reserve_egress_delay(buffer->size());
    if (delay_ms.count() <= 0) {
        fire_write();
        return;
    }
    auto timer = std::make_shared<boost::asio::steady_timer>(strand_);
    timer->expires_after(delay_ms);
    timer->async_wait([timer, fire_write = std::move(fire_write)](const boost::system::error_code& ec) mutable {
        if (!ec) fire_write();
    });
}

void Session::enqueue_remote_write(uint8_t stream_id, const std::vector<uint8_t>& data) {
    std::shared_ptr<RemoteStream> remote;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }
        remote = it->second;
    }
    remote->upstream_bytes += static_cast<std::uint64_t>(data.size());
    if (remote->first_upstream_ms == 0) {
        remote->first_upstream_ms = util::now_ms();
        util::log_timing("server.stream",
                         "first_upstream",
                         "session=" + std::to_string(session_id_) +
                             " stream=" + std::to_string(stream_id) +
                             " proto=tcp ms=" +
                             std::to_string(remote->first_upstream_ms - remote->open_started_ms) +
                             " bytes=" + std::to_string(data.size()));
    }
    remote->write_queue.push_back(data);
    if (!remote->write_in_flight) {
        do_remote_write(stream_id);
    }
}

void Session::do_remote_write(uint8_t stream_id) {
    std::shared_ptr<RemoteStream> remote;
    std::vector<uint8_t> data_to_write;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }
        remote = it->second;
        if (!remote->connected) {
            remote->write_in_flight = false;
            return;
        }
        if (remote->write_queue.empty()) {
            remote->write_in_flight = false;
            if (remote->write_shutdown_pending && !remote->write_shutdown_sent && remote->connected) {
                // Do the half-shutdown outside the mutex.
            } else {
                return;
            }
        }
        if (remote->write_queue.empty() && remote->write_shutdown_pending &&
            !remote->write_shutdown_sent && remote->connected) {
            // Nothing left to write from the client side; send FIN to the upstream TCP peer.
            remote->write_in_flight = false;
            remote->write_shutdown_sent = true;
            data_to_write.clear();
        } else if (remote->write_queue.empty()) {
            return;
        }
        if (!remote->write_queue.empty()) {
            remote->write_in_flight = true;
            data_to_write = std::move(remote->write_queue.front());
            remote->write_queue.pop_front();
        }
    }

    if (data_to_write.empty()) {
        boost::system::error_code ec;
        remote->socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
        finish_remote_stream_if_done(stream_id);
        return;
    }

    auto buffer = std::make_shared<std::vector<uint8_t>>(std::move(data_to_write));
    auto self = shared_from_this();
    auto fire_write = [self, remote, buffer, stream_id]() {
        boost::asio::async_write(remote->socket, boost::asio::buffer(*buffer),
                                 boost::asio::bind_executor(self->strand_,
                                                            [self, buffer, stream_id](const boost::system::error_code& ec, std::size_t) {
                                                                if (ec) {
                                                                    self->handle_close(stream_id, "remote write failed");
                                                                    self->send_control_close(stream_id, "");
                                                                    return;
                                                                }
                                                                self->do_remote_write(stream_id);
                                                            }));
    };
    const auto delay_ms = reserve_egress_delay(buffer->size());
    if (delay_ms.count() <= 0) {
        fire_write();
        return;
    }
    auto timer = std::make_shared<boost::asio::steady_timer>(strand_);
    timer->expires_after(delay_ms);
    timer->async_wait([timer, fire_write = std::move(fire_write)](const boost::system::error_code& ec) mutable {
        if (!ec) fire_write();
    });
}

void Session::shutdown_remote_send_if_ready(uint8_t stream_id) {
    std::shared_ptr<RemoteStream> remote;
    bool shutdown_now = false;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }
        remote = it->second;
        if (remote->write_shutdown_pending && !remote->write_shutdown_sent &&
            !remote->write_in_flight && remote->write_queue.empty() && remote->connected) {
            remote->write_shutdown_sent = true;
            shutdown_now = true;
        }
    }
    if (!shutdown_now) {
        return;
    }
    boost::system::error_code ec;
    remote->socket.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
    finish_remote_stream_if_done(stream_id);
}

void Session::finish_remote_stream_if_done(uint8_t stream_id) {
    bool done = false;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }
        const auto& remote = it->second;
        done = remote->client_fin_received && remote->remote_fin_sent &&
               remote->write_queue.empty() && !remote->write_in_flight;
    }
    if (done) {
        handle_close(stream_id, "tcp half-close complete");
    }
}

void Session::async_write_frame(const protocol::Frame& frame,
                                std::function<void(const boost::system::error_code&, std::size_t)> handler) {
    auto data = std::make_shared<std::vector<uint8_t>>(protocol::encode_frame(
        static_cast<protocol::FrameType>(frame.header.type),
        frame.header.stream_id,
        frame.header.flags,
        frame.payload,
        cfg_.obfs_pad_multiple));

    boost::asio::post(strand_, [self = shared_from_this(), data, handler = std::move(handler)]() mutable {
        self->queue_encoded_write_on_strand(data, std::move(handler));
    });
}

void Session::queue_frame_on_strand(const protocol::Frame& frame,
                                    std::function<void(const boost::system::error_code&, std::size_t)> handler) {
    auto data = std::make_shared<std::vector<uint8_t>>(protocol::encode_frame(
        static_cast<protocol::FrameType>(frame.header.type),
        frame.header.stream_id,
        frame.header.flags,
        frame.payload,
        cfg_.obfs_pad_multiple));
    queue_encoded_write_on_strand(std::move(data), std::move(handler));
}

void Session::queue_encoded_write_on_strand(
    std::shared_ptr<std::vector<uint8_t>> data,
    std::function<void(const boost::system::error_code&, std::size_t)> handler) {
    if (close_state_ != CloseState::Open) {
        if (handler) {
            handler(boost::asio::error::operation_aborted, 0);
        }
        return;
    }

    if (write_queue_depth_ >= kMaxWriteQueueSize) {
        util::log_warn("session " + std::to_string(session_id_) +
                      ": write queue overflow (" + std::to_string(write_queue_depth_) +
                      " pending), closing to prevent SSL corruption");
        close_with_reason("write queue overrun - too many pending frames");
        if (handler) {
            handler(boost::asio::error::operation_aborted, 0);
        }
        return;
    }

    write_queue_.push_back({std::move(data), std::move(handler)});
    write_queue_depth_++;
    if (!write_in_flight_) {
        do_write();
    }
}

bool Session::should_pause_inbound_reads_on_strand() const {
    return close_state_ != CloseState::Open || write_queue_depth_ >= kWriteQueueHighWatermark;
}

void Session::maybe_resume_inbound_reads_on_strand() {
    if (close_state_ != CloseState::Open || write_queue_depth_ > kWriteQueueLowWatermark) {
        return;
    }

    std::vector<uint8_t> tcp_to_resume;
    std::vector<uint8_t> udp_to_resume;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        uint32_t budget = 0;
        if (write_queue_depth_ < kWriteQueueHighWatermark) {
            budget = kWriteQueueHighWatermark - write_queue_depth_;
        }
        if (budget == 0) {
            return;
        }

        for (const auto& [stream_id, remote] : streams_) {
            if (budget == 0) {
                break;
            }
            if (remote->read_paused && !remote->read_in_flight) {
                remote->read_paused = false;
                tcp_to_resume.push_back(stream_id);
                --budget;
            }
        }
        for (const auto& [stream_id, udp] : udp_streams_) {
            if (budget == 0) {
                break;
            }
            if (udp->read_paused && !udp->read_in_flight) {
                udp->read_paused = false;
                udp_to_resume.push_back(stream_id);
                --budget;
            }
        }
    }

    for (uint8_t stream_id : tcp_to_resume) {
        start_remote_read(stream_id);
    }
    for (uint8_t stream_id : udp_to_resume) {
        start_udp_read(stream_id);
    }
}

void Session::do_write() {
    if (write_queue_.empty()) {
        write_in_flight_ = false;
        if (close_state_ != CloseState::Open) {
            maybe_finish_close();
        }
        return;
    }
    write_in_flight_ = true;

    std::size_t batch_count = 0;
    std::size_t total_bytes = 0;
    for (auto it = write_queue_.begin();
         it != write_queue_.end() &&
         batch_count < kMaxWriteBatchFrames &&
         total_bytes < kMaxWriteBatchBytes;
         ++it) {
        total_bytes += it->data ? it->data->size() : 0;
        ++batch_count;
    }
    if (batch_count == 0) {
        write_in_flight_ = false;
        return;
    }

    std::shared_ptr<std::vector<uint8_t>> batch_data;
    if (batch_count == 1) {
        batch_data = write_queue_.front().data;
    } else {
        batch_data = std::make_shared<std::vector<uint8_t>>();
        batch_data->reserve(total_bytes);
        std::size_t copied = 0;
        for (auto it = write_queue_.begin(); it != write_queue_.end() && copied < batch_count; ++it, ++copied) {
            if (it->data && !it->data->empty()) {
                batch_data->insert(batch_data->end(), it->data->begin(), it->data->end());
            }
        }
    }

    auto self = shared_from_this();
    auto on_complete = [self, batch_data, batch_count](const boost::system::error_code& ec,
                                                       std::size_t bytes) {
        std::vector<PendingWrite> completed;
        completed.reserve(batch_count);
        std::size_t popped = 0;
        while (popped < batch_count && !self->write_queue_.empty()) {
            completed.push_back(std::move(self->write_queue_.front()));
            self->write_queue_.pop_front();
            ++popped;
        }
        if (self->write_queue_depth_ >= popped) {
            self->write_queue_depth_ -= static_cast<uint32_t>(popped);
        } else {
            self->write_queue_depth_ = 0;
        }
        if (!ec) {
            self->maybe_resume_inbound_reads_on_strand();
        }
        for (auto& item : completed) {
            if (item.handler) {
                const std::size_t item_bytes = (!ec && item.data) ? item.data->size() : bytes;
                item.handler(ec, item_bytes);
            }
        }
        if (ec) {
            if (self->close_state_ != CloseState::Open && is_expected_close_ec(ec)) {
                self->shutdown_transport();
                return;
            }
            std::string error_msg = "frame write failed: " + describe_error_code(ec);
            if (ec.category().name() == std::string("ssl") ||
                ec == boost::asio::ssl::error::stream_truncated) {
                error_msg = "SSL/TLS write error: " + error_msg + " [client must reconnect]";
            }
            self->close_with_reason(error_msg);
            return;
        }
        self->do_write();
    };

    auto fire_write = [self, batch_data, on_complete = std::move(on_complete)]() mutable {
        boost::asio::async_write(self->stream_, boost::asio::buffer(*batch_data),
                                 boost::asio::bind_executor(self->strand_, std::move(on_complete)));
    };

    // Per-batch send-side jitter. Defers the actual async_write by a
    // uniform random 0..obfs_jitter_ms delay. Because do_write() is
    // strand-serialised and the next do_write() only fires from
    // on_complete, the delay propagates: each batch is offset
    // independently. This is what defeats the "every keepalive arrives
    // T ms after the last" ML feature. Opt-in via --obfs-jitter-ms; 0 =
    // no delay, no timer overhead.
    std::chrono::milliseconds delay_ms = reserve_egress_delay(batch_data ? batch_data->size() : 0);
    if (cfg_.obfs_jitter_ms > 0) {
        thread_local std::mt19937 jitter_rng{std::random_device{}()};
        std::uniform_int_distribution<std::uint32_t> dist(0, cfg_.obfs_jitter_ms);
        delay_ms += std::chrono::milliseconds(dist(jitter_rng));
    }
    if (delay_ms.count() <= 0) {
        fire_write();
        return;
    }
    auto timer = std::make_shared<boost::asio::steady_timer>(strand_);
    timer->expires_after(delay_ms);
    timer->async_wait([timer, fire_write = std::move(fire_write)](const boost::system::error_code& ec) mutable {
        if (!ec) fire_write();
    });
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
