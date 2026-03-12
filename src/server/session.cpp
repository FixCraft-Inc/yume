/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "server/session.hpp"
#include "server/manager.hpp"

#include <openssl/pem.h>

#include <chrono>
#include <algorithm>
#include <fstream>
#include <ctime>
#include <random>
#include <string>

#include "core/inner_crypto.hpp"
#include "core/protocol.hpp"
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

namespace {
constexpr uint32_t kMaxFrameSize = 16 * 1024 * 1024;
constexpr uint8_t kMinFrameType = protocol::AUTH;
constexpr uint8_t kMaxFrameType = protocol::SOPEN;
constexpr int64_t kIdleTimeoutMs = 90 * 1000;
constexpr int64_t kIdleCheckIntervalMs = 30 * 1000;

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

bool is_private_ipv4(const boost::asio::ip::address_v4& addr) {
    const auto bytes = addr.to_bytes();
    const uint8_t a = bytes[0];
    const uint8_t b = bytes[1];
    if (a == 10) return true;
    if (a == 127) return true;
    if (a == 0) return true;
    if (a == 169 && b == 254) return true;
    if (a == 172 && (b >= 16 && b <= 31)) return true;
    if (a == 192 && b == 168) return true;
    if (a == 100 && (b >= 64 && b <= 127)) return true; // CGNAT
    if (a == 192 && b == 0) return true;
    if (a == 198 && (b == 18 || b == 19)) return true;
    if (a == 198 && b == 51) return true;
    if (a == 203 && b == 0) return true;
    if (a >= 224) return true; // multicast/reserved
    return false;
}

bool is_private_ipv6(const boost::asio::ip::address_v6& addr) {
    if (addr.is_loopback() || addr.is_unspecified() || addr.is_multicast()) {
        return true;
    }
    const auto bytes = addr.to_bytes();
    if ((bytes[0] & 0xFE) == 0xFC) { // fc00::/7
        return true;
    }
    if (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80) { // fe80::/10
        return true;
    }
    if (addr.is_v4_mapped()) {
        boost::asio::ip::address_v4::bytes_type v4bytes{
            {bytes[12], bytes[13], bytes[14], bytes[15]}
        };
        return is_private_ipv4(boost::asio::ip::address_v4(v4bytes));
    }
    return false;
}

bool is_public_address(const boost::asio::ip::address& addr) {
    if (addr.is_v4()) {
        return !is_private_ipv4(addr.to_v4());
    }
    if (addr.is_v6()) {
        return false;
    }
    return false;
}

bool is_allowed_address(const boost::asio::ip::address& addr, const ServerConfig& cfg) {
    if (cfg.control_full) {
        return true;
    }
    if (is_public_address(addr)) {
        return true;
    }
    return cfg.allow_local_ip;
}

bool is_blocked_host_literal(const std::string& host, const ServerConfig& cfg) {
    if (cfg.control_full) {
        return false;
    }
    if ((host == "localhost" || host == "localhost.localdomain") && !cfg.allow_local_ip) {
        return true;
    }
    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address(host, ec);
    if (!ec) {
        return !is_allowed_address(addr, cfg);
    }
    return false;
}

int random_int_inclusive(int min_value, int max_value) {
    if (min_value >= max_value) {
        return min_value;
    }
    static thread_local std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(min_value, max_value);
    return dist(rng);
}

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
    , idle_timer_(stream_.get_executor()) {
    last_activity_ms_.store(now_ms(), std::memory_order_relaxed);
}

void Session::start() {
    touch_activity();
    schedule_idle_check();
    auto self = shared_from_this();
    boost::system::error_code keep_ec;
    stream_.lowest_layer().set_option(boost::asio::socket_base::keep_alive(true), keep_ec);
    stream_.async_handshake(boost::asio::ssl::stream_base::server,
                            boost::asio::bind_executor(strand_,
                                                       [self](const boost::system::error_code& ec) {
                                                           self->on_handshake(ec);
                                                       }));
}

void Session::stop() {
    boost::asio::post(strand_, [self = shared_from_this()]() { self->close(); });
}

void Session::on_handshake(const boost::system::error_code& ec) {
    if (ec) {
        util::log_warn("session " + std::to_string(session_id_) + ": TLS handshake failed: " + ec.message());
        close();
        return;
    }
    boost::system::error_code ep_ec;
    auto ep = stream_.lowest_layer().remote_endpoint(ep_ec);
    if (!ep_ec) {
        client_wan_ip_ = ep.address().to_string();
    }

    if (cfg_.real_http) {
        start_preface_read();
        return;
    }

    send_auth_challenge();
}

void Session::start_preface_read() {
    preface_accum_.clear();
    preface_received_ = false;
    preface_timer_.expires_after(std::chrono::milliseconds(200));
    auto self = shared_from_this();
    preface_timer_.async_wait(boost::asio::bind_executor(strand_,
                                                         [self](const boost::system::error_code& ec) {
                                                             self->on_preface_timeout(ec);
                                                         }));
    stream_.async_read_some(boost::asio::buffer(preface_buf_),
                            boost::asio::bind_executor(strand_,
                                                       [self](const boost::system::error_code& ec, std::size_t bytes) {
                                                           self->on_preface_read(ec, bytes);
                                                       }));
}

void Session::on_preface_read(const boost::system::error_code& ec, std::size_t bytes) {
    if (ec) {
        if (ec != boost::asio::error::operation_aborted) {
            close();
        }
        return;
    }
    if (bytes == 0) {
        return;
    }

    preface_timer_.cancel();
    preface_received_ = true;
    preface_accum_.insert(preface_accum_.end(), preface_buf_.begin(), preface_buf_.begin() + static_cast<std::ptrdiff_t>(bytes));

    std::string preface(reinterpret_cast<const char*>(preface_accum_.data()), preface_accum_.size());
    if (handle_http_preface(preface)) {
        return;
    }

    if (preface_accum_.size() < preface_buf_.size()) {
        // need more to decide; read again
        auto self = shared_from_this();
        stream_.async_read_some(boost::asio::buffer(preface_buf_),
                                boost::asio::bind_executor(strand_,
                                                           [self](const boost::system::error_code& e, std::size_t n) {
                                                               self->on_preface_read(e, n);
                                                           }));
        return;
    }

    if (preface_accum_.size() < header_buf_.size()) {
        auto self = shared_from_this();
        stream_.async_read_some(boost::asio::buffer(preface_buf_),
                                boost::asio::bind_executor(strand_,
                                                           [self](const boost::system::error_code& e, std::size_t n) {
                                                               self->on_preface_read(e, n);
                                                           }));
        return;
    }

    uint32_t len = (static_cast<uint32_t>(preface_accum_[0]) << 24) |
                   (static_cast<uint32_t>(preface_accum_[1]) << 16) |
                   (static_cast<uint32_t>(preface_accum_[2]) << 8) |
                   (static_cast<uint32_t>(preface_accum_[3]));
    uint8_t type = preface_accum_[4];
    bool header_ok = len <= kMaxFrameSize && type >= kMinFrameType && type <= kMaxFrameType;
    if (!header_ok && cfg_.real_http) {
        send_real_http_response("/");
        return;
    }
    if (preface_accum_.size() > header_buf_.size()) {
        util::log_warn("session " + std::to_string(session_id_) + ": unexpected preface data");
        close();
        return;
    }

    std::copy(preface_accum_.begin(), preface_accum_.begin() + header_buf_.size(), header_buf_.begin());
    header_prefetched_ = true;
    read_header();
}

void Session::on_preface_timeout(const boost::system::error_code& ec) {
    if (ec == boost::asio::error::operation_aborted) {
        return;
    }
    if (!preface_received_) {
        send_auth_challenge();
    }
}
bool Session::handle_http_preface(const std::string& preface) {
    const std::string methods[] = {"GET ", "HEAD ", "POST ", "OPTIONS "};
    bool is_http = false;
    for (const auto& m : methods) {
        if (preface.rfind(m, 0) == 0) {
            is_http = true;
            break;
        }
    }
    if (!is_http && preface.rfind("PRI * HT", 0) == 0) {
        is_http = true;
    }
    if (!is_http) {
        return false;
    }

    auto self = shared_from_this();
    auto request = std::make_shared<std::string>(preface);
    boost::asio::async_read_until(stream_, boost::asio::dynamic_buffer(*request), "\r\n\r\n",
                                  boost::asio::bind_executor(strand_,
                                                             [self, request](const boost::system::error_code& e, std::size_t) {
                                                                 if (e) {
                                                                     self->close();
                                                                     return;
                                                                 }
                                                                 std::string line;
                                                                 auto pos = request->find("\r\n");
                                                                 if (pos != std::string::npos) {
                                                                     line = request->substr(0, pos);
                                                                 }
                                                                 std::string path = "/";
                                                                 if (!line.empty()) {
                                                                     auto p1 = line.find(' ');
                                                                     if (p1 != std::string::npos) {
                                                                         auto p2 = line.find(' ', p1 + 1);
                                                                         if (p2 != std::string::npos) {
                                                                             path = line.substr(p1 + 1, p2 - p1 - 1);
                                                                         }
                                                                     }
                                                                 }
                                                                 self->send_real_http_response(path);
                                                             }));
    return true;
}

std::string Session::load_real_index() {
    if (!cfg_.real_index_path.empty()) {
        std::ifstream in(cfg_.real_index_path, std::ios::binary);
        if (in) {
            std::string contents((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            return contents;
        }
    }
    return "<!doctype html><html><head><meta charset=\"utf-8\">"
           "<title>Redirecting...</title>"
           "<meta http-equiv=\"refresh\" content=\"0;url=https://ja.wikipedia.org/wiki/%E5%AE%87%E5%AE%99\">"
           "<script>window.location.replace(\"https://ja.wikipedia.org/wiki/%E5%AE%87%E5%AE%99\");</script>"
           "</head><body>"
           "<noscript><meta http-equiv=\"refresh\" content=\"0;url=https://ja.wikipedia.org/wiki/%E5%AE%87%E5%AE%99\"></noscript>"
           "<p>Redirecting to Wikipedia...</p>"
           "</body></html>";
}

std::string Session::build_hidden_blob() {
#if YUME_USE_BASEFWX
    if (cfg_.real_secret.empty()) {
        return "";
    }
    basefwx::crypto::Bytes salt = basefwx::crypto::RandomBytes(basefwx::constants::kUserKdfSaltSize);
    basefwx::crypto::Bytes key = basefwx::crypto::Pbkdf2HmacSha256(
        cfg_.real_secret,
        salt,
        basefwx::constants::kUserKdfIterations,
        32);
    nlohmann::json meta{
        {"ts", static_cast<long long>(std::time(nullptr))},
        {"sid", static_cast<long long>(session_id_)},
        {"note", "yume-real"}
    };
    std::string meta_str = meta.dump();
    basefwx::crypto::Bytes payload(meta_str.begin(), meta_str.end());
    basefwx::crypto::Bytes aad{'y', 'u', 'm', 'e', '-', 'r', 'e', 'a', 'l'};
    basefwx::crypto::Bytes blob = basefwx::crypto::AeadEncrypt(key, payload, aad);

    basefwx::crypto::Bytes combined;
    combined.reserve(salt.size() + blob.size());
    combined.insert(combined.end(), salt.begin(), salt.end());
    combined.insert(combined.end(), blob.begin(), blob.end());
    std::string b64 = basefwx::base64::Encode(combined);
    return b64;
#else
    return "";
#endif
}

void Session::send_real_http_response(const std::string& path) {
    std::string body;
    std::string status_line = "HTTP/1.1 200 OK\r\n";
    if (path != "/") {
        status_line = "HTTP/1.1 302 Found\r\n";
        body = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Redirect</title></head>"
               "<body>Redirecting to /</body></html>";
    } else {
        body = load_real_index();
    }

    std::string hidden = build_hidden_blob();
    if (!hidden.empty()) {
        body += "<span style=\"display:none\" aria-hidden=\"true\">" + hidden + "</span>";
        body += "<!--" + hidden + "-->";
    }

    std::string headers;
    headers += status_line;
    if (path != "/") {
        headers += "Location: /\r\n";
    }
    headers += "Server: nginx\r\n";
    headers += "Content-Type: text/html; charset=utf-8\r\n";
    headers += "Cache-Control: no-store\r\n";
    if (!hidden.empty()) {
        headers += "X-Yume-Blob: " + hidden + "\r\n";
    }
    headers += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    headers += "Connection: close\r\n\r\n";

    auto resp = std::make_shared<std::string>(headers + body);
    auto self = shared_from_this();
    boost::asio::async_write(stream_, boost::asio::buffer(*resp),
                             boost::asio::bind_executor(strand_,
                                                        [self, resp](const boost::system::error_code&, std::size_t) {
                                                            self->close();
                                                        }));
}

void Session::send_auth_challenge() {
    challenge_ = crypto::random_bytes(32);
    protocol::Frame frame{{static_cast<uint32_t>(challenge_.size()), protocol::AUTH, 0, 0}, challenge_};
    auto self = shared_from_this();
    async_write_frame(frame, [self](const boost::system::error_code& ec, std::size_t) {
        if (ec) {
            self->close();
            return;
        }
        self->read_header();
    });
}

void Session::read_header() {
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
        close();
        return;
    }

    uint32_t len = (static_cast<uint32_t>(header_buf_[0]) << 24) |
                   (static_cast<uint32_t>(header_buf_[1]) << 16) |
                   (static_cast<uint32_t>(header_buf_[2]) << 8) |
                   (static_cast<uint32_t>(header_buf_[3]));

    if (len > kMaxFrameSize) {
        util::log_warn("session " + std::to_string(session_id_) + ": frame too large");
        close();
        return;
    }

    current_header_.len = len;
    current_header_.type = header_buf_[4];
    current_header_.stream_id = header_buf_[5];
    current_header_.flags = static_cast<uint16_t>(header_buf_[6] << 8) |
                            static_cast<uint16_t>(header_buf_[7]);

    payload_buf_.assign(len, 0);
    if (len == 0) {
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
        close();
        return;
    }

    protocol::Frame frame{current_header_, payload_buf_};
    handle_frame(frame);
}

void Session::handle_frame(const protocol::Frame& frame) {
    touch_activity();
    if (!authenticated_) {
        if (frame.header.type != protocol::AUTH) {
            util::log_warn("session " + std::to_string(session_id_) + ": expected AUTH");
            close();
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
                self->close();
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
        anon["hop_enabled"] = cfg_.inner_hop;
        anon["hop_interval_ms"] = cfg_.hop_interval_ms;
        anon["server_time_ms"] = now_ms();
        anon["cap_pq"] = inner::pq_supported();
        anon["cap_argon2"] = inner::argon2_supported();
        anon["cap_pbkdf2"] = inner::pbkdf2_supported();
        std::string payload_str = anon.dump();
        crypto::Bytes payload(payload_str.begin(), payload_str.end());
        protocol::Frame anon_frame{{static_cast<uint32_t>(payload.size()), protocol::ANON, 0, 0}, payload};
        async_write_frame(anon_frame, [self = shared_from_this()](const boost::system::error_code& ec, std::size_t) {
            if (ec) {
                self->close();
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
            close();
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
                handle_close(frame.header.stream_id, "client closed");
            }
            break;
        default:
            util::log_warn("session " + std::to_string(session_id_) + ": unknown frame");
            break;
    }

    read_header();
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
            std::uint64_t candidates[3] = {hop_id, hop_id > 0 ? hop_id - 1 : hop_id, hop_id + 1};
            for (std::size_t i = 0; i < 3; ++i) {
                std::uint64_t id = candidates[i];
                if (i == 1 && hop_id == 0) {
                    continue;
                }
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
    return inner::hop_id_from_time_ms(now_ms(), hop_interval_ms_, hop_offset_ms_);
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
        EVP_PKEY_free(pubkey);

        if (!sig_ok || !auth_ok) {
            if (!sig_ok) {
                auth_error_ = "access denied: bad signature";
            } else {
                auth_error_ = "access denied: invalid key";
            }
            return false;
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
    } catch (const std::exception&) {
        auth_error_ = "access denied: invalid key";
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
    if (streams_.find(frame.header.stream_id) != streams_.end()) {
        send_open_reply(frame.header.stream_id, false, "stream already exists");
        return;
    }

    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        crypto::Bytes decrypted;
        if (decrypt_inner_payload(frame.header.type, frame.header.stream_id, frame.payload, &decrypted)) {
            payload = std::move(decrypted);
        } else {
            util::log_warn("session " + std::to_string(session_id_) + ": OPEN decrypt failed");
            close();
            return;
        }
    }
    std::string payload_str(payload.begin(), payload.end());
    std::string host;
    int port = 0;
    std::string proto;

    try {
        auto json = nlohmann::json::parse(payload_str);
        host = json.value("host", "");
        port = json.value("port", 0);
        proto = json.value("proto", "");
    } catch (const std::exception&) {
        send_open_reply(frame.header.stream_id, false, "invalid OPEN payload");
        return;
    }

    if (host.empty() || port <= 0) {
        send_open_reply(frame.header.stream_id, false, "missing host/port");
        return;
    }
    if (is_blocked_host_literal(host, cfg_)) {
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
        auto udp = std::make_shared<UdpStream>(stream_.get_executor());
        boost::system::error_code open_ec;
        udp->socket.open(boost::asio::ip::udp::v4(), open_ec);
        if (open_ec) {
            send_open_reply(frame.header.stream_id, false, "udp open failed: " + open_ec.message());
            return;
        }
        udp_streams_[frame.header.stream_id] = udp;

        auto self = shared_from_this();
        udp->resolver.async_resolve(boost::asio::ip::udp::v4(), host, std::to_string(port),
                                    boost::asio::bind_executor(strand_,
                                                               [self, stream_id = frame.header.stream_id, udp](const boost::system::error_code& ec,
                                                                                                              const boost::asio::ip::udp::resolver::results_type& results) {
                                                                   if (ec) {
                                                                       self->send_open_reply(stream_id, false, "resolve failed: " + ec.message());
                                                                       self->udp_streams_.erase(stream_id);
                                                                       return;
                                                                   }
                                                                   std::vector<boost::asio::ip::udp::endpoint> allowed;
                                                                   for (const auto& entry : results) {
                                                                       if (is_allowed_address(entry.endpoint().address(), self->cfg_)) {
                                                                           allowed.push_back(entry.endpoint());
                                                                       }
                                                                   }
                                                                   if (allowed.empty()) {
                                                                       self->send_open_reply(stream_id, false, "blocked destination");
                                                                       self->udp_streams_.erase(stream_id);
                                                                       return;
                                                                   }
                                                                   udp->remote = allowed.front();
                                                                   boost::system::error_code ec2;
                                                                   udp->socket.connect(udp->remote, ec2);
                                                                   if (ec2) {
                                                                       self->send_open_reply(stream_id, false, "connect failed: " + ec2.message());
                                                                       self->udp_streams_.erase(stream_id);
                                                                       return;
                                                                   }
                                                                   self->send_open_reply(stream_id, true, "");
                                                                   self->start_udp_read(stream_id);
                                                               }));
        return;
    }

    auto remote = std::make_shared<RemoteStream>(stream_.get_executor());
    boost::system::error_code keep_ec;
    remote->socket.set_option(boost::asio::socket_base::keep_alive(true), keep_ec);
    streams_[frame.header.stream_id] = remote;

    auto self = shared_from_this();
    remote->resolver.async_resolve(boost::asio::ip::tcp::v4(), host, std::to_string(port),
                                   boost::asio::bind_executor(strand_,
                                                              [self, stream_id = frame.header.stream_id, remote](const boost::system::error_code& ec,
                                                                                                                 const boost::asio::ip::tcp::resolver::results_type& results) {
                                                                  if (ec) {
                                                                      self->send_open_reply(stream_id, false, "resolve failed: " + ec.message());
                                                                      self->streams_.erase(stream_id);
                                                                      return;
                                                                  }
                                                                  std::vector<boost::asio::ip::tcp::endpoint> allowed;
                                                                  for (const auto& entry : results) {
                                                                      if (is_allowed_address(entry.endpoint().address(), self->cfg_)) {
                                                                          allowed.push_back(entry.endpoint());
                                                                      }
                                                                  }
                                                                  if (allowed.empty()) {
                                                                      self->send_open_reply(stream_id, false, "blocked destination");
                                                                      self->streams_.erase(stream_id);
                                                                      return;
                                                                  }
                                                                  boost::asio::async_connect(remote->socket, allowed,
                                                                                             boost::asio::bind_executor(self->strand_,
                                                                                                                        [self, stream_id, remote](const boost::system::error_code& ec2,
                                                                                                                                                 const boost::asio::ip::tcp::endpoint&) {
                                                                                                                            if (ec2) {
                                                                                                                                self->send_open_reply(stream_id, false, "connect failed: " + ec2.message());
                                                                                                                                self->streams_.erase(stream_id);
                                                                                                                                return;
                                                                                                                            }
                                                                                                                            self->send_open_reply(stream_id, true, "");
                                                                                                                            self->start_remote_read(stream_id);
                                                                                                                        }));
                                                              }));
}

uint8_t Session::reserve_stream_id() {
    std::lock_guard<std::mutex> lock(control_mutex_);
    for (int i = 1; i < 255; ++i) {
        uint8_t candidate = static_cast<uint8_t>(i);
        if (streams_.find(candidate) == streams_.end() &&
            udp_streams_.find(candidate) == udp_streams_.end() &&
            pending_reverse_.find(candidate) == pending_reverse_.end() &&
            reverse_listeners_.find(candidate) == reverse_listeners_.end() &&
            control_outbound_.find(candidate) == control_outbound_.end() &&
            control_inbound_.find(candidate) == control_inbound_.end()) {
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
            // Client requested a range outside server policy; fall back to server range.
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

void Session::handle_control(const protocol::Frame& frame) {
    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        crypto::Bytes decrypted;
        if (decrypt_inner_payload(protocol::CONTROL, frame.header.stream_id, frame.payload, &decrypted)) {
            payload = std::move(decrypted);
        } else {
            util::log_warn("session " + std::to_string(session_id_) + ": CONTROL decrypt failed");
            return;
        }
    }

    nlohmann::json json;
    try {
        json = nlohmann::json::parse(std::string(payload.begin(), payload.end()));
    } catch (...) {
        util::log_warn("session " + std::to_string(session_id_) + ": invalid CONTROL payload");
        return;
    }

    const std::string cmd = json.value("cmd", "");
    if (cmd == "register") {
        client_hostname_ = json.value("hostname", "");
        client_server_in_charge_ = json.value("server_in_charge", false);
        client_allow_exec_ = json.value("allow_exec", false);
        const std::string reported_ip = json.value("wan_ip", "");
        if (!reported_ip.empty()) {
            client_wan_ip_ = reported_ip;
        }
        if (manager_) {
            ControlledClientInfo info;
            info.id = client_id_;
            info.hostname = client_hostname_;
            info.wan_ip = client_wan_ip_;
            info.allow_exec = client_allow_exec_;
            info.server_in_charge = client_server_in_charge_;
            manager_->register_controlled_client(shared_from_this(), info);
        }
        return;
    }

    auto send_json = [&](const nlohmann::json& resp) {
        std::string out = resp.dump();
        crypto::Bytes bytes(out.begin(), out.end());
        send_control_frame(protocol::CONTROL, frame.header.stream_id, bytes);
    };

    if (cmd == "list") {
        nlohmann::json resp;
        resp["cmd"] = "list";
        resp["clients"] = nlohmann::json::array();
        if (manager_) {
            auto list = manager_->list_controlled_clients(cfg_.anonym);
            for (const auto& info : list) {
                nlohmann::json item;
                item["id"] = info.id;
                item["hostname"] = info.hostname;
                item["wan_ip"] = info.wan_ip;
                item["allow_exec"] = info.allow_exec;
                item["server_in_charge"] = info.server_in_charge;
                resp["clients"].push_back(std::move(item));
            }
        } else {
            resp["error"] = "manager unavailable";
        }
        send_json(resp);
        return;
    }

    if (cmd == "attach") {
        nlohmann::json resp;
        resp["cmd"] = "attach";
        const std::string id = json.value("id", "");
        if (id.empty()) {
            resp["ok"] = false;
            resp["error"] = "missing id";
            send_json(resp);
            return;
        }
        ControlledClientInfo info;
        std::shared_ptr<Session> target;
        if (manager_) {
            target = manager_->find_controlled_session(id, &info);
        }
        if (!target) {
            resp["ok"] = false;
            resp["error"] = "client not found";
            send_json(resp);
            return;
        }
        if (!info.server_in_charge) {
            resp["ok"] = false;
            resp["error"] = "client did not grant server-in-charge";
            send_json(resp);
            return;
        }
        is_controller_ = true;
        control_target_ = target;
        control_target_id_ = id;
        resp["ok"] = true;
        resp["id"] = info.id;
        resp["hostname"] = info.hostname;
        resp["wan_ip"] = info.wan_ip;
        resp["allow_exec"] = info.allow_exec;
        resp["server_in_charge"] = info.server_in_charge;
        send_json(resp);
        return;
    }

    nlohmann::json resp;
    resp["cmd"] = cmd;
    resp["ok"] = false;
    resp["error"] = "unknown control command";
    send_json(resp);
}

bool Session::handle_control_open_request(const protocol::Frame& frame) {
    if (!is_controller_) {
        return false;
    }
    auto target = control_target_.lock();
    if (!target) {
        send_open_reply(frame.header.stream_id, false, "control target unavailable");
        return true;
    }

    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        if (!decrypt_inner_payload(protocol::OPEN, frame.header.stream_id, frame.payload, &payload)) {
            send_open_reply(frame.header.stream_id, false, "control open decrypt failed");
            return true;
        }
    }

    uint8_t target_stream = target->reserve_stream_id();
    if (target_stream == 0) {
        send_open_reply(frame.header.stream_id, false, "no stream ids available");
        return true;
    }

    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        control_outbound_[frame.header.stream_id] = ControlLink{target, target_stream, true, false};
    }
    {
        std::lock_guard<std::mutex> lock(target->control_mutex_);
        target->control_inbound_[target_stream] = ControlLink{shared_from_this(), frame.header.stream_id, true, false};
    }

    target->send_control_frame(protocol::SOPEN, target_stream, payload);
    return true;
}

bool Session::handle_control_open_ack(const protocol::Frame& frame) {
    ControlLink link;
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        auto it = control_inbound_.find(frame.header.stream_id);
        if (it == control_inbound_.end()) {
            return false;
        }
        link = it->second;
    }

    auto peer = link.peer.lock();
    if (!peer) {
        std::lock_guard<std::mutex> lock(control_mutex_);
        control_inbound_.erase(frame.header.stream_id);
        return true;
    }

    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        if (!decrypt_inner_payload(protocol::OPEN, frame.header.stream_id, frame.payload, &payload)) {
            if (auto peer = link.peer.lock()) {
                peer->send_control_close(link.peer_stream_id, "control open decrypt failed");
            }
            std::lock_guard<std::mutex> lock(control_mutex_);
            control_inbound_.erase(frame.header.stream_id);
            return true;
        }
    }
    const bool ok = (frame.header.flags & protocol::kFlagOpenOk) != 0;
    const std::string reason(payload.begin(), payload.end());

    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        auto it = control_inbound_.find(frame.header.stream_id);
        if (it != control_inbound_.end()) {
            if (!ok) {
                control_inbound_.erase(it);
            } else {
                it->second.pending = false;
            }
        }
    }
    {
        std::lock_guard<std::mutex> lock(peer->control_mutex_);
        auto it = peer->control_outbound_.find(link.peer_stream_id);
        if (it != peer->control_outbound_.end()) {
            if (!ok) {
                peer->control_outbound_.erase(it);
            } else {
                it->second.pending = false;
            }
        }
    }

    peer->send_open_reply(link.peer_stream_id, ok, reason);
    return true;
}

bool Session::handle_control_data(const protocol::Frame& frame) {
    ControlLink link;
    bool found = false;
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        auto it = control_outbound_.find(frame.header.stream_id);
        if (it != control_outbound_.end()) {
            link = it->second;
            found = true;
        } else {
            auto it_in = control_inbound_.find(frame.header.stream_id);
            if (it_in != control_inbound_.end()) {
                link = it_in->second;
                found = true;
            }
        }
    }
    if (!found) {
        return false;
    }

    auto peer = link.peer.lock();
    if (!peer) {
        std::lock_guard<std::mutex> lock(control_mutex_);
        control_outbound_.erase(frame.header.stream_id);
        control_inbound_.erase(frame.header.stream_id);
        return true;
    }

    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        if (!decrypt_inner_payload(protocol::DATA, frame.header.stream_id, frame.payload, &payload)) {
            if (auto peer = link.peer.lock()) {
                peer->send_control_close(link.peer_stream_id, "control data decrypt failed");
            }
            std::lock_guard<std::mutex> lock(control_mutex_);
            control_outbound_.erase(frame.header.stream_id);
            control_inbound_.erase(frame.header.stream_id);
            return true;
        }
    }

    peer->send_control_frame(protocol::DATA, link.peer_stream_id, payload);
    return true;
}

bool Session::handle_control_close(const protocol::Frame& frame) {
    ControlLink link;
    bool found = false;
    bool outbound = false;
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        auto it = control_outbound_.find(frame.header.stream_id);
        if (it != control_outbound_.end()) {
            link = it->second;
            found = true;
            outbound = true;
        } else {
            auto it_in = control_inbound_.find(frame.header.stream_id);
            if (it_in != control_inbound_.end()) {
                link = it_in->second;
                found = true;
            }
        }
    }
    if (!found) {
        return false;
    }

    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        if (!decrypt_inner_payload(protocol::CLOSE, frame.header.stream_id, frame.payload, &payload)) {
            payload.clear();
        }
    }
    const std::string reason(payload.begin(), payload.end());

    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        if (outbound) {
            control_outbound_.erase(frame.header.stream_id);
        } else {
            control_inbound_.erase(frame.header.stream_id);
        }
    }
    if (auto peer = link.peer.lock()) {
        peer->send_control_close(link.peer_stream_id, reason);
    }
    return true;
}

bool Session::handle_control_exec(const protocol::Frame& frame) {
    if (!is_controller_) {
        return false;
    }
    auto target = control_target_.lock();
    if (!target) {
        send_control_close(frame.header.stream_id, "control target unavailable");
        return true;
    }
    if (!target->client_allow_exec_) {
        const std::string msg = "EXEC not allowed by client";
        crypto::Bytes payload(msg.begin(), msg.end());
        send_control_frame(protocol::DATA, frame.header.stream_id, payload);
        send_control_close(frame.header.stream_id, "exec denied");
        return true;
    }

    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        if (!decrypt_inner_payload(protocol::EXEC, frame.header.stream_id, frame.payload, &payload)) {
            send_control_close(frame.header.stream_id, "control exec decrypt failed");
            return true;
        }
    }

    uint8_t target_stream = target->reserve_stream_id();
    if (target_stream == 0) {
        send_control_close(frame.header.stream_id, "no stream ids available");
        return true;
    }

    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        control_outbound_[frame.header.stream_id] = ControlLink{target, target_stream, false, true};
    }
    {
        std::lock_guard<std::mutex> lock(target->control_mutex_);
        target->control_inbound_[target_stream] = ControlLink{shared_from_this(), frame.header.stream_id, false, true};
    }

    target->send_control_frame(protocol::EXEC, target_stream, payload);
    return true;
}

void Session::send_control_frame(protocol::FrameType type, uint8_t stream_id, const crypto::Bytes& payload, uint16_t extra_flags) {
    crypto::Bytes out = payload;
    uint16_t flags = extra_flags;
    if (inner_key_.has_value()) {
        out = encrypt_inner_payload(type, stream_id, out);
        flags |= protocol::kFlagInnerEncrypted;
    }
    protocol::Frame frame{{static_cast<uint32_t>(out.size()), type, stream_id, flags}, out};
    async_write_frame(frame);
}

void Session::send_control_close(uint8_t stream_id, const std::string& reason) {
    crypto::Bytes payload(reason.begin(), reason.end());
    send_control_frame(protocol::CLOSE, stream_id, payload);
}

void Session::handle_data(const protocol::Frame& frame) {
    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        if (!decrypt_inner_payload(frame.header.type, frame.header.stream_id, frame.payload, &payload)) {
            util::log_warn("session " + std::to_string(session_id_) + ": DATA decrypt failed");
            close();
            return;
        }
    }
    auto it_udp = udp_streams_.find(frame.header.stream_id);
    if (it_udp != udp_streams_.end()) {
        auto udp = it_udp->second;
        auto buffer = std::make_shared<crypto::Bytes>(std::move(payload));
        auto self = shared_from_this();
        udp->socket.async_send(boost::asio::buffer(*buffer),
                               boost::asio::bind_executor(strand_,
                                                          [self, buffer, stream_id = frame.header.stream_id](const boost::system::error_code& ec, std::size_t) {
                                                              if (ec) {
                                                                  self->handle_close(stream_id, "udp send failed");
                                                                  protocol::Frame close_frame{{0, protocol::CLOSE, stream_id, 0}, {}};
                                                                  self->async_write_frame(close_frame);
                                                              }
                                                          }));
        return;
    }
    enqueue_remote_write(frame.header.stream_id, payload);
}

void Session::handle_close(uint8_t stream_id, const std::string& reason) {
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
        boost::system::error_code ec;
        it_udp->second->socket.close(ec);
        udp_streams_.erase(it_udp);
        return;
    }
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) {
        return;
    }

    util::log_info("session " + std::to_string(session_id_) + ": stream " + std::to_string(stream_id) + " closed: " + reason);
    boost::system::error_code ec;
    it->second->socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    it->second->socket.close(ec);
    streams_.erase(it);
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
    protocol::Frame close_frame{{0, protocol::CLOSE, frame.header.stream_id, 0}, {}};
    async_write_frame(close_frame);
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
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) {
        return;
    }
    auto remote = it->second;
    auto self = shared_from_this();
    remote->socket.async_read_some(boost::asio::buffer(remote->read_buf),
                                   boost::asio::bind_executor(strand_,
                                                              [self, stream_id](const boost::system::error_code& ec, std::size_t bytes) {
                                                                  self->on_remote_read(stream_id, ec, bytes);
                                                              }));
}

void Session::on_remote_read(uint8_t stream_id, const boost::system::error_code& ec, std::size_t bytes) {
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) {
        return;
    }
    if (ec) {
        handle_close(stream_id, "remote closed");
        protocol::Frame close_frame{{0, protocol::CLOSE, stream_id, 0}, {}};
        async_write_frame(close_frame);
        return;
    }

    const auto& buf = it->second->read_buf;
    crypto::Bytes payload(buf.data(), buf.data() + bytes);
    uint16_t flags = 0;
    if (inner_key_.has_value()) {
        payload = encrypt_inner_payload(protocol::DATA, stream_id, payload);
        flags |= protocol::kFlagInnerEncrypted;
    }
    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::DATA, stream_id, flags}, payload};
    async_write_frame(frame);
    start_remote_read(stream_id);
}

void Session::start_udp_read(uint8_t stream_id) {
    auto it = udp_streams_.find(stream_id);
    if (it == udp_streams_.end()) {
        return;
    }
    auto udp = it->second;
    auto self = shared_from_this();
    udp->socket.async_receive(boost::asio::buffer(udp->read_buf),
                              boost::asio::bind_executor(strand_,
                                                         [self, stream_id](const boost::system::error_code& ec, std::size_t bytes) {
                                                             self->on_udp_read(stream_id, ec, bytes);
                                                         }));
}

void Session::on_udp_read(uint8_t stream_id, const boost::system::error_code& ec, std::size_t bytes) {
    auto it = udp_streams_.find(stream_id);
    if (it == udp_streams_.end()) {
        return;
    }
    if (ec) {
        handle_close(stream_id, "udp remote closed");
        protocol::Frame close_frame{{0, protocol::CLOSE, stream_id, 0}, {}};
        async_write_frame(close_frame);
        return;
    }

    const auto& buf = it->second->read_buf;
    crypto::Bytes payload(buf.data(), buf.data() + bytes);
    uint16_t flags = 0;
    if (inner_key_.has_value()) {
        payload = encrypt_inner_payload(protocol::DATA, stream_id, payload);
        flags |= protocol::kFlagInnerEncrypted;
    }
    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::DATA, stream_id, flags}, payload};
    async_write_frame(frame);
    start_udp_read(stream_id);
}

void Session::enqueue_remote_write(uint8_t stream_id, const std::vector<uint8_t>& data) {
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) {
        return;
    }
    auto remote = it->second;
    remote->write_queue.push_back(data);
    if (!remote->write_in_flight) {
        do_remote_write(stream_id);
    }
}

void Session::do_remote_write(uint8_t stream_id) {
    auto it = streams_.find(stream_id);
    if (it == streams_.end()) {
        return;
    }
    auto remote = it->second;
    if (remote->write_queue.empty()) {
        remote->write_in_flight = false;
        return;
    }
    remote->write_in_flight = true;

    auto data = std::move(remote->write_queue.front());
    remote->write_queue.pop_front();
    auto buffer = std::make_shared<std::vector<uint8_t>>(std::move(data));
    auto self = shared_from_this();
    boost::asio::async_write(remote->socket, boost::asio::buffer(*buffer),
                             boost::asio::bind_executor(strand_,
                                                        [self, buffer, stream_id](const boost::system::error_code& ec, std::size_t) {
                                                            if (ec) {
                                                                self->handle_close(stream_id, "remote write failed");
                                                                protocol::Frame close_frame{{0, protocol::CLOSE, stream_id, 0}, {}};
                                                                self->async_write_frame(close_frame);
                                                                return;
                                                            }
                                                            self->do_remote_write(stream_id);
                                                        }));
}

void Session::async_write_frame(const protocol::Frame& frame,
                                std::function<void(const boost::system::error_code&, std::size_t)> handler) {
    auto data = std::make_shared<std::vector<uint8_t>>(protocol::encode_frame(
        static_cast<protocol::FrameType>(frame.header.type),
        frame.header.stream_id,
        frame.header.flags,
        frame.payload));

    boost::asio::post(strand_, [self = shared_from_this(), data, handler = std::move(handler)]() mutable {
        self->write_queue_.push_back({data, std::move(handler)});
        if (!self->write_in_flight_) {
            self->do_write();
        }
    });
}

void Session::do_write() {
    if (write_queue_.empty()) {
        write_in_flight_ = false;
        return;
    }
    write_in_flight_ = true;

    auto& item = write_queue_.front();
    auto self = shared_from_this();
    boost::asio::async_write(stream_, boost::asio::buffer(*item.data),
                             boost::asio::bind_executor(strand_,
                                                        [self](const boost::system::error_code& ec,
                                                               std::size_t bytes) {
                                                            auto item = std::move(self->write_queue_.front());
                                                            self->write_queue_.pop_front();
                                                            if (item.handler) {
                                                                item.handler(ec, bytes);
                                                            }
                                                            if (ec) {
                                                                self->close();
                                                                return;
                                                            }
                                                            self->do_write();
                                                        }));
}

void Session::touch_activity() {
    last_activity_ms_.store(now_ms(), std::memory_order_relaxed);
}

bool Session::is_stale() const {
    const int64_t last = last_activity_ms_.load(std::memory_order_relaxed);
    return last > 0 && (now_ms() - last) > kIdleTimeoutMs;
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
                self->close();
                return;
            }
            self->schedule_idle_check();
        }));
}

void Session::close() {
    boost::system::error_code ec;
    idle_timer_.cancel();
    if (manager_) {
        for (const auto& entry : reverse_listener_ports_) {
            manager_->unregister_reverse_listener(entry.second, this);
        }
        manager_->unregister_controlled_client(this);
    }
    reverse_listener_ports_.clear();
    reverse_port_streams_.clear();

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

    stream_.shutdown(ec);
    stream_.lowest_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    stream_.lowest_layer().close(ec);
}

}  // namespace yume::server
