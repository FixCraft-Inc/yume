/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "server/session.hpp"

#include <openssl/pem.h>

#include <algorithm>
#include <fstream>
#include <chrono>
#include <ctime>
#include <string>

#include "core/inner_crypto.hpp"
#include "core/protocol.hpp"
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
constexpr uint8_t kMaxFrameType = protocol::ANON;

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
        return is_private_ipv4(addr.to_v4());
    }
    return false;
}

bool is_public_address(const boost::asio::ip::address& addr) {
    if (addr.is_v4()) {
        return !is_private_ipv4(addr.to_v4());
    }
    if (addr.is_v6()) {
        return !is_private_ipv6(addr.to_v6());
    }
    return false;
}

bool is_blocked_host_literal(const std::string& host) {
    if (host == "localhost" || host == "localhost.localdomain") {
        return true;
    }
    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address(host, ec);
    if (!ec) {
        return !is_public_address(addr);
    }
    return false;
}

}

Session::Session(boost::asio::ip::tcp::socket socket,
                 boost::asio::ssl::context& ssl_ctx,
                 const ServerConfig& cfg,
                 std::shared_ptr<const std::vector<crypto::Bytes>> authorized_keys,
                 uint64_t session_id)
    : stream_(std::move(socket), ssl_ctx)
    , cfg_(cfg)
    , authorized_keys_(std::move(authorized_keys))
    , session_id_(session_id)
    , strand_(stream_.get_executor())
    , preface_timer_(stream_.get_executor()) {}

void Session::start() {
    auto self = shared_from_this();
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
    return "<!doctype html><html><head><meta charset=\"utf-8\"><title>OK</title></head>"
           "<body><h1>Service Online</h1><p>Welcome.</p></body></html>";
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
    headers += "Content-Type: text/html; charset=utf-8\r\n";
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
    if (!authenticated_) {
        if (frame.header.type != protocol::AUTH) {
            util::log_warn("session " + std::to_string(session_id_) + ": expected AUTH");
            close();
            return;
        }

        if (!handle_auth(frame)) {
            util::log_warn("session " + std::to_string(session_id_) + ": auth failed");
            close();
            return;
        }

        authenticated_ = true;
        if (!cfg_.anonym) {
            util::log_info("session " + std::to_string(session_id_) + ": authenticated");
        }
        nlohmann::json anon = {
            {"mode", cfg_.anonym ? "anonym" : "normal"},
            {"hash", cfg_.anonym_hash},
            {"sig", cfg_.anonym_sig},
            {"ts", cfg_.anonym_ts},
            {"nonce", cfg_.anonym_nonce},
            {"certfp", cfg_.anonym_certfp},
            {"algo", "ed25519"}
        };
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
         frame.header.type == protocol::RLISTEN)) {
        if ((frame.header.flags & protocol::kFlagInnerEncrypted) == 0) {
            util::log_warn("session " + std::to_string(session_id_) + ": missing inner encryption flag");
            close();
            return;
        }
    }

    switch (frame.header.type) {
        case protocol::OPEN:
            handle_open(frame);
            break;
        case protocol::DATA:
            handle_data(frame);
            break;
        case protocol::EXEC: {
            send_open_reply(frame.header.stream_id, false, "EXEC disabled for safety");
            break;
        }
        case protocol::RLISTEN: {
            handle_rlisten(frame);
            break;
        }
        case protocol::CLOSE:
            handle_close(frame.header.stream_id, "client closed");
            break;
        default:
            util::log_warn("session " + std::to_string(session_id_) + ": unknown frame");
            break;
    }

    read_header();
}

bool Session::handle_auth(const protocol::Frame& frame) {
    try {
        size_t offset = 0;
        crypto::Bytes pub_pem = read_field(frame.payload, offset);
        crypto::Bytes sig = read_field(frame.payload, offset);
        std::optional<crypto::Bytes> pq_ciphertext;
        std::optional<crypto::Bytes> pq_salt;
        if (offset < frame.payload.size()) {
            pq_ciphertext = read_field(frame.payload, offset);
        }
        if (offset < frame.payload.size()) {
            pq_salt = read_field(frame.payload, offset);
        }

        BIO* pub_bio = BIO_new_mem_buf(pub_pem.data(), static_cast<int>(pub_pem.size()));
        if (!pub_bio) {
            return false;
        }
        EVP_PKEY* pubkey = PEM_read_bio_PUBKEY(pub_bio, nullptr, nullptr, nullptr);
        BIO_free(pub_bio);
        if (!pubkey) {
            return false;
        }

        bool sig_ok = crypto::verify_key(pubkey, challenge_, sig);
        bool auth_ok = authorized_keys_ ? is_authorized(pubkey, *authorized_keys_) : false;
        std::string fingerprint = fingerprint_pubkey(pubkey);
        EVP_PKEY_free(pubkey);

        if (!sig_ok || !auth_ok) {
            return false;
        }

        if (cfg_.inner_crypto) {
            if (!pq_ciphertext.has_value() || !pq_salt.has_value()) {
                util::log_warn("session " + std::to_string(session_id_) + ": missing PQ ciphertext or salt");
                return false;
            }
            if (pq_salt->empty()) {
                util::log_warn("session " + std::to_string(session_id_) + ": missing PQ salt");
                return false;
            }
            inner::Config inner_cfg;
            inner_cfg.enabled = cfg_.inner_crypto;
            inner_cfg.pq_private_key = cfg_.pq_private_key;
            auto derived = inner::server_derive_key(inner_cfg, *pq_ciphertext, *pq_salt, cfg_.inner_heavy);
            if (!derived.has_value() || derived->empty()) {
                util::log_warn("session " + std::to_string(session_id_) + ": PQ key derivation failed");
                return false;
            }
            inner_key_ = *derived;
        }

        if (!cfg_.anonym) {
            update_auth_meta(cfg_.auth_keys_meta, fingerprint);
        }
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

void Session::handle_open(const protocol::Frame& frame) {
    if (pending_reverse_.find(frame.header.stream_id) != pending_reverse_.end()) {
        bool ok = (frame.header.flags & protocol::kFlagOpenOk) != 0;
        crypto::Bytes payload = frame.payload;
        if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
            try {
                payload = inner::decrypt_payload(*inner_key_, frame.header.type, frame.header.stream_id, frame.payload);
            } catch (...) {
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
        try {
            payload = inner::decrypt_payload(*inner_key_, frame.header.type, frame.header.stream_id, frame.payload);
        } catch (const std::exception& ex) {
            util::log_warn("session " + std::to_string(session_id_) + ": OPEN decrypt failed: " + ex.what());
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
    if (is_blocked_host_literal(host)) {
        send_open_reply(frame.header.stream_id, false, "blocked destination");
        return;
    }

    if (!proto.empty() && proto != "tcp") {
        send_open_reply(frame.header.stream_id, false, "proto not supported");
        return;
    }

    auto remote = std::make_shared<RemoteStream>(stream_.get_executor());
    streams_[frame.header.stream_id] = remote;

    auto self = shared_from_this();
    remote->resolver.async_resolve(host, std::to_string(port),
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
                                                                      if (is_public_address(entry.endpoint().address())) {
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
    for (int i = 1; i < 255; ++i) {
        uint8_t candidate = static_cast<uint8_t>(i);
        if (streams_.find(candidate) == streams_.end() &&
            pending_reverse_.find(candidate) == pending_reverse_.end()) {
            return candidate;
        }
    }
    return 0;
}

void Session::handle_rlisten(const protocol::Frame& frame) {
    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        try {
            payload = inner::decrypt_payload(*inner_key_, frame.header.type, frame.header.stream_id, frame.payload);
        } catch (...) {
            send_open_reply(frame.header.stream_id, false, "RLISTEN decrypt failed");
            return;
        }
    }
    std::string payload_str(payload.begin(), payload.end());
    int listen_port = 0;
    try {
        auto json = nlohmann::json::parse(payload_str);
        listen_port = json.value("port", 0);
    } catch (...) {
        send_open_reply(frame.header.stream_id, false, "invalid RLISTEN payload");
        return;
    }
    if (listen_port <= 0) {
        send_open_reply(frame.header.stream_id, false, "invalid listen port");
        return;
    }
    if (listen_port < 1024) {
        send_open_reply(frame.header.stream_id, false, "listen port must be >= 1024");
        return;
    }
    if (reverse_listeners_.find(frame.header.stream_id) != reverse_listeners_.end()) {
        send_open_reply(frame.header.stream_id, false, "listener exists");
        return;
    }
    auto acceptor = std::make_shared<boost::asio::ip::tcp::acceptor>(stream_.get_executor());
    boost::system::error_code ec;
    boost::asio::ip::tcp::endpoint ep(boost::asio::ip::tcp::v4(), listen_port);
    acceptor->open(ep.protocol(), ec);
    if (ec) {
        send_open_reply(frame.header.stream_id, false, "listen failed: " + ec.message());
        return;
    }
    acceptor->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
    acceptor->bind(ep, ec);
    if (ec) {
        send_open_reply(frame.header.stream_id, false, "bind failed: " + ec.message());
        return;
    }
    acceptor->listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec) {
        send_open_reply(frame.header.stream_id, false, "listen failed: " + ec.message());
        return;
    }
    reverse_listeners_[frame.header.stream_id] = acceptor;
    send_open_reply(frame.header.stream_id, true, "");

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
                    self->streams_[stream_id] = remote;
                    self->pending_reverse_.insert(stream_id);

                    nlohmann::json json{{"listen_id", listen_id}};
                    std::string payload_str = json.dump();
                    std::vector<uint8_t> payload(payload_str.begin(), payload_str.end());
                    uint16_t flags = 0;
                    if (self->inner_key_.has_value()) {
                        payload = inner::encrypt_payload(*self->inner_key_, protocol::ROPEN, stream_id, payload);
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

void Session::handle_data(const protocol::Frame& frame) {
    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        try {
            payload = inner::decrypt_payload(*inner_key_, frame.header.type, frame.header.stream_id, frame.payload);
        } catch (const std::exception& ex) {
            util::log_warn("session " + std::to_string(session_id_) + ": DATA decrypt failed: " + ex.what());
            close();
            return;
        }
    }
    enqueue_remote_write(frame.header.stream_id, payload);
}

void Session::handle_close(uint8_t stream_id, const std::string& reason) {
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
        payload = inner::encrypt_payload(*inner_key_, protocol::DATA, frame.header.stream_id, payload);
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
        payload = inner::encrypt_payload(*inner_key_, protocol::OPEN, stream_id, payload);
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
        payload = inner::encrypt_payload(*inner_key_, protocol::DATA, stream_id, payload);
        flags |= protocol::kFlagInnerEncrypted;
    }
    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::DATA, stream_id, flags}, payload};
    async_write_frame(frame);
    start_remote_read(stream_id);
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

void Session::close() {
    for (auto& entry : streams_) {
        boost::system::error_code ec;
        entry.second->socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        entry.second->socket.close(ec);
    }
    streams_.clear();

    boost::system::error_code ec;
    stream_.shutdown(ec);
    stream_.lowest_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    stream_.lowest_layer().close(ec);
}

}  // namespace yume::server
