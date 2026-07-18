/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * ----------------------------------------------------------------
 * Session carrier / disguise methods, extracted verbatim from
 * session.cpp. Implements the HTTP/2 stealth carrier: the TLS preface
 * read, HTTP-probe disguise responses (404 / real-index / robots.txt),
 * and the H2 carrier handshake probe that precedes YUME auth.
 *
 * Same Session:: class, same signatures, same wire output. No behavior
 * change. Shared helpers come from server/session/internal.hpp.
 * ---------------------------------------------------------------- */

#include "server/session/session.hpp"
#include "server/runtime/manager.hpp"
#include "server/session/internal.hpp"
#include "server/host/host_routes.hpp"
#include "server/host/http_proxy.hpp"
#include "core/app_codec/codec.hpp"

namespace yume::server {

using namespace detail;

void Session::start_preface_read() {
    preface_accum_.clear();
    preface_received_ = false;
    preface_probe_active_ = true;
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
            close_with_reason("preface read failed: " + ec.message());
        }
        return;
    }
    if (!preface_probe_active_) {
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
        preface_probe_active_ = false;
        return;
    }

    if (preface_accum_.size() < header_buf_.size()) {
        auto self = shared_from_this();
        preface_timer_.expires_after(std::chrono::milliseconds(200));
        preface_timer_.async_wait(boost::asio::bind_executor(
            strand_, [self](const boost::system::error_code& timer_ec) {
                self->on_preface_timeout(timer_ec);
            }));
        stream_.async_read_some(boost::asio::buffer(preface_buf_),
                                boost::asio::bind_executor(strand_,
                                                           [self](const boost::system::error_code& e, std::size_t n) {
                                                               self->on_preface_read(e, n);
                                                           }));
        return;
    }

    // In obfs mode, only the validated H2 opening exchange may cross into the
    // YUME AUTH path. A raw frame-shaped prefix is an active probe and remains
    // entirely inside the configured masquerade response behavior.
    if (cfg_.obfuscation) {
        preface_probe_active_ = false;
        if (obfs::selected_alpn(stream_.native_handle()) == "h2") {
            serve_fake_h2_real_index();
        } else if (cfg_.real_http) {
            send_real_http_response("/");
        } else {
            send_disguise_404("/");
        }
        return;
    }

    uint32_t len = (static_cast<uint32_t>(preface_accum_[0]) << 24) |
                   (static_cast<uint32_t>(preface_accum_[1]) << 16) |
                   (static_cast<uint32_t>(preface_accum_[2]) << 8) |
                   (static_cast<uint32_t>(preface_accum_[3]));
    uint8_t type = preface_accum_[4];
    bool header_ok = len <= kMaxFrameSize && type >= kMinFrameType && type <= kMaxFrameType;
    if (!header_ok) {
        // Non-yume preface. With --real, serve the disguise root page
        // so probers see a styled redirect (the cover site). Otherwise
        // serve a profile-matching 404 — anything is less of a DPI
        // signal than a TLS-handshake-then-immediate-close (which the
        // pre-1.0 close path used to leak).
        preface_probe_active_ = false;
        if (cfg_.real_http) {
            send_real_http_response("/");
        } else {
            send_disguise_404("/");
        }
        return;
    }

    std::copy(preface_accum_.begin(), preface_accum_.begin() + header_buf_.size(), header_buf_.begin());
    preface_probe_active_ = false;
    if (!cfg_.accept_yume_clients) {
        send_disguise_404("/");
        return;
    }
    header_prefetched_ = true;
    read_header();
}

void Session::on_preface_timeout(const boost::system::error_code& ec) {
    if (ec == boost::asio::error::operation_aborted) {
        return;
    }
    if (preface_probe_active_) {
        preface_probe_active_ = false;
        boost::system::error_code cancel_ec;
        stream_.lowest_layer().cancel(cancel_ec);
        if (preface_received_) {
            // A partial/malformed opening never falls through to AUTH. Return
            // the same cover behavior as other active probes, then close.
            if (cfg_.obfuscation &&
                obfs::selected_alpn(stream_.native_handle()) == "h2") {
                serve_fake_h2_real_index();
            } else if (cfg_.real_http) {
                send_real_http_response("/");
            } else {
                send_disguise_404("/");
            }
            return;
        }
        // When ANY stealth mode is enabled, we must NEVER send the
        // AUTH challenge to a connection that hasn't proven it's a
        // Yume client by sending a recognised preface. Browsers
        // routinely hold idle pooled TLS connections open for tens of
        // seconds without sending a request — the previous behaviour
        // dropped the AUTH challenge (containing the very obvious
        // `{"challenge_meta":1,"argon2_mem_max":...}` JSON) into
        // those idle sockets, making the server trivially
        // fingerprintable to anyone who opened the IP in a browser.
        // The fix: in stealth modes, idle-with-no-preface ==
        // "probably not a yume client" → close silently. A real
        // yume client either sends the h2 carrier handshake (obfs
        // on) or the raw AUTH header (no obfs, no stealth), both
        // arrive well under the 200 ms preface timer.
        if (cfg_.real_http || cfg_.robots_deny || cfg_.obfuscation || !cfg_.http_profile.empty()
            || !cfg_.upstream_response_bytes.empty()
            || !cfg_.upstream_response_dir.empty()
            || !cfg_.accept_yume_clients) {
            close_with_reason("preface timeout (stealth mode): no recognised preface received");
            return;
        }
        send_auth_challenge();
    }
}
bool Session::handle_http_preface(const std::string& preface) {
    if (cfg_.obfuscation && preface.rfind("PRI * HT", 0) == 0) {
        if (!cfg_.accept_yume_clients) {
            if (obfs::selected_alpn(stream_.native_handle()) == "h2") {
                serve_fake_h2_real_index();
            } else if (cfg_.real_http) {
                send_real_http_response("/");
            } else {
                send_disguise_404("/");
            }
            return true;
        }
        const std::string negotiated = obfs::selected_alpn(stream_.native_handle());
        if (negotiated != "h2") {
            if (cfg_.real_http) {
                send_real_http_response("/");
            } else {
                send_disguise_404("/");
            }
            return true;
        }
        start_h2_carrier_probe();
        return true;
    }

    const std::string methods[] = {"GET ", "HEAD ", "POST ", "OPTIONS ", "PUT ", "DELETE ", "TRACE ", "PATCH ", "CONNECT "};
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
    boost::asio::async_read_until(stream_,
                                  boost::asio::dynamic_buffer(*request,
                                                              yume::app_codec::kMaxHttpHeaderBytes + 1),
                                  "\r\n\r\n",
                                  boost::asio::bind_executor(strand_,
                                                             [self, request](const boost::system::error_code& e, std::size_t) {
                                                                 if (e || request->size() > yume::app_codec::kMaxHttpHeaderBytes) {
                                                                     self->close_with_reason(
                                                                         e ? "HTTP preface read failed: " + e.message()
                                                                           : "HTTP preface read failed: headers too large");
                                                                     return;
                                                                 }
                                                                 std::string line;
                                                                 auto pos = request->find("\r\n");
                                                                 if (pos != std::string::npos) {
                                                                     line = request->substr(0, pos);
                                                                 }
                                                                 std::string method;
                                                                 std::string target = "/";
                                                                 if (!line.empty()) {
                                                                     auto p1 = line.find(' ');
                                                                     if (p1 != std::string::npos) {
                                                                         method = line.substr(0, p1);
                                                                         auto p2 = line.find(' ', p1 + 1);
                                                                         if (p2 != std::string::npos && p2 > p1 + 1) {
                                                                             target = line.substr(p1 + 1, p2 - p1 - 1);
                                                                         }
                                                                     }
                                                                 }

                                                                 std::string path = target;
                                                                 if (self->cfg_.host_mode != host::HostMode::Off &&
                                                                     self->manager_ &&
                                                                     !self->manager_->host_routes().empty()) {
                                                                     const std::string sni = host::tls_sni(self->stream_.native_handle());
                                                                     const std::string host_header = host::http_header_value(*request, "Host");
                                                                     auto host_only = host_header;
                                                                     const auto colon = host_only.find(':');
                                                                     if (colon != std::string::npos) {
                                                                         host_only = host_only.substr(0, colon);
                                                                     }
                                                                     auto match = self->manager_->host_routes().match(sni, host_only, path);
                                                                     if (match.has_value()) {
                                                                         auto backend = host::parse_loopback_backend(match->route->backend);
                                                                         if (backend.has_value()) {
                                                                             auto handoff = self->release_for_host_proxy();
                                                                             if (handoff.has_value()) {
                                                                                 host::start_http_reverse_proxy(
                                                                                     std::move(*handoff),
                                                                                     std::move(*request),
                                                                                     backend->first,
                                                                                     backend->second,
                                                                                     self->manager_);
                                                                             }
                                                                             return;
                                                                         }
                                                                     }
                                                                 }
                                                                 if (self->cfg_.robots_deny &&
                                                                     path == "/robots.txt" &&
                                                                     (method == "GET" || method == "HEAD")) {
                                                                     self->send_robots_txt_response(method == "HEAD");
                                                                     return;
                                                                 }
                                                                 if (self->cfg_.real_http) {
                                                                     self->send_real_http_response(path);
                                                                 } else {
                                                                     // Pre-1.0 this path closed immediately, which is a
                                                                     // strong DPI signal. Serve a profile-driven 404 so
                                                                     // the probe sees what looks like a real web server
                                                                     // with nothing at that path.
                                                                     self->send_disguise_404(path);
                                                                 }
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

void Session::send_disguise_404(const std::string& path) {
    (void)path;  // not echoed back; logged only as the connection close reason
    // Resolution order, strongest disguise first:
    //   1. --upstream-response-dir <dir> (rotation): pick one of N
    //      pre-captured replies. Defeats "probe twice, both replies
    //      identical" inspection.
    //   2. --upstream-response <file>: single normalized captured replay.
    //   3. profile-driven synthetic 404 (--hide-in-the-crowd / yumed).
    std::shared_ptr<std::string> resp;
    std::string reason;
    std::string rotated;
    if (manager_) {
        rotated = manager_->upstream_response_pick();
    }
    if (!rotated.empty()) {
        resp = std::make_shared<std::string>(std::move(rotated));
        reason = "served upstream-response replay (rotated)";
    } else if (!cfg_.upstream_response_bytes.empty()) {
        resp = std::make_shared<std::string>(cfg_.upstream_response_bytes);
        reason = "served upstream-response replay";
    } else {
        auto profile = yume::http_profile::server(
            cfg_.http_profile.empty() ? "yumed" : cfg_.http_profile);
        if (!profile.has_value()) {
            profile = yume::http_profile::server("yumed");
        }
        resp = std::make_shared<std::string>(
            yume::http_profile::render_404(*profile, /*connection_close=*/true));
        reason = "served disguise 404";
    }
    auto self = shared_from_this();
    boost::asio::async_write(stream_, boost::asio::buffer(*resp),
                             boost::asio::bind_executor(strand_,
                                                        [self, resp, reason](const boost::system::error_code&, std::size_t) {
                                                            self->close_with_reason(reason);
                                                        }));
}

void Session::send_real_http_response(const std::string& path) {
    if (cfg_.robots_deny && path == "/robots.txt") {
        send_robots_txt_response(false);
        return;
    }
    // Non-`/` paths get an nginx-style 404 via the same disguise
    // pipeline that --hide-in-the-crowd uses without --real. The
    // previous behaviour (302 Location: / on every unknown path)
    // was a soft fingerprint: a real nginx returns 404 for
    // /random-path, not "Redirecting to /". The 302-everywhere
    // pattern is recognisable to any prober that GETs more than
    // one URL on the same TLS connection.
    if (path != "/") {
        send_disguise_404(path);
        return;
    }
    std::string body = load_real_index();
    std::string status_line = "HTTP/1.1 200 OK\r\n";

    std::string hidden = build_hidden_blob();
    if (!hidden.empty()) {
        // Hidden blob stays in the body (zero-width <span> + HTML
        // comment) — both are picked up by clients that parse the
        // body. The previous X-Yume-Blob response header was dropped
        // in 1.0: it had no in-tree consumers and the "Yume" substring
        // was a passive fingerprint for any layer-7 inspector reading
        // headers.
        body += "<span style=\"display:none\" aria-hidden=\"true\">" + hidden + "</span>";
        body += "<!--" + hidden + "-->";
    }

    // Disguise headers come from yume::http_profile. The default
    // profile (empty config => "yumed") preserves pre-1.0 behavior;
    // operators who pass --hide-in-the-crowd <profile> get the
    // selected disguise. --public-node forces "nginx" if no profile
    // is set explicitly.
    auto profile = yume::http_profile::server(
        cfg_.http_profile.empty() ? "yumed" : cfg_.http_profile);
    if (!profile.has_value()) {
        // Validation runs at startup, so reaching here means an
        // operator hot-edited the config; fall back to yumed.
        profile = yume::http_profile::server("yumed");
    }

    std::string headers;
    headers += status_line;
    if (!profile->server_header_value.empty()) {
        headers += "Server: " + profile->server_header_value + "\r\n";
    }
    if (!profile->extra_response_headers.empty()) {
        headers += profile->extra_response_headers;
    }
    headers += "Content-Type: text/html; charset=utf-8\r\n";
    headers += "Cache-Control: no-store\r\n";
    headers += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    headers += "Connection: close\r\n\r\n";

    auto resp = std::make_shared<std::string>(headers + body);
    auto self = shared_from_this();
    boost::asio::async_write(stream_, boost::asio::buffer(*resp),
                             boost::asio::bind_executor(strand_,
                                                        [self, resp](const boost::system::error_code&, std::size_t) {
                                                            self->close_with_reason("served HTTP disguise response");
                                                        }));
}

void Session::send_robots_txt_response(bool head_only) {
    const std::string body = "User-agent: *\nDisallow: /\n";
    auto profile = yume::http_profile::server(
        cfg_.http_profile.empty() ? "yumed" : cfg_.http_profile);
    if (!profile.has_value()) {
        profile = yume::http_profile::server("yumed");
    }

    std::string headers;
    headers += "HTTP/1.1 200 OK\r\n";
    if (profile.has_value() && !profile->server_header_value.empty()) {
        headers += "Server: " + profile->server_header_value + "\r\n";
    }
    if (profile.has_value() && !profile->extra_response_headers.empty()) {
        headers += profile->extra_response_headers;
    }
    headers += "Content-Type: text/plain; charset=utf-8\r\n";
    headers += "Cache-Control: no-store\r\n";
    headers += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    headers += "Connection: close\r\n\r\n";

    auto resp = std::make_shared<std::string>(head_only ? headers : headers + body);
    auto self = shared_from_this();
    boost::asio::async_write(stream_, boost::asio::buffer(*resp),
                             boost::asio::bind_executor(strand_,
                                                        [self, resp](const boost::system::error_code&, std::size_t) {
                                                            self->close_with_reason("served robots.txt");
                                                        }));
}

void Session::start_h2_carrier_probe() {
    carrier_probe_active_ = true;
    carrier_decoder_ = std::make_unique<obfs::H2InboundDecoder>(true);
    if (!preface_accum_.empty()) {
        carrier_decoder_->feed(preface_accum_.data(), preface_accum_.size());
        preface_accum_.clear();
    }
    auto self = shared_from_this();
    preface_timer_.expires_after(std::chrono::milliseconds(200));
    preface_timer_.async_wait(boost::asio::bind_executor(
        strand_, [self](const boost::system::error_code& ec) {
            if (ec || !self->carrier_probe_active_) {
                return;
            }
            self->carrier_probe_active_ = false;
            boost::system::error_code cancel_ec;
            self->stream_.lowest_layer().cancel(cancel_ec);
            self->serve_fake_h2_real_index();
        }));
    stream_.async_read_some(
        boost::asio::buffer(carrier_scratch_),
        boost::asio::bind_executor(strand_,
                                   [self](const boost::system::error_code& ec, std::size_t bytes) {
                                       self->on_h2_probe_read(ec, bytes);
                                   }));
}

void Session::on_h2_probe_read(const boost::system::error_code& ec, std::size_t bytes) {
    if (ec) {
        if (ec == boost::asio::error::operation_aborted) {
            return;
        }
        close_with_reason("h2 carrier probe read failed: " + ec.message());
        return;
    }
    if (!carrier_probe_active_ || !carrier_decoder_) {
        return;
    }
    if (bytes > 0) {
        carrier_decoder_->feed(carrier_scratch_.data(), bytes);
    }
    if (carrier_decoder_->failed()) {
        util::log_warn("session " + std::to_string(session_id_) +
                       ": h2 carrier decode rejected; serving masquerade response: " +
                       carrier_decoder_->error());
        carrier_probe_active_ = false;
        preface_timer_.cancel();
        serve_fake_h2_real_index();
        return;
    }

    if (carrier_decoder_->headers_seen()) {
        if (!carrier_decoder_->headers_end_stream()) {
            util::log_warn("session " + std::to_string(session_id_) +
                           ": h2 carrier request did not end stream; serving masquerade response");
            carrier_probe_active_ = false;
            preface_timer_.cancel();
            serve_fake_h2_real_index();
            return;
        }
        std::string path = carrier_decoder_->extracted_path();
        std::string authority = carrier_decoder_->extracted_authority();
        const std::string tls_sni = host::tls_sni(stream_.native_handle());
        std::optional<std::uint16_t> listener_port;
        boost::system::error_code endpoint_ec;
        const auto local_endpoint = stream_.lowest_layer().local_endpoint(endpoint_ec);
        if (!endpoint_ec && local_endpoint.port() > 0) {
            listener_port = local_endpoint.port();
        }
        std::int64_t now_s = static_cast<std::int64_t>(std::time(nullptr));
        const bool authority_ok =
            obfs::authority_matches_tls_sni(authority, tls_sni, listener_port);
        const bool token_ok = obfs::carrier_path_admitted(
            cfg_.obfs_secret, authority, tls_sni, path, now_s, listener_port);
        carrier_probe_active_ = false;
        preface_timer_.cancel();

        if (!token_ok) {
            std::string sanitized;
            sanitized.reserve(path.size());
            for (unsigned char c : path) {
                sanitized.push_back((c >= 0x20 && c < 0x7f) ? static_cast<char>(c) : '?');
            }
            util::log_warn("session " + std::to_string(session_id_) +
                          ": h2 carrier path token rejected (size=" +
                          std::to_string(path.size()) + ", authority_sni=" +
                          (authority_ok ? std::string("match") : std::string("mismatch")) +
                          ", path=" + sanitized + ")");
            serve_fake_h2_real_index();
            return;
        }

        send_h2_server_handshake_then_continue();
        return;
    }

    if (carrier_decoder_->inbound_buffered() > 32768) {
        close_with_reason("h2 carrier handshake too large");
        return;
    }

    auto self = shared_from_this();
    stream_.async_read_some(
        boost::asio::buffer(carrier_scratch_),
        boost::asio::bind_executor(strand_,
                                   [self](const boost::system::error_code& e, std::size_t n) {
                                       self->on_h2_probe_read(e, n);
                                   }));
}

void Session::send_h2_server_handshake_then_continue() {
    if (!cfg_.accept_yume_clients) {
        serve_fake_h2_real_index();
        return;
    }
    obfs::H2ResponseSpec accepted;
    accepted.status = 200;
    accepted.headers.emplace_back("content-type", "application/grpc-web+proto");
    auto profile = yume::http_profile::server(
        cfg_.http_profile.empty() ? "yumed" : cfg_.http_profile);
    if (profile.has_value() && !profile->server_header_value.empty()) {
        accepted.headers.emplace_back("server", profile->server_header_value);
    }

    crypto::Bytes combined = obfs::encode_server_settings();
    if (carrier_decoder_) {
        crypto::Bytes replies = carrier_decoder_->take_outbound_replies();
        combined.insert(combined.end(), replies.begin(), replies.end());
    }
    crypto::Bytes headers = obfs::encode_response_headers(
        accepted, std::nullopt, false);
    combined.insert(combined.end(), headers.begin(), headers.end());

    auto data = std::make_shared<std::vector<uint8_t>>(std::move(combined));
    const auto payload_size = data->size();
    queue_encoded_write_on_strand(
        std::move(data), protocol::CONTROL, 0, payload_size,
        [self = shared_from_this()](const boost::system::error_code& ec, std::size_t) {
            if (ec) {
                self->close_with_reason("h2 carrier response write failed: " + ec.message());
                return;
            }
            self->start_h2_settings_ack_wait();
        });
}

void Session::start_h2_settings_ack_wait() {
    if (!carrier_decoder_) {
        close_with_reason("h2 carrier decoder unavailable after response");
        return;
    }
    carrier_decoder_->mark_carrier_active();
    if (carrier_decoder_->failed()) {
        close_with_reason("h2 carrier post-headers decode failed: " +
                          carrier_decoder_->error());
        return;
    }
    if (carrier_decoder_->peer_settings_ack_seen()) {
        finish_h2_settings_ack_wait();
        return;
    }

    carrier_settings_ack_wait_active_ = true;
    preface_timer_.expires_after(std::chrono::milliseconds(250));
    preface_timer_.async_wait(boost::asio::bind_executor(
        strand_, [self = shared_from_this()](const boost::system::error_code& ec) {
            if (ec || !self->carrier_settings_ack_wait_active_) return;
            self->carrier_settings_ack_wait_active_ = false;
            boost::system::error_code cancel_ec;
            self->stream_.lowest_layer().cancel(cancel_ec);
            self->close_with_reason("h2 SETTINGS ACK timeout");
        }));
    stream_.async_read_some(
        boost::asio::buffer(carrier_scratch_),
        boost::asio::bind_executor(
            strand_, [self = shared_from_this()](const boost::system::error_code& ec,
                                                  std::size_t bytes) {
                self->on_h2_settings_ack_read(ec, bytes);
            }));
}

void Session::on_h2_settings_ack_read(const boost::system::error_code& ec,
                                      std::size_t bytes) {
    if (!carrier_settings_ack_wait_active_) return;
    if (ec) {
        if (ec == boost::asio::error::operation_aborted) return;
        close_with_reason("h2 SETTINGS ACK read failed: " + ec.message());
        return;
    }
    if (bytes > 0 && carrier_decoder_) {
        carrier_decoder_->feed(carrier_scratch_.data(), bytes);
    }
    if (!carrier_decoder_ || carrier_decoder_->failed()) {
        close_with_reason("h2 SETTINGS ACK decode failed" +
                          (carrier_decoder_ ? ": " + carrier_decoder_->error()
                                            : std::string{}));
        return;
    }
    if (carrier_decoder_->peer_settings_ack_seen()) {
        finish_h2_settings_ack_wait();
        return;
    }
    stream_.async_read_some(
        boost::asio::buffer(carrier_scratch_),
        boost::asio::bind_executor(
            strand_, [self = shared_from_this()](const boost::system::error_code& read_ec,
                                                  std::size_t read_bytes) {
                self->on_h2_settings_ack_read(read_ec, read_bytes);
            }));
}

void Session::finish_h2_settings_ack_wait() {
    carrier_settings_ack_wait_active_ = false;
    preface_timer_.cancel();
    carrier_decoder_.reset();
    util::log_info("session " + std::to_string(session_id_) +
                   ": h2 carrier admission accepted");
    send_auth_challenge();
}

void Session::serve_fake_h2_real_index() {
    obfs::H2ResponseSpec response;
    bool have_response = false;

    std::string upstream;
    if (manager_) {
        upstream = manager_->upstream_response_pick();
    }
    if (upstream.empty()) {
        upstream = cfg_.upstream_response_bytes;
    }
    if (!upstream.empty()) {
        auto parsed = obfs::parse_http1_response_for_h2(upstream);
        if (parsed.has_value()) {
            response = std::move(*parsed);
            have_response = true;
        } else {
            util::log_warn("session " + std::to_string(session_id_) +
                           ": configured upstream response could not be converted to h2; using profile fallback");
        }
    }

    auto profile = yume::http_profile::server(
        cfg_.http_profile.empty() ? "yumed" : cfg_.http_profile);
    if (!profile.has_value()) {
        profile = yume::http_profile::server("yumed");
    }

    if (!have_response && cfg_.real_http) {
        std::string body = load_real_index();
        const std::string hidden = build_hidden_blob();
        if (!hidden.empty()) {
            body += "<span style=\"display:none\" aria-hidden=\"true\">" + hidden + "</span>";
            body += "<!--" + hidden + "-->";
        }
        std::string http1 = "HTTP/1.1 200 OK\r\n";
        if (profile.has_value() && !profile->server_header_value.empty()) {
            http1 += "Server: " + profile->server_header_value + "\r\n";
        }
        if (profile.has_value()) {
            http1 += profile->extra_response_headers;
        }
        http1 += "Content-Type: text/html; charset=utf-8\r\n";
        http1 += "Cache-Control: no-store\r\n";
        http1 += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
        http1 += body;
        auto parsed = obfs::parse_http1_response_for_h2(http1);
        if (parsed.has_value()) {
            response = std::move(*parsed);
            have_response = true;
        }
    }

    if (!have_response && profile.has_value()) {
        auto parsed = obfs::parse_http1_response_for_h2(
            yume::http_profile::render_404(*profile, /*connection_close=*/true));
        if (parsed.has_value()) {
            response = std::move(*parsed);
            have_response = true;
        }
    }
    if (!have_response) {
        response.status = 404;
        response.headers.emplace_back("content-type", "text/html; charset=utf-8");
        response.body.assign({'N', 'o', 't', ' ', 'F', 'o', 'u', 'n', 'd', '\n'});
    }

    obfs::H2EncodeParams params;
    params.padding_mean = 0;
    params.padding_max = 0;
    params.end_stream = true;
    // Honour the peer's SETTINGS_MAX_FRAME_SIZE so a stateful H2
    // middlebox doesn't see a DATA frame oversize relative to what
    // the client advertised. Fall back to the protocol default
    // (16384) when no peer SETTINGS were seen (e.g. when we never
    // got into the carrier decoder for this connection).
    if (carrier_decoder_ && carrier_decoder_->peer_settings_seen()) {
        params.max_data_payload = carrier_decoder_->peer_max_frame_size();
    }
    // Honour the peer's flow-control budget: the lesser of the conn-
    // level and per-stream send window the peer has granted us. If a
    // peer advertised a small INITIAL_WINDOW_SIZE we'd otherwise
    // emit DATA exceeding it, which a fully-conformant H2 middlebox
    // flags as a flow-control protocol error. Clamp to non-negative
    // — a negative window means "wait for WINDOW_UPDATE", which we
    // can't here because we close right after, so we just don't send
    // any DATA past the budget (the response gets truncated, the
    // browser sees the headers and the truncated body which is
    // still less suspicious than an over-window emit).
    if (carrier_decoder_) {
        const std::int64_t conn   = carrier_decoder_->conn_send_window();
        const std::int64_t stream = carrier_decoder_->stream_send_window(1);
        const std::int64_t budget = std::max<std::int64_t>(0, std::min(conn, stream));
        if (budget < static_cast<std::int64_t>(0xFFFFFFFFu)) {
            params.send_window = static_cast<std::uint32_t>(budget);
        }
    }
    const std::size_t body_size = std::min<std::size_t>(
        response.body.size(), params.send_window);
    response.body.resize(body_size);
    crypto::Bytes headers = obfs::encode_response_headers(
        response, response.body.size(), response.body.empty());
    crypto::Bytes data_frames;
    if (!response.body.empty()) {
        data_frames = obfs::encode_data_frames(
            response.body.data(), response.body.size(), params);
    }
    if (carrier_decoder_) {
        // Account for what we just emitted so any subsequent emit on
        // this decoder (none today, but kept for hygiene) sees the
        // updated windows.
        const std::size_t emitted = response.body.size();
        carrier_decoder_->on_local_data_sent(1, static_cast<std::uint32_t>(emitted));
    }
    crypto::Bytes settings = obfs::encode_server_settings();
    crypto::Bytes replies;
    if (carrier_decoder_) {
        replies = carrier_decoder_->take_outbound_replies();
    }
    std::vector<uint8_t> combined;
    combined.reserve(settings.size() + replies.size() + headers.size() + data_frames.size());
    combined.insert(combined.end(), settings.begin(), settings.end());
    combined.insert(combined.end(), replies.begin(), replies.end());
    combined.insert(combined.end(), headers.begin(), headers.end());
    combined.insert(combined.end(), data_frames.begin(), data_frames.end());
    auto buf = std::make_shared<std::vector<uint8_t>>(std::move(combined));
    const auto payload_size = buf->size();
    queue_encoded_write_on_strand(
        std::move(buf), protocol::CONTROL, 0, payload_size,
        [self = shared_from_this()](const boost::system::error_code&, std::size_t) {
            self->carrier_decoder_.reset();
            self->close_with_reason("served h2 masquerade response to non-yume probe");
        });
}

}  // namespace yume::server
