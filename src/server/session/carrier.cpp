/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * Session carrier / disguise methods. Implements the HTTP/2 stealth carrier:
 * the TLS preface
 * read, HTTP-probe disguise responses (404 / real-index / robots.txt),
 * and the H2 carrier handshake probe that precedes YUME auth.
 */

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <filesystem>
#include <limits>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

#include <boost/beast/http/status.hpp>

#include "server/session/session.hpp"
#include "core/runtime/bounded_file.hpp"
#include "core/security/secure_erase.hpp"
#include "server/runtime/cover_response.hpp"
#include "server/runtime/manager.hpp"
#include "server/session/internal.hpp"
#include "server/host/host_routes.hpp"
#include "server/host/http_proxy.hpp"
#include "server/host/http_backend_client.hpp"
#include "server/session/static_site.hpp"
#include "server/session/http_masq.hpp"
#include "core/app_codec/codec.hpp"
#include "core/stealth/http_profile.hpp"

namespace yume::server {

using namespace detail;

namespace {
// Keep-alive bounds for the masquerade responder. A real nginx keeps the
// connection open across a page's assets; these cap how long/how many so a
// decoy connection cannot be held open indefinitely.
constexpr int kMaxKeepAliveRequests = 100;
constexpr int kKeepAliveIdleMs = 10000;

// Whether a parsed request carries a message body we would have to consume to
// stay framed. Keep-alive is refused for these (see http_masq). Conservative:
// any nonzero Content-Length digit or a Transfer-Encoding counts as a body.
bool request_has_message_body(const std::string& headers) {
    if (!host::http_header_value(headers, "Transfer-Encoding").empty()) {
        return true;
    }
    const std::string cl = host::http_header_value(headers, "Content-Length");
    for (char c : cl) {
        if (c >= '1' && c <= '9') return true;
    }
    return false;
}

std::string backend_status_line(unsigned status) {
    if (status < 100 || status > 599) status = 502;
    const auto reason = boost::beast::http::obsolete_reason(
        static_cast<boost::beast::http::status>(status));
    return "HTTP/1.1 " + std::to_string(status) + " " +
           std::string(reason.data(), reason.size()) + "\r\n";
}

std::shared_ptr<std::string> render_backend_h1_response(
    host::BackendHttpResponse response,
    bool head_only,
    bool keep_alive) {
    auto wire = std::make_shared<std::string>();
    wire->reserve(response.body.size() + 1024);
    *wire += backend_status_line(response.status);
    bool content_length_seen = false;
    for (const auto& [name, value] : response.headers) {
        if (name.empty() || name.front() == ':' ||
            name.find_first_of("\r\n") != std::string::npos ||
            value.find_first_of("\r\n") != std::string::npos) {
            continue;
        }
        if (name == "connection") continue;
        if (name == "content-length") content_length_seen = true;
        *wire += name + ": " + value + "\r\n";
    }
    if (!content_length_seen) {
        *wire += "content-length: " + std::to_string(response.body.size()) +
                 "\r\n";
    }
    *wire += keep_alive ? "connection: keep-alive\r\n\r\n"
                        : "connection: close\r\n\r\n";
    if (!head_only) {
        wire->append(reinterpret_cast<const char*>(response.body.data()),
                     response.body.size());
    }
    return wire;
}

host::BackendHttpResponse node_gateway_failure() {
    host::BackendHttpResponse response;
    response.status = 502;
    response.headers = {
        {"content-type", "text/plain; charset=utf-8"},
        {"date", yume::http_profile::http_date_now()},
        {"content-length", "12"},
    };
    response.body = {'B', 'a', 'd', ' ', 'G', 'a', 't', 'e', 'w', 'a', 'y', '\n'};
    return response;
}

std::string etag_hex(std::uintmax_t value) {
    if (value == 0) return "0";
    static const char kDigits[] = "0123456789abcdef";
    std::string out;
    while (value != 0) {
        out.push_back(kDigits[value & 0xF]);
        value >>= 4;
    }
    std::reverse(out.begin(), out.end());
    return out;
}
}  // namespace

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
            send_real_http_response("/", "GET");
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
            send_real_http_response("/", "GET");
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
                send_real_http_response("/", "GET");
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
                send_real_http_response("/", "GET");
            } else {
                send_disguise_404("/");
            }
            return true;
        }
        const std::string negotiated = obfs::selected_alpn(stream_.native_handle());
        if (negotiated != "h2") {
            if (cfg_.real_http) {
                send_real_http_response("/", "GET");
            } else {
                send_disguise_404("/");
            }
            return true;
        }
        start_v2_h2_session();
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

    // The preface bytes are the start of the request; hand off to the
    // keep-alive request loop, which reads the rest and then either serves the
    // next request on the same connection or closes.
    begin_http_masquerade(preface);
    return true;
}

void Session::begin_http_masquerade(std::string initial) {
    http_request_buf_ = std::move(initial);
    http_requests_served_ = 0;
    read_http_request();
}

void Session::read_http_request() {
    auto self = shared_from_this();
    // Idle deadline between requests: a real keep-alive connection is not held
    // open forever. Cancels the pending read on expiry.
    http_idle_timer_.expires_after(std::chrono::milliseconds(kKeepAliveIdleMs));
    http_idle_timer_.async_wait(boost::asio::bind_executor(
        strand_, [self](const boost::system::error_code& ec) {
            if (ec) return;  // cancelled by a completed read
            boost::system::error_code cancel_ec;
            self->stream_.lowest_layer().cancel(cancel_ec);
            self->close_with_reason("http keepalive idle timeout");
        }));
    boost::asio::async_read_until(
        stream_,
        boost::asio::dynamic_buffer(http_request_buf_,
                                    yume::app_codec::kMaxHttpHeaderBytes + 1),
        "\r\n\r\n",
        boost::asio::bind_executor(
            strand_, [self](const boost::system::error_code& ec, std::size_t n) {
                self->on_http_request_read(ec, n);
            }));
}

void Session::on_http_request_read(const boost::system::error_code& ec, std::size_t n) {
    http_idle_timer_.cancel();
    if (ec) {
        if (ec == boost::asio::error::operation_aborted) return;
        // not_found (headers too large / cap hit), EOF, or reset: close quietly
        // like a web server dropping an unusable or finished connection.
        close_with_reason("http masquerade read ended: " + ec.message());
        return;
    }
    // n covers the request line + headers up to and including "\r\n\r\n"; keep
    // any over-read/pipelined bytes as the seed for the next request.
    std::string request = http_request_buf_.substr(0, n);
    http_request_buf_.erase(0, n);
    dispatch_http_request(std::move(request));
}

void Session::dispatch_http_request(std::string request) {
    ++http_requests_served_;

    std::string line;
    const auto pos = request.find("\r\n");
    if (pos != std::string::npos) line = request.substr(0, pos);
    const auto req = http_masq::parse_request_line(line);
    const std::string& method = req.method;
    std::string path = req.target;

    // Host-route reverse proxy stays terminal (it takes over the socket); the
    // keep-alive loop only governs the local decoy responses below. Forward the
    // header block plus any bytes we already read past it.
    if (cfg_.host_mode != host::HostMode::Off && manager_ &&
        !manager_->host_routes().empty()) {
        const std::string sni = host::tls_sni(stream_.native_handle());
        std::string host_only = host::http_header_value(request, "Host");
        const auto colon = host_only.find(':');
        if (colon != std::string::npos) host_only = host_only.substr(0, colon);
        auto match = manager_->host_routes().match(sni, host_only, path);
        if (match.has_value()) {
            auto backend = host::parse_loopback_backend(match->route->backend);
            if (backend.has_value()) {
                auto handoff = release_for_host_proxy();
                if (handoff.has_value()) {
                    host::start_http_reverse_proxy(std::move(*handoff),
                                                   request + http_request_buf_,
                                                   backend->first, backend->second,
                                                   manager_);
                }
                return;
            }
        }
    }

    const bool keep_alive = http_masq::response_keep_alive(
        method, req.version, host::http_header_value(request, "Connection"),
        request_has_message_body(request), http_requests_served_,
        kMaxKeepAliveRequests);

    if (cfg_.robots_deny && path == "/robots.txt" &&
        (method == "GET" || method == "HEAD")) {
        send_robots_txt_response(method == "HEAD", keep_alive);
        return;
    }
    if (cfg_.real_http) {
        send_real_http_response(path, method, keep_alive, request);
    } else {
        // Pre-1.0 this path closed immediately, which is a strong DPI signal.
        // Serve a profile-driven 404 so the probe sees a real-looking web
        // server with nothing at that path. (Terminal: closes the connection.)
        send_disguise_404(path);
    }
}

void Session::finish_masq_write(std::shared_ptr<std::string> resp,
                                bool keep_alive,
                                std::string close_reason) {
    auto self = shared_from_this();
    boost::asio::async_write(
        stream_, boost::asio::buffer(*resp),
        boost::asio::bind_executor(
            strand_, [self, resp, keep_alive, close_reason](
                         const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    self->close_with_reason("masquerade write failed: " + ec.message());
                    return;
                }
                if (keep_alive) {
                    self->read_http_request();
                } else {
                    self->close_with_reason(close_reason);
                }
            }));
}

std::optional<std::string> Session::load_real_index() {
    // With --real-root, the H2 decoy and the HTTP/1.1 "/" path must present the
    // same index bytes so an active probe sees one web identity across both
    // carriers.
    //
    // There is deliberately no built-in fallback page. A constant page
    // compiled into the daemon is byte-identical on every deployment, which
    // is exactly the global active-probe fingerprint the cover path exists to
    // avoid. Startup refuses a configuration with no cover source, and a
    // source that disappears at runtime returns nullopt so the caller answers
    // with the profile's ordinary 404 instead.
    if (!cfg_.real_root.empty()) {
        auto file = static_site::read_under_root(
            cfg_.real_root, "index.html", cover_response::kMaxResponseBytes);
        if (file.has_value()) {
            return std::move(file->bytes);
        }
        return std::nullopt;
    }
    if (!cfg_.real_index_path.empty()) {
        std::string contents;
        if (runtime::read_text_file_bounded(
                cfg_.real_index_path, cover_response::kMaxResponseBytes,
                &contents)) {
            return contents;
        }
    }
    return std::nullopt;
}

std::string Session::build_hidden_blob() {
#if YUME_USE_BASEFWX
    if (cfg_.real_secret.empty()) {
        return "";
    }
    basefwx::crypto::Bytes salt = basefwx::crypto::RandomBytes(basefwx::constants::kUserKdfSaltSize);
    basefwx::crypto::SecureBytes key{
        basefwx::crypto::Pbkdf2HmacSha256(
            cfg_.real_secret,
            salt,
            basefwx::constants::kUserKdfIterations,
            32)};
    nlohmann::json meta{
        {"ts", static_cast<long long>(std::time(nullptr))},
        {"sid", static_cast<long long>(session_id_)},
        {"note", "yume-real"}
    };
    std::string meta_str = meta.dump();
    basefwx::crypto::Bytes payload(meta_str.begin(), meta_str.end());
    basefwx::crypto::Bytes aad{'y', 'u', 'm', 'e', '-', 'r', 'e', 'a', 'l'};
    basefwx::crypto::Bytes blob =
        basefwx::crypto::AeadEncrypt(key.bytes(), payload, aad);

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
            cfg_.http_profile.empty() ? "nginx" : cfg_.http_profile);
        if (!profile.has_value()) {
            profile = yume::http_profile::server("nginx");
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

void Session::send_real_http_response(const std::string& path, const std::string& method,
                                      bool keep_alive, const std::string& request_headers) {
    const bool head_only = method == "HEAD";
    if (cfg_.robots_deny && path == "/robots.txt") {
        send_robots_txt_response(head_only, keep_alive);
        return;
    }

    // The evidence-backed 2.0 facade is the separately supervised Node
    // process. H1 and H2 take the same bounded structured-proxy route; neither
    // hands the public socket, peer-selected Host, or tunnel bytes to Node.
    if (!cfg_.real_backend.empty()) {
        if (method != "GET" && method != "HEAD") {
            send_disguise_404(path);
            return;
        }
        const auto backend = host::parse_loopback_backend(cfg_.real_backend);
        if (!backend.has_value()) {
            finish_masq_write(
                render_backend_h1_response(node_gateway_failure(), head_only,
                                           false),
                false, "Node cover backend configuration rejected");
            return;
        }
        auto self = shared_from_this();
        host::fetch_loopback_http(
            strand_, backend->first, backend->second, method,
            path.empty() ? std::string("/") : path, {},
            [self, head_only, keep_alive](
                std::string error, host::BackendHttpResponse response) mutable {
                if (self->close_state_ != CloseState::Open) return;
                const bool backend_ok = error.empty();
                if (!backend_ok) response = node_gateway_failure();
                const bool response_keep_alive = backend_ok && keep_alive;
                self->finish_masq_write(
                    render_backend_h1_response(std::move(response), head_only,
                                               response_keep_alive),
                    response_keep_alive,
                    backend_ok ? "served loopback Node cover response"
                               : "loopback Node cover unavailable");
            });
        return;
    }

    // --real-root: serve GET/HEAD for any real file under the root so the cover
    // is a coherent multi-asset site, not "/ => 200, everything else => 404".
    // Resolution rejects traversal/encoded-slash/symlink escape; a miss or a
    // non-GET/HEAD method falls through to the profile 404, which is what a
    // real nginx returns for an unrouted path.
    if (!cfg_.real_root.empty()) {
        if (method == "GET" || method == "HEAD") {
            auto resolved = static_site::resolve_target(path, "index.html");
            if (resolved.has_value()) {
                auto file = static_site::read_under_root(
                    cfg_.real_root, resolved->rel_path,
                    cover_response::kMaxResponseBytes);
                if (file.has_value()) {
                    send_static_file(resolved->rel_path, std::move(*file), head_only,
                                     keep_alive, request_headers);
                    return;
                }
            }
        }
        send_disguise_404(path);
        return;
    }

    // Single-page mode (--real-index / default): only "/" is a page;
    // everything else is a profile 404, because real nginx returns 404 for
    // /random-path and a blanket "302 Location: /" is a soft fingerprint to
    // any prober that GETs more than one URL.
    if (path != "/") {
        send_disguise_404(path);
        return;
    }
    auto index = load_real_index();
    if (!index.has_value()) {
        // The configured cover source vanished. A real nginx whose document
        // root lost its index answers 404, so do that rather than inventing a
        // page that only YUME servers serve.
        send_disguise_404(path);
        return;
    }
    std::string body = std::move(*index);
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

    // Disguise headers come from yume::http_profile. An unset profile
    // resolves to "nginx": the server must never identify itself by
    // default, so the disguise is opt-out, not opt-in.
    auto profile = yume::http_profile::server(
        cfg_.http_profile.empty() ? "nginx" : cfg_.http_profile);
    if (!profile.has_value()) {
        // Validation runs at startup, so reaching here means an
        // operator hot-edited the config into an unknown profile.
        profile = yume::http_profile::server("nginx");
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
    headers += keep_alive ? "Connection: keep-alive\r\n\r\n" : "Connection: close\r\n\r\n";

    auto resp = std::make_shared<std::string>(head_only ? std::move(headers) : headers + body);
    finish_masq_write(std::move(resp), keep_alive, "served HTTP disguise response");
}

void Session::send_static_file(const std::string& rel_path,
                               static_site::FileContents file,
                               bool head_only,
                               bool keep_alive,
                               const std::string& request_headers) {
    auto profile = yume::http_profile::server(
        cfg_.http_profile.empty() ? "nginx" : cfg_.http_profile);
    if (!profile.has_value()) {
        profile = yume::http_profile::server("nginx");
    }

    const std::uintmax_t len = file.bytes.size();
    const std::uintmax_t mtime_secs =
        file.mtime > 0 ? static_cast<std::uintmax_t>(file.mtime) : 0;
    // nginx computes the ETag as "<hex-mtime>-<hex-length>"; match it so a
    // byte-level comparison against real nginx lines up.
    const std::string etag = "\"" + etag_hex(mtime_secs) + "-" + etag_hex(len) + "\"";
    const std::string conn = keep_alive ? "Connection: keep-alive\r\n"
                                        : "Connection: close\r\n";

    // Common validator headers present on every static reply.
    auto server_and_date = [&]() {
        std::string h;
        if (!profile->server_header_value.empty()) {
            h += "Server: " + profile->server_header_value + "\r\n";
        }
        h += "Date: " + yume::http_profile::http_date_now() + "\r\n";
        return h;
    };
    auto last_modified = [&]() {
        if (mtime_secs == 0) return std::string();
        return "Last-Modified: " +
               yume::http_profile::http_date(static_cast<std::time_t>(mtime_secs)) + "\r\n";
    };

    // Conditional GET (RFC 7232): If-None-Match wins over If-Modified-Since. A
    // match means the client already has this representation -> 304, no body.
    const std::string inm = host::http_header_value(request_headers, "If-None-Match");
    bool not_modified = false;
    if (!inm.empty()) {
        not_modified = inm == "*" || inm.find(etag) != std::string::npos;
    } else {
        const std::string ims = host::http_header_value(request_headers, "If-Modified-Since");
        if (!ims.empty() && mtime_secs != 0) {
            const auto since = yume::http_profile::parse_http_date(ims);
            if (since.has_value() &&
                static_cast<std::time_t>(mtime_secs) <= *since) {
                not_modified = true;
            }
        }
    }
    if (not_modified) {
        std::string headers = "HTTP/1.1 304 Not Modified\r\n";
        headers += server_and_date();
        headers += last_modified();
        headers += conn;
        headers += "ETag: " + etag + "\r\n\r\n";
        finish_masq_write(std::make_shared<std::string>(std::move(headers)),
                          keep_alive, "served static 304");
        return;
    }

    // Byte-range request. Absent -> full 200; Unsatisfiable -> 416; else 206.
    const auto range = static_site::parse_byte_range(
        host::http_header_value(request_headers, "Range"), len);
    if (range.status == static_site::ByteRange::Status::Unsatisfiable) {
        std::string headers = "HTTP/1.1 416 Range Not Satisfiable\r\n";
        headers += server_and_date();
        headers += "Content-Range: bytes */" + std::to_string(len) + "\r\n";
        headers += "Content-Length: 0\r\n";
        headers += conn;
        headers += "\r\n";
        finish_masq_write(std::make_shared<std::string>(std::move(headers)),
                          keep_alive, "served static 416");
        return;
    }

    const bool partial = range.status == static_site::ByteRange::Status::Satisfiable;
    const std::uint64_t body_start = partial ? range.start : 0;
    const std::uint64_t body_len = partial ? range.length() : len;

    std::string headers = partial ? "HTTP/1.1 206 Partial Content\r\n"
                                   : "HTTP/1.1 200 OK\r\n";
    headers += server_and_date();
    headers += "Content-Type: " + static_site::mime_type(rel_path) + "\r\n";
    headers += "Content-Length: " + std::to_string(body_len) + "\r\n";
    headers += last_modified();
    if (partial) {
        headers += "Content-Range: bytes " + std::to_string(range.start) + "-" +
                   std::to_string(range.end) + "/" + std::to_string(len) + "\r\n";
    }
    headers += conn;
    headers += "ETag: " + etag + "\r\n";
    headers += "Accept-Ranges: bytes\r\n\r\n";

    std::string out = std::move(headers);
    if (!head_only) {
        out.append(file.bytes, static_cast<std::size_t>(body_start),
                   static_cast<std::size_t>(body_len));
    }
    finish_masq_write(std::make_shared<std::string>(std::move(out)), keep_alive,
                      partial ? "served static 206" : "served static file");
}

void Session::send_robots_txt_response(bool head_only, bool keep_alive) {
    const std::string body = "User-agent: *\nDisallow: /\n";
    auto profile = yume::http_profile::server(
        cfg_.http_profile.empty() ? "nginx" : cfg_.http_profile);
    if (!profile.has_value()) {
        profile = yume::http_profile::server("nginx");
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
    headers += keep_alive ? "Connection: keep-alive\r\n\r\n" : "Connection: close\r\n\r\n";

    auto resp = std::make_shared<std::string>(head_only ? std::move(headers) : headers + body);
    finish_masq_write(std::move(resp), keep_alive, "served robots.txt");
}

void Session::start_v2_h2_session() {
    carrier_probe_active_ = false;
    carrier_settings_ack_wait_active_ = false;
    carrier_decoder_.reset();
    preface_timer_.cancel();
    v2_h2_carrier_ = std::make_unique<obfs::H2Carrier>(
        obfs::H2CarrierRole::Server);
#if YUME_ENABLE_DEV_DIAGNOSTICS
    v2_h2_carrier_->set_timing_enabled(YUME_TIMING_ENABLED());
#endif
    if (!preface_accum_.empty()) {
        v2_h2_carrier_->Feed(preface_accum_.data(), preface_accum_.size());
        preface_accum_.clear();
    }
    process_v2_h2_stream_closes();
    if (v2_h2_carrier_->failed()) {
        close_with_reason("v2 HTTP/2 opening rejected: " +
                          v2_h2_carrier_->error());
        return;
    }
    flush_v2_h2_wire_on_strand();
    process_v2_h2_requests();
}

void Session::read_v2_h2_cover() {
    if (!v2_h2_carrier_ || v2_h2_tunnel_active_ ||
        v2_h2_tls_read_in_flight_ || close_state_ != CloseState::Open) {
        return;
    }
    v2_h2_tls_read_in_flight_ = true;
    auto self = shared_from_this();
    stream_.async_read_some(
        boost::asio::buffer(carrier_scratch_),
        boost::asio::bind_executor(
            strand_, [self](const boost::system::error_code& ec, std::size_t bytes) {
                self->on_v2_h2_cover_read(ec, bytes);
            }));
}

void Session::on_v2_h2_cover_read(const boost::system::error_code& ec,
                                   std::size_t bytes) {
    v2_h2_tls_read_in_flight_ = false;
    if (ec) {
        close_with_reason("v2 HTTP/2 cover read failed: " + ec.message());
        return;
    }
    if (!v2_h2_carrier_) {
        close_with_reason("v2 HTTP/2 state disappeared");
        return;
    }
    v2_h2_carrier_->Feed(carrier_scratch_.data(), bytes);
    process_v2_h2_stream_closes();
    if (v2_h2_carrier_->failed()) {
        close_with_reason("v2 HTTP/2 protocol error: " +
                          v2_h2_carrier_->error());
        return;
    }
    flush_v2_h2_wire_on_strand();
    process_v2_h2_requests();
}

void Session::process_v2_h2_requests() {
    if (!v2_h2_carrier_ || close_state_ != CloseState::Open) return;
    process_v2_h2_stream_closes();
    auto requests = v2_h2_carrier_->TakeRequests();
    for (auto& request : requests) {
        if (request.method == "GET" || request.method == "HEAD") {
            if (!v2_h2_cover_fetches_.admit(request.stream_id)) {
                if (!v2_h2_carrier_->RefuseStream(request.stream_id)) {
                    close_with_reason(
                        "failed to refuse saturated HTTP/2 cover stream: " +
                        v2_h2_carrier_->error());
                    return;
                }
                process_v2_h2_stream_closes();
                flush_v2_h2_wire_on_strand();
                process_v2_h2_stream_closes();
                continue;
            }
            const auto backend = host::parse_loopback_backend(cfg_.real_backend);
            if (!backend.has_value()) {
                (void)v2_h2_cover_fetches_.complete_fetch(request.stream_id);
                v2_h2_carrier_->RespondHttp(
                    request.stream_id, 502,
                    {{"content-type", "text/plain; charset=utf-8"},
                     {"date", yume::http_profile::http_date_now()}},
                    crypto::Bytes{'B', 'a', 'd', ' ', 'G', 'a', 't', 'e', 'w', 'a', 'y', '\n'},
                    request.method == "HEAD");
                if (v2_h2_carrier_->failed()) {
                    close_with_reason("Node cover response failed: " +
                                      v2_h2_carrier_->error());
                    return;
                }
                process_v2_h2_stream_closes();
                flush_v2_h2_wire_on_strand();
                process_v2_h2_stream_closes();
                continue;
            }
            std::weak_ptr<Session> weak = weak_from_this();
            auto fetch = host::fetch_loopback_http(
                strand_, backend->first, backend->second, request.method,
                request.path.empty() ? std::string("/") : request.path,
                {},
                [weak = std::move(weak), stream_id = request.stream_id,
                 head = request.method == "HEAD"](
                    std::string error, host::BackendHttpResponse response) mutable {
                    if (auto self = weak.lock()) {
                        self->complete_v2_h2_cover_fetch(
                            stream_id, head, std::move(error),
                            std::move(response));
                    }
                });
            const auto cancel_fetch = fetch;
            if (!v2_h2_cover_fetches_.attach_cancel(
                    request.stream_id,
                    [cancel_fetch]() { cancel_fetch->cancel(); })) {
                fetch->cancel();
                close_with_reason(
                    "HTTP/2 cover fetch registry lost admitted stream");
                return;
            }
            continue;
        }

        if (request.method == "CONNECT" && request.protocol == "websocket" &&
            !v2_h2_tunnel_active_) {
            const std::string tls_sni = host::tls_sni(stream_.native_handle());
            std::optional<std::uint16_t> listener_port;
            boost::system::error_code endpoint_ec;
            const auto endpoint = stream_.lowest_layer().local_endpoint(endpoint_ec);
            if (!endpoint_ec && endpoint.port() > 0) listener_port = endpoint.port();
            const auto now_s = static_cast<std::int64_t>(std::time(nullptr));
            crypto::Bytes admission_secret;
            if (cfg_.obfs_secret_material) {
                admission_secret = cfg_.obfs_secret_material->CopyBytes();
            }
            const bool hmac_ok = obfs::carrier_path_admitted(
                admission_secret, request.authority, tls_sni, request.path,
                now_s, listener_port);
            security::secure_erase(admission_secret);
            const bool replay_ok = hmac_ok && admission_replay_cache_ &&
                admission_replay_cache_->AcceptPath(request.path, now_s);
            if (!replay_ok) {
                v2_h2_carrier_->RejectCarrier(
                    request.stream_id, 404,
                    {{"content-type", "text/plain; charset=utf-8"},
                     {"date", yume::http_profile::http_date_now()}},
                    crypto::Bytes{'N', 'o', 't', ' ', 'F', 'o', 'u', 'n', 'd', '\n'});
                if (v2_h2_carrier_->failed()) {
                    close_with_reason("failed to reject v2 extended CONNECT: " +
                                      v2_h2_carrier_->error());
                    return;
                }
                flush_v2_h2_wire_on_strand();
                process_v2_h2_stream_closes();
                continue;
            }
            if (!v2_h2_carrier_->AcceptCarrier(request.stream_id)) {
                close_with_reason("failed to accept v2 extended CONNECT: " +
                                  v2_h2_carrier_->error());
                return;
            }
            v2_h2_tunnel_active_ = true;
            process_v2_h2_stream_closes();
            flush_v2_h2_wire_on_strand();
            send_auth_challenge();
            return;
        }

        v2_h2_carrier_->RespondHttp(
            request.stream_id, 404,
            {{"content-type", "text/plain; charset=utf-8"},
             {"date", yume::http_profile::http_date_now()}},
            crypto::Bytes{'N', 'o', 't', ' ', 'F', 'o', 'u', 'n', 'd', '\n'});
        if (v2_h2_carrier_->failed()) {
            close_with_reason("HTTP/2 cover rejection failed: " +
                              v2_h2_carrier_->error());
            return;
        }
        flush_v2_h2_wire_on_strand();
        process_v2_h2_stream_closes();
    }
    read_v2_h2_cover();
}

void Session::process_v2_h2_stream_closes() {
    if (!v2_h2_carrier_) {
        return;
    }
    for (const auto& closed : v2_h2_carrier_->TakeStreamCloses()) {
        (void)v2_h2_cover_fetches_.close_stream(closed.stream_id);
    }
}

void Session::complete_v2_h2_cover_fetch(
    std::int32_t stream_id,
    bool head_request,
    std::string error,
    host::BackendHttpResponse response) {
    if (!v2_h2_cover_fetches_.complete_fetch(stream_id)) {
        return;
    }
    if (!v2_h2_carrier_ || close_state_ != CloseState::Open) {
        (void)v2_h2_cover_fetches_.close_stream(stream_id);
        return;
    }
    if (!error.empty()) {
        v2_h2_carrier_->RespondHttp(
            stream_id, 502,
            {{"content-type", "text/plain; charset=utf-8"},
             {"date", yume::http_profile::http_date_now()}},
            crypto::Bytes{'B', 'a', 'd', ' ', 'G', 'a', 't', 'e', 'w', 'a', 'y', '\n'},
            head_request);
    } else {
        v2_h2_carrier_->RespondHttp(
            stream_id, response.status, response.headers,
            std::move(response.body), head_request);
    }
    if (v2_h2_carrier_->failed()) {
        close_with_reason("Node cover response failed: " +
                          v2_h2_carrier_->error());
        return;
    }
    process_v2_h2_stream_closes();
    flush_v2_h2_wire_on_strand();
    process_v2_h2_stream_closes();
}

void Session::cancel_v2_h2_cover_fetches() {
    v2_h2_cover_fetches_.cancel_all();
}

void Session::schedule_v2_h2_wire_flush_on_strand() {
    if (v2_h2_flush_scheduled_ || close_state_ != CloseState::Open) {
        return;
    }
    v2_h2_flush_scheduled_ = true;
    boost::asio::post(strand_, [self = shared_from_this()]() {
        if (!self->v2_h2_flush_scheduled_) {
            return;
        }
        self->v2_h2_flush_scheduled_ = false;
        self->flush_v2_h2_wire_on_strand();
    });
}

void Session::flush_v2_h2_wire_on_strand() {
    if (!v2_h2_carrier_ || close_state_ != CloseState::Open) return;
    auto wire = v2_h2_carrier_->TakeOutbound();
    if (v2_h2_carrier_->failed()) {
        close_with_reason("v2 HTTP/2 output failed: " + v2_h2_carrier_->error());
        return;
    }
    if (wire.empty()) return;

    auto data = std::make_shared<std::vector<std::uint8_t>>(std::move(wire));
    const std::size_t cover_output_bytes = v2_h2_tunnel_active_
        ? 0U : data->size();
    if (cover_output_bytes != 0U &&
        !v2_h2_cover_fetches_.reserve_output_bytes(cover_output_bytes)) {
        close_with_reason(
            "unauthenticated HTTP/2 cover TLS output budget exhausted");
        return;
    }
    std::deque<PendingWrite> completed_app_writes;
    std::size_t completed_app_bytes = 0U;
    if (v2_h2_carrier_->queued_output_bytes() == 0) {
        completed_app_writes.swap(v2_h2_pending_app_writes_);
        for (const auto& item : completed_app_writes) {
            if (item.data) {
                completed_app_bytes += item.data->size();
            }
        }
    }
    enqueue_tls_write_on_strand(
        data, protocol::DATA, 0, data->size(),
        [self = shared_from_this(),
         completed = std::move(completed_app_writes),
         completed_app_bytes,
         cover_output_bytes](
            const boost::system::error_code& ec, std::size_t bytes) mutable {
            if (cover_output_bytes != 0U &&
                !self->v2_h2_cover_fetches_.release_output_bytes(
                    cover_output_bytes)) {
                self->close_with_reason(
                    "unauthenticated HTTP/2 cover TLS output ledger mismatch");
            }
            self->v2_h2_app_write_frames_ =
                completed.size() <= self->v2_h2_app_write_frames_
                    ? self->v2_h2_app_write_frames_ - completed.size()
                    : 0U;
            self->v2_h2_app_write_bytes_ =
                completed_app_bytes <= self->v2_h2_app_write_bytes_
                    ? self->v2_h2_app_write_bytes_ - completed_app_bytes
                    : 0U;
            for (auto& item : completed) {
                if (item.handler) {
                    item.handler(ec, !ec && item.data ? item.data->size() : bytes);
                }
            }
            if (!ec) {
                self->maybe_resume_inbound_reads_on_strand();
            }
        });
}

void Session::start_v2_h2_exact_read(
    std::uint8_t* target, std::size_t size,
    std::function<void(const boost::system::error_code&, std::size_t)> handler) {
    if (!v2_h2_tunnel_active_ || !v2_h2_carrier_ || v2_h2_read_handler_) {
        handler(boost::asio::error::operation_not_supported, 0);
        return;
    }
    v2_h2_read_target_ = target;
    v2_h2_read_size_ = size;
    v2_h2_read_copied_ = 0;
    v2_h2_read_handler_ = std::move(handler);
    continue_v2_h2_exact_read();
}

runtime::InboundCredit Session::make_v2_h2_inbound_credit_on_strand(
    std::size_t bytes) {
    if (bytes == 0U || !v2_h2_tunnel_active_ || !v2_h2_carrier_) {
        return {};
    }
    std::weak_ptr<Session> weak = weak_from_this();
    return runtime::InboundCredit(
        bytes, [weak = std::move(weak)](std::size_t released_bytes) {
            if (auto self = weak.lock()) {
                self->release_v2_h2_inbound_credit(released_bytes);
            }
        });
}

void Session::release_v2_h2_inbound_credit(std::size_t bytes) {
    if (bytes == 0U) {
        return;
    }
    if (!strand_.running_in_this_thread()) {
        boost::asio::post(
            strand_, [self = shared_from_this(), bytes]() {
                self->release_v2_h2_inbound_credit(bytes);
            });
        return;
    }
    if (!v2_h2_carrier_ || close_state_ != CloseState::Open ||
        v2_h2_credit_release_failed_) {
        return;
    }
    if (bytes > std::numeric_limits<std::size_t>::max() -
                    v2_h2_pending_credit_release_bytes_) {
        v2_h2_pending_credit_release_bytes_ = 0U;
        v2_h2_credit_release_scheduled_ = false;
        v2_h2_credit_release_failed_ = true;
        boost::asio::post(strand_, [self = shared_from_this()]() {
            if (self->close_state_ == CloseState::Open) {
                self->close_with_reason(
                    "v2 HTTP/2 receive-credit release overflow");
            }
        });
        return;
    }
    v2_h2_pending_credit_release_bytes_ += bytes;
    if (v2_h2_credit_release_scheduled_) {
        return;
    }
    v2_h2_credit_release_scheduled_ = true;
    boost::asio::post(strand_, [self = shared_from_this()]() {
        self->flush_v2_h2_inbound_credit_on_strand();
    });
}

void Session::flush_v2_h2_inbound_credit_on_strand() {
    if (!v2_h2_credit_release_scheduled_) {
        return;
    }
    v2_h2_credit_release_scheduled_ = false;
    const std::size_t bytes =
        std::exchange(v2_h2_pending_credit_release_bytes_, 0U);
    if (bytes == 0U || !v2_h2_carrier_ ||
        close_state_ != CloseState::Open || v2_h2_credit_release_failed_) {
        return;
    }
    if (!v2_h2_carrier_->ConsumeTunnelBytes(bytes)) {
        v2_h2_credit_release_failed_ = true;
        close_with_reason(
            "v2 HTTP/2 receive-credit release failed: " +
            v2_h2_carrier_->error());
        return;
    }
    schedule_v2_h2_wire_flush_on_strand();
}

void Session::continue_v2_h2_exact_read() {
    if (!v2_h2_read_handler_ || !v2_h2_carrier_) return;
    if (v2_h2_decoded_offset_ == v2_h2_decoded_.size()) {
        v2_h2_decoded_ = v2_h2_carrier_->TakeTunnelBytes();
        v2_h2_decoded_offset_ = 0;
    }
    const std::size_t available = v2_h2_decoded_.size() - v2_h2_decoded_offset_;
    const std::size_t need = v2_h2_read_size_ - v2_h2_read_copied_;
    const std::size_t take = std::min(available, need);
    if (take > 0) {
        std::copy_n(v2_h2_decoded_.data() + v2_h2_decoded_offset_, take,
                    v2_h2_read_target_ + v2_h2_read_copied_);
        v2_h2_decoded_offset_ += take;
        v2_h2_read_copied_ += take;
    }
    if (v2_h2_read_copied_ == v2_h2_read_size_) {
        auto handler = std::move(v2_h2_read_handler_);
        const std::size_t complete = v2_h2_read_copied_;
        v2_h2_read_target_ = nullptr;
        v2_h2_read_size_ = 0;
        v2_h2_read_copied_ = 0;
        handler({}, complete);
        return;
    }
    if (v2_h2_carrier_->carrier_closed()) {
        auto handler = std::move(v2_h2_read_handler_);
        handler(boost::asio::error::eof, v2_h2_read_copied_);
        return;
    }
    if (v2_h2_tls_read_in_flight_) return;
    v2_h2_tls_read_in_flight_ = true;
    auto self = shared_from_this();
    stream_.async_read_some(
        boost::asio::buffer(carrier_scratch_),
        boost::asio::bind_executor(
            strand_, [self](const boost::system::error_code& ec, std::size_t bytes) {
                self->on_v2_h2_exact_tls_read(ec, bytes);
            }));
}

void Session::on_v2_h2_exact_tls_read(const boost::system::error_code& ec,
                                      std::size_t bytes) {
    v2_h2_tls_read_in_flight_ = false;
    if (ec) {
        if (v2_h2_read_handler_) {
            auto handler = std::move(v2_h2_read_handler_);
            handler(ec, v2_h2_read_copied_);
        }
        return;
    }
    v2_h2_carrier_->Feed(carrier_scratch_.data(), bytes);
    process_v2_h2_stream_closes();
    if (v2_h2_carrier_->failed()) {
        if (v2_h2_read_handler_) {
            auto handler = std::move(v2_h2_read_handler_);
            handler(boost::asio::error::fault, v2_h2_read_copied_);
        }
        return;
    }
    process_v2_h2_requests();
    if (close_state_ != CloseState::Open) {
        return;
    }
    flush_v2_h2_wire_on_strand();
    process_v2_h2_stream_closes();
    continue_v2_h2_exact_read();
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
        // This is an asynchronous trust boundary: the bytes are peer-supplied
        // and unauthenticated, and an escaping exception would unwind into the
        // Asio worker rather than this session. The decoder is written to
        // reject malformed input instead of throwing; contain a throw anyway
        // so a future decoder defect degrades to the decoy response.
        try {
            carrier_decoder_->feed(carrier_scratch_.data(), bytes);
        } catch (const std::exception& ex) {
            util::log_warn("session " + std::to_string(session_id_) +
                           ": h2 carrier decode threw; serving masquerade "
                           "response: " + std::string(ex.what()));
            carrier_probe_active_ = false;
            preface_timer_.cancel();
            serve_fake_h2_real_index();
            return;
        }
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
        crypto::Bytes admission_secret;
        if (cfg_.obfs_secret_material) {
            admission_secret = cfg_.obfs_secret_material->CopyBytes();
        }
        const bool hmac_ok = obfs::carrier_path_admitted(
            admission_secret, authority, tls_sni, path, now_s, listener_port);
        security::secure_erase(admission_secret);
        const bool token_ok = hmac_ok && admission_replay_cache_ &&
                              admission_replay_cache_->AcceptPath(path, now_s);
        carrier_probe_active_ = false;
        preface_timer_.cancel();

        if (!token_ok) {
            util::log_warn("session " + std::to_string(session_id_) +
                          ": h2 carrier path token rejected (size=" +
                          std::to_string(path.size()) + ", authority_sni=" +
                          (authority_ok ? std::string("match") : std::string("mismatch")) +
                          ", replay_or_hmac=" +
                          (hmac_ok ? std::string("replay") : std::string("hmac")) + ")");
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
        cfg_.http_profile.empty() ? "nginx" : cfg_.http_profile);
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
        cfg_.http_profile.empty() ? "nginx" : cfg_.http_profile);
    if (!profile.has_value()) {
        profile = yume::http_profile::server("nginx");
    }

    auto index = cfg_.real_http ? load_real_index() : std::nullopt;
    if (!have_response && index.has_value()) {
        std::string body = std::move(*index);
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
