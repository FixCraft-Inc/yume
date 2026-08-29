/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "outbound/proxy.hpp"
#include "outbound/io.hpp"

#include <array>
#include <cstring>
#include <sstream>
#include <string_view>

#include <boost/asio/connect.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>

namespace yume::outbound::proxy {

namespace {

// RFC 1928 / 1929 byte tags.
constexpr std::uint8_t kVer5         = 0x05;
constexpr std::uint8_t kAuthNone     = 0x00;
constexpr std::uint8_t kAuthUserPass = 0x02;
constexpr std::uint8_t kAuthVer      = 0x01;
constexpr std::uint8_t kCmdConnect   = 0x01;
constexpr std::uint8_t kAtypIpv4     = 0x01;
constexpr std::uint8_t kAtypDomain   = 0x03;
constexpr std::uint8_t kAtypIpv6     = 0x04;
constexpr std::uint8_t kRepSuccess   = 0x00;

char const* socks5_reply_reason(std::uint8_t rep) {
    switch (rep) {
        case 0x00: return "success";
        case 0x01: return "general SOCKS server failure";
        case 0x02: return "connection not allowed by ruleset";
        case 0x03: return "network unreachable";
        case 0x04: return "host unreachable";
        case 0x05: return "connection refused";
        case 0x06: return "TTL expired";
        case 0x07: return "command not supported";
        case 0x08: return "address type not supported";
        default:   return "unknown SOCKS5 reply";
    }
}

bool write_all(boost::asio::ip::tcp::socket& sock,
               boost::asio::io_context& io,
               void const* data, std::size_t len,
               std::chrono::milliseconds timeout,
               std::string& err,
               bool& cancelled,
               const yume::outbound::StopPredicate& should_stop) {
    auto cancel = [&]() {
        boost::system::error_code ignored;
        sock.cancel(ignored);
    };
    const auto result = yume::outbound::write_all_with_timeout(
        sock, io, boost::asio::buffer(data, len), timeout, cancel, should_stop);
    cancelled = result.cancelled;
    if (result.cancelled) { err = "proxy operation cancelled"; return false; }
    if (result.timed_out) { err = "timeout writing to proxy"; return false; }
    if (result.ec) {
        err = "proxy write failed: " + result.ec.message();
        return false;
    }
    return true;
}

bool read_exact(boost::asio::ip::tcp::socket& sock,
                boost::asio::io_context& io,
                void* data, std::size_t len,
                std::chrono::milliseconds timeout,
                std::string& err,
                bool& cancelled,
                const yume::outbound::StopPredicate& should_stop) {
    auto cancel = [&]() {
        boost::system::error_code ignored;
        sock.cancel(ignored);
    };
    const auto result = yume::outbound::read_exact_with_timeout(
        sock, io, boost::asio::buffer(data, len), timeout, cancel, should_stop);
    cancelled = result.cancelled;
    if (result.cancelled) { err = "proxy operation cancelled"; return false; }
    if (result.timed_out) { err = "timeout reading from proxy"; return false; }
    if (result.ec) {
        err = "proxy read failed: " + result.ec.message();
        return false;
    }
    return true;
}

}  // namespace

DialResult socks5_dial(boost::asio::ip::tcp::socket& sock,
                       boost::asio::io_context& io,
                       Config const& cfg,
                       std::string const& target_host,
                       int target_port,
                       std::chrono::milliseconds timeout,
                       const SocketProtectCallback& protect_socket,
                       const std::function<bool()>& should_stop) {
    DialResult res;

    if (target_host.empty() || target_host.size() > 255) {
        res.error = "SOCKS5: target host name length out of range";
        return res;
    }
    if (target_port <= 0 || target_port > 65535) {
        res.error = "SOCKS5: target port out of range";
        return res;
    }

    // ---- TCP connect to the proxy itself ----------------------------------
    boost::asio::ip::tcp::resolver resolver(io);
    const auto resolved = yume::outbound::resolve_with_timeout(
        resolver, io, cfg.host, std::to_string(cfg.port), timeout, should_stop);
    if (resolved.cancelled) {
        res.cancelled = true;
        res.error = "proxy operation cancelled";
        return res;
    }
    if (resolved.timed_out) {
        res.timed_out = true;
        res.error = "proxy DNS resolution timed out";
        return res;
    }
    if (resolved.ec) {
        res.error = "could not resolve proxy '" + cfg.host + "': " +
                    resolved.ec.message();
        return res;
    }

    auto connect_result = yume::outbound::connect_with_timeout(
        sock, resolved.endpoints, io, timeout, protect_socket, should_stop);
    if (connect_result.cancelled) {
        res.cancelled = true;
        res.error = "proxy operation cancelled";
        return res;
    }
    if (connect_result.timed_out) {
        res.timed_out = true;
        res.error = "connect to proxy timed out";
        return res;
    }
    if (connect_result.ec) {
        res.error = "connect to proxy failed: " + connect_result.ec.message();
        return res;
    }

    // ---- Method negotiation (RFC 1928 §3) ---------------------------------
    // We offer both NO_AUTH and USERNAME/PASSWORD so a Tor without a
    // SocksAuth line accepts NO_AUTH and a hardened proxy that
    // requires creds picks USERNAME/PASSWORD.
    {
        std::uint8_t greet[4] = { kVer5, 0x02, kAuthNone, kAuthUserPass };
        std::size_t greet_len = cfg.username.empty() ? 3u : 4u;
        if (cfg.username.empty()) {
            greet[1] = 0x01;          // one method offered
            greet[2] = kAuthNone;
        }
        if (!write_all(sock, io, greet, greet_len, timeout, res.error,
                       res.cancelled, should_stop)) return res;
    }

    std::uint8_t method_reply[2]{};
    if (!read_exact(sock, io, method_reply, 2, timeout, res.error,
                    res.cancelled, should_stop)) return res;
    if (method_reply[0] != kVer5) {
        res.error = "proxy did not speak SOCKS5";
        return res;
    }
    if (method_reply[1] == 0xFF) {
        res.error = "proxy rejected all auth methods";
        return res;
    }
    if (method_reply[1] == kAuthUserPass) {
        if (cfg.username.empty()) {
            res.error = "proxy requires SOCKS5 auth but no credentials configured";
            return res;
        }
        if (cfg.username.size() > 255 || cfg.password.size() > 255) {
            res.error = "SOCKS5 username/password too long";
            return res;
        }
        std::string auth;
        auth.push_back(static_cast<char>(kAuthVer));
        auth.push_back(static_cast<char>(cfg.username.size()));
        auth.append(cfg.username);
        auth.push_back(static_cast<char>(cfg.password.size()));
        auth.append(cfg.password);
        if (!write_all(sock, io, auth.data(), auth.size(), timeout, res.error,
                       res.cancelled, should_stop)) return res;
        std::uint8_t auth_reply[2]{};
        if (!read_exact(sock, io, auth_reply, 2, timeout, res.error,
                        res.cancelled, should_stop)) return res;
        if (auth_reply[0] != kAuthVer || auth_reply[1] != 0x00) {
            res.error = "SOCKS5 authentication failed";
            return res;
        }
    } else if (method_reply[1] != kAuthNone) {
        res.error = "proxy chose an unsupported SOCKS5 auth method";
        return res;
    }

    // ---- CONNECT request (RFC 1928 §4) ------------------------------------
    // ATYP_DOMAIN is critical: it makes Tor resolve the hostname on the
    // proxy side, which is the only path that works for .onion. Even
    // for normal hostnames, leaking DNS through Tor is the right thing.
    std::string req;
    req.reserve(7 + target_host.size());
    req.push_back(static_cast<char>(kVer5));
    req.push_back(static_cast<char>(kCmdConnect));
    req.push_back(0x00);                                  // RSV
    req.push_back(static_cast<char>(kAtypDomain));
    req.push_back(static_cast<char>(target_host.size()));
    req.append(target_host);
    req.push_back(static_cast<char>((target_port >> 8) & 0xFF));
    req.push_back(static_cast<char>(target_port & 0xFF));
    if (!write_all(sock, io, req.data(), req.size(), timeout, res.error,
                   res.cancelled, should_stop)) return res;

    // Reply is `[VER REP RSV ATYP BND.ADDR BND.PORT]`. The BND fields
    // vary by ATYP — we just discard them.
    std::uint8_t hdr[4]{};
    if (!read_exact(sock, io, hdr, 4, timeout, res.error,
                    res.cancelled, should_stop)) return res;
    if (hdr[0] != kVer5) {
        res.error = "proxy reply had wrong version";
        return res;
    }
    if (hdr[1] != kRepSuccess) {
        res.error = std::string("proxy refused CONNECT: ") + socks5_reply_reason(hdr[1]);
        return res;
    }
    std::size_t skip = 0;
    switch (hdr[3]) {
        case kAtypIpv4:   skip = 4; break;
        case kAtypIpv6:   skip = 16; break;
        case kAtypDomain: {
            std::uint8_t dlen = 0;
            if (!read_exact(sock, io, &dlen, 1, timeout, res.error,
                            res.cancelled, should_stop)) return res;
            skip = dlen;
            break;
        }
        default:
            res.error = "proxy returned unknown ATYP";
            return res;
    }
    std::array<std::uint8_t, 256 + 2> bnd{};
    if (!read_exact(sock, io, bnd.data(), skip + 2, timeout, res.error,
                    res.cancelled, should_stop)) return res;

    res.ok = true;
    return res;
}

bool parse_proxy_url(std::string const& url, Config& out, std::string* err) {
    auto fail = [&](char const* msg) {
        if (err) *err = msg;
        return false;
    };
    if (url.empty()) { out = {}; return true; }
    std::string s = url;
    constexpr std::string_view scheme = "socks5://";
    if (s.rfind(scheme, 0) != 0) {
        return fail("only socks5:// proxies are supported");
    }
    s.erase(0, scheme.size());

    // optional user:pass@
    std::string userinfo;
    if (auto at = s.find('@'); at != std::string::npos) {
        userinfo = s.substr(0, at);
        s.erase(0, at + 1);
    }
    if (!userinfo.empty()) {
        auto colon = userinfo.find(':');
        if (colon == std::string::npos) {
            out.username = userinfo;
        } else {
            out.username = userinfo.substr(0, colon);
            out.password = userinfo.substr(colon + 1);
        }
    }

    auto colon = s.rfind(':');
    if (colon == std::string::npos) {
        return fail("proxy URL missing :port");
    }
    out.host = s.substr(0, colon);
    if (out.host.empty()) return fail("proxy URL missing host");
    try {
        out.port = std::stoi(s.substr(colon + 1));
    } catch (...) {
        return fail("proxy URL port is not a number");
    }
    if (out.port <= 0 || out.port > 65535) {
        return fail("proxy URL port out of range");
    }
    out.type = Type::Socks5;
    return true;
}

}  // namespace yume::outbound::proxy
