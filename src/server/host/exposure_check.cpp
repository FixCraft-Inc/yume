/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/host/exposure_check.hpp"

#include <array>
#include <chrono>
#include <cstring>

#include <boost/asio.hpp>

namespace yume::server::host {
namespace {

bool http_response_has_cf_ray(const std::string& response) {
    return response.find("cf-ray:") != std::string::npos ||
           response.find("CF-RAY:") != std::string::npos ||
           response.find("server: cloudflare") != std::string::npos ||
           response.find("Server: cloudflare") != std::string::npos;
}

}  // namespace

ExposureResult probe_exposure(const std::string& hostname, int port) {
    ExposureResult result;
    result.hostname = hostname;
    if (hostname.empty()) {
        result.kind = ExposureKind::Unknown;
        result.detail = "no hostname configured";
        return result;
    }

    boost::asio::io_context io;
    boost::system::error_code ec;
    boost::asio::ip::tcp::resolver resolver(io);
    const auto endpoints = resolver.resolve(hostname, std::to_string(port), ec);
    if (ec || endpoints.empty()) {
        result.kind = ExposureKind::Blocked;
        result.detail = "dns resolve failed: " + ec.message();
        return result;
    }

    boost::asio::ip::tcp::socket tcp(io);
    boost::asio::steady_timer timer(io);
    bool timed_out = false;
    timer.expires_after(std::chrono::seconds(5));
    timer.async_wait([&](const boost::system::error_code& tec) {
        if (!tec) {
            timed_out = true;
            boost::system::error_code cancel_ec;
            tcp.cancel(cancel_ec);
        }
    });
    boost::asio::async_connect(tcp, endpoints,
                               [&](const boost::system::error_code& cec, const boost::asio::ip::tcp::endpoint&) {
                                   ec = cec;
                                   timer.cancel();
                               });
    io.run();

    if (timed_out || ec) {
        result.kind = ExposureKind::Blocked;
        result.detail = timed_out ? "tcp connect timed out" : ("tcp connect failed: " + ec.message());
        return result;
    }

    const std::string request =
        "GET / HTTP/1.1\r\nHost: " + hostname + "\r\nConnection: close\r\n\r\n";
    ec.clear();
    timed_out = false;
    io.restart();
    timer.expires_after(std::chrono::seconds(3));
    timer.async_wait([&](const boost::system::error_code& tec) {
        if (!tec) {
            timed_out = true;
            boost::system::error_code cancel_ec;
            tcp.cancel(cancel_ec);
        }
    });
    boost::asio::async_write(tcp, boost::asio::buffer(request),
                             [&](const boost::system::error_code& wec, std::size_t) {
                                 ec = wec;
                                 timer.cancel();
                             });
    io.run();
    if (timed_out || ec) {
        boost::system::error_code close_ec;
        tcp.close(close_ec);
        result.kind = ExposureKind::DirectTcp;
        result.detail = timed_out ? "tcp open but http write timed out (likely raw tcp passthrough)"
                                  : "tcp open but http write failed (likely raw tcp passthrough)";
        return result;
    }

    std::array<char, 4096> response_buf{};
    std::size_t n = 0;
    ec.clear();
    timed_out = false;
    io.restart();
    timer.expires_after(std::chrono::seconds(3));
    timer.async_wait([&](const boost::system::error_code& tec) {
        if (!tec) {
            timed_out = true;
            boost::system::error_code cancel_ec;
            tcp.cancel(cancel_ec);
        }
    });
    tcp.async_read_some(boost::asio::buffer(response_buf),
                        [&](const boost::system::error_code& rec, std::size_t bytes) {
                            ec = rec;
                            n = bytes;
                            timer.cancel();
                        });
    io.run();
    boost::system::error_code close_ec;
    tcp.close(close_ec);
    if (timed_out || (ec && n == 0)) {
        result.kind = ExposureKind::DirectTcp;
        result.detail = timed_out ? "tcp reachable but http read timed out (likely raw tcp passthrough)"
                                  : "tcp reachable but http read failed (likely raw tcp passthrough)";
        return result;
    }

    std::string response(response_buf.data(), n);

    if (response.rfind("HTTP/", 0) != 0) {
        result.kind = ExposureKind::DirectTcp;
        result.detail = "tcp reachable; response is not http (yume stealth compatible)";
        return result;
    }

    if (http_response_has_cf_ray(response)) {
        result.kind = ExposureKind::CfHttpProxy;
        result.detail = "cloudflare http proxy detected; yume tls carrier will not work through orange-cloud http mode";
        return result;
    }

    result.kind = ExposureKind::DirectTcp;
    result.detail = "direct tcp with http response (not cloudflare http proxy)";
    return result;
}

}  // namespace yume::server::host
