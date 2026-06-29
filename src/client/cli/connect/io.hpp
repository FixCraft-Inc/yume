#pragma once

/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * CLI low-level async-I/O-with-timeout helpers and wire-inspection
 * diagnostics, extracted verbatim from client/cli/entry.cpp. Several of these
 * are function templates or small inline helpers, so the cluster is
 * header-resident. Included by CLI connection/auth code.
 */

#include <array>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include "core/protocol/protocol.hpp"

namespace yume::client {

// Shared CLI fatal-error exception (used here by read_frame_with_timeout and
// throughout entry.cpp). Lives in this header because connect/io.hpp is included
// by entry.cpp, so every call site sees the one definition.
struct FatalError : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct IoOpResult {
    boost::system::error_code ec;
    bool timed_out{false};
    std::size_t bytes{0};
};

template <typename AsyncStream, typename CancelFn>
IoOpResult read_exact_with_timeout(AsyncStream& stream,
                                  boost::asio::io_context& io,
                                  const boost::asio::mutable_buffer& buf,
                                  std::chrono::milliseconds timeout,
                                  CancelFn cancel) {
    IoOpResult res{};
    bool done = false;

    boost::asio::steady_timer timer(io);
    timer.expires_after(timeout);
    timer.async_wait([&](const boost::system::error_code& ec) {
        if (!ec && !done) {
            res.timed_out = true;
            cancel();
        }
    });

    boost::asio::async_read(stream, buf, [&](const boost::system::error_code& ec, std::size_t bytes) {
        res.ec = ec;
        res.bytes = bytes;
        done = true;
        (void)timer.cancel();
    });

    io.restart();
    io.run();
    return res;
}

template <typename AsyncStream, typename CancelFn>
IoOpResult read_exact_with_timeout_prefetched(AsyncStream& stream,
                                              boost::asio::io_context& io,
                                              const boost::asio::mutable_buffer& buf,
                                              std::chrono::milliseconds timeout,
                                              CancelFn cancel,
                                              std::vector<uint8_t>* prefetched) {
    IoOpResult res{};
    auto* out = static_cast<uint8_t*>(buf.data());
    const std::size_t target = buf.size();
    std::size_t copied = 0;

    if (prefetched && !prefetched->empty()) {
        copied = std::min<std::size_t>(target, prefetched->size());
        std::copy_n(prefetched->begin(), copied, out);
        prefetched->erase(prefetched->begin(), prefetched->begin() + static_cast<std::ptrdiff_t>(copied));
    }

    if (copied == target) {
        res.bytes = copied;
        return res;
    }

    IoOpResult tail = read_exact_with_timeout(
        stream,
        io,
        boost::asio::buffer(out + copied, target - copied),
        timeout,
        cancel);
    tail.bytes += copied;
    return tail;
}

inline IoOpResult connect_with_timeout(boost::asio::ip::tcp::socket& sock,
                                       const boost::asio::ip::tcp::resolver::results_type& endpoints,
                                       boost::asio::io_context& io,
                                       std::chrono::milliseconds timeout) {
    IoOpResult res{};
    bool done = false;

    boost::asio::steady_timer timer(io);
    timer.expires_after(timeout);
    timer.async_wait([&](const boost::system::error_code& ec) {
        if (!ec && !done) {
            res.timed_out = true;
            boost::system::error_code ignored;
            sock.cancel(ignored);
            sock.close(ignored);
        }
    });

    boost::asio::async_connect(sock, endpoints,
                               [&](const boost::system::error_code& ec, const boost::asio::ip::tcp::endpoint&) {
                                   res.ec = ec;
                                   done = true;
                                   (void)timer.cancel();
                               });

    io.restart();
    io.run();
    return res;
}

inline IoOpResult handshake_with_timeout(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
                                         boost::asio::io_context& io,
                                         std::chrono::milliseconds timeout) {
    IoOpResult res{};
    bool done = false;

    boost::asio::steady_timer timer(io);
    timer.expires_after(timeout);
    timer.async_wait([&](const boost::system::error_code& ec) {
        if (!ec && !done) {
            res.timed_out = true;
            boost::system::error_code ignored;
            stream.lowest_layer().cancel(ignored);
            stream.lowest_layer().close(ignored);
        }
    });

    stream.async_handshake(boost::asio::ssl::stream_base::client,
                           [&](const boost::system::error_code& ec) {
                               res.ec = ec;
                               done = true;
                               (void)timer.cancel();
                           });

    io.restart();
    io.run();
    return res;
}

template <typename AsyncStream, typename CancelFn>
IoOpResult write_all_with_timeout(AsyncStream& stream,
                                  boost::asio::io_context& io,
                                  const boost::asio::const_buffer& buf,
                                  std::chrono::milliseconds timeout,
                                  CancelFn cancel) {
    IoOpResult res{};
    bool done = false;

    boost::asio::steady_timer timer(io);
    timer.expires_after(timeout);
    timer.async_wait([&](const boost::system::error_code& ec) {
        if (!ec && !done) {
            res.timed_out = true;
            cancel();
        }
    });

    boost::asio::async_write(stream, buf, [&](const boost::system::error_code& ec, std::size_t bytes) {
        res.ec = ec;
        res.bytes = bytes;
        done = true;
        (void)timer.cancel();
    });

    io.restart();
    io.run();
    return res;
}

template <typename AsyncStream, typename CancelFn>
IoOpResult read_until_with_timeout(AsyncStream& stream,
                                   boost::asio::io_context& io,
                                   std::string* data,
                                   std::string_view delimiter,
                                   std::chrono::milliseconds timeout,
                                   CancelFn cancel) {
    IoOpResult res{};
    if (!data) {
        res.ec = boost::asio::error::invalid_argument;
        return res;
    }

    bool done = false;
    const std::string delim(delimiter);
    boost::asio::steady_timer timer(io);
    timer.expires_after(timeout);
    timer.async_wait([&](const boost::system::error_code& ec) {
        if (!ec && !done) {
            res.timed_out = true;
            cancel();
        }
    });

    boost::asio::async_read_until(stream, boost::asio::dynamic_buffer(*data), delim,
                                  [&](const boost::system::error_code& ec, std::size_t bytes) {
                                      res.ec = ec;
                                      res.bytes = bytes;
                                      done = true;
                                      (void)timer.cancel();
                                  });

    io.restart();
    io.run();
    return res;
}

inline std::string hex_preview(const uint8_t* data, std::size_t len, std::size_t max = 16) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    std::size_t n = std::min(len, max);
    for (std::size_t i = 0; i < n; ++i) {
        if (i) {
            oss << ' ';
        }
        oss << std::setw(2) << static_cast<unsigned int>(data[i]);
    }
    if (len > max) {
        oss << " ...";
    }
    return oss.str();
}

inline std::string ascii_preview(const uint8_t* data, std::size_t len, std::size_t max = 64) {
    std::string out;
    std::size_t n = std::min(len, max);
    out.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        unsigned char c = data[i];
        if (c >= 0x20 && c < 0x7f) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('.');
        }
    }
    if (len > max) {
        out += "...";
    }
    return out;
}

inline std::string classify_plaintext_prefix(const uint8_t* data, std::size_t len) {
    if (!data || len == 0) {
        return {};
    }
    const auto starts_with = [&](const char* lit) {
        std::size_t n = std::strlen(lit);
        return len >= n && std::memcmp(data, lit, n) == 0;
    };
    if (starts_with("SSH-")) {
        return "SSH";
    }
    if (starts_with("HTTP/")) {
        return "HTTP";
    }
    if (starts_with("PRI * HTTP/2.0")) {
        return "HTTP/2";
    }
    if (starts_with("GET ") || starts_with("POST ") || starts_with("HEAD ") || starts_with("PUT ") || starts_with("OPTIONS ")) {
        return "HTTP";
    }
    return {};
}

inline std::string classify_http2_frame_prefix(const uint8_t* data, std::size_t len) {
    // Recognize a short HTTP/2 SETTINGS frame prefix.
    if (!data || len < 8) {
        return {};
    }
    uint8_t type = data[3];
    uint8_t flags = data[4];
    bool stream0_prefix = (data[5] == 0x00 && data[6] == 0x00 && data[7] == 0x00);
    if (type == 0x04 && flags == 0x00 && stream0_prefix) {
        return "HTTP/2";
    }
    return {};
}

inline std::string endpoint_hint_tls(bool tls_handshake_succeeded,
                                     const uint8_t* prefix,
                                     std::size_t prefix_len) {
    std::string plain = classify_plaintext_prefix(prefix, prefix_len);
    if (!plain.empty()) {
        if (tls_handshake_succeeded) {
            return (plain == "HTTP" || plain == "HTTP/2") ? ("HTTPS (" + plain + ")") : ("TLS (" + plain + ")");
        }
        return plain;
    }

    if (tls_handshake_succeeded) {
        std::string h2 = classify_http2_frame_prefix(prefix, prefix_len);
        if (!h2.empty()) {
            return "HTTPS (" + h2 + ")";
        }
        return "TLS (likely HTTPS)";
    }
    return "unknown";
}

inline bool looks_like_yume_header(const std::array<uint8_t, 8>& header) {
    uint32_t len = (static_cast<uint32_t>(header[0]) << 24) |
                   (static_cast<uint32_t>(header[1]) << 16) |
                   (static_cast<uint32_t>(header[2]) << 8) |
                   (static_cast<uint32_t>(header[3]));
    uint8_t type = header[4];
    if (len > 16U * 1024U * 1024U) {
        return false;
    }
    if (type < protocol::AUTH || type > protocol::SOPEN) {
        return false;
    }
    return true;
}

inline protocol::Frame read_frame_with_timeout(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
                                              boost::asio::io_context& io,
                                              std::chrono::milliseconds timeout,
                                              const char* what,
                                              const std::string& host,
                                              int port,
                                              bool tls_handshake_succeeded,
                                              std::vector<uint8_t>* prefetched = nullptr) {
    std::array<uint8_t, 8> header_buf{};
    auto cancel = [&]() {
        boost::system::error_code ignored;
        stream.lowest_layer().cancel(ignored);
        stream.lowest_layer().close(ignored);
    };

    IoOpResult hr = read_exact_with_timeout_prefetched(
        stream,
        io,
        boost::asio::buffer(header_buf),
        timeout,
        cancel,
        prefetched);
    if (hr.timed_out) {
        if (what && std::strcmp(what, "server info") == 0) {
            throw FatalError(std::string("timed out waiting for server confirmation (") + host + ":" + std::to_string(port) +
                             "; inner crypto negotiation may be overloaded). try again or lower inner KDF cost");
        }
        std::string hint = endpoint_hint_tls(tls_handshake_succeeded, nullptr, 0);
        throw FatalError(std::string("this endpoint is not a yume server (") + host + ":" + std::to_string(port) +
                         "; timed out waiting for " + what +
                         "); please check the origin and try again (endpoint identified as: " + hint + ")");
    }
    if (hr.ec) {
        std::string hint = endpoint_hint_tls(tls_handshake_succeeded, header_buf.data(), header_buf.size());
        throw FatalError(std::string("this endpoint is not a yume server (") + host + ":" + std::to_string(port) +
                         "; failed to read " + what +
                         ": " + hr.ec.message() + "); please check the origin and try again (endpoint identified as: " + hint + ")");
    }
    if (!looks_like_yume_header(header_buf)) {
        std::string hint = endpoint_hint_tls(tls_handshake_succeeded, header_buf.data(), header_buf.size());
        throw FatalError(std::string("this endpoint is not a yume server (") + host + ":" + std::to_string(port) +
                         "; unexpected " + what +
                         " header; ascii=\"" + ascii_preview(header_buf.data(), header_buf.size()) +
                         "\" hex=" + hex_preview(header_buf.data(), header_buf.size()) +
                         "); please check the origin and try again (endpoint identified as: " + hint + ")");
    }

    uint32_t len = (static_cast<uint32_t>(header_buf[0]) << 24) |
                   (static_cast<uint32_t>(header_buf[1]) << 16) |
                   (static_cast<uint32_t>(header_buf[2]) << 8) |
                   (static_cast<uint32_t>(header_buf[3]));
    protocol::Frame frame{};
    frame.header.len = len;
    frame.header.type = header_buf[4];
    frame.header.stream_id = header_buf[5];
    frame.header.flags = static_cast<uint16_t>(header_buf[6] << 8) |
                         static_cast<uint16_t>(header_buf[7]);

    frame.payload.resize(len);
    if (len > 0) {
        IoOpResult pr = read_exact_with_timeout_prefetched(
            stream,
            io,
            boost::asio::buffer(frame.payload),
            timeout,
            cancel,
            prefetched);
        if (pr.timed_out) {
            throw FatalError(std::string("this endpoint is not a yume server (") + host + ":" + std::to_string(port) +
                             "; timed out reading " + what +
                             " payload); please check the origin and try again (endpoint identified as: " +
                             endpoint_hint_tls(tls_handshake_succeeded, nullptr, 0) + ")");
        }
        if (pr.ec) {
            throw FatalError(std::string("this endpoint is not a yume server (") + host + ":" + std::to_string(port) +
                             "; failed reading " + what +
                             " payload: " + pr.ec.message() + "); please check the origin and try again (endpoint identified as: " +
                             endpoint_hint_tls(tls_handshake_succeeded, nullptr, 0) + ")");
        }
    }
    return frame;
}

}  // namespace yume::client
