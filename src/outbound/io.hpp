#pragma once

/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * Neutral outbound async-I/O-with-timeout helpers and wire diagnostics.
 * Several are function templates or small inline helpers, so the cluster is
 * header-resident and can be shared by client and server-originated dials.
 */

#include <array>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include "core/protocol/protocol.hpp"
#include "core/stealth/cover_profile.hpp"
#include "outbound/socket_protection.hpp"

namespace yume::outbound {

// Typed failure from neutral outbound transport establishment. Presentation
// layers may translate this to CLI- or server-specific wording.
struct TransportError : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct IoOpResult {
    boost::system::error_code ec;
    bool timed_out{false};
    bool cancelled{false};
    std::size_t bytes{0};
};

struct ResolveOpResult : IoOpResult {
    boost::asio::ip::tcp::resolver::results_type endpoints;
};

using StopPredicate = std::function<bool()>;

inline constexpr std::chrono::milliseconds kStopPollInterval{10};

inline bool stop_is_requested(const StopPredicate& should_stop) noexcept {
    if (!should_stop) return false;
    try {
        return should_stop();
    } catch (...) {
        // Cancellation predicates cross an executor boundary. Treat a broken
        // embedder callback as stop intent so no exception can unwind io.run()
        // while asynchronous handlers still reference this helper's stack.
        return true;
    }
}

inline ResolveOpResult resolve_with_timeout(
        boost::asio::ip::tcp::resolver& resolver,
        boost::asio::io_context& io,
        const std::string& host,
        const std::string& service,
        std::chrono::milliseconds timeout,
        const StopPredicate& should_stop = {}) {
    ResolveOpResult res{};
    bool done = false;
    if (stop_is_requested(should_stop)) {
        res.cancelled = true;
        res.ec = boost::asio::error::operation_aborted;
        return res;
    }

    boost::asio::steady_timer deadline(io);
    deadline.expires_after(timeout);
    deadline.async_wait([&](const boost::system::error_code& ec) {
        if (!ec && !done) {
            res.timed_out = true;
            resolver.cancel();
        }
    });

    boost::asio::steady_timer stop_poll(io);
    std::function<void()> arm_stop_poll;
    arm_stop_poll = [&]() {
        if (!should_stop || done) return;
        stop_poll.expires_after(kStopPollInterval);
        stop_poll.async_wait([&](const boost::system::error_code& ec) {
            if (ec || done) return;
            if (stop_is_requested(should_stop)) {
                res.cancelled = true;
                resolver.cancel();
                return;
            }
            arm_stop_poll();
        });
    };
    arm_stop_poll();

    resolver.async_resolve(
        boost::asio::ip::tcp::v4(), host, service,
        [&](const boost::system::error_code& ec,
            boost::asio::ip::tcp::resolver::results_type endpoints) {
            res.ec = ec;
            res.endpoints = std::move(endpoints);
            done = true;
            (void)deadline.cancel();
            (void)stop_poll.cancel();
        });

    io.restart();
    io.run();
    return res;
}

template <typename AsyncStream, typename CancelFn>
IoOpResult read_exact_with_timeout(AsyncStream& stream,
                                  boost::asio::io_context& io,
                                  const boost::asio::mutable_buffer& buf,
                                  std::chrono::milliseconds timeout,
                                  CancelFn cancel,
                                  const StopPredicate& should_stop = {}) {
    IoOpResult res{};
    bool done = false;

    if (stop_is_requested(should_stop)) {
        res.cancelled = true;
        cancel();
        return res;
    }

    boost::asio::steady_timer timer(io);
    timer.expires_after(timeout);
    timer.async_wait([&](const boost::system::error_code& ec) {
        if (!ec && !done) {
            res.timed_out = true;
            cancel();
        }
    });

    boost::asio::steady_timer stop_poll(io);
    std::function<void()> arm_stop_poll;
    arm_stop_poll = [&]() {
        if (!should_stop || done) return;
        stop_poll.expires_after(kStopPollInterval);
        stop_poll.async_wait([&](const boost::system::error_code& ec) {
            if (ec || done) return;
            if (stop_is_requested(should_stop)) {
                res.cancelled = true;
                cancel();
                return;
            }
            arm_stop_poll();
        });
    };
    arm_stop_poll();

    boost::asio::async_read(stream, buf, [&](const boost::system::error_code& ec, std::size_t bytes) {
        res.ec = ec;
        res.bytes = bytes;
        done = true;
        (void)timer.cancel();
        (void)stop_poll.cancel();
    });

    io.restart();
    io.run();
    return res;
}

template <typename AsyncStream, typename CancelFn>
IoOpResult read_some_with_timeout(AsyncStream& stream,
                                  boost::asio::io_context& io,
                                  const boost::asio::mutable_buffer& buf,
                                  std::chrono::milliseconds timeout,
                                  CancelFn cancel,
                                  const StopPredicate& should_stop = {}) {
    IoOpResult res{};
    bool done = false;
    if (stop_is_requested(should_stop)) {
        res.cancelled = true;
        cancel();
        return res;
    }
    boost::asio::steady_timer timer(io);
    timer.expires_after(timeout);
    timer.async_wait([&](const boost::system::error_code& ec) {
        if (!ec && !done) {
            res.timed_out = true;
            cancel();
        }
    });
    boost::asio::steady_timer stop_poll(io);
    std::function<void()> arm_stop_poll;
    arm_stop_poll = [&]() {
        if (!should_stop || done) return;
        stop_poll.expires_after(kStopPollInterval);
        stop_poll.async_wait([&](const boost::system::error_code& ec) {
            if (ec || done) return;
            if (stop_is_requested(should_stop)) {
                res.cancelled = true;
                cancel();
                return;
            }
            arm_stop_poll();
        });
    };
    arm_stop_poll();
    stream.async_read_some(buf, [&](const boost::system::error_code& ec,
                                    std::size_t bytes) {
        res.ec = ec;
        res.bytes = bytes;
        done = true;
        (void)timer.cancel();
        (void)stop_poll.cancel();
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
                                              std::vector<uint8_t>* prefetched,
                                              const StopPredicate& should_stop = {}) {
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
        cancel,
        should_stop);
    tail.bytes += copied;
    return tail;
}

inline IoOpResult connect_with_timeout(boost::asio::ip::tcp::socket& sock,
                                       const boost::asio::ip::tcp::resolver::results_type& endpoints,
                                       boost::asio::io_context& io,
                                       std::chrono::milliseconds timeout,
                                       const SocketProtectCallback& protect_socket = {},
                                       const StopPredicate& should_stop = {}) {
    IoOpResult res{};
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    if (endpoints.empty()) {
        res.ec = boost::asio::error::host_not_found;
        return res;
    }

    for (const auto& entry : endpoints) {
        if (stop_is_requested(should_stop)) {
            boost::system::error_code ignored;
            sock.close(ignored);
            res.cancelled = true;
            res.ec = boost::asio::error::operation_aborted;
            return res;
        }
        boost::system::error_code ignored;
        sock.close(ignored);

        boost::system::error_code open_ec;
        sock.open(entry.endpoint().protocol(), open_ec);
        if (open_ec) {
            res.ec = open_ec;
            continue;
        }

        if (protect_socket) {
            bool protected_ok = false;
            try {
                protected_ok = protect_socket(
                    static_cast<std::intptr_t>(sock.native_handle()));
            } catch (...) {
                protected_ok = false;
            }
            if (!protected_ok) {
                sock.close(ignored);
                res.ec = boost::system::errc::make_error_code(
                    boost::system::errc::permission_denied);
                return res;
            }
        }

        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            sock.close(ignored);
            res.timed_out = true;
            res.ec = boost::asio::error::timed_out;
            return res;
        }

        bool done = false;
        boost::asio::steady_timer timer(io);
        timer.expires_at(deadline);
        timer.async_wait([&](const boost::system::error_code& ec) {
            if (!ec && !done) {
                res.timed_out = true;
                boost::system::error_code cancel_ec;
                sock.cancel(cancel_ec);
                sock.close(cancel_ec);
            }
        });
        boost::asio::steady_timer stop_poll(io);
        std::function<void()> arm_stop_poll;
        arm_stop_poll = [&]() {
            if (!should_stop || done) return;
            stop_poll.expires_after(kStopPollInterval);
            stop_poll.async_wait([&](const boost::system::error_code& ec) {
                if (ec || done) return;
                if (stop_is_requested(should_stop)) {
                    res.cancelled = true;
                    boost::system::error_code cancel_ec;
                    sock.cancel(cancel_ec);
                    sock.close(cancel_ec);
                    return;
                }
                arm_stop_poll();
            });
        };
        arm_stop_poll();
        sock.async_connect(entry.endpoint(), [&](const boost::system::error_code& ec) {
            res.ec = ec;
            done = true;
            (void)timer.cancel();
            (void)stop_poll.cancel();
        });

        io.restart();
        io.run();
        if (!res.ec || res.timed_out || res.cancelled) {
            return res;
        }
    }
    return res;
}

inline IoOpResult handshake_with_timeout(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
                                         boost::asio::io_context& io,
                                         std::chrono::milliseconds timeout,
                                         const StopPredicate& should_stop = {}) {
    IoOpResult res{};
    bool done = false;

    if (stop_is_requested(should_stop)) {
        res.cancelled = true;
        boost::system::error_code ignored;
        stream.lowest_layer().close(ignored);
        return res;
    }

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

    boost::asio::steady_timer stop_poll(io);
    std::function<void()> arm_stop_poll;
    arm_stop_poll = [&]() {
        if (!should_stop || done) return;
        stop_poll.expires_after(kStopPollInterval);
        stop_poll.async_wait([&](const boost::system::error_code& ec) {
            if (ec || done) return;
            if (stop_is_requested(should_stop)) {
                res.cancelled = true;
                boost::system::error_code ignored;
                stream.lowest_layer().cancel(ignored);
                stream.lowest_layer().close(ignored);
                return;
            }
            arm_stop_poll();
        });
    };
    arm_stop_poll();

    stream.async_handshake(boost::asio::ssl::stream_base::client,
                           [&](const boost::system::error_code& ec) {
                               res.ec = ec;
                               done = true;
                               (void)timer.cancel();
                               (void)stop_poll.cancel();
                           });

    io.restart();
    io.run();

    // The cover profile offers a browser-shaped version range, which for a
    // Chrome-like ClientHello means advertising TLS 1.2 as well as 1.3. Accept
    // only the version the profile says the handshake must end on, so shaping
    // the offer never becomes a downgrade on the carrier. Fail closed.
    if (!res.ec && !res.timed_out && !res.cancelled) {
        const std::uint16_t required =
            yume::cover_profile::active().tls_required_version;
        if (required != 0 &&
            SSL_version(stream.native_handle()) != static_cast<int>(required)) {
            boost::system::error_code ignored;
            stream.lowest_layer().close(ignored);
            res.ec = boost::system::errc::make_error_code(
                boost::system::errc::protocol_not_supported);
        }
    }
    return res;
}

template <typename AsyncStream, typename CancelFn>
IoOpResult write_all_with_timeout(AsyncStream& stream,
                                  boost::asio::io_context& io,
                                  const boost::asio::const_buffer& buf,
                                  std::chrono::milliseconds timeout,
                                  CancelFn cancel,
                                  const StopPredicate& should_stop = {}) {
    IoOpResult res{};
    bool done = false;

    if (stop_is_requested(should_stop)) {
        res.cancelled = true;
        cancel();
        return res;
    }

    boost::asio::steady_timer timer(io);
    timer.expires_after(timeout);
    timer.async_wait([&](const boost::system::error_code& ec) {
        if (!ec && !done) {
            res.timed_out = true;
            cancel();
        }
    });

    boost::asio::steady_timer stop_poll(io);
    std::function<void()> arm_stop_poll;
    arm_stop_poll = [&]() {
        if (!should_stop || done) return;
        stop_poll.expires_after(kStopPollInterval);
        stop_poll.async_wait([&](const boost::system::error_code& ec) {
            if (ec || done) return;
            if (stop_is_requested(should_stop)) {
                res.cancelled = true;
                cancel();
                return;
            }
            arm_stop_poll();
        });
    };
    arm_stop_poll();

    boost::asio::async_write(stream, buf, [&](const boost::system::error_code& ec, std::size_t bytes) {
        res.ec = ec;
        res.bytes = bytes;
        done = true;
        (void)timer.cancel();
        (void)stop_poll.cancel();
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
                                   CancelFn cancel,
                                   const StopPredicate& should_stop = {}) {
    IoOpResult res{};
    if (!data) {
        res.ec = boost::asio::error::invalid_argument;
        return res;
    }

    bool done = false;
    if (stop_is_requested(should_stop)) {
        res.cancelled = true;
        cancel();
        return res;
    }
    const std::string delim(delimiter);
    boost::asio::steady_timer timer(io);
    timer.expires_after(timeout);
    timer.async_wait([&](const boost::system::error_code& ec) {
        if (!ec && !done) {
            res.timed_out = true;
            cancel();
        }
    });
    boost::asio::steady_timer stop_poll(io);
    std::function<void()> arm_stop_poll;
    arm_stop_poll = [&]() {
        if (!should_stop || done) return;
        stop_poll.expires_after(kStopPollInterval);
        stop_poll.async_wait([&](const boost::system::error_code& ec) {
            if (ec || done) return;
            if (stop_is_requested(should_stop)) {
                res.cancelled = true;
                cancel();
                return;
            }
            arm_stop_poll();
        });
    };
    arm_stop_poll();

    boost::asio::async_read_until(stream, boost::asio::dynamic_buffer(*data), delim,
                                  [&](const boost::system::error_code& ec, std::size_t bytes) {
                                      res.ec = ec;
                                      res.bytes = bytes;
                                      done = true;
                                      (void)timer.cancel();
                                      (void)stop_poll.cancel();
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
    if (len > protocol::kMaxFramePayloadBytes) {
        return false;
    }
    if (type < protocol::AUTH || type > protocol::SOPEN) {
        return false;
    }
    return true;
}

template <typename AsyncStream>
inline protocol::Frame read_frame_with_timeout(AsyncStream& stream,
                                              boost::asio::io_context& io,
                                              std::chrono::milliseconds timeout,
                                              const char* what,
                                              const std::string& host,
                                              int port,
                                              bool tls_handshake_succeeded,
                                              std::vector<uint8_t>* prefetched = nullptr,
                                              const StopPredicate& should_stop = {}) {
    const std::string operation = what ? what : "frame";
    std::array<uint8_t, 8> header_buf{};
    auto cancel = [&]() {
        if constexpr (requires { stream.cancel_and_close(); }) {
            stream.cancel_and_close();
        } else {
            boost::system::error_code ignored;
            stream.lowest_layer().cancel(ignored);
            stream.lowest_layer().close(ignored);
        }
    };

    IoOpResult hr = read_exact_with_timeout_prefetched(
        stream,
        io,
        boost::asio::buffer(header_buf),
        timeout,
        cancel,
        prefetched,
        should_stop);
    if (hr.cancelled) {
        throw TransportError("operation cancelled while reading " + operation);
    }
    if (hr.timed_out) {
        if (what && std::strcmp(what, "server info") == 0) {
            throw TransportError("timed out reading server info from " + host +
                                 ":" + std::to_string(port));
        }
        std::string hint = endpoint_hint_tls(tls_handshake_succeeded, nullptr, 0);
        throw TransportError(std::string("outbound peer read failed (") + host + ":" + std::to_string(port) +
                         "; timed out waiting for " + operation +
                         "; classified as: " + hint + ")");
    }
    if (hr.ec) {
        std::string hint = endpoint_hint_tls(tls_handshake_succeeded, header_buf.data(), header_buf.size());
        throw TransportError(std::string("outbound peer closed before frame header (") + host + ":" + std::to_string(port) +
                         "; failed to read " + operation +
                         ": " + hr.ec.message() + "; classified as: " + hint + ")");
    }
    if (!looks_like_yume_header(header_buf)) {
        std::string hint = endpoint_hint_tls(tls_handshake_succeeded, header_buf.data(), header_buf.size());
        throw TransportError(std::string("invalid outbound frame header (") + host + ":" + std::to_string(port) +
                         "; unexpected " + operation +
                         " header; ascii=\"" + ascii_preview(header_buf.data(), header_buf.size()) +
                         "\" hex=" + hex_preview(header_buf.data(), header_buf.size()) +
                         "; classified as: " + hint + ")");
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
            prefetched,
            should_stop);
        if (pr.cancelled) {
            throw TransportError(
                "operation cancelled while reading " + operation);
        }
        if (pr.timed_out) {
            throw TransportError(std::string("outbound frame payload read failed (") + host + ":" + std::to_string(port) +
                             "; timed out reading " + operation +
                             " payload; classified as: " +
                             endpoint_hint_tls(tls_handshake_succeeded, nullptr, 0) + ")");
        }
        if (pr.ec) {
            throw TransportError(std::string("outbound peer closed before frame payload (") + host + ":" + std::to_string(port) +
                             "; failed reading " + operation +
                             " payload: " + pr.ec.message() + "; classified as: " +
                             endpoint_hint_tls(tls_handshake_succeeded, nullptr, 0) + ")");
        }
    }
    return frame;
}

}  // namespace yume::outbound
