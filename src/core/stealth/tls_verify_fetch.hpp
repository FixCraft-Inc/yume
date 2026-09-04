/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * HTTP fetch used by the optional TLS fingerprint diagnostic
 * (`openssl-diagnostic` plus `tls_fingerprint_verify`). It talks to a
 * third-party echo endpoint over a connection the operator named, so the
 * response is untrusted input on a path that is not part of the tunnel. Every
 * loop here is bounded by VerifyFetchLimits: a redirected or hostile endpoint
 * must not be able to exhaust or stall the client.
 *
 * Internal to core/stealth. Not installed and not a public interface; it lives
 * in a header only so the bounds can be tested against a scripted stream
 * instead of a live network endpoint.
 */

#pragma once

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include <boost/asio/buffer.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>

#include "core/stealth/http_profile.hpp"

namespace yume::tls_stealth::verify_fetch {

// Bounds for one diagnostic fetch. The expected response is a small JSON
// object describing the ClientHello the endpoint observed, so these are
// generous ceilings rather than protocol limits.
struct VerifyFetchLimits {
    // HTTP/1.1: total bytes accepted before the connection is abandoned. The
    // body is read to EOF, so without this a `Connection: close` endpoint that
    // never closes streams forever.
    std::size_t max_response_bytes{512U * 1024U};
    // HTTP/2: total DATA bytes accumulated for stream 1.
    std::size_t max_body_bytes{256U * 1024U};
    // HTTP/2: largest frame payload accepted. We advertise empty SETTINGS, so
    // RFC 7540 6.5.2 defaults apply and a peer must not exceed 16384.
    std::size_t max_frame_payload{16384U};
    // HTTP/2: frames read before END_STREAM must arrive. Bounds an endpoint
    // that answers with an unending stream of SETTINGS or PING.
    std::size_t max_frames{256U};
    // Wall-clock ceiling for the whole exchange, checked between reads. The
    // caller additionally sets a receive timeout on the socket so a single
    // blocking read cannot outlive it.
    std::chrono::steady_clock::time_point deadline{
        std::chrono::steady_clock::time_point::max()};
};

inline void check_deadline(const VerifyFetchLimits& limits) {
    if (std::chrono::steady_clock::now() > limits.deadline) {
        throw std::runtime_error(
            "TLS fingerprint verification exceeded its deadline");
    }
}

struct VerificationEndpoint {
    std::string host;
    std::string authority;
    std::string path;
    uint16_t port{443};
};

inline std::string trim_copy(std::string value) {
    auto not_space = [](unsigned char ch) { return std::isspace(ch) == 0; };
    auto begin = std::find_if(value.begin(), value.end(), not_space);
    auto end = std::find_if(value.rbegin(), value.rend(), not_space).base();
    if (begin >= end) {
        return {};
    }
    return std::string(begin, end);
}

inline VerificationEndpoint parse_verification_endpoint(const std::string& input, uint16_t default_port) {
    std::string value = trim_copy(input);
    if (value.empty()) {
        throw std::runtime_error("TLS fingerprint test endpoint is empty");
    }
    const std::string https_prefix = "https://";
    const std::string http_prefix = "http://";
    if (value.rfind(https_prefix, 0) == 0) {
        value.erase(0, https_prefix.size());
    } else if (value.rfind(http_prefix, 0) == 0) {
        value.erase(0, http_prefix.size());
    }

    VerificationEndpoint endpoint;
    endpoint.port = default_port;

    const std::size_t slash = value.find('/');
    std::string authority = slash == std::string::npos ? value : value.substr(0, slash);
    endpoint.path = slash == std::string::npos ? "/api/all" : value.substr(slash);
    if (endpoint.path.empty()) {
        endpoint.path = "/api/all";
    } else if (endpoint.path.front() != '/') {
        endpoint.path.insert(endpoint.path.begin(), '/');
    }
    if (authority.empty()) {
        throw std::runtime_error("TLS fingerprint test endpoint is missing a host");
    }

    if (authority.front() == '[') {
        const std::size_t close = authority.find(']');
        if (close == std::string::npos) {
            throw std::runtime_error("Invalid IPv6 TLS fingerprint test endpoint");
        }
        endpoint.host = authority.substr(1, close - 1);
        if (close + 1 < authority.size()) {
            if (authority[close + 1] != ':') {
                throw std::runtime_error("Invalid TLS fingerprint test endpoint port");
            }
            endpoint.port = static_cast<uint16_t>(std::stoul(authority.substr(close + 2)));
        }
    } else {
        const std::size_t first_colon = authority.find(':');
        const std::size_t last_colon = authority.rfind(':');
        if (first_colon != std::string::npos && first_colon == last_colon) {
            endpoint.host = authority.substr(0, first_colon);
            endpoint.port = static_cast<uint16_t>(std::stoul(authority.substr(first_colon + 1)));
        } else {
            endpoint.host = authority;
        }
    }

    if (endpoint.host.empty()) {
        throw std::runtime_error("TLS fingerprint test endpoint is missing a host");
    }
    endpoint.authority = endpoint.host;
    if (endpoint.port != 443) {
        endpoint.authority += ":" + std::to_string(endpoint.port);
    }
    return endpoint;
}

inline void hpack_encode_integer(std::vector<uint8_t>& out,
                                 uint32_t value,
                                 uint8_t prefix_bits,
                                 uint8_t prefix_mask) {
    const uint8_t prefix_max = static_cast<uint8_t>((1u << prefix_bits) - 1u);
    out.push_back(prefix_mask);
    if (value < prefix_max) {
        out.back() |= static_cast<uint8_t>(value);
        return;
    }
    out.back() |= prefix_max;
    value -= prefix_max;
    while (value >= 128) {
        out.push_back(static_cast<uint8_t>((value & 0x7fu) | 0x80u));
        value >>= 7;
    }
    out.push_back(static_cast<uint8_t>(value));
}

inline void hpack_encode_string(std::vector<uint8_t>& out, const std::string& value) {
    hpack_encode_integer(out, static_cast<uint32_t>(value.size()), 7, 0x00);
    out.insert(out.end(), value.begin(), value.end());
}

inline void hpack_encode_indexed_field(std::vector<uint8_t>& out, uint32_t index) {
    hpack_encode_integer(out, index, 7, 0x80);
}

inline void hpack_encode_literal_indexed_name(std::vector<uint8_t>& out,
                                             uint32_t name_index,
                                             const std::string& value) {
    hpack_encode_integer(out, name_index, 4, 0x00);
    hpack_encode_string(out, value);
}

inline std::vector<uint8_t> build_http2_request_headers(const VerificationEndpoint& endpoint) {
    std::vector<uint8_t> block;
    hpack_encode_indexed_field(block, 2);   // :method: GET
    hpack_encode_indexed_field(block, 7);   // :scheme: https
    hpack_encode_literal_indexed_name(block, 4, endpoint.path);       // :path
    hpack_encode_literal_indexed_name(block, 1, endpoint.authority);  // :authority
    // UA comes from yume::http_profile::active_client_ua(), which always
    // returns the pinned cover-profile User-Agent. Stealth probes therefore
    // carry the same identity as tunnel traffic; there is no YUME-specific
    // fallback string for an unset profile.
    hpack_encode_literal_indexed_name(block, 58, yume::http_profile::active_client_ua());
    hpack_encode_literal_indexed_name(block, 19, "application/json");
    return block;
}

inline void append_http2_frame(std::vector<uint8_t>& out,
                               uint8_t type,
                               uint8_t flags,
                               uint32_t stream_id,
                               const std::vector<uint8_t>& payload) {
    const uint32_t length = static_cast<uint32_t>(payload.size());
    out.push_back(static_cast<uint8_t>((length >> 16) & 0xffu));
    out.push_back(static_cast<uint8_t>((length >> 8) & 0xffu));
    out.push_back(static_cast<uint8_t>(length & 0xffu));
    out.push_back(type);
    out.push_back(flags);
    out.push_back(static_cast<uint8_t>((stream_id >> 24) & 0x7fu));
    out.push_back(static_cast<uint8_t>((stream_id >> 16) & 0xffu));
    out.push_back(static_cast<uint8_t>((stream_id >> 8) & 0xffu));
    out.push_back(static_cast<uint8_t>(stream_id & 0xffu));
    out.insert(out.end(), payload.begin(), payload.end());
}

template <typename Stream>
void write_http2_ping_ack(Stream& stream, const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> frame;
    append_http2_frame(frame, 0x6, 0x1, 0, payload);
    boost::asio::write(stream, boost::asio::buffer(frame));
}

template <typename Stream>
void write_http2_settings_ack(Stream& stream) {
    std::vector<uint8_t> frame;
    append_http2_frame(frame, 0x4, 0x1, 0, {});
    boost::asio::write(stream, boost::asio::buffer(frame));
}

inline std::string extract_http_body(const std::string& response) {
    const std::size_t header_end = response.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        throw std::runtime_error("TLS fingerprint verification returned an invalid HTTP response");
    }
    return response.substr(header_end + 4);
}

template <typename Stream>
std::string fetch_http11_json(Stream& stream,
                              const VerificationEndpoint& endpoint,
                              const VerifyFetchLimits& limits) {
    const std::string request =
        "GET " + endpoint.path + " HTTP/1.1\r\n"
        "Host: " + endpoint.authority + "\r\n"
        "User-Agent: " + yume::http_profile::active_client_ua() + "\r\n"
        "Accept: application/json\r\n"
        "Connection: close\r\n\r\n";
    boost::asio::write(stream, boost::asio::buffer(request));

    boost::system::error_code ec;
    std::string response;
    std::array<char, 4096> buffer{};
    for (;;) {
        check_deadline(limits);
        const std::size_t n = stream.read_some(boost::asio::buffer(buffer), ec);
        if (n > 0) {
            if (n > limits.max_response_bytes - response.size()) {
                throw std::runtime_error(
                    "TLS fingerprint verification response exceeded its size "
                    "limit");
            }
            response.append(buffer.data(), n);
        }
        if (ec == boost::asio::error::eof) {
            break;
        }
        if (ec) {
            throw boost::system::system_error(ec);
        }
    }
    return extract_http_body(response);
}

template <typename Stream>
std::string fetch_http2_json(Stream& stream,
                             const VerificationEndpoint& endpoint,
                             const VerifyFetchLimits& limits) {
    std::vector<uint8_t> request;
    static constexpr char kClientPreface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    request.insert(request.end(), kClientPreface, kClientPreface + sizeof(kClientPreface) - 1);
    append_http2_frame(request, 0x4, 0x0, 0, {});
    append_http2_frame(request, 0x1, 0x5, 1, build_http2_request_headers(endpoint));
    boost::asio::write(stream, boost::asio::buffer(request));

    std::string body;
    bool end_stream = false;
    std::size_t frames_read = 0;
    while (!end_stream) {
        check_deadline(limits);
        if (frames_read >= limits.max_frames) {
            throw std::runtime_error(
                "TLS fingerprint verification read too many HTTP/2 frames "
                "without END_STREAM");
        }
        frames_read += 1;
        std::array<uint8_t, 9> header{};
        boost::asio::read(stream, boost::asio::buffer(header));
        const uint32_t length = (static_cast<uint32_t>(header[0]) << 16)
            | (static_cast<uint32_t>(header[1]) << 8)
            | static_cast<uint32_t>(header[2]);
        const uint8_t type = header[3];
        const uint8_t flags = header[4];
        const uint32_t stream_id = ((static_cast<uint32_t>(header[5]) & 0x7fu) << 24)
            | (static_cast<uint32_t>(header[6]) << 16)
            | (static_cast<uint32_t>(header[7]) << 8)
            | static_cast<uint32_t>(header[8]);

        // Before the allocation: `length` is a peer-declared 24-bit field, and
        // we advertised empty SETTINGS, so anything above the RFC 7540 6.5.2
        // default is already a protocol violation.
        if (length > limits.max_frame_payload) {
            throw std::runtime_error(
                "TLS fingerprint verification received an oversize HTTP/2 "
                "frame");
        }
        std::vector<uint8_t> payload(length);
        if (length > 0) {
            boost::asio::read(stream, boost::asio::buffer(payload));
        }

        switch (type) {
            case 0x0: {
                if (stream_id != 1) {
                    break;
                }
                size_t offset = 0;
                size_t payload_size = payload.size();
                if ((flags & 0x8u) != 0) {
                    if (payload.empty()) {
                        throw std::runtime_error("Invalid padded HTTP/2 DATA frame");
                    }
                    const size_t padding = payload.front();
                    if (padding + 1 > payload_size) {
                        throw std::runtime_error("Invalid HTTP/2 DATA padding");
                    }
                    offset = 1;
                    payload_size -= padding + 1;
                }
                if (payload_size > limits.max_body_bytes - body.size()) {
                    throw std::runtime_error(
                        "TLS fingerprint verification response body exceeded "
                        "its size limit");
                }
                body.append(reinterpret_cast<const char*>(payload.data() + offset), payload_size);
                if ((flags & 0x1u) != 0) {
                    end_stream = true;
                }
                break;
            }
            case 0x1:
            case 0x9:
                if (stream_id == 1 && (flags & 0x1u) != 0) {
                    end_stream = true;
                }
                break;
            case 0x3:
                if (stream_id == 1) {
                    throw std::runtime_error("HTTP/2 stream reset during TLS fingerprint verification");
                }
                break;
            case 0x4:
                if ((flags & 0x1u) == 0) {
                    write_http2_settings_ack(stream);
                }
                break;
            case 0x6:
                if ((flags & 0x1u) == 0) {
                    write_http2_ping_ack(stream, payload);
                }
                break;
            case 0x7:
                if (body.empty()) {
                    throw std::runtime_error("HTTP/2 connection closed before TLS fingerprint response body arrived");
                }
                end_stream = true;
                break;
            default:
                break;
        }
    }
    return body;
}

}  // namespace yume::tls_stealth::verify_fetch
