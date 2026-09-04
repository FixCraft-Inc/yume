/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * Bounds contract for the optional TLS fingerprint diagnostic's HTTP fetch.
 * The endpoint is third-party and operator-named, so every case here is a
 * response a redirected or hostile endpoint can produce.
 */

#include "core/stealth/tls_verify_fetch.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include <boost/asio/buffer.hpp>
#include <boost/system/error_code.hpp>

namespace {

using yume::tls_stealth::verify_fetch::VerificationEndpoint;
using yume::tls_stealth::verify_fetch::VerifyFetchLimits;

// A synchronous stream that replays a script, then optionally repeats a tail
// block forever. The repeating tail is how an endpoint that never closes and
// never ends the stream is expressed without an actual network peer.
class ScriptedStream {
public:
    ScriptedStream(std::vector<uint8_t> script, std::vector<uint8_t> repeat_tail = {})
        : script_(std::move(script)), repeat_tail_(std::move(repeat_tail)) {}

    template <typename ConstBufferSequence>
    std::size_t write_some(const ConstBufferSequence& buffers,
                           boost::system::error_code& ec) {
        ec = {};
        std::size_t total = 0;
        for (auto it = boost::asio::buffer_sequence_begin(buffers);
             it != boost::asio::buffer_sequence_end(buffers); ++it) {
            total += boost::asio::const_buffer(*it).size();
        }
        return total;
    }

    template <typename MutableBufferSequence>
    std::size_t read_some(const MutableBufferSequence& buffers,
                          boost::system::error_code& ec) {
        ec = {};
        std::size_t copied = 0;
        for (auto it = boost::asio::buffer_sequence_begin(buffers);
             it != boost::asio::buffer_sequence_end(buffers); ++it) {
            boost::asio::mutable_buffer buffer(*it);
            auto* out = static_cast<uint8_t*>(buffer.data());
            std::size_t want = buffer.size();
            read_requested_ += want;
            while (want > 0) {
                if (offset_ >= script_.size()) {
                    if (repeat_tail_.empty()) {
                        if (copied == 0) {
                            ec = boost::asio::error::eof;
                        }
                        return copied;
                    }
                    // Wrap onto the repeating tail rather than ending.
                    script_.insert(script_.end(), repeat_tail_.begin(),
                                   repeat_tail_.end());
                    tail_bytes_ += repeat_tail_.size();
                    // A test that never terminates is a broken test, not a
                    // passing one. This budget is far above every cap under
                    // test, so reaching it means the fetch is unbounded --
                    // and abort() is deliberate: a thrown exception would be
                    // caught by `rejects` and read as a pass.
                    assert(tail_bytes_ < 8U * 1024U * 1024U);
                }
                const std::size_t take =
                    std::min(want, script_.size() - offset_);
                std::memcpy(out, script_.data() + offset_, take);
                offset_ += take;
                out += take;
                want -= take;
                copied += take;
            }
        }
        return copied;
    }

    std::size_t read_requested() const { return read_requested_; }

private:
    std::vector<uint8_t> script_;
    std::vector<uint8_t> repeat_tail_;
    std::size_t offset_{0};
    std::size_t tail_bytes_{0};
    std::size_t read_requested_{0};
};

VerificationEndpoint test_endpoint() {
    VerificationEndpoint endpoint;
    endpoint.host = "verify.example";
    endpoint.authority = "verify.example";
    endpoint.path = "/api/all";
    return endpoint;
}

void push_h2_frame(std::vector<uint8_t>& out, uint32_t length, uint8_t type,
                   uint8_t flags, uint32_t stream_id,
                   const std::vector<uint8_t>& payload) {
    out.push_back(static_cast<uint8_t>((length >> 16) & 0xFFu));
    out.push_back(static_cast<uint8_t>((length >> 8) & 0xFFu));
    out.push_back(static_cast<uint8_t>(length & 0xFFu));
    out.push_back(type);
    out.push_back(flags);
    out.push_back(static_cast<uint8_t>((stream_id >> 24) & 0x7Fu));
    out.push_back(static_cast<uint8_t>((stream_id >> 16) & 0xFFu));
    out.push_back(static_cast<uint8_t>((stream_id >> 8) & 0xFFu));
    out.push_back(static_cast<uint8_t>(stream_id & 0xFFu));
    out.insert(out.end(), payload.begin(), payload.end());
}

template <typename Fetch>
bool rejects(Fetch fetch) {
    try {
        fetch();
    } catch (const std::exception&) {
        return true;
    }
    return false;
}

// An endpoint that answers HTTP/1.1 and never closes the connection. Without
// a size cap the reader appends to EOF and EOF never comes.
void test_http11_rejects_unbounded_body() {
    std::vector<uint8_t> head;
    const std::string headers =
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n";
    head.assign(headers.begin(), headers.end());
    const std::vector<uint8_t> tail(4096, 'A');

    ScriptedStream stream(head, tail);
    VerifyFetchLimits limits;
    limits.max_response_bytes = 64U * 1024U;
    assert(rejects([&] {
        (void)yume::tls_stealth::verify_fetch::fetch_http11_json(
            stream, test_endpoint(), limits);
    }));
}

// A response inside the cap still parses, and the body is what follows the
// header terminator.
void test_http11_accepts_bounded_body() {
    const std::string response =
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ja3\":\"x\"}";
    ScriptedStream stream(std::vector<uint8_t>(response.begin(), response.end()));
    VerifyFetchLimits limits;
    const std::string body = yume::tls_stealth::verify_fetch::fetch_http11_json(
        stream, test_endpoint(), limits);
    assert(body == "{\"ja3\":\"x\"}");
}

// A peer-declared 24-bit frame length of 0xffffff must be refused before the
// 16 MiB allocation, not read into.
void test_http2_rejects_oversize_frame_declaration() {
    std::vector<uint8_t> wire;
    push_h2_frame(wire, 0xFFFFFFu, 0x0, 0x0, 1, {});

    ScriptedStream stream(wire);
    VerifyFetchLimits limits;
    assert(rejects([&] {
        (void)yume::tls_stealth::verify_fetch::fetch_http2_json(
            stream, test_endpoint(), limits);
    }));
    // The discriminating assertion. A reader without the cap also throws here
    // once the stream runs dry, but only after allocating 16 MiB and asking
    // for it; never reading past the 9-byte frame header is what proves the
    // declaration was refused before the allocation.
    assert(stream.read_requested() == 9);
}

// DATA that keeps arriving without END_STREAM must stop at the body cap.
void test_http2_rejects_unbounded_data() {
    std::vector<uint8_t> tail;
    push_h2_frame(tail, 4096, 0x0, 0x0, 1, std::vector<uint8_t>(4096, 'A'));

    ScriptedStream stream({}, tail);
    VerifyFetchLimits limits;
    limits.max_body_bytes = 64U * 1024U;
    assert(rejects([&] {
        (void)yume::tls_stealth::verify_fetch::fetch_http2_json(
            stream, test_endpoint(), limits);
    }));
}

// An endpoint that answers only with SETTINGS/PING never sets END_STREAM. The
// body cap never trips because no DATA arrives, so the frame count must.
void test_http2_rejects_missing_end_stream() {
    std::vector<uint8_t> tail;
    push_h2_frame(tail, 0, 0x4, 0x1, 0, {});  // SETTINGS ACK, ignored

    ScriptedStream stream({}, tail);
    VerifyFetchLimits limits;
    limits.max_frames = 64;
    assert(rejects([&] {
        (void)yume::tls_stealth::verify_fetch::fetch_http2_json(
            stream, test_endpoint(), limits);
    }));
}

// A deadline already in the past stops the exchange before the first read.
void test_deadline_stops_the_exchange() {
    std::vector<uint8_t> tail;
    push_h2_frame(tail, 0, 0x4, 0x1, 0, {});

    ScriptedStream stream({}, tail);
    VerifyFetchLimits limits;
    limits.deadline = std::chrono::steady_clock::now() - std::chrono::seconds(1);
    assert(rejects([&] {
        (void)yume::tls_stealth::verify_fetch::fetch_http2_json(
            stream, test_endpoint(), limits);
    }));
}

// An ordinary short response still round-trips: HEADERS then DATA with
// END_STREAM.
void test_http2_accepts_bounded_response() {
    const std::string json = "{\"ja3\":\"x\"}";
    std::vector<uint8_t> wire;
    push_h2_frame(wire, 0, 0x4, 0x0, 0, {});  // peer SETTINGS
    push_h2_frame(wire, 0, 0x1, 0x4, 1, {});  // HEADERS, END_HEADERS only
    push_h2_frame(wire, static_cast<uint32_t>(json.size()), 0x0, 0x1, 1,
                  std::vector<uint8_t>(json.begin(), json.end()));

    ScriptedStream stream(wire);
    VerifyFetchLimits limits;
    const std::string body = yume::tls_stealth::verify_fetch::fetch_http2_json(
        stream, test_endpoint(), limits);
    assert(body == json);
}

}  // namespace

int main() {
    test_http11_rejects_unbounded_body();
    test_http11_accepts_bounded_body();
    test_http2_rejects_oversize_frame_declaration();
    test_http2_rejects_unbounded_data();
    test_http2_rejects_missing_end_stream();
    test_deadline_stops_the_exchange();
    test_http2_accepts_bounded_response();
    std::puts("tls_verify_fetch_test: all cases passed");
    return 0;
}
