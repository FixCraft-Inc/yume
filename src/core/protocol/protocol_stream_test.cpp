/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * Bounds contract for the synchronous transport-frame reader. The 4-byte
 * length in a frame header is peer-supplied, so read_frame must reject an
 * oversize declaration before it allocates or reads the payload.
 */

#include "core/protocol/protocol_stream.hpp"
#include "core/security/auth_v2.hpp"

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <cassert>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include <boost/asio/buffer.hpp>
#include <boost/system/error_code.hpp>

namespace {

// A synchronous stream that replays a fixed script and records how many bytes
// the reader actually asked for. Only the header is scripted for the hostile
// cases: a reader that tries to fill the declared payload runs out of input,
// which is exactly the state we do not want it to reach.
class ScriptedStream {
public:
    explicit ScriptedStream(std::vector<uint8_t> script)
        : script_(std::move(script)) {}

    template <typename MutableBufferSequence>
    std::size_t read_some(const MutableBufferSequence& buffers,
                          boost::system::error_code& ec) {
        std::size_t copied = 0;
        for (auto it = boost::asio::buffer_sequence_begin(buffers);
             it != boost::asio::buffer_sequence_end(buffers); ++it) {
            boost::asio::mutable_buffer buffer(*it);
            requested_ += buffer.size();
            const std::size_t available = script_.size() - offset_;
            const std::size_t take = std::min(buffer.size(), available);
            if (take > 0) {
                std::memcpy(buffer.data(), script_.data() + offset_, take);
                offset_ += take;
                copied += take;
            }
            if (take < buffer.size()) {
                break;
            }
        }
        if (copied == 0) {
            ec = boost::asio::error::eof;
        }
        return copied;
    }

    std::size_t requested() const { return requested_; }

private:
    std::vector<uint8_t> script_;
    std::size_t offset_{0};
    std::size_t requested_{0};
};

std::vector<uint8_t> header_declaring(uint32_t len, uint8_t type,
                                    uint16_t flags = 0) {
    return {
        static_cast<uint8_t>((len >> 24) & 0xFF),
        static_cast<uint8_t>((len >> 16) & 0xFF),
        static_cast<uint8_t>((len >> 8) & 0xFF),
        static_cast<uint8_t>(len & 0xFF),
        type,
        0,
        static_cast<uint8_t>(flags >> 8),
        static_cast<uint8_t>(flags),
    };
}

void test_auth_bound_before_payload_read() {
    for (const bool padded : {false, true}) {
        const auto maximum = yume::auth_v2::kMaxRecordBytes + (padded ? 256U : 0U);
        ScriptedStream stream(header_declaring(
            static_cast<uint32_t>(maximum + 1U), yume::protocol::AUTH,
            padded ? yume::protocol::kFlagPadded : 0));
        bool rejected = false;
        try { (void)yume::protocol::read_frame(stream); }
        catch (const std::runtime_error&) { rejected = true; }
        assert(rejected && stream.requested() == 8);
    }
}

void test_decode_length_arithmetic() {
    for (const auto length : {0xFFFFFFFFU, 0xFFFFFFF8U}) {
        bool rejected = false;
        try {
            (void)yume::protocol::decode_frame(
                header_declaring(length, yume::protocol::DATA));
        } catch (const std::runtime_error&) { rejected = true; }
        assert(rejected);
    }
}

void test_auth_exact_boundary() {
    const std::vector<uint8_t> payload(yume::auth_v2::kMaxRecordBytes, 0x41);
    for (const uint16_t padding : {uint16_t{0}, uint16_t{256}}) {
        const auto wire = yume::protocol::encode_frame(
            yume::protocol::AUTH, 0, 0, payload, padding);
        assert(wire.size() == 8U + payload.size() + (padding ? 256U : 0U));
        ScriptedStream stream(wire);
        auto frame = yume::protocol::read_frame(stream);
        assert(yume::protocol::strip_padding(frame));
        assert(frame.payload == payload);
        assert(yume::protocol::decode_frame(wire).payload == payload);
        assert(stream.requested() == wire.size());
    }
    bool rejected = false;
    try {
        (void)yume::protocol::encode_frame(yume::protocol::AUTH, 0, 0,
            std::vector<uint8_t>(payload.size() + 1U, 0x41));
    } catch (const std::runtime_error&) { rejected = true; }
    assert(rejected);
}

// A peer that declares 4 GiB must be refused before anything is allocated or
// read. Without the cap, read_frame resizes the payload to the declared size
// and only then blocks on a read the peer never intends to satisfy.
void test_rejects_oversize_declared_payload() {
    ScriptedStream stream(header_declaring(0xFFFFFFFFu, yume::protocol::CONTROL));
    bool rejected = false;
    try {
        (void)yume::protocol::read_frame(stream);
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    assert(rejected);
    // The discriminating assertion. An unbounded reader also throws here, but
    // only after resizing the payload to 4 GiB and issuing the read that runs
    // the stream dry; requesting nothing past the header is what proves the
    // declaration was refused before any allocation.
    assert(stream.requested() == 8);
}

// The boundary itself: one byte over the cap is refused, and the cap is a
// transport-protocol constant rather than an HTTP/2 carrier limit.
void test_rejects_one_byte_over_the_cap() {
    ScriptedStream stream(header_declaring(
        static_cast<uint32_t>(yume::protocol::kMaxFramePayloadBytes) + 1u,
        yume::protocol::DATA));
    bool rejected = false;
    try {
        (void)yume::protocol::read_frame(stream);
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    assert(rejected);
    assert(stream.requested() == 8);
}

// An ordinary frame still round-trips, header fields intact.
void test_accepts_ordinary_frame() {
    const std::vector<uint8_t> payload{'y', 'u', 'm', 'e'};
    auto wire = yume::protocol::encode_frame(yume::protocol::CONTROL, 7, 0x1234,
                                             payload);
    ScriptedStream stream(wire);
    const auto frame = yume::protocol::read_frame(stream);
    assert(frame.header.len == payload.size());
    assert(frame.header.type == yume::protocol::CONTROL);
    assert(frame.header.stream_id == 7);
    assert(frame.header.flags == 0x1234);
    assert(frame.payload == payload);
}

// A zero-length frame reads without touching the payload read path.
void test_accepts_empty_payload() {
    auto wire = yume::protocol::encode_frame(yume::protocol::PING, 0, 0, {});
    ScriptedStream stream(wire);
    const auto frame = yume::protocol::read_frame(stream);
    assert(frame.header.len == 0);
    assert(frame.header.type == yume::protocol::PING);
    assert(frame.payload.empty());
    assert(stream.requested() == 8);
}

}  // namespace

int main() {
    test_auth_bound_before_payload_read();
    test_auth_exact_boundary();
    test_decode_length_arithmetic();
    test_rejects_oversize_declared_payload();
    test_rejects_one_byte_over_the_cap();
    test_accepts_ordinary_frame();
    test_accepts_empty_payload();
    std::puts("protocol_stream_test: all cases passed");
    return 0;
}
