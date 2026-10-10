#include "stealth/websocket_codec.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace {

using yume::obfs::WebSocketBytes;
using yume::obfs::WebSocketCodec;
using yume::obfs::WebSocketRole;

WebSocketBytes Binary(WebSocketCodec& codec, const WebSocketBytes& payload) {
    WebSocketBytes out;
    codec.EncodeBinary(out, payload.data(), payload.size());
    return out;
}

WebSocketBytes Fragmented(WebSocketCodec& codec, const WebSocketBytes& payload,
                          std::size_t first_fragment_bytes) {
    WebSocketBytes out;
    codec.EncodeBinaryFragmented(out, payload.data(), payload.size(),
                                 first_fragment_bytes);
    return out;
}

WebSocketBytes Close(WebSocketCodec& codec) {
    WebSocketBytes out;
    codec.EncodeClose(out);
    return out;
}

std::uint8_t Pattern(std::size_t index) {
    return static_cast<std::uint8_t>((index * 151U + 7U) ^ (index >> 8U));
}

// The RFC 6455 definition: payload byte i uses key byte i % 4.
void ReferenceMask(std::uint8_t* data, std::size_t size,
                   const std::array<std::uint8_t, 4>& key, std::size_t phase) {
    for (std::size_t i = 0; i < size; ++i) {
        data[i] = static_cast<std::uint8_t>(data[i] ^ key[(phase + i) & 3U]);
    }
}

void MaskMatchesPerByteReference() {
    const std::array<std::uint8_t, 4> key{0x9d, 0x01, 0xe7, 0x5a};
    std::vector<std::size_t> lengths;
    for (std::size_t length = 0; length <= 40U; ++length)
        lengths.push_back(length);
    lengths.push_back(16U * 1024U);
    for (const std::size_t length : lengths) {
        for (std::size_t alignment = 0; alignment < 8U; ++alignment) {
            for (std::size_t phase = 0; phase < 4U; ++phase) {
                // Guard bytes on both sides catch a write outside the range.
                WebSocketBytes actual(length + alignment + 16U, 0xa5);
                for (std::size_t i = 0; i < length; ++i) {
                    actual[alignment + 8U + i] = Pattern(i + phase);
                }
                WebSocketBytes expected = actual;
                yume::obfs::ApplyWebSocketMask(actual.data() + alignment + 8U,
                                               length, key, phase);
                ReferenceMask(expected.data() + alignment + 8U, length, key,
                              phase);
                assert(actual == expected);
            }
        }
    }
}

// Every encoder appends whole frames after what `out` already holds, at any
// alignment, and a client frame unmasks with its own key to the input.
void EncodeAppendsMaskedFrames() {
    WebSocketCodec client(WebSocketRole::Client);
    WebSocketCodec server(WebSocketRole::Server);
    std::vector<std::size_t> lengths;
    for (std::size_t length = 0; length <= 40U; ++length)
        lengths.push_back(length);
    for (const std::size_t length : {125U, 126U, 16384U, 65535U, 65536U}) {
        lengths.push_back(length);
    }
    for (const std::size_t length : lengths) {
        WebSocketBytes payload(length);
        for (std::size_t i = 0; i < length; ++i) payload[i] = Pattern(i);
        for (std::size_t prefix = 0; prefix < 8U; ++prefix) {
            WebSocketBytes out(prefix, 0x33);
            client.EncodeBinary(out, payload.data(), payload.size());
            assert(out.size() == prefix + client.FrameBytes(length));
            for (std::size_t i = 0; i < prefix; ++i) assert(out[i] == 0x33);
            const std::uint8_t* frame = out.data() + prefix;
            assert(frame[0] == 0x82);
            assert((frame[1] & 0x80U) != 0);
            const std::size_t header = out.size() - prefix - length;
            std::array<std::uint8_t, 4> key{};
            for (std::size_t i = 0; i < 4U; ++i)
                key[i] = frame[header - 4U + i];
            WebSocketBytes unmasked(frame + header, frame + header + length);
            ReferenceMask(unmasked.data(), unmasked.size(), key, 0);
            assert(unmasked == payload);

            server.Feed(frame, out.size() - prefix);
            assert(!server.failed());
            assert(server.TakeDrain().tunnel_bytes == payload);

            WebSocketBytes plain(prefix, 0x44);
            server.EncodeBinary(plain, payload.data(), payload.size());
            assert(plain.size() == prefix + server.FrameBytes(length));
            assert(WebSocketBytes(
                       plain.end() - static_cast<std::ptrdiff_t>(length),
                       plain.end()) == payload);
        }
    }
}

// A refused encode leaves the caller's buffer as it was.
void FailedEncodeKeepsOutput() {
    WebSocketCodec client(WebSocketRole::Client);
    WebSocketBytes out{1, 2, 3};
    // The second fragment exceeds the message limit after the first fragment
    // was appended, which the rollback must remove again.
    const WebSocketBytes big(16U * 1024U * 1024U + 17U, 0x11);
    bool threw = false;
    try {
        client.EncodeBinary(out, big.data(), big.size());
    } catch (const std::runtime_error&) {
        threw = true;
    }
    assert(threw && out == WebSocketBytes({1, 2, 3}));
    threw = false;
    try {
        client.EncodeBinaryFragmented(out, big.data(), big.size(), 16U);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    assert(threw && out == WebSocketBytes({1, 2, 3}));
}

// Frames split at every byte boundary decode to the same payload and the
// same credit as frames fed whole.
void SplitInputDecodesAlike() {
    WebSocketCodec client(WebSocketRole::Client);
    WebSocketBytes wire;
    WebSocketBytes payload;
    std::size_t index = 0;
    for (const std::size_t length : {1U, 125U, 126U, 300U, 0U, 70000U}) {
        WebSocketBytes record(length);
        for (auto& byte : record) byte = Pattern(index++);
        client.EncodeBinary(wire, record.data(), record.size());
        payload.insert(payload.end(), record.begin(), record.end());
    }
    const std::uint8_t ping[] = {'p'};
    client.EncodePing(wire, ping, sizeof(ping));
    for (const std::size_t piece : {1U, 2U, 3U, 7U, 13U, 4096U, 100000U}) {
        WebSocketCodec server(WebSocketRole::Server);
        WebSocketBytes decoded;
        std::size_t consumable = 0;
        for (std::size_t at = 0; at < wire.size(); at += piece) {
            const std::size_t length = std::min(piece, wire.size() - at);
            server.Feed(wire.data() + at, length);
            assert(!server.failed());
            auto drain = server.TakeDrain();
            decoded.insert(decoded.end(), drain.tunnel_bytes.begin(),
                           drain.tunnel_bytes.end());
            consumable += drain.immediately_consumable_wire_bytes;
        }
        assert(decoded == payload);
        assert(consumable + payload.size() == wire.size());
        const auto pong = server.TakeWireReplies();
        assert(pong == WebSocketBytes({0x8a, 0x01, 'p'}));
    }
}

void ObserveFrame(
    void* context,
    const yume::obfs::WebSocketFrameMetadata& frame) noexcept {
    static_cast<std::vector<yume::obfs::WebSocketFrameMetadata>*>(context)
        ->push_back(frame);
}

void RoundTripAndMasking() {
    WebSocketCodec client(WebSocketRole::Client);
    WebSocketCodec server(WebSocketRole::Server);
    const WebSocketBytes payload{1, 2, 3, 4, 5};
    auto wire = Binary(client, payload);
    assert((wire[1] & 0x80U) != 0);
    server.Feed(wire);
    assert(!server.failed());
    auto server_drain = server.TakeDrain();
    assert(server_drain.tunnel_bytes == payload);
    assert(server_drain.immediately_consumable_wire_bytes == 6);

    auto response = Binary(server, payload);
    assert((response[1] & 0x80U) == 0);
    client.Feed(response);
    auto client_drain = client.TakeDrain();
    assert(client_drain.tunnel_bytes == payload);
    assert(client_drain.immediately_consumable_wire_bytes == 2);
}

void FragmentAndPing() {
    WebSocketCodec server(WebSocketRole::Server);
    // masked FIN=0 binary "ab"
    const WebSocketBytes first{0x02, 0x82, 1, 2, 3, 4,
                               static_cast<unsigned char>('a' ^ 1),
                               static_cast<unsigned char>('b' ^ 2)};
    // masked PING "x" interleaved between fragments
    const WebSocketBytes ping{0x89, 0x81, 4, 3, 2, 1,
                              static_cast<unsigned char>('x' ^ 4)};
    // masked FIN continuation "cd"
    const WebSocketBytes last{0x80, 0x82, 5, 6, 7, 8,
                              static_cast<unsigned char>('c' ^ 5),
                              static_cast<unsigned char>('d' ^ 6)};
    server.Feed(first);
    server.Feed(ping);
    server.Feed(last);
    assert(!server.failed());
    auto drain = server.TakeDrain();
    assert(drain.tunnel_bytes == WebSocketBytes({'a', 'b', 'c', 'd'}));
    // Each binary fragment defers only its two payload bytes. The two
    // masked frame headers (6 + 6) and the complete masked PING (7) retire
    // immediately.
    assert(drain.immediately_consumable_wire_bytes == 19);
    auto reply = server.TakeWireReplies();
    assert(reply.size() == 3 && reply[0] == 0x8A && reply[2] == 'x');
}

void EncodeFragmentedRoundTrip() {
    WebSocketCodec server(WebSocketRole::Server);
    WebSocketCodec client(WebSocketRole::Client);
    const WebSocketBytes payload(16384, 0x59);
    auto wire = Fragmented(server, payload, 8192);
    assert((wire[0] & 0x80U) == 0);
    assert((wire[0] & 0x0fU) == 0x02U);
    client.Feed(wire);
    assert(!client.failed());
    auto drain = client.TakeDrain();
    assert(drain.tunnel_bytes == payload);
    assert(drain.immediately_consumable_wire_bytes == 8);
}

void ExtendedEmptyAndCloseAccounting() {
    WebSocketCodec client(WebSocketRole::Client);
    WebSocketCodec server(WebSocketRole::Server);

    const WebSocketBytes extended_payload(126, 0x37);
    const auto extended_wire = Binary(client, extended_payload);
    server.Feed(extended_wire);
    auto extended = server.TakeDrain();
    assert(extended.tunnel_bytes == extended_payload);
    assert(extended.immediately_consumable_wire_bytes == 8);
    assert(extended_wire.size() ==
           extended.immediately_consumable_wire_bytes +
               extended.tunnel_bytes.size());

    server.Feed(Binary(client, {}));
    auto empty = server.TakeDrain();
    assert(empty.tunnel_bytes.empty());
    assert(empty.immediately_consumable_wire_bytes == 6);

    server.Feed(Close(client));
    auto close = server.TakeDrain();
    assert(close.tunnel_bytes.empty());
    assert(close.immediately_consumable_wire_bytes == 8);
    assert(server.closed());
}

void RejectWrongMaskAndText() {
    WebSocketCodec server(WebSocketRole::Server);
    server.Feed(WebSocketBytes{0x82, 0x01, 0x01});
    assert(server.failed());

    WebSocketCodec server2(WebSocketRole::Server);
    server2.Feed(WebSocketBytes{0x81, 0x81, 1, 2, 3, 4,
                                static_cast<unsigned char>('x' ^ 1)});
    assert(server2.failed());
}

void ObserveOnlyCompleteValidatedMetadata() {
    WebSocketCodec client(WebSocketRole::Client);
    WebSocketCodec server(WebSocketRole::Server);
    std::vector<yume::obfs::WebSocketFrameMetadata> observed;
    observed.reserve(2);
    server.set_inbound_frame_observer(&ObserveFrame, &observed);

    const WebSocketBytes payload{'s', 'e', 'c', 'r', 'e', 't'};
    auto wire = Binary(client, payload);
    server.Feed(wire.data(), wire.size() - 1);
    assert(observed.empty());
    auto partial = server.TakeDrain();
    assert(partial.tunnel_bytes.empty());
    assert(partial.immediately_consumable_wire_bytes == 0);
    server.Feed(wire.data() + wire.size() - 1, 1);
    assert(observed.size() == 1);
    assert(observed[0].opcode == 0x2);
    assert(observed[0].final);
    assert(observed[0].masked);
    assert(observed[0].payload_bytes == payload.size());
    auto complete = server.TakeDrain();
    assert(complete.tunnel_bytes == payload);
    assert(complete.immediately_consumable_wire_bytes == 6);

    WebSocketCodec invalid(WebSocketRole::Server);
    invalid.set_inbound_frame_observer(&ObserveFrame, &observed);
    invalid.Feed(WebSocketBytes{0x81, 0x81, 1, 2, 3, 4,
                                static_cast<unsigned char>('x' ^ 1)});
    assert(invalid.failed());
    assert(observed.size() == 1);
}

void ConfigurableInboundBinaryLimitPreservesDefault() {
    WebSocketCodec client(WebSocketRole::Client);
    const WebSocketBytes at_limit(4, 0x41);
    const WebSocketBytes above_limit(5, 0x42);

    WebSocketCodec constrained(WebSocketRole::Server, at_limit.size());
    constrained.Feed(Binary(client, at_limit));
    assert(!constrained.failed());
    assert(constrained.TakeDrain().tunnel_bytes == at_limit);

    WebSocketCodec rejected(WebSocketRole::Server, at_limit.size());
    rejected.Feed(Binary(client, above_limit));
    assert(rejected.failed());

    const WebSocketBytes above_h2_profile(16U * 1024U + 1U, 0x43);
    WebSocketCodec general(WebSocketRole::Server);
    general.Feed(Binary(client, above_h2_profile));
    assert(!general.failed());
    assert(general.TakeDrain().tunnel_bytes == above_h2_profile);

    constexpr std::size_t kH2MessageBytes = 16U * 1024U;
    const WebSocketBytes fragmented_at_limit(kH2MessageBytes, 0x44);
    WebSocketCodec accepted_fragmented(WebSocketRole::Server,
                                       kH2MessageBytes);
    accepted_fragmented.Feed(
        Fragmented(client, fragmented_at_limit, kH2MessageBytes / 2));
    assert(!accepted_fragmented.failed());
    assert(accepted_fragmented.TakeDrain().tunnel_bytes ==
           fragmented_at_limit);

    const WebSocketBytes fragmented_above_limit(kH2MessageBytes + 1, 0x45);
    WebSocketCodec rejected_fragmented(WebSocketRole::Server,
                                       kH2MessageBytes);
    rejected_fragmented.Feed(
        Fragmented(client, fragmented_above_limit, kH2MessageBytes / 2));
    assert(rejected_fragmented.failed());
}

}  // namespace

int main() {
    RoundTripAndMasking();
    FragmentAndPing();
    EncodeFragmentedRoundTrip();
    ExtendedEmptyAndCloseAccounting();
    RejectWrongMaskAndText();
    ObserveOnlyCompleteValidatedMetadata();
    ConfigurableInboundBinaryLimitPreservesDefault();
    MaskMatchesPerByteReference();
    EncodeAppendsMaskedFrames();
    FailedEncodeKeepsOutput();
    SplitInputDecodesAlike();
    return 0;
}
