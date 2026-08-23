#include "core/stealth/websocket_codec.hpp"

#include <cassert>
#include <vector>

namespace {

using yume::obfs::WebSocketBytes;
using yume::obfs::WebSocketCodec;
using yume::obfs::WebSocketRole;

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
    auto wire = client.EncodeBinary(payload);
    assert((wire[1] & 0x80U) != 0);
    server.Feed(wire);
    assert(!server.failed());
    auto server_drain = server.TakeDrain();
    assert(server_drain.tunnel_bytes == payload);
    assert(server_drain.immediately_consumable_wire_bytes == 6);

    auto response = server.EncodeBinary(payload);
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
    auto wire = server.EncodeBinaryFragmented(payload, 8192);
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
    const auto extended_wire = client.EncodeBinary(extended_payload);
    server.Feed(extended_wire);
    auto extended = server.TakeDrain();
    assert(extended.tunnel_bytes == extended_payload);
    assert(extended.immediately_consumable_wire_bytes == 8);
    assert(extended_wire.size() ==
           extended.immediately_consumable_wire_bytes +
               extended.tunnel_bytes.size());

    server.Feed(client.EncodeBinary({}));
    auto empty = server.TakeDrain();
    assert(empty.tunnel_bytes.empty());
    assert(empty.immediately_consumable_wire_bytes == 6);

    server.Feed(client.EncodeClose());
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
    auto wire = client.EncodeBinary(payload);
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
    constrained.Feed(client.EncodeBinary(at_limit));
    assert(!constrained.failed());
    assert(constrained.TakeDrain().tunnel_bytes == at_limit);

    WebSocketCodec rejected(WebSocketRole::Server, at_limit.size());
    rejected.Feed(client.EncodeBinary(above_limit));
    assert(rejected.failed());

    const WebSocketBytes above_h2_profile(16U * 1024U + 1U, 0x43);
    WebSocketCodec general(WebSocketRole::Server);
    general.Feed(client.EncodeBinary(above_h2_profile));
    assert(!general.failed());
    assert(general.TakeDrain().tunnel_bytes == above_h2_profile);

    constexpr std::size_t kH2MessageBytes = 16U * 1024U;
    const WebSocketBytes fragmented_at_limit(kH2MessageBytes, 0x44);
    WebSocketCodec accepted_fragmented(WebSocketRole::Server,
                                       kH2MessageBytes);
    accepted_fragmented.Feed(client.EncodeBinaryFragmented(
        fragmented_at_limit, kH2MessageBytes / 2));
    assert(!accepted_fragmented.failed());
    assert(accepted_fragmented.TakeDrain().tunnel_bytes ==
           fragmented_at_limit);

    const WebSocketBytes fragmented_above_limit(kH2MessageBytes + 1, 0x45);
    WebSocketCodec rejected_fragmented(WebSocketRole::Server,
                                       kH2MessageBytes);
    rejected_fragmented.Feed(client.EncodeBinaryFragmented(
        fragmented_above_limit, kH2MessageBytes / 2));
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
    return 0;
}
