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
    assert(server.TakeDecoded() == payload);

    auto response = server.EncodeBinary(payload);
    assert((response[1] & 0x80U) == 0);
    client.Feed(response);
    assert(client.TakeDecoded() == payload);
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
    assert(server.TakeDecoded() == WebSocketBytes({'a', 'b', 'c', 'd'}));
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
    assert(client.TakeDecoded() == payload);
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
    server.Feed(wire.data() + wire.size() - 1, 1);
    assert(observed.size() == 1);
    assert(observed[0].opcode == 0x2);
    assert(observed[0].final);
    assert(observed[0].masked);
    assert(observed[0].payload_bytes == payload.size());

    WebSocketCodec invalid(WebSocketRole::Server);
    invalid.set_inbound_frame_observer(&ObserveFrame, &observed);
    invalid.Feed(WebSocketBytes{0x81, 0x81, 1, 2, 3, 4,
                                static_cast<unsigned char>('x' ^ 1)});
    assert(invalid.failed());
    assert(observed.size() == 1);
}

}  // namespace

int main() {
    RoundTripAndMasking();
    FragmentAndPing();
    EncodeFragmentedRoundTrip();
    RejectWrongMaskAndText();
    ObserveOnlyCompleteValidatedMetadata();
    return 0;
}
