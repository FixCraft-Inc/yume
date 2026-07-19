#include "core/stealth/websocket_codec.hpp"

#include <cassert>

namespace {

using yume::obfs::WebSocketBytes;
using yume::obfs::WebSocketCodec;
using yume::obfs::WebSocketRole;

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

}  // namespace

int main() {
    RoundTripAndMasking();
    FragmentAndPing();
    EncodeFragmentedRoundTrip();
    RejectWrongMaskAndText();
    return 0;
}
