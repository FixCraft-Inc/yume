/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/runtime/service_stream.hpp"

#include <cassert>
#include <cstdint>
#include <string>

namespace {

yume::runtime::ServiceStream::Bytes one_byte(std::uint8_t value) {
    return yume::runtime::ServiceStream::Bytes{value};
}

}  // namespace

int main() {
    using yume::runtime::ServiceStream;
    using yume::runtime::kMaxInboundQueuedFrames;

    ServiceStream stream("svc", "peer");
    std::string error;
    for (std::size_t i = 0; i < kMaxInboundQueuedFrames; ++i) {
        assert(stream.receive_data(one_byte(static_cast<std::uint8_t>(i)), &error));
    }
    assert(!stream.receive_data(one_byte(0xff), &error));
    assert(!error.empty());

    std::uint8_t out = 0;
    std::size_t bytes_read = 0;
    std::string reason;
    assert(stream.read(&out, sizeof(out), 0, &bytes_read, &reason) ==
           ServiceStream::ReadResult::Data);
    assert(bytes_read == 1U);
    assert(stream.receive_data(one_byte(0xee), &error));

    stream.close("test close");
    assert(stream.closed());
    assert(stream.read(&out, sizeof(out), 0, &bytes_read, &reason) ==
           ServiceStream::ReadResult::Closed);
    assert(stream.receive_data(one_byte(0xdd), &error));

    return 0;
}
