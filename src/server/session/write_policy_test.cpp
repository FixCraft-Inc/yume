/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/session/write_policy.hpp"

#include <cassert>
#include <cstddef>

int main() {
    using yume::server::detail::frame_write_priority;

    const int saturated_packet_priority =
        frame_write_priority(yume::protocol::DATA, 64U * 1024U);
    assert(frame_write_priority(yume::protocol::REKEY_INIT, 4096) == 0);
    assert(frame_write_priority(yume::protocol::REKEY_ACK, 4096) == 0);
    assert(frame_write_priority(yume::protocol::REKEY_INIT, 4096) <
           saturated_packet_priority);
    assert(frame_write_priority(yume::protocol::REKEY_ACK, 4096) <
           saturated_packet_priority);
    return 0;
}
