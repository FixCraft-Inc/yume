/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>

namespace yume::relay {

// What a relay channel carries. The handshake encodes these as 1 to 4 in this
// order, and the control records spell them "chat", "file", "bytes" and
// "admin".
enum class ChannelKind : std::uint8_t {
    Chat,
    File,
    Bytes,
    Admin,
};

}  // namespace yume::relay
