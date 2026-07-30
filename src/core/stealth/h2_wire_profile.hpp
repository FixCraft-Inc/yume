/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "core/stealth/cover_profile.hpp"

namespace yume::obfs::detail {

// New nghttp2 releases ignore the deprecated RFC 7540 priority argument.
// This adapter preserves the version-pinned captured request bytes while
// leaving HPACK and the rest of the HTTP/2 state machine with nghttp2.
class H2WireProfile {
public:
    using Bytes = std::vector<std::uint8_t>;

    bool QueuePriority(
        std::int32_t stream_id,
        const cover_profile::H2Priority& priority,
        std::string& error);

    bool AppendSerializedBatch(
        const Bytes& batch,
        std::size_t max_output_bytes,
        Bytes& output,
        std::string& error);

private:
    std::unordered_map<std::int32_t, cover_profile::H2Priority>
        pending_priorities_;
};

}  // namespace yume::obfs::detail
