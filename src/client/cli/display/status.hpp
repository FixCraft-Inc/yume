/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace yume::client {

struct HopStatusSnapshot {
    bool enabled = false;
    std::uint32_t interval_ms = 0;
    std::int64_t offset_ms = 0;
};

struct ConnectionStatusSummary {
    std::string server;
    std::string version;
    std::string inner_kdf_name;
    std::vector<std::string> verified_proof_sources;
    HopStatusSnapshot hop;
    bool obfuscation_enabled = false;
    bool inner_established = false;
    bool inner_heavy = false;
    bool have_inner_caps = false;
    bool server_inner_dual = false;
    bool server_inner_active = false;
    bool verity_applicable = false;
    bool verity_ok = false;
    std::uint64_t epoch_byte_limit = 0;
    std::uint64_t epoch_frame_limit = 0;
    std::uint64_t epoch_active_limit_ms = 0;
};

std::function<std::string()> make_connection_status_block(ConnectionStatusSummary summary);

}  // namespace yume::client
