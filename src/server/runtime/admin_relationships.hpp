/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <string>
#include <unordered_map>

#include "core/protocol/control_protocol.hpp"

namespace yume::server::admin_relationships {

using ActiveChannelMap =
    std::unordered_map<std::string, control::ActiveRelayChannel>;

bool is_established_admin_channel(
    const control::ActiveRelayChannel& channel) noexcept;

bool has_established_channel(const ActiveChannelMap& active_channels,
                             const std::string& controller_id,
                             const std::string& target_id) noexcept;

// Either endpoint may be null when its other half belongs to a federation
// peer. The relationship is still published on whichever endpoint is local.
void add_local_relationship(control::EndpointInfo* controller,
                            control::EndpointInfo* target,
                            const std::string& controller_id,
                            const std::string& target_id);

void remove_local_relationship_if_unused(
    const ActiveChannelMap& active_channels,
    control::EndpointInfo* controller,
    control::EndpointInfo* target,
    const std::string& controller_id,
    const std::string& target_id);

}  // namespace yume::server::admin_relationships
