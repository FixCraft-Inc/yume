/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/runtime/admin_relationships.hpp"

#include <algorithm>
#include <vector>

namespace yume::server::admin_relationships {

namespace {

void add_unique(std::vector<std::string>* values, const std::string& value) {
    if (!values || value.empty()) {
        return;
    }
    if (std::find(values->begin(), values->end(), value) == values->end()) {
        values->push_back(value);
    }
}

void remove_value(std::vector<std::string>* values,
                  const std::string& value) {
    if (!values) {
        return;
    }
    values->erase(std::remove(values->begin(), values->end(), value),
                  values->end());
}

}  // namespace

bool is_established_admin_channel(
    const control::ActiveRelayChannel& channel) noexcept {
    return channel.channel_kind == control::ChannelKind::admin &&
        !channel.pending && !channel.left_endpoint_id.empty() &&
        !channel.right_endpoint_id.empty();
}

bool has_established_channel(const ActiveChannelMap& active_channels,
                             const std::string& controller_id,
                             const std::string& target_id) noexcept {
    return std::any_of(
        active_channels.begin(), active_channels.end(),
        [&](const auto& entry) {
            const auto& channel = entry.second;
            return is_established_admin_channel(channel) &&
                channel.left_endpoint_id == controller_id &&
                channel.right_endpoint_id == target_id;
        });
}

void add_local_relationship(control::EndpointInfo* controller,
                            control::EndpointInfo* target,
                            const std::string& controller_id,
                            const std::string& target_id) {
    if (controller_id.empty() || target_id.empty()) {
        return;
    }
    if (controller) {
        add_unique(&controller->controlled_target_ids, target_id);
    }
    if (target) {
        add_unique(&target->controller_ids, controller_id);
    }
}

void remove_local_relationship_if_unused(
    const ActiveChannelMap& active_channels,
    control::EndpointInfo* controller,
    control::EndpointInfo* target,
    const std::string& controller_id,
    const std::string& target_id) {
    if (has_established_channel(active_channels, controller_id, target_id)) {
        return;
    }
    if (controller) {
        remove_value(&controller->controlled_target_ids, target_id);
    }
    if (target) {
        remove_value(&target->controller_ids, controller_id);
    }
}

}  // namespace yume::server::admin_relationships
