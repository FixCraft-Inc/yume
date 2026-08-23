/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/runtime/admin_relationships.hpp"

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

namespace {

using yume::control::ActiveRelayChannel;
using yume::control::ChannelKind;
using yume::control::EndpointInfo;
using yume::server::admin_relationships::ActiveChannelMap;

bool contains(const std::vector<std::string>& values,
              const std::string& value) {
    return std::find(values.begin(), values.end(), value) != values.end();
}

ActiveRelayChannel channel(std::string id, bool pending = false) {
    ActiveRelayChannel result;
    result.channel_id = std::move(id);
    result.channel_kind = ChannelKind::admin;
    result.left_endpoint_id = "controller";
    result.right_endpoint_id = "target";
    result.pending = pending;
    return result;
}

void test_only_established_admin_channels_count() {
    auto pending = channel("pending", true);
    assert(!yume::server::admin_relationships::is_established_admin_channel(
        pending));

    auto ordinary = channel("ordinary");
    ordinary.channel_kind = ChannelKind::file;
    assert(!yume::server::admin_relationships::is_established_admin_channel(
        ordinary));

    auto established = channel("established");
    assert(yume::server::admin_relationships::is_established_admin_channel(
        established));
}

void test_federated_half_is_recorded_on_the_local_endpoint() {
    EndpointInfo controller;
    EndpointInfo target;

    yume::server::admin_relationships::add_local_relationship(
        &controller, nullptr, "controller", "remote/target");
    assert(contains(controller.controlled_target_ids, "remote/target"));

    yume::server::admin_relationships::add_local_relationship(
        nullptr, &target, "remote/controller", "target");
    assert(contains(target.controller_ids, "remote/controller"));

    // Re-registration of the same established channel remains idempotent.
    yume::server::admin_relationships::add_local_relationship(
        &controller, nullptr, "controller", "remote/target");
    assert(controller.controlled_target_ids.size() == 1);
}

void test_relationship_survives_until_the_last_channel_closes() {
    EndpointInfo controller;
    EndpointInfo target;
    ActiveChannelMap active;
    active.emplace("one", channel("one"));
    active.emplace("two", channel("two"));
    yume::server::admin_relationships::add_local_relationship(
        &controller, &target, "controller", "target");

    active.erase("one");
    yume::server::admin_relationships::remove_local_relationship_if_unused(
        active, &controller, &target, "controller", "target");
    assert(contains(controller.controlled_target_ids, "target"));
    assert(contains(target.controller_ids, "controller"));

    active.erase("two");
    yume::server::admin_relationships::remove_local_relationship_if_unused(
        active, &controller, &target, "controller", "target");
    assert(controller.controlled_target_ids.empty());
    assert(target.controller_ids.empty());
}

}  // namespace

int main() {
    test_only_established_admin_channels_count();
    test_federated_half_is_recorded_on_the_local_endpoint();
    test_relationship_survives_until_the_last_channel_closes();
    std::puts("admin_relationships_test: all cases passed");
    return 0;
}
