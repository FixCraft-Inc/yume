/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <span>

#include "engine/status.hpp"
#include "runtime/cluster_list.hpp"
#include "runtime/native_credentials.hpp"

namespace yume::runtime {

// Checks the routes view a client's entry served on yume.routes: the
// operator's signature over the view, then the view's bytes, as the node
// sends them. The view must verify under the operator key, not have
// expired, have at least the client's floor as its serial and name the
// client's entry. A higher serial than the state file holds is saved there
// before the view is used, and the floor rises to it. FailedPrecondition
// for an expired or older view, one without the entry or a state file that
// cannot be written, and verify_routes's codes otherwise.
engine::Result<cluster::Routes> accept_served_routes(
    NativeCircuitCredentials& circuits, std::span<const std::byte> served,
    std::chrono::system_clock::time_point now) noexcept;

}  // namespace yume::runtime
