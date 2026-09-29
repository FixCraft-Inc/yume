/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/client_routes.hpp"

#include <algorithm>
#include <new>

#include "runtime/cluster_state.hpp"
#include "ytp/security.hpp"

namespace yume::runtime {

using engine::Result;
using engine::Status;
using engine::StatusCode;

Result<cluster::Routes> accept_served_routes(
    NativeCircuitCredentials& circuits, std::span<const std::byte> served,
    std::chrono::system_clock::time_point now) noexcept {
    using Accepted = Result<cluster::Routes>;
    try {
        if (served.size() <= ytp1::kCompositeSignatureSize) {
            return Accepted(Status::diagnostic(
                StatusCode::InvalidArgument,
                "the entry served a routes view without a body"));
        }
        auto routes = cluster::verify_routes(
            served.subspan(ytp1::kCompositeSignatureSize),
            served.first(ytp1::kCompositeSignatureSize),
            circuits.operator_key_pem, now);
        if (!routes.ok()) return routes;
        const auto& view = routes.value();
        if (view.serial < circuits.floor) {
            return Accepted(
                Status::diagnostic(StatusCode::FailedPrecondition,
                                   "the entry served a routes view older than "
                                   "one this client has verified"));
        }
        if (view.find(circuits.entry) == nullptr) {
            return Accepted(Status::diagnostic(
                StatusCode::FailedPrecondition,
                "the entry served a routes view that does not name it"));
        }
        if (view.serial > circuits.saved) {
            if (const auto saved = cluster::write_state(
                    circuits.state, {circuits.cluster, view.serial});
                !saved.ok()) {
                return Accepted(Status::diagnostic(
                    StatusCode::FailedPrecondition,
                    "the circuits state file could not be written"));
            }
            circuits.saved = view.serial;
        }
        circuits.floor = std::max(circuits.floor, view.serial);
        return routes;
    } catch (const std::bad_alloc&) {
        return Accepted(Status(StatusCode::ResourceExhausted));
    } catch (...) {
        return Accepted(Status(StatusCode::Internal));
    }
}

}  // namespace yume::runtime
