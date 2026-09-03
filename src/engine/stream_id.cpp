/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "engine/stream_id.hpp"

namespace yume::engine {

Result<StreamId> StreamId::application(std::uint32_t value,
                                       EndpointRole owner) {
    if (value == 0U) {
        return Result<StreamId>(Status(
            StatusCode::InvalidArgument,
            "stream zero is reserved for session control"));
    }
    if (value > kMaxApplicationValue) {
        return Result<StreamId>(Status(
            StatusCode::InvalidArgument,
            "application stream ID exceeds the 31-bit YTP/1 limit"));
    }
    const StreamId candidate(value);
    if (!candidate.owned_by(owner)) {
        return Result<StreamId>(Status(
            StatusCode::InvalidArgument,
            owner == EndpointRole::Client
                ? "client-owned stream IDs must be odd"
                : "server-owned stream IDs must be even"));
    }
    return Result<StreamId>(candidate);
}

Result<StreamId> StreamId::peer_application(std::uint32_t value,
                                            EndpointRole local_role) {
    const EndpointRole peer_role = local_role == EndpointRole::Client
        ? EndpointRole::Server
        : EndpointRole::Client;
    return application(value, peer_role);
}

}  // namespace yume::engine
