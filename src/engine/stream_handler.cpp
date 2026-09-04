/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "engine/stream_handler.hpp"

#include <utility>

namespace yume::engine {

StreamOpenContext::StreamOpenContext(
    StreamId stream_id,
    std::string service_name,
    ServiceKind service_kind,
    PeerEvidence peer_evidence,
    std::optional<RouteDestination> destination) noexcept
    : stream_id_(stream_id),
      service_name_(std::move(service_name)),
      service_kind_(service_kind),
      peer_evidence_(std::move(peer_evidence)),
      destination_(std::move(destination)) {}

Result<StreamOpenContext> StreamOpenContext::create(
    StreamId stream_id,
    std::string service_name,
    ServiceKind service_kind,
    PeerEvidence peer_evidence,
    std::optional<RouteDestination> destination) {
    if (stream_id.is_control()) {
        return Result<StreamOpenContext>(Status(
            StatusCode::InvalidArgument,
            "stream zero cannot be dispatched to an application service"));
    }
    if (!valid_service_name(service_name)) {
        return Result<StreamOpenContext>(Status(
            StatusCode::InvalidArgument,
            "service name is invalid"));
    }
    if (destination &&
        ((service_kind == ServiceKind::ByteStream &&
          destination->protocol() != NetworkProtocol::Tcp) ||
         (service_kind == ServiceKind::PacketChannel &&
          destination->protocol() != NetworkProtocol::Udp))) {
        return Result<StreamOpenContext>(Status(
            StatusCode::InvalidArgument,
            "route protocol does not match the service kind"));
    }
    return Result<StreamOpenContext>(StreamOpenContext(
        stream_id, std::move(service_name), service_kind,
        std::move(peer_evidence), std::move(destination)));
}

void StreamHandler::on_route(
    AuthorizedRouteRequest,
    std::shared_ptr<StreamResponder> stream) {
    if (stream) {
        stream->close(Status(
            StatusCode::FailedPrecondition,
            "stream handler does not implement authorized routing"));
    }
}

}  // namespace yume::engine
