/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "config/v1/config.hpp"
#include "engine/route_provider.hpp"
#include "engine/stream_handler.hpp"

namespace yume::runtime {

// Destination authority declared by schema-1 direct adapters. One immutable
// rule per (service, protocol) decides both stages of a routed OPEN. The
// requested destination is checked before any DNS or socket work, then every
// numeric address a DNS name selects is checked before a socket opens.
// Port and hostname are not policy inputs. Unspecified, multicast and
// reserved addresses are refused even when a network contains them, and
// IPv4-mapped IPv6 is evaluated as IPv4.
class NativeEgressPolicy final {
public:
    // Adapters other than direct TCP/UDP are ignored. A policy without direct
    // adapters permits nothing. A duplicate service/protocol pair or a rule
    // that permits nothing is InvalidArgument.
    static engine::Result<std::shared_ptr<const NativeEgressPolicy>> create(
        const std::vector<config::v1::Adapter>& adapters);

    NativeEgressPolicy(const NativeEgressPolicy&) = delete;
    NativeEgressPolicy& operator=(const NativeEgressPolicy&) = delete;

    // Decides a numeric destination. A DNS name passes to authorize_resolved,
    // which the route provider must apply to every selected address. An OPEN
    // without a destination, or for an undeclared service, is refused.
    engine::Status authorize_request(
        const engine::StreamOpenContext& context) const noexcept;
    // Decides one resolved numeric address for an already authorized request.
    engine::Status authorize_resolved(
        const engine::AuthorizedRouteRequest& request,
        const engine::RouteDestination& resolved) const noexcept;
    // Decides one numeric destination for a declared service and protocol.
    // DNS names are refused here.
    engine::Status authorize_address(
        std::string_view service,
        const engine::RouteDestination& destination) const noexcept;

private:
    struct Rule final {
        std::string service;
        engine::NetworkProtocol protocol;
        config::v1::DestinationPolicy destinations;
    };

    explicit NativeEgressPolicy(std::vector<Rule> rules) noexcept;
    const Rule* find(std::string_view service,
                     engine::NetworkProtocol protocol) const noexcept;
    static engine::Status evaluate(
        const Rule& rule, const engine::RouteDestination& destination) noexcept;

    std::vector<Rule> rules_;
};

}  // namespace yume::runtime
