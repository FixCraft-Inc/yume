/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/native_egress_policy.hpp"

#include <algorithm>
#include <new>
#include <utility>
#include <variant>

#include "common/egress_address.hpp"

namespace yume::runtime {
namespace {
using engine::NetworkProtocol;
using engine::RouteAddressKind;
using engine::Status;
using engine::StatusCode;

// Refusal text is diagnostic only. Losing it to allocation failure keeps the
// typed refusal.
Status refusal(std::string_view message) noexcept {
    try {
        return Status(StatusCode::PermissionDenied, message);
    } catch (...) {
        return Status(StatusCode::PermissionDenied);
    }
}
}  // namespace

NativeEgressPolicy::NativeEgressPolicy(std::vector<Rule> rules) noexcept
    : rules_(std::move(rules)) {}

engine::Result<std::shared_ptr<const NativeEgressPolicy>> NativeEgressPolicy::create(
    const std::vector<config::v1::Adapter>& adapters) {
    using Created = engine::Result<std::shared_ptr<const NativeEgressPolicy>>;
    try {
        std::vector<Rule> rules;
        rules.reserve(adapters.size());
        for (const auto& adapter : adapters) {
            const auto* tcp = std::get_if<config::v1::DirectTcpAdapter>(&adapter);
            const auto* udp = std::get_if<config::v1::DirectUdpAdapter>(&adapter);
            if (!tcp && !udp) continue;
            const auto& service = tcp ? tcp->service() : udp->service();
            const auto protocol = tcp ? NetworkProtocol::Tcp : NetworkProtocol::Udp;
            const auto& destinations = tcp ? tcp->destinations() : udp->destinations();
            if (!destinations.public_addresses() && destinations.networks().empty()) {
                return Created(Status(StatusCode::InvalidArgument,
                    "direct adapter destination policy permits nothing"));
            }
            if (std::any_of(rules.begin(), rules.end(), [&](const Rule& rule) {
                    return rule.service == service && rule.protocol == protocol;
                })) {
                return Created(Status(StatusCode::InvalidArgument,
                    "duplicate direct adapter destination policy"));
            }
            rules.push_back(Rule{service, protocol, destinations});
        }
        return Created(std::shared_ptr<const NativeEgressPolicy>(
            new NativeEgressPolicy(std::move(rules))));
    } catch (const std::bad_alloc&) {
        return Created(Status(StatusCode::ResourceExhausted));
    }
}

const NativeEgressPolicy::Rule* NativeEgressPolicy::find(
    std::string_view service, NetworkProtocol protocol) const noexcept {
    const auto found = std::find_if(rules_.begin(), rules_.end(), [&](const Rule& rule) {
        return rule.protocol == protocol && rule.service == service;
    });
    return found == rules_.end() ? nullptr : &*found;
}

Status NativeEgressPolicy::evaluate(const Rule& rule,
                                    const engine::RouteDestination& destination) noexcept {
    if (destination.address_kind() == RouteAddressKind::DnsName) {
        return refusal("destination policy requires a numeric address");
    }
    const auto family = destination.address_kind() == RouteAddressKind::Ipv4
        ? common::IpFamily::V4
        : common::IpFamily::V6;
    const auto address =
        common::EgressAddress::from_bytes(family, destination.address_bytes());
    if (!address) return refusal("malformed destination address");
    const auto address_class = common::classify_egress_address(*address);
    if (address_class == common::EgressAddressClass::NeverAllowed) {
        return refusal("destination address is never reachable");
    }
    if (address_class == common::EgressAddressClass::Public &&
        rule.destinations.public_addresses()) {
        return Status::success();
    }
    for (const auto& network : rule.destinations.networks()) {
        if (common::ip_network_contains(network, address->family(), address->bytes())) {
            return Status::success();
        }
    }
    return refusal("destination is outside the service's permitted destinations");
}

Status NativeEgressPolicy::authorize_request(
    const engine::StreamOpenContext& context) const noexcept {
    const auto* destination = context.destination_if();
    if (!destination) return refusal("direct adapter OPEN requires a destination");
    if (destination->address_kind() != RouteAddressKind::DnsName) {
        return authorize_address(context.service_name(), *destination);
    }
    // Resolution selects the numeric addresses. authorize_resolved decides each.
    return find(context.service_name(), destination->protocol())
        ? Status::success()
        : refusal("service has no destination policy for this protocol");
}

Status NativeEgressPolicy::authorize_resolved(
    const engine::AuthorizedRouteRequest& request,
    const engine::RouteDestination& resolved) const noexcept {
    if (resolved.protocol() != request.destination().protocol()) {
        return refusal("resolved destination changed protocol");
    }
    return authorize_address(request.service_name(), resolved);
}

Status NativeEgressPolicy::authorize_address(
    std::string_view service, const engine::RouteDestination& destination) const noexcept {
    const Rule* rule = find(service, destination.protocol());
    if (!rule) return refusal("service has no destination policy for this protocol");
    return evaluate(*rule, destination);
}

}  // namespace yume::runtime
