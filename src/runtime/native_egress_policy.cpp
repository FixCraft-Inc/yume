/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/native_egress_policy.hpp"

#include <algorithm>
#include <new>
#include <string>
#include <utility>
#include <variant>

#include "common/egress_address.hpp"
#include "fs/bounded_file.hpp"
#include "runtime/egress_lists.hpp"

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

// Keeps the loader's code and prefixes the configuration entry.
Status at_entry(const std::string& pointer, const Status& status) {
    return Status(status.code(), pointer + ": " + status.message());
}

std::vector<std::uint8_t> read_list_file(const std::filesystem::path& base,
                                         const config::v1::FileReference& file,
                                         std::size_t maximum,
                                         const std::string& pointer) {
    const std::filesystem::path path(file.path());
    std::vector<std::uint8_t> contents;
    std::string error;
    if (!read_file_bounded(path.is_absolute() ? path : base / path, maximum, &contents, &error)) {
        throw Status(StatusCode::InvalidArgument,
                     pointer + ": " + (error.empty() ? std::string("cannot read the file") : error));
    }
    return contents;
}

// Reads one adapter's lists and country database into rules. Throws Status.
std::shared_ptr<const EgressListRules> load_lists(const config::v1::DestinationPolicy& destinations,
                                                  const std::filesystem::path& base,
                                                  const std::string& pointer) {
    using config::v1::DestinationListAction;
    using config::v1::DestinationListFormat;
    EgressListBuilder builder;
    for (std::size_t index = 0; index < destinations.lists().size(); ++index) {
        const auto& list = destinations.lists()[index];
        const std::string entry = pointer + "/lists/" + std::to_string(index);
        const bool json = list.format() == DestinationListFormat::Json;
        const auto contents = read_list_file(base, list.file(),
                                             json ? kMaxJsonListBytes : kMaxVpdbBytes, entry);
        const auto action = list.action() == DestinationListAction::Allow ? EgressListAction::Allow
                                                                          : EgressListAction::Deny;
        const Status added = json
            ? builder.add_json_list(
                  std::string_view(reinterpret_cast<const char*>(contents.data()), contents.size()),
                  action)
            : builder.add_vpdb(contents, action);
        if (!added.ok()) throw at_entry(entry, added);
    }
    const std::string database = pointer + "/country_database";
    if (destinations.country_database()) {
        if (!builder.needs_country_database()) {
            throw Status(StatusCode::InvalidArgument, database + ": no list names a country");
        }
        const auto contents = read_list_file(base, *destinations.country_database(),
                                             kMaxCountryDatabaseBytes, database);
        const Status added = builder.add_country_database(contents);
        if (!added.ok()) throw at_entry(database, added);
    } else if (builder.needs_country_database()) {
        throw Status(StatusCode::InvalidArgument,
                     pointer + ": a list names countries, so country_database is required");
    }
    auto built = builder.build();
    if (!built.ok()) throw at_entry(pointer, built.status());
    return std::move(built).take_value();
}

bool same_lists(const config::v1::DestinationPolicy& left,
                const config::v1::DestinationPolicy& right) noexcept {
    const auto& a = left.lists();
    const auto& b = right.lists();
    if (a.size() != b.size()) return false;
    for (std::size_t index = 0; index < a.size(); ++index) {
        if (a[index].action() != b[index].action() || a[index].format() != b[index].format() ||
            a[index].file().path() != b[index].file().path()) {
            return false;
        }
    }
    const auto& x = left.country_database();
    const auto& y = right.country_database();
    return x.has_value() == y.has_value() && (!x || x->path() == y->path());
}
}  // namespace

NativeEgressPolicy::NativeEgressPolicy(std::vector<Rule> rules) noexcept
    : rules_(std::move(rules)) {}

engine::Result<std::shared_ptr<const NativeEgressPolicy>> NativeEgressPolicy::create(
    const std::vector<config::v1::Adapter>& adapters,
    const std::filesystem::path& base_directory) {
    using Created = engine::Result<std::shared_ptr<const NativeEgressPolicy>>;
    try {
        std::vector<Rule> rules;
        rules.reserve(adapters.size());
        for (std::size_t index = 0; index < adapters.size(); ++index) {
            const auto& adapter = adapters[index];
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
            std::shared_ptr<const EgressListRules> lists;
            if (!destinations.lists().empty()) {
                const auto shared = std::find_if(rules.begin(), rules.end(), [&](const Rule& rule) {
                    return rule.lists && same_lists(rule.destinations, destinations);
                });
                lists = shared != rules.end()
                    ? shared->lists
                    : load_lists(destinations, base_directory,
                                 "/adapters/" + std::to_string(index) + "/destinations");
            }
            rules.push_back(Rule{service, protocol, destinations, std::move(lists)});
        }
        return Created(std::shared_ptr<const NativeEgressPolicy>(
            new NativeEgressPolicy(std::move(rules))));
    } catch (const Status& status) {
        return Created(status);
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
    const bool permitted =
        (address_class == common::EgressAddressClass::Public &&
         rule.destinations.public_addresses()) ||
        std::any_of(rule.destinations.networks().begin(), rule.destinations.networks().end(),
                    [&](const common::IpNetwork& network) {
                        return common::ip_network_contains(network, address->family(),
                                                           address->bytes());
                    });
    if (!permitted) return refusal("destination is outside the service's permitted destinations");
    // Lists only narrow: an Allow entry exempts an address from a broader
    // Deny, never from the adapter's own destinations.
    if (rule.lists && rule.lists->match(address->family(), address->bytes()) == EgressListAction::Deny) {
        return refusal("an egress list refuses the destination");
    }
    return Status::success();
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
