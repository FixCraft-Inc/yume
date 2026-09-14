/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include "common/ip_network.hpp"

namespace yume::common {

// How destination policy may treat a numeric address. The schema-1 parser and
// the native egress policy both read these tables, so a configured network
// cannot be accepted by one and ignored by the other.
enum class EgressAddressClass : std::uint8_t {
    // Unspecified, multicast and reserved IPv4 space including broadcast.
    // Linux connects an unspecified destination to the local host, so no
    // configuration can permit these.
    NeverAllowed,
    // Private, shared, loopback, link-local, documentation, benchmarking,
    // translation and other special-purpose space. Only an explicit network
    // permits these.
    ExplicitOnly,
    // Globally reachable unicast space.
    Public,
};

namespace detail {

inline constexpr std::array<IpNetwork, 4> kNeverAllowedNetworks{{
    {IpFamily::V4, {0}, 8},
    {IpFamily::V4, {224}, 3},
    {IpFamily::V6, {}, 128},
    {IpFamily::V6, {0xff}, 8},
}};

inline constexpr IpNetwork kIpv4MappedNetwork{
    IpFamily::V6, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}, 96};

inline constexpr std::array<IpNetwork, 12> kExplicitOnlyIpv4{{
    {IpFamily::V4, {10}, 8},
    {IpFamily::V4, {100, 64}, 10},
    {IpFamily::V4, {127}, 8},
    {IpFamily::V4, {169, 254}, 16},
    {IpFamily::V4, {172, 16}, 12},
    {IpFamily::V4, {192, 0, 0}, 24},
    {IpFamily::V4, {192, 0, 2}, 24},
    {IpFamily::V4, {192, 88, 99}, 24},
    {IpFamily::V4, {192, 168}, 16},
    {IpFamily::V4, {198, 18}, 15},
    {IpFamily::V4, {198, 51, 100}, 24},
    {IpFamily::V4, {203, 0, 113}, 24},
}};

// Only 2000::/3 is allocated as IPv6 global unicast. Inside it, 2001::/23
// holds protocol assignments including Teredo, and 6to4 uses 2002::/16. Both
// can embed private IPv4 addresses. The others are documentation prefixes.
inline constexpr IpNetwork kIpv6GlobalUnicast{IpFamily::V6, {0x20}, 3};
inline constexpr std::array<IpNetwork, 4> kExplicitOnlyIpv6Global{{
    {IpFamily::V6, {0x20, 0x01}, 23},
    {IpFamily::V6, {0x20, 0x01, 0x0d, 0xb8}, 32},
    {IpFamily::V6, {0x20, 0x02}, 16},
    {IpFamily::V6, {0x3f, 0xff}, 20},
}};

inline bool contained_in_any(std::span<const IpNetwork> table,
                             IpFamily family,
                             std::span<const std::uint8_t> bytes) noexcept {
    return std::any_of(table.begin(), table.end(), [&](const IpNetwork& network) {
        return ip_network_contains(network, family, bytes);
    });
}

}  // namespace detail

// A numeric destination in the form policy evaluates. IPv4-mapped IPv6 names
// an IPv4 destination and becomes IPv4, so an IPv6 network can never admit a
// private IPv4 address through its mapped spelling.
class EgressAddress final {
public:
    // Refuses input whose size differs from the family's address size.
    static std::optional<EgressAddress> from_bytes(
        IpFamily family, std::span<const std::uint8_t> bytes) noexcept {
        if (bytes.size() != detail::ip_address_bytes(family)) return std::nullopt;
        EgressAddress address;
        if (family == IpFamily::V6 &&
            ip_network_contains(detail::kIpv4MappedNetwork, family, bytes)) {
            address.family_ = IpFamily::V4;
            std::copy(bytes.begin() + 12, bytes.end(), address.bytes_.begin());
        } else {
            address.family_ = family;
            std::copy(bytes.begin(), bytes.end(), address.bytes_.begin());
        }
        return address;
    }

    IpFamily family() const noexcept { return family_; }
    std::span<const std::uint8_t> bytes() const noexcept {
        return std::span<const std::uint8_t>(bytes_).first(
            detail::ip_address_bytes(family_));
    }

private:
    EgressAddress() noexcept = default;

    IpFamily family_{IpFamily::V4};
    std::array<std::uint8_t, 16> bytes_{};
};

inline EgressAddressClass classify_egress_address(
    const EgressAddress& address) noexcept {
    const auto bytes = address.bytes();
    if (detail::contained_in_any(detail::kNeverAllowedNetworks, address.family(), bytes)) {
        return EgressAddressClass::NeverAllowed;
    }
    if (address.family() == IpFamily::V4) {
        return detail::contained_in_any(detail::kExplicitOnlyIpv4, IpFamily::V4, bytes)
            ? EgressAddressClass::ExplicitOnly
            : EgressAddressClass::Public;
    }
    if (!ip_network_contains(detail::kIpv6GlobalUnicast, IpFamily::V6, bytes) ||
        detail::contained_in_any(detail::kExplicitOnlyIpv6Global, IpFamily::V6, bytes)) {
        return EgressAddressClass::ExplicitOnly;
    }
    return EgressAddressClass::Public;
}

// True when no destination could ever match the network: it lies inside
// never-allowed space, or inside IPv4-mapped space, which is evaluated as IPv4.
inline bool ip_network_never_allowed(const IpNetwork& network) noexcept {
    const auto inside = [&network](const IpNetwork& outer) {
        return outer.family == network.family &&
               network.prefix_length >= outer.prefix_length &&
               ip_network_contains(outer, network.family,
                   std::span<const std::uint8_t>(network.address)
                       .first(detail::ip_address_bytes(network.family)));
    };
    return std::any_of(detail::kNeverAllowedNetworks.begin(),
                       detail::kNeverAllowedNetworks.end(), inside) ||
           inside(detail::kIpv4MappedNetwork);
}

}  // namespace yume::common
