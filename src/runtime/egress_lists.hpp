/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "common/ip_network.hpp"
#include "engine/status.hpp"

namespace yume::runtime {

// Egress lists name destination addresses that a direct adapter refuses, or
// exempts from a broader refusal. They only narrow what the adapter's own
// destination policy permits.
enum class EgressListAction : std::uint8_t {
    Allow,
    Deny,
};

// Operator files are read whole, so each format has a size bound, and all
// lists and countries together have a range bound.
inline constexpr std::size_t kMaxJsonListBytes = 16U * 1024U * 1024U;
inline constexpr std::size_t kMaxVpdbBytes = 128U * 1024U * 1024U;
inline constexpr std::size_t kMaxCountryDatabaseBytes = 128U * 1024U * 1024U;
inline constexpr std::size_t kMaxEgressListRanges = 2U * 1024U * 1024U;

// The decision for the addresses that list ranges cover. An address takes the
// action of the most specific range that contains it, and Deny when an Allow
// and a Deny range are equally specific. A network's specificity is its prefix
// length. An arbitrary range counts as the smallest network that holds it.
// Country ranges have specificity 0, so every address range overrides them.
class EgressListRules final {
public:
    // nullopt when no range contains the address. IPv4 takes four bytes and
    // IPv6 sixteen. IPv4-mapped IPv6 is not converted here.
    std::optional<EgressListAction> match(
        common::IpFamily family,
        std::span<const std::uint8_t> address) const noexcept;

    bool empty() const noexcept { return v4_.empty() && v6_.empty(); }

private:
    friend class EgressListBuilder;

    // Disjoint, sorted and inclusive. IPv4 uses the first four bytes.
    struct Segment final {
        std::array<std::uint8_t, 16> first{};
        std::array<std::uint8_t, 16> last{};
        EgressListAction action{EgressListAction::Deny};
    };

    std::vector<Segment> v4_;
    std::vector<Segment> v6_;
};

// Collects list files and country rules, then builds immutable rules. Each
// add takes every entry of its input or, when it fails, none of them.
class EgressListBuilder final {
public:
    // A JSON object {"ips": [...], "countries": [...]} with at least one of
    // the two arrays. An "ips" entry is an IPv4 or IPv6 address, or a network
    // with zero host bits. A country is a two-letter ISO 3166 code.
    engine::Status add_json_list(std::string_view text, EgressListAction action);
    // A binary VPN provider database, format 1 ("VPDB").
    engine::Status add_vpdb(std::span<const std::uint8_t> data, EgressListAction action);

    // True once a list named a country. Countries turn into address ranges
    // only through add_country_database.
    bool needs_country_database() const noexcept { return !countries_.empty(); }
    // Reads a MaxMind DB (MMDB) file and adds the ranges of every country the
    // lists named. A record's country is country.iso_code, or
    // registered_country.iso_code when it has none. Call it once, after every
    // list that names countries. A later list that names one is refused.
    engine::Status add_country_database(std::span<const std::uint8_t> data);

    // Fails when a list named a country and no database was added.
    engine::Result<std::shared_ptr<const EgressListRules>> build();

private:
    struct Range final {
        std::array<std::uint8_t, 16> first{};
        std::array<std::uint8_t, 16> last{};
        std::uint8_t specificity{0};
        EgressListAction action{EgressListAction::Deny};
    };
    struct Country final {
        std::array<char, 2> code{};
        EgressListAction action{EgressListAction::Deny};
    };

    engine::Status take(std::vector<Range>&& v4, std::vector<Range>&& v6,
                        std::vector<Country>&& countries);
    // Sorts the ranges and sweeps them into disjoint segments.
    static std::vector<EgressListRules::Segment> flatten(std::vector<Range>& ranges,
                                                         common::IpFamily family);

    std::vector<Range> v4_;
    std::vector<Range> v6_;
    std::vector<Country> countries_;
    bool country_database_added_{false};
};

}  // namespace yume::runtime
