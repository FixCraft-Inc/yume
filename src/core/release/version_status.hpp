/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace yume::release {

enum class Freshness {
    up_to_date,
    outdated,
    development,
    ahead,
    unknown,
};

enum class ReferenceKind {
    stable_release,
    tag,
};

struct ParsedVersion {
    std::uint64_t major{0};
    std::uint64_t minor{0};
    std::uint64_t patch{0};
    bool development{false};
    std::uint64_t development_sequence{0};
};

struct ReleaseReference {
    std::string tag;
    std::string published_date;
    std::string url;
    ReferenceKind kind{ReferenceKind::stable_release};
};

struct ComponentStatus {
    std::string name;
    std::string installed_version;
    Freshness freshness{Freshness::unknown};
    std::optional<ReleaseReference> reference;
    std::string note;
};

std::optional<ParsedVersion> parse_version(std::string_view text);
int compare_version_numbers(const ParsedVersion& lhs, const ParsedVersion& rhs);

// A stable GitHub release is authoritative. A plain tag is only enough to
// recognize a numerically newer -devN build; it never upgrades a stable build
// to "Up To Date" by itself.
ComponentStatus evaluate_version_status(
    std::string name,
    std::string installed_version,
    const std::optional<ReleaseReference>& latest_stable_release,
    const std::optional<ReleaseReference>& highest_version_tag,
    std::string unavailable_note = {});

std::string format_github_date(std::string_view timestamp);

}  // namespace yume::release
