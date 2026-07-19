/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/release/version_status.hpp"

#include <array>
#include <charconv>
#include <cctype>
#include <system_error>
#include <utility>

namespace yume::release {
namespace {

bool parse_number(std::string_view text, std::size_t* offset, std::uint64_t* value) {
    const std::size_t begin = *offset;
    while (*offset < text.size() &&
           std::isdigit(static_cast<unsigned char>(text[*offset])) != 0) {
        ++*offset;
    }
    if (begin == *offset) {
        return false;
    }
    const char* first = text.data() + begin;
    const char* last = text.data() + *offset;
    auto [ptr, ec] = std::from_chars(first, last, *value);
    return ec == std::errc() && ptr == last;
}

std::optional<ParsedVersion> parse_reference(const std::optional<ReleaseReference>& reference) {
    if (!reference.has_value()) {
        return std::nullopt;
    }
    auto parsed = parse_version(reference->tag);
    if (!parsed.has_value() || parsed->development) {
        return std::nullopt;
    }
    return parsed;
}

}  // namespace

std::optional<ParsedVersion> parse_version(std::string_view text) {
    if (text.empty()) {
        return std::nullopt;
    }

    std::size_t offset = 0;
    if (text.front() == 'v' || text.front() == 'V') {
        offset = 1;
    }

    ParsedVersion version;
    if (!parse_number(text, &offset, &version.major) ||
        offset >= text.size() || text[offset++] != '.' ||
        !parse_number(text, &offset, &version.minor)) {
        return std::nullopt;
    }

    if (offset < text.size() && text[offset] == '.') {
        ++offset;
        if (!parse_number(text, &offset, &version.patch)) {
            return std::nullopt;
        }
    }

    if (offset == text.size()) {
        return version;
    }

    constexpr std::string_view kDevelopmentSuffix = "-dev";
    if (text.substr(offset, kDevelopmentSuffix.size()) != kDevelopmentSuffix) {
        return std::nullopt;
    }
    offset += kDevelopmentSuffix.size();
    version.development = true;
    if (!parse_number(text, &offset, &version.development_sequence) ||
        offset != text.size()) {
        return std::nullopt;
    }
    return version;
}

int compare_version_numbers(const ParsedVersion& lhs, const ParsedVersion& rhs) {
    if (lhs.major != rhs.major) return lhs.major < rhs.major ? -1 : 1;
    if (lhs.minor != rhs.minor) return lhs.minor < rhs.minor ? -1 : 1;
    if (lhs.patch != rhs.patch) return lhs.patch < rhs.patch ? -1 : 1;
    return 0;
}

ComponentStatus evaluate_version_status(
    std::string name,
    std::string installed_version,
    const std::optional<ReleaseReference>& latest_stable_release,
    const std::optional<ReleaseReference>& highest_version_tag,
    std::string unavailable_note) {
    ComponentStatus status;
    status.name = std::move(name);
    status.installed_version = std::move(installed_version);
    status.note = std::move(unavailable_note);

    const auto installed = parse_version(status.installed_version);
    if (!installed.has_value()) {
        status.note = "Installed version is not comparable";
        return status;
    }

    const auto stable = parse_reference(latest_stable_release);
    const auto tag = parse_reference(highest_version_tag);

    if (installed->development) {
        if (stable.has_value() && compare_version_numbers(*installed, *stable) <= 0) {
            status.reference = latest_stable_release;
            status.freshness = Freshness::outdated;
            status.note = "A stable release is available";
            return status;
        }

        // A development build is only called ahead after checking the tag list
        // as well as /releases/latest. A newer tag without a release is still
        // enough to make an "ahead" claim ambiguous.
        if (tag.has_value()) {
            const int tag_comparison = compare_version_numbers(*installed, *tag);
            if (tag_comparison > 0) {
                if (stable.has_value() &&
                    compare_version_numbers(*tag, *stable) <= 0) {
                    status.reference = latest_stable_release;
                    status.note = "Development build ahead of the latest stable release";
                } else {
                    status.reference = highest_version_tag;
                    status.note = "Development build ahead of the newest version tag";
                }
                status.freshness = Freshness::development;
            } else {
                status.reference = highest_version_tag;
                status.note = "Development build is not newer than the newest version tag";
            }
            return status;
        }

        if (status.note.empty()) {
            status.note = "The newest version tag could not be verified";
        }
        return status;
    }

    if (stable.has_value()) {
        status.reference = latest_stable_release;
        const int comparison = compare_version_numbers(*installed, *stable);
        if (comparison < 0) {
            status.freshness = Freshness::outdated;
            status.note = "A newer stable release is available";
        } else if (comparison == 0) {
            status.freshness = Freshness::up_to_date;
            status.note = "Matches the latest stable release";
        } else {
            status.freshness = Freshness::ahead;
            status.note = "Installed version is ahead of the latest stable release";
        }
        return status;
    }

    if (status.note.empty()) {
        status.note = "No comparable stable GitHub release was found";
    }
    return status;
}

std::string format_github_date(std::string_view timestamp) {
    if (timestamp.size() < 10 || timestamp[4] != '-' || timestamp[7] != '-') {
        return {};
    }

    unsigned year = 0;
    unsigned month = 0;
    unsigned day = 0;
    auto parse_date_part = [&](std::size_t begin, std::size_t end, unsigned* out) {
        const char* first = timestamp.data() + begin;
        const char* last = timestamp.data() + end;
        auto [ptr, ec] = std::from_chars(first, last, *out);
        return ec == std::errc() && ptr == last;
    };
    if (!parse_date_part(0, 4, &year) || !parse_date_part(5, 7, &month) ||
        !parse_date_part(8, 10, &day) || month < 1 || month > 12 ||
        day < 1 || day > 31) {
        return {};
    }

    constexpr std::array<std::string_view, 12> kMonths = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    };
    return std::to_string(day) + " " + std::string(kMonths[month - 1]) + " " +
           std::to_string(year);
}

}  // namespace yume::release
