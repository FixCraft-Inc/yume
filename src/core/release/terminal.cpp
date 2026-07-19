/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/release/terminal.hpp"

#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>

#include "util.hpp"

namespace yume::release {
namespace {

constexpr std::size_t kComponentWidth = 12;
constexpr std::size_t kInstalledWidth = 17;
constexpr std::size_t kStatusWidth = 18;
constexpr std::size_t kLatestWidth = 17;
constexpr std::size_t kReleasedWidth = 12;
constexpr char kDarkGreen[] = "32";
constexpr char kDarkBlue[] = "34";
constexpr char kBrand[] = "1;35";
constexpr char kBrandAccent[] = "1;36";
constexpr char kOrange[] = "38;5;208";
constexpr char kYellow[] = "33";

std::string pad(std::string value, std::size_t width) {
    if (value.size() < width) {
        value.append(width - value.size(), ' ');
    }
    return value;
}

std::string ansi(std::string value, const char* code, bool enabled) {
    if (!enabled) {
        return value;
    }
    return std::string("\033[") + code + "m" + value + "\033[0m";
}

std::string freshness_label(Freshness freshness) {
    switch (freshness) {
        case Freshness::up_to_date: return "Up To Date";
        case Freshness::outdated: return "Outdated";
        case Freshness::development: return "Development";
        case Freshness::ahead: return "Ahead";
        case Freshness::unknown: return "Unknown";
    }
    return "Unknown";
}

const char* freshness_color(Freshness freshness) {
    switch (freshness) {
        case Freshness::up_to_date: return kDarkGreen;
        case Freshness::outdated: return kOrange;
        case Freshness::development: return kDarkBlue;
        case Freshness::ahead: return kDarkBlue;
        case Freshness::unknown: return kYellow;
    }
    return kYellow;
}

std::string latest_label(const ComponentStatus& component) {
    if (!component.reference.has_value()) {
        return "-";
    }
    std::string label = component.reference->tag;
    if (component.reference->kind == ReferenceKind::tag) {
        label += " (tag)";
    }
    return label;
}

std::string yume_version(const VersionReport& report) {
    const auto found = std::find_if(
        report.components.begin(), report.components.end(),
        [](const ComponentStatus& component) { return component.name == "Yume"; });
    return found == report.components.end() ? "Unknown" : found->installed_version;
}

Freshness yume_freshness(const VersionReport& report) {
    const auto found = std::find_if(
        report.components.begin(), report.components.end(),
        [](const ComponentStatus& component) { return component.name == "Yume"; });
    return found == report.components.end() ? Freshness::unknown : found->freshness;
}

std::string component_version(const VersionReport& report, std::string_view name) {
    const auto found = std::find_if(
        report.components.begin(), report.components.end(),
        [name](const ComponentStatus& component) { return component.name == name; });
    return found == report.components.end() ? "Unknown" : found->installed_version;
}

std::string render_compact_report(const VersionReport& report, std::string_view title) {
    std::ostringstream out;
    out << title << " " << yume_version(report) << "\n"
        << "BaseFWX " << component_version(report, "BaseFWX") << "\n"
        << "OpenSSL " << report.openssl_version;
    if (!report.openssl_release_date.empty()) {
        out << " (released " << report.openssl_release_date << ")";
    }
    out << "\n"
        << "PQ/ML-KEM " << report.pq.provider;
    if (!report.pq.version.empty()) {
        out << " " << report.pq.version;
    }
    if (!report.pq.algorithms.empty()) {
        out << " (" << report.pq.algorithms << ")";
    }
    out << "\n"
        << "Inner suite " << report.inner_suite << "\n";
    return out.str();
}

}  // namespace

std::string render_brand_header(std::string_view section,
                                bool colors_enabled) {
    std::ostringstream out;
    out << ansi("YUME", kBrand, colors_enabled);
    if (!section.empty()) {
        out << " / " << ansi(std::string(section), kBrandAccent,
                             colors_enabled);
    }
    out << "\n"
        << ansi("Post-quantum stealth transport", kBrandAccent,
                colors_enabled)
        << "\n";
    return out.str();
}

std::string render_version_report(const VersionReport& report,
                                  std::string_view title,
                                  bool colors_enabled) {
    std::ostringstream out;
    out << render_brand_header({}, colors_enabled)
        << ansi(std::string(title) + " " + yume_version(report),
                freshness_color(yume_freshness(report)), colors_enabled)
        << "\n\n"
        << ansi("Version status", "1", colors_enabled) << "\n"
        << "  " << pad("Component", kComponentWidth)
        << pad("Installed", kInstalledWidth)
        << pad("Status", kStatusWidth)
        << ansi(pad("Latest", kLatestWidth), kDarkGreen, colors_enabled)
        << pad("Released", kReleasedWidth) << "\n"
        << "  " << std::string(kComponentWidth + kInstalledWidth + kStatusWidth +
                                 kLatestWidth + kReleasedWidth - 1, '-')
        << "\n";

    for (const auto& component : report.components) {
        const std::string released =
            component.reference.has_value() && !component.reference->published_date.empty()
                ? component.reference->published_date
                : "-";
        const std::string status = pad(
            report.update_check_attempted
                ? freshness_label(component.freshness)
                : "Not checked",
            kStatusWidth);
        out << "  " << pad(component.name, kComponentWidth)
            << pad(component.installed_version, kInstalledWidth)
            << ansi(status, freshness_color(component.freshness), colors_enabled)
            << ansi(pad(latest_label(component), kLatestWidth), kDarkGreen,
                    colors_enabled && component.reference.has_value())
            << pad(released, kReleasedWidth) << "\n";
    }

    out << "\n" << ansi("Runtime", "1", colors_enabled) << "\n"
        << "  OpenSSL version   " << report.openssl_version << "\n"
        << "  Release date      "
        << (report.openssl_release_date.empty() ? "Unknown" : report.openssl_release_date)
        << "\n\n"
        << ansi("Cryptography", "1", colors_enabled) << "\n"
        << "  PQ backend        " << report.pq.provider;
    if (!report.pq.version.empty()) {
        out << " " << report.pq.version;
    }
    out << "\n"
        << "  PQ algorithms     "
        << (report.pq.algorithms.empty() ? "Unavailable" : report.pq.algorithms) << "\n"
        << "  Inner suite       " << report.inner_suite << "\n";

    bool has_update = false;
    for (const auto& component : report.components) {
        if (component.freshness != Freshness::outdated ||
            !component.reference.has_value() || component.reference->url.empty()) {
            continue;
        }
        if (!has_update) {
            out << "\n" << ansi("Update available", "1;38;5;208", colors_enabled) << "\n";
            has_update = true;
        }
        out << "  " << component.name << " " << component.reference->tag
            << "  " << component.reference->url << "\n";
    }

    out << "\n";
    return out.str();
}

void print_version_report(std::string_view title) {
    const bool terminal = yume::util::stdout_is_terminal();
    const bool check_updates = update_check_enabled();
    const VersionReport report = collect_version_report(check_updates);
    if (!terminal && !check_updates) {
        // Release artifact self-tests expect deterministic five-line output.
        std::cout << render_compact_report(report, title);
        return;
    }
    std::cout << render_version_report(
        report, title, yume::util::stdout_colors_enabled());
}

}  // namespace yume::release
