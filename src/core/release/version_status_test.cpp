/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/release/version_status.hpp"

#include <cassert>
#include <iostream>
#include <string>
#include <utility>

namespace {

using yume::release::Freshness;
using yume::release::ReferenceKind;
using yume::release::ReleaseReference;

ReleaseReference release(std::string tag) {
    return {std::move(tag), "9 Jul 2026", "https://example.invalid/release",
            ReferenceKind::stable_release};
}

ReleaseReference tag(std::string name) {
    return {std::move(name), {}, "https://example.invalid/tag", ReferenceKind::tag};
}

void test_version_parsing() {
    const auto short_version = yume::release::parse_version("v3.2");
    assert(short_version.has_value());
    assert(short_version->major == 3);
    assert(short_version->minor == 2);
    assert(short_version->patch == 0);
    assert(!short_version->development);

    const auto development = yume::release::parse_version("2.0-dev1");
    assert(development.has_value());
    assert(development->major == 2);
    assert(development->minor == 0);
    assert(development->patch == 0);
    assert(development->development);
    assert(development->development_sequence == 1);

    assert(!yume::release::parse_version("2").has_value());
    assert(!yume::release::parse_version("2.0-rc1").has_value());
    assert(!yume::release::parse_version("2.0-dev").has_value());
    assert(!yume::release::parse_version("2.0-dev1-extra").has_value());
}

void test_stable_release_statuses() {
    const auto latest = release("v3.7.0");
    const auto latest_tag = tag("v3.7.0");
    assert(yume::release::evaluate_version_status(
               "BaseFWX", "3.7.0", latest, std::nullopt)
               .freshness == Freshness::up_to_date);
    assert(yume::release::evaluate_version_status(
               "BaseFWX", "3.6.4", latest, std::nullopt)
               .freshness == Freshness::outdated);
    const auto development = yume::release::evaluate_version_status(
        "BaseFWX", "3.8.0-dev1", latest, latest_tag);
    assert(development.freshness == Freshness::development);
    assert(development.reference.has_value());
    assert(development.reference->kind == ReferenceKind::stable_release);
    assert(yume::release::evaluate_version_status(
               "BaseFWX", "3.7.0-dev2", latest, std::nullopt)
               .freshness == Freshness::outdated);
    assert(yume::release::evaluate_version_status(
               "BaseFWX", "3.8.0", latest, std::nullopt)
               .freshness == Freshness::ahead);

    assert(yume::release::evaluate_version_status(
               "BaseFWX", "3.8.0-dev1", latest, tag("v3.8.0"))
               .freshness == Freshness::unknown);
    assert(yume::release::evaluate_version_status(
               "BaseFWX", "3.8.0-dev1", latest, std::nullopt, "tag lookup failed")
               .freshness == Freshness::unknown);
}

void test_tag_only_failsafe() {
    const auto old_tag = tag("v1.0");
    assert(yume::release::evaluate_version_status(
               "Yume", "2.0-dev1", std::nullopt, old_tag)
               .freshness == Freshness::development);
    assert(yume::release::evaluate_version_status(
               "Yume", "1.0", std::nullopt, old_tag)
               .freshness == Freshness::unknown);
    assert(yume::release::evaluate_version_status(
               "Yume", "1.0-dev1", std::nullopt, old_tag)
               .freshness == Freshness::unknown);
    assert(yume::release::evaluate_version_status(
               "Yume", "2.0-dev1", std::nullopt, std::nullopt, "network error")
               .freshness == Freshness::unknown);
}

void test_date_formatting() {
    assert(yume::release::format_github_date("2026-07-09T14:58:32Z") ==
           "9 Jul 2026");
    assert(yume::release::format_github_date("bad").empty());
}

}  // namespace

int main() {
    test_version_parsing();
    test_stable_release_statuses();
    test_tag_only_failsafe();
    test_date_formatting();
    std::cout << "version_status_test ok\n";
    return 0;
}
