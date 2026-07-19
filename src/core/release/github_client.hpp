/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <optional>
#include <string>

#include "core/release/version_status.hpp"

namespace yume::release {

struct GitHubProject {
    std::string owner;
    std::string repository;
};

struct RemoteProjectInfo {
    std::optional<ReleaseReference> latest_stable_release;
    std::optional<ReleaseReference> highest_version_tag;
    std::string error;
};

// Queries GitHub's public API with certificate verification, a bounded body,
// and one overall deadline per request. Local -devN builds also check the tag
// list, because they are only "Development" when newer than every valid tag.
RemoteProjectInfo query_github_project(
    const GitHubProject& project,
    const std::string& installed_version,
    std::chrono::milliseconds request_timeout = std::chrono::milliseconds(3000));

}  // namespace yume::release
