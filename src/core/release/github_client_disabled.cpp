/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/release/github_client.hpp"

namespace yume::release {

RemoteProjectInfo query_github_project(
    const GitHubProject&,
    const std::string&,
    std::chrono::milliseconds) {
    RemoteProjectInfo info;
    info.error = "GitHub update checks are unavailable in the client-only ABI";
    return info;
}

}  // namespace yume::release
