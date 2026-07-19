/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <string>
#include <vector>

#include "core/release/version_status.hpp"

namespace yume::release {

struct PqBuildInfo {
    bool available{false};
    std::string provider;
    std::string version;
    std::string algorithms;
};

struct VersionReport {
    std::vector<ComponentStatus> components;
    std::string openssl_version;
    std::string openssl_release_date;
    PqBuildInfo pq;
    std::string inner_suite;
    bool update_check_attempted{false};
};

// Update checks are opt-in because even a version command should not create
// unexpected network traffic. YUME_NO_UPDATE_CHECK remains a hard override.
bool update_check_enabled();
VersionReport collect_version_report(bool check_updates);

}  // namespace yume::release
