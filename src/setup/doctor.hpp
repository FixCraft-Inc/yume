/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace yume::setup {

// One finding: the RFC 6901 pointer of the failing location, in the
// configuration or a file it names, and what is wrong there. Neither names
// secret material.
struct Diagnostic final {
    std::string pointer;
    std::string detail;
};

struct DoctorReport final {
    std::vector<Diagnostic> diagnostics;
    // The tuning preset whose settings a valid configuration's limits hold,
    // or "custom".
    std::string preset;
};

// Checks a schema-1 configuration with the parser yume and yumed use, then
// the credential, cover, list, cluster and circuits files it names, without
// starting a session. A configuration error stops at its first finding, and
// each file is checked on its own, so several files can fail at once.
DoctorReport diagnose(const std::filesystem::path& config_path);

}  // namespace yume::setup
