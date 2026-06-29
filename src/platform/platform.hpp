/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// Cross-platform OS abstractions. Each declaration here has exactly one
// per-OS implementation under src/platform/<thing>_<os>.cpp, selected at
// configure time by src/CMakeLists.txt (executable_windows.cpp on Windows,
// executable_macos.cpp on Apple, executable_linux.cpp elsewhere). Keep this
// header free of any platform headers so it is safe to include anywhere.
#pragma once

#include <filesystem>
#include <string>

namespace yume::platform {

// Absolute path to the currently-running executable.
//
// Uses the native OS query (GetModuleFileName / _NSGetExecutablePath /
// readlink("/proc/self/exe")). If that fails and `argv0` is provided, it
// falls back to resolving argv0 against the current directory. Returns an
// empty string only if every strategy fails.
std::string executable_path(const char* argv0 = nullptr);

// Directory containing the running executable (parent of executable_path()).
// Convenience wrapper used by sibling-binary lookup; empty if the path could
// not be determined.
inline std::filesystem::path executable_dir(const char* argv0 = nullptr) {
    const std::string self = executable_path(argv0);
    if (self.empty()) {
        return {};
    }
    return std::filesystem::path(self).parent_path();
}

}  // namespace yume::platform
