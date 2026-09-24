/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <string_view>

namespace yume::runtime {

// argv[0] of a process that launches a module. yumed starts itself under this
// name, so the installed daemon launches modules without another program.
inline constexpr std::string_view kModuleLauncherArgv0 = "yume-module";

// True when argv[0] is kModuleLauncherArgv0 and a module program follows.
bool is_module_launcher(int argc, const char* const* argv) noexcept;

// Checks that descriptor 3 is a listening UNIX stream socket whose listener is
// this process's parent, arranges SIGKILL for when that parent dies, drops
// every privilege and replaces this process with the program in argv[1],
// passing argv[1] onward as its arguments. The module keeps descriptor 3 and
// this environment. Returns only on failure, with a nonzero status.
int run_module_launcher(int argc, char** argv) noexcept;

}  // namespace yume::runtime
