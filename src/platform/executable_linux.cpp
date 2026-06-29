/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// Linux (and other /proc-providing Unix) implementation of executable_path().
// The kernel exposes the running image as the symlink /proc/self/exe. This
// file is also the generic-POSIX fallback for any non-Apple, non-Windows
// target; if /proc is unavailable we resolve argv0 instead.

#include "platform/platform.hpp"

#include <unistd.h>

namespace yume::platform {

std::string executable_path(const char* argv0) {
    std::error_code ec;
    std::filesystem::path link = std::filesystem::read_symlink("/proc/self/exe", ec);
    if (!ec && !link.empty()) {
        return link.string();
    }
    if (argv0 && argv0[0] != '\0') {
        std::filesystem::path p = std::filesystem::absolute(argv0, ec);
        if (!ec) {
            return p.string();
        }
    }
    return {};
}

}  // namespace yume::platform
