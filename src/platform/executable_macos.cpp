/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

// macOS implementation of executable_path(). Mach-O images expose their own
// on-disk path via _NSGetExecutablePath; the returned path may contain
// symlinks / "." / ".." segments, so we canonicalize to an absolute path.

#include "platform/platform.hpp"

#include <mach-o/dyld.h>

#include <cstdint>
#include <vector>

namespace yume::platform {

std::string executable_path(const char* argv0) {
    uint32_t size = 0;
    // First call with a null buffer reports the required size (including the
    // NUL terminator) via `size`.
    _NSGetExecutablePath(nullptr, &size);
    if (size > 0) {
        std::vector<char> buf(size);
        if (_NSGetExecutablePath(buf.data(), &size) == 0) {
            std::string raw(buf.data());
            std::error_code ec;
            std::filesystem::path resolved = std::filesystem::canonical(raw, ec);
            if (ec) {
                resolved = std::filesystem::absolute(raw, ec);
            }
            if (!ec) {
                return resolved.string();
            }
            return raw;
        }
    }
    if (argv0 && argv0[0] != '\0') {
        std::error_code ec;
        std::filesystem::path p = std::filesystem::absolute(argv0, ec);
        if (!ec) {
            return p.string();
        }
    }
    return {};
}

}  // namespace yume::platform
