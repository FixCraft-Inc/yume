/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

// Windows implementation of executable_path(). GetModuleFileNameA(nullptr, ...)
// returns the path of the current process image. We grow the buffer until the
// call no longer reports truncation (ERROR_INSUFFICIENT_BUFFER), so paths
// longer than MAX_PATH are handled correctly.

#include "platform/platform.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <vector>

namespace yume::platform {

std::string executable_path(const char* argv0) {
    std::vector<char> buf(MAX_PATH);
    for (;;) {
        DWORD len = GetModuleFileNameA(nullptr, buf.data(),
                                       static_cast<DWORD>(buf.size()));
        if (len == 0) {
            break;  // hard failure; fall back to argv0 below
        }
        if (len < buf.size()) {
            std::string raw(buf.data(), len);
            std::error_code ec;
            std::filesystem::path p = std::filesystem::absolute(raw, ec);
            return ec ? raw : p.string();
        }
        if (buf.size() >= 32768) {
            break;  // already at the Windows long-path ceiling; give up
        }
        buf.resize(buf.size() * 2);  // ERROR_INSUFFICIENT_BUFFER: grow + retry
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
