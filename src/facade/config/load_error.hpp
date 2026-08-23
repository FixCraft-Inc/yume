/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cerrno>

namespace yume::facade::config_io {

// Machine-readable classification for config-file load failures. Diagnostic
// strings remain available separately and must not be parsed for control flow.
enum class ConfigLoadError {
    None,
    NotFound,
    PermissionDenied,
    Io,
    Parse,
};

inline ConfigLoadError ConfigOpenErrorFromErrno(int value) noexcept {
    switch (value) {
    case ENOENT:
#ifdef ENOTDIR
    case ENOTDIR:
#endif
        return ConfigLoadError::NotFound;
    case EACCES:
#ifdef EPERM
#if EPERM != EACCES
    case EPERM:
#endif
#endif
        return ConfigLoadError::PermissionDenied;
    default:
        return ConfigLoadError::Io;
    }
}

}  // namespace yume::facade::config_io
