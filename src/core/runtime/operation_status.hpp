/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

namespace yume::runtime {

// Stable, machine-readable outcomes for internal operations that cross the C
// ABI boundary. Human-readable diagnostics are carried separately and must not
// be parsed to recover one of these values.
enum class OperationStatus {
    Success,
    InvalidArgument,
    NotRunning,
    AlreadyRunning,
    Timeout,
    NotFound,
    PermissionDenied,
    WouldBlock,
    ResourceExhausted,
    ParseError,
    InternalError,
};

inline void SetOperationStatus(OperationStatus* output,
                               OperationStatus value) noexcept {
    if (output) *output = value;
}

}  // namespace yume::runtime
