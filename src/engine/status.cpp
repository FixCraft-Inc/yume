/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "engine/status.hpp"

#include <algorithm>

namespace yume::engine {

Status::Status(StatusCode code, std::string_view message)
    : code_(code) {
    if (code_ == StatusCode::Ok) {
        return;
    }
    const std::size_t retained =
        std::min(message.size(), kMaxStatusMessageBytes);
    message_.assign(message.data(), retained);
}

Status Status::diagnostic(StatusCode code, std::string_view message) noexcept {
    try {
        return Status(code, message);
    } catch (...) {
        Status result;
        result.code_ = code;
        return result;
    }
}

}  // namespace yume::engine
