/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include "core/runtime/service_stream.hpp"
#include "yume/yume.h"

#include <cstdint>

namespace yume::abi::detail {

constexpr int service_read_status(
    runtime::ServiceStream::ReadResult result,
    std::uint32_t timeout_ms) noexcept {
    using Result = runtime::ServiceStream::ReadResult;
    switch (result) {
    case Result::Data:
    case Result::Eof:
        return YUME_STATUS_OK;
    case Result::Timeout:
        return timeout_ms == 0 ? YUME_STATUS_WOULD_BLOCK
                               : YUME_STATUS_TIMEOUT;
    case Result::Closed:
        return YUME_STATUS_NOT_RUNNING;
    }
    return YUME_STATUS_INTERNAL_ERROR;
}

}  // namespace yume::abi::detail
