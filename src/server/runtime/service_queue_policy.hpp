/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>

namespace yume::server::service_queue_policy {

inline constexpr std::size_t kMaxPendingTotal = 256;
inline constexpr std::size_t kMaxPendingPerService = 64;

inline bool admission_allowed(std::size_t pending_total,
                              std::size_t pending_for_service) noexcept {
    return pending_total < kMaxPendingTotal &&
           pending_for_service < kMaxPendingPerService;
}

}  // namespace yume::server::service_queue_policy
