/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include "outbound/udp_queue.hpp"

namespace yume::client::detail {

inline constexpr std::size_t kMaxUdpQueuedDatagrams =
    outbound::detail::kMaxUdpQueuedDatagrams;
inline constexpr std::size_t kMaxUdpQueuedBytes =
    outbound::detail::kMaxUdpQueuedBytes;
using UdpQueueBudget = outbound::detail::UdpQueueBudget;
using BudgetedUdpDatagramQueue =
    outbound::detail::BudgetedUdpDatagramQueue;

}  // namespace yume::client::detail
