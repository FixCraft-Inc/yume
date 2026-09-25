/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <functional>
#include <memory>

#include "engine/session_engine.hpp"

namespace yume::runtime {

// Returns the client's current active session, or null when none is
// available. Local adapters ask it for every connection they open.
using NativeSessionSource = std::function<std::shared_ptr<engine::SessionEngine>()>;

}  // namespace yume::runtime
