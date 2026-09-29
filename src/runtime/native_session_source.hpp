/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <functional>
#include <memory>
#include <string>

#include "engine/session_engine.hpp"

namespace yume::runtime {

// Returns the client's current active session, or null when none is
// available. Local adapters ask it for every connection they open.
using NativeSessionSource = std::function<std::shared_ptr<engine::SessionEngine>()>;

// Opens a TCP byte stream to a destination for a local adapter, in place of
// an OPEN on the current session: the client's circuits provide one. service
// is the adapter's service, which a route of one hop opens on the session.
using NativeStreamOpener = std::function<void(
    const engine::RouteDestination& destination, std::string service,
    engine::CancellationToken cancellation,
    engine::SessionEngine::OpenCompletion done)>;

}  // namespace yume::runtime
