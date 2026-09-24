/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <functional>
#include <memory>
#include <string>

#include "engine/stream_handler.hpp"
#include "providers/asio_execution_context.hpp"
#include "runtime/egress_limiter.hpp"

namespace yume::runtime {

// Wraps one authenticated stream so its payload waits for the limiter. The
// server relays each byte of the stream once, so pacing both directions here
// counts every relayed byte once, whatever service the stream reaches.
//
// A read record is held until its reservation starts. It keeps its receive
// credit meanwhile, so the peer slows down. A write waits before it reaches
// the stream, at most 16 of them in issue order. shutdown_write() follows the
// writes already accepted. weight() is read at every reservation, so a
// credential reload reaches streams already open.
//
// Reads, writes and shutdown_write() run on the context, like the stream's own
// completions. close() may come from any thread. A held operation checks the
// stream's termination and its cancellation token at least every 250 ms, so
// it never delays teardown or the context drain by longer than that. close()
// settles held operations at once, with Closed.
engine::Result<std::shared_ptr<engine::StreamResponder>> pace_stream(
    std::shared_ptr<providers::AsioExecutionContext> context,
    std::shared_ptr<EgressLimiter> limiter,
    std::string identity,
    std::function<double()> weight,
    std::shared_ptr<engine::StreamResponder> stream);

}  // namespace yume::runtime
