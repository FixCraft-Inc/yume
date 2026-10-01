/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <string>
#include <string_view>

#include "engine/status.hpp"

namespace yume::runtime {

// The lines yume --status or yumed --status prints for a control protocol 1
// status reply, and the line an accepted route prints. A reply that is not
// protocol 1, or that reports an error, fails with FailedPrecondition. The
// replies themselves are control_socket's, and this is only their
// presentation.
engine::Result<std::string> status_reply_text(std::string_view reply);

}  // namespace yume::runtime
