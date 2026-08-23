/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <atomic>

namespace yume::server {

enum class ShutdownRequest {
    Graceful,
    Force,
};

// A process signal may race with a different termination signal. Keep the
// first/second request decision atomic so exactly one request begins graceful
// shutdown and every later request escalates.
class ShutdownRequestLatch final {
public:
    ShutdownRequest request() noexcept {
        return requested_.exchange(true, std::memory_order_acq_rel)
            ? ShutdownRequest::Force
            : ShutdownRequest::Graceful;
    }

private:
    std::atomic<bool> requested_{false};
};

class Server {
public:
    int run(int argc, char** argv);
};

}  // namespace yume::server
