/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <memory>
#include <type_traits>
#include <utility>

#include "providers/asio_execution_context.hpp"

namespace yume::runtime {

// A delivery exception does not identify which runtime owner failed. Invoke
// stop once on the context, then keep running to drain accepted completions.
// stop must close every owner and call finish(), without throwing. Reserve its
// task before running: shutdown cannot depend on an allocation after failure.
template <typename Stop>
void run_native_context(std::shared_ptr<providers::AsioExecutionContext> context, Stop stop) {
    static_assert(std::is_nothrow_invocable_v<Stop&>);
    struct FailureTask final {
        explicit FailureTask(Stop callback) : stop(std::move(callback)) {}

        providers::ControlTask task{[](void* owner) noexcept {
            auto& self = *static_cast<FailureTask*>(owner);
            if (std::exchange(self.notified, true)) return;
            self.stop();
        }};
        Stop stop;
        bool notified{false};
    };
    const auto failure = std::make_shared<FailureTask>(std::move(stop));
    for (;;) {
        try {
            context->run();
            return;
        } catch (...) {
            if (!failure->notified) context->submit(failure->task, failure);
        }
    }
}

}  // namespace yume::runtime
