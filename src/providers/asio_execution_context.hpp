/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <memory>

#include <boost/asio/io_context.hpp>

#include "engine/types.hpp"
#include "engine/status.hpp"
#include "providers/control_task.hpp"

namespace yume::providers {

// One caller-owned execution context shared by native providers. run()/poll()
// permit only one runner; this object owns no thread and never joins one.
// Initiate provider operations on executor(), and keep running through close
// and completion drain before stop(). Do not run its underlying Asio context
// through an executor's context() escape hatch.
// Retain a public context handle through drain: destruction does not cancel
// queued work, and abandoning a pending owner/control cycle leaks that work.
class AsioExecutionContext final {
public:
    using Executor = boost::asio::io_context::executor_type;

    // Tasks belong to this context's mailbox for their lifetime. Callbacks
    // run on this context, outside the mailbox lock.
    using ControlTask = yume::providers::ControlTask;

    static engine::Result<std::shared_ptr<AsioExecutionContext>> create(
        engine::ExecutorAffinity affinity);

    AsioExecutionContext(const AsioExecutionContext&) = delete;
    AsioExecutionContext& operator=(const AsioExecutionContext&) = delete;
    ~AsioExecutionContext();

    Executor executor() noexcept;
    engine::ExecutorAffinity affinity() const noexcept;
    bool running_in_this_thread() const noexcept;

    // Invalid caller affinity is a synchronous initiation error: no operation
    // is accepted and no callback is scheduled. It is never a fallback thread.
    void require_context() const;
    // Like Asio, these propagate handler/delivery exceptions. The runtime must
    // catch at its runner boundary and resume to drain reserved failure tasks;
    // an exception is not cancellation or proof of completion delivery.
    std::size_t run();
    std::size_t poll();
    // After closing all owned providers/channels, release the idle work guard.
    // run() then returns when their queued control and I/O completions drain.
    // This does not cancel active operations; the caller must close them first.
    void finish() noexcept;
    // Emergency interruption only; pending work still needs a later run/drain.
    void stop() noexcept;

    void submit(ControlTask& task, std::shared_ptr<void> owner) noexcept;

private:
    struct State;
    explicit AsioExecutionContext(std::shared_ptr<State> state) noexcept;
    std::shared_ptr<State> state_;
};

}  // namespace yume::providers
