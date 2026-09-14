/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cassert>
#include <memory>
#include <utility>

namespace yume::providers {

class ControlTaskQueue;

// Embedded in an operation or provider state. A queued task retains that
// state without allocating and belongs to one queue for its lifetime.
// owner.get() is the callback argument and must keep the embedded task alive.
class ControlTask final {
public:
    using Callback = void (*)(void*) noexcept;

    explicit ControlTask(Callback callback) noexcept : callback_(callback) {}
    ControlTask(const ControlTask&) = delete;
    ControlTask& operator=(const ControlTask&) = delete;
    ~ControlTask() { assert(!queued_); }

private:
    friend class ControlTaskQueue;
    Callback callback_;
    ControlTask* next_{nullptr};
    std::shared_ptr<void> owner_;
    bool queued_{false};
};

// Intrusive control mailbox, independent of an event loop. The caller owns
// synchronization and schedules a pump on the required executor. Pop under
// that synchronization, then invoke the pending callback outside the lock.
// Drain accepted tasks before destroying the queue or its retained owners.
class ControlTaskQueue final {
public:
    class Pending final {
    public:
        Pending() = default;
        Pending(const Pending&) = delete;
        Pending& operator=(const Pending&) = delete;
        Pending(Pending&& other) noexcept
            : task_(std::exchange(other.task_, nullptr)),
              owner_(std::move(other.owner_)) {}
        Pending& operator=(Pending&& other) noexcept {
            if (this != &other) {
                assert(!task_);
                task_ = std::exchange(other.task_, nullptr);
                owner_ = std::move(other.owner_);
            }
            return *this;
        }

        explicit operator bool() const noexcept { return task_ != nullptr; }

        void run() noexcept {
            auto* task = std::exchange(task_, nullptr);
            if (!task) return;
            // The callback may queue itself again or release every public
            // handle. Its state stays alive until this invocation returns.
            const auto owner = std::move(owner_);
            task->callback_(owner.get());
        }

    private:
        friend class ControlTaskQueue;
        Pending(ControlTask* task, std::shared_ptr<void> owner) noexcept
            : task_(task), owner_(std::move(owner)) {}

        ControlTask* task_{nullptr};
        std::shared_ptr<void> owner_;
    };

    ControlTaskQueue() = default;
    ControlTaskQueue(const ControlTaskQueue&) = delete;
    ControlTaskQueue& operator=(const ControlTaskQueue&) = delete;
    ~ControlTaskQueue() { assert(empty()); }

    void push(ControlTask& task, std::shared_ptr<void> owner) noexcept {
        assert(owner && task.callback_);
        // Re-submission uses the same owner. Coalescing must not replace the
        // owner of an already queued task or release its state prematurely.
        if (task.queued_) return;
        task.owner_ = std::move(owner);
        task.queued_ = true;
        if (tail_) tail_->next_ = &task;
        else head_ = &task;
        tail_ = &task;
    }

    bool empty() const noexcept { return head_ == nullptr; }

    Pending pop() noexcept {
        auto* task = head_;
        if (!task) return {};
        head_ = task->next_;
        if (!head_) tail_ = nullptr;
        task->next_ = nullptr;
        task->queued_ = false;
        return Pending(task, std::move(task->owner_));
    }

    bool run_one() noexcept {
        auto pending = pop();
        if (!pending) return false;
        pending.run();
        return true;
    }

private:
    ControlTask* head_{nullptr};
    ControlTask* tail_{nullptr};
};

}  // namespace yume::providers
