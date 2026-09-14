/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/asio_execution_context.hpp"

#include <array>
#include <atomic>
#include <mutex>
#include <new>
#include <stdexcept>
#include <utility>

#include <boost/asio/bind_allocator.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/post.hpp>
#include <boost/system/system_error.hpp>

namespace yume::providers {
namespace {

// Only the one mailbox pump uses this storage. io_context destroys its
// executor operation before invoking the callback, so the slot is reusable
// when the next pump is scheduled. No strand or type-erased executor sits
// between this allocator and io_context's scheduler.
struct PumpStorage final {
    alignas(std::max_align_t) std::array<std::byte, 512U> bytes{};
    std::atomic<bool> used{false};
};

template <typename T>
struct PumpAllocator {
    using value_type = T;
    PumpStorage* storage;

    explicit PumpAllocator(PumpStorage* value) noexcept : storage(value) {}
    template <typename U>
    PumpAllocator(const PumpAllocator<U>& other) noexcept : storage(other.storage) {}

    T* allocate(std::size_t count) {
        static_assert(alignof(T) <= alignof(std::max_align_t));
        static_assert(sizeof(T) <= 512U, "Asio mailbox operation exceeds reserved storage");
        if (count != 1U || storage->used.exchange(true, std::memory_order_acq_rel)) {
            // Reusing a live slot would corrupt the scheduler. These are local
            // programming errors, not resource pressure from a remote peer.
            throw std::logic_error("Asio control-pump storage is already in use");
        }
        return reinterpret_cast<T*>(storage->bytes.data());
    }
    void deallocate(T*, std::size_t) noexcept {
        storage->used.store(false, std::memory_order_release);
    }
    template <typename U>
    bool operator==(const PumpAllocator<U>& other) const noexcept {
        return storage == other.storage;
    }
};

thread_local const void* active_context = nullptr;

}  // namespace

struct AsioExecutionContext::State final : public std::enable_shared_from_this<State> {
    explicit State(engine::ExecutorAffinity identity)
        : guard(boost::asio::make_work_guard(io)), affinity(identity) {}

    // Called with mutex held. The previous operation's storage is released
    // before drain(), so a continuation uses the same reserved slot.
    void schedule_pump() {
        boost::asio::post(io.get_executor(), boost::asio::bind_allocator(
            PumpAllocator<std::byte>(&storage),
            [self = shared_from_this()]() noexcept { self->drain(); }));
    }

    void drain() noexcept {
        // A producer or self-requeued task must not monopolize the I/O runner.
        constexpr std::size_t kMaxTasksPerPump = 64U;
        for (std::size_t count = 0; count < kMaxTasksPerPump; ++count) {
            ControlTaskQueue::Pending pending;
            {
                std::lock_guard<std::mutex> lock(mutex);
                pending = controls.pop();
                if (!pending) {
                    pump_pending = false;
                    return;
                }
            }
            pending.run();
        }
        std::lock_guard<std::mutex> lock(mutex);
        if (!controls.empty()) schedule_pump();
        else pump_pending = false;
    }

    std::size_t execute(bool poll_only) {
        bool expected = false;
        if (!running.compare_exchange_strong(expected, true)) {
            throw std::logic_error("AsioExecutionContext already has a runner");
        }
        struct RunnerGuard final {
            State& state;
            const void* previous{active_context};
            explicit RunnerGuard(State& value) : state(value) { active_context = &value; }
            ~RunnerGuard() { active_context = previous; state.running.store(false); }
        } runner(*this);
        if (io.stopped()) io.restart();
        return poll_only ? io.poll() : io.run();
    }

    boost::asio::io_context io;
    boost::asio::executor_work_guard<Executor> guard;
    engine::ExecutorAffinity affinity;
    PumpStorage storage;
    std::mutex mutex;
    ControlTaskQueue controls;
    bool pump_pending{false};
    std::atomic<bool> running{false};
};

engine::Result<std::shared_ptr<AsioExecutionContext>> AsioExecutionContext::create(
    engine::ExecutorAffinity affinity) {
    if (!affinity.valid()) {
        return engine::Result<std::shared_ptr<AsioExecutionContext>>(
            engine::Status(engine::StatusCode::InvalidArgument));
    }
    try {
        auto state = std::make_shared<State>(affinity);
        return engine::Result<std::shared_ptr<AsioExecutionContext>>(
            std::shared_ptr<AsioExecutionContext>(new AsioExecutionContext(std::move(state))));
    } catch (const std::bad_alloc&) {
        return engine::Result<std::shared_ptr<AsioExecutionContext>>(
            engine::Status(engine::StatusCode::ResourceExhausted));
    } catch (const boost::system::system_error&) {
        return engine::Result<std::shared_ptr<AsioExecutionContext>>(
            engine::Status(engine::StatusCode::Internal));
    }
}

AsioExecutionContext::AsioExecutionContext(std::shared_ptr<State> state) noexcept
    : state_(std::move(state)) {}
AsioExecutionContext::~AsioExecutionContext() = default;
AsioExecutionContext::Executor AsioExecutionContext::executor() noexcept {
    return state_->io.get_executor();
}
engine::ExecutorAffinity AsioExecutionContext::affinity() const noexcept {
    return state_->affinity;
}
bool AsioExecutionContext::running_in_this_thread() const noexcept {
    return active_context == state_.get();
}
void AsioExecutionContext::require_context() const {
    if (!running_in_this_thread()) {
        throw std::logic_error("operation must start on its AsioExecutionContext");
    }
}
std::size_t AsioExecutionContext::run() {
    const auto state = state_;
    return state->execute(false);
}
std::size_t AsioExecutionContext::poll() {
    const auto state = state_;
    return state->execute(true);
}
void AsioExecutionContext::stop() noexcept { state_->io.stop(); }
void AsioExecutionContext::finish() noexcept {
    std::lock_guard<std::mutex> lock(state_->mutex);
    state_->guard.reset();
}

void AsioExecutionContext::submit(ControlTask& task, std::shared_ptr<void> owner) noexcept {
    const auto state = state_;
    std::lock_guard<std::mutex> lock(state->mutex);
    state->controls.push(task, std::move(owner));
    if (state->pump_pending) return;
    state->pump_pending = true;
    state->schedule_pump();
}

}  // namespace yume::providers
