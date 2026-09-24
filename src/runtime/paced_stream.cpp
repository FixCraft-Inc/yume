/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/paced_stream.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <deque>
#include <new>
#include <optional>
#include <string_view>
#include <utility>

#include <boost/asio/steady_timer.hpp>

#include "providers/control_task.hpp"

namespace yume::runtime {
namespace {
using engine::Buffer;
using engine::CancellationToken;
using engine::ReceivedRecord;
using engine::Result;
using engine::Status;
using engine::StatusCode;
using engine::StreamResponder;
using Clock = EgressLimiter::Clock;
using Timer = boost::asio::basic_waitable_timer<
    std::chrono::steady_clock, boost::asio::wait_traits<std::chrono::steady_clock>,
    providers::AsioExecutionContext::Executor>;

// The longest single wait. A held operation checks its stream and token at
// least this often.
constexpr Clock::duration kMaxWait = std::chrono::milliseconds(250);
// The route bridge and the C ABI stream keep one write in flight.
constexpr std::size_t kMaxHeldWrites = 16U;

Status failure(StatusCode code, std::string_view message) noexcept {
    try {
        return Status(code, message);
    } catch (...) {
        return Status(code);
    }
}

template <typename Completion, typename... Args>
void complete(Completion& completion, Args&&... args) noexcept {
    try {
        if (completion) completion(std::forward<Args>(args)...);
    } catch (...) {
    }
}

class PacedState final : public std::enable_shared_from_this<PacedState> {
public:
    PacedState(std::shared_ptr<providers::AsioExecutionContext> context,
               std::shared_ptr<EgressLimiter> limiter, std::string identity,
               std::function<double()> weight, std::shared_ptr<StreamResponder> stream)
        : context_(std::move(context)),
          limiter_(std::move(limiter)),
          identity_(std::move(identity)),
          weight_(std::move(weight)),
          stream_(std::move(stream)),
          read_timer_(context_->executor()),
          write_timer_(context_->executor()),
          close_task_([](void* owner) noexcept {
              static_cast<PacedState*>(owner)->settle_closed();
          }) {}

    const StreamResponder& stream() const noexcept { return *stream_; }

    void read(CancellationToken cancellation, StreamResponder::ReadCompletion completion) {
        context_->require_context();
        if (!completion) return;
        if (closed_.load(std::memory_order_acquire)) {
            complete(completion, Result<ReceivedRecord>(Status(StatusCode::Closed)));
            return;
        }
        if (read_pending_) {
            complete(completion, Result<ReceivedRecord>(failure(
                StatusCode::FailedPrecondition, "stream already has a pending read")));
            return;
        }
        // Build the callback before claiming the read: allocation failure
        // leaves nothing accepted.
        StreamResponder::ReadCompletion arrived =
            [self = shared_from_this(), cancellation, completion = std::move(completion)](
                Result<ReceivedRecord> result) mutable noexcept {
                self->read_arrived(std::move(cancellation), std::move(completion),
                                   std::move(result));
            };
        read_pending_ = true;
        try {
            stream_->async_read(std::move(cancellation), std::move(arrived));
        } catch (...) {
            read_pending_ = false;
            throw;
        }
    }

    void write(Buffer payload, CancellationToken cancellation,
               StreamResponder::WriteCompletion completion) {
        context_->require_context();
        if (!completion) return;
        if (closed_.load(std::memory_order_acquire)) {
            complete(completion, Status(StatusCode::Closed), 0U);
            return;
        }
        if (shutdown_requested_) {
            complete(completion, failure(StatusCode::Closed, "stream write side is shut down"), 0U);
            return;
        }
        if (held_writes_.size() >= kMaxHeldWrites) {
            complete(completion, failure(StatusCode::ResourceExhausted,
                                         "paced stream write queue is full"), 0U);
            return;
        }
        Clock::time_point due;
        try {
            due = reservation_start(payload.size());
        } catch (...) {
            complete(completion, failure(StatusCode::ResourceExhausted,
                                         "egress reservation failed"), 0U);
            return;
        }
        if (held_writes_.empty() && due <= Clock::now()) {
            stream_->async_write(std::move(payload), std::move(cancellation),
                                 std::move(completion));
            return;
        }
        HeldWrite held{std::move(payload), std::move(cancellation), std::move(completion), due};
        try {
            held_writes_.push_back(std::move(held));
        } catch (...) {
            // A failed push leaves the element where it was.
            complete(held.completion, failure(StatusCode::ResourceExhausted,
                                              "paced stream write allocation failed"), 0U);
            return;
        }
        if (!write_timer_armed_ && !arm_write_timer(due)) fail_held_writes();
    }

    // Repeated calls after the stream's own shutdown reach the stream again.
    Status shutdown_write() noexcept {
        if (!context_->running_in_this_thread()) return Status(StatusCode::FailedPrecondition);
        if (closed_.load(std::memory_order_acquire)) return Status(StatusCode::Closed);
        if (shutdown_forwarded_) return stream_->shutdown_write();
        shutdown_requested_ = true;
        if (!held_writes_.empty()) return Status::success();
        shutdown_forwarded_ = true;
        return stream_->shutdown_write();
    }

    void close(Status reason) noexcept {
        closed_.store(true, std::memory_order_release);
        stream_->close(std::move(reason));
        if (context_->running_in_this_thread()) {
            settle_closed();
        } else if (auto self = weak_from_this().lock()) {
            context_->submit(close_task_, std::move(self));
        }
    }

private:
    struct HeldRead final {
        ReceivedRecord record;
        StreamResponder::ReadCompletion completion;
        CancellationToken cancellation;
        Clock::time_point due;
    };

    struct HeldWrite final {
        Buffer payload;
        CancellationToken cancellation;
        StreamResponder::WriteCompletion completion;
        Clock::time_point due;
    };

    Clock::time_point reservation_start(std::size_t bytes) {
        const auto now = Clock::now();
        return now + limiter_->reserve(identity_, weight_(), bytes, now);
    }

    // Why a held operation must end now: its token was cancelled, or the
    // stream or this wrapper closed. Success means it may keep waiting.
    Status stopped(const CancellationToken& cancellation) const noexcept {
        if (closed_.load(std::memory_order_acquire) || stream_->terminated())
            return Status(StatusCode::Closed);
        if (cancellation.is_cancelled()) return Status(StatusCode::Cancelled);
        return Status::success();
    }

    void read_arrived(CancellationToken cancellation, StreamResponder::ReadCompletion completion,
                      Result<ReceivedRecord> result) noexcept {
        if (!result.ok() || closed_.load(std::memory_order_acquire) ||
            result.value().payload().empty()) {
            read_pending_ = false;
            complete(completion, std::move(result));
            return;
        }
        Clock::time_point due;
        try {
            due = reservation_start(result.value().payload().size());
        } catch (...) {
            read_pending_ = false;
            complete(completion, Result<ReceivedRecord>(failure(
                StatusCode::ResourceExhausted, "egress reservation failed")));
            return;
        }
        if (due <= Clock::now()) {
            read_pending_ = false;
            complete(completion, std::move(result));
            return;
        }
        held_read_.emplace(HeldRead{std::move(result).take_value(), std::move(completion),
                                    std::move(cancellation), due});
        if (!arm_read_timer(due))
            settle_read(Result<ReceivedRecord>(failure(
                StatusCode::ResourceExhausted, "paced stream timer allocation failed")));
    }

    bool arm_read_timer(Clock::time_point due) noexcept {
        try {
            read_timer_.expires_at(std::min(due, Clock::now() + kMaxWait));
            read_timer_.async_wait(
                [self = shared_from_this()](const boost::system::error_code&) noexcept {
                    self->read_timer_armed_ = false;
                    self->read_due();
                });
            read_timer_armed_ = true;
            return true;
        } catch (...) {
            return false;
        }
    }

    bool arm_write_timer(Clock::time_point due) noexcept {
        try {
            write_timer_.expires_at(std::min(due, Clock::now() + kMaxWait));
            write_timer_.async_wait(
                [self = shared_from_this()](const boost::system::error_code&) noexcept {
                    self->write_timer_armed_ = false;
                    self->writes_due();
                });
            write_timer_armed_ = true;
            return true;
        } catch (...) {
            return false;
        }
    }

    // Also runs for a wait that close() cancelled, after it settled everything.
    void read_due() noexcept {
        if (!held_read_) return;
        auto reason = stopped(held_read_->cancellation);
        if (!reason.ok()) {
            settle_read(Result<ReceivedRecord>(std::move(reason)));
        } else if (Clock::now() < held_read_->due) {
            if (!read_timer_armed_ && !arm_read_timer(held_read_->due))
                settle_read(Result<ReceivedRecord>(failure(
                    StatusCode::ResourceExhausted, "paced stream timer allocation failed")));
        } else {
            settle_read(Result<ReceivedRecord>(std::move(held_read_->record)));
        }
    }

    void settle_read(Result<ReceivedRecord> result) noexcept {
        auto completion = std::move(held_read_->completion);
        held_read_.reset();
        read_pending_ = false;
        complete(completion, std::move(result));
    }

    // Completions may issue the next write, so the queue is read afresh each
    // turn and never held across a callback.
    void writes_due() noexcept {
        while (!held_writes_.empty()) {
            auto reason = stopped(held_writes_.front().cancellation);
            if (!reason.ok()) {
                auto completion = std::move(held_writes_.front().completion);
                held_writes_.pop_front();
                complete(completion, std::move(reason), 0U);
                continue;
            }
            const auto due = held_writes_.front().due;
            if (Clock::now() < due) {
                if (!write_timer_armed_ && !arm_write_timer(due)) fail_held_writes();
                return;
            }
            HeldWrite write = std::move(held_writes_.front());
            held_writes_.pop_front();
            forward(std::move(write));
        }
        finish_shutdown();
    }

    // The stream reports allocation failure through its completion. The
    // guard still keeps completion exactly-once if it throws.
    void forward(HeldWrite write) noexcept {
        std::shared_ptr<StreamResponder::WriteCompletion> guard;
        try {
            guard = std::make_shared<StreamResponder::WriteCompletion>(std::move(write.completion));
        } catch (...) {
            complete(write.completion, failure(StatusCode::ResourceExhausted,
                                               "paced stream write allocation failed"), 0U);
            return;
        }
        try {
            stream_->async_write(std::move(write.payload), std::move(write.cancellation),
                [guard](Status status, std::size_t transferred) noexcept {
                    auto completion = std::exchange(*guard, {});
                    complete(completion, std::move(status), transferred);
                });
        } catch (...) {
            auto completion = std::exchange(*guard, {});
            complete(completion, failure(StatusCode::Internal, "stream write failed to start"), 0U);
        }
    }

    void fail_held_writes() noexcept {
        while (!held_writes_.empty()) {
            auto completion = std::move(held_writes_.front().completion);
            held_writes_.pop_front();
            complete(completion, failure(StatusCode::ResourceExhausted,
                                         "paced stream timer allocation failed"), 0U);
        }
        finish_shutdown();
    }

    void finish_shutdown() noexcept {
        if (!shutdown_requested_ || shutdown_forwarded_ || !held_writes_.empty() ||
            closed_.load(std::memory_order_acquire))
            return;
        shutdown_forwarded_ = true;
        auto status = stream_->shutdown_write();
        if (!status.ok()) close(std::move(status));
    }

    void settle_closed() noexcept {
        boost::system::error_code ignored;
        read_timer_.cancel(ignored);
        write_timer_.cancel(ignored);
        if (held_read_) settle_read(Result<ReceivedRecord>(Status(StatusCode::Closed)));
        while (!held_writes_.empty()) {
            auto completion = std::move(held_writes_.front().completion);
            held_writes_.pop_front();
            complete(completion, Status(StatusCode::Closed), 0U);
        }
    }

    const std::shared_ptr<providers::AsioExecutionContext> context_;
    const std::shared_ptr<EgressLimiter> limiter_;
    const std::string identity_;
    const std::function<double()> weight_;
    const std::shared_ptr<StreamResponder> stream_;
    Timer read_timer_;
    Timer write_timer_;
    std::optional<HeldRead> held_read_;
    std::deque<HeldWrite> held_writes_;
    bool read_pending_{false};
    bool read_timer_armed_{false};
    bool write_timer_armed_{false};
    bool shutdown_requested_{false};
    bool shutdown_forwarded_{false};
    std::atomic<bool> closed_{false};
    providers::ControlTask close_task_;
};

class PacedStream final : public StreamResponder {
public:
    explicit PacedStream(std::shared_ptr<PacedState> state) noexcept : state_(std::move(state)) {}

    engine::ExecutorAffinity executor_affinity() const noexcept override {
        return state_->stream().executor_affinity();
    }
    engine::ServiceKind service_kind() const noexcept override {
        return state_->stream().service_kind();
    }
    std::size_t max_write_size() const noexcept override {
        return state_->stream().max_write_size();
    }
    bool terminated() const noexcept override { return state_->stream().terminated(); }
    void async_read(CancellationToken cancellation, ReadCompletion completion) override {
        state_->read(std::move(cancellation), std::move(completion));
    }
    void async_write(Buffer payload, CancellationToken cancellation,
                     WriteCompletion completion) override {
        state_->write(std::move(payload), std::move(cancellation), std::move(completion));
    }
    Status shutdown_write() noexcept override { return state_->shutdown_write(); }
    void close(Status reason) noexcept override { state_->close(std::move(reason)); }

private:
    std::shared_ptr<PacedState> state_;
};

}  // namespace

Result<std::shared_ptr<StreamResponder>> pace_stream(
    std::shared_ptr<providers::AsioExecutionContext> context,
    std::shared_ptr<EgressLimiter> limiter, std::string identity,
    std::function<double()> weight, std::shared_ptr<StreamResponder> stream) {
    using Created = Result<std::shared_ptr<StreamResponder>>;
    if (!context || !limiter || identity.empty() || !weight || !stream ||
        stream->executor_affinity() != context->affinity())
        return Created(Status(StatusCode::InvalidArgument));
    try {
        auto state = std::make_shared<PacedState>(std::move(context), std::move(limiter),
                                                  std::move(identity), std::move(weight),
                                                  std::move(stream));
        return Created(std::shared_ptr<StreamResponder>(
            std::make_shared<PacedStream>(std::move(state))));
    } catch (const std::bad_alloc&) {
        return Created(Status(StatusCode::ResourceExhausted));
    }
}

}  // namespace yume::runtime
