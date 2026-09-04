/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/runtime/service_stream.hpp"

#include <cassert>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

yume::runtime::ServiceStream::Bytes one_byte(std::uint8_t value) {
    return yume::runtime::ServiceStream::Bytes{value};
}

void test_admission_fifo_deadline_and_stale_finish() {
    using Queue = yume::runtime::ServiceWriteAdmissionQueue;
    using Result = Queue::AdmissionResult;

    Queue queue(3U, 3U);
    bool needs_dispatch = false;
    std::string reason;
    assert(queue.enqueue(1U, one_byte(0x11), std::chrono::milliseconds::zero(),
                         {}, {}, &needs_dispatch, &reason) == Result::Accepted);
    assert(needs_dispatch);
    assert(queue.enqueue(2U, one_byte(0x22), std::chrono::milliseconds::zero(),
                         {}, {}, &needs_dispatch, &reason) == Result::Accepted);
    assert(!needs_dispatch);
    assert(queue.enqueue(3U, one_byte(0x33), std::chrono::milliseconds::zero(),
                         {}, {}, &needs_dispatch, &reason) == Result::Accepted);
    assert(!needs_dispatch);
    assert(queue.outstanding_frames() == 3U);
    assert(queue.outstanding_bytes() == 3U);

    Queue::Bytes polled = one_byte(0x44);
    assert(queue.enqueue(4U, std::move(polled),
                         std::chrono::milliseconds::zero(), {}, {},
                         &needs_dispatch, &reason) == Result::WouldBlock);
    assert(polled == one_byte(0x44));

    Queue::Bytes timed = one_byte(0x55);
    assert(queue.enqueue(5U, std::move(timed), std::chrono::milliseconds{3},
                         {}, {}, &needs_dispatch, &reason) == Result::Timeout);
    assert(timed == one_byte(0x55));

    Queue::Bytes never_fits(4U, 0x66);
    assert(queue.enqueue(6U, std::move(never_fits),
                         std::chrono::milliseconds{10}, {}, {},
                         &needs_dispatch, &reason) == Result::Invalid);
    assert(never_fits.size() == 4U);

    auto first = queue.take_next();
    assert(first.has_value());
    assert(first->stream_id == 1U);
    assert(first->payload == one_byte(0x11));
    assert(!queue.finish(first->sequence + 100U, &needs_dispatch));
    assert(queue.outstanding_frames() == 3U);
    assert(queue.outstanding_bytes() == 3U);
    assert(queue.finish(first->sequence, &needs_dispatch));
    assert(needs_dispatch);

    auto second = queue.take_next();
    assert(second.has_value());
    assert(second->stream_id == 2U);
    assert(second->payload == one_byte(0x22));
    assert(!queue.finish(first->sequence, &needs_dispatch));
    assert(queue.outstanding_frames() == 2U);
    assert(queue.finish(second->sequence, &needs_dispatch));
    assert(needs_dispatch);

    auto third = queue.take_next();
    assert(third.has_value());
    assert(third->stream_id == 3U);
    assert(third->payload == one_byte(0x33));
    assert(queue.finish(third->sequence, &needs_dispatch));
    assert(!needs_dispatch);
    assert(queue.outstanding_frames() == 0U);
    assert(queue.outstanding_bytes() == 0U);
}

void test_admission_cancel_reuses_one_scheduled_wake() {
    using Queue = yume::runtime::ServiceWriteAdmissionQueue;
    using Result = Queue::AdmissionResult;

    Queue queue(1U, 1U);
    std::size_t cancelled_completions = 0U;
    for (std::size_t i = 0; i < 256U; ++i) {
        bool needs_dispatch = false;
        assert(queue.enqueue(
                   7U, one_byte(static_cast<std::uint8_t>(i)),
                   std::chrono::milliseconds::zero(),
                   [&cancelled_completions](bool ok, std::string) {
                       assert(!ok);
                       ++cancelled_completions;
                   },
                   {}, &needs_dispatch) == Result::Accepted);
        // The first entry creates the one outstanding strand wake. Cancelling
        // and re-enqueuing before it runs must reuse that wake, not mint 255
        // additional posts.
        assert(needs_dispatch == (i == 0U));
        assert(!queue.cancel_stream(7U, "cancelled"));
    }
    assert(cancelled_completions == 256U);

    bool needs_dispatch = true;
    assert(queue.enqueue(8U, one_byte(0x80),
                         std::chrono::milliseconds::zero(), {}, {},
                         &needs_dispatch) == Result::Accepted);
    assert(!needs_dispatch);
    auto final_entry = queue.take_next();
    assert(final_entry.has_value());
    assert(final_entry->stream_id == 8U);
    assert(queue.finish(final_entry->sequence, &needs_dispatch));
    assert(!needs_dispatch);
}

void test_admission_cancel_and_stop_wake_waiters() {
    using Queue = yume::runtime::ServiceWriteAdmissionQueue;
    using Result = Queue::AdmissionResult;

    Queue cancelled_queue(1U, 1U);
    bool needs_dispatch = false;
    assert(cancelled_queue.enqueue(
               1U, one_byte(0x01), std::chrono::milliseconds::zero(), {}, {},
               &needs_dispatch) == Result::Accepted);
    auto cancelled_in_flight = cancelled_queue.take_next();
    assert(cancelled_in_flight.has_value());

    std::atomic<bool> cancelled{false};
    std::atomic<unsigned int> cancellation_checks{0U};
    std::promise<void> cancel_wait_armed;
    auto cancel_wait_ready = cancel_wait_armed.get_future();
    Result cancel_result = Result::Invalid;
    std::thread cancel_waiter([&] {
        cancel_result = cancelled_queue.enqueue(
            2U, one_byte(0x02), std::chrono::seconds{1}, {},
            [&] {
                // Capture the second result before announcing it: this is the
                // predicate check performed immediately before wait_until().
                // The notifier must synchronize with the transition into the
                // wait so this false result cannot lose the subsequent wake.
                const bool result =
                    cancelled.load(std::memory_order_acquire);
                if (cancellation_checks.fetch_add(
                        1U, std::memory_order_relaxed) == 1U) {
                    cancel_wait_armed.set_value();
                }
                return result;
            },
            &needs_dispatch);
    });
    cancel_wait_ready.wait();
    cancelled.store(true, std::memory_order_release);
    cancelled_queue.notify_waiters();
    cancel_waiter.join();
    assert(cancel_result == Result::Stopped);
    assert(cancelled_queue.finish(cancelled_in_flight->sequence));

    Queue stopped_queue(1U, 1U);
    assert(stopped_queue.enqueue(
               3U, one_byte(0x03), std::chrono::milliseconds::zero(), {}, {},
               &needs_dispatch) == Result::Accepted);
    auto stopped_in_flight = stopped_queue.take_next();
    assert(stopped_in_flight.has_value());

    std::promise<void> stop_wait_started;
    auto stop_wait_ready = stop_wait_started.get_future();
    Result stop_result = Result::Invalid;
    std::thread stop_waiter([&] {
        stop_wait_started.set_value();
        stop_result = stopped_queue.enqueue(
            4U, one_byte(0x04), std::chrono::seconds{5}, {}, {},
            &needs_dispatch);
    });
    stop_wait_ready.wait();
    stopped_queue.stop("test stop");
    stop_waiter.join();
    assert(stop_result == Result::Stopped);
    assert(stopped_queue.stopped());
    assert(stopped_queue.finish(stopped_in_flight->sequence));
    assert(stopped_queue.outstanding_frames() == 0U);

    Queue reentrant_stop(2U, 2U);
    std::size_t stop_completions = 0U;
    assert(reentrant_stop.enqueue(
               5U, one_byte(0x05), std::chrono::milliseconds::zero(),
               [&reentrant_stop, &stop_completions](bool ok, std::string) {
                   assert(!ok);
                   ++stop_completions;
                   bool dispatch = true;
                   assert(reentrant_stop.enqueue(
                              6U, one_byte(0x06),
                              std::chrono::milliseconds::zero(), {}, {},
                              &dispatch) == Result::Stopped);
                   assert(!dispatch);
               },
               {}, &needs_dispatch) == Result::Accepted);
    reentrant_stop.stop("reentrant stop");
    assert(stop_completions == 1U);
}

// Regression: write() returns Accepted when the transport admits a frame, not
// when it drains. shutdown_write used to emit FIN immediately, so under load
// the FIN overtook the final record and the peer saw EOF instead of the reply.
// That silently truncated the most ordinary request/response exchange there is.
void test_shutdown_write_waits_for_accepted_writes_to_drain() {
    using ServiceStream = yume::runtime::ServiceStream;
    ServiceStream stream("drain", "peer");
    ServiceStream::WriteCompletion pending;
    bool fin_sent = false;

    stream.set_callbacks(
        [&pending](ServiceStream::Bytes,
                   std::uint32_t,
                   ServiceStream::WriteCompletion completion,
                   std::string*) {
            // Hold the completion: the frame is admitted but not yet drained.
            pending = std::move(completion);
            return ServiceStream::WriteResult::Accepted;
        },
        [](std::string) {},
        [&fin_sent](std::string) { fin_sent = true; });

    const char payload = 'x';
    std::string error;
    assert(stream.write(&payload, 1U, 0U, &error) ==
           ServiceStream::WriteResult::Accepted);
    assert(!fin_sent);

    // With the write still in flight and no deadline to wait on, shutdown must
    // fail rather than send a FIN that would overtake it.
    assert(stream.shutdown_write(&error, 0U) ==
           ServiceStream::ShutdownWriteResult::WouldBlock);
    assert(!fin_sent);
    assert(!error.empty());

    // A bounded wait times out for the same reason while the write is stuck.
    assert(stream.shutdown_write(&error, 30U) ==
           ServiceStream::ShutdownWriteResult::Timeout);
    assert(!fin_sent);

    // Draining the write releases the shutdown.
    assert(pending);
    pending(true, {});
    assert(stream.shutdown_write(&error, 5000U) ==
           ServiceStream::ShutdownWriteResult::Sent);
    assert(fin_sent);

    // Idempotent: a second shutdown neither fails nor re-sends.
    fin_sent = false;
    assert(stream.shutdown_write(&error, 5000U) ==
           ServiceStream::ShutdownWriteResult::Sent);
    assert(!fin_sent);
}

void test_shutdown_write_reports_failed_accepted_write() {
    using ServiceStream = yume::runtime::ServiceStream;
    ServiceStream stream("failed-write", "peer");
    ServiceStream::WriteCompletion pending;
    bool fin_sent = false;
    stream.set_callbacks(
        [&pending](ServiceStream::Bytes,
                   std::uint32_t,
                   ServiceStream::WriteCompletion completion,
                   std::string*) {
            pending = std::move(completion);
            return ServiceStream::WriteResult::Accepted;
        },
        [](std::string) {},
        [&fin_sent](std::string) { fin_sent = true; });

    const char payload = 'x';
    std::string error;
    assert(stream.write(&payload, 1U, 0U, &error) ==
           ServiceStream::WriteResult::Accepted);
    pending(false, "injected transport failure");
    assert(stream.shutdown_write(&error, 5000U) ==
           ServiceStream::ShutdownWriteResult::Closed);
    assert(error == "injected transport failure");
    assert(!fin_sent);
}

void test_shutdown_write_callback_failure_is_terminal() {
    using ServiceStream = yume::runtime::ServiceStream;
    ServiceStream stream("failed-fin", "peer");
    unsigned int attempts = 0U;
    unsigned int closes = 0U;
    stream.set_callbacks(
        [](ServiceStream::Bytes,
           std::uint32_t,
           ServiceStream::WriteCompletion,
           std::string*) { return ServiceStream::WriteResult::Accepted; },
        [&closes](std::string) { ++closes; },
        [&attempts](std::string) {
            ++attempts;
            throw std::runtime_error("injected FIN failure");
        });

    std::string error;
    assert(stream.shutdown_write(&error, 5000U) ==
           ServiceStream::ShutdownWriteResult::Failed);
    assert(attempts == 1U);
    assert(closes == 1U);
    assert(stream.shutdown_write(&error, 5000U) ==
           ServiceStream::ShutdownWriteResult::Closed);
    assert(attempts == 1U);
    assert(closes == 1U);
}

void test_service_stream_admission_gate_serializes_stop() {
    using Gate = yume::runtime::ServiceStreamAdmissionGate;

    Gate gate;
    auto permit = gate.try_acquire();
    assert(permit);

    std::atomic<bool> stop_completed{false};
    std::thread stopper([&] {
        gate.stop();
        stop_completed.store(true, std::memory_order_release);
    });

    while (!gate.stopping()) {
        std::this_thread::yield();
    }
    // stop() has published its terminal request but cannot complete while the
    // pre-existing OPEN transaction owns the permit. New OPEN transactions
    // are rejected immediately instead of overtaking that stop request.
    assert(!stop_completed.load(std::memory_order_acquire));
    assert(!gate.try_acquire());

    permit = {};
    stopper.join();
    assert(stop_completed.load(std::memory_order_acquire));
    assert(!gate.try_acquire());

    // Terminal publication is idempotent.
    gate.stop();
}

}  // namespace

int main() {
    using yume::runtime::InboundCredit;
    using yume::runtime::ServiceStream;
    using yume::runtime::kMaxInboundQueuedFrames;

    ServiceStream stream("svc", "peer");
    std::string error;
    for (std::size_t i = 0; i < kMaxInboundQueuedFrames; ++i) {
        assert(stream.receive_data(one_byte(static_cast<std::uint8_t>(i)), &error));
    }
    assert(!stream.receive_data(one_byte(0xff), &error));
    assert(!error.empty());

    std::uint8_t out = 0;
    std::size_t bytes_read = 0;
    std::string reason;
    assert(stream.read(&out, sizeof(out), 0, &bytes_read, &reason) ==
           ServiceStream::ReadResult::Data);
    assert(bytes_read == 1U);
    assert(stream.receive_data(one_byte(0xee), &error));

    stream.close("test close");
    assert(stream.closed());
    assert(stream.read(&out, sizeof(out), 0, &bytes_read, &reason) ==
           ServiceStream::ReadResult::Closed);
    assert(stream.receive_data(one_byte(0xdd), &error));

    std::size_t released = 0U;
    ServiceStream credited("credited", "peer");
    assert(credited.receive_data(
        ServiceStream::Bytes{0x01, 0x02},
        InboundCredit(9U, [&released](std::size_t bytes) {
            released += bytes;
        }),
        &error));
    assert(credited.read(&out, 1U, 0, &bytes_read, &reason) ==
           ServiceStream::ReadResult::Data);
    assert(released == 0U);
    assert(credited.read(&out, 1U, 0, &bytes_read, &reason) ==
           ServiceStream::ReadResult::Data);
    assert(released == 9U);

    assert(credited.receive_data(
        one_byte(0x03),
        InboundCredit(4U, [&released](std::size_t bytes) {
            released += bytes;
        }),
        &error));
    credited.close("release queued credit");
    assert(released == 13U);

    ServiceStream reentrant("reentrant", "peer");
    bool callback_reentered = false;
    assert(reentrant.receive_data(
        one_byte(0x04),
        InboundCredit(5U, [&reentrant, &callback_reentered](std::size_t bytes) {
            assert(bytes == 5U);
            callback_reentered = !reentrant.closed();
        }),
        &error));
    assert(reentrant.read(&out, 1U, 0, &bytes_read, &reason) ==
           ServiceStream::ReadResult::Data);
    assert(callback_reentered);

    ServiceStream outbound("outbound", "peer");
    ServiceStream::WriteCompletion pending_write;
    std::size_t admitted_bytes = 0U;
    outbound.set_callbacks(
        [&pending_write, &admitted_bytes](
            ServiceStream::Bytes data,
            std::uint32_t,
            ServiceStream::WriteCompletion completion,
            std::string*) {
            admitted_bytes += data.size();
            pending_write = std::move(completion);
            return ServiceStream::WriteResult::Accepted;
        },
        [](std::string) {},
        [](std::string) {});

    ServiceStream::Bytes oversized_write(
        yume::runtime::kMaxServiceWriteBytes + 1U, 0x50);
    assert(outbound.write(
               oversized_write.data(), oversized_write.size(), 0U, &error) ==
           ServiceStream::WriteResult::Invalid);
    assert(error.find("256 KiB") != std::string::npos);
    assert(admitted_bytes == 0U);

    const std::uint8_t first_write = 0x51;
    assert(outbound.write(&first_write, 1U, 0U, &error) ==
           ServiceStream::WriteResult::Accepted);
    auto stale_first_completion = pending_write;
    const std::uint8_t second_write = 0x52;
    assert(outbound.write(&second_write, 1U, 0U, &error) ==
           ServiceStream::WriteResult::WouldBlock);
    assert(outbound.write(&second_write, 1U, 2U, &error) ==
           ServiceStream::WriteResult::Timeout);
    assert(pending_write);
    pending_write(true, {});
    pending_write = {};
    assert(outbound.write(&second_write, 1U, 0U, &error) ==
           ServiceStream::WriteResult::Accepted);
    assert(admitted_bytes == 2U);
    assert(pending_write);
    stale_first_completion(true, {});
    assert(outbound.write(&second_write, 1U, 0U, &error) ==
           ServiceStream::WriteResult::WouldBlock);
    pending_write(false, "transport write failed");
    pending_write = {};
    assert(outbound.write(&second_write, 1U, 0U, &error) ==
           ServiceStream::WriteResult::Closed);

    ServiceStream wake_on_close("wake", "peer");
    ServiceStream::WriteCompletion held_write;
    wake_on_close.set_callbacks(
        [&held_write](ServiceStream::Bytes,
                      std::uint32_t,
                      ServiceStream::WriteCompletion completion,
                      std::string*) {
            held_write = std::move(completion);
            return ServiceStream::WriteResult::Accepted;
        },
        [](std::string) {},
        [](std::string) {});
    assert(wake_on_close.write(&first_write, 1U, 0U, &error) ==
           ServiceStream::WriteResult::Accepted);
    ServiceStream::WriteResult wake_result =
        ServiceStream::WriteResult::Failed;
    std::promise<void> blocked_write_started;
    auto blocked_write_ready = blocked_write_started.get_future();
    std::thread blocked_writer([&] {
        blocked_write_started.set_value();
        wake_result = wake_on_close.write(
            &second_write, 1U, 2000U, &error);
    });
    blocked_write_ready.wait();
    wake_on_close.close("test shutdown");
    blocked_writer.join();
    assert(wake_result == ServiceStream::WriteResult::Closed);

    ServiceStream no_block_on_executor("on-executor", "peer");
    ServiceStream::WriteCompletion executor_held_write;
    no_block_on_executor.set_callbacks(
        [&executor_held_write](ServiceStream::Bytes,
                              std::uint32_t,
                              ServiceStream::WriteCompletion completion,
                              std::string*) {
            executor_held_write = std::move(completion);
            return ServiceStream::WriteResult::Accepted;
        },
        [](std::string) {},
        [](std::string) {},
        [] { return false; });
    assert(no_block_on_executor.write(&first_write, 1U, 0U, &error) ==
           ServiceStream::WriteResult::Accepted);
    assert(no_block_on_executor.write(&second_write, 1U, 5000U, &error) ==
           ServiceStream::WriteResult::WouldBlock);
    executor_held_write(true, {});

    ServiceStream::WriteCompletion completion_after_destruction;
    {
        auto lifetime = std::make_unique<ServiceStream>("lifetime", "peer");
        lifetime->set_callbacks(
            [&completion_after_destruction](
                ServiceStream::Bytes,
                std::uint32_t,
                ServiceStream::WriteCompletion completion,
                std::string*) {
                completion_after_destruction = std::move(completion);
                return ServiceStream::WriteResult::Accepted;
            },
            [](std::string) {},
            [](std::string) {});
        assert(lifetime->write(&first_write, 1U, 0U, &error) ==
               ServiceStream::WriteResult::Accepted);
    }
    assert(completion_after_destruction);
    completion_after_destruction(true, {});

    test_admission_fifo_deadline_and_stale_finish();
    test_admission_cancel_reuses_one_scheduled_wake();
    test_admission_cancel_and_stop_wake_waiters();
    test_service_stream_admission_gate_serializes_stop();
    test_shutdown_write_waits_for_accepted_writes_to_drain();
    test_shutdown_write_reports_failed_accepted_write();
    test_shutdown_write_callback_failure_is_terminal();

    return 0;
}
