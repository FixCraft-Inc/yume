/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * Transport write admission under injected allocation failure. Each case
 * sweeps the failure across every allocation the admission performs and
 * checks the same transaction: nothing queued without a scheduler entry, no
 * reserved capacity without a queued frame, and one settlement per accepted
 * completion.
 */

#include "client/transport/core.hpp"
#include "test_support/allocation_failure.hpp"

#include <cstdio>
#include <cstdlib>
#include <memory>
#include <new>
#include <string>
#include <utility>
#include <vector>

namespace {

using TransportCore = yume::client::TransportCore;
using Admission = TransportCore::DataWriteAdmission;
using Bytes = std::vector<std::uint8_t>;

// Mirrors the transport's bulk byte budget (16 MiB total minus the 1 MiB
// control reservation). check_budget_constants() proves the value below still
// matches the transport rather than trusting the comment.
constexpr std::size_t kBulkByteBudget = 16U * 1024U * 1024U - 1U * 1024U * 1024U;

void check(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "transport async failure: %s\n", message);
        std::exit(1);
    }
}

struct Recorder {
    std::size_t writes{0};
    std::string close_reason;

    TransportCore::WriteHandler writer() {
        return [this](std::shared_ptr<Bytes> data,
                      TransportCore::WriteCompletion completion) {
            ++writes;
            if (completion) completion(true, data->size(), {});
        };
    }

    std::function<void(const std::string&)> closer() {
        return [this](const std::string& reason) { close_reason = reason; };
    }
};

// Admitting the whole bulk budget proves no capacity is reserved beyond what
// is actually queued. Call it only once the queue has drained: a write that is
// still queued legitimately holds its own reservation.
bool bulk_budget_is_intact(TransportCore& core) {
    return core.wait_send_data(9, Bytes(kBulkByteBudget),
                               std::chrono::milliseconds::zero()) ==
           Admission::accepted;
}

void check_budget_constants() {
    Recorder recorder;
    TransportCore core(recorder.writer(), recorder.closer());
    core.start();
    check(core.wait_send_data(1, Bytes(kBulkByteBudget + 1U),
                              std::chrono::milliseconds::zero()) ==
              Admission::invalid,
          "one byte over the bulk budget was not rejected");
    check(bulk_budget_is_intact(core),
          "an exact bulk-budget write was not admitted");
}

void test_try_send_data_failure_settles_once_and_reserves_nothing() {
    for (std::size_t nth = 1;; ++nth) {
        Recorder recorder;
        TransportCore core(recorder.writer(), recorder.closer());
        core.start();

        std::size_t completions = 0;
        bool completion_ok = false;
        bool accepted = false;
        bool escaped = false;
        // Build the arguments before arming. Failing to construct a payload
        // or completion is the caller's own failure and never starts a write.
        Bytes payload{0x11, 0x22};
        TransportCore::WriteCompletion completion =
            [&](bool ok, std::size_t, const std::string&) {
                ++completions;
                completion_ok = ok;
            };
        yume::test::arm_allocation_failure(nth);
        try {
            accepted = core.try_send_data(1, std::move(payload),
                                          std::move(completion));
        } catch (...) {
            escaped = true;
        }
        const bool fired = yume::test::disarm_allocation_failure();
        if (!fired) {
            check(nth > 1, "the admission performed no allocation at all");
            break;
        }

        check(!escaped, "an allocation failure escaped try_send_data");
        if (!accepted) {
            // A refused write is answered synchronously and reserves nothing.
            check(completions == 1, "a refused write did not settle once");
            check(!completion_ok, "a refused write reported success");
        } else {
            check(completions <= 1, "an accepted write settled twice");
        }

        // The scheduler is still usable: a later write on the same stream is
        // admitted rather than stranded behind a marker with no queue entry,
        // and dispatching it drains anything a failed dispatch left queued.
        std::size_t later_completions = 0;
        check(core.try_send_data(
                  1, Bytes{0x33},
                  TransportCore::WriteCompletion(
                      [&](bool, std::size_t, const std::string&) {
                          ++later_completions;
                      })),
              "the transport refused a later write after a failed admission");
        check(bulk_budget_is_intact(core),
              "a failed admission left bulk capacity reserved");

        // Terminal shutdown is the deadline for every admitted completion.
        (void)core.shutdown();
        check(completions == 1,
              "an admitted write was never settled, even by shutdown");
        check(later_completions == 1, "a later write was never settled");
    }
}

void test_wait_send_data_failure_returns_the_payload_unsettled() {
    for (std::size_t nth = 1;; ++nth) {
        Recorder recorder;
        TransportCore core(recorder.writer(), recorder.closer());
        core.start();

        Bytes payload{0x41, 0x42, 0x43, 0x44};
        std::size_t completions = 0;
        Admission result = Admission::invalid;
        bool escaped = false;
        TransportCore::WriteCompletion completion =
            [&](bool, std::size_t, const std::string&) { ++completions; };
        yume::test::arm_allocation_failure(nth);
        try {
            result = core.wait_send_data(2, std::move(payload),
                                         std::chrono::milliseconds::zero(),
                                         std::move(completion));
        } catch (...) {
            escaped = true;
        }
        const bool fired = yume::test::disarm_allocation_failure();
        if (!fired) {
            check(nth > 1, "the admission performed no allocation at all");
            break;
        }

        check(!escaped, "an allocation failure escaped wait_send_data");
        check(result == Admission::accepted || result == Admission::failed,
              "a contained allocation failure produced an unrelated status");
        if (result == Admission::failed) {
            // A rejected admission never takes the completion, and the
            // payload returns to the caller intact for its own retry.
            check(completions == 0,
                  "a rejected admission invoked the completion");
            check(payload.size() == 4U,
                  "a rejected admission consumed the caller's payload");
        }
        // Drain whatever a failed dispatch left queued before asking for the
        // whole budget back.
        check(core.try_send_data(3, Bytes{0x45}),
              "the transport refused a later write after a failed admission");
        check(bulk_budget_is_intact(core),
              "a failed admission left bulk capacity reserved");
        (void)core.shutdown();
        check(completions == (result == Admission::accepted ? 1U : 0U),
              "an admitted write was not settled exactly once");
    }
}

void test_shutdown_settles_every_queued_write_when_one_throws() {
    std::vector<TransportCore::WriteCompletion> deferred;
    TransportCore core(
        [&](std::shared_ptr<Bytes>, TransportCore::WriteCompletion completion) {
            if (completion) deferred.push_back(std::move(completion));
        },
        [](const std::string&) {});
    core.start();

    // The first write occupies the dispatcher. The rest stay queued and are
    // the ones terminal shutdown has to settle.
    core.send_data(1, Bytes{0x01});
    std::size_t settled = 0;
    core.send_data(2, Bytes{0x02},
                   [&](bool ok, std::size_t, const std::string&) {
                       check(!ok, "a shutdown settlement reported success");
                       ++settled;
                       throw std::runtime_error("completion boom");
                   });
    core.send_data(3, Bytes{0x03},
                   [&](bool ok, std::size_t, const std::string&) {
                       check(!ok, "a shutdown settlement reported success");
                       ++settled;
                   });
    core.send_data(4, Bytes{0x04},
                   [&](bool ok, std::size_t, const std::string&) {
                       check(!ok, "a shutdown settlement reported success");
                       ++settled;
                   });
    check(deferred.size() == 1, "the dispatcher did not retain one write");

    (void)core.shutdown();
    check(settled == 3,
          "shutdown stopped settling queued writes at a throwing completion");
}

void test_shutdown_needs_no_allocation() {
    TransportCore::WriteCompletion active;
    TransportCore core(
        [&](std::shared_ptr<Bytes>, TransportCore::WriteCompletion completion) {
            active = std::move(completion);
        },
        [](const std::string&) {});
    core.start();
    std::size_t closed = 0;
    check(core.register_stream(5, {}, [&](const std::string&) { ++closed; }),
          "the shutdown fixture could not register its stream");
    core.send_data(1, Bytes{0x01});
    std::size_t settled = 0;
    core.send_data(2, Bytes{0x02},
                   [&](bool ok, std::size_t, const std::string&) {
                       check(!ok, "shutdown reported a queued write as sent");
                       check(core.is_stopped(), "shutdown called back under its state lock");
                       ++settled;
                   });
    bool escaped = false;
    yume::test::arm_allocation_failure(1);
    try {
        auto callbacks = core.shutdown();
        for (auto& callback : callbacks) {
            if (callback) callback({});
        }
    } catch (...) {
        escaped = true;
    }
    const bool fired = yume::test::disarm_allocation_failure();
    check(!escaped, "shutdown threw after publishing the stopped state");
    check(!fired, "shutdown allocated while retiring its callbacks");
    check(settled == 1 && closed == 1,
          "shutdown lost a queued write or registered stream callback");
    active(false, 0, {});
    (void)core.shutdown();
    check(settled == 1 && closed == 1, "repeated shutdown settled twice");
}

}  // namespace

int main() {
    check_budget_constants();
    test_try_send_data_failure_settles_once_and_reserves_nothing();
    test_wait_send_data_failure_returns_the_payload_unsettled();
    test_shutdown_settles_every_queued_write_when_one_throws();
    test_shutdown_needs_no_allocation();
    std::puts("transport async failure: passed");
    return 0;
}
