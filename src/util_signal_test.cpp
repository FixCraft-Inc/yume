/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "util.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>

#include "server/cli/entry.hpp"

namespace {

using namespace std::chrono_literals;

volatile std::sig_atomic_t g_restored_signal = 0;

void preceding_signal_handler(int signum) noexcept {
    g_restored_signal = signum;
}

void expect(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

template <typename Predicate>
void wait_for(std::condition_variable& cv, std::mutex& mutex,
              Predicate&& predicate, const char* message) {
    std::unique_lock<std::mutex> lock(mutex);
    if (!cv.wait_for(lock, 2s, std::forward<Predicate>(predicate))) {
        throw std::runtime_error(message);
    }
}

void test_callback_runs_outside_the_os_handler() {
    std::mutex callback_gate;
    std::mutex observation_mutex;
    std::condition_variable observation_cv;
    bool called = false;

    std::unique_lock<std::mutex> gate_lock(callback_gate);
    yume::util::SignalHandlerRegistration registration([&](int signum) {
        std::lock_guard<std::mutex> gate(callback_gate);
        {
            std::lock_guard<std::mutex> lock(observation_mutex);
            called = signum == SIGTERM;
        }
        observation_cv.notify_all();
    });

    expect(std::raise(SIGTERM) == 0, "raising SIGTERM failed");
    // A direct callback from the OS handler would deadlock raise() while the
    // interrupted thread owns callback_gate. The bridge must return first.
    gate_lock.unlock();
    wait_for(observation_cv, observation_mutex, [&]() { return called; },
             "SIGTERM callback was not dispatched");
}

void test_second_signal_escalates_while_graceful_callback_is_blocked() {
    yume::server::ShutdownRequestLatch latch;
    std::mutex mutex;
    std::condition_variable cv;
    bool graceful_started = false;
    bool release_graceful = false;
    bool force_seen = false;

    yume::util::SignalHandlerRegistration registration([&](int signum) {
        expect(signum == SIGTERM, "dispatcher changed the signal number");
        const auto request = latch.request();
        std::unique_lock<std::mutex> lock(mutex);
        if (request == yume::server::ShutdownRequest::Graceful) {
            graceful_started = true;
            cv.notify_all();
            cv.wait(lock, [&]() { return release_graceful; });
        } else {
            force_seen = true;
            cv.notify_all();
        }
    });

    expect(std::raise(SIGTERM) == 0, "raising first SIGTERM failed");
    wait_for(cv, mutex, [&]() { return graceful_started; },
             "first SIGTERM did not begin graceful shutdown");
    expect(std::raise(SIGTERM) == 0, "raising second SIGTERM failed");
    wait_for(cv, mutex, [&]() { return force_seen; },
             "second SIGTERM was blocked behind graceful shutdown");
    {
        std::lock_guard<std::mutex> lock(mutex);
        release_graceful = true;
    }
    cv.notify_all();
    registration.reset();
}

void test_stale_registration_cannot_clear_a_new_owner() {
    std::atomic<int> old_calls{0};
    std::mutex mutex;
    std::condition_variable cv;
    int new_calls = 0;
    yume::util::SignalHandlerRegistration old_registration(
        [&](int) { old_calls.fetch_add(1, std::memory_order_relaxed); });
    yume::util::SignalHandlerRegistration new_registration([&](int) {
        {
            std::lock_guard<std::mutex> lock(mutex);
            ++new_calls;
        }
        cv.notify_all();
    });

    old_registration.reset();
    expect(std::raise(SIGINT) == 0, "raising SIGINT failed");
    wait_for(cv, mutex, [&]() { return new_calls == 1; },
             "stale registration cleared the newer signal owner");
    expect(old_calls.load(std::memory_order_relaxed) == 0,
           "superseded signal owner received a callback");
}

void test_reset_waits_for_an_inflight_callback() {
    std::mutex mutex;
    std::condition_variable cv;
    bool entered = false;
    bool release = false;
    std::atomic<bool> reset_finished{false};
    yume::util::SignalHandlerRegistration registration([&](int) {
        std::unique_lock<std::mutex> lock(mutex);
        entered = true;
        cv.notify_all();
        cv.wait(lock, [&]() { return release; });
    });

    expect(std::raise(SIGINT) == 0, "raising reset SIGINT failed");
    wait_for(cv, mutex, [&]() { return entered; },
             "reset fixture callback did not start");
    std::thread resetter([&]() {
        registration.reset();
        reset_finished.store(true, std::memory_order_release);
    });
    std::this_thread::sleep_for(20ms);
    expect(!reset_finished.load(std::memory_order_acquire),
           "registration reset did not drain its in-flight callback");
    {
        std::lock_guard<std::mutex> lock(mutex);
        release = true;
    }
    cv.notify_all();
    resetter.join();
    expect(reset_finished.load(std::memory_order_acquire),
           "registration reset did not complete after callback release");
}

void test_reset_restores_the_preceding_os_handler() {
    using SignalFunction = void (*)(int);
    const SignalFunction previous = std::signal(SIGTERM, preceding_signal_handler);
    expect(previous != SIG_ERR, "installing preceding SIGTERM handler failed");
    {
        yume::util::SignalHandlerRegistration registration([](int) {});
        registration.reset();
    }
    g_restored_signal = 0;
    expect(std::raise(SIGTERM) == 0, "raising restored SIGTERM failed");
    expect(g_restored_signal == SIGTERM,
           "registration reset did not restore the preceding OS handler");
    expect(std::signal(SIGTERM, previous) != SIG_ERR,
           "restoring test SIGTERM handler failed");
}

}  // namespace

int main() {
    test_callback_runs_outside_the_os_handler();
    test_second_signal_escalates_while_graceful_callback_is_blocked();
    test_stale_registration_cannot_clear_a_new_owner();
    test_reset_waits_for_an_inflight_callback();
    test_reset_restores_the_preceding_os_handler();
    return 0;
}
