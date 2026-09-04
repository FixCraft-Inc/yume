/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * A completion handler that throws must not take the process down.
 *
 * These cases run the worker on a real std::thread, which is the shape that
 * makes this a defect rather than an inconvenience: an exception escaping a
 * thread entry point calls std::terminate. A plain `io.run()` in the thread
 * body aborts here. run_worker must not.
 */

#include "core/runtime/worker_loop.hpp"

#include <atomic>
#include <cassert>
#include <cstdio>
#include <stdexcept>
#include <thread>

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>

namespace {

// One throwing handler must be contained, and the worker must exit normally
// once the remaining work drains.
void test_contains_a_throwing_handler() {
    boost::asio::io_context io;
    std::atomic<std::size_t> contained{0};
    std::atomic<bool> later_handler_ran{false};

    boost::asio::post(io, [] { throw std::runtime_error("handler failed"); });
    boost::asio::post(io, [&] { later_handler_ran.store(true); });

    std::thread worker(
        [&] { yume::runtime::run_worker(io, "test", &contained); });
    worker.join();

    assert(contained.load() == 1);
    // Work queued behind the throwing handler must still be served. The point
    // of containing is that one bad connection does not stop the others.
    assert(later_handler_ran.load());
}

// A handler that throws something not derived from std::exception is contained
// on the same path.
void test_contains_a_non_standard_exception() {
    boost::asio::io_context io;
    std::atomic<std::size_t> contained{0};

    boost::asio::post(io, [] { throw 42; });

    std::thread worker(
        [&] { yume::runtime::run_worker(io, "test", &contained); });
    worker.join();

    assert(contained.load() == 1);
}

// Repeated throws are contained independently and counted, and the worker
// still returns rather than spinning, because each throw consumes its handler.
void test_counts_every_contained_exception() {
    boost::asio::io_context io;
    std::atomic<std::size_t> contained{0};

    for (int i = 0; i < 8; ++i) {
        boost::asio::post(io, [] { throw std::logic_error("again"); });
    }

    std::thread worker(
        [&] { yume::runtime::run_worker(io, "test", &contained); });
    worker.join();

    assert(contained.load() == 8);
}

// The ordinary path costs nothing: no throw, no count, normal return.
void test_ordinary_work_is_untouched() {
    boost::asio::io_context io;
    std::atomic<std::size_t> contained{0};
    std::atomic<int> ran{0};

    for (int i = 0; i < 4; ++i) {
        boost::asio::post(io, [&] { ran.fetch_add(1); });
    }

    std::thread worker(
        [&] { yume::runtime::run_worker(io, "test", &contained); });
    worker.join();

    assert(contained.load() == 0);
    assert(ran.load() == 4);
}

// The counter is optional.
void test_counter_is_optional() {
    boost::asio::io_context io;
    boost::asio::post(io, [] { throw std::runtime_error("no counter"); });
    std::thread worker([&] { yume::runtime::run_worker(io, "test", nullptr); });
    worker.join();
}

}  // namespace

int main() {
    test_contains_a_throwing_handler();
    test_contains_a_non_standard_exception();
    test_counts_every_contained_exception();
    test_ordinary_work_is_untouched();
    test_counter_is_optional();
    std::puts("worker_loop_test: all cases passed");
    return 0;
}
