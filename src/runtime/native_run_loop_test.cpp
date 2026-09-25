/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/native_run_loop.hpp"

#include <chrono>
#include <cstdio>
#include <new>

#include <boost/asio/basic_waitable_timer.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>

// Asio may allocate the recovery post through its aligned C allocation path.
#define YUME_TEST_ALIGNED_ALLOCATIONS 1
#include "test_support/allocation_failure.hpp"

namespace {
using yume::providers::AsioExecutionContext;
using Timer = boost::asio::basic_waitable_timer<
    std::chrono::steady_clock, boost::asio::wait_traits<std::chrono::steady_clock>,
    AsioExecutionContext::Executor>;
using Tcp = boost::asio::ip::tcp;

bool failure_drains(bool exhaust_allocations) {
    auto created = AsioExecutionContext::create(yume::engine::ExecutorAffinity(1U));
    if (!created.ok()) return false;
    const auto context = std::move(created).take_value();
    Tcp::acceptor listener(context->executor(), Tcp::endpoint(Tcp::v4(), 0));
    Tcp::socket socket(context->executor());
    Timer timer(context->executor());
    unsigned stopped = 0;
    bool on_context = false;
    bool accept_cancelled = false;
    bool timer_cancelled = false;
    bool late_exception = false;
    boost::asio::post(context->executor(), [&] {
        listener.async_accept(socket, [&](const boost::system::error_code& error) {
            accept_cancelled = error == boost::asio::error::operation_aborted;
            // A second delivery exception during drain must not notify again
            // or prevent the other cancelled operation from settling.
            late_exception = true;
            throw std::bad_alloc();
        });
        timer.expires_after(std::chrono::hours(1));
        timer.async_wait([&](const boost::system::error_code& error) noexcept {
            timer_cancelled = error == boost::asio::error::operation_aborted;
        });
        yume::test::fail_allocations.store(exhaust_allocations);
        throw std::bad_alloc();
    });
    yume::runtime::run_native_context(context, [&]() noexcept {
        ++stopped;
        on_context = context->running_in_this_thread();
        boost::system::error_code ignored;
        listener.close(ignored);
        timer.cancel(ignored);
        context->finish();
    });
    yume::test::fail_allocations.store(false);
    return stopped == 1U && on_context && accept_cancelled && timer_cancelled &&
           late_exception && !listener.is_open();
}

bool normal_drain() {
    auto created = AsioExecutionContext::create(yume::engine::ExecutorAffinity(2U));
    if (!created.ok()) return false;
    const auto context = std::move(created).take_value();
    bool stopped = false;
    bool delivered = false;
    boost::asio::post(context->executor(), [&]() noexcept {
        delivered = true;
        context->finish();
    });
    yume::runtime::run_native_context(context, [&]() noexcept { stopped = true; });
    return delivered && !stopped;
}
}  // namespace

int main() {
    try {
        if (!normal_drain() || !failure_drains(false) || !failure_drains(true)) {
            std::fputs("native runner cleanup failed\n", stderr);
            return 1;
        }
    } catch (...) {
        yume::test::fail_allocations.store(false);
        std::fputs("native runner exception escaped\n", stderr);
        return 1;
    }
    std::puts("native runner: normal drain and exception cleanup passed");
    return 0;
}
