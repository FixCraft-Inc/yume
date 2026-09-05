/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <atomic>
#include <cstddef>

#include <boost/asio/io_context.hpp>

namespace yume::runtime {

// Run `io` as a worker-thread entry point.
//
// An exception that escapes a completion handler propagates out of
// io_context::run(). When run() is the body of a std::thread, letting it
// escape calls std::terminate: the whole process aborts. Any peer that reaches
// a throwing handler would therefore take the daemon down, which for a stealth
// transport is both a denial of service and the loudest possible signal to a
// prober.
//
// This boundary keeps the worker alive and resumes the next handler. It has
// no session ownership: other reads, writes, or timers may still retain the
// failed session. Session handlers must settle their own state and cancel
// outstanding work. Process containment alone does not establish cleanup.
//
// This is a backstop, not a licence to throw across an executor boundary.
// Handlers at a trust boundary must still reject bad input rather than throw.
// A nonzero `contained` count means one of them did not.
//
// `role` is a short static label used in the log line ("server", "client").
// `contained`, when given, is incremented once per contained exception.
void run_worker(boost::asio::io_context& io,
                const char* role,
                std::atomic<std::size_t>* contained = nullptr) noexcept;

}  // namespace yume::runtime
