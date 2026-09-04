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
// Containing here drops only the connection whose handler threw. The exception
// unwinds that handler, releasing the shared_ptr it was holding, so the session
// destructs and its socket closes. Every other session keeps being served.
// That is why this re-enters run() instead of stopping the context. Asio
// permits re-entry after a handler throws, and the throwing handler has already
// been consumed, so re-entry resumes with the next one rather than spinning.
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
