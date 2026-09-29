/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <memory>
#include <span>

#include "engine/stream_handler.hpp"

// The plain-HTTP refusal on circuits (owner decision D9, CIRCUIT_1 clients):
// a stream whose first bytes form an HTTP/1.x request line or the HTTP/2
// cleartext preface ends before those bytes leave the client. It catches the
// common case only. Other cleartext protocols, and HTTP sent later in a
// stream or behind another protocol's greeting, pass.
namespace yume::runtime {

enum class Cleartext {
    // The bytes so far could still begin a request line or the preface.
    Undecided,
    Http,
    Other,
};

// How much of a stream's start is held before a still-matching prefix counts
// as HTTP, which also bounds what the guard holds.
inline constexpr std::size_t kCleartextHoldBytes = 8U * 1024U;

// A request line is a method of 1 to 20 characters from A-Z, '-' and '_', one
// space, a target without spaces or control bytes, one space, "HTTP/1." and
// a digit, then CRLF or LF. The preface is "PRI * HTTP/2.0\r\n".
Cleartext classify_cleartext(std::span<const std::byte> start) noexcept;

// Wraps a stream so that its first writes are held, at most
// kCleartextHoldBytes, until classify_cleartext decides. HTTP closes the
// stream with PermissionDenied and sends nothing. Anything else sends what
// was held and passes every later write through. A write the guard holds
// completes at once, as if a small buffer had taken it. Ending the write
// direction while undecided sends what was held, since an unfinished line is
// not a request. Reads pass through. Calls follow the wrapped stream's
// executor.
std::shared_ptr<engine::StreamResponder> guard_plain_http(
    std::shared_ptr<engine::StreamResponder> stream);

}  // namespace yume::runtime
