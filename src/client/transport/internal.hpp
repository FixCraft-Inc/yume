#pragma once

/* Compatibility include for the neutral outbound transport internals. */

#include "outbound/internal.hpp"

namespace yume::client::detail {

using outbound::detail::frame_write_priority;
using outbound::detail::kMaxFramePayloadBytes;
using outbound::detail::kMaxWriteBatchBytes;
using outbound::detail::kMaxWriteBatchFrames;
using outbound::detail::parse_header;
using outbound::detail::payload_to_string;

}  // namespace yume::client::detail
