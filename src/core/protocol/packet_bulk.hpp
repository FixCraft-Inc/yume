/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yume::protocol::packet_bulk {

using Bytes = std::vector<std::uint8_t>;

inline constexpr std::string_view kCapability = "packet_bulk_v1";
inline constexpr std::string_view kOpenProto = "packet-bulk-v1";
inline constexpr std::uint32_t kMagic = 0x59425031u;  // "YBP1"
inline constexpr std::uint8_t kVersion = 1;
inline constexpr std::size_t kHeaderBytes = 16;
inline constexpr std::size_t kPacketLengthBytes = 2;
inline constexpr std::size_t kMaxPacketBytes = 65535;
inline constexpr std::size_t kMaxPacketsPerBatch = 64;
inline constexpr std::size_t kDefaultMaxBatchBytes = 128 * 1024;
inline constexpr std::uint32_t kDefaultFlushDelayMicros = 2000;

struct Batch {
    // Android mirrors this as a signed Long, so v1 keeps the high bit clear.
    std::uint64_t sequence{0};
    std::uint8_t flags{0};
    std::vector<Bytes> packets;
};

std::size_t encoded_size(const Batch& batch);

bool can_append_packet(std::size_t current_encoded_bytes,
                       std::size_t current_packet_count,
                       std::size_t next_packet_bytes,
                       std::size_t max_encoded_bytes = kDefaultMaxBatchBytes);

Bytes encode_batch(const Batch& batch);

std::optional<Batch> decode_batch(const Bytes& payload, std::string* error = nullptr);

}  // namespace yume::protocol::packet_bulk
