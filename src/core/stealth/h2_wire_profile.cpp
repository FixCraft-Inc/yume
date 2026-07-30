/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/stealth/h2_wire_profile.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <utility>

namespace yume::obfs::detail {
namespace {

constexpr std::size_t kFrameHeaderSize = 9;
constexpr std::size_t kPriorityFieldSize = 5;
constexpr std::uint8_t kFrameHeaders = 0x01;
constexpr std::uint8_t kFlagPadded = 0x08;
constexpr std::uint8_t kFlagPriority = 0x20;
constexpr std::string_view kClientPreface =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

bool Fail(std::string& error, std::string reason) {
    if (error.empty()) error = std::move(reason);
    return false;
}

std::uint32_t ReadBe24(const std::uint8_t* data) {
    return (static_cast<std::uint32_t>(data[0]) << 16U) |
           (static_cast<std::uint32_t>(data[1]) << 8U) |
           static_cast<std::uint32_t>(data[2]);
}

std::uint32_t ReadBe32(const std::uint8_t* data) {
    return (static_cast<std::uint32_t>(data[0]) << 24U) |
           (static_cast<std::uint32_t>(data[1]) << 16U) |
           (static_cast<std::uint32_t>(data[2]) << 8U) |
           static_cast<std::uint32_t>(data[3]);
}

void AppendBe24(H2WireProfile::Bytes& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
}

void AppendBe32(H2WireProfile::Bytes& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
}

void AppendPriority(
    H2WireProfile::Bytes& output,
    const cover_profile::H2Priority& priority) {
    std::uint32_t dependency =
        static_cast<std::uint32_t>(priority.parent_stream_id);
    if (priority.exclusive) dependency |= 0x80000000U;
    AppendBe32(output, dependency);
    output.push_back(static_cast<std::uint8_t>(priority.weight - 1));
}

bool PriorityMatches(
    const std::uint8_t* fields,
    const cover_profile::H2Priority& priority) {
    const std::uint32_t dependency = ReadBe32(fields);
    return static_cast<std::int32_t>(dependency & 0x7fffffffU) ==
               priority.parent_stream_id &&
           ((dependency & 0x80000000U) != 0) == priority.exclusive &&
           static_cast<std::int32_t>(fields[4]) + 1 == priority.weight;
}

}  // namespace

bool H2WireProfile::QueuePriority(
    std::int32_t stream_id,
    const cover_profile::H2Priority& priority,
    std::string& error) {
    if (stream_id <= 0 || priority.parent_stream_id < 0 ||
        priority.weight < 1 || priority.weight > 256 ||
        priority.parent_stream_id == stream_id) {
        return Fail(error, "invalid captured HTTP/2 priority");
    }
    const auto [_, inserted] =
        pending_priorities_.emplace(stream_id, priority);
    return inserted
        ? true
        : Fail(error, "duplicate captured HTTP/2 priority");
}

bool H2WireProfile::AppendSerializedBatch(
    const Bytes& batch,
    std::size_t max_output_bytes,
    Bytes& output,
    std::string& error) {
    Bytes transformed;
    transformed.reserve(
        batch.size() + pending_priorities_.size() * kPriorityFieldSize);
    std::size_t offset = 0;
    if (batch.size() >= kClientPreface.size() &&
        std::equal(kClientPreface.begin(), kClientPreface.end(),
                   batch.begin())) {
        transformed.insert(
            transformed.end(), batch.begin(),
            batch.begin() +
                static_cast<std::ptrdiff_t>(kClientPreface.size()));
        offset = kClientPreface.size();
    }

    while (offset < batch.size()) {
        if (batch.size() - offset < kFrameHeaderSize) {
            return Fail(error, "libnghttp2 emitted a truncated frame header");
        }
        const auto* header = batch.data() + offset;
        const std::size_t length = ReadBe24(header);
        const std::size_t frame_size = kFrameHeaderSize + length;
        if (frame_size > batch.size() - offset) {
            return Fail(error, "libnghttp2 emitted a truncated frame");
        }

        const std::uint8_t type = header[3];
        const std::uint8_t flags = header[4];
        const std::int32_t stream_id = static_cast<std::int32_t>(
            ReadBe32(header + 5) & 0x7fffffffU);
        const auto pending = pending_priorities_.find(stream_id);
        if (type != kFrameHeaders || pending == pending_priorities_.end()) {
            transformed.insert(
                transformed.end(),
                batch.begin() + static_cast<std::ptrdiff_t>(offset),
                batch.begin() +
                    static_cast<std::ptrdiff_t>(offset + frame_size));
            offset += frame_size;
            continue;
        }

        std::size_t payload_prefix = 0;
        if ((flags & kFlagPadded) != 0) {
            if (length == 0) {
                return Fail(
                    error, "libnghttp2 emitted truncated padded HEADERS");
            }
            payload_prefix = 1;
        }
        const auto& priority = pending->second;
        if ((flags & kFlagPriority) != 0) {
            if (length - payload_prefix < kPriorityFieldSize ||
                !PriorityMatches(
                    header + kFrameHeaderSize + payload_prefix, priority)) {
                return Fail(
                    error,
                    "libnghttp2 emitted unexpected HTTP/2 priority");
            }
            transformed.insert(
                transformed.end(),
                batch.begin() + static_cast<std::ptrdiff_t>(offset),
                batch.begin() +
                    static_cast<std::ptrdiff_t>(offset + frame_size));
        } else {
            if (length > 0x00ffffffU - kPriorityFieldSize) {
                return Fail(
                    error,
                    "HTTP/2 HEADERS is too large for captured priority");
            }
            AppendBe24(
                transformed,
                static_cast<std::uint32_t>(length + kPriorityFieldSize));
            transformed.push_back(type);
            transformed.push_back(
                static_cast<std::uint8_t>(flags | kFlagPriority));
            transformed.insert(transformed.end(), header + 5, header + 9);
            const auto* payload = header + kFrameHeaderSize;
            transformed.insert(
                transformed.end(), payload, payload + payload_prefix);
            AppendPriority(transformed, priority);
            transformed.insert(
                transformed.end(), payload + payload_prefix,
                payload + length);
        }
        pending_priorities_.erase(pending);
        offset += frame_size;
    }

    if (transformed.size() >
        max_output_bytes - std::min(max_output_bytes, output.size())) {
        return Fail(error, "serialized HTTP/2 output exceeded 32 MiB");
    }
    output.insert(output.end(), transformed.begin(), transformed.end());
    return true;
}

}  // namespace yume::obfs::detail
