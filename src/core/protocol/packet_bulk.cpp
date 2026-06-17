/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "core/protocol/packet_bulk.hpp"

#include <limits>
#include <stdexcept>

namespace yume::protocol::packet_bulk {

namespace {

constexpr std::uint64_t kMaxSequence = 0x7FFF'FFFF'FFFF'FFFFull;

void fail(std::string* error, const std::string& message) {
    if (error) {
        *error = message;
    }
}

void put_be16(Bytes& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(value & 0xFF));
}

void put_be32(Bytes& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(value & 0xFF));
}

void put_be64(Bytes& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xFF));
    }
}

std::uint16_t read_be16(const Bytes& in, std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(in[offset]) << 8) |
                                      static_cast<std::uint16_t>(in[offset + 1]));
}

std::uint32_t read_be32(const Bytes& in, std::size_t offset) {
    return (static_cast<std::uint32_t>(in[offset]) << 24) |
           (static_cast<std::uint32_t>(in[offset + 1]) << 16) |
           (static_cast<std::uint32_t>(in[offset + 2]) << 8) |
           static_cast<std::uint32_t>(in[offset + 3]);
}

std::uint64_t read_be64(const Bytes& in, std::size_t offset) {
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        value = (value << 8) | static_cast<std::uint64_t>(in[offset + i]);
    }
    return value;
}

void validate_batch(const Batch& batch) {
    if (batch.packets.empty()) {
        throw std::invalid_argument("packet bulk batch is empty");
    }
    if (batch.packets.size() > kMaxPacketsPerBatch) {
        throw std::invalid_argument("packet bulk batch has too many packets");
    }
    if (batch.sequence > kMaxSequence) {
        throw std::invalid_argument("packet bulk sequence exceeds v1 range");
    }
    for (const auto& packet : batch.packets) {
        if (packet.empty()) {
            throw std::invalid_argument("packet bulk packet is empty");
        }
        if (packet.size() > kMaxPacketBytes) {
            throw std::invalid_argument("packet bulk packet is too large");
        }
    }
}

}  // namespace

std::size_t encoded_size(const Batch& batch) {
    validate_batch(batch);
    std::size_t total = kHeaderBytes;
    for (const auto& packet : batch.packets) {
        if (total > std::numeric_limits<std::size_t>::max() - kPacketLengthBytes - packet.size()) {
            throw std::overflow_error("packet bulk batch is too large");
        }
        total += kPacketLengthBytes + packet.size();
    }
    return total;
}

bool can_append_packet(std::size_t current_encoded_bytes,
                       std::size_t current_packet_count,
                       std::size_t next_packet_bytes,
                       std::size_t max_encoded_bytes) {
    if (current_packet_count >= kMaxPacketsPerBatch || next_packet_bytes == 0 ||
        next_packet_bytes > kMaxPacketBytes) {
        return false;
    }
    const std::size_t base = current_packet_count == 0 ? kHeaderBytes : current_encoded_bytes;
    if (base < kHeaderBytes || max_encoded_bytes < kHeaderBytes) {
        return false;
    }
    if (base > std::numeric_limits<std::size_t>::max() - kPacketLengthBytes - next_packet_bytes) {
        return false;
    }
    return base + kPacketLengthBytes + next_packet_bytes <= max_encoded_bytes;
}

Bytes encode_batch(const Batch& batch) {
    const std::size_t size = encoded_size(batch);
    Bytes out;
    out.reserve(size);
    put_be32(out, kMagic);
    out.push_back(kVersion);
    out.push_back(batch.flags);
    put_be16(out, static_cast<std::uint16_t>(batch.packets.size()));
    put_be64(out, batch.sequence);
    for (const auto& packet : batch.packets) {
        put_be16(out, static_cast<std::uint16_t>(packet.size()));
        out.insert(out.end(), packet.begin(), packet.end());
    }
    return out;
}

std::optional<Batch> decode_batch(const Bytes& payload, std::string* error) {
    if (payload.size() < kHeaderBytes) {
        fail(error, "packet bulk payload is shorter than the header");
        return std::nullopt;
    }
    if (read_be32(payload, 0) != kMagic) {
        fail(error, "packet bulk magic mismatch");
        return std::nullopt;
    }
    if (payload[4] != kVersion) {
        fail(error, "packet bulk version mismatch");
        return std::nullopt;
    }
    const auto packet_count = read_be16(payload, 6);
    if (packet_count == 0 || packet_count > kMaxPacketsPerBatch) {
        fail(error, "packet bulk packet count is invalid");
        return std::nullopt;
    }
    Batch batch;
    batch.flags = payload[5];
    batch.sequence = read_be64(payload, 8);
    if (batch.sequence > kMaxSequence) {
        fail(error, "packet bulk sequence exceeds v1 range");
        return std::nullopt;
    }
    batch.packets.reserve(packet_count);
    std::size_t offset = kHeaderBytes;
    for (std::uint16_t i = 0; i < packet_count; ++i) {
        if (offset + kPacketLengthBytes > payload.size()) {
            fail(error, "packet bulk packet length is truncated");
            return std::nullopt;
        }
        const auto packet_len = read_be16(payload, offset);
        offset += kPacketLengthBytes;
        if (packet_len == 0) {
            fail(error, "packet bulk packet is empty");
            return std::nullopt;
        }
        if (offset + packet_len > payload.size()) {
            fail(error, "packet bulk packet body is truncated");
            return std::nullopt;
        }
        batch.packets.emplace_back(payload.begin() + static_cast<std::ptrdiff_t>(offset),
                                   payload.begin() + static_cast<std::ptrdiff_t>(offset + packet_len));
        offset += packet_len;
    }
    if (offset != payload.size()) {
        fail(error, "packet bulk payload has trailing bytes");
        return std::nullopt;
    }
    return batch;
}

}  // namespace yume::protocol::packet_bulk
