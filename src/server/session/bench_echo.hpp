/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace yume::server {

class BenchEchoTransaction final {
public:
    using Bytes = std::vector<std::uint8_t>;

    static constexpr std::uint64_t kRequiredBytes = 1024ULL * 1024ULL;
    static constexpr std::size_t kRequiredMessageBytes = 16U * 1024U;

    static std::optional<BenchEchoTransaction> Create(
        std::uint64_t requested_bytes,
        std::size_t message_bytes) noexcept {
        if (requested_bytes != kRequiredBytes ||
            message_bytes != kRequiredMessageBytes) {
            return std::nullopt;
        }
        return BenchEchoTransaction{};
    }

    bool Accept(const Bytes& payload, Bytes* reply) noexcept {
        if (!reply || payload.size() != kRequiredMessageBytes ||
            received_bytes_ > kRequiredBytes - payload.size()) {
            return false;
        }
        try {
            *reply = payload;
        } catch (...) {
            return false;
        }
        received_bytes_ += payload.size();
        return true;
    }

    bool complete() const noexcept {
        return received_bytes_ == kRequiredBytes;
    }

    std::uint64_t received_bytes() const noexcept { return received_bytes_; }

private:
    std::uint64_t received_bytes_{0};
};

}  // namespace yume::server
