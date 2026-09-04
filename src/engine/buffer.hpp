/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <span>
#include <vector>

#include "engine/status.hpp"

namespace yume::engine {

inline constexpr std::size_t kAbsoluteMaxBufferBytes =
    16U * 1024U * 1024U;

// Single-owner storage with a lifetime bound on both size and retained
// capacity. The limit follows the buffer through moves so an asynchronous
// queue cannot silently retain more memory than its admission decision.
class Buffer final {
public:
    static Result<Buffer> allocate(std::size_t size, std::size_t max_size);
    static Result<Buffer> copy_from(std::span<const std::byte> bytes,
                                    std::size_t max_size);

    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;
    Buffer(Buffer&& other) noexcept;
    Buffer& operator=(Buffer&& other) noexcept;
    ~Buffer() = default;

    Status append(std::span<const std::byte> bytes);
    Status resize(std::size_t size);
    void clear() noexcept { storage_.clear(); }

    std::size_t size() const noexcept { return storage_.size(); }
    std::size_t max_size() const noexcept { return max_size_; }
    bool empty() const noexcept { return storage_.empty(); }

    std::span<const std::byte> bytes() const noexcept { return storage_; }
    std::span<std::byte> mutable_bytes() noexcept { return storage_; }

private:
    explicit Buffer(std::size_t max_size) noexcept : max_size_(max_size) {}

    std::vector<std::byte> storage_;
    std::size_t max_size_{0U};
};

}  // namespace yume::engine
