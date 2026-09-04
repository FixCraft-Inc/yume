/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "engine/buffer.hpp"

#include <algorithm>
#include <limits>
#include <new>
#include <stdexcept>
#include <utility>

namespace yume::engine {
namespace {

Status validate_limit(std::size_t max_size) {
    if (max_size == 0U || max_size > kAbsoluteMaxBufferBytes) {
        return Status(StatusCode::InvalidArgument,
                      "buffer limit must be within the engine maximum");
    }
    return Status::success();
}

}  // namespace

Result<Buffer> Buffer::allocate(std::size_t size, std::size_t max_size) {
    const Status limit_status = validate_limit(max_size);
    if (!limit_status.ok()) {
        return Result<Buffer>(limit_status);
    }
    if (size > max_size) {
        return Result<Buffer>(Status(
            StatusCode::ResourceExhausted,
            "requested buffer size exceeds its declared bound"));
    }
    Buffer buffer(max_size);
    try {
        buffer.storage_.resize(size);
    } catch (const std::bad_alloc&) {
        return Result<Buffer>(Status(StatusCode::ResourceExhausted,
                                     "buffer allocation failed"));
    } catch (const std::length_error&) {
        return Result<Buffer>(Status(StatusCode::ResourceExhausted,
                                     "buffer allocation is too large"));
    }
    return Result<Buffer>(std::move(buffer));
}

Result<Buffer> Buffer::copy_from(std::span<const std::byte> bytes,
                                 std::size_t max_size) {
    auto result = allocate(bytes.size(), max_size);
    if (!result.ok()) {
        return result;
    }
    Buffer buffer = std::move(result).take_value();
    std::copy(bytes.begin(), bytes.end(), buffer.storage_.begin());
    return Result<Buffer>(std::move(buffer));
}

Buffer::Buffer(Buffer&& other) noexcept
    : storage_(std::move(other.storage_)),
      max_size_(std::exchange(other.max_size_, 0U)) {}

Buffer& Buffer::operator=(Buffer&& other) noexcept {
    if (this != &other) {
        storage_ = std::move(other.storage_);
        max_size_ = std::exchange(other.max_size_, 0U);
    }
    return *this;
}

Status Buffer::append(std::span<const std::byte> bytes) {
    if (bytes.size() > max_size_ ||
        storage_.size() > max_size_ - bytes.size()) {
        return Status(StatusCode::ResourceExhausted,
                      "buffer append exceeds its declared bound");
    }
    try {
        storage_.insert(storage_.end(), bytes.begin(), bytes.end());
    } catch (const std::bad_alloc&) {
        return Status(StatusCode::ResourceExhausted,
                      "buffer append allocation failed");
    } catch (const std::length_error&) {
        return Status(StatusCode::ResourceExhausted,
                      "buffer append is too large");
    }
    return Status::success();
}

Status Buffer::resize(std::size_t size) {
    if (size > max_size_) {
        return Status(StatusCode::ResourceExhausted,
                      "buffer resize exceeds its declared bound");
    }
    try {
        storage_.resize(size);
    } catch (const std::bad_alloc&) {
        return Status(StatusCode::ResourceExhausted,
                      "buffer resize allocation failed");
    } catch (const std::length_error&) {
        return Status(StatusCode::ResourceExhausted,
                      "buffer resize is too large");
    }
    return Status::success();
}

}  // namespace yume::engine
