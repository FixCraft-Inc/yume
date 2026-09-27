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

Status validate_limit(std::size_t max_size) noexcept {
    if (max_size == 0U || max_size > kAbsoluteMaxBufferBytes) {
        return Status::diagnostic(
            StatusCode::InvalidArgument,
            "buffer limit must be within the engine maximum");
    }
    return Status::success();
}

}  // namespace

Result<Buffer> Buffer::allocate(std::size_t size, std::size_t max_size) {
    Status limit_status = validate_limit(max_size);
    if (!limit_status.ok()) {
        return Result<Buffer>(std::move(limit_status));
    }
    if (size > max_size) {
        return Result<Buffer>(Status::diagnostic(
            StatusCode::ResourceExhausted,
            "requested buffer size exceeds its declared bound"));
    }
    Buffer buffer(max_size);
    try {
        buffer.storage_.resize(size);
    } catch (const std::bad_alloc&) {
        return Result<Buffer>(Status::diagnostic(StatusCode::ResourceExhausted,
                                                 "buffer allocation failed"));
    } catch (const std::length_error&) {
        return Result<Buffer>(Status::diagnostic(
            StatusCode::ResourceExhausted, "buffer allocation is too large"));
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
        return Status::diagnostic(StatusCode::ResourceExhausted,
                                  "buffer append exceeds its declared bound");
    }
    try {
        const std::size_t old_size = storage_.size();
        const std::size_t size = old_size + bytes.size();
        if (size > storage_.capacity()) {
            // Vector's implicit growth can overshoot the declared limit.
            // Keep the old storage alive while copying an aliased input span.
            std::vector<std::byte> grown;
            grown.reserve(
                std::min(max_size_, std::max(size, storage_.capacity() * 2U)));
            grown.insert(grown.end(), storage_.begin(), storage_.end());
            grown.insert(grown.end(), bytes.begin(), bytes.end());
            storage_.swap(grown);
        } else {
            storage_.resize(size);
            std::copy(bytes.begin(), bytes.end(), storage_.begin() + old_size);
        }
    } catch (const std::bad_alloc&) {
        return Status::diagnostic(StatusCode::ResourceExhausted,
                                  "buffer append allocation failed");
    } catch (const std::length_error&) {
        return Status::diagnostic(StatusCode::ResourceExhausted,
                                  "buffer append is too large");
    }
    return Status::success();
}

Status Buffer::resize(std::size_t size) {
    if (size > max_size_) {
        return Status::diagnostic(StatusCode::ResourceExhausted,
                                  "buffer resize exceeds its declared bound");
    }
    try {
        if (size > storage_.capacity()) {
            storage_.reserve(
                std::min(max_size_, std::max(size, storage_.capacity() * 2U)));
        }
        storage_.resize(size);
    } catch (const std::bad_alloc&) {
        return Status::diagnostic(StatusCode::ResourceExhausted,
                                  "buffer resize allocation failed");
    } catch (const std::length_error&) {
        return Status::diagnostic(StatusCode::ResourceExhausted,
                                  "buffer resize is too large");
    }
    return Status::success();
}

}  // namespace yume::engine
