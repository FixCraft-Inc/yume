/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace yume::engine {

inline constexpr std::size_t kMaxStatusMessageBytes = 1024U;

enum class StatusCode : std::uint8_t {
    Ok,
    InvalidArgument,
    ResourceExhausted,
    Cancelled,
    Closed,
    FailedPrecondition,
    NotFound,
    AlreadyExists,
    ProviderMismatch,
    Internal,
};

class Status final {
public:
    Status() = default;
    Status(StatusCode code, std::string_view message = {});

    static Status success() noexcept { return {}; }

    bool ok() const noexcept { return code_ == StatusCode::Ok; }
    StatusCode code() const noexcept { return code_; }
    const std::string& message() const noexcept { return message_; }

private:
    StatusCode code_{StatusCode::Ok};
    std::string message_;
};

template <typename T>
class Result final {
    static_assert(!std::is_reference_v<T>);
    static_assert(!std::is_same_v<std::remove_cv_t<T>, Status>);

public:
    explicit Result(T value)
        : value_(std::move(value)) {}

    explicit Result(Status status)
        : status_(status.ok()
              ? Status(StatusCode::Internal,
                       "successful status cannot represent a failed result")
              : std::move(status)) {}

    Result(const Result&) = delete;
    Result& operator=(const Result&) = delete;
    Result(Result&&) noexcept(std::is_nothrow_move_constructible_v<T>) = default;
    Result& operator=(Result&&) noexcept(
        std::is_nothrow_move_assignable_v<T>) = default;

    bool ok() const noexcept { return value_.has_value(); }
    const Status& status() const noexcept { return status_; }

    T* value_if() noexcept { return value_ ? &*value_ : nullptr; }
    const T* value_if() const noexcept { return value_ ? &*value_ : nullptr; }

    T& value() & {
        if (!value_) {
            throw std::logic_error("attempted to read a failed result");
        }
        return *value_;
    }

    const T& value() const& {
        if (!value_) {
            throw std::logic_error("attempted to read a failed result");
        }
        return *value_;
    }

    T take_value() && {
        if (!value_) {
            throw std::logic_error("attempted to move from a failed result");
        }
        return std::move(*value_);
    }

private:
    std::optional<T> value_;
    Status status_{};
};

}  // namespace yume::engine
