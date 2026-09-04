/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "engine/cancellation.hpp"

#include <limits>
#include <mutex>
#include <new>
#include <unordered_map>
#include <utility>

namespace yume::engine {
namespace detail {

struct CancellationState {
    std::mutex mutex;
    std::unordered_map<std::uint64_t, std::function<void()>> callbacks;
    std::uint64_t next_callback_id{1U};
    bool cancelled{false};
};

}  // namespace detail
namespace {

void invoke_noexcept(std::function<void()>& callback) noexcept {
    if (!callback) {
        return;
    }
    try {
        callback();
    } catch (...) {
        // Cancellation is a cleanup boundary. One callback must not prevent
        // sibling callbacks or escape a destructor/cancel path.
    }
}

}  // namespace

CancellationRegistration::CancellationRegistration(
    std::weak_ptr<detail::CancellationState> state,
    std::uint64_t callback_id) noexcept
    : state_(std::move(state)), callback_id_(callback_id) {}

CancellationRegistration::CancellationRegistration(
    CancellationRegistration&& other) noexcept
    : state_(std::move(other.state_)),
      callback_id_(std::exchange(other.callback_id_, 0U)) {}

CancellationRegistration& CancellationRegistration::operator=(
    CancellationRegistration&& other) noexcept {
    if (this != &other) {
        unregister();
        state_ = std::move(other.state_);
        callback_id_ = std::exchange(other.callback_id_, 0U);
    }
    return *this;
}

CancellationRegistration::~CancellationRegistration() noexcept {
    unregister();
}

void CancellationRegistration::unregister() noexcept {
    const std::uint64_t callback_id =
        std::exchange(callback_id_, 0U);
    if (callback_id == 0U) {
        state_.reset();
        return;
    }
    if (auto state = state_.lock()) {
        std::lock_guard<std::mutex> lock(state->mutex);
        state->callbacks.erase(callback_id);
    }
    state_.reset();
}

bool CancellationToken::is_cancelled() const noexcept {
    if (!state_) {
        return false;
    }
    std::lock_guard<std::mutex> lock(state_->mutex);
    return state_->cancelled;
}

Result<CancellationRegistration> CancellationToken::register_callback(
    std::function<void()> callback) const {
    if (!callback) {
        return Result<CancellationRegistration>(Status(
            StatusCode::InvalidArgument,
            "cancellation callback must not be empty"));
    }
    if (!state_) {
        return Result<CancellationRegistration>(CancellationRegistration{});
    }

    bool invoke_immediately = false;
    std::uint64_t callback_id = 0U;
    try {
        std::lock_guard<std::mutex> lock(state_->mutex);
        if (state_->cancelled) {
            invoke_immediately = true;
        } else {
            if (state_->callbacks.size() >= kMaxCancellationCallbacks ||
                state_->next_callback_id ==
                    std::numeric_limits<std::uint64_t>::max()) {
                return Result<CancellationRegistration>(Status(
                    StatusCode::ResourceExhausted,
                    "cancellation callback capacity exhausted"));
            }
            callback_id = state_->next_callback_id++;
            state_->callbacks.emplace(callback_id, std::move(callback));
        }
    } catch (const std::bad_alloc&) {
        return Result<CancellationRegistration>(Status(
            StatusCode::ResourceExhausted,
            "cancellation callback allocation failed"));
    }

    if (invoke_immediately) {
        invoke_noexcept(callback);
        return Result<CancellationRegistration>(CancellationRegistration{});
    }
    return Result<CancellationRegistration>(
        CancellationRegistration(state_, callback_id));
}

CancellationSource::CancellationSource()
    : state_(std::make_shared<detail::CancellationState>()) {}

CancellationSource& CancellationSource::operator=(
    CancellationSource&& other) noexcept {
    if (this != &other) {
        cancel();
        state_ = std::move(other.state_);
    }
    return *this;
}

CancellationSource::~CancellationSource() noexcept {
    cancel();
}

bool CancellationSource::cancel() noexcept {
    if (!state_) {
        return false;
    }
    std::unordered_map<std::uint64_t, std::function<void()>> callbacks;
    {
        std::lock_guard<std::mutex> lock(state_->mutex);
        if (state_->cancelled) {
            return false;
        }
        state_->cancelled = true;
        callbacks.swap(state_->callbacks);
    }
    for (auto& [_, callback] : callbacks) {
        invoke_noexcept(callback);
    }
    return true;
}

bool CancellationSource::is_cancelled() const noexcept {
    return token().is_cancelled();
}

}  // namespace yume::engine
