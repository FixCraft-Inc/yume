/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>

#include "engine/status.hpp"

namespace yume::engine {

inline constexpr std::size_t kMaxCancellationCallbacks = 4096U;

namespace detail {
struct CancellationState;
}

class CancellationRegistration final {
public:
    CancellationRegistration() = default;
    CancellationRegistration(const CancellationRegistration&) = delete;
    CancellationRegistration& operator=(const CancellationRegistration&) =
        delete;
    CancellationRegistration(CancellationRegistration&& other) noexcept;
    CancellationRegistration& operator=(
        CancellationRegistration&& other) noexcept;
    ~CancellationRegistration() noexcept;

    void unregister() noexcept;
    bool active() const noexcept { return callback_id_ != 0U; }

private:
    friend class CancellationToken;
    CancellationRegistration(std::weak_ptr<detail::CancellationState> state,
                             std::uint64_t callback_id) noexcept;

    std::weak_ptr<detail::CancellationState> state_;
    std::uint64_t callback_id_{0U};
};

class CancellationToken final {
public:
    CancellationToken() = default;

    bool is_cancelled() const noexcept;
    Result<CancellationRegistration> register_callback(
        std::function<void()> callback) const;

private:
    friend class CancellationSource;
    explicit CancellationToken(
        std::shared_ptr<detail::CancellationState> state) noexcept
        : state_(std::move(state)) {}

    std::shared_ptr<detail::CancellationState> state_;
};

// Destruction requests cancellation. Callbacks are detached from the internal
// lock before invocation, may safely re-enter cancel/register operations, and
// cannot unwind through cancel().
class CancellationSource final {
public:
    CancellationSource();
    CancellationSource(const CancellationSource&) = delete;
    CancellationSource& operator=(const CancellationSource&) = delete;
    CancellationSource(CancellationSource&&) noexcept = default;
    CancellationSource& operator=(CancellationSource&& other) noexcept;
    ~CancellationSource() noexcept;

    CancellationToken token() const noexcept {
        return CancellationToken(state_);
    }
    bool cancel() noexcept;
    bool is_cancelled() const noexcept;

private:
    std::shared_ptr<detail::CancellationState> state_;
};

}  // namespace yume::engine
