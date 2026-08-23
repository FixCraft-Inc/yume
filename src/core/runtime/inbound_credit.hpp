/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <functional>
#include <utility>

namespace yume::runtime {

// Move-only ownership of receive-window credit. Keeping the token with a
// queued or in-flight operation prevents the transport from advertising more
// capacity until that operation has actually finished with the bytes.
class InboundCredit {
public:
    using ReleaseHandler = std::function<void(std::size_t)>;

    InboundCredit() = default;

    InboundCredit(std::size_t bytes, ReleaseHandler release)
        : bytes_(bytes)
        , release_(std::move(release)) {}

    InboundCredit(const InboundCredit&) = delete;
    InboundCredit& operator=(const InboundCredit&) = delete;

    InboundCredit(InboundCredit&& other) noexcept
        : bytes_(std::exchange(other.bytes_, 0U))
        , release_(std::move(other.release_)) {}

    InboundCredit& operator=(InboundCredit&& other) noexcept {
        if (this != &other) {
            release_now();
            bytes_ = std::exchange(other.bytes_, 0U);
            release_ = std::move(other.release_);
        }
        return *this;
    }

    ~InboundCredit() noexcept { release_now(); }

    void release_now() noexcept {
        const std::size_t bytes = std::exchange(bytes_, 0U);
        if (bytes == 0U || !release_) {
            release_ = {};
            return;
        }
        try {
            release_(bytes);
        } catch (...) {
            // Receive-credit release must remain safe from destructors and
            // error cleanup. Callers should use non-throwing handlers.
        }
        release_ = {};
    }

    std::size_t size() const noexcept { return bytes_; }
    explicit operator bool() const noexcept { return bytes_ != 0U; }

private:
    std::size_t bytes_{0U};
    ReleaseHandler release_;
};

}  // namespace yume::runtime
