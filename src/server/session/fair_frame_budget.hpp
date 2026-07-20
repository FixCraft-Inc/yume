/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <unordered_set>

namespace yume::server {

// Strand-confined aggregate reservation helper. The caller decides whether a
// source still has work; this class guarantees one ready entry per source,
// round-robin selection, and a hard session-wide outstanding-frame limit.
class FairFrameBudget {
public:
    explicit FairFrameBudget(std::size_t limit) : limit_(limit) {}

    void activate(std::uint8_t source) {
        if (ready_set_.insert(source).second) ready_.push_back(source);
    }

    void deactivate(std::uint8_t source) {
        ready_set_.erase(source);
        ready_.erase(std::remove(ready_.begin(), ready_.end(), source), ready_.end());
    }

    std::optional<std::uint8_t> pop_ready() {
        while (!ready_.empty()) {
            const auto source = ready_.front();
            ready_.pop_front();
            if (ready_set_.erase(source) != 0) return source;
        }
        return std::nullopt;
    }

    bool reserve() noexcept {
        if (reserved_ >= limit_) return false;
        ++reserved_;
        peak_reserved_ = std::max(peak_reserved_, reserved_);
        return true;
    }

    void release() noexcept {
        if (reserved_ > 0) --reserved_;
    }

    bool full() const noexcept { return reserved_ >= limit_; }
    std::size_t reserved() const noexcept { return reserved_; }
    std::size_t peak_reserved() const noexcept { return peak_reserved_; }
    std::size_t ready_sources() const noexcept { return ready_set_.size(); }

private:
    std::size_t limit_{0};
    std::size_t reserved_{0};
    std::size_t peak_reserved_{0};
    std::deque<std::uint8_t> ready_;
    std::unordered_set<std::uint8_t> ready_set_;
};

}  // namespace yume::server
