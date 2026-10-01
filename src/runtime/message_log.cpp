/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/message_log.hpp"

#include <random>
#include <utility>

namespace yume::runtime {

MessageLog::MessageLog() noexcept {
    // The instance only tells two runs apart. It protects nothing, so a
    // clock value stands in when no random device is available.
    std::uint64_t value = 0U;
    try {
        std::random_device device;
        value = (std::uint64_t{device()} << 32U) | device();
    } catch (...) {
        value = static_cast<std::uint64_t>(
            std::chrono::steady_clock::now().time_since_epoch().count());
    }
    constexpr char kDigits[] = "0123456789abcdef";
    for (std::size_t index = 0; index < 16U; ++index) {
        instance_[index] = kDigits[(value >> (60U - 4U * index)) & 0xfU];
    }
    instance_[16] = '\0';
}

void MessageLog::add(std::string_view text) noexcept {
    const auto now = std::chrono::system_clock::now();
    std::lock_guard<std::mutex> lock(mutex_);
    const std::uint64_t seq = next_++;
    try {
        Entry entry{seq, now, std::string(text.substr(0U, kMaxTextBytes))};
        if (entries_.size() == kCapacity) entries_.pop_front();
        entries_.push_back(std::move(entry));
    } catch (...) {
    }
}

MessageLog::Page MessageLog::after(std::uint64_t seq) const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    const std::uint64_t numbered = next_ - 1U > seq ? next_ - 1U - seq : 0U;
    Page page;
    try {
        for (const auto& entry : entries_) {
            if (entry.seq > seq) page.entries.push_back(entry);
        }
    } catch (...) {
        page.entries.clear();
    }
    page.missed = numbered - page.entries.size();
    return page;
}

MessageLog::Next MessageLog::next_after(std::uint64_t seq) const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    Next next;
    for (const auto& entry : entries_) {
        if (entry.seq <= seq) continue;
        try {
            next.entry = entry;
            next.missed = entry.seq - seq - 1U;
        } catch (...) {
            next.entry.reset();
        }
        return next;
    }
    next.missed = next_ - 1U > seq ? next_ - 1U - seq : 0U;
    return next;
}

}  // namespace yume::runtime
