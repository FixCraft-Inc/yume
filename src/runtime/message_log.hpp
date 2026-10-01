/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yume::runtime {

// The latest messages a program has printed, which the messages request of
// control protocol 1 serves. Messages are numbered from 1 in the order they
// were added. Every call is thread-safe and none throws.
class MessageLog final {
public:
    static constexpr std::size_t kCapacity = 256U;
    static constexpr std::size_t kMaxTextBytes = 512U;

    struct Entry final {
        std::uint64_t seq{0U};
        std::chrono::system_clock::time_point time{};
        std::string text;
    };

    // The kept messages numbered above a point, oldest first, and how many
    // numbered above it are no longer kept.
    struct Page final {
        std::vector<Entry> entries;
        std::uint64_t missed{0U};
    };

    MessageLog() noexcept;
    MessageLog(const MessageLog&) = delete;
    MessageLog& operator=(const MessageLog&) = delete;

    // The oldest kept message numbered above a point, when one is kept, and
    // how many numbered above that point and below it are no longer kept.
    struct Next final {
        std::optional<Entry> entry;
        std::uint64_t missed{0U};
    };

    // Keeps text, cut to kMaxTextBytes, as the next message. Beyond
    // kCapacity the oldest message goes. A message that cannot be stored
    // still takes its number and counts as missed.
    void add(std::string_view text) noexcept;
    // An empty page when the copy cannot be made.
    Page after(std::uint64_t seq) const noexcept;
    // No entry when the copy cannot be made.
    Next next_after(std::uint64_t seq) const noexcept;
    // 16 hexadecimal digits chosen when the log is made, so a client can tell
    // a restarted program's numbers from the ones it has already seen.
    std::string_view instance() const noexcept {
        return {instance_.data(), instance_.size() - 1U};
    }

private:
    mutable std::mutex mutex_;
    std::deque<Entry> entries_;
    std::uint64_t next_{1U};
    std::array<char, 17> instance_{};
};

}  // namespace yume::runtime
