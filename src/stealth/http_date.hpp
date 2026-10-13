/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <array>
#include <chrono>
#include <optional>
#include <string_view>

namespace yume::obfs {

// IMF-fixdate uses English names and exactly four year digits, independent of
// the process locale and time zone. Reject out-of-range clocks before calendar
// conversion; chrono::year has a narrower range than sys_seconds.
inline std::optional<std::array<char, 29U>> format_http_date(
    std::chrono::sys_seconds now) noexcept {
    using namespace std::chrono;
    if (now < sys_days{year{1}/January/1} ||
        now >= sys_days{year{10000}/January/1}) return std::nullopt;
    const auto day = floor<days>(now);
    const year_month_day date{day};
    const hh_mm_ss time{now - day};
    constexpr std::array<std::string_view, 7U> weekdays{
        "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    constexpr std::array<std::string_view, 12U> months{
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    std::array<char, 29U> text{};
    constexpr std::string_view pattern = "Sun, 00 Jan 0000 00:00:00 GMT";
    for (std::size_t i = 0U; i < text.size(); ++i) text[i] = pattern[i];
    const auto weekday = weekdays[std::chrono::weekday{day}.c_encoding()];
    const auto month = months[static_cast<unsigned>(date.month()) - 1U];
    for (std::size_t i = 0U; i < 3U; ++i) {
        text[i] = weekday[i];
        text[8U + i] = month[i];
    }
    const auto digits = [&](std::size_t offset, unsigned value, unsigned count) {
        while (count != 0U) {
            text[offset + --count] = static_cast<char>('0' + value % 10U);
            value /= 10U;
        }
    };
    digits(5U, static_cast<unsigned>(date.day()), 2U);
    digits(12U, static_cast<unsigned>(static_cast<int>(date.year())), 4U);
    digits(17U, static_cast<unsigned>(time.hours().count()), 2U);
    digits(20U, static_cast<unsigned>(time.minutes().count()), 2U);
    digits(23U, static_cast<unsigned>(time.seconds().count()), 2U);
    return text;
}

}  // namespace yume::obfs
