/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * Selftest/benchmark terminal presentation: progress bar, ANSI color,
 * and grade colouring. Extracted verbatim from tools/selftest.cpp.
 */

#include "tools/selftest/render.hpp"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>

#if !defined(_WIN32)
#include <unistd.h>
#endif

namespace yume::tools::selftest {

namespace {
bool& progress_line_active() {
    static bool active = false;
    return active;
}
}  // namespace

std::string checksum_detail(int value) {
    return std::string(kChecksumField) + "=" + std::to_string(value & 0xff);
}

std::vector<std::uint8_t> ascii_bytes(std::string_view value) {
    return {value.begin(), value.end()};
}

bool stderr_is_tty() {
#if !defined(_WIN32)
    static const bool enabled = ::isatty(STDERR_FILENO) == 1;
#else
    static const bool enabled = true;
#endif
    return enabled;
}

bool progress_inline_enabled() {
    return stderr_is_tty();
}

bool color_enabled(const Args& args) {
    return args.color && stderr_is_tty() && std::getenv("NO_COLOR") == nullptr;
}


void finish_progress_line() {
    if (progress_inline_enabled() && progress_line_active()) {
        std::cerr << "\n";
        progress_line_active() = false;
    }
}

std::string ansi_wrap(const Args& args, std::string_view code, std::string value) {
    if (!color_enabled(args)) {
        return value;
    }
    return "\033[" + std::string(code) + "m" + value + "\033[0m";
}

std::string grade_color_code(std::string_view grade, long long score) {
    if (score > 0 && score < 2500) return "1;30;47";       // critical: black on white
    if (grade == "F-") return "1;38;2;80;0;0";             // darkest red
    if (grade == "F") return "1;38;2;120;0;0";
    if (grade == "F+") return "1;38;2;160;18;18";
    if (grade == "D-") return "1;38;2;196;32;32";          // red
    if (grade == "D") return "1;38;2;224;44;28";
    if (grade == "D+") return "1;38;2;212;82;0";           // dark orange
    if (grade == "C-") return "1;38;2;236;112;0";
    if (grade == "C") return "1;38;2;246;146;0";           // orange
    if (grade == "C+") return "1;38;2;255;176;24";
    if (grade == "B-") return "1;38;2;144;112;0";          // dark yellow
    if (grade == "B") return "1;38;2;190;156;0";
    if (grade == "B+") return "1;38;2;242;218;34";         // light yellow
    if (grade == "A-") return "1;38;2;190;238;64";
    if (grade == "A") return "1;38;2;124;220;68";          // light green
    if (grade == "A+") return "1;38;2;80;200;64";
    if (grade == "AAA-") return "1;38;2;32;168;72";
    if (grade == "AAA") return "1;38;2;18;132;62";         // green
    if (grade == "AAA+") return "1;38;2;0;92;54";          // dark green
    if (grade == "S-") return "1;38;2;0;64;116";
    if (grade == "S") return "1;38;2;0;76;156";            // dark blue
    if (grade == "S+") return "1;38;2;0;92;190";
    if (grade == "SS-") return "1;38;2;0;122;224";
    if (grade == "SS") return "1;38;2;0;158;242";
    if (grade == "SS+") return "1;38;2;34;190;255";
    if (grade == "SSS-") return "1;38;2;78;214;255";
    if (grade == "SSS") return "1;38;2;128;232;255";
    return "1;38;2;178;244;255";                           // SSS+ light blue
}

std::string color_grade(const Args& args, std::string grade, long long score) {
    return ansi_wrap(args, grade_color_code(grade, score), std::move(grade));
}

void render_progress_bar(double completed, int total, std::string_view label) {
    total = std::max(1, total);
    completed = std::clamp(completed, 0.0, static_cast<double>(total));
    constexpr int kWidth = 28;
    const int filled = static_cast<int>((completed * kWidth) / static_cast<double>(total));
    const int percent = static_cast<int>((completed * 100.0) / static_cast<double>(total));
    std::ostringstream line;
    line << kBenchLogPrefix << " progress [";
    for (int i = 0; i < kWidth; ++i) {
        line << (i < filled ? '#' : '.');
    }
    line << "] " << std::setw(3) << std::clamp(percent, 0, 100) << "% ";
    const double rounded = std::round(completed);
    if (std::abs(completed - rounded) < 0.05) {
        line << static_cast<int>(rounded);
    } else {
        line << std::fixed << std::setprecision(1) << completed;
    }
    line << "/" << total << " " << label;

    if (progress_inline_enabled()) {
        std::cerr << "\r" << line.str() << "        " << std::flush;
        progress_line_active() = true;
        if (completed >= total) {
            std::cerr << "\n";
            progress_line_active() = false;
        }
        return;
    }

    static int last_bucket = -1;
    static int last_percent = -1;
    static int last_total = -1;
    if (last_total != total || completed <= 0.0) {
        last_bucket = -1;
        last_percent = -1;
        last_total = total;
    }
    const int bucket = std::clamp(percent, 0, 100) / 10;
    const bool final_line = completed >= total;
    const bool should_print = final_line ? last_percent < 100 : (percent > 0 && bucket != last_bucket);
    if (should_print) {
        std::cerr << line.str() << "\n";
        last_bucket = bucket;
        last_percent = std::clamp(percent, 0, 100);
    }
}

void render_progress_bar(int completed, int total, std::string_view label) {
    render_progress_bar(static_cast<double>(completed), total, label);
}
}  // namespace yume::tools::selftest
