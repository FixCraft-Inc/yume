/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * Selftest/benchmark terminal presentation helpers (progress bar, ANSI
 * color, grade colouring), extracted from tools/selftest.cpp. No behavior
 * change.
 */

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "tools/selftest/runtime.hpp"

namespace yume::tools::selftest {

inline constexpr std::string_view kBenchLogPrefix = "[bench]";
inline constexpr std::string_view kChecksumField = "checksum";

std::string checksum_detail(int value);
std::vector<std::uint8_t> ascii_bytes(std::string_view value);
bool stderr_is_tty();
bool progress_inline_enabled();
bool color_enabled(const Args& args);
void finish_progress_line();
std::string ansi_wrap(const Args& args, std::string_view code, std::string value);
std::string grade_color_code(std::string_view grade, long long score);
std::string color_grade(const Args& args, std::string grade, long long score);
void render_progress_bar(double completed, int total, std::string_view label);
void render_progress_bar(int completed, int total, std::string_view label);

}  // namespace yume::tools::selftest
