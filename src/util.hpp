/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <functional>
#include <string>

#include <nlohmann/json.hpp>

namespace yume::util {

nlohmann::json read_json_config(const std::string& path);
std::string expand_user(const std::string& path);
std::string resolve_path(const std::string& path,
                         const std::string& base_dir,
                         const std::string& exe_dir);

void init_logging();
void log_info(const std::string& msg);
void log_warn(const std::string& msg);
void log_error(const std::string& msg);
void log_info_rate_limited(const std::string& key, const std::string& msg, int64_t interval_ms);
void log_warn_rate_limited(const std::string& key, const std::string& msg, int64_t interval_ms);
void set_logging_enabled(bool enabled);
bool is_logging_enabled();
void set_timing_enabled(bool enabled);
bool timing_enabled();
void log_timing(const std::string& component,
                const std::string& event,
                const std::string& details = {});
void set_status_enabled(bool enabled);
void set_status_line(const std::string& line);
void clear_status_line();
bool stdout_is_terminal();
bool stdout_colors_enabled();
bool drop_privileges(std::string* error = nullptr, std::string* summary = nullptr);
std::string random_hex(size_t bytes);
int64_t now_ms();
// Per-stream relay read-buffer size in bytes (see definition). Tunable via
// YUME_RELAY_READ_BUF (KiB); default 64 KiB.
std::size_t relay_read_buf_size();
std::string base64_decode(const std::string& input);
std::string base64_encode(const std::string& input);

void install_signal_handlers(const std::function<void(int)>& handler);

}  // namespace yume::util
