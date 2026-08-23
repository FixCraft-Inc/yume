/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

#include "core/diagnostics/timing.hpp"

namespace yume::util {

// read_json_config() lives in util_json.hpp: it is the only declaration here
// that needed <nlohmann/json.hpp>, and it has two call sites while this header
// has 54 includers.
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
bool env_flag(const char* name, bool fallback = false);
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
// Server target/source reads use smaller DATA records so one 256 KiB epoch is
// incrementally receivable instead of blocking behind one maximum-size frame.
std::size_t server_relay_read_buf_size();
std::string base64_decode(const std::string& input);
std::string base64_encode(const std::string& input);

// Owns the process-wide SIGINT/SIGTERM callback registration. POSIX signal
// handlers only enqueue the signal into an async-signal-safe bridge; the user
// callback runs on a managed dispatcher thread. Destroying a registration
// disables it and waits for any in-flight callback before captured state can
// disappear, then restores the process's preceding OS handlers.
//
// There is deliberately one process-wide slot. Installing a newer standalone
// CLI/server registration supersedes an older one; destroying the older token
// cannot clear the newer callback. Embedded runtimes must leave signal policy
// to their host and use their explicit cancellation channel instead.
class SignalHandlerRegistration final {
public:
    SignalHandlerRegistration() noexcept = default;
    explicit SignalHandlerRegistration(std::function<void(int)> handler);
    ~SignalHandlerRegistration();

    SignalHandlerRegistration(const SignalHandlerRegistration&) = delete;
    SignalHandlerRegistration& operator=(const SignalHandlerRegistration&) = delete;
    SignalHandlerRegistration(SignalHandlerRegistration&& other) noexcept;
    SignalHandlerRegistration& operator=(SignalHandlerRegistration&& other) noexcept;

    void reset() noexcept;
    explicit operator bool() const noexcept { return generation_ != 0; }

private:
    std::uint64_t generation_{0};
};

}  // namespace yume::util
