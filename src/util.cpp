/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "util.hpp"

#include <chrono>
#include <cstdio>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <iostream>
#include <vector>

#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cctype>

#if YUME_USE_SPDLOG
#include <spdlog/spdlog.h>
#endif

namespace yume::util {

namespace {
std::function<void(int)> g_signal_handler;
std::mutex g_signal_mutex;
bool g_logging_enabled = true;
std::mutex g_status_mutex;
std::string g_status_text;
std::size_t g_status_lines = 0;
bool g_status_enabled = true;
bool g_status_active = false;
bool g_status_supported = true;

bool is_tty_stdout() {
#if defined(_WIN32)
    return _isatty(_fileno(stdout)) != 0;
#else
    return isatty(fileno(stdout)) != 0;
#endif
}

bool is_tty_stderr() {
#if defined(_WIN32)
    return _isatty(_fileno(stderr)) != 0;
#else
    return isatty(fileno(stderr)) != 0;
#endif
}

bool env_var_enabled(const char* name, bool fallback) {
    const char* raw = std::getenv(name);
    if (!raw || !*raw) {
        return fallback;
    }
    std::string value(raw);
    for (char& ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    if (value == "1" || value == "true" || value == "yes" || value == "on") {
        return true;
    }
    if (value == "0" || value == "false" || value == "no" || value == "off") {
        return false;
    }
    return fallback;
}

bool log_colors_enabled() {
    if (!is_tty_stderr()) {
        return false;
    }
    if (std::getenv("NO_COLOR") != nullptr) {
        return false;
    }
    return env_var_enabled("YUME_COLOR", true) && !env_var_enabled("YUME_NO_COLOR", false);
}

void print_plain_log(const char* level, const std::string& msg) {
    std::cerr << "[" << level << "] " << msg << std::endl;
}

void print_colored_log(const char* level, const char* color_code, const std::string& msg) {
    if (!log_colors_enabled()) {
        print_plain_log(level, msg);
        return;
    }
    std::cerr << "\033[" << color_code << "m[" << level << "]\033[0m " << msg << std::endl;
}

std::size_t count_status_lines(const std::string& text) {
    if (text.empty()) {
        return 0;
    }
    std::size_t lines = 1;
    for (char ch : text) {
        if (ch == '\n') {
            ++lines;
        }
    }
    return lines;
}

void clear_status_line_locked() {
    if (!g_status_supported || !g_status_enabled) {
        return;
    }
    if (!g_status_active && g_status_text.empty()) {
        return;
    }
    if (g_status_lines == 0) {
        g_status_active = false;
        return;
    }
    for (std::size_t i = 0; i < g_status_lines; ++i) {
        std::cout << "\r\033[2K";
        if (i + 1 < g_status_lines) {
            std::cout << "\033[1A";
        }
    }
    std::cout << std::flush;
    g_status_active = false;
}

void render_status_line_locked() {
    if (!g_status_supported || !g_status_enabled) {
        return;
    }
    if (g_status_text.empty()) {
        return;
    }
    std::cout << "\r" << g_status_text << "\033[2K" << std::flush;
    g_status_active = true;
}

bool is_env_char(char ch) {
    return std::isalnum(static_cast<unsigned char>(ch)) != 0 || ch == '_';
}

std::string expand_env_vars(const std::string& input) {
    std::string out;
    out.reserve(input.size());
    for (size_t i = 0; i < input.size();) {
        if (input[i] == '%') {
            size_t end = input.find('%', i + 1);
            if (end != std::string::npos && end > i + 1) {
                std::string key = input.substr(i + 1, end - i - 1);
                const char* val = std::getenv(key.c_str());
                if (val) {
                    out.append(val);
                } else {
                    out.append(input, i, end - i + 1);
                }
                i = end + 1;
                continue;
            }
        } else if (input[i] == '$') {
            if (i + 1 < input.size() && input[i + 1] == '{') {
                size_t end = input.find('}', i + 2);
                if (end != std::string::npos && end > i + 2) {
                    std::string key = input.substr(i + 2, end - i - 2);
                    const char* val = std::getenv(key.c_str());
                    if (val) {
                        out.append(val);
                    } else {
                        out.append(input, i, end - i + 1);
                    }
                    i = end + 1;
                    continue;
                }
            } else {
                size_t j = i + 1;
                while (j < input.size() && is_env_char(input[j])) {
                    ++j;
                }
                if (j > i + 1) {
                    std::string key = input.substr(i + 1, j - i - 1);
                    const char* val = std::getenv(key.c_str());
                    if (val) {
                        out.append(val);
                    } else {
                        out.append(input, i, j - i);
                    }
                    i = j;
                    continue;
                }
            }
        }
        out.push_back(input[i]);
        ++i;
    }
    return out;
}

void signal_dispatch(int signum) {
    std::lock_guard<std::mutex> lock(g_signal_mutex);
    if (g_signal_handler) {
        g_signal_handler(signum);
    }
}
}  // namespace

nlohmann::json read_json_config(const std::string& path) {
    std::ifstream in(expand_user(path));
    if (!in.is_open()) {
        throw std::runtime_error("failed to open config: " + path);
    }
    nlohmann::json cfg;
    in >> cfg;
    return cfg;
}

std::string expand_user(const std::string& path) {
    if (path.rfind("~/", 0) == 0 || path.rfind("~\\", 0) == 0) {
        const char* home = std::getenv("HOME");
#if defined(_WIN32)
        if (!home) {
            home = std::getenv("USERPROFILE");
        }
#endif
        if (home) {
            return std::string(home) + path.substr(1);
        }
    }
    return path;
}

std::string resolve_path(const std::string& path,
                         const std::string& base_dir,
                         const std::string& exe_dir) {
    if (path.empty()) {
        return {};
    }
    std::string expanded = expand_env_vars(expand_user(path));
    std::filesystem::path p(expanded);
    if (p.is_absolute() || p.has_root_name()) {
        return p.lexically_normal().string();
    }
    if (!base_dir.empty()) {
        return (std::filesystem::path(base_dir) / p).lexically_normal().string();
    }
    if (!exe_dir.empty()) {
        return (std::filesystem::path(exe_dir) / p).lexically_normal().string();
    }
    return expanded;
}

void init_logging() {
#if YUME_USE_SPDLOG
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");
    spdlog::set_level(spdlog::level::info);
#endif
    {
        std::lock_guard<std::mutex> lock(g_status_mutex);
        g_status_supported = is_tty_stdout();
        if (!g_status_supported) {
            g_status_enabled = false;
            g_status_text.clear();
            g_status_lines = 0;
            g_status_active = false;
        }
    }
}

void log_info(const std::string& msg) {
    if (!g_logging_enabled) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_status_mutex);
    clear_status_line_locked();
#if YUME_USE_SPDLOG
    spdlog::info(msg);
#else
    print_colored_log("INFO", "1;36", msg);
#endif
    render_status_line_locked();
}

void log_warn(const std::string& msg) {
    if (!g_logging_enabled) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_status_mutex);
    clear_status_line_locked();
#if YUME_USE_SPDLOG
    spdlog::warn(msg);
#else
    print_colored_log("WARN", "1;33", msg);
#endif
    render_status_line_locked();
}

void log_error(const std::string& msg) {
    if (!g_logging_enabled) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_status_mutex);
    clear_status_line_locked();
#if YUME_USE_SPDLOG
    spdlog::error(msg);
#else
    print_colored_log("ERROR", "1;31", msg);
#endif
    render_status_line_locked();
}

void set_logging_enabled(bool enabled) {
    g_logging_enabled = enabled;
}

bool is_logging_enabled() {
    return g_logging_enabled;
}

void set_status_enabled(bool enabled) {
    std::lock_guard<std::mutex> lock(g_status_mutex);
    g_status_enabled = enabled;
    if (!g_status_enabled) {
        clear_status_line_locked();
        g_status_text.clear();
        g_status_lines = 0;
        return;
    }
    render_status_line_locked();
}

void set_status_line(const std::string& line) {
    std::lock_guard<std::mutex> lock(g_status_mutex);
    if (!g_status_enabled || !g_status_supported) {
        return;
    }
    if (g_status_active) {
        clear_status_line_locked();
    }
    g_status_text = line;
    g_status_lines = count_status_lines(line);
    render_status_line_locked();
}

void clear_status_line() {
    std::lock_guard<std::mutex> lock(g_status_mutex);
    clear_status_line_locked();
}

std::string random_hex(size_t bytes) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.resize(bytes * 2);
    std::vector<unsigned char> buf(bytes);
    if (bytes > 0) {
        if (RAND_bytes(buf.data(), static_cast<int>(buf.size())) != 1) {
            return {};
        }
    }
    for (size_t i = 0; i < bytes; ++i) {
        out[i * 2] = kHex[(buf[i] >> 4) & 0xF];
        out[i * 2 + 1] = kHex[buf[i] & 0xF];
    }
    return out;
}

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string base64_decode(const std::string& input) {
    if (input.empty()) {
        return {};
    }
    std::string clean;
    clean.reserve(input.size());
    for (unsigned char c : input) {
        if (c == '=' || std::isalnum(c) || c == '+' || c == '/') {
            clean.push_back(static_cast<char>(c));
        }
    }

    std::string out((clean.size() * 3) / 4 + 2, '\0');
    int len = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(&out[0]),
                              reinterpret_cast<const unsigned char*>(clean.data()),
                              static_cast<int>(clean.size()));
    if (len < 0) {
        return {};
    }
    size_t padding = 0;
    if (!clean.empty() && clean.back() == '=') {
        padding++;
        if (clean.size() > 1 && clean[clean.size() - 2] == '=') {
            padding++;
        }
    }
    if (padding > 0 && static_cast<size_t>(len) >= padding) {
        len -= static_cast<int>(padding);
    }
    out.resize(static_cast<size_t>(len));
    return out;
}

std::string base64_encode(const std::string& input) {
    if (input.empty()) {
        return {};
    }
    std::string out(((input.size() + 2) / 3) * 4, '\0');
    int len = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&out[0]),
                              reinterpret_cast<const unsigned char*>(input.data()),
                              static_cast<int>(input.size()));
    if (len <= 0) {
        return {};
    }
    out.resize(static_cast<size_t>(len));
    return out;
}

void install_signal_handlers(const std::function<void(int)>& handler) {
    std::lock_guard<std::mutex> lock(g_signal_mutex);
    g_signal_handler = handler;
    std::signal(SIGINT, signal_dispatch);
    std::signal(SIGTERM, signal_dispatch);
}

}  // namespace yume::util
