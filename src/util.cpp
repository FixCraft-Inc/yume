/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "util.hpp"

#include <csignal>
#include <cstdlib>
#include <fstream>
#include <mutex>
#include <iostream>

#if YUME_USE_SPDLOG
#include <spdlog/spdlog.h>
#endif

namespace yume::util {

namespace {
std::function<void(int)> g_signal_handler;
std::mutex g_signal_mutex;

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
    if (path.rfind("~/", 0) == 0) {
        const char* home = std::getenv("HOME");
        if (home) {
            return std::string(home) + path.substr(1);
        }
    }
    return path;
}

void init_logging() {
#if YUME_USE_SPDLOG
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");
    spdlog::set_level(spdlog::level::info);
#endif
}

void log_info(const std::string& msg) {
#if YUME_USE_SPDLOG
    spdlog::info(msg);
#else
    std::cerr << "[INFO] " << msg << std::endl;
#endif
}

void log_warn(const std::string& msg) {
#if YUME_USE_SPDLOG
    spdlog::warn(msg);
#else
    std::cerr << "[WARN] " << msg << std::endl;
#endif
}

void log_error(const std::string& msg) {
#if YUME_USE_SPDLOG
    spdlog::error(msg);
#else
    std::cerr << "[ERROR] " << msg << std::endl;
#endif
}

void install_signal_handlers(const std::function<void(int)>& handler) {
    std::lock_guard<std::mutex> lock(g_signal_mutex);
    g_signal_handler = handler;
    std::signal(SIGINT, signal_dispatch);
    std::signal(SIGTERM, signal_dispatch);
}

}  // namespace yume::util
