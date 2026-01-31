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
#include <vector>

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
    if (!g_logging_enabled) {
        return;
    }
#if YUME_USE_SPDLOG
    spdlog::info(msg);
#else
    std::cerr << "[INFO] " << msg << std::endl;
#endif
}

void log_warn(const std::string& msg) {
    if (!g_logging_enabled) {
        return;
    }
#if YUME_USE_SPDLOG
    spdlog::warn(msg);
#else
    std::cerr << "[WARN] " << msg << std::endl;
#endif
}

void log_error(const std::string& msg) {
    if (!g_logging_enabled) {
        return;
    }
#if YUME_USE_SPDLOG
    spdlog::error(msg);
#else
    std::cerr << "[ERROR] " << msg << std::endl;
#endif
}

void set_logging_enabled(bool enabled) {
    g_logging_enabled = enabled;
}

bool is_logging_enabled() {
    return g_logging_enabled;
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
