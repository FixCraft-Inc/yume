/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <system_error>
#include <type_traits>
#include <utility>

#include <nlohmann/json.hpp>

#include "config/document_error.hpp"

namespace yume::facade::config_io::detail {

// Reads `key` into `dst` when present and non-null. Integral targets are
// range-checked instead of narrowed: nlohmann's get<std::uint32_t>() would
// turn "obfs_jitter_ms": -1 into ~49 days of jitter and get<std::uint16_t>()
// would fold 65792 into 256, so a value the field cannot represent is a
// configuration error, the same rule the CLI parser applies.
template <typename T>
void read_opt(nlohmann::json const& j, const char* key, T& dst) {
    auto it = j.find(key);
    if (it == j.end() || it->is_null()) {
        return;
    }
    if constexpr (std::is_integral_v<T> && !std::is_same_v<T, bool>) {
        if (!it->is_number_integer()) {
            throw yume::config::member_error(
                key, std::string(key) + ": must be an integer");
        }
        if (it->is_number_unsigned()) {
            const auto value = it->get<std::uint64_t>();
            if (!std::in_range<T>(value)) {
                throw yume::config::member_error(
                    key, std::string(key) + ": value is out of range");
            }
            dst = static_cast<T>(value);
        } else {
            const auto value = it->get<std::int64_t>();
            if (!std::in_range<T>(value)) {
                throw yume::config::member_error(
                    key, std::string(key) + ": value is out of range");
            }
            dst = static_cast<T>(value);
        }
        return;
    } else {
        try {
            dst = it->get<T>();
        } catch (const nlohmann::json::exception& error) {
            throw yume::config::member_error(
                key, std::string(key) + ": invalid value: " + error.what());
        }
    }
}

inline std::filesystem::path home_dir() {
#ifdef _WIN32
    if (const char* p = std::getenv("USERPROFILE")) return p;
    if (const char* p = std::getenv("HOMEDRIVE")) {
        if (const char* h = std::getenv("HOMEPATH")) {
            return std::filesystem::path(p) / h;
        }
    }
    return {};
#else
    if (const char* p = std::getenv("HOME")) return p;
    return {};
#endif
}

inline std::filesystem::path expand_user_path(std::string const& value) {
    if (value == "~") return home_dir();
    if (value.rfind("~/", 0) == 0 || value.rfind("~\\", 0) == 0) {
        return home_dir() / value.substr(2);
    }
    return std::filesystem::path(value);
}

inline void resolve_config_path(std::string& value, std::filesystem::path const& base) {
    if (value.empty()) return;
    std::filesystem::path p = expand_user_path(value);
    if (p.is_relative() && !base.empty()) {
        p = base / p;
    }

    std::error_code ec;
    auto abs = std::filesystem::absolute(p, ec);
    if (!ec) p = abs;
    value = p.lexically_normal().string();
}

inline void resolve_filter_spec_path(std::string& value, std::filesystem::path const& base) {
    const auto first = value.find(':');
    const auto second = first == std::string::npos ? std::string::npos : value.find(':', first + 1);
    if (first == std::string::npos || second == std::string::npos || second + 1 >= value.size()) {
        return;
    }
    std::string list_path = value.substr(second + 1);
    resolve_config_path(list_path, base);
    value = value.substr(0, second + 1) + list_path;
}

}  // namespace yume::facade::config_io::detail
