/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "facade/config/profiles.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <fstream>
#include <random>
#include <sstream>
#include <system_error>

#include <nlohmann/json.hpp>

#include "facade/config/config_io.hpp"

namespace yume::facade::profiles {

namespace {

using nlohmann::json;

std::filesystem::path active_marker() {
    return profiles_dir() / "active";
}

std::string read_active_id() {
    std::ifstream in(active_marker());
    if (!in) return {};
    std::string id;
    std::getline(in, id);
    while (!id.empty() && (id.back() == '\n' || id.back() == '\r')) id.pop_back();
    return id;
}

}  // namespace

std::filesystem::path profiles_dir() {
    return config_io::default_data_dir() / "profiles";
}

std::filesystem::path active_pointer_path() {
    return active_marker();
}

std::string slug_from(std::string const& display_name) {
    std::string out;
    out.reserve(display_name.size());
    for (char c : display_name) {
        if (std::isalnum(static_cast<unsigned char>(c))) {
            out.push_back(static_cast<char>(
                std::tolower(static_cast<unsigned char>(c))));
        } else if (c == ' ' || c == '-' || c == '_' || c == '.') {
            out.push_back('-');
        }
    }
    while (out.size() > 1 && out.back() == '-') out.pop_back();
    if (out.empty()) {
        std::random_device rd;
        char buf[16];
        std::snprintf(buf, sizeof(buf), "profile-%08x", rd());
        out = buf;
    }
    return out;
}

std::vector<ProfileSummary> list() {
    std::vector<ProfileSummary> out;
    std::error_code ec;
    std::filesystem::create_directories(profiles_dir(), ec);
    const std::string active = read_active_id();
    for (auto const& e : std::filesystem::directory_iterator(profiles_dir(), ec)) {
        if (!e.is_regular_file()) continue;
        if (e.path().extension() != ".json") continue;

        ProfileSummary s;
        s.path = e.path();
        s.id = e.path().stem().string();
        s.display_name = s.id;

        // Try to read display_name from inside the file.
        std::ifstream in(e.path());
        if (in) {
            try {
                json j;
                in >> j;
                if (j.is_object() && j.contains("display_name") &&
                    j["display_name"].is_string()) {
                    s.display_name = j["display_name"].get<std::string>();
                }
            } catch (...) {
                // keep id as display
            }
        }
        s.is_active = (s.id == active);
        out.push_back(std::move(s));
    }
    std::sort(out.begin(), out.end(),
              [](auto const& a, auto const& b) {
                  return a.display_name < b.display_name;
              });
    return out;
}

std::string active_id() {
    return read_active_id();
}

bool set_active(std::string const& id) {
    std::error_code ec;
    std::filesystem::create_directories(profiles_dir(), ec);
    std::ofstream out(active_marker(), std::ios::trunc);
    if (!out) return false;
    out << id;
    return out.good();
}

std::optional<client::ClientConfig> load(std::string const& id, std::string* err) {
    const auto path = profiles_dir() / (id + ".json");
    return config_io::load_client(path, err);
}

bool save(std::string const& id,
          std::string const& display_name,
          client::ClientConfig const& cfg,
          std::string* err) {
    const auto path = profiles_dir() / (id + ".json");
    if (!config_io::save_client(cfg, path, err)) return false;

    // Re-open and inject the display_name field so list() can show it
    // without keeping a separate index.
    std::ifstream in(path);
    if (!in) return true;  // best-effort
    json j;
    try {
        in >> j;
    } catch (...) {
        return true;
    }
    in.close();
    j["display_name"] = display_name;
    std::ofstream out(path, std::ios::trunc);
    if (!out) return true;
    out << j.dump(2);
    return out.good();
}

bool remove(std::string const& id, std::string* err) {
    const auto path = profiles_dir() / (id + ".json");
    std::error_code ec;
    if (!std::filesystem::remove(path, ec)) {
        if (err) *err = ec ? ec.message() : std::string("profile not found");
        return false;
    }
    if (read_active_id() == id) {
        std::filesystem::remove(active_marker(), ec);
    }
    return true;
}

std::optional<std::string> create(std::string const& display_name,
                                  client::ClientConfig const& cfg,
                                  std::string* err) {
    std::string id = slug_from(display_name);
    // Avoid id collisions by appending a numeric suffix if needed.
    int suffix = 0;
    while (std::filesystem::exists(profiles_dir() / (id + ".json"))) {
        ++suffix;
        id = slug_from(display_name) + "-" + std::to_string(suffix);
    }
    if (!save(id, display_name, cfg, err)) return std::nullopt;
    return id;
}

}  // namespace yume::facade::profiles
