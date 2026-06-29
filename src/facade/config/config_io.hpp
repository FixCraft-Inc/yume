/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "client/cli/entry.hpp"
#include "server/config/config.hpp"

namespace yume::facade::config_io {

struct ValidationReport {
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
    bool ok() const noexcept { return errors.empty(); }
};

// JSON ↔ ClientConfig. The format matches what main_client.cpp accepts so
// the GUI and CLI can share config files. Unknown keys are ignored
// (forward-compatible). Returns nullopt with *err populated on parse fail.
std::optional<client::ClientConfig> load_client(
    std::filesystem::path const& path, std::string* err);
std::optional<client::ClientConfig> parse_client_json(
    std::string_view text,
    std::filesystem::path const& base_dir,
    std::string* err);
bool save_client(client::ClientConfig const& cfg,
                 std::filesystem::path const& path,
                 std::string* err);
ValidationReport validate(client::ClientConfig const& cfg);

// JSON ↔ ServerConfig. Same conventions as load_client/save_client.
std::optional<server::ServerConfig> load_server(
    std::filesystem::path const& path, std::string* err);
std::optional<server::ServerConfig> parse_server_json(
    std::string_view text,
    std::filesystem::path const& base_dir,
    std::string* err);
bool save_server(server::ServerConfig const& cfg,
                 std::filesystem::path const& path,
                 std::string* err);
ValidationReport validate(server::ServerConfig const& cfg);

// GUI user data location. The desktop app intentionally keeps profiles,
// trust material, and generated keys together under ~/.yume.
std::filesystem::path default_data_dir();
std::filesystem::path default_client_config_path();
std::filesystem::path default_server_config_path();

// GUI-only preferences (theme, window). Kept separate from
// Client/ServerConfig so the CLI build doesn't pull GUI-specific knobs
// in. Unknown JSON keys are ignored on load; missing keys fall back to
// the defaults below.
struct GuiPreferences {
    bool dark_mode{true};
    bool minimize_to_tray_on_close{true};
};

std::filesystem::path default_gui_preferences_path();
GuiPreferences load_gui_preferences();
bool save_gui_preferences(GuiPreferences const& prefs);

}  // namespace yume::facade::config_io
