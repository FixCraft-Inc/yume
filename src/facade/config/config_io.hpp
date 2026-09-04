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
#include "facade/config/load_error.hpp"
#include "server/config/config.hpp"

namespace yume::facade::config_io {

struct ValidationReport {
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
    bool ok() const noexcept { return errors.empty(); }
};

// JSON ↔ ClientConfig. The format matches what main_client.cpp accepts so
// the GUI and CLI can share config files. The key set is closed: see
// config/client_document_keys.hpp. Returns nullopt with *err populated on
// parse failure. When `json_pointer` is given it receives an RFC 6901
// pointer to the offending member, or an empty string when the failure
// belongs to no single member.
std::optional<client::ClientConfig> load_client(
    std::filesystem::path const& path,
    std::string* err,
    ConfigLoadError* load_error = nullptr);
std::optional<client::ClientConfig> parse_client_json(
    std::string_view text,
    std::filesystem::path const& base_dir,
    std::string* err,
    std::string* json_pointer = nullptr);
bool save_client(client::ClientConfig const& cfg,
                 std::filesystem::path const& path,
                 std::string* err);
bool serialize_client_json(
    client::ClientConfig const& cfg,
    std::optional<std::string_view> display_name,
    std::string* serialized,
    std::string* err);
ValidationReport validate(client::ClientConfig const& cfg);

// JSON ↔ ServerConfig. Same conventions as load_client/save_client, with the
// closed key set in config/server_document_keys.hpp.
std::optional<server::ServerConfig> load_server(
    std::filesystem::path const& path,
    std::string* err,
    ConfigLoadError* load_error = nullptr);
std::optional<server::ServerConfig> parse_server_json(
    std::string_view text,
    std::filesystem::path const& base_dir,
    std::string* err,
    std::string* json_pointer = nullptr);
bool save_server(server::ServerConfig const& cfg,
                 std::filesystem::path const& path,
                 std::string* err);
ValidationReport validate(server::ServerConfig const& cfg);

// GUI user data location. The desktop app intentionally keeps profiles,
// trust material, and generated keys together under ~/.yume.
std::filesystem::path default_data_dir();
std::filesystem::path default_client_config_path();
std::filesystem::path default_server_config_path();

}  // namespace yume::facade::config_io
