/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace yume::setup {

using Json = nlohmann::json;

// The largest JSON document setup reads: configurations, stores and the
// operator's cluster record.
inline constexpr std::size_t kMaxJsonBytes = std::size_t{4} * 1024U * 1024U;

// Client and node names: 1 to 63 letters, digits, '.', '_' or '-', beginning
// and ending with a letter or digit. They name files, so nothing else passes.
bool valid_name(std::string_view name) noexcept;
std::string require_client_name(std::string_view name);
std::string require_node_name(std::string_view name);
// A host a client endpoint may name, in setup's canonical text: an IP
// literal as inet_ntop prints it, or a DNS name in lowercase.
std::string require_host(std::string_view host);
// The canonical text of an IP literal, or nothing.
std::optional<std::string> canonical_ip(std::string_view text);

// The optional per-client settings, checked against the daemon's bounds.
void require_max_sessions(std::optional<std::int64_t> value);
void require_weight(std::optional<double> value);
void require_max_egress_mbps(std::optional<std::int64_t> value);

// A bounded, regular, non-symlink UTF-8 JSON file with no duplicate keys.
Json read_json(const std::filesystem::path& path);
// The text setup writes every JSON document in: keys sorted, two-space
// indent, non-ASCII escaped and one final newline.
std::string json_text(const Json& value);
// A new owner-only file holding value.
void write_json(const std::filesystem::path& path, const Json& value);

// One tuning preset of config/tuning_presets.json: the limits it sets on
// both sides of a kit.
struct Preset final {
    std::string id;
    Json limits;
};
// The presets table, which the build embeds unchanged.
const std::vector<Preset>& presets();
const std::string& default_preset();
// The preset with this id, or nullptr.
const Preset* find_preset(std::string_view id);

// The file reference at section/key/file of a configuration, resolved
// against the server directory. "server configuration lacks section.key"
// when it is absent.
std::filesystem::path config_reference(const std::filesystem::path& server,
                                       const Json& config,
                                       std::string_view section,
                                       std::string_view key);

// A server directory's yumed.json, which must be a schema-1 server
// configuration. what names the directory in the error.
Json read_server_config(const std::filesystem::path& server,
                        const std::string& what);

}  // namespace yume::setup
