/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "setup/provision.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <set>

#include <arpa/inet.h>

#include "config/v1/config.hpp"
#include "runtime/egress_limiter.hpp"
#include "runtime/native_credentials.hpp"
#include "setup/files.hpp"
#include "setup/tuning_presets_json.hpp"

namespace yume::setup {
namespace {

namespace fs = std::filesystem;

constexpr std::size_t kMaxNameBytes = 63U;

bool name_character(char ch) noexcept {
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
           (ch >= '0' && ch <= '9');
}

std::string format_bound(double value) {
    std::array<char, 32> text{};
    static_cast<void>(std::snprintf(text.data(), text.size(), "%g", value));
    return text.data();
}

std::vector<Preset> load_presets() {
    const auto table = Json::parse(std::string_view(kTuningPresetsJson));
    std::vector<Preset> loaded;
    for (const auto& entry : table.at("presets")) {
        loaded.push_back(
            {entry.at("id").get<std::string>(), entry.at("limits")});
    }
    return loaded;
}

}  // namespace

bool valid_name(std::string_view name) noexcept {
    return !name.empty() && name.size() <= kMaxNameBytes &&
           name_character(name.front()) && name_character(name.back()) &&
           std::all_of(name.begin(), name.end(), [](char ch) {
               return name_character(ch) || ch == '.' || ch == '_' || ch == '-';
           });
}

std::string require_client_name(std::string_view name) {
    if (!valid_name(name)) {
        throw SetupError(
            "client name must contain 1..63 letters, digits, '.', '_', or '-', "
            "and must begin with a letter or digit");
    }
    return std::string(name);
}

std::string require_node_name(std::string_view name) {
    if (!valid_name(name)) {
        throw SetupError(
            "node name must contain 1..63 letters, digits, '.', '_', or '-', "
            "and must begin and end with a letter or digit");
    }
    return std::string(name);
}

std::optional<std::string> canonical_ip(std::string_view text) {
    if (!config::v1::IsIpAddressLiteral(text)) return std::nullopt;
    const std::string input(text);
    std::array<unsigned char, 16> address{};
    std::array<char, INET6_ADDRSTRLEN> output{};
    const int family =
        input.find(':') == std::string::npos ? AF_INET : AF_INET6;
    if (::inet_pton(family, input.c_str(), address.data()) != 1 ||
        ::inet_ntop(family, address.data(), output.data(),
                    static_cast<socklen_t>(output.size())) == nullptr) {
        return std::nullopt;
    }
    return std::string(output.data());
}

std::string require_host(std::string_view host) {
    if (const auto ip = canonical_ip(host)) return *ip;
    if (!config::v1::IsEndpointHost(host)) {
        throw SetupError("host must be a valid IP literal or DNS name");
    }
    std::string lower(host);
    std::transform(lower.begin(), lower.end(), lower.begin(), [](char ch) {
        return ch >= 'A' && ch <= 'Z' ? static_cast<char>(ch - 'A' + 'a') : ch;
    });
    return lower;
}

void require_max_sessions(std::optional<std::int64_t> value) {
    if (value && (*value < 1 || static_cast<std::uint64_t>(*value) >
                                    runtime::kMaxSessionsPerIdentity)) {
        throw SetupError("max sessions must be in 1.." +
                         std::to_string(runtime::kMaxSessionsPerIdentity));
    }
}

void require_weight(std::optional<double> value) {
    using runtime::EgressLimiter;
    if (value &&
        !(std::isfinite(*value) && *value >= EgressLimiter::kMinWeight &&
          *value <= EgressLimiter::kMaxWeight)) {
        throw SetupError("weight must be in " +
                         format_bound(EgressLimiter::kMinWeight) + ".." +
                         format_bound(EgressLimiter::kMaxWeight));
    }
}

void require_max_egress_mbps(std::optional<std::int64_t> value) {
    if (value && (*value < 1 || *value > config::v1::kMaxEgressMbps)) {
        throw SetupError("max egress Mbps must be in 1.." +
                         std::to_string(config::v1::kMaxEgressMbps));
    }
}

Json read_json(const fs::path& path) {
    const auto bytes = read_bounded(path, kMaxJsonBytes);
    std::vector<std::set<std::string>> scopes;
    const Json::parser_callback_t guard = [&](int, Json::parse_event_t event,
                                              Json& value) {
        if (event == Json::parse_event_t::object_start) {
            scopes.emplace_back();
        } else if (event == Json::parse_event_t::object_end) {
            scopes.pop_back();
        } else if (event == Json::parse_event_t::key &&
                   !scopes.back().insert(value.get<std::string>()).second) {
            throw SetupError(path.string() + " contains a duplicate key: " +
                             value.get<std::string>());
        }
        return true;
    };
    try {
        return Json::parse(bytes.begin(), bytes.end(), guard);
    } catch (const Json::exception&) {
        throw SetupError(path.string() + " is not valid JSON");
    }
}

std::string json_text(const Json& value) {
    return value.dump(2, ' ', true) + "\n";
}

void write_json(const fs::path& path, const Json& value) {
    const auto text = json_text(value);
    write_new_file(path, as_bytes(text));
}

const std::vector<Preset>& presets() {
    static const std::vector<Preset> table = load_presets();
    return table;
}

const std::string& default_preset() {
    static const std::string name =
        Json::parse(std::string_view(kTuningPresetsJson))
            .at("default")
            .get<std::string>();
    return name;
}

const Preset* find_preset(std::string_view id) {
    const auto& table = presets();
    const auto found =
        std::find_if(table.begin(), table.end(),
                     [id](const Preset& preset) { return preset.id == id; });
    return found == table.end() ? nullptr : &*found;
}

fs::path config_reference(const fs::path& server, const Json& config,
                          std::string_view section, std::string_view key) {
    const std::string name(section);
    const std::string field(key);
    const Json* reference = nullptr;
    if (config.is_object() && config.contains(name) &&
        config.at(name).is_object() && config.at(name).contains(field)) {
        reference = &config.at(name).at(field);
    }
    if (reference == nullptr || !reference->is_object() ||
        !reference->contains("file") || !reference->at("file").is_string() ||
        reference->at("file").get<std::string>().empty()) {
        throw SetupError("server configuration lacks " + name + "." + field);
    }
    const fs::path path(reference->at("file").get<std::string>());
    return path.is_absolute() ? path : server / path;
}

Json read_server_config(const fs::path& server, const std::string& what) {
    auto config = read_json(server / "yumed.json");
    if (!config.is_object() || !config.contains("schema") ||
        config.at("schema") != 1 || !config.at("schema").is_number_integer() ||
        !config.contains("role") || config.at("role") != "server") {
        throw SetupError(what + " must hold a schema-1 server yumed.json");
    }
    return config;
}

}  // namespace yume::setup
