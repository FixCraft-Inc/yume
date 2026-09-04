/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/protocol/control_command_policy.hpp"

#include <algorithm>
#include <array>
#include <exception>

#include <boost/asio/ip/address.hpp>
#include <boost/system/error_code.hpp>

#include "core/protocol/control_fields.hpp"
#include "core/protocol/directory_policy.hpp"

namespace yume::control {
namespace {

constexpr std::array<std::string_view, 5> kRegistrationFields{
    "cmd", fields::hostname, "wan_ip", "server_in_charge", "allow_exec",
};

constexpr std::array<std::string_view, 12> kLifecycleCommandFields{
    "cmd",
    "request_id",
    fields::state,
    fields::message,
    fields::detail,
    fields::client_platform,
    fields::client_variant,
    fields::client_version,
    fields::effective_protection,
    fields::traffic_verified,
    fields::exit_ip,
    fields::error_code,
};

void SetError(std::string* error, std::string_view message) noexcept {
    if (!error) return;
    try {
        error->assign(message);
    } catch (...) {
    }
}

template <std::size_t Size>
bool HasOnlyKnownFields(
    const nlohmann::json& json,
    const std::array<std::string_view, Size>& known) {
    if (!json.is_object() || json.size() > known.size()) return false;
    for (auto it = json.begin(); it != json.end(); ++it) {
        if (std::find(known.begin(), known.end(), it.key()) == known.end()) {
            return false;
        }
    }
    return true;
}

bool IsSafeText(std::string_view value,
                std::size_t max_bytes,
                bool allow_empty) noexcept {
    if (value.size() > max_bytes || (!allow_empty && value.empty())) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](unsigned char byte) {
        return byte >= 0x20U && byte != 0x7fU;
    });
}

bool OptionalString(const nlohmann::json& json,
                    const char* key,
                    std::size_t max_bytes,
                    bool allow_empty = true) {
    return !json.contains(key) ||
           (json[key].is_string() &&
            IsSafeText(json[key].get_ref<const std::string&>(), max_bytes,
                       allow_empty));
}

bool RequiredString(const nlohmann::json& json,
                    const char* key,
                    std::size_t max_bytes,
                    bool allow_empty) {
    return json.contains(key) && json[key].is_string() &&
           IsSafeText(json[key].get_ref<const std::string&>(), max_bytes,
                      allow_empty);
}

bool OptionalBool(const nlohmann::json& json, const char* key) {
    return !json.contains(key) || json[key].is_boolean();
}

bool IsKnownPlatform(std::string_view value) noexcept {
    return value == "linux" || value == "windows" || value == "macos" ||
           value == "android" || value == "unknown";
}

bool IsKnownVariant(std::string_view value) noexcept {
    return value == "cli" || value == "android_vpn" || value == "unknown";
}

bool IsIpAddressOrEmpty(std::string_view value) noexcept {
    if (value.empty()) return true;
    boost::system::error_code error;
    boost::asio::ip::make_address(value, error);
    return !error;
}

bool AddAccounted(std::string_view value,
                  std::size_t limit,
                  std::size_t* total) noexcept {
    if (!total || value.size() > limit - std::min(limit, *total)) {
        return false;
    }
    *total += value.size();
    return true;
}

bool AccountOptionalString(const nlohmann::json& json,
                           const char* key,
                           std::size_t limit,
                           std::size_t* total) {
    return !json.contains(key) ||
           AddAccounted(json[key].get_ref<const std::string&>(), limit,
                        total);
}

}  // namespace

bool is_valid_control_command_name(std::string_view value) noexcept {
    return IsSafeText(value, kMaxControlCommandBytes, false);
}

bool is_valid_lifecycle_state(std::string_view value) noexcept {
    return value == "connecting" || value == "authenticated" ||
           value == "traffic_flowing" || value == "disconnecting" ||
           value == "error";
}

std::optional<ControlRegistration>
try_control_registration_from_json(
    const nlohmann::json& json,
    std::string* error) noexcept {
    if (error) error->clear();
    try {
        if (!HasOnlyKnownFields(json, kRegistrationFields) ||
            !RequiredString(json, "cmd", kMaxControlCommandBytes, false) ||
            json["cmd"].get_ref<const std::string&>() != "register" ||
            !OptionalString(json, fields::hostname,
                            kMaxRegistrationHostnameBytes) ||
            !OptionalString(json, "wan_ip", kMaxRegistrationIpBytes) ||
            !OptionalBool(json, "server_in_charge") ||
            !OptionalBool(json, "allow_exec")) {
            SetError(error, "invalid registration fields");
            return std::nullopt;
        }
        const std::string_view hostname = json.contains(fields::hostname)
            ? std::string_view(
                  json[fields::hostname].get_ref<const std::string&>())
            : std::string_view{};
        const std::string_view wan_ip = json.contains("wan_ip")
            ? std::string_view(json["wan_ip"].get_ref<const std::string&>())
            : std::string_view{};
        if (!IsIpAddressOrEmpty(wan_ip) ||
            hostname.size() > kMaxRegistrationStringBytes -
                std::min(kMaxRegistrationStringBytes, wan_ip.size())) {
            SetError(error, "invalid registration address or size");
            return std::nullopt;
        }

        ControlRegistration registration;
        registration.hostname = hostname;
        registration.wan_ip = wan_ip;
        registration.server_in_charge =
            json.contains("server_in_charge") &&
            json["server_in_charge"].get<bool>();
        registration.allow_exec = json.contains("allow_exec") &&
                                  json["allow_exec"].get<bool>();
        return registration;
    } catch (const std::exception&) {
        SetError(error, "invalid registration fields");
        return std::nullopt;
    } catch (...) {
        SetError(error, "invalid registration fields");
        return std::nullopt;
    }
}

std::optional<ClientLifecycleEvent> try_lifecycle_command_from_json(
    const nlohmann::json& json,
    std::string* error) noexcept {
    if (error) error->clear();
    try {
        if (!HasOnlyKnownFields(json, kLifecycleCommandFields) ||
            !RequiredString(json, "cmd", kMaxControlCommandBytes, false) ||
            json["cmd"].get_ref<const std::string&>() !=
                "client.lifecycle" ||
            !RequiredString(json, fields::state, kMaxControlCommandBytes,
                            false) ||
            !RequiredString(json, fields::message,
                            kMaxLifecycleMessageBytes, false) ||
            !OptionalString(json, "request_id",
                            kMaxDirectoryRequestIdBytes, false) ||
            !OptionalString(json, fields::detail,
                            kMaxLifecycleDetailBytes) ||
            !OptionalString(json, fields::client_platform,
                            kMaxLifecyclePlatformBytes, false) ||
            !OptionalString(json, fields::client_variant,
                            kMaxLifecycleVariantBytes, false) ||
            !OptionalString(json, fields::client_version,
                            kMaxLifecycleVersionBytes) ||
            !OptionalString(json, fields::effective_protection,
                            kMaxLifecycleProtectionBytes) ||
            !OptionalBool(json, fields::traffic_verified) ||
            !OptionalString(json, fields::exit_ip,
                            kMaxLifecycleExitIpBytes) ||
            !OptionalString(json, fields::error_code,
                            kMaxLifecycleErrorCodeBytes)) {
            SetError(error, "invalid lifecycle fields");
            return std::nullopt;
        }

        const auto& state = json[fields::state].get_ref<const std::string&>();
        if (!is_valid_lifecycle_state(state)) {
            SetError(error, "invalid lifecycle state");
            return std::nullopt;
        }
        if (json.contains(fields::client_platform) &&
            !IsKnownPlatform(
                json[fields::client_platform].get_ref<const std::string&>())) {
            SetError(error, "invalid lifecycle platform");
            return std::nullopt;
        }
        if (json.contains(fields::client_variant) &&
            !IsKnownVariant(
                json[fields::client_variant].get_ref<const std::string&>())) {
            SetError(error, "invalid lifecycle variant");
            return std::nullopt;
        }
        if (json.contains(fields::exit_ip) &&
            !IsIpAddressOrEmpty(
                json[fields::exit_ip].get_ref<const std::string&>())) {
            SetError(error, "invalid lifecycle exit IP");
            return std::nullopt;
        }

        std::size_t accounted = 0;
        if (!AccountOptionalString(json, "request_id",
                                   kMaxLifecycleAggregateStringBytes,
                                   &accounted) ||
            !AddAccounted(state, kMaxLifecycleAggregateStringBytes,
                          &accounted) ||
            !AddAccounted(
                json[fields::message].get_ref<const std::string&>(),
                kMaxLifecycleAggregateStringBytes, &accounted) ||
            !AccountOptionalString(json, fields::detail,
                                   kMaxLifecycleAggregateStringBytes,
                                   &accounted) ||
            !AccountOptionalString(json, fields::client_platform,
                                   kMaxLifecycleAggregateStringBytes,
                                   &accounted) ||
            !AccountOptionalString(json, fields::client_variant,
                                   kMaxLifecycleAggregateStringBytes,
                                   &accounted) ||
            !AccountOptionalString(json, fields::client_version,
                                   kMaxLifecycleAggregateStringBytes,
                                   &accounted) ||
            !AccountOptionalString(json, fields::effective_protection,
                                   kMaxLifecycleAggregateStringBytes,
                                   &accounted) ||
            !AccountOptionalString(json, fields::exit_ip,
                                   kMaxLifecycleAggregateStringBytes,
                                   &accounted) ||
            !AccountOptionalString(json, fields::error_code,
                                   kMaxLifecycleAggregateStringBytes,
                                   &accounted)) {
            SetError(error, "lifecycle fields exceed aggregate size limit");
            return std::nullopt;
        }

        ClientLifecycleEvent event;
        event.state = state;
        event.message =
            json[fields::message].get_ref<const std::string&>();
        if (json.contains(fields::detail)) {
            event.detail = json[fields::detail].get<std::string>();
        }
        if (json.contains(fields::client_platform)) {
            event.client_platform =
                json[fields::client_platform].get<std::string>();
        }
        if (json.contains(fields::client_variant)) {
            event.client_variant =
                json[fields::client_variant].get<std::string>();
        }
        if (json.contains(fields::client_version)) {
            event.client_version =
                json[fields::client_version].get<std::string>();
        }
        if (json.contains(fields::effective_protection)) {
            event.effective_protection =
                json[fields::effective_protection].get<std::string>();
        }
        event.traffic_verified =
            json.contains(fields::traffic_verified) &&
            json[fields::traffic_verified].get<bool>();
        if (json.contains(fields::exit_ip)) {
            event.exit_ip = json[fields::exit_ip].get<std::string>();
        }
        if (json.contains(fields::error_code)) {
            event.error_code = json[fields::error_code].get<std::string>();
        }
        return event;
    } catch (const std::exception&) {
        SetError(error, "invalid lifecycle fields");
        return std::nullopt;
    } catch (...) {
        SetError(error, "invalid lifecycle fields");
        return std::nullopt;
    }
}

std::optional<nlohmann::json> try_lifecycle_command_to_json(
    const ClientLifecycleEvent& event,
    std::string* error) noexcept {
    if (error) error->clear();
    try {
        nlohmann::json json{
            {"cmd", "client.lifecycle"},
            {fields::state, event.state},
            {fields::message, event.message},
            {fields::detail, event.detail},
            {fields::client_platform, event.client_platform},
            {fields::client_variant, event.client_variant},
            {fields::client_version, event.client_version},
            {fields::effective_protection, event.effective_protection},
            {fields::traffic_verified, event.traffic_verified},
            {fields::exit_ip, event.exit_ip},
            {fields::error_code, event.error_code},
        };
        std::string validation_error;
        if (!try_lifecycle_command_from_json(json, &validation_error)) {
            SetError(error, validation_error.empty()
                                ? "invalid lifecycle event"
                                : validation_error);
            return std::nullopt;
        }
        return json;
    } catch (const std::exception&) {
        SetError(error, "failed to serialize lifecycle event");
        return std::nullopt;
    } catch (...) {
        SetError(error, "failed to serialize lifecycle event");
        return std::nullopt;
    }
}

}  // namespace yume::control
