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
#include "core/protocol/control_json_policy.hpp"
#include "core/protocol/directory_policy.hpp"

namespace yume::control {
namespace {

using json_policy::has_only_known_fields;
using json_policy::is_known_client_platform;
using json_policy::is_known_client_variant;
using json_policy::is_safe_text;
using json_policy::optional_bool;
using json_policy::optional_string;
using json_policy::required_string;
using json_policy::set_error;

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

bool is_ip_address_or_empty(const std::string& value) noexcept {
    if (value.empty()) return true;
    boost::system::error_code error;
    // Boost's string_view overload can allocate inside noexcept. Borrow the
    // validated JSON string's terminated storage so allocation failure stays
    // within the caller's exception boundary.
    boost::asio::ip::make_address(value.c_str(), error);
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
    return is_safe_text(value, kMaxControlCommandBytes, false);
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
        if (!has_only_known_fields(json, kRegistrationFields) ||
            !required_string(json, "cmd", kMaxControlCommandBytes, false) ||
            json["cmd"].get_ref<const std::string&>() != "register" ||
            !optional_string(json, fields::hostname,
                             kMaxRegistrationHostnameBytes) ||
            !optional_string(json, "wan_ip", kMaxRegistrationIpBytes) ||
            !optional_bool(json, "server_in_charge") ||
            !optional_bool(json, "allow_exec")) {
            set_error(error, "invalid registration fields");
            return std::nullopt;
        }
        const std::string empty;
        const std::string& hostname = json.contains(fields::hostname)
            ? json[fields::hostname].get_ref<const std::string&>() : empty;
        const std::string& wan_ip = json.contains("wan_ip")
            ? json["wan_ip"].get_ref<const std::string&>() : empty;
        if (!is_ip_address_or_empty(wan_ip) ||
            hostname.size() > kMaxRegistrationStringBytes -
                std::min(kMaxRegistrationStringBytes, wan_ip.size())) {
            set_error(error, "invalid registration address or size");
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
        set_error(error, "invalid registration fields");
        return std::nullopt;
    } catch (...) {
        set_error(error, "invalid registration fields");
        return std::nullopt;
    }
}

std::optional<ClientLifecycleEvent> try_lifecycle_command_from_json(
    const nlohmann::json& json,
    std::string* error) noexcept {
    if (error) error->clear();
    try {
        if (!has_only_known_fields(json, kLifecycleCommandFields) ||
            !required_string(json, "cmd", kMaxControlCommandBytes, false) ||
            json["cmd"].get_ref<const std::string&>() !=
                "client.lifecycle" ||
            !required_string(json, fields::state, kMaxControlCommandBytes,
                             false) ||
            !required_string(json, fields::message,
                             kMaxLifecycleMessageBytes, false) ||
            !optional_string(json, "request_id",
                             kMaxDirectoryRequestIdBytes, false) ||
            !optional_string(json, fields::detail,
                             kMaxLifecycleDetailBytes) ||
            !optional_string(json, fields::client_platform,
                             kMaxLifecyclePlatformBytes, false) ||
            !optional_string(json, fields::client_variant,
                             kMaxLifecycleVariantBytes, false) ||
            !optional_string(json, fields::client_version,
                             kMaxLifecycleVersionBytes) ||
            !optional_string(json, fields::effective_protection,
                             kMaxLifecycleProtectionBytes) ||
            !optional_bool(json, fields::traffic_verified) ||
            !optional_string(json, fields::exit_ip,
                             kMaxLifecycleExitIpBytes) ||
            !optional_string(json, fields::error_code,
                             kMaxLifecycleErrorCodeBytes)) {
            set_error(error, "invalid lifecycle fields");
            return std::nullopt;
        }

        const auto& state = json[fields::state].get_ref<const std::string&>();
        if (!is_valid_lifecycle_state(state)) {
            set_error(error, "invalid lifecycle state");
            return std::nullopt;
        }
        if (json.contains(fields::client_platform) &&
            !is_known_client_platform(
                json[fields::client_platform].get_ref<const std::string&>())) {
            set_error(error, "invalid lifecycle platform");
            return std::nullopt;
        }
        if (json.contains(fields::client_variant) &&
            !is_known_client_variant(
                json[fields::client_variant].get_ref<const std::string&>())) {
            set_error(error, "invalid lifecycle variant");
            return std::nullopt;
        }
        if (json.contains(fields::exit_ip) &&
            !is_ip_address_or_empty(
                json[fields::exit_ip].get_ref<const std::string&>())) {
            set_error(error, "invalid lifecycle exit IP");
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
            set_error(error, "lifecycle fields exceed aggregate size limit");
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
        set_error(error, "invalid lifecycle fields");
        return std::nullopt;
    } catch (...) {
        set_error(error, "invalid lifecycle fields");
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
            set_error(error, validation_error.empty()
                                ? "invalid lifecycle event"
                                : validation_error);
            return std::nullopt;
        }
        return json;
    } catch (const std::exception&) {
        set_error(error, "failed to serialize lifecycle event");
        return std::nullopt;
    } catch (...) {
        set_error(error, "failed to serialize lifecycle event");
        return std::nullopt;
    }
}

}  // namespace yume::control
