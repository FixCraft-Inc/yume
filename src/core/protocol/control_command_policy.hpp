/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

#include "core/protocol/control_protocol.hpp"

namespace yume::control {

// CONTROL frames can be as large as the authenticated data-frame ceiling, but
// command names and retained metadata are intentionally much smaller.  These
// limits bound both per-session legacy registration state and the manager's
// 512-entry lifecycle history.
inline constexpr std::size_t kMaxControlCommandBytes = 64U;
inline constexpr std::size_t kMaxLegacyHostnameBytes = 255U;
inline constexpr std::size_t kMaxLegacyIpBytes = 64U;
inline constexpr std::size_t kMaxLegacyRegistrationStringBytes = 280U;

inline constexpr std::size_t kMaxLifecycleMessageBytes = 256U;
inline constexpr std::size_t kMaxLifecycleDetailBytes = 1024U;
inline constexpr std::size_t kMaxLifecyclePlatformBytes = 16U;
inline constexpr std::size_t kMaxLifecycleVariantBytes = 32U;
inline constexpr std::size_t kMaxLifecycleVersionBytes = 128U;
inline constexpr std::size_t kMaxLifecycleProtectionBytes = 256U;
inline constexpr std::size_t kMaxLifecycleExitIpBytes = 64U;
inline constexpr std::size_t kMaxLifecycleErrorCodeBytes = 64U;
inline constexpr std::size_t kMaxLifecycleAggregateStringBytes = 1536U;

struct LegacyControlRegistration {
    std::string hostname;
    std::string wan_ip;
    bool server_in_charge{false};
    bool allow_exec{false};
};

// Command names are copied into logs and responses.  Validate the type and
// small printable representation before allocating that copy.
bool is_valid_control_command_name(std::string_view value) noexcept;

bool is_valid_lifecycle_state(std::string_view value) noexcept;

// Strict wire parsers reject unknown fields, implicit JSON conversions,
// control characters, invalid state/IP values, and every per-field or
// aggregate overrun.  They never throw on peer-controlled input.
std::optional<LegacyControlRegistration>
try_legacy_control_registration_from_json(
    const nlohmann::json& json,
    std::string* error = nullptr) noexcept;

std::optional<ClientLifecycleEvent> try_lifecycle_command_from_json(
    const nlohmann::json& json,
    std::string* error = nullptr) noexcept;

// Client emission uses the same policy as server admission so locally
// generated diagnostic text cannot create a frame that the server must reject
// or retain beyond its fixed budget.
std::optional<nlohmann::json> try_lifecycle_command_to_json(
    const ClientLifecycleEvent& event,
    std::string* error = nullptr) noexcept;

}  // namespace yume::control
