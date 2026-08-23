/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

#include "core/security/ratchet_policy.hpp"

namespace yume::config {

inline ratchet::SecurityProfileConfig ParseSecurityProfile(
    const nlohmann::json& config,
    ratchet::SecurityProfileConfig fallback = {}) {
    const auto read_u64 = [](const nlohmann::json& object,
                             const char* key) -> std::uint64_t {
        const auto& value = object.at(key);
        if (value.is_number_unsigned()) {
            return value.get<std::uint64_t>();
        }
        if (!value.is_number_integer()) {
            throw std::runtime_error(std::string(key) +
                                     " must be a non-negative integer");
        }
        const auto parsed = value.get<std::int64_t>();
        if (parsed < 0) {
            throw std::runtime_error(std::string(key) +
                                     " must be a non-negative integer");
        }
        return static_cast<std::uint64_t>(parsed);
    };

    if (config.contains("security_mode")) {
        if (!config["security_mode"].is_string()) {
            throw std::runtime_error("security_mode must be a string");
        }
        const auto mode = ratchet::ParseSecurityMode(
            config["security_mode"].get<std::string>());
        if (!mode.has_value()) {
            throw std::runtime_error(
                "security_mode must be extreme, normal, soft, or ultimate");
        }
        fallback.mode = *mode;
    }

    if (config.contains("security_custom")) {
        const auto& custom = config["security_custom"];
        if (!custom.is_object() || !custom.contains("epoch_bytes") ||
            !custom.contains("epoch_frames") ||
            !custom.contains("epoch_active_ms")) {
            throw std::runtime_error(
                "security_custom requires epoch_bytes, epoch_frames, and "
                "epoch_active_ms");
        }
        const std::uint64_t epoch_bytes = read_u64(custom, "epoch_bytes");
        const std::uint64_t epoch_frames = read_u64(custom, "epoch_frames");
        const std::uint64_t active_ms = read_u64(custom, "epoch_active_ms");
        const auto max_active_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                ratchet::kMaxEpochActiveLimit)
                .count();
        if (active_ms > static_cast<std::uint64_t>(max_active_ms)) {
            throw std::runtime_error("security_custom values are out of range");
        }
        ratchet::RatchetPolicy policy{
            epoch_bytes,
            epoch_frames,
            std::chrono::milliseconds(static_cast<std::int64_t>(active_ms)),
        };
        if (!ratchet::IsRatchetPolicyValid(policy)) {
            throw std::runtime_error(
                "security_custom values are out of range: epoch_bytes=" +
                std::to_string(policy.epoch_byte_limit) +
                ", epoch_frames=" +
                std::to_string(policy.epoch_frame_limit) +
                ", epoch_active_ms=" +
                std::to_string(policy.epoch_active_limit.count()));
        }
        fallback.custom_policy = policy;
    }

    if (!ratchet::ResolveSecurityProfile(fallback).has_value()) {
        throw std::runtime_error(
            "security_mode ultimate requires a valid security_custom object"
            " within the documented bounds");
    }
    return fallback;
}

inline void WriteSecurityProfile(nlohmann::json& config,
                                 const ratchet::SecurityProfileConfig& profile) {
    config["security_mode"] = ratchet::SecurityModeName(profile.mode);
    if (profile.custom_policy.has_value()) {
        const auto& policy = *profile.custom_policy;
        config["security_custom"] = {
            {"epoch_bytes", policy.epoch_byte_limit},
            {"epoch_frames", policy.epoch_frame_limit},
            {"epoch_active_ms", policy.epoch_active_limit.count()},
        };
    } else {
        config.erase("security_custom");
    }
}

}  // namespace yume::config
