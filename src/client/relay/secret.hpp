/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <filesystem>
#include <string>

#include <nlohmann/json.hpp>

namespace yume::client {

// Overwrites the complete currently-owned string buffer before clearing it.
// This is best-effort ordinary-memory hygiene, not a locked-page allocator.
void wipe_relay_secret(std::string& value) noexcept;

// Scope guard for password-derived strings and command lines that may contain
// an inline password. The referenced string must outlive the guard.
class RelaySecretWiper {
public:
    explicit RelaySecretWiper(std::string& value) noexcept : value_(value) {}
    RelaySecretWiper(const RelaySecretWiper&) = delete;
    RelaySecretWiper& operator=(const RelaySecretWiper&) = delete;
    ~RelaySecretWiper() { wipe_relay_secret(value_); }

private:
    std::string& value_;
};

// Best-effort erasure for JSON copies owned by YUME request plumbing. It
// recursively wipes string values below `password` and `relay_secret` keys;
// callers still own and must clear their original input buffers.
void wipe_relay_request_secrets(nlohmann::json& value) noexcept;

class RelayRequestSecretsWiper {
public:
    explicit RelayRequestSecretsWiper(nlohmann::json& value) noexcept
        : value_(value) {}
    RelayRequestSecretsWiper(const RelayRequestSecretsWiper&) = delete;
    RelayRequestSecretsWiper& operator=(
        const RelayRequestSecretsWiper&) = delete;
    ~RelayRequestSecretsWiper() { wipe_relay_request_secrets(value_); }

private:
    nlohmann::json& value_;
};

std::string derive_relay_secret_b64(const std::string& password);
bool validate_relay_secret_b64(const std::string& relay_secret_b64, std::string* error);
bool load_relay_secret_file(const std::filesystem::path& path,
                            std::string* relay_secret_b64,
                            std::string* error);
bool write_relay_secret_file(const std::filesystem::path& path,
                             const std::string& relay_secret_b64,
                             std::string* error);

}  // namespace yume::client
