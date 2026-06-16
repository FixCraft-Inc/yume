/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "server/auth/auth.hpp"

#include <openssl/pem.h>
#include <openssl/sha.h>

#include <mutex>
#include <fstream>
#include <ctime>
#include <algorithm>
#include <sstream>
#include <stdexcept>

#include <nlohmann/json.hpp>

namespace yume::server {

namespace {

std::optional<bool> read_policy_bool(const nlohmann::json& entry, const char* key) {
    if (entry.contains("permissions") && entry["permissions"].is_object()) {
        const auto& permissions = entry["permissions"];
        if (permissions.contains(key) && permissions[key].is_boolean()) {
            return permissions[key].get<bool>();
        }
    }
    if (entry.contains(key) && entry[key].is_boolean()) {
        return entry[key].get<bool>();
    }
    return std::nullopt;
}

std::optional<std::uint32_t> read_policy_uint(const nlohmann::json& entry,
                                              const char* key,
                                              std::uint32_t min_value,
                                              std::uint32_t max_value) {
    const auto read_value = [&](const nlohmann::json& value) -> std::optional<std::uint32_t> {
        if (!value.is_number_unsigned() && !value.is_number_integer()) {
            return std::nullopt;
        }
        const auto parsed = value.get<std::int64_t>();
        if (parsed <= 0) {
            return min_value;
        }
        const auto clamped = std::clamp(static_cast<std::uint32_t>(parsed), min_value, max_value);
        return clamped;
    };

    if (entry.contains("permissions") && entry["permissions"].is_object()) {
        const auto& permissions = entry["permissions"];
        if (permissions.contains(key)) {
            return read_value(permissions[key]);
        }
    }
    if (entry.contains(key)) {
        return read_value(entry[key]);
    }
    return std::nullopt;
}

}  // namespace

bool AuthKeyPolicy::empty() const {
    return !allow_exec.has_value() &&
           !allow_local_ip.has_value() &&
           !control_full.has_value() &&
           !allow_inbound_admin.has_value() &&
           !allow_outbound_admin.has_value() &&
           !allow_chat.has_value() &&
           !allow_file.has_value() &&
           !allow_bytes.has_value() &&
           !priority.has_value() &&
           federation_peer_id.empty();
}

std::vector<crypto::Bytes> load_authorized_keys(const std::string& path) {
    std::vector<crypto::Bytes> keys;
    if (path.empty()) {
        return keys;
    }

    BIO* bio = BIO_new_file(path.c_str(), "r");
    if (!bio) {
        throw std::runtime_error("failed to open authorized_keys");
    }

    while (true) {
        EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        if (!key) {
            break;
        }
        int len = i2d_PUBKEY(key, nullptr);
        if (len > 0) {
            crypto::Bytes der(static_cast<size_t>(len));
            unsigned char* p = der.data();
            i2d_PUBKEY(key, &p);
            keys.push_back(std::move(der));
        }
        EVP_PKEY_free(key);
    }
    BIO_free(bio);

    return keys;
}

AuthKeyPolicyMap load_auth_policies(const std::string& meta_path) {
    AuthKeyPolicyMap policies;
    if (meta_path.empty()) {
        return policies;
    }

    std::ifstream in(meta_path);
    if (!in) {
        return policies;
    }

    nlohmann::json meta = nlohmann::json::object();
    try {
        in >> meta;
    } catch (const std::exception& ex) {
        throw std::runtime_error(std::string("failed to parse auth_keys_meta: ") + ex.what());
    }
    if (!meta.is_object()) {
        throw std::runtime_error("auth_keys_meta root must be an object");
    }

    for (auto it = meta.begin(); it != meta.end(); ++it) {
        if (!it.value().is_object()) {
            continue;
        }
        AuthKeyPolicy policy;
        policy.allow_exec = read_policy_bool(it.value(), "allow_exec");
        policy.allow_local_ip = read_policy_bool(it.value(), "allow_local_ip");
        policy.control_full = read_policy_bool(it.value(), "control_full");
        policy.allow_inbound_admin = read_policy_bool(it.value(), "allow_inbound_admin");
        policy.allow_outbound_admin = read_policy_bool(it.value(), "allow_outbound_admin");
        policy.allow_chat = read_policy_bool(it.value(), "allow_chat");
        policy.allow_file = read_policy_bool(it.value(), "allow_file");
        policy.allow_bytes = read_policy_bool(it.value(), "allow_bytes");
        policy.priority = read_policy_uint(it.value(), "priority", 1, 100);
        if (it.value().contains("federation_peer_id") && it.value()["federation_peer_id"].is_string()) {
            policy.federation_peer_id = it.value()["federation_peer_id"].get<std::string>();
        }
        if (!policy.empty()) {
            policies[it.key()] = std::move(policy);
        }
    }
    return policies;
}

bool is_authorized(EVP_PKEY* pubkey, const std::vector<crypto::Bytes>& authorized) {
    if (!pubkey) {
        return false;
    }
    int len = i2d_PUBKEY(pubkey, nullptr);
    if (len <= 0) {
        return false;
    }
    crypto::Bytes der(static_cast<size_t>(len));
    unsigned char* p = der.data();
    i2d_PUBKEY(pubkey, &p);

    for (const auto& allowed : authorized) {
        if (allowed == der) {
            return true;
        }
    }
    return false;
}

crypto::Bytes read_field(const crypto::Bytes& payload, size_t& offset) {
    if (offset + 2 > payload.size()) {
        throw std::runtime_error("auth payload truncated");
    }
    uint16_t len = static_cast<uint16_t>((payload[offset] << 8) | payload[offset + 1]);
    offset += 2;
    if (offset + len > payload.size()) {
        throw std::runtime_error("auth payload truncated");
    }
    crypto::Bytes out(payload.begin() + offset, payload.begin() + offset + len);
    offset += len;
    return out;
}

std::string fingerprint_pubkey(EVP_PKEY* pubkey) {
    if (!pubkey) {
        return "";
    }
    int len = i2d_PUBKEY(pubkey, nullptr);
    if (len <= 0) {
        return "";
    }
    crypto::Bytes der(static_cast<size_t>(len));
    unsigned char* p = der.data();
    i2d_PUBKEY(pubkey, &p);

    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};
    SHA256(der.data(), der.size(), hash);

    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(SHA256_DIGEST_LENGTH * 2);
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        out.push_back(kHex[(hash[i] >> 4) & 0xF]);
        out.push_back(kHex[hash[i] & 0xF]);
    }
    return out;
}

std::string summarize_auth_policy(const AuthKeyPolicy& policy) {
    std::vector<std::string> parts;
    auto append = [&](const char* key, const std::optional<bool>& value) {
        if (!value.has_value()) {
            return;
        }
        parts.emplace_back(std::string(key) + "=" + (*value ? "true" : "false"));
    };
    append("allow_exec", policy.allow_exec);
    append("allow_local_ip", policy.allow_local_ip);
    append("control_full", policy.control_full);
    append("allow_inbound_admin", policy.allow_inbound_admin);
    append("allow_outbound_admin", policy.allow_outbound_admin);
    append("allow_chat", policy.allow_chat);
    append("allow_file", policy.allow_file);
    append("allow_bytes", policy.allow_bytes);
    if (policy.priority.has_value()) {
        parts.emplace_back("priority=" + std::to_string(*policy.priority));
    }
    if (!policy.federation_peer_id.empty()) {
        parts.emplace_back("federation_peer_id=" + policy.federation_peer_id);
    }

    std::ostringstream out;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) {
            out << ",";
        }
        out << parts[i];
    }
    return out.str();
}

void update_auth_meta(const std::string& meta_path, const std::string& fingerprint, const std::string& alias) {
    if (meta_path.empty() || fingerprint.empty()) {
        return;
    }
    static std::mutex meta_mutex;
    std::lock_guard<std::mutex> lock(meta_mutex);

    nlohmann::json meta = nlohmann::json::object();
    std::ifstream in(meta_path);
    if (in) {
        try {
            in >> meta;
        } catch (...) {
            meta = nlohmann::json::object();
        }
    }
    nlohmann::json entry = meta.value(fingerprint, nlohmann::json::object());
    if (!alias.empty()) {
        entry["alias"] = alias;
    }
    entry["last_seen"] = static_cast<long long>(std::time(nullptr));
    meta[fingerprint] = entry;

    std::ofstream out(meta_path);
    out << meta.dump(2);
}

}  // namespace yume::server
