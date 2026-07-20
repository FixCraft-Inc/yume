/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/auth/auth.hpp"

#include <openssl/pem.h>
#include <openssl/sha.h>

#include <mutex>
#include <fstream>
#include <ctime>
#include <algorithm>
#include <cmath>
#include <sstream>
#include <stdexcept>

#include <nlohmann/json.hpp>

#include "core/app_codec/builtin/monero_rpc.hpp"
#include "core/app_codec/codec.hpp"

namespace yume::server {

namespace {

std::mutex auth_meta_file_mutex;

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

AuthKeyType read_key_type(const nlohmann::json& entry) {
    const auto it = entry.find("key_type");
    if (it == entry.end()) {
        return AuthKeyType::Individual;
    }
    if (!it->is_string()) {
        throw std::runtime_error("auth key policy key_type must be 'individual' or 'bulk'");
    }
    const std::string value = it->get<std::string>();
    if (value == "individual") {
        return AuthKeyType::Individual;
    }
    if (value == "bulk") {
        return AuthKeyType::Bulk;
    }
    throw std::runtime_error("auth key policy key_type must be 'individual' or 'bulk'");
}

std::optional<double> read_policy_weight(const nlohmann::json& entry) {
    const auto it = entry.find("weight");
    if (it == entry.end()) {
        return std::nullopt;
    }
    if (!it->is_number()) {
        throw std::runtime_error("auth key policy weight must be a number in 0.1..100");
    }
    const double value = it->get<double>();
    if (!std::isfinite(value) || value < 0.1 || value > 100.0) {
        throw std::runtime_error("auth key policy weight must be in 0.1..100");
    }
    return value;
}

std::optional<std::uint32_t> read_policy_max_sessions(const nlohmann::json& entry) {
    const auto it = entry.find("max_sessions");
    if (it == entry.end()) {
        return std::nullopt;
    }
    if (!it->is_number_integer() && !it->is_number_unsigned()) {
        throw std::runtime_error("auth key policy max_sessions must be a positive integer");
    }
    const auto value = it->get<std::int64_t>();
    if (value <= 0 || value > 65535) {
        throw std::runtime_error("auth key policy max_sessions must be in 1..65535");
    }
    return static_cast<std::uint32_t>(value);
}

void validate_key_policy(const AuthKeyPolicy& policy) {
    if (policy.key_type == AuthKeyType::Individual &&
        policy.max_sessions.value_or(1) != 1) {
        throw std::runtime_error(
            "individual auth key max_sessions must be 1; use key_type 'bulk' for sharing");
    }
    if (policy.key_type != AuthKeyType::Bulk) {
        return;
    }
    if (policy.allow_exec.value_or(false) ||
        policy.allow_local_ip.value_or(false) ||
        policy.control_full.value_or(false) ||
        policy.allow_monero_rpc.value_or(false) ||
        !policy.allowed_codecs.empty() ||
        !policy.allowed_services.empty() ||
        policy.allow_inbound_admin.value_or(false) ||
        policy.allow_outbound_admin.value_or(false) ||
        !policy.federation_peer_id.empty()) {
        throw std::runtime_error(
            "bulk auth keys cannot grant exec, local-ip, full-control, codec, service, admin, or federation privileges");
    }
}

void read_policy_codecs(const nlohmann::json& entry, std::vector<std::string>* out) {
    if (!out) {
        return;
    }
    auto read_array = [&](const nlohmann::json& value) {
        if (!value.is_array()) {
            return;
        }
        for (const auto& item : value) {
            if (!item.is_string()) {
                continue;
            }
            const std::string codec = app_codec::canonical_codec_id(item.get<std::string>());
            if (app_codec::is_supported_codec(codec)) {
                app_codec::add_codec_unique(out, codec);
            }
        }
    };
    if (entry.contains("permissions") && entry["permissions"].is_object()) {
        const auto& permissions = entry["permissions"];
        if (permissions.contains("allow_codecs")) {
            read_array(permissions["allow_codecs"]);
        }
        if (permissions.contains("codec_allow")) {
            read_array(permissions["codec_allow"]);
        }
    }
    if (entry.contains("allow_codecs")) {
        read_array(entry["allow_codecs"]);
    }
    if (entry.contains("codec_allow")) {
        read_array(entry["codec_allow"]);
    }
}

void read_policy_strings(const nlohmann::json& entry,
                         const char* key,
                         std::vector<std::string>* out) {
    if (!out) {
        return;
    }
    auto read_array = [&](const nlohmann::json& value) {
        if (!value.is_array()) {
            return;
        }
        for (const auto& item : value) {
            if (!item.is_string()) {
                continue;
            }
            const std::string value_text = item.get<std::string>();
            if (value_text.empty() ||
                std::find(out->begin(), out->end(), value_text) != out->end()) {
                continue;
            }
            out->push_back(value_text);
        }
    };
    if (entry.contains("permissions") && entry["permissions"].is_object()) {
        const auto& permissions = entry["permissions"];
        if (permissions.contains(key)) {
            read_array(permissions[key]);
        }
    }
    if (entry.contains(key)) {
        read_array(entry[key]);
    }
}

}  // namespace

bool AuthKeyPolicy::empty() const {
    return !allow_exec.has_value() &&
           !allow_local_ip.has_value() &&
           !control_full.has_value() &&
           !allow_monero_rpc.has_value() &&
           allowed_codecs.empty() &&
           allowed_services.empty() &&
           !allow_inbound_admin.has_value() &&
           !allow_outbound_admin.has_value() &&
           !allow_chat.has_value() &&
           !allow_file.has_value() &&
           !allow_bytes.has_value() &&
           !priority.has_value() &&
           !weight.has_value() &&
           !max_sessions.has_value() &&
           key_type == AuthKeyType::Individual &&
           federation_peer_id.empty();
}

double AuthKeyPolicy::effective_weight() const {
    if (weight.has_value()) {
        return *weight;
    }
    if (priority.has_value()) {
        return std::clamp(static_cast<double>(*priority) / 50.0, 0.1, 100.0);
    }
    return 1.0;
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
    std::lock_guard<std::mutex> lock(auth_meta_file_mutex);
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
        policy.allow_monero_rpc = read_policy_bool(it.value(), "allow_monero_rpc");
        read_policy_codecs(it.value(), &policy.allowed_codecs);
        read_policy_strings(it.value(), "allow_services", &policy.allowed_services);
        if (policy.allow_monero_rpc.value_or(false)) {
            app_codec::add_codec_unique(&policy.allowed_codecs, app_codec::builtin::kMoneroRpcCodecId);
        }
        policy.allow_inbound_admin = read_policy_bool(it.value(), "allow_inbound_admin");
        policy.allow_outbound_admin = read_policy_bool(it.value(), "allow_outbound_admin");
        policy.allow_chat = read_policy_bool(it.value(), "allow_chat");
        policy.allow_file = read_policy_bool(it.value(), "allow_file");
        policy.allow_bytes = read_policy_bool(it.value(), "allow_bytes");
        policy.priority = read_policy_uint(it.value(), "priority", 1, 100);
        policy.weight = read_policy_weight(it.value());
        policy.max_sessions = read_policy_max_sessions(it.value());
        policy.key_type = read_key_type(it.value());
        if (it.value().contains("federation_peer_id") && it.value()["federation_peer_id"].is_string()) {
            policy.federation_peer_id = it.value()["federation_peer_id"].get<std::string>();
        }
        validate_key_policy(policy);
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

const char* auth_key_type_name(AuthKeyType type) {
    switch (type) {
        case AuthKeyType::Individual:
            return "individual";
        case AuthKeyType::Bulk:
            return "bulk";
    }
    return "individual";
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
    append("allow_monero_rpc", policy.allow_monero_rpc);
    if (!policy.allowed_codecs.empty()) {
        std::ostringstream joined;
        for (std::size_t i = 0; i < policy.allowed_codecs.size(); ++i) {
            if (i > 0) {
                joined << ',';
            }
            joined << policy.allowed_codecs[i];
        }
        parts.emplace_back("allow_codecs=" + joined.str());
    }
    if (!policy.allowed_services.empty()) {
        std::ostringstream joined;
        for (std::size_t i = 0; i < policy.allowed_services.size(); ++i) {
            if (i > 0) {
                joined << ',';
            }
            joined << policy.allowed_services[i];
        }
        parts.emplace_back("allow_services=" + joined.str());
    }
    append("allow_inbound_admin", policy.allow_inbound_admin);
    append("allow_outbound_admin", policy.allow_outbound_admin);
    append("allow_chat", policy.allow_chat);
    append("allow_file", policy.allow_file);
    append("allow_bytes", policy.allow_bytes);
    if (policy.priority.has_value()) {
        parts.emplace_back("priority=" + std::to_string(*policy.priority));
    }
    if (policy.weight.has_value()) {
        std::ostringstream value;
        value << *policy.weight;
        parts.emplace_back("weight=" + value.str());
    }
    if (policy.max_sessions.has_value()) {
        parts.emplace_back("max_sessions=" + std::to_string(*policy.max_sessions));
    }
    if (policy.key_type != AuthKeyType::Individual) {
        parts.emplace_back(std::string("key_type=") + auth_key_type_name(policy.key_type));
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
    std::lock_guard<std::mutex> lock(auth_meta_file_mutex);

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
