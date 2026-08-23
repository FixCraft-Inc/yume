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
#include <filesystem>
#include <ctime>
#include <algorithm>
#include <cmath>
#include <sstream>
#include <stdexcept>

#include <nlohmann/json.hpp>

#include "core/app_codec/builtin/monero_rpc.hpp"
#include "core/app_codec/codec.hpp"
#include "core/runtime/atomic_file.hpp"
#include "core/runtime/file_transaction_lock.hpp"
#include "server/auth/auth_metadata_json.hpp"
#include "server/federation/types.hpp"

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
    const auto read_value = [&](const nlohmann::json& value) {
        std::uint64_t parsed = 0;
        if (value.is_number_unsigned()) {
            parsed = value.get<std::uint64_t>();
        } else if (value.is_number_integer()) {
            const auto signed_value = value.get<std::int64_t>();
            if (signed_value < 0) {
                throw std::runtime_error(
                    std::string("auth key policy ") + key + " must be in " +
                    std::to_string(min_value) + ".." +
                    std::to_string(max_value));
            }
            parsed = static_cast<std::uint64_t>(signed_value);
        } else {
            throw std::runtime_error(
                std::string("auth key policy ") + key + " must be an integer");
        }
        if (parsed < min_value || parsed > max_value) {
            throw std::runtime_error(
                std::string("auth key policy ") + key + " must be in " +
                std::to_string(min_value) + ".." +
                std::to_string(max_value));
        }
        return std::optional<std::uint32_t>(
            static_cast<std::uint32_t>(parsed));
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
    std::uint64_t value = 0;
    if (it->is_number_unsigned()) {
        value = it->get<std::uint64_t>();
    } else {
        const auto signed_value = it->get<std::int64_t>();
        if (signed_value <= 0) {
            throw std::runtime_error(
                "auth key policy max_sessions must be in 1..65535");
        }
        value = static_cast<std::uint64_t>(signed_value);
    }
    if (value == 0 || value > 65535) {
        throw std::runtime_error("auth key policy max_sessions must be in 1..65535");
    }
    return static_cast<std::uint32_t>(value);
}

void RejectAdminPrivilegeInVisitorStore(const AuthKeyPolicy& policy,
                                        const std::string& fingerprint) {
    // Admin is no longer expressible as a flag on a visitor key. It requires a
    // second, distinct key from the separate admin store, proven by its own
    // signature over the AUTH transcript.
    //
    // This throws rather than clearing the flag, and it applies to Individual
    // keys as well as Bulk. Silently downgrading would leave an operator
    // believing a key is privileged when it is not -- which is the mirror of the
    // failure this whole design exists to prevent. A loud refusal at startup is
    // the only safe reading of an admin flag in the wrong file.
    if (policy.allow_inbound_admin.value_or(false) ||
        policy.allow_outbound_admin.value_or(false) ||
        policy.control_full.value_or(false)) {
        throw std::runtime_error(
            "auth key policy for " + fingerprint +
            " grants admin or full control, which visitor keys can no longer "
            "carry. Admin now requires a second key listed in --admin-keys; "
            "remove allow_inbound_admin / allow_outbound_admin / control_full "
            "from this file and enrol the operator's admin key instead");
    }
}

void validate_key_policy(const AuthKeyPolicy& policy,
                         const std::string& fingerprint = "<key>") {
    RejectAdminPrivilegeInVisitorStore(policy, fingerprint);
    if (!policy.federation_peer_id.empty() &&
        !is_valid_federation_peer_id(policy.federation_peer_id)) {
        throw std::runtime_error(
            "federation_peer_id must be 1-64 ASCII letters, digits, '.', "
            "'_', or '-' (':' is reserved for visible endpoint IDs)");
    }
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

namespace {

bool is_pem_whitespace(char value) {
    return value == ' ' || value == '\t' || value == '\r' || value == '\n';
}

std::optional<crypto::Bytes> take_public_pem_block(
    std::string_view contents, std::size_t& cursor, const char* what) {
    while (cursor < contents.size() && is_pem_whitespace(contents[cursor])) {
        ++cursor;
    }
    if (cursor == contents.size()) return std::nullopt;

    static constexpr std::string_view kBegin = "-----BEGIN PUBLIC KEY-----";
    static constexpr std::string_view kEnd = "-----END PUBLIC KEY-----";
    if (!contents.substr(cursor).starts_with(kBegin)) {
        throw std::runtime_error(std::string(what) +
                                 " contains non-PEM or malformed data");
    }
    const std::size_t start = cursor;
    const std::size_t end_start = contents.find(kEnd, cursor + kBegin.size());
    if (end_start == std::string_view::npos) {
        throw std::runtime_error(std::string(what) +
                                 " contains an unterminated public-key PEM block");
    }
    cursor = end_start + kEnd.size();
    if (cursor < contents.size() && !is_pem_whitespace(contents[cursor])) {
        throw std::runtime_error(std::string(what) +
                                 " contains trailing data after a PEM block");
    }
    return crypto::Bytes(contents.begin() + static_cast<std::ptrdiff_t>(start),
                         contents.begin() + static_cast<std::ptrdiff_t>(cursor));
}

// Reads composite identities from a PEM file. Each identity is two consecutive
// blocks -- Ed25519 then ML-DSA-87 -- stored as one canonical blob so the pair
// is matched atomically. A trailing odd block is an error rather than a
// silently ignored line: a half-written identity in an authorized-keys file
// should stop the server, not quietly authorize nothing.
std::vector<crypto::Bytes> load_composite_store(const std::string& path,
                                                const char* what) {
    std::vector<crypto::Bytes> keys;
    if (path.empty()) return keys;

    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        throw std::runtime_error(std::string("failed to open ") + what);
    }
    constexpr std::streamoff kMaximumStoreBytes = 64 * 1024 * 1024;
    const std::streamoff size = input.tellg();
    if (size < 0 || size > kMaximumStoreBytes) {
        throw std::runtime_error(std::string(what) + " is too large");
    }
    std::string contents(static_cast<std::size_t>(size), '\0');
    input.seekg(0);
    if (size != 0 &&
        !input.read(contents.data(), static_cast<std::streamsize>(size))) {
        throw std::runtime_error(std::string("failed to read ") + what);
    }

    std::size_t cursor = 0;
    while (true) {
        auto classical = take_public_pem_block(contents, cursor, what);
        if (!classical.has_value()) break;
        auto pq = take_public_pem_block(contents, cursor, what);
        if (!pq.has_value()) {
            throw std::runtime_error(
                std::string(what) +
                " contains an incomplete composite identity: every entry must be "
                "an Ed25519 public key followed by an ML-DSA-87 public key");
        }

        crypto::Bytes bundle = std::move(*classical);
        bundle.push_back('\n');
        bundle.insert(bundle.end(), pq->begin(), pq->end());
        crypto::CompositePublicKey composite =
            crypto::parse_composite_identity(bundle);
        if (!composite.valid()) {
            throw std::runtime_error(
                std::string(what) +
                ": every entry must be an Ed25519 public key followed by an "
                "ML-DSA-87 public key");
        }
        keys.push_back(crypto::composite_canonical_encoding(composite));
    }
    return keys;
}

}  // namespace

std::vector<crypto::Bytes> load_authorized_keys(const std::string& path) {
    return load_composite_store(path, "authorized_keys");
}

std::vector<crypto::Bytes> load_admin_keys(const std::string& path) {
    return load_composite_store(path, "admin_keys");
}

bool is_composite_authorized(const crypto::CompositePublicKey& key,
                             const std::vector<crypto::Bytes>& authorized) {
    if (!key.valid()) return false;
    const crypto::Bytes canonical = crypto::composite_canonical_encoding(key);
    if (canonical.empty()) return false;
    // Constant work per entry; the comparison is over public data, so a plain
    // equality check is fine here.
    for (const auto& allowed : authorized) {
        if (allowed == canonical) return true;
    }
    return false;
}

AuthKeyPolicyMap load_auth_policies(const std::string& meta_path) {
    std::lock_guard<std::mutex> lock(auth_meta_file_mutex);
    AuthKeyPolicyMap policies;
    if (meta_path.empty()) {
        return policies;
    }

    constexpr std::uintmax_t kMaximumMetadataBytes =
        16U * 1024U * 1024U;
    std::error_code status_error;
    const bool exists = std::filesystem::exists(meta_path, status_error);
    if (status_error) {
        throw std::runtime_error(
            "failed to inspect auth_keys_meta: " + status_error.message());
    }
    if (!exists) {
        return policies;
    }
    const auto size = std::filesystem::file_size(meta_path, status_error);
    if (status_error) {
        throw std::runtime_error(
            "failed to inspect auth_keys_meta size: " +
            status_error.message());
    }
    if (size > kMaximumMetadataBytes) {
        throw std::runtime_error("auth_keys_meta exceeds 16 MiB");
    }

    std::ifstream in(meta_path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open auth_keys_meta");
    }

    nlohmann::json meta = nlohmann::json::object();
    try {
        in >> meta;
    } catch (const std::exception& ex) {
        throw std::runtime_error(std::string("failed to parse auth_keys_meta: ") + ex.what());
    }
    if (in.bad()) {
        throw std::runtime_error("failed to finish reading auth_keys_meta");
    }
    if (!meta.is_object()) {
        throw std::runtime_error("auth_keys_meta root must be an object");
    }
    std::string validation_error;
    if (!validate_auth_metadata_json_types(meta, &validation_error)) {
        throw std::runtime_error(validation_error);
    }

    for (auto it = meta.begin(); it != meta.end(); ++it) {
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

bool update_auth_meta(const std::string& meta_path,
                      const std::string& fingerprint,
                      const std::string& alias,
                      std::string* error) {
    if (error) error->clear();
    if (meta_path.empty() || fingerprint.empty()) {
        return true;
    }
    runtime::FileTransactionLock transaction_lock;
    if (!transaction_lock.Acquire({meta_path}, error)) return false;

    // Validate semantic policy state before taking the in-process reader lock.
    // The lock order is always file transaction -> auth_meta_file_mutex, which
    // avoids deadlock with CLI/facade writers that validate policies while
    // holding the same sidecar lock.
    try {
        (void)load_auth_policies(meta_path);
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }

    std::lock_guard<std::mutex> lock(auth_meta_file_mutex);

    nlohmann::json meta = nlohmann::json::object();
    std::error_code status_error;
    const bool exists = std::filesystem::exists(meta_path, status_error);
    if (status_error) {
        if (error) {
            *error = "cannot inspect auth metadata '" + meta_path + "': " +
                     status_error.message();
        }
        return false;
    }
    if (exists) {
        constexpr std::uintmax_t kMaximumMetadataBytes =
            16U * 1024U * 1024U;
        const auto size = std::filesystem::file_size(meta_path, status_error);
        if (status_error || size > kMaximumMetadataBytes) {
            if (error) {
                *error = status_error
                             ? "cannot inspect auth metadata size: " +
                                   status_error.message()
                             : "auth metadata file is too large";
            }
            return false;
        }
        std::ifstream in(meta_path, std::ios::binary);
        if (!in) {
            if (error) *error = "cannot open auth metadata: " + meta_path;
            return false;
        }
        try {
            in >> meta;
        } catch (const std::exception& ex) {
            if (error) {
                *error = "cannot parse auth metadata '" + meta_path +
                         "': " + ex.what();
            }
            return false;
        }
        if (in.bad()) {
            if (error) *error = "cannot finish reading auth metadata: " + meta_path;
            return false;
        }
        if (!validate_auth_metadata_json_types(meta, error)) return false;
    }
    nlohmann::json entry = meta.value(fingerprint, nlohmann::json::object());
    if (!alias.empty()) {
        entry["alias"] = alias;
    }
    entry["last_seen"] = static_cast<long long>(std::time(nullptr));
    meta[fingerprint] = entry;

    std::string serialized;
    try {
        serialized = meta.dump(2);
    } catch (const std::exception& ex) {
        if (error) *error = std::string("cannot serialize auth metadata: ") + ex.what();
        return false;
    }
    return runtime::AtomicWriteFile(
        meta_path, serialized, error,
        runtime::ParentDirectoryPolicy::Create);
}

}  // namespace yume::server
