/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "client/share_file.hpp"

#include <basefwx/fwxaes.hpp>
#include <nlohmann/json.hpp>

#include <array>
#include <cstring>
#include <stdexcept>

namespace yume::share {

namespace {

constexpr char     kMagic[]      = "YUMESHRE";
constexpr std::size_t kMagicLen  = 8;
constexpr std::size_t kHeaderLen = 12;  // magic + version + type + 2 reserved

nlohmann::json bundle_to_json(const ShareBundle& b) {
    nlohmann::json j;
    j["magic"] = "yume-share";
    j["version"] = static_cast<int>(kFormatVersion);
    j["type"] = (b.type == BundleType::Backup) ? "backup" : "unknown";
    if (!b.created_at_iso8601.empty()) j["created_at"] = b.created_at_iso8601;
    if (!b.created_by.empty())          j["created_by"] = b.created_by;
    if (!b.label.empty())               j["label"] = b.label;

    j["server"] = {
        {"host", b.server_host},
        {"port", b.server_port},
    };
    if (!b.auth_private_key_pem.empty()) {
        j["auth"] = nlohmann::json{{"private_key_pem", b.auth_private_key_pem}};
    }
    nlohmann::json stealth;
    stealth["obfuscation"] = b.obfuscation;
    if (!b.obfs_secret.empty())       stealth["obfs_secret"] = b.obfs_secret;
    if (b.obfs_pad_multiple > 0)      stealth["obfs_pad_multiple"] = b.obfs_pad_multiple;
    if (b.obfs_jitter_ms > 0)         stealth["obfs_jitter_ms"] = b.obfs_jitter_ms;
    if (!b.tls_pin_sha256.empty())    stealth["tls_pin_sha256"] = b.tls_pin_sha256;
    if (!b.tls_stealth_profile.empty()) stealth["tls_stealth_profile"] = b.tls_stealth_profile;
    j["stealth"] = stealth;

    if (!b.anonym_ca_cert_pem.empty() || !b.anonym_pubkey.empty()) {
        nlohmann::json anon;
        if (!b.anonym_ca_cert_pem.empty()) anon["ca_cert_pem"] = b.anonym_ca_cert_pem;
        if (!b.anonym_pubkey.empty())      anon["pubkey"]      = b.anonym_pubkey;
        j["anonym"] = anon;
    }
    if (!b.pq_public_key_pem.empty()) {
        j["pq"] = nlohmann::json{{"public_key_pem", b.pq_public_key_pem}};
    }

    j["client_settings"] = {
        {"inner_crypto", b.inner_crypto},
        {"inner_heavy",  b.inner_heavy},
        {"inner_hop",    b.inner_hop},
        {"hop_interval_ms", b.hop_interval_ms},
        {"allow_udp", b.allow_udp},
        {"allow_local_ip", b.allow_local_ip},
    };
    return j;
}

bool json_to_bundle(const nlohmann::json& j, ShareBundle* out, std::string* error) {
    auto fail = [&](const char* msg) {
        if (error) *error = msg;
        return false;
    };
    if (!j.is_object())                                       return fail("share bundle is not a JSON object");
    if (!j.contains("magic") || j["magic"] != "yume-share")   return fail("share bundle missing or wrong 'magic' field");
    if (!j.contains("server") || !j["server"].is_object())    return fail("share bundle missing 'server' object");

    const auto& server = j["server"];
    if (!server.contains("host") || !server["host"].is_string()) return fail("share bundle missing server.host");
    if (!server.contains("port") || !server["port"].is_number_integer()) return fail("share bundle missing server.port");
    out->server_host = server["host"].get<std::string>();
    out->server_port = server["port"].get<int>();
    if (out->server_host.empty() || out->server_port < 1 || out->server_port > 65535) {
        return fail("share bundle has invalid server endpoint");
    }

    auto type_str = j.value("type", std::string("backup"));
    out->type = (type_str == "backup") ? BundleType::Backup : BundleType::Backup;

    out->created_at_iso8601 = j.value("created_at", std::string{});
    out->created_by         = j.value("created_by", std::string{});
    out->label              = j.value("label", std::string{});

    if (j.contains("auth") && j["auth"].is_object()) {
        out->auth_private_key_pem = j["auth"].value("private_key_pem", std::string{});
    }

    if (j.contains("stealth") && j["stealth"].is_object()) {
        const auto& s = j["stealth"];
        out->obfuscation         = s.value("obfuscation", true);
        out->obfs_secret         = s.value("obfs_secret", std::string{});
        out->obfs_pad_multiple   = static_cast<std::uint16_t>(s.value("obfs_pad_multiple", 0));
        out->obfs_jitter_ms      = static_cast<std::uint32_t>(s.value("obfs_jitter_ms", 0));
        out->tls_pin_sha256      = s.value("tls_pin_sha256", std::string{});
        out->tls_stealth_profile = s.value("tls_stealth_profile", std::string{});
    }

    if (j.contains("anonym") && j["anonym"].is_object()) {
        out->anonym_ca_cert_pem = j["anonym"].value("ca_cert_pem", std::string{});
        out->anonym_pubkey      = j["anonym"].value("pubkey", std::string{});
    }
    if (j.contains("pq") && j["pq"].is_object()) {
        out->pq_public_key_pem = j["pq"].value("public_key_pem", std::string{});
    }

    if (j.contains("client_settings") && j["client_settings"].is_object()) {
        const auto& cs = j["client_settings"];
        out->inner_crypto    = cs.value("inner_crypto", true);
        out->inner_heavy     = cs.value("inner_heavy", true);
        out->inner_hop       = cs.value("inner_hop", true);
        out->hop_interval_ms = static_cast<std::uint32_t>(cs.value("hop_interval_ms", 500));
        out->allow_udp       = cs.value("allow_udp", false);
        out->allow_local_ip  = cs.value("allow_local_ip", false);
    }
    return true;
}

}  // namespace

std::vector<std::uint8_t> encode_share(const ShareBundle& bundle,
                                       const std::string& password,
                                       std::string* error) {
    if (password.empty()) {
        if (error) *error = "password must not be empty";
        return {};
    }
    if (bundle.server_host.empty() || bundle.server_port < 1 || bundle.server_port > 65535) {
        if (error) *error = "bundle missing valid server endpoint";
        return {};
    }
    if (bundle.type == BundleType::Backup && bundle.auth_private_key_pem.empty()) {
        if (error) *error = "backup bundle requires an auth private key";
        return {};
    }

    std::string serialised;
    try {
        serialised = bundle_to_json(bundle).dump();
    } catch (const std::exception& ex) {
        if (error) *error = std::string("serialise failed: ") + ex.what();
        return {};
    }

    std::vector<std::uint8_t> plaintext(serialised.begin(), serialised.end());
    std::vector<std::uint8_t> encrypted;
    try {
        encrypted = basefwx::fwxaes::EncryptRaw(plaintext, password);
    } catch (const std::exception& ex) {
        if (error) *error = std::string("encrypt failed: ") + ex.what();
        return {};
    }

    std::vector<std::uint8_t> out;
    out.reserve(kHeaderLen + encrypted.size());
    out.insert(out.end(), kMagic, kMagic + kMagicLen);
    out.push_back(kFormatVersion);
    out.push_back(static_cast<std::uint8_t>(bundle.type));
    out.push_back(0);
    out.push_back(0);
    out.insert(out.end(), encrypted.begin(), encrypted.end());
    return out;
}

bool peek_share_header(const std::vector<std::uint8_t>& blob, ShareFileHeader* out) {
    if (!out) return false;
    if (blob.size() < kHeaderLen) return false;
    if (std::memcmp(blob.data(), kMagic, kMagicLen) != 0) return false;
    out->version = blob[kMagicLen];
    if (out->version != kFormatVersion) return false;
    out->type = static_cast<BundleType>(blob[kMagicLen + 1]);
    return true;
}

std::optional<ShareBundle> decode_share(const std::vector<std::uint8_t>& blob,
                                        const std::string& password,
                                        std::string* error) {
    ShareFileHeader hdr{};
    if (!peek_share_header(blob, &hdr)) {
        if (error) *error = "not a yume-share file (bad magic or unsupported version)";
        return std::nullopt;
    }
    if (password.empty()) {
        if (error) *error = "password must not be empty";
        return std::nullopt;
    }

    std::vector<std::uint8_t> encrypted(blob.begin() + kHeaderLen, blob.end());
    std::vector<std::uint8_t> plaintext;
    try {
        plaintext = basefwx::fwxaes::DecryptRaw(encrypted, password);
    } catch (const std::exception& ex) {
        if (error) *error = std::string("decrypt failed (wrong password or corrupted file): ") + ex.what();
        return std::nullopt;
    }

    nlohmann::json j;
    try {
        j = nlohmann::json::parse(plaintext.begin(), plaintext.end());
    } catch (const std::exception& ex) {
        if (error) *error = std::string("payload is not JSON: ") + ex.what();
        return std::nullopt;
    }

    ShareBundle bundle;
    if (!json_to_bundle(j, &bundle, error)) {
        return std::nullopt;
    }
    return bundle;
}

}  // namespace yume::share
