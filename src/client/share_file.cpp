/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "client/share_file.hpp"

#include <basefwx/fwxaes.hpp>
#include <nlohmann/json.hpp>

#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <stdexcept>

#ifndef _WIN32
#include <sys/stat.h>
#endif

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
    // We don't require an auth key here — both full backups (with
    // private key) and info-only bundles (server connection + CA +
    // obfs secret, no key) are valid. The downstream importer
    // surfaces "no auth key in this bundle, you'll need to add one"
    // in its summary UI; the operator decides what's acceptable.

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

namespace {
std::string slurp_text_file(const std::string& path, std::string* error) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        if (error) *error = "cannot open " + path;
        return {};
    }
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

bool write_file_owner_only(const std::string& path,
                           const std::vector<std::uint8_t>& data,
                           std::string* error) {
#ifndef _WIN32
    const mode_t prior = ::umask(0077);
#endif
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
#ifndef _WIN32
    ::umask(prior);
#endif
    if (!f) {
        if (error) *error = "cannot write " + path;
        return false;
    }
    if (!data.empty()) {
        f.write(reinterpret_cast<const char*>(data.data()),
                static_cast<std::streamsize>(data.size()));
    }
    if (!f) {
        if (error) *error = "write failed: " + path;
        return false;
    }
    f.close();
#ifndef _WIN32
    (void)::chmod(path.c_str(), 0600);
#endif
    return true;
}
}  // namespace

bool build_backup_bundle(const BackupInputs& in, ShareBundle* out, std::string* error) {
    if (!out) {
        if (error) *error = "build_backup_bundle: out is null";
        return false;
    }
    if (in.server_host.empty() || in.server_port < 1 || in.server_port > 65535) {
        if (error) *error = "server endpoint missing or invalid";
        return false;
    }
    // identity_path may be empty for an info-only bundle (Android's
    // current export mode). build_backup_bundle just won't populate
    // auth_private_key_pem in that case.
    std::string err;
    out->type = BundleType::Backup;
    {
        using namespace std::chrono;
        auto now = system_clock::now();
        std::time_t t = system_clock::to_time_t(now);
        std::tm tm{};
#ifdef _WIN32
        gmtime_s(&tm, &t);
#else
        gmtime_r(&t, &tm);
#endif
        char buf[32]{};
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
        out->created_at_iso8601 = buf;
    }
    out->created_by = in.created_by;
    out->label      = in.label;
    out->server_host = in.server_host;
    out->server_port = in.server_port;

    if (!in.identity_path.empty()) {
        out->auth_private_key_pem = slurp_text_file(in.identity_path, &err);
        if (out->auth_private_key_pem.empty()) {
            if (error) *error = "auth identity: " + err;
            return false;
        }
    }
    if (!in.anonym_ca_cert_path.empty()) {
        std::string ca = slurp_text_file(in.anonym_ca_cert_path, &err);
        if (!ca.empty()) out->anonym_ca_cert_pem = std::move(ca);
        // missing CA is non-fatal — the caller may not have configured one
    }
    if (!in.pq_public_key_path.empty()) {
        std::string pq = slurp_text_file(in.pq_public_key_path, &err);
        if (!pq.empty()) out->pq_public_key_pem = std::move(pq);
    }

    out->obfuscation         = in.obfuscation;
    out->obfs_secret         = in.obfs_secret;
    out->obfs_pad_multiple   = in.obfs_pad_multiple;
    out->obfs_jitter_ms      = in.obfs_jitter_ms;
    out->tls_pin_sha256      = in.tls_pin_sha256;
    out->tls_stealth_profile = in.tls_stealth_profile;
    out->anonym_pubkey       = in.anonym_pubkey;
    out->inner_crypto        = in.inner_crypto;
    out->inner_heavy         = in.inner_heavy;
    out->inner_hop           = in.inner_hop;
    out->hop_interval_ms     = in.hop_interval_ms;
    out->allow_udp           = in.allow_udp;
    out->allow_local_ip      = in.allow_local_ip;
    return true;
}

bool apply_imported_bundle(const ShareBundle& bundle,
                           ApplyResult* out,
                           std::string* error) {
    if (!out) {
        if (error) *error = "apply_imported_bundle: out is null";
        return false;
    }
    namespace fs = std::filesystem;
    fs::path home;
    if (const char* h = std::getenv("HOME")) home = h;
    if (home.empty()) {
        if (error) *error = "HOME not set";
        return false;
    }
    fs::path target = home / ".yume" / "imported" / bundle.server_host;
#ifndef _WIN32
    const mode_t prior = ::umask(0077);
#endif
    std::error_code ec;
    fs::create_directories(target, ec);
#ifndef _WIN32
    ::umask(prior);
    (void)::chmod(target.c_str(), 0700);
#endif
    if (ec) {
        if (error) *error = "create_directories(" + target.string() + "): " + ec.message();
        return false;
    }
    out->target_dir = target.string();

    auto write_pem = [&](const std::string& name, const std::string& pem,
                         std::string* dst_path) -> bool {
        if (pem.empty()) return true;
        const auto p = (target / name).string();
        std::vector<std::uint8_t> bytes(pem.begin(), pem.end());
        std::string werr;
        if (!write_file_owner_only(p, bytes, &werr)) {
            if (error) *error = werr;
            return false;
        }
        *dst_path = p;
        return true;
    };
    if (!write_pem("identity.key", bundle.auth_private_key_pem, &out->identity_path)) return false;
    if (!write_pem("anonym_ca.pem", bundle.anonym_ca_cert_pem, &out->anonym_ca_path)) return false;
    if (!write_pem("pq_public.key", bundle.pq_public_key_pem, &out->pq_public_path)) return false;

    nlohmann::json cfg = nlohmann::json::object();
    cfg["server"] = bundle.server_host;
    cfg["port"]   = bundle.server_port;
    if (!out->identity_path.empty())   cfg["identity"] = out->identity_path;
    if (!out->anonym_ca_path.empty())  cfg["anonym_ca_cert"] = out->anonym_ca_path;
    if (!out->pq_public_path.empty())  cfg["pq_public_key"] = out->pq_public_path;
    cfg["obfuscation"] = bundle.obfuscation;
    if (!bundle.obfs_secret.empty())    cfg["obfs_secret"] = bundle.obfs_secret;
    if (bundle.obfs_pad_multiple > 0)   cfg["obfs_pad_multiple"] = bundle.obfs_pad_multiple;
    if (bundle.obfs_jitter_ms > 0)      cfg["obfs_jitter_ms"] = bundle.obfs_jitter_ms;
    if (!bundle.tls_pin_sha256.empty()) cfg["tls_pin"] = bundle.tls_pin_sha256;
    if (!bundle.tls_stealth_profile.empty()) cfg["tls_stealth_profile"] = bundle.tls_stealth_profile;
    if (!bundle.anonym_pubkey.empty())  cfg["anonym_pubkey"] = bundle.anonym_pubkey;
    cfg["inner_crypto"]    = bundle.inner_crypto;
    cfg["inner_heavy"]     = bundle.inner_heavy;
    cfg["inner_hop"]       = bundle.inner_hop;
    cfg["hop_interval_ms"] = bundle.hop_interval_ms;
    cfg["udp"]             = bundle.allow_udp;
    cfg["allow_local_ip"]  = bundle.allow_local_ip;

    const auto cfg_path = (target / "config.json").string();
    {
#ifndef _WIN32
        const mode_t p2 = ::umask(0077);
#endif
        std::ofstream f(cfg_path);
#ifndef _WIN32
        ::umask(p2);
#endif
        if (!f) {
            if (error) *error = "cannot write " + cfg_path;
            return false;
        }
        f << cfg.dump(2) << "\n";
#ifndef _WIN32
        ::chmod(cfg_path.c_str(), 0600);
#endif
    }
    out->config_path = cfg_path;
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
