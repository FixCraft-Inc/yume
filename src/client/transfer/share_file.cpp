/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/transfer/share_file.hpp"

#include <basefwx/constants.hpp>
#include <basefwx/crypto.hpp>
#include <basefwx/fwxaes.hpp>
#include <nlohmann/json.hpp>

#include <array>
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "core/runtime/bounded_file.hpp"
#include "core/security/secret_file.hpp"

#ifndef _WIN32
#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#if defined(__linux__)
#include <linux/fs.h>
#include <sys/syscall.h>
#endif
#endif

#if !defined(_WIN32) && defined(O_NOFOLLOW) && defined(O_DIRECTORY) && \
    defined(O_CLOEXEC) && defined(AT_SYMLINK_NOFOLLOW)
#define YUME_SHARE_HAS_SECURE_POSIX_PERSISTENCE 1
#else
#define YUME_SHARE_HAS_SECURE_POSIX_PERSISTENCE 0
#endif

namespace yume::share {

// Delegation completes the object before assignment can throw, so its
// destructor wipes partial secret copies before their strings are destroyed.
ShareBundle::ShareBundle(const ShareBundle& other) : ShareBundle() {
    *this = other;
}
ShareBundle& ShareBundle::operator=(const ShareBundle& other) {
    if (this == &other) return *this;
    clear_secrets();
    type = other.type;
    created_at_iso8601 = other.created_at_iso8601;
    created_by = other.created_by;
    label = other.label;
    server_host = other.server_host;
    server_port = other.server_port;
    auth_private_key_pem = other.auth_private_key_pem;
    obfuscation = other.obfuscation;
    obfs_secret = other.obfs_secret;
    inner_psk = other.inner_psk;
    obfs_pad_multiple = other.obfs_pad_multiple;
    obfs_jitter_ms = other.obfs_jitter_ms;
    tls_pin_sha256 = other.tls_pin_sha256;
    tls_stealth_profile = other.tls_stealth_profile;
    tls_ca_cert_pem = other.tls_ca_cert_pem;
    tls_server_name = other.tls_server_name;
    anonym_ca_cert_pem = other.anonym_ca_cert_pem;
    anonym_pubkey = other.anonym_pubkey;
    pq_public_key_pem = other.pq_public_key_pem;
    inner_crypto = other.inner_crypto;
    tunnel_count = other.tunnel_count;
    require_operator_identity = other.require_operator_identity;
    allow_udp = other.allow_udp;
    allow_local_ip = other.allow_local_ip;
    relay_trust_mode = other.relay_trust_mode;
    relay_peer_pins = other.relay_peer_pins;
    return *this;
}

ShareBundle::ShareBundle(ShareBundle&& other) : ShareBundle() {
    *this = std::move(other);
}

ShareBundle& ShareBundle::operator=(ShareBundle&& other) {
    if (this == &other) return *this;
    clear_secrets();
    type = other.type;
    created_at_iso8601 = std::move(other.created_at_iso8601);
    created_by = std::move(other.created_by);
    label = std::move(other.label);
    server_host = std::move(other.server_host);
    server_port = other.server_port;
    // Copy the three sensitive strings, then wipe their original storage.
    // A conforming std::string move may leave short-string bytes in the
    // moved-from object where clear() can no longer reach them.
    auth_private_key_pem = other.auth_private_key_pem;
    obfuscation = other.obfuscation;
    obfs_secret = other.obfs_secret;
    inner_psk = other.inner_psk;
    other.clear_secrets();
    obfs_pad_multiple = other.obfs_pad_multiple;
    obfs_jitter_ms = other.obfs_jitter_ms;
    tls_pin_sha256 = std::move(other.tls_pin_sha256);
    tls_stealth_profile = std::move(other.tls_stealth_profile);
    tls_ca_cert_pem = std::move(other.tls_ca_cert_pem);
    tls_server_name = std::move(other.tls_server_name);
    anonym_ca_cert_pem = std::move(other.anonym_ca_cert_pem);
    anonym_pubkey = std::move(other.anonym_pubkey);
    pq_public_key_pem = std::move(other.pq_public_key_pem);
    inner_crypto = other.inner_crypto;
    tunnel_count = other.tunnel_count;
    require_operator_identity = other.require_operator_identity;
    allow_udp = other.allow_udp;
    allow_local_ip = other.allow_local_ip;
    relay_trust_mode = std::move(other.relay_trust_mode);
    relay_peer_pins = std::move(other.relay_peer_pins);
    return *this;
}

ShareBundle::~ShareBundle() { clear_secrets(); }

void ShareBundle::clear_secrets() noexcept {
    basefwx::crypto::SecureClear(auth_private_key_pem);
    basefwx::crypto::SecureClear(obfs_secret);
    basefwx::crypto::SecureClear(inner_psk);
}

namespace {

constexpr char     kMagic[]      = "YUMESHRE";
constexpr std::size_t kMagicLen  = 8;
constexpr std::size_t kHeaderLen = 12;  // magic + version + type + 2 reserved
static_assert(kPasswordMin == basefwx::constants::kShortPasswordMin,
              "YUME share password policy must match BaseFWX FwxAES");

bool valid_relay_endpoint_id(std::string_view value) noexcept {
    if (value.empty() || value.size() > 255U || value == "." ||
        value == "..") {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return (ch >= 'a' && ch <= 'z') ||
               (ch >= 'A' && ch <= 'Z') ||
               (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' ||
               ch == '.' || ch == ':';
    });
}

bool valid_server_host_component(std::string_view value) {
    if (value.empty() || value.size() > 255U || value == "." ||
        value == ".." ||
        value.find('/') != std::string_view::npos ||
        value.find('\\') != std::string_view::npos ||
        value.find('\0') != std::string_view::npos) {
        return false;
    }
    const std::filesystem::path path{std::string(value)};
    return !path.has_root_path() && path == path.filename();
}

bool normalize_relay_fingerprint(std::string value,
                                 std::string* normalized) {
    if (!normalized || value.size() != 64U) return false;
    for (char& ch : value) {
        if (ch >= '0' && ch <= '9') continue;
        if (ch >= 'a' && ch <= 'f') continue;
        if (ch >= 'A' && ch <= 'F') {
            ch = static_cast<char>(ch - 'A' + 'a');
            continue;
        }
        return false;
    }
    *normalized = std::move(value);
    return true;
}

bool normalize_relay_trust_policy(const std::string& mode,
                                  const RelayPeerPins& pins,
                                  RelayPeerPins* normalized,
                                  std::string* error) {
    if (!normalized) {
        if (error) *error = "relay trust validation output is null";
        return false;
    }
    normalized->clear();
    if (mode != "tofu" && mode != "pinned") {
        if (error) *error = "relay_trust_mode must be tofu or pinned";
        return false;
    }
    for (const auto& [endpoint_id, fingerprint] : pins) {
        if (!valid_relay_endpoint_id(endpoint_id)) {
            if (error) {
                *error = "relay_peer_pins contains an invalid endpoint id";
            }
            return false;
        }
        std::string canonical;
        if (!normalize_relay_fingerprint(fingerprint, &canonical)) {
            if (error) {
                *error = "relay_peer_pins fingerprint for " + endpoint_id +
                         " must be exactly 64 hexadecimal characters";
            }
            return false;
        }
        normalized->emplace(endpoint_id, std::move(canonical));
    }
    return true;
}

void wipe_json_strings(nlohmann::json& value) noexcept {
    try {
        if (value.is_string()) {
            basefwx::crypto::SecureClear(value.get_ref<std::string&>());
            return;
        }
        if (value.is_array()) {
            for (auto& item : value) wipe_json_strings(item);
            return;
        }
        if (value.is_object()) {
            for (auto& item : value.items()) {
                wipe_json_strings(item.value());
            }
        }
    } catch (...) {
        // Cleanup must not throw. The decrypted byte buffer is independently
        // guarded even if a malformed JSON shape reaches here.
    }
}

void wipe_bundle_json_secrets(nlohmann::json& document) noexcept {
    wipe_json_strings(document);
}

class JsonSecretWiper {
public:
    explicit JsonSecretWiper(nlohmann::json& document) noexcept
        : document_(document) {}
    JsonSecretWiper(const JsonSecretWiper&) = delete;
    JsonSecretWiper& operator=(const JsonSecretWiper&) = delete;
    ~JsonSecretWiper() { wipe_bundle_json_secrets(document_); }

private:
    nlohmann::json& document_;
};

void wipe_bundle_secrets(ShareBundle& bundle) noexcept {
    bundle.clear_secrets();
}

class BundleSecretWiper {
public:
    explicit BundleSecretWiper(ShareBundle& bundle) noexcept
        : bundle_(&bundle) {}
    BundleSecretWiper(const BundleSecretWiper&) = delete;
    BundleSecretWiper& operator=(const BundleSecretWiper&) = delete;
    ~BundleSecretWiper() {
        if (bundle_) wipe_bundle_secrets(*bundle_);
    }
    void dismiss() noexcept { bundle_ = nullptr; }

private:
    ShareBundle* bundle_;
};

nlohmann::json bundle_to_json(const ShareBundle& b,
                              const RelayPeerPins& normalized_pins) {
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
        nlohmann::json auth;
        auth["private_key_pem"] = b.auth_private_key_pem;
        j["auth"] = std::move(auth);
    }
    nlohmann::json stealth;
    stealth["obfuscation"] = b.obfuscation;
    if (!b.obfs_secret.empty())       stealth["obfs_secret"] = b.obfs_secret;
    if (b.obfs_pad_multiple > 0)      stealth["obfs_pad_multiple"] = b.obfs_pad_multiple;
    if (b.obfs_jitter_ms > 0)         stealth["obfs_jitter_ms"] = b.obfs_jitter_ms;
    if (!b.tls_pin_sha256.empty())    stealth["tls_pin_sha256"] = b.tls_pin_sha256;
    if (!b.tls_stealth_profile.empty()) stealth["tls_stealth_profile"] = b.tls_stealth_profile;
    j["stealth"] = std::move(stealth);

    if (!b.tls_ca_cert_pem.empty() || !b.tls_server_name.empty()) {
        nlohmann::json tls;
        if (!b.tls_ca_cert_pem.empty()) tls["ca_cert_pem"] = b.tls_ca_cert_pem;
        if (!b.tls_server_name.empty()) tls["server_name"] = b.tls_server_name;
        j["tls"] = std::move(tls);
    }

    if (!b.anonym_ca_cert_pem.empty() || !b.anonym_pubkey.empty()) {
        nlohmann::json anon;
        if (!b.anonym_ca_cert_pem.empty()) anon["ca_cert_pem"] = b.anonym_ca_cert_pem;
        if (!b.anonym_pubkey.empty())      anon["pubkey"]      = b.anonym_pubkey;
        j["anonym"] = anon;
    }
    if (!b.pq_public_key_pem.empty()) {
        j["pq"] = nlohmann::json{{"public_key_pem", b.pq_public_key_pem}};
    }

    nlohmann::json client_settings;
    client_settings["inner_crypto"] = b.inner_crypto;
    client_settings["inner_psk"] = b.inner_psk;
    client_settings["tunnels"] = b.tunnel_count;
    client_settings["require_operator_identity"] =
        b.require_operator_identity;
    client_settings["allow_udp"] = b.allow_udp;
    client_settings["allow_local_ip"] = b.allow_local_ip;
    client_settings["relay_trust_mode"] = b.relay_trust_mode;
    client_settings["relay_peer_pins"] = normalized_pins;
    j["client_settings"] = std::move(client_settings);
    return j;
}

bool json_to_bundle(const nlohmann::json& j, ShareBundle* out, std::string* error) {
    auto fail = [&](const char* msg) {
        if (error) *error = msg;
        return false;
    };
    if (!j.is_object())                                       return fail("share bundle is not a JSON object");
    if (!j.contains("magic") || j["magic"] != "yume-share")   return fail("share bundle missing or wrong 'magic' field");
    if (!j.contains("version") || !j["version"].is_number_integer() ||
        j["version"].get<int>() != kFormatVersion) {
        return fail("share bundle has an unsupported inner version");
    }
    if (!j.contains("type") || !j["type"].is_string() ||
        j["type"].get<std::string>() != "backup") {
        return fail("share bundle has an unsupported type");
    }
    if (!j.contains("server") || !j["server"].is_object())    return fail("share bundle missing 'server' object");

    const auto& server = j["server"];
    if (!server.contains("host") || !server["host"].is_string()) return fail("share bundle missing server.host");
    if (!server.contains("port") || !server["port"].is_number_integer()) return fail("share bundle missing server.port");
    out->server_host = server["host"].get<std::string>();
    out->server_port = server["port"].get<int>();
    if (!valid_server_host_component(out->server_host) ||
        out->server_port < 1 || out->server_port > 65535) {
        return fail("share bundle has invalid server endpoint");
    }

    out->type = BundleType::Backup;

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
    if (j.contains("tls") && j["tls"].is_object()) {
        out->tls_ca_cert_pem = j["tls"].value("ca_cert_pem", std::string{});
        out->tls_server_name = j["tls"].value("server_name", std::string{});
    }
    // Android ShareFile.kt applies this same .yss rule when TLS CA is omitted.
    // Keep both importers consistent when separating these trust inputs.
    if (out->tls_ca_cert_pem.empty() && !out->anonym_ca_cert_pem.empty()) {
        out->tls_ca_cert_pem = out->anonym_ca_cert_pem;
    }
    if (j.contains("pq") && j["pq"].is_object()) {
        out->pq_public_key_pem = j["pq"].value("public_key_pem", std::string{});
    }

    if (j.contains("client_settings") &&
        !j["client_settings"].is_object()) {
        return fail("share bundle client_settings must be an object");
    }
    if (j.contains("client_settings")) {
        const auto& cs = j["client_settings"];
        out->inner_crypto    = cs.value("inner_crypto", true);
        out->inner_psk       = cs.value("inner_psk", std::string{});
        out->tunnel_count = static_cast<std::uint8_t>(
            std::clamp(cs.value("tunnels", 1), 1, 16));
        out->require_operator_identity = cs.value(
            "require_operator_identity", !out->anonym_ca_cert_pem.empty());
        out->allow_udp       = cs.value("allow_udp", false);
        out->allow_local_ip  = cs.value("allow_local_ip", false);

        if (cs.contains("relay_trust_mode")) {
            if (!cs["relay_trust_mode"].is_string()) {
                return fail("share bundle relay_trust_mode must be a string");
            }
            out->relay_trust_mode =
                cs["relay_trust_mode"].get<std::string>();
        }
        RelayPeerPins parsed_pins;
        if (cs.contains("relay_peer_pins")) {
            const auto& pins = cs["relay_peer_pins"];
            if (!pins.is_object()) {
                return fail("share bundle relay_peer_pins must be an object");
            }
            for (auto it = pins.begin(); it != pins.end(); ++it) {
                if (!it.value().is_string()) {
                    return fail(
                        "share bundle relay_peer_pins values must be strings");
                }
                parsed_pins.emplace(
                    it.key(), it.value().get<std::string>());
            }
        }
        RelayPeerPins normalized_pins;
        if (!normalize_relay_trust_policy(out->relay_trust_mode,
                                          parsed_pins,
                                          &normalized_pins,
                                          error)) {
            return false;
        }
        out->relay_peer_pins = std::move(normalized_pins);
    }
    return true;
}

}  // namespace

std::vector<std::uint8_t> encode_share(const ShareBundle& bundle,
                                       const std::string& password,
                                       std::string* error) {
    if (password.size() < kPasswordMin) {
        if (error) {
            *error = "password must be at least " +
                     std::to_string(kPasswordMin) + " characters";
        }
        return {};
    }
    if (bundle.type != BundleType::Backup) {
        if (error) *error = "bundle has an unsupported type";
        return {};
    }
    if (!valid_server_host_component(bundle.server_host) ||
        bundle.server_port < 1 || bundle.server_port > 65535) {
        if (error) *error = "bundle missing valid server endpoint";
        return {};
    }
    RelayPeerPins normalized_pins;
    if (!normalize_relay_trust_policy(bundle.relay_trust_mode,
                                      bundle.relay_peer_pins,
                                      &normalized_pins,
                                      error)) {
        return {};
    }
    // We don't require an auth key here — both full backups (with
    // private key) and info-only bundles (server connection + CA +
    // obfs secret, no key) are valid. The downstream importer
    // surfaces "no auth key in this bundle, you'll need to add one"
    // in its summary UI; the operator decides what's acceptable.

    std::string serialised;
    basefwx::crypto::SecretGuard serialised_wiper;
    serialised_wiper.Add(serialised);
    try {
        nlohmann::json document =
            bundle_to_json(bundle, normalized_pins);
        JsonSecretWiper document_wiper(document);
        serialised = document.dump();
    } catch (const std::exception& ex) {
        if (error) *error = std::string("serialise failed: ") + ex.what();
        return {};
    }
    if (serialised.size() > kMaxShareFileBytes - kHeaderLen) {
        if (error) *error = "share payload exceeds 16 MiB limit";
        return {};
    }

    basefwx::crypto::SecureBytes plaintext{
        std::vector<std::uint8_t>(serialised.begin(), serialised.end())};
    // The share-file KDF is a YUME format decision. BaseFWX resolves its
    // default "auto" label through the BASEFWX_USER_KDF environment variable,
    // so leaving the default would let the process environment downgrade new
    // share files to PBKDF2. Argon2id is a hard BaseFWX build requirement
    // (BASEFWX_REQUIRE_ARGON2), so the explicit label always resolves. The
    // decoder reads the serialized label and needs no matching option.
    basefwx::fwxaes::Options encrypt_options;
    encrypt_options.user_kdf.label = "argon2id";
    std::vector<std::uint8_t> encrypted;
    try {
        encrypted = basefwx::fwxaes::EncryptRaw(
            plaintext.bytes(), password, encrypt_options);
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
    if (out.size() > kMaxShareFileBytes) {
        basefwx::crypto::SecureClear(out);
        if (error) *error = "encrypted share file exceeds 16 MiB limit";
        return {};
    }
    return out;
}

bool peek_share_header(const std::vector<std::uint8_t>& blob, ShareFileHeader* out) {
    if (!out) return false;
    if (blob.size() < kHeaderLen) return false;
    if (std::memcmp(blob.data(), kMagic, kMagicLen) != 0) return false;
    out->version = blob[kMagicLen];
    if (out->version != kFormatVersion) return false;
    if (blob[kMagicLen + 1] !=
            static_cast<std::uint8_t>(BundleType::Backup) ||
        blob[kMagicLen + 2] != 0 || blob[kMagicLen + 3] != 0) {
        return false;
    }
    out->type = static_cast<BundleType>(blob[kMagicLen + 1]);
    return true;
}

bool read_share_file(const std::filesystem::path& path,
                     std::vector<std::uint8_t>* contents,
                     std::string* error) {
    return runtime::read_file_bounded(
        path, kMaxShareFileBytes, contents, error);
}

bool write_share_file_exclusive(const std::filesystem::path& path,
                                std::span<const std::uint8_t> contents,
                                std::string* error) {
    if (contents.size() > kMaxShareFileBytes) {
        if (error) *error = "share file exceeds 16 MiB limit";
        return false;
    }
    return security::WriteFileExclusive0600(
        path, contents, error,
        security::PrivateParentPolicy::RequireExisting);
}

namespace {
std::string slurp_text_file(const std::string& path, std::string* error) {
    std::string contents;
    (void)runtime::read_text_file_bounded(
        path, security::kMaxPrivateKeyFileBytes, &contents, error);
    return contents;
}

bool valid_secret_hex(const std::string& value) {
    return value.size() == 64 &&
           std::all_of(value.begin(), value.end(), [](unsigned char ch) {
               return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
           });
}

bool load_secret_text(const std::string& path, const char* label,
                      std::string* out, std::string* error) {
    if (path.empty()) return true;
    std::string read_error;
    auto value = slurp_text_file(path, &read_error);
    basefwx::crypto::SecretGuard value_wiper;
    value_wiper.Add(value);
    if (!valid_secret_hex(value)) {
        if (error) {
            *error = std::string(label) + ": " +
                     (!read_error.empty()
                          ? read_error
                          : "must contain exactly 64 lowercase hex characters with no newline");
        }
        return false;
    }
    *out = std::move(value);
    return true;
}

#if YUME_SHARE_HAS_SECURE_POSIX_PERSISTENCE

constexpr mode_t kPrivateDirectoryMode = S_IRWXU;
constexpr mode_t kPrivateFileMode = S_IRUSR | S_IWUSR;
constexpr unsigned kTemporaryDirectoryAttempts = 128U;
constexpr std::array<std::string_view, 7> kImportFileNames{
    "identity.key",
    "anonym_ca.pem",
    "tls_ca.pem",
    "pq_public.key",
    "admission.hex",
    "inner-psk.hex",
    "config.json",
};
std::atomic<std::uint64_t> g_import_sequence{0};

[[noreturn]] void throw_persistence_error(std::string_view operation,
                                          int error_number) {
    throw std::runtime_error(
        std::string(operation) + ": " +
        std::generic_category().message(error_number));
}

class FileDescriptor {
public:
    explicit FileDescriptor(int fd = -1) noexcept : fd_(fd) {}
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    FileDescriptor(FileDescriptor&& other) noexcept : fd_(other.fd_) {
        other.fd_ = -1;
    }
    FileDescriptor& operator=(FileDescriptor&& other) noexcept {
        if (this != &other) {
            if (fd_ >= 0) (void)::close(fd_);
            fd_ = other.fd_;
            other.fd_ = -1;
        }
        return *this;
    }
    ~FileDescriptor() {
        if (fd_ >= 0) (void)::close(fd_);
    }

    int get() const noexcept { return fd_; }
    explicit operator bool() const noexcept { return fd_ >= 0; }

    void close_checked(std::string_view operation) {
        const int fd = fd_;
        fd_ = -1;
        if (::close(fd) != 0) {
            throw_persistence_error(operation, errno);
        }
    }

private:
    int fd_;
};

class DirectoryLock {
public:
    explicit DirectoryLock(int fd) : fd_(fd) {
        while (::flock(fd_, LOCK_EX) != 0) {
            if (errno == EINTR) continue;
            throw_persistence_error("lock imported-share directory", errno);
        }
    }
    DirectoryLock(const DirectoryLock&) = delete;
    DirectoryLock& operator=(const DirectoryLock&) = delete;
    ~DirectoryLock() { (void)::flock(fd_, LOCK_UN); }

private:
    int fd_;
};

struct DirectoryContents {
    std::vector<std::string> file_names;
};

bool has_private_directory_mode(mode_t mode) noexcept {
    constexpr mode_t permissions = S_IRWXU | S_IRWXG | S_IRWXO;
    constexpr mode_t special = S_ISUID | S_ISGID | S_ISVTX;
    return (mode & permissions) == kPrivateDirectoryMode &&
           (mode & special) == 0;
}

bool has_private_file_mode(mode_t mode) noexcept {
    constexpr mode_t permissions = S_IRWXU | S_IRWXG | S_IRWXO;
    constexpr mode_t special = S_ISUID | S_ISGID | S_ISVTX;
    return (mode & permissions) == kPrivateFileMode &&
           (mode & special) == 0;
}

struct stat stat_descriptor(int fd, std::string_view label) {
    struct stat info {};
    if (::fstat(fd, &info) != 0) {
        throw_persistence_error("stat " + std::string(label), errno);
    }
    return info;
}

void validate_private_directory(int fd, std::string_view label) {
    const struct stat info = stat_descriptor(fd, label);
    if (!S_ISDIR(info.st_mode) || info.st_uid != ::geteuid()) {
        throw std::runtime_error(
            std::string(label) +
            " must be a directory owned by the current user");
    }
    if (!has_private_directory_mode(info.st_mode)) {
        throw std::runtime_error(
            std::string(label) +
            " must have owner-only mode 0700 and no special mode bits");
    }
}

void validate_owned_home_directory(int fd) {
    const struct stat info = stat_descriptor(fd, "HOME directory");
    if (!S_ISDIR(info.st_mode) || info.st_uid != ::geteuid()) {
        throw std::runtime_error(
            "HOME must be a directory owned by the current user");
    }
    if ((info.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        throw std::runtime_error(
            "HOME must not be group/world writable");
    }
}

void validate_private_regular(const struct stat& info,
                              std::string_view label) {
    if (!S_ISREG(info.st_mode) || info.st_uid != ::geteuid() ||
        info.st_nlink != 1) {
        throw std::runtime_error(
            std::string(label) +
            " must be a singly-linked regular file owned by the current user");
    }
    if (!has_private_file_mode(info.st_mode)) {
        throw std::runtime_error(
            std::string(label) +
            " must have owner-only mode 0600 and no special mode bits");
    }
}

bool same_object(const struct stat& lhs, const struct stat& rhs) noexcept {
    return lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino;
}

std::vector<std::string> absolute_path_components(
        const std::filesystem::path& path) {
    if (!path.is_absolute() || !path.root_name().empty()) {
        throw std::runtime_error("HOME must be an absolute POSIX path");
    }
    std::vector<std::string> components;
    for (const auto& component_path : path.relative_path()) {
        const std::string component = component_path.string();
        if (component.empty()) continue;
        if (component == "." || component == ".." ||
            component.find('\0') != std::string::npos) {
            throw std::runtime_error(
                "HOME must not contain '.', '..', or NUL path components");
        }
        components.push_back(component);
    }
    if (components.empty()) {
        throw std::runtime_error("HOME must not be the filesystem root");
    }
    return components;
}

FileDescriptor open_owned_home(const std::filesystem::path& home) {
    const auto components = absolute_path_components(home);
    FileDescriptor current(::open(
        "/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (!current) throw_persistence_error("open HOME path root", errno);

    for (const std::string& component : components) {
        FileDescriptor next(::openat(
            current.get(), component.c_str(),
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
        if (!next) {
            throw_persistence_error(
                "open HOME directory component without following links",
                errno);
        }
        current = std::move(next);
    }
    validate_owned_home_directory(current.get());
    return current;
}

FileDescriptor open_or_create_private_directory(int parent_fd,
                                                std::string_view name,
                                                std::string_view label) {
    bool created = false;
    if (::mkdirat(parent_fd, std::string(name).c_str(),
                  kPrivateDirectoryMode) == 0) {
        created = true;
    } else if (errno != EEXIST) {
        throw_persistence_error(
            "create " + std::string(label), errno);
    }

    FileDescriptor directory(::openat(
        parent_fd, std::string(name).c_str(),
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (!directory) {
        throw_persistence_error(
            "open " + std::string(label) + " without following links",
            errno);
    }
    if (created && ::fchmod(directory.get(), kPrivateDirectoryMode) != 0) {
        throw_persistence_error("protect " + std::string(label), errno);
    }
    validate_private_directory(directory.get(), label);
    if (created) {
        if (::fsync(directory.get()) != 0) {
            throw_persistence_error("sync new " + std::string(label), errno);
        }
        if (::fsync(parent_fd) != 0) {
            throw_persistence_error(
                "sync parent of new " + std::string(label), errno);
        }
    }
    return directory;
}

bool known_import_file_name(std::string_view name) noexcept {
    return std::find(kImportFileNames.begin(), kImportFileNames.end(), name) !=
           kImportFileNames.end();
}

DirectoryContents inspect_private_target_directory(int fd) {
    const int duplicate = ::openat(
        fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (duplicate < 0) {
        throw_persistence_error("duplicate imported-share directory", errno);
    }
    DIR* raw = ::fdopendir(duplicate);
    if (!raw) {
        const int open_error = errno;
        (void)::close(duplicate);
        throw_persistence_error("enumerate imported-share directory",
                                open_error);
    }
    struct DirectoryCloser {
        DIR* value;
        ~DirectoryCloser() {
            if (value) (void)::closedir(value);
        }
    } closer{raw};

    DirectoryContents contents;
    errno = 0;
    while (dirent* entry = ::readdir(raw)) {
        const std::string name(entry->d_name);
        if (name == "." || name == "..") {
            errno = 0;
            continue;
        }
        if (!known_import_file_name(name)) {
            throw std::runtime_error(
                "existing imported-share directory contains unexpected entry '" +
                name + "'");
        }
        struct stat info {};
        if (::fstatat(fd, name.c_str(), &info, AT_SYMLINK_NOFOLLOW) != 0) {
            throw_persistence_error(
                "stat existing imported-share file '" + name + "'", errno);
        }
        validate_private_regular(
            info, "existing imported-share file '" + name + "'");
        contents.file_names.push_back(name);
        errno = 0;
    }
    if (errno != 0) {
        throw_persistence_error("enumerate imported-share directory", errno);
    }
    std::sort(contents.file_names.begin(), contents.file_names.end());
    return contents;
}

struct ExistingTarget {
    FileDescriptor directory;
    DirectoryContents contents;
    struct stat identity {};
};

std::optional<ExistingTarget> open_existing_target(
        int imported_fd, const std::string& name) {
    struct stat named {};
    if (::fstatat(imported_fd, name.c_str(), &named,
                  AT_SYMLINK_NOFOLLOW) != 0) {
        const int stat_error = errno;
        if (stat_error == ENOENT) return std::nullopt;
        throw_persistence_error("stat imported-share target", stat_error);
    }
    if (!S_ISDIR(named.st_mode)) {
        throw std::runtime_error(
            "imported-share target must be a real directory, not a link or file");
    }

    FileDescriptor directory(::openat(
        imported_fd, name.c_str(),
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (!directory) {
        throw_persistence_error(
            "open imported-share target without following links", errno);
    }
    validate_private_directory(directory.get(), "imported-share target");
    const struct stat opened = stat_descriptor(
        directory.get(), "opened imported-share target");
    if (!same_object(named, opened)) {
        throw std::runtime_error(
            "imported-share target changed while it was opened");
    }
    DirectoryContents contents =
        inspect_private_target_directory(directory.get());
    return ExistingTarget{
        std::move(directory), std::move(contents), opened};
}

void write_all(int fd, std::string_view content,
               std::string_view label) {
    std::size_t offset = 0;
    while (offset < content.size()) {
        const std::size_t chunk = std::min<std::size_t>(
            content.size() - offset,
            static_cast<std::size_t>(std::numeric_limits<ssize_t>::max()));
        const ssize_t count = ::write(fd, content.data() + offset, chunk);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            throw_persistence_error(
                "write " + std::string(label), count < 0 ? errno : EIO);
        }
        offset += static_cast<std::size_t>(count);
    }
}

class StagedImportDirectory {
public:
    explicit StagedImportDirectory(int parent_fd) : parent_fd_(parent_fd) {
        const auto process_id = static_cast<std::uint64_t>(::getpid());
        for (unsigned attempt = 0; attempt < kTemporaryDirectoryAttempts;
             ++attempt) {
            const auto sequence = g_import_sequence.fetch_add(
                1, std::memory_order_relaxed);
            name_ = ".import-tmp." + std::to_string(process_id) + "." +
                    std::to_string(sequence);
            if (::mkdirat(parent_fd_, name_.c_str(),
                          kPrivateDirectoryMode) == 0) {
                break;
            }
            if (errno != EEXIST) {
                throw_persistence_error(
                    "create imported-share staging directory", errno);
            }
            name_.clear();
        }
        if (name_.empty()) {
            throw std::runtime_error(
                "create imported-share staging directory: name attempts exhausted");
        }

        try {
            directory_ = FileDescriptor(::openat(
                parent_fd_, name_.c_str(),
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
            if (!directory_) {
                throw_persistence_error(
                    "open imported-share staging directory", errno);
            }
            if (::fchmod(directory_.get(), kPrivateDirectoryMode) != 0) {
                throw_persistence_error(
                    "protect imported-share staging directory", errno);
            }
            validate_private_directory(
                directory_.get(), "imported-share staging directory");
            if (::fsync(directory_.get()) != 0) {
                throw_persistence_error(
                    "sync imported-share staging directory", errno);
            }
            if (::fsync(parent_fd_) != 0) {
                throw_persistence_error(
                    "sync imported-share staging parent", errno);
            }
        } catch (...) {
            (void)::unlinkat(parent_fd_, name_.c_str(), AT_REMOVEDIR);
            throw;
        }
    }

    StagedImportDirectory(const StagedImportDirectory&) = delete;
    StagedImportDirectory& operator=(const StagedImportDirectory&) = delete;
    ~StagedImportDirectory() {
        if (!cleanup_) return;
        for (auto it = file_names_.rbegin(); it != file_names_.rend(); ++it) {
            (void)::unlinkat(directory_.get(), it->c_str(), 0);
        }
        (void)::fsync(directory_.get());
        (void)::unlinkat(parent_fd_, name_.c_str(), AT_REMOVEDIR);
        (void)::fsync(parent_fd_);
    }

    int fd() const noexcept { return directory_.get(); }
    const std::string& name() const noexcept { return name_; }
    void record_file(std::string name) {
        file_names_.push_back(std::move(name));
    }
    void published() noexcept { cleanup_ = false; }

private:
    int parent_fd_;
    std::string name_;
    FileDescriptor directory_;
    std::vector<std::string> file_names_;
    bool cleanup_{true};
};

void create_staged_private_file(StagedImportDirectory& stage,
                                const std::string& name,
                                std::string_view content) {
    FileDescriptor file(::openat(
        stage.fd(), name.c_str(),
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
        kPrivateFileMode));
    if (!file) {
        throw_persistence_error(
            "create staged imported-share file '" + name + "'", errno);
    }
    bool complete = false;
    try {
        if (::fchmod(file.get(), kPrivateFileMode) != 0) {
            throw_persistence_error(
                "protect staged imported-share file '" + name + "'", errno);
        }
        validate_private_regular(
            stat_descriptor(file.get(), "staged imported-share file '" + name + "'"),
            "staged imported-share file '" + name + "'");
        write_all(file.get(), content,
                  "staged imported-share file '" + name + "'");
        if (::fsync(file.get()) != 0) {
            throw_persistence_error(
                "sync staged imported-share file '" + name + "'", errno);
        }
        file.close_checked(
            "close staged imported-share file '" + name + "'");
        stage.record_file(name);
        complete = true;
    } catch (...) {
        if (!complete) {
            (void)::unlinkat(stage.fd(), name.c_str(), 0);
            (void)::fsync(stage.fd());
        }
        throw;
    }
}

void verify_named_directory_identity(int parent_fd,
                                     const std::string& name,
                                     const struct stat& expected,
                                     std::string_view label) {
    struct stat named {};
    if (::fstatat(parent_fd, name.c_str(), &named,
                  AT_SYMLINK_NOFOLLOW) != 0) {
        throw_persistence_error("stat " + std::string(label), errno);
    }
    if (!S_ISDIR(named.st_mode) || !same_object(named, expected)) {
        throw std::runtime_error(
            std::string(label) + " changed during secure import");
    }
}

bool exchange_directories(int parent_fd,
                          const std::string& lhs,
                          const std::string& rhs,
                          int* exchange_error) noexcept {
#if defined(__linux__) && defined(SYS_renameat2) && defined(RENAME_EXCHANGE)
    int result;
    do {
        result = static_cast<int>(::syscall(
            SYS_renameat2, parent_fd, lhs.c_str(), parent_fd, rhs.c_str(),
            RENAME_EXCHANGE));
    } while (result != 0 && errno == EINTR);
    if (result == 0) return true;
    if (exchange_error) *exchange_error = errno;
    return false;
#else
    (void)parent_fd;
    (void)lhs;
    (void)rhs;
    if (exchange_error) *exchange_error = ENOTSUP;
    return false;
#endif
}

void remove_replaced_target_best_effort(
        int parent_fd,
        const std::string& old_name,
        ExistingTarget& old_target) noexcept {
    try {
        verify_named_directory_identity(
            parent_fd, old_name, old_target.identity,
            "replaced imported-share directory");
        const DirectoryContents current =
            inspect_private_target_directory(old_target.directory.get());
        if (current.file_names != old_target.contents.file_names) return;
        for (const std::string& name : current.file_names) {
            if (::unlinkat(old_target.directory.get(), name.c_str(), 0) != 0) {
                return;
            }
        }
        if (::fsync(old_target.directory.get()) != 0) return;
        if (::unlinkat(parent_fd, old_name.c_str(), AT_REMOVEDIR) != 0) return;
        (void)::fsync(parent_fd);
    } catch (...) {
        // Publication already committed. Leaving the protected old directory
        // is safer than deleting an entry whose identity cannot be rechecked.
    }
}

void publish_staged_import(int parent_fd,
                           const std::string& target_name,
                           StagedImportDirectory& stage,
                           std::optional<ExistingTarget>& old_target) {
    if (::fsync(stage.fd()) != 0) {
        throw_persistence_error("sync completed imported-share staging directory",
                                errno);
    }

    if (!old_target) {
        if (::renameat(parent_fd, stage.name().c_str(),
                       parent_fd, target_name.c_str()) != 0) {
            throw_persistence_error(
                "publish imported-share directory atomically", errno);
        }
        if (::fsync(parent_fd) != 0) {
            const int sync_error = errno;
            if (::renameat(parent_fd, target_name.c_str(),
                           parent_fd, stage.name().c_str()) != 0) {
                // The new directory may remain published. Do not let staged
                // cleanup unlink files through its still-open descriptor.
                stage.published();
            }
            (void)::fsync(parent_fd);
            throw_persistence_error(
                "sync published imported-share directory", sync_error);
        }
        stage.published();
        return;
    }

    verify_named_directory_identity(
        parent_fd, target_name, old_target->identity,
        "existing imported-share target");
    int exchange_error = 0;
    if (!exchange_directories(parent_fd, target_name, stage.name(),
                              &exchange_error)) {
        if (exchange_error == ENOSYS || exchange_error == EINVAL ||
            exchange_error == EOPNOTSUPP || exchange_error == ENOTSUP) {
            throw std::runtime_error(
                "atomic imported-share replacement is unsupported by this "
                "kernel/filesystem; existing data was left unchanged");
        }
        throw_persistence_error(
            "atomically exchange imported-share directories", exchange_error);
    }
    if (::fsync(parent_fd) != 0) {
        const int sync_error = errno;
        int rollback_error = 0;
        if (!exchange_directories(
                parent_fd, target_name, stage.name(), &rollback_error)) {
            // The exchange may remain committed. Suppress cleanup because the
            // staging descriptor names the newly published directory.
            stage.published();
        }
        (void)::fsync(parent_fd);
        throw_persistence_error(
            "sync replaced imported-share directory", sync_error);
    }

    stage.published();
    remove_replaced_target_best_effort(
        parent_fd, stage.name(), *old_target);
}

#endif  // YUME_SHARE_HAS_SECURE_POSIX_PERSISTENCE
}  // namespace

bool build_backup_bundle(const BackupInputs& in, ShareBundle* out, std::string* error) {
    if (!out) {
        if (error) *error = "build_backup_bundle: out is null";
        return false;
    }
    out->clear_secrets();
    BundleSecretWiper output_wiper(*out);
    if (!valid_server_host_component(in.server_host) ||
        in.server_port < 1 || in.server_port > 65535) {
        if (error) *error = "server endpoint missing or invalid";
        return false;
    }
    RelayPeerPins normalized_pins;
    if (!normalize_relay_trust_policy(in.relay_trust_mode,
                                      in.relay_peer_pins,
                                      &normalized_pins,
                                      error)) {
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
    if (!in.tls_ca_cert_path.empty()) {
        std::string tls_ca = slurp_text_file(in.tls_ca_cert_path, &err);
        if (tls_ca.empty()) {
            if (error) *error = "TLS CA: " + err;
            return false;
        }
        out->tls_ca_cert_pem = std::move(tls_ca);
    }
    if (!in.pq_public_key_path.empty()) {
        std::string pq = slurp_text_file(in.pq_public_key_path, &err);
        if (!pq.empty()) out->pq_public_key_pem = std::move(pq);
    }

    out->obfuscation = in.obfuscation;
    if (!load_secret_text(in.obfs_secret_path, "admission secret",
                          &out->obfs_secret, error)) {
        return false;
    }
    if (!load_secret_text(in.inner_psk_path, "inner PSK",
                          &out->inner_psk, error)) {
        return false;
    }
    out->obfs_pad_multiple   = in.obfs_pad_multiple;
    out->obfs_jitter_ms      = in.obfs_jitter_ms;
    out->tls_pin_sha256      = in.tls_pin_sha256;
    out->tls_stealth_profile = in.tls_stealth_profile;
    out->tls_server_name     = in.tls_server_name;
    out->anonym_pubkey       = in.anonym_pubkey;
    out->inner_crypto        = in.inner_crypto;
    out->tunnel_count        = std::clamp<std::uint8_t>(in.tunnel_count, 1, 16);
    out->require_operator_identity = in.require_operator_identity;
    out->allow_udp           = in.allow_udp;
    out->allow_local_ip      = in.allow_local_ip;
    out->relay_trust_mode    = in.relay_trust_mode;
    out->relay_peer_pins     = std::move(normalized_pins);
    output_wiper.dismiss();
    return true;
}

bool apply_imported_bundle(const ShareBundle& bundle,
                           ApplyResult* out,
                           std::string* error) {
    if (error) error->clear();
    if (!out) {
        if (error) *error = "apply_imported_bundle: out is null";
        return false;
    }
    RelayPeerPins normalized_pins;
    if (!normalize_relay_trust_policy(bundle.relay_trust_mode,
                                      bundle.relay_peer_pins,
                                      &normalized_pins,
                                      error)) {
        return false;
    }
    if (bundle.type != BundleType::Backup) {
        if (error) *error = "imported bundle has an unsupported type";
        return false;
    }
    if (!valid_server_host_component(bundle.server_host) ||
        bundle.server_port < 1 || bundle.server_port > 65535) {
        if (error) *error = "imported bundle has an invalid server endpoint";
        return false;
    }
#if defined(_WIN32)
    if (error) {
        *error =
            "secure share persistence is unavailable on Windows; decoding "
            "and inspection remain supported";
    }
    return false;
#elif !YUME_SHARE_HAS_SECURE_POSIX_PERSISTENCE
    if (error) {
        *error =
            "secure share persistence requires O_NOFOLLOW, O_DIRECTORY, "
            "O_CLOEXEC, and AT_SYMLINK_NOFOLLOW";
    }
    return false;
#else
    namespace fs = std::filesystem;
    fs::path home;
    if (const char* h = std::getenv("HOME")) home = h;
    if (home.empty()) {
        if (error) *error = "HOME not set";
        return false;
    }
    try {
        const fs::path target =
            home / ".yume" / "imported" / bundle.server_host;
        ApplyResult result;
        result.target_dir = target.string();

        auto set_output_path = [&](std::string_view name,
                                   const std::string& content,
                                   std::string* destination) {
            if (!content.empty()) {
                *destination = (target / std::string(name)).string();
            }
        };
        set_output_path("identity.key", bundle.auth_private_key_pem,
                        &result.identity_path);
        set_output_path("anonym_ca.pem", bundle.anonym_ca_cert_pem,
                        &result.anonym_ca_path);
        set_output_path("tls_ca.pem", bundle.tls_ca_cert_pem,
                        &result.tls_ca_path);
        set_output_path("pq_public.key", bundle.pq_public_key_pem,
                        &result.pq_public_path);
        set_output_path("admission.hex", bundle.obfs_secret,
                        &result.obfs_secret_path);
        set_output_path("inner-psk.hex", bundle.inner_psk,
                        &result.inner_psk_path);
        result.config_path = (target / "config.json").string();

        nlohmann::json cfg = nlohmann::json::object();
        cfg["server"] = bundle.server_host;
        cfg["port"] = bundle.server_port;
        if (!result.identity_path.empty()) {
            cfg["identity"] = result.identity_path;
        }
        if (!result.anonym_ca_path.empty()) {
            cfg["anonym_ca_cert"] = result.anonym_ca_path;
        }
        if (!result.tls_ca_path.empty()) {
            cfg["tls_ca_cert"] = result.tls_ca_path;
        }
        if (!result.pq_public_path.empty()) {
            cfg["pq_public_key"] = result.pq_public_path;
        }
        cfg["obfuscation"] = bundle.obfuscation;
        if (!result.obfs_secret_path.empty()) {
            cfg["obfs_secret_file"] = result.obfs_secret_path;
        }
        if (!result.inner_psk_path.empty()) {
            cfg["inner_psk_file"] = result.inner_psk_path;
        }
        if (bundle.obfs_pad_multiple > 0) {
            cfg["obfs_pad_multiple"] = bundle.obfs_pad_multiple;
        }
        if (bundle.obfs_jitter_ms > 0) {
            cfg["obfs_jitter_ms"] = bundle.obfs_jitter_ms;
        }
        if (!bundle.tls_pin_sha256.empty()) {
            cfg["tls_pin"] = bundle.tls_pin_sha256;
        }
        if (!bundle.tls_stealth_profile.empty()) {
            cfg["tls_stealth_profile"] = bundle.tls_stealth_profile;
        }
        if (!bundle.tls_server_name.empty()) {
            cfg["tls_server_name"] = bundle.tls_server_name;
        }
        if (!bundle.anonym_pubkey.empty()) {
            cfg["anonym_pubkey"] = bundle.anonym_pubkey;
        }
        cfg["inner_crypto"] = bundle.inner_crypto;
        cfg["tunnels"] = std::clamp<int>(bundle.tunnel_count, 1, 16);
        cfg["require_anonym"] = bundle.require_operator_identity;
        cfg["udp"] = bundle.allow_udp;
        cfg["allow_local_ip"] = bundle.allow_local_ip;
        cfg["relay_trust_mode"] = bundle.relay_trust_mode;
        cfg["relay_peer_pins"] = std::move(normalized_pins);
        // Intentionally omit relay_trust_dir. Config normalization selects the
        // platform-local configured/default store; neither its path nor
        // learned TOFU state is portable authorization material.
        std::string config_text = cfg.dump(2);
        config_text.push_back('\n');

        FileDescriptor home_directory = open_owned_home(home);
        FileDescriptor yume_directory = open_or_create_private_directory(
            home_directory.get(), ".yume", "YUME state directory");
        FileDescriptor imported_directory = open_or_create_private_directory(
            yume_directory.get(), "imported", "imported-share root");
        DirectoryLock import_lock(imported_directory.get());

        auto existing = open_existing_target(
            imported_directory.get(), bundle.server_host);
        StagedImportDirectory stage(imported_directory.get());
        auto stage_file = [&](const std::string& name,
                              const std::string& content) {
            if (!content.empty()) {
                create_staged_private_file(stage, name, content);
            }
        };
        stage_file("identity.key", bundle.auth_private_key_pem);
        stage_file("anonym_ca.pem", bundle.anonym_ca_cert_pem);
        stage_file("tls_ca.pem", bundle.tls_ca_cert_pem);
        stage_file("pq_public.key", bundle.pq_public_key_pem);
        stage_file("admission.hex", bundle.obfs_secret);
        stage_file("inner-psk.hex", bundle.inner_psk);
        create_staged_private_file(stage, "config.json", config_text);

        publish_staged_import(imported_directory.get(), bundle.server_host,
                              stage, existing);
        *out = std::move(result);
        return true;
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
#endif
}

std::optional<ShareBundle> decode_share(const std::vector<std::uint8_t>& blob,
                                        const std::string& password,
                                        std::string* error) {
    if (blob.size() > kMaxShareFileBytes) {
        if (error) *error = "share file exceeds 16 MiB limit";
        return std::nullopt;
    }
    ShareFileHeader hdr{};
    if (!peek_share_header(blob, &hdr)) {
        if (error) *error = "not a .yss file (bad magic or unsupported version)";
        return std::nullopt;
    }
    if (password.empty()) {
        if (error) *error = "password must not be empty";
        return std::nullopt;
    }

    std::vector<std::uint8_t> encrypted(blob.begin() + kHeaderLen, blob.end());
    basefwx::crypto::SecureBytes plaintext;
    try {
        plaintext.Reset(basefwx::fwxaes::DecryptRaw(encrypted, password));
    } catch (const std::exception& ex) {
        if (error) *error = std::string("decrypt failed (wrong password or corrupted file): ") + ex.what();
        return std::nullopt;
    }

    nlohmann::json j;
    try {
        j = nlohmann::json::parse(plaintext.bytes().begin(),
                                  plaintext.bytes().end());
    } catch (const std::exception& ex) {
        if (error) *error = std::string("payload is not JSON: ") + ex.what();
        return std::nullopt;
    }
    JsonSecretWiper document_wiper(j);

    ShareBundle bundle;
    BundleSecretWiper bundle_wiper(bundle);
    try {
        if (!json_to_bundle(j, &bundle, error)) {
            return std::nullopt;
        }
    } catch (const std::exception& ex) {
        if (error) {
            *error = std::string("malformed share bundle: ") + ex.what();
        }
        return std::nullopt;
    }
    std::optional<ShareBundle> result{std::move(bundle)};
    bundle_wiper.dismiss();
    return result;
}

}  // namespace yume::share
