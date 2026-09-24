/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "modules/share/bundle_file.hpp"

#include <cstring>
#include <exception>

#include <basefwx/constants.hpp>
#include <basefwx/crypto.hpp>
#include <basefwx/fwxaes.hpp>

#include "core/runtime/bounded_file.hpp"
#include "core/security/secret_file.hpp"
#include "core/security/secure_erase.hpp"

namespace yume::share {
namespace {

constexpr char kMagic[] = "YUMESHRE";
constexpr std::size_t kMagicLen = 8;
constexpr std::size_t kHeaderLen = 12;  // magic + version + type + 2 reserved
static_assert(kPasswordMin == basefwx::constants::kShortPasswordMin,
              "the share password minimum must equal BaseFWX's short-password length");

void set_error(std::string* error, const std::string& message) {
    if (error) *error = message;
}

// BaseFWX reads a password that starts with "file://" from that path and
// strips a "password://" prefix. A share password is the literal text a person
// typed, so both prefixes are refused instead of resolved.
bool is_password_reference(const std::string& password) {
    return password.rfind("file://", 0) == 0 || password.rfind("password://", 0) == 0;
}

constexpr char kPasswordReferenceError[] =
    "password must not start with file:// or password://";

}  // namespace

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
            for (auto& item : value.items()) wipe_json_strings(item.value());
        }
    } catch (...) {
        // Cleanup must not throw. The decrypted bytes are guarded separately.
    }
}

bool peek_share_header(const std::vector<std::uint8_t>& blob, ShareFileHeader* out) {
    if (!out) return false;
    if (blob.size() < kHeaderLen) return false;
    if (std::memcmp(blob.data(), kMagic, kMagicLen) != 0) return false;
    out->version = blob[kMagicLen];
    if (out->version != kFormatVersion) return false;
    if (blob[kMagicLen + 1] != static_cast<std::uint8_t>(BundleType::Backup) ||
        blob[kMagicLen + 2] != 0 || blob[kMagicLen + 3] != 0) {
        return false;
    }
    out->type = static_cast<BundleType>(blob[kMagicLen + 1]);
    return true;
}

std::vector<std::uint8_t> seal_share(const nlohmann::json& document,
                                     BundleType type,
                                     const std::string& password,
                                     std::string* error) {
    if (password.size() < kPasswordMin) {
        set_error(error, "password must be at least " + std::to_string(kPasswordMin) +
                             " characters");
        return {};
    }
    if (is_password_reference(password)) {
        set_error(error, kPasswordReferenceError);
        return {};
    }
    if (type != BundleType::Backup) {
        set_error(error, "bundle has an unsupported type");
        return {};
    }

    std::string serialised;
    security::ScopedErase serialised_wiper(serialised);
    try {
        serialised = document.dump();
    } catch (const std::exception& ex) {
        set_error(error, std::string("serialise failed: ") + ex.what());
        return {};
    }
    if (serialised.size() > kMaxShareFileBytes - kHeaderLen) {
        set_error(error, "share payload exceeds 16 MiB limit");
        return {};
    }

    basefwx::crypto::SecureBytes plaintext{
        std::vector<std::uint8_t>(serialised.begin(), serialised.end())};
    // The share-file KDF is a YUME format decision. BaseFWX resolves its
    // default "auto" label through the BASEFWX_USER_KDF environment variable,
    // so the default would let the environment downgrade new files to PBKDF2.
    // Argon2id is a hard BaseFWX build requirement, so this label always
    // resolves. The decoder reads the label from the file.
    basefwx::fwxaes::Options encrypt_options;
    encrypt_options.user_kdf.label = "argon2id";
    std::vector<std::uint8_t> encrypted;
    try {
        encrypted = basefwx::fwxaes::EncryptRaw(plaintext.bytes(), password, encrypt_options);
    } catch (const std::exception& ex) {
        set_error(error, std::string("encrypt failed: ") + ex.what());
        return {};
    }

    std::vector<std::uint8_t> out;
    out.reserve(kHeaderLen + encrypted.size());
    out.insert(out.end(), kMagic, kMagic + kMagicLen);
    out.push_back(kFormatVersion);
    out.push_back(static_cast<std::uint8_t>(type));
    out.push_back(0);
    out.push_back(0);
    out.insert(out.end(), encrypted.begin(), encrypted.end());
    if (out.size() > kMaxShareFileBytes) {
        basefwx::crypto::SecureClear(out);
        set_error(error, "encrypted share file exceeds 16 MiB limit");
        return {};
    }
    return out;
}

std::optional<nlohmann::json> open_share(const std::vector<std::uint8_t>& blob,
                                         const std::string& password,
                                         std::string* error) {
    if (blob.size() > kMaxShareFileBytes) {
        set_error(error, "share file exceeds 16 MiB limit");
        return std::nullopt;
    }
    ShareFileHeader header{};
    if (!peek_share_header(blob, &header)) {
        set_error(error, "not a .yss file (bad magic or unsupported version)");
        return std::nullopt;
    }
    if (password.empty()) {
        set_error(error, "password must not be empty");
        return std::nullopt;
    }
    if (is_password_reference(password)) {
        set_error(error, kPasswordReferenceError);
        return std::nullopt;
    }

    const std::vector<std::uint8_t> encrypted(blob.begin() + kHeaderLen, blob.end());
    basefwx::crypto::SecureBytes plaintext;
    try {
        plaintext.Reset(basefwx::fwxaes::DecryptRaw(encrypted, password));
    } catch (const std::exception& ex) {
        set_error(error, std::string("decrypt failed (wrong password or corrupted file): ") +
                             ex.what());
        return std::nullopt;
    }

    nlohmann::json document;
    try {
        document = nlohmann::json::parse(plaintext.bytes().begin(), plaintext.bytes().end());
    } catch (const std::exception& ex) {
        set_error(error, std::string("payload is not JSON: ") + ex.what());
        return std::nullopt;
    }
    return document;
}

bool read_share_file(const std::filesystem::path& path,
                     std::vector<std::uint8_t>* contents,
                     std::string* error) {
    return runtime::read_file_bounded(path, kMaxShareFileBytes, contents, error);
}

bool write_share_file_exclusive(const std::filesystem::path& path,
                                std::span<const std::uint8_t> contents,
                                std::string* error) {
    if (contents.size() > kMaxShareFileBytes) {
        set_error(error, "share file exceeds 16 MiB limit");
        return false;
    }
    return security::WriteFileExclusive0600(path, contents, error,
                                            security::PrivateParentPolicy::RequireExisting);
}

}  // namespace yume::share
