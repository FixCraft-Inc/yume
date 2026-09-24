/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace yume::share {

// A .yss ("yume secure store") file:
//
//   magic[8] "YUMESHRE" | version[1] = 1 | bundle type[1] | reserved[2] = 0 |
//   BaseFWX FwxAES blob
//
// The FwxAES blob holds a JSON document under AES-GCM. Its key is wrapped
// under a key that Argon2id derives from the password, so a wrong password
// fails at a tag check. Nothing in the document can be read without the
// password, but the file is not disguised: the header above, the FwxAES header
// with its KDF label, salt and nonce, and the ciphertext length are plaintext.
// A reader learns that the file is a YUME bundle and roughly how large its
// document is. Transport v2 kept its client settings in this container. A
// schema-1 kit import format defines its own document on top of it.
inline constexpr std::uint8_t kFormatVersion = 1;
// BaseFWX raises its KDF cost for shorter passwords. Sealing refuses them
// before the KDF runs.
inline constexpr std::size_t kPasswordMin = 12;
inline constexpr std::size_t kMaxShareFileBytes = 16U * 1024U * 1024U;

enum class BundleType : std::uint8_t {
    // A user's own settings and private keys, moved to another device.
    Backup = 0,
};

struct ShareFileHeader {
    std::uint8_t version{0};
    BundleType type{BundleType::Backup};
};

// Reads the plaintext header without decrypting. False unless the magic, the
// version, a known type and zero reserved bytes are all present.
bool peek_share_header(const std::vector<std::uint8_t>& blob, ShareFileHeader* out);

// Encrypts the document into complete file contents. Every string in the
// document counts as a secret. The finished serialisation is wiped on every
// path. The smaller buffers it outgrew and copies inside BaseFWX are not. The
// key always comes from Argon2id, whatever BASEFWX_USER_KDF says. A password
// is literal text, so one that starts with file:// or password:// is refused
// rather than resolved by BaseFWX. Returns an empty vector and sets *error on
// failure.
std::vector<std::uint8_t> seal_share(const nlohmann::json& document,
                                     BundleType type,
                                     const std::string& password,
                                     std::string* error);

// Decrypts and parses file contents. Returns nullopt with a one-line message
// for a bad header, a refused password, a wrong password, corrupted data or a
// payload that is not JSON. The decrypted bytes are wiped. The caller owns the
// document and wipes it, for example with JsonSecretWiper. The JSON parser's
// own buffers are not wiped.
std::optional<nlohmann::json> open_share(const std::vector<std::uint8_t>& blob,
                                         const std::string& password,
                                         std::string* error);

// Wipes every string value in the document, at any depth. Object keys are
// not wiped, so secrets belong in values. Never throws.
void wipe_json_strings(nlohmann::json& value) noexcept;

// Wipes a document's string values when it leaves scope.
class JsonSecretWiper {
public:
    explicit JsonSecretWiper(nlohmann::json& document) noexcept : document_(document) {}
    JsonSecretWiper(const JsonSecretWiper&) = delete;
    JsonSecretWiper& operator=(const JsonSecretWiper&) = delete;
    ~JsonSecretWiper() { wipe_json_strings(document_); }

private:
    nlohmann::json& document_;
};

// A bounded read that never follows the final path component.
bool read_share_file(const std::filesystem::path& path,
                     std::vector<std::uint8_t>* contents,
                     std::string* error);
// Creates a new owner-only file in an existing directory, refuses to replace
// anything, flushes before reporting success and removes a partial file.
bool write_share_file_exclusive(const std::filesystem::path& path,
                                std::span<const std::uint8_t> contents,
                                std::string* error);

}  // namespace yume::share
