/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/relay/secret.hpp"

#include <cctype>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
#include <basefwx/crypto.hpp>
#else
#include <openssl/evp.h>
#endif
#include <nlohmann/json.hpp>

#include "core/security/secret_file.hpp"
#include "core/security/secure_erase.hpp"
#include "util.hpp"

namespace yume::client {

namespace {

constexpr std::size_t kRelaySecretBytes = 32;
constexpr std::size_t kRelayPasswordPbkdf2Iterations = 600000;
constexpr char kRelayKeyFormat[] = "yume-relay-key-v1";
constexpr char kRelaySecretSalt[] = "yume-relay-secret-v1/pbkdf2-sha256";

void trim_in_place(std::string& value) {
    const auto is_space = [](unsigned char ch) {
        return std::isspace(ch) != 0;
    };
    while (!value.empty() &&
           is_space(static_cast<unsigned char>(value.front()))) {
        value.erase(value.begin());
    }
    while (!value.empty() &&
           is_space(static_cast<unsigned char>(value.back()))) {
        value.pop_back();
    }
}

class StringWiper {
public:
    explicit StringWiper(std::string& value) noexcept : value_(value) {}
    ~StringWiper() { wipe_relay_secret(value_); }
    StringWiper(const StringWiper&) = delete;
    StringWiper& operator=(const StringWiper&) = delete;

private:
    std::string& value_;
};

class BytesWiper {
public:
    explicit BytesWiper(std::vector<std::uint8_t>& value) noexcept
        : value_(value) {}
    ~BytesWiper() { security::secure_erase(value_); }
    BytesWiper(const BytesWiper&) = delete;
    BytesWiper& operator=(const BytesWiper&) = delete;

private:
    std::vector<std::uint8_t>& value_;
};

class RelayJsonWiper {
public:
    explicit RelayJsonWiper(nlohmann::json& value) noexcept : value_(value) {}
    ~RelayJsonWiper() {
        try {
            if (value_.is_object() && value_.contains("secret_b64") &&
                value_["secret_b64"].is_string()) {
                auto& secret = value_["secret_b64"].get_ref<std::string&>();
                wipe_relay_secret(secret);
                value_.erase("secret_b64");
            }
        } catch (...) {
        }
    }
    RelayJsonWiper(const RelayJsonWiper&) = delete;
    RelayJsonWiper& operator=(const RelayJsonWiper&) = delete;

private:
    nlohmann::json& value_;
};

#if !(defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX)
std::vector<std::uint8_t> pbkdf2_hmac_sha256(
        const std::string& password,
        const unsigned char* salt,
        std::size_t salt_len,
        int iterations,
        std::size_t out_len) {
    std::vector<std::uint8_t> out(out_len);
    if (PKCS5_PBKDF2_HMAC(password.data(),
                          static_cast<int>(password.size()),
                          salt,
                          static_cast<int>(salt_len),
                          iterations,
                          EVP_sha256(),
                          static_cast<int>(out.size()),
                          out.data()) != 1) {
        throw std::runtime_error(
            "failed to derive relay secret with PBKDF2-HMAC-SHA256");
    }
    return out;
}
#endif

}  // namespace

void wipe_relay_secret(std::string& value) noexcept {
    try {
        // Reaching capacity() also overwrites bytes retained beyond size()
        // after a move or erase, including ordinary SSO storage.
        value.resize(value.capacity(), '\0');
    } catch (...) {
        // The live range is still overwritten below.
    }
    volatile char* cursor = value.empty() ? nullptr : value.data();
    for (std::size_t i = 0; i < value.size(); ++i) {
        cursor[i] = 0;
    }
    value.clear();
}

std::string derive_relay_secret_b64(const std::string& password) {
#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
    basefwx::crypto::Bytes salt(
        kRelaySecretSalt, kRelaySecretSalt + sizeof(kRelaySecretSalt) - 1);
    auto secret = basefwx::crypto::Pbkdf2HmacSha256(
        password,
        salt,
        kRelayPasswordPbkdf2Iterations,
        kRelaySecretBytes);
#else
    auto secret = pbkdf2_hmac_sha256(
        password,
        reinterpret_cast<const unsigned char*>(kRelaySecretSalt),
        sizeof(kRelaySecretSalt) - 1,
        static_cast<int>(kRelayPasswordPbkdf2Iterations),
        kRelaySecretBytes);
#endif
    BytesWiper secret_wiper{secret};
    std::string raw(secret.begin(), secret.end());
    StringWiper raw_wiper{raw};
    return yume::util::base64_encode(raw);
}

bool validate_relay_secret_b64(const std::string& relay_secret_b64,
                               std::string* error) {
    if (relay_secret_b64.empty()) {
        if (error) *error = "relay secret is empty";
        return false;
    }
    std::string raw = yume::util::base64_decode(relay_secret_b64);
    StringWiper raw_wiper{raw};
    if (raw.size() != kRelaySecretBytes) {
        if (error) *error = "relay secret must decode to 32 bytes";
        return false;
    }
    return true;
}

bool load_relay_secret_file(const std::filesystem::path& path,
                            std::string* relay_secret_b64,
                            std::string* error) {
    if (!relay_secret_b64) {
        if (error) *error = "relay secret output is null";
        return false;
    }

    std::vector<std::uint8_t> file_bytes;
    try {
        file_bytes = security::ReadPrivateKeyFileStrict(path);
    } catch (const std::exception& ex) {
        if (error) {
            *error = "failed to load protected relay key file " +
                path.string() + ": " + ex.what();
        }
        return false;
    }
    BytesWiper file_bytes_wiper{file_bytes};
    std::string content(file_bytes.begin(), file_bytes.end());
    StringWiper content_wiper{content};
    trim_in_place(content);
    if (content.empty()) {
        if (error) *error = "relay key file is empty: " + path.string();
        return false;
    }

    std::string loaded_secret;
    StringWiper loaded_secret_wiper{loaded_secret};
    nlohmann::json json;
    RelayJsonWiper json_wiper{json};
    try {
        if (content.front() == '{') {
            json = nlohmann::json::parse(content);
            if (json.value("format", "") != kRelayKeyFormat) {
                if (error) {
                    *error = "unsupported relay key file format: " +
                        path.string();
                }
                return false;
            }
            loaded_secret = json.value("secret_b64", "");
        } else {
            loaded_secret = content;
        }
    } catch (const std::exception& ex) {
        if (error) {
            *error = "failed to parse relay key file " + path.string() +
                ": " + ex.what();
        }
        return false;
    }

    if (!validate_relay_secret_b64(loaded_secret, error)) {
        if (error && !error->empty()) {
            *error = "invalid relay key file " + path.string() + ": " +
                *error;
        }
        return false;
    }
    wipe_relay_secret(*relay_secret_b64);
    *relay_secret_b64 = std::move(loaded_secret);
    return true;
}

bool write_relay_secret_file(const std::filesystem::path& path,
                             const std::string& relay_secret_b64,
                             std::string* error) {
    if (path.empty()) {
        if (error) *error = "relay key file path is empty";
        return false;
    }
    if (!validate_relay_secret_b64(relay_secret_b64, error)) return false;

    nlohmann::json json{
        {"format", kRelayKeyFormat},
        {"secret_b64", relay_secret_b64},
        {"secret_bytes", kRelaySecretBytes},
        {"kdf", "pbkdf2-hmac-sha256"},
        {"pbkdf2_iterations", kRelayPasswordPbkdf2Iterations},
        {"generated_at_ms", yume::util::now_ms()},
    };
    RelayJsonWiper json_wiper{json};
    std::string serialized = json.dump(2);
    serialized.push_back('\n');
    StringWiper serialized_wiper{serialized};
    std::vector<std::uint8_t> bytes(serialized.begin(), serialized.end());
    BytesWiper bytes_wiper{bytes};
    return security::WriteFileExclusive0600(
        path, std::span<const std::uint8_t>(bytes), error);
}

}  // namespace yume::client
