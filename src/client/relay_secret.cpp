#include "client/relay_secret.hpp"

#include <cctype>
#include <fstream>
#include <stdexcept>
#include <vector>

#if !defined(_WIN32)
#include <sys/stat.h>
#endif

#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
#include <basefwx/crypto.hpp>
#else
#include <openssl/evp.h>
#endif
#include <nlohmann/json.hpp>

#include "util.hpp"

namespace yume::client {

namespace {

constexpr std::size_t kRelaySecretBytes = 32;
constexpr std::size_t kRelayPasswordPbkdf2Iterations = 600000;
constexpr char kRelayKeyFormat[] = "yume-relay-key-v1";
constexpr char kRelaySecretSalt[] = "yume-relay-secret-v1/pbkdf2-sha256";

std::string trim_copy(std::string value) {
    auto is_space = [](unsigned char ch) { return std::isspace(ch) != 0; };
    while (!value.empty() && is_space(static_cast<unsigned char>(value.front()))) {
        value.erase(value.begin());
    }
    while (!value.empty() && is_space(static_cast<unsigned char>(value.back()))) {
        value.pop_back();
    }
    return value;
}

#if !(defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX)
std::vector<unsigned char> pbkdf2_hmac_sha256(const std::string& password,
                                              const unsigned char* salt,
                                              std::size_t salt_len,
                                              int iterations,
                                              std::size_t out_len) {
    std::vector<unsigned char> out(out_len);
    if (PKCS5_PBKDF2_HMAC(password.data(),
                          static_cast<int>(password.size()),
                          salt,
                          static_cast<int>(salt_len),
                          iterations,
                          EVP_sha256(),
                          static_cast<int>(out.size()),
                          out.data()) != 1) {
        throw std::runtime_error("failed to derive relay secret with PBKDF2-HMAC-SHA256");
    }
    return out;
}
#endif

}  // namespace

std::string derive_relay_secret_b64(const std::string& password) {
#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
    basefwx::crypto::Bytes salt(kRelaySecretSalt, kRelaySecretSalt + sizeof(kRelaySecretSalt) - 1);
    const auto secret = basefwx::crypto::Pbkdf2HmacSha256(
        password,
        salt,
        kRelayPasswordPbkdf2Iterations,
        kRelaySecretBytes);
    return yume::util::base64_encode(std::string(secret.begin(), secret.end()));
#else
    const auto secret = pbkdf2_hmac_sha256(
        password,
        reinterpret_cast<const unsigned char*>(kRelaySecretSalt),
        sizeof(kRelaySecretSalt) - 1,
        static_cast<int>(kRelayPasswordPbkdf2Iterations),
        kRelaySecretBytes);
    return yume::util::base64_encode(std::string(secret.begin(), secret.end()));
#endif
}

bool validate_relay_secret_b64(const std::string& relay_secret_b64, std::string* error) {
    if (relay_secret_b64.empty()) {
        if (error) {
            *error = "relay secret is empty";
        }
        return false;
    }
    const std::string raw = yume::util::base64_decode(relay_secret_b64);
    if (raw.size() != kRelaySecretBytes) {
        if (error) {
            *error = "relay secret must decode to 32 bytes";
        }
        return false;
    }
    return true;
}

bool load_relay_secret_file(const std::filesystem::path& path,
                            std::string* relay_secret_b64,
                            std::string* error) {
    if (!relay_secret_b64) {
        if (error) {
            *error = "relay secret output is null";
        }
        return false;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        if (error) {
            *error = "relay key file not found: " + path.string();
        }
        return false;
    }
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (!in.good() && !in.eof()) {
        if (error) {
            *error = "failed to read relay key file: " + path.string();
        }
        return false;
    }
    content = trim_copy(std::move(content));
    if (content.empty()) {
        if (error) {
            *error = "relay key file is empty: " + path.string();
        }
        return false;
    }

    std::string loaded_secret;
    try {
        if (!content.empty() && content.front() == '{') {
            auto json = nlohmann::json::parse(content);
            if (json.value("format", "") != kRelayKeyFormat) {
                if (error) {
                    *error = "unsupported relay key file format: " + path.string();
                }
                return false;
            }
            loaded_secret = json.value("secret_b64", "");
        } else {
            loaded_secret = content;
        }
    } catch (const std::exception& ex) {
        if (error) {
            *error = "failed to parse relay key file " + path.string() + ": " + ex.what();
        }
        return false;
    }

    if (!validate_relay_secret_b64(loaded_secret, error)) {
        if (error && !error->empty()) {
            *error = "invalid relay key file " + path.string() + ": " + *error;
        }
        return false;
    }
    *relay_secret_b64 = loaded_secret;
    return true;
}

bool write_relay_secret_file(const std::filesystem::path& path,
                             const std::string& relay_secret_b64,
                             std::string* error) {
    if (path.empty()) {
        if (error) {
            *error = "relay key file path is empty";
        }
        return false;
    }
    if (!validate_relay_secret_b64(relay_secret_b64, error)) {
        return false;
    }

    std::error_code ec;
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path(), ec);
        if (ec) {
            if (error) {
                *error = "failed to create relay key directory: " + path.parent_path().string();
            }
            return false;
        }
    }

    nlohmann::json json{
        {"format", kRelayKeyFormat},
        {"secret_b64", relay_secret_b64},
        {"secret_bytes", kRelaySecretBytes},
        {"kdf", "pbkdf2-hmac-sha256"},
        {"pbkdf2_iterations", kRelayPasswordPbkdf2Iterations},
        {"generated_at_ms", yume::util::now_ms()},
    };

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        if (error) {
            *error = "failed to open relay key file for writing: " + path.string();
        }
        return false;
    }
    out << json.dump(2) << '\n';
    out.close();
    if (!out) {
        if (error) {
            *error = "failed to write relay key file: " + path.string();
        }
        return false;
    }
#if !defined(_WIN32)
    ::chmod(path.c_str(), 0600);
#endif
    return true;
}

}  // namespace yume::client
