/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "setup/doctor.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "common/hex.hpp"
#include "common/service_name.hpp"
#include "common/socks5_credentials.hpp"
#include "config/v1/config.hpp"
#include "providers/composite_keys.hpp"
#include "providers/openssl_security_provider.hpp"
#include "providers/ytp1_crypto.hpp"
#include "runtime/cluster_list.hpp"
#include "runtime/cluster_state.hpp"
#include "runtime/egress_limiter.hpp"
#include "runtime/native_credentials.hpp"
#include "setup/files.hpp"
#include "setup/material.hpp"
#include "setup/provision.hpp"
#include "stealth/cover_profile.hpp"
#include "ytp/security.hpp"

namespace yume::setup {
namespace {

namespace fs = std::filesystem;
namespace keys = providers::keys;
namespace v1 = config::v1;
namespace crypto = providers::ytp1_crypto;

constexpr std::size_t kMaxDocumentBytes = v1::kMaxDocumentBytes;
// The native loader's bounds on each egress list file.
constexpr std::size_t kMaxJsonListBytes = std::size_t{16} * 1024U * 1024U;
constexpr std::size_t kMaxVpdbBytes = std::size_t{128} * 1024U * 1024U;
constexpr std::size_t kMaxCountryDatabaseBytes =
    std::size_t{128} * 1024U * 1024U;
constexpr std::size_t kMaxSocksCredentialBytes =
    2U * common::Socks5Credentials::kMaxFieldBytes + 2U;
constexpr std::size_t kMaxAdminIdentities = 4096U;
constexpr std::size_t kMaxJsonDepth = 16U;
constexpr std::size_t kSecretBytes = 32U;
constexpr std::size_t kMinCoverPageCharacters = 256U;
constexpr std::string_view kRejected =
    "OpenSSL rejected the credential material";
constexpr const char* kProperties = crypto::kOpenSslPropertyQuery.data();

using Digest = std::array<std::byte, 32>;
using Services = std::set<std::pair<std::string, std::string>>;

// Thrown to end one check. Every caller that keeps going records it.
struct Failure final {
    Diagnostic diagnostic;
};

[[noreturn]] void fail(std::string pointer, std::string detail) {
    throw Failure{{std::move(pointer), std::move(detail)}};
}

std::string join(const std::string& base, std::string_view token) {
    std::string escaped;
    for (const char ch : token) {
        if (ch == '~') {
            escaped += "~0";
        } else if (ch == '/') {
            escaped += "~1";
        } else {
            escaped += ch;
        }
    }
    return base + "/" + escaped;
}

std::string join(const std::string& base, std::size_t index) {
    return base + "/" + std::to_string(index);
}

fs::path resolve(const fs::path& base, const std::string& reference) {
    const fs::path path(reference);
    return path.is_absolute() ? path : base / path;
}

bool same_file(const struct stat& left, const struct stat& right) noexcept {
    return left.st_dev == right.st_dev && left.st_ino == right.st_ino &&
           left.st_size == right.st_size &&
           left.st_mtim.tv_sec == right.st_mtim.tv_sec &&
           left.st_mtim.tv_nsec == right.st_mtim.tv_nsec &&
           left.st_ctim.tv_sec == right.st_ctim.tv_sec &&
           left.st_ctim.tv_nsec == right.st_ctim.tv_nsec;
}

// The checks that come before reading a file: present, no symlink, regular,
// owner-only when private, and within its bounds.
struct stat checked_status(const fs::path& path, const std::string& pointer,
                           bool private_file, std::size_t maximum) {
    struct stat status{};
    if (::lstat(path.c_str(), &status) != 0) {
        fail(pointer, "referenced file is missing or inaccessible");
    }
    if (S_ISLNK(status.st_mode)) fail(pointer, "symlink files are forbidden");
    if (!S_ISREG(status.st_mode))
        fail(pointer, "must reference a regular file");
    if (private_file && (status.st_mode & 0077U) != 0U) {
        fail(pointer, "group/world permissions are forbidden");
    }
    if (status.st_size <= 0) fail(pointer, "file must not be empty");
    if (static_cast<std::uint64_t>(status.st_size) > maximum) {
        fail(pointer,
             "file exceeds the " + std::to_string(maximum) + "-byte limit");
    }
    return status;
}

class Descriptor final {
public:
    explicit Descriptor(int fd) noexcept : fd_(fd) {}
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    ~Descriptor() {
        if (fd_ >= 0) static_cast<void>(::close(fd_));
    }
    int get() const noexcept { return fd_; }

private:
    int fd_;
};

// Reads a file through the handle whose identity, size and timestamps match
// the path that was checked, before and after the read, so a file replaced
// meanwhile fails closed.
SecretBytes checked_bytes(const fs::path& path, const std::string& pointer,
                          bool private_file = true,
                          std::size_t maximum = kMaxDocumentBytes) {
    const auto before = checked_status(path, pointer, private_file, maximum);
    Descriptor fd(
        ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (fd.get() < 0) fail(pointer, "referenced file is not safely readable");
    struct stat after{};
    if (::fstat(fd.get(), &after) != 0 || !S_ISREG(after.st_mode) ||
        !same_file(before, after)) {
        fail(pointer, "file changed during validation");
    }
    if (private_file && (after.st_mode & 0077U) != 0U) {
        fail(pointer, "group/world permissions are forbidden");
    }
    SecretBytes data(static_cast<std::size_t>(after.st_size));
    std::size_t used = 0;
    while (used < data.size()) {
        const auto count =
            ::read(fd.get(), data.data() + used, data.size() - used);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) fail(pointer, "file changed during validation");
        used += static_cast<std::size_t>(count);
    }
    std::uint8_t extra = 0;
    struct stat final_status{};
    if (::read(fd.get(), &extra, 1) != 0 ||
        ::fstat(fd.get(), &final_status) != 0 ||
        !same_file(after, final_status)) {
        fail(pointer, "file changed during validation");
    }
    return data;
}

void check_list_file(const fs::path& path, const std::string& pointer,
                     std::size_t maximum) {
    static_cast<void>(checked_status(path, pointer, false, maximum));
}

bool pem_space(char ch) noexcept {
    return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\v' ||
           ch == '\f';
}

bool blank(std::string_view text) noexcept {
    return std::all_of(text.begin(), text.end(), pem_space);
}

// PEM objects as "-----BEGIN LABEL-----", whitespace, and the nearest
// matching END line. Exactly count of them, with only whitespace around.
std::vector<std::string_view> pem_objects(std::string_view text,
                                          const std::string& pointer,
                                          std::size_t count) {
    constexpr std::string_view kBegin = "-----BEGIN ";
    constexpr std::string_view kDashes = "-----";
    std::vector<std::pair<std::size_t, std::size_t>> found;
    std::size_t from = 0;
    for (;;) {
        const auto start = text.find(kBegin, from);
        if (start == std::string_view::npos) break;
        from = start + 1U;
        std::size_t cursor = start + kBegin.size();
        const auto label_start = cursor;
        while (cursor < text.size() &&
               ((text[cursor] >= 'A' && text[cursor] <= 'Z') ||
                (text[cursor] >= '0' && text[cursor] <= '9') ||
                (text[cursor] == ' ' && cursor > label_start))) {
            ++cursor;
        }
        const auto label = text.substr(label_start, cursor - label_start);
        if (label.empty() || text.substr(cursor, kDashes.size()) != kDashes)
            continue;
        cursor += kDashes.size();
        if (cursor >= text.size() || !pem_space(text[cursor])) continue;
        // The nearest "-----END LABEL-----" after the whitespace, matched in
        // place.
        constexpr std::string_view kEnd = "-----END ";
        std::size_t finish = cursor + 1U;
        std::size_t stop = std::string_view::npos;
        while ((finish = text.find(kEnd, finish)) != std::string_view::npos) {
            const auto after = finish + kEnd.size();
            if (text.substr(after, label.size()) == label &&
                text.substr(after + label.size(), kDashes.size()) == kDashes) {
                stop = after + label.size() + kDashes.size();
                break;
            }
            ++finish;
        }
        if (stop == std::string_view::npos) continue;
        found.emplace_back(start, stop);
        from = stop;
    }
    if (found.size() != count) {
        fail(pointer,
             "must contain exactly " + std::to_string(count) + " PEM objects");
    }
    std::vector<std::string_view> objects;
    std::size_t position = 0;
    for (const auto& [start, finish] : found) {
        if (!blank(text.substr(position, start - position))) {
            fail(pointer, "contains data outside PEM objects");
        }
        objects.push_back(text.substr(start, finish - start));
        position = finish;
    }
    if (!blank(text.substr(position)))
        fail(pointer, "contains data outside PEM objects");
    return objects;
}

int refuse_password(char*, int, int, void*) noexcept {
    return 0;
}

keys::PkeyPtr read_key(const keys::KeyContext& context, std::string_view pem,
                       bool private_key, const std::string& pointer) {
    using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
    BioPtr input(pem.size() <= static_cast<std::size_t>(INT32_MAX)
                     ? BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()))
                     : nullptr,
                 BIO_free);
    if (input == nullptr) fail(pointer, std::string(kRejected));
    keys::PkeyPtr key(
        private_key
            ? PEM_read_bio_PrivateKey_ex(input.get(), nullptr, refuse_password,
                                         nullptr, context.context(),
                                         kProperties)
            : PEM_read_bio_PUBKEY_ex(input.get(), nullptr, refuse_password,
                                     nullptr, context.context(), kProperties));
    if (key == nullptr) fail(pointer, std::string(kRejected));
    return key;
}

std::vector<std::byte> public_der(EVP_PKEY* key, const std::string& pointer) {
    try {
        return keys::public_der(key);
    } catch (const keys::KeyError&) {
        fail(pointer, std::string(kRejected));
    }
}

// The YTP/1 key algorithms a credential file may hold.
std::string_view algorithm_of(EVP_PKEY* key, const std::string& pointer) {
    for (const auto algorithm :
         {crypto::kEd25519Algorithm, crypto::kMlDsa87Algorithm,
          crypto::kMlKem1024Algorithm}) {
        if (EVP_PKEY_is_a(key, algorithm.data()) == 1) return algorithm;
    }
    fail(pointer, "uses an unsupported key algorithm");
}

// The public keys of a composite identity file, Ed25519 then ML-DSA-87.
std::vector<std::vector<std::byte>> composite_public_ders(
    const keys::KeyContext& context, std::string_view text,
    const std::string& pointer, bool private_key) {
    std::vector<std::vector<std::byte>> ders;
    std::vector<std::string_view> algorithms;
    for (const auto block : pem_objects(text, pointer, 2)) {
        const auto key = read_key(context, block, private_key, pointer);
        ders.push_back(public_der(key.get(), pointer));
        algorithms.push_back(algorithm_of(key.get(), pointer));
    }
    if (algorithms[0] != crypto::kEd25519Algorithm ||
        algorithms[1] != crypto::kMlDsa87Algorithm) {
        fail(pointer, "must be Ed25519 followed by ML-DSA-87");
    }
    return ders;
}

std::vector<std::byte> single_public_der(const keys::KeyContext& context,
                                         std::string_view text,
                                         const std::string& pointer,
                                         bool private_key,
                                         std::string_view algorithm) {
    const auto block = pem_objects(text, pointer, 1).front();
    const auto key = read_key(context, block, private_key, pointer);
    auto der = public_der(key.get(), pointer);
    if (algorithm_of(key.get(), pointer) != algorithm) {
        fail(pointer, "must use " + std::string(algorithm));
    }
    return der;
}

std::string fingerprint(const keys::KeyContext& context,
                        const std::vector<std::vector<std::byte>>& ders) {
    return context.fingerprint(ders[0], ders[1]);
}

bool equal_bytes(std::span<const std::byte> left,
                 std::span<const std::byte> right) {
    return left.size() == right.size() &&
           CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0;
}

bool public_check(const keys::KeyContext& context, EVP_PKEY* key) {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> check(
        EVP_PKEY_CTX_new_from_pkey(context.context(), key, kProperties),
        EVP_PKEY_CTX_free);
    return check != nullptr && EVP_PKEY_public_check(check.get()) == 1;
}

// The leaf key families the browser TLS signature profile offers. This is an
// offline key check: negotiated signature and chain compatibility still
// need a handshake with the TLS provider.
void check_tls_public_key(const keys::KeyContext& context, EVP_PKEY* key,
                          const std::string& pointer) {
    if (!public_check(context, key)) fail(pointer, std::string(kRejected));
    if (EVP_PKEY_is_a(key, "EC") == 1) {
        std::array<char, 64> group{};
        std::size_t size = 0;
        if (EVP_PKEY_get_group_name(key, group.data(), group.size(), &size) ==
            1) {
            const std::string_view name(group.data(), size);
            for (const auto allowed : {"prime256v1", "P-256", "secp384r1",
                                       "P-384", "secp521r1", "P-521"}) {
                if (name == allowed) return;
            }
        }
    } else if ((EVP_PKEY_is_a(key, "RSA") == 1 ||
                EVP_PKEY_is_a(key, "RSA-PSS") == 1) &&
               EVP_PKEY_get_bits(key) >= 2048) {
        return;
    }
    fail(pointer,
         "TLS leaf key must use P-256, P-384, P-521 or RSA of at least 2048 "
         "bits");
}

Digest secret_digest(const keys::KeyContext& context,
                     const SecretBytes& payload, const std::string& pointer) {
    if (payload.size() != kSecretBytes)
        fail(pointer, "must contain exactly 32 binary bytes");
    if (std::all_of(payload.bytes().begin(), payload.bytes().end(),
                    [](std::uint8_t byte) { return byte == 0U; })) {
        fail(pointer, "must not contain the all-zero secret");
    }
    return context.digest({std::as_bytes(payload.bytes())});
}

Json load_json(const SecretBytes& payload, const std::string& pointer) {
    std::vector<std::set<std::string>> scopes;
    bool duplicate = false;
    bool too_deep = false;
    const Json::parser_callback_t guard =
        [&](int depth, Json::parse_event_t event, Json& value) {
            if (event == Json::parse_event_t::object_start ||
                event == Json::parse_event_t::array_start) {
                if (static_cast<std::size_t>(depth) >= kMaxJsonDepth)
                    too_deep = true;
            }
            if (event == Json::parse_event_t::object_start) {
                scopes.emplace_back();
            } else if (event == Json::parse_event_t::object_end) {
                scopes.pop_back();
            } else if (event == Json::parse_event_t::key &&
                       !scopes.back().insert(value.get<std::string>()).second) {
                duplicate = true;
            }
            return !(duplicate || too_deep);
        };
    Json document;
    try {
        document = Json::parse(payload.text(), guard);
    } catch (const Json::parse_error& error) {
        if (!duplicate && !too_deep) {
            fail(pointer,
                 "invalid JSON syntax at byte " + std::to_string(error.byte));
        }
    } catch (const Json::exception&) {
        fail(pointer, "contains invalid or excessively nested JSON");
    }
    if (duplicate) fail(pointer, "contains a duplicate object key");
    if (too_deep) fail(pointer, "JSON nesting exceeds the 16-level limit");
    return document;
}

void closed_object(const Json& value, const std::string& pointer,
                   std::initializer_list<std::string_view> allowed,
                   std::initializer_list<std::string_view> required) {
    if (!value.is_object()) fail(pointer, "must be an object");
    for (const auto& [key, child] : value.items()) {
        static_cast<void>(child);
        if (std::find(allowed.begin(), allowed.end(), key) == allowed.end()) {
            fail(join(pointer, key), "unknown key");
        }
    }
    std::vector<std::string_view> missing(required);
    std::sort(missing.begin(), missing.end());
    for (const auto key : missing) {
        if (!value.contains(key))
            fail(join(pointer, key), "required key is missing");
    }
}

void closed_object(const Json& value, const std::string& pointer,
                   std::initializer_list<std::string_view> keys) {
    closed_object(value, pointer, keys, keys);
}

std::string string_value(const Json& value, const std::string& pointer,
                         std::size_t maximum) {
    if (!value.is_string()) fail(pointer, "must be a string");
    const auto& text = value.get_ref<const std::string&>();
    if (text.size() > maximum) {
        fail(pointer, "must be at most " + std::to_string(maximum) + " bytes");
    }
    return text;
}

std::int64_t integer_value(const Json& value, const std::string& pointer,
                           std::int64_t minimum, std::int64_t maximum) {
    if (!value.is_number_integer()) fail(pointer, "must be an integer");
    if (value.is_number_unsigned() && value.get<std::uint64_t>() > INT64_MAX) {
        fail(pointer, "must be in " + std::to_string(minimum) + ".." +
                          std::to_string(maximum));
    }
    const auto number = value.get<std::int64_t>();
    if (number < minimum || number > maximum) {
        fail(pointer, "must be in " + std::to_string(minimum) + ".." +
                          std::to_string(maximum));
    }
    return number;
}

// A store's file reference, by the rules config::v1 applies to its own.
std::string file_text(const Json& value, const std::string& pointer) {
    auto path = string_value(value, pointer, v1::kMaxFileReferenceBytes);
    if (path.empty()) fail(pointer, "file reference must not be empty");
    if (pem_space(path.front()) || pem_space(path.back())) {
        fail(pointer, "file reference must not have surrounding whitespace");
    }
    if (std::any_of(path.begin(), path.end(), [](unsigned char ch) {
            return ch < 0x20U || ch == 0x7FU;
        })) {
        fail(pointer, "file reference must not contain control characters");
    }
    if (path.starts_with("~") || path.find("://") != std::string::npos) {
        fail(pointer, "file reference must be a literal path");
    }
    bool parent = path == ".";
    std::size_t begin = 0;
    while (!parent) {
        const auto end = path.find_first_of("/\\", begin);
        parent =
            path.substr(begin, end == std::string::npos ? end : end - begin) ==
            "..";
        if (end == std::string::npos) break;
        begin = end + 1U;
    }
    if (parent)
        fail(pointer, "file reference must not contain parent traversal");
    const bool hex_secret = path.size() == 64U &&
                            std::all_of(path.begin(), path.end(), [](char ch) {
                                return (ch >= '0' && ch <= '9') ||
                                       (ch >= 'a' && ch <= 'f') ||
                                       (ch >= 'A' && ch <= 'F');
                            });
    if (path.starts_with("-----BEGIN") || hex_secret) {
        fail(pointer, "inline credential material is forbidden");
    }
    return path;
}

void check_fingerprint_text(const std::string& value,
                            const std::string& pointer) {
    if (value.size() != 64U || !encoding::is_lower_hex(value)) {
        fail(pointer, "must be a lowercase SHA-256 fingerprint");
    }
}

// Reads a store identity file and checks it holds the named fingerprint.
void check_store_identity(const keys::KeyContext& context,
                          const fs::path& directory,
                          const std::string& reference,
                          const std::string& expected,
                          const std::string& pointer) {
    const auto payload = checked_bytes(resolve(directory, reference), pointer);
    const auto ders =
        composite_public_ders(context, payload.text(), pointer, false);
    if (fingerprint(context, ders) != expected) {
        fail(pointer, "identity fingerprint does not match");
    }
}

template <typename Check>
void collect(std::vector<Diagnostic>& diagnostics, Check&& check) {
    try {
        check();
    } catch (const Failure& failure) {
        diagnostics.push_back(failure.diagnostic);
    }
}

std::set<std::string> check_authorized_keys(
    const keys::KeyContext& context, const SecretBytes& payload,
    const fs::path& store_path, const Services& services, bool cluster_member,
    const std::optional<Digest>& admission,
    std::vector<Diagnostic>& diagnostics) {
    const std::string pointer = "/credentials/authorized_keys";
    const auto store = load_json(payload, pointer);
    closed_object(store, pointer, {"schema", "keys"});
    integer_value(store.at("schema"), pointer + "/schema", 1, 1);
    const auto& keys = store.at("keys");
    if (!keys.is_array()) fail(pointer + "/keys", "must be an array");
    if (keys.empty() || keys.size() > providers::kMaxAuthorizedIdentities) {
        fail(pointer + "/keys",
             "must contain 1.." +
                 std::to_string(providers::kMaxAuthorizedIdentities) +
                 " authorized keys");
    }
    std::set<std::string> names;
    std::vector<Digest> psk_digests;
    std::set<std::string> fingerprints;
    const auto directory = store_path.parent_path();
    for (std::size_t index = 0; index < keys.size(); ++index) {
        const auto key_pointer = join(pointer + "/keys", index);
        const auto& entry = keys.at(index);
        closed_object(entry, key_pointer,
                      {"name", "identity", "access_psk", "capabilities",
                       "max_sessions", "weight"},
                      {"name", "identity", "access_psk", "capabilities"});
        if (entry.contains("max_sessions")) {
            // A newer session of this identity replaces the oldest beyond it.
            integer_value(
                entry.at("max_sessions"), key_pointer + "/max_sessions", 1,
                static_cast<std::int64_t>(runtime::kMaxSessionsPerIdentity));
        }
        if (entry.contains("weight")) {
            // The identity's share of limits.max_egress_mbps among busy
            // clients.
            const auto& weight = entry.at("weight");
            using runtime::EgressLimiter;
            if (!weight.is_number() ||
                weight.get<double>() < EgressLimiter::kMinWeight ||
                weight.get<double>() > EgressLimiter::kMaxWeight) {
                fail(key_pointer + "/weight", "must be a number in 0.1..100");
            }
        }
        const auto name =
            string_value(entry.at("name"), key_pointer + "/name", 63);
        if (!valid_name(name))
            fail(key_pointer + "/name", "invalid client name");
        if (!names.insert(name).second)
            fail(key_pointer + "/name", "duplicate client name");

        const auto& identity = entry.at("identity");
        closed_object(identity, key_pointer + "/identity", {"file", "sha256"});
        const auto identity_pointer = key_pointer + "/identity/file";
        const auto identity_reference =
            file_text(identity.at("file"), identity_pointer);
        const auto expected = string_value(
            identity.at("sha256"), key_pointer + "/identity/sha256", 64);
        check_fingerprint_text(expected, key_pointer + "/identity/sha256");
        collect(diagnostics, [&] {
            check_store_identity(context, directory, identity_reference,
                                 expected, identity_pointer);
        });

        const auto& psk = entry.at("access_psk");
        closed_object(psk, key_pointer + "/access_psk", {"file"});
        const auto psk_pointer = key_pointer + "/access_psk/file";
        const auto psk_reference = file_text(psk.at("file"), psk_pointer);
        collect(diagnostics, [&] {
            const auto psk_payload =
                checked_bytes(resolve(directory, psk_reference), psk_pointer);
            const auto digest =
                secret_digest(context, psk_payload, psk_pointer);
            if (std::any_of(psk_digests.begin(), psk_digests.end(),
                            [&](const Digest& other) {
                                return equal_bytes(other, digest);
                            })) {
                fail(psk_pointer,
                     "access PSK is reused by another authorized key");
            }
            if (admission && equal_bytes(*admission, digest)) {
                fail(psk_pointer, "access PSK must differ from admission key");
            }
            psk_digests.push_back(digest);
        });

        if (!fingerprints.insert(expected).second) {
            fail(key_pointer + "/identity/sha256",
                 "identity is reused by another authorized key");
        }

        const auto capabilities_pointer = key_pointer + "/capabilities";
        const auto& capabilities = entry.at("capabilities");
        if (!capabilities.is_array())
            fail(capabilities_pointer, "must be an array");
        if (capabilities.empty() || capabilities.size() > v1::kMaxServices) {
            fail(capabilities_pointer, "must contain 1.." +
                                           std::to_string(v1::kMaxServices) +
                                           " capabilities");
        }
        Services seen;
        for (std::size_t item = 0; item < capabilities.size(); ++item) {
            const auto capability_pointer = join(capabilities_pointer, item);
            const auto& capability = capabilities.at(item);
            closed_object(capability, capability_pointer, {"service", "kind"});
            const auto service = string_value(capability.at("service"),
                                              capability_pointer + "/service",
                                              common::kMaxServiceNameBytes);
            if (!common::valid_service_name(service)) {
                fail(capability_pointer + "/service",
                     "must use lowercase ASCII namespace segments");
            }
            const auto kind = string_value(capability.at("kind"),
                                           capability_pointer + "/kind", 16);
            if (!seen.emplace(service, kind).second) {
                fail(capability_pointer + "/service", "duplicate capability");
            }
            // yume.circuit is the daemon's own packet service, which only a
            // cluster member offers.
            const bool circuit = service == common::kCircuitServiceName &&
                                 kind == "packet" && cluster_member;
            if (!circuit && services.count({service, kind}) == 0U) {
                fail(capability_pointer,
                     "capability does not match a configured service");
            }
        }
    }
    return fingerprints;
}

// The separate second-factor store. Admin is proved by an identity from this
// store in addition to an authorized traffic identity. An identity in both
// stores would satisfy both halves by itself, so overlap is refused. An
// empty store is valid and means the deployment has no administrator.
void check_admin_keys(const keys::KeyContext& context,
                      const SecretBytes& payload, const fs::path& store_path,
                      const std::set<std::string>& authorized,
                      std::vector<Diagnostic>& diagnostics) {
    const std::string pointer = "/credentials/admin_keys";
    const auto store = load_json(payload, pointer);
    closed_object(store, pointer, {"schema", "keys"});
    integer_value(store.at("schema"), pointer + "/schema", 1, 1);
    const auto& keys = store.at("keys");
    if (!keys.is_array()) fail(pointer + "/keys", "must be an array");
    if (keys.size() > kMaxAdminIdentities) {
        fail(pointer + "/keys", "must contain at most " +
                                    std::to_string(kMaxAdminIdentities) +
                                    " admin keys");
    }
    std::set<std::string> names;
    std::set<std::string> fingerprints;
    for (std::size_t index = 0; index < keys.size(); ++index) {
        const auto key_pointer = join(pointer + "/keys", index);
        // No policy metadata lives here on purpose: this store proves a
        // second identity, it never describes what anyone may do.
        const auto& entry = keys.at(index);
        closed_object(entry, key_pointer, {"name", "identity"});
        const auto name =
            string_value(entry.at("name"), key_pointer + "/name", 63);
        if (!valid_name(name))
            fail(key_pointer + "/name", "invalid admin key name");
        if (!names.insert(name).second)
            fail(key_pointer + "/name", "duplicate admin key name");
        const auto& identity = entry.at("identity");
        closed_object(identity, key_pointer + "/identity", {"file", "sha256"});
        const auto identity_pointer = key_pointer + "/identity/file";
        const auto reference = file_text(identity.at("file"), identity_pointer);
        const auto sha_pointer = key_pointer + "/identity/sha256";
        const auto expected =
            string_value(identity.at("sha256"), sha_pointer, 64);
        check_fingerprint_text(expected, sha_pointer);
        if (authorized.count(expected) != 0U) {
            fail(sha_pointer,
                 "admin identity must not also appear in authorized_keys");
        }
        if (!fingerprints.insert(expected).second) {
            fail(sha_pointer, "identity is reused by another admin key");
        }
        collect(diagnostics, [&] {
            check_store_identity(context, store_path.parent_path(), reference,
                                 expected, identity_pointer);
        });
    }
}

X509Ptr first_certificate(const keys::KeyContext& context,
                          const SecretBytes& payload,
                          const std::string& pointer) {
    auto certificates = read_certificates(context, payload.text());
    if (certificates.empty() ||
        !certificate_current(certificates.front().get())) {
        fail(pointer, std::string(kRejected));
    }
    return std::move(certificates.front());
}

std::vector<std::byte> certificate_public_der(const keys::KeyContext& context,
                                              X509* certificate,
                                              const std::string& pointer) {
    EVP_PKEY* key = X509_get0_pubkey(certificate);
    if (key == nullptr) fail(pointer, std::string(kRejected));
    check_tls_public_key(context, key, pointer);
    return public_der(key, pointer);
}

void check_certificate_and_key(const keys::KeyContext& context,
                               const SecretBytes& certificate,
                               const SecretBytes& key,
                               const SecretBytes& trust) {
    const std::string certificate_pointer = "/credentials/tls_certificate";
    const std::string key_pointer = "/credentials/tls_key";
    const std::string trust_pointer = "/credentials/tls_certificate/trust";
    const auto leaf =
        first_certificate(context, certificate, certificate_pointer);
    static_cast<void>(first_certificate(context, trust, trust_pointer));
    const auto certificate_der =
        certificate_public_der(context, leaf.get(), certificate_pointer);
    const auto block = pem_objects(key.text(), key_pointer, 1).front();
    const auto private_key = read_key(context, block, true, key_pointer);
    check_tls_public_key(context, private_key.get(), key_pointer);
    const auto key_der = public_der(private_key.get(), key_pointer);
    if (!equal_bytes(certificate_der, key_der)) {
        fail(key_pointer, "TLS certificate and private key do not match");
    }
    const auto anchors = read_certificates(context, trust.text());
    if (!verify_server_certificate(context, leaf.get(), anchors)) {
        fail(certificate_pointer, std::string(kRejected));
    }
}

// A trust anchor is not a TLS leaf or a composite YTP identity. X.509 chain
// validation enforces its signature and security policy.
void check_trust(const keys::KeyContext& context, const SecretBytes& payload,
                 const std::string& pointer) {
    const auto anchor = first_certificate(context, payload, pointer);
    EVP_PKEY* key = X509_get0_pubkey(anchor.get());
    if (key == nullptr || !public_check(context, key))
        fail(pointer, std::string(kRejected));
}

fs::path companion_public_path(const fs::path& private_path) {
    auto name = private_path.filename().string();
    if (name.ends_with(".pem")) name.resize(name.size() - 4U);
    return private_path.parent_path() / (name + ".pub.pem");
}

void check_composite_pair(const keys::KeyContext& context,
                          const SecretBytes& private_payload,
                          const fs::path& private_path,
                          std::vector<Diagnostic>& diagnostics) {
    const std::string pointer = "/credentials/composite_key";
    const std::string public_pointer = pointer + "/public";
    std::optional<SecretBytes> public_payload;
    collect(diagnostics, [&] {
        public_payload =
            checked_bytes(companion_public_path(private_path), public_pointer);
    });
    if (!public_payload) return;
    const auto private_ders =
        composite_public_ders(context, private_payload.text(), pointer, true);
    const auto public_ders = composite_public_ders(
        context, public_payload->text(), public_pointer, false);
    if (!equal_bytes(private_ders[0], public_ders[0]) ||
        !equal_bytes(private_ders[1], public_ders[1])) {
        fail(public_pointer, "does not match the composite private key");
    }
}

// Characters, not bytes, as the page's length rule counts them.
std::size_t utf8_characters(std::string_view text) {
    return static_cast<std::size_t>(
        std::count_if(text.begin(), text.end(), [](char ch) {
            return (static_cast<unsigned char>(ch) & 0xC0U) != 0x80U;
        }));
}

bool valid_utf8(std::string_view text) {
    try {
        static_cast<void>(Json(std::string(text)).dump());
        return true;
    } catch (const Json::exception&) {
        return false;
    }
}

void check_cover(const fs::path& base, const v1::StaticCover& cover,
                 std::vector<Diagnostic>& diagnostics) {
    const std::string pointer = "/cover/root";
    const auto root = resolve(base, cover.root().path());
    struct stat status{};
    if (::lstat(root.c_str(), &status) != 0) {
        diagnostics.push_back({pointer, "cover root is inaccessible"});
        return;
    }
    if (S_ISLNK(status.st_mode)) {
        diagnostics.push_back({pointer, "cover root must not be a symlink"});
        return;
    }
    if (!S_ISDIR(status.st_mode)) {
        diagnostics.push_back({pointer, "cover root must be a directory"});
        return;
    }
    if (::access(root.c_str(), R_OK | X_OK) != 0) {
        diagnostics.push_back({pointer, "cover root is not readable"});
        return;
    }
    for (const auto* filename : {"index.html", "404.html"}) {
        const auto page_pointer = pointer + "/" + filename;
        collect(diagnostics, [&] {
            const auto page =
                checked_bytes(root / filename, page_pointer, false);
            if (!valid_utf8(page.text()))
                fail(page_pointer, "must be UTF-8 HTML");
            std::string html(page.text());
            std::transform(html.begin(), html.end(), html.begin(), [](char ch) {
                return ch >= 'A' && ch <= 'Z'
                           ? static_cast<char>(ch - 'A' + 'a')
                           : ch;
            });
            if (utf8_characters(html) < kMinCoverPageCharacters ||
                html.find("<!doctype html>") == std::string::npos ||
                html.find("<html") == std::string::npos ||
                html.find("<body") == std::string::npos) {
                fail(page_pointer, "must be a complete static HTML cover page");
            }
            if (html.find("yume") != std::string::npos) {
                fail(page_pointer,
                     "must not expose a YUME-specific public marker");
            }
        });
    }
    const auto* profile = cover_profile::find_by_id(cover.profile());
    if (profile == nullptr) return;
    for (const auto& asset : profile->assets) {
        const auto asset_pointer = pointer + std::string(asset.path);
        collect(diagnostics, [&] {
            const fs::path relative(std::string(asset.path).substr(1));
            fs::path parent = root;
            for (const auto& component : relative.parent_path()) {
                parent /= component;
                struct stat directory{};
                if (::lstat(parent.c_str(), &directory) != 0) {
                    fail(asset_pointer, "asset parent is inaccessible");
                }
                if (S_ISLNK(directory.st_mode) || !S_ISDIR(directory.st_mode)) {
                    fail(asset_pointer,
                         "asset parents must be ordinary directories");
                }
            }
            static_cast<void>(
                checked_bytes(root / relative, asset_pointer, false));
        });
    }
}

std::string kind_text(v1::ServiceKind kind) {
    return kind == v1::ServiceKind::Stream ? "stream" : "packet";
}

// Each egress list file a direct adapter names, with its pointer and bound.
struct ListFile final {
    std::string pointer;
    std::string reference;
    std::size_t maximum;
};

std::vector<ListFile> list_files(const v1::Config& config) {
    std::vector<ListFile> files;
    for (std::size_t index = 0; index < config.adapters().size(); ++index) {
        const v1::DestinationPolicy* policy = nullptr;
        if (const auto* tcp =
                std::get_if<v1::DirectTcpAdapter>(&config.adapters()[index])) {
            policy = &tcp->destinations();
        } else if (const auto* udp = std::get_if<v1::DirectUdpAdapter>(
                       &config.adapters()[index])) {
            policy = &udp->destinations();
        }
        if (policy == nullptr) continue;
        const auto base = join("/adapters", index) + "/destinations";
        for (std::size_t item = 0; item < policy->lists().size(); ++item) {
            const auto& list = policy->lists()[item];
            files.push_back({join(base + "/lists", item) + "/file",
                             list.file().path(),
                             list.format() == v1::DestinationListFormat::Json
                                 ? kMaxJsonListBytes
                                 : kMaxVpdbBytes});
        }
        if (policy->country_database()) {
            files.push_back({base + "/country_database/file",
                             policy->country_database()->path(),
                             kMaxCountryDatabaseBytes});
        }
    }
    return files;
}

void check_socks5_credentials(const SecretBytes& payload,
                              const std::string& pointer) {
    const auto text = payload.text();
    if (text.find('\r') != std::string_view::npos ||
        text.find('\0') != std::string_view::npos) {
        fail(pointer,
             "SOCKS5 proxy credentials must not contain a carriage return or "
             "NUL");
    }
    const auto line_end = text.find('\n');
    if (line_end == std::string_view::npos) {
        fail(pointer,
             "SOCKS5 proxy credentials need a username line and a password "
             "line");
    }
    auto end = text.size();
    if (end > line_end + 1U && text[end - 1U] == '\n') --end;
    if (text.substr(line_end + 1U, end - line_end - 1U).find('\n') !=
        std::string_view::npos) {
        fail(pointer,
             "SOCKS5 proxy credentials hold only a username line and a "
             "password line");
    }
    const auto password = end - line_end - 1U;
    if (line_end < 1U || line_end > common::Socks5Credentials::kMaxFieldBytes ||
        password < 1U || password > common::Socks5Credentials::kMaxFieldBytes) {
        fail(pointer,
             "SOCKS5 proxy username and password need 1 to 255 bytes each");
    }
}

// A cluster's or circuits section's files, as yumed's loader opens them.
// The state file may be absent, but its directory must exist.
void check_section_file(const fs::path& base, const std::string& section,
                        const std::string& name, const std::string& reference,
                        std::size_t maximum,
                        std::vector<Diagnostic>& diagnostics) {
    collect(diagnostics, [&] {
        const auto path = resolve(base, reference);
        const auto pointer = "/" + section + "/" + name;
        if (name == "state") {
            if (!directory_at(path.parent_path()))
                fail(pointer, "its directory does not exist");
            if (!exists_no_follow(path)) return;
        }
        static_cast<void>(checked_bytes(path, pointer, true, maximum));
    });
}

std::string preset_of(const v1::ResourceLimits& limits) {
    const Json tuning{
        {"max_queued_bytes", limits.max_queued_bytes()},
        {"max_epoch_bytes", limits.max_epoch_bytes()},
        {"credit_returns_per_window", limits.credit_returns_per_window()},
        {"idle_epoch_rotation", limits.idle_epoch_rotation()},
    };
    for (const auto& preset : presets()) {
        if (preset.limits == tuning) return preset.id;
    }
    return "custom";
}

std::vector<Diagnostic> check_files(const v1::Config& config,
                                    const fs::path& base) {
    std::vector<Diagnostic> diagnostics;
    // yumed parses list contents when it starts or validates. The doctor
    // checks that each file is one the loader would open.
    for (const auto& file : list_files(config)) {
        collect(diagnostics, [&] {
            check_list_file(resolve(base, file.reference), file.pointer,
                            file.maximum);
        });
    }
    if (const auto* client =
            std::get_if<v1::ClientEndpoint>(&config.endpoint());
        client != nullptr && client->socks5_proxy() &&
        client->socks5_proxy()->credentials()) {
        const std::string pointer = "/endpoint/socks5_proxy/credentials/file";
        collect(diagnostics, [&] {
            const auto payload = checked_bytes(
                resolve(base, client->socks5_proxy()->credentials()->path()),
                pointer, true, kMaxSocksCredentialBytes);
            check_socks5_credentials(payload, pointer);
        });
    }
    // yumed verifies the list's signature and the peer store when it starts
    // or validates. These files are checked as the loader would open them.
    constexpr std::size_t kSignatureBytes = ytp1::kCompositeSignatureSize;
    if (const auto& cluster = config.cluster()) {
        const std::array<std::tuple<std::string, std::string, std::size_t>, 7>
            files{{
                {"list", cluster->list.path(), runtime::cluster::kMaxListBytes},
                {"operator_key", cluster->operator_key.path(),
                 kMaxDocumentBytes},
                {"peers", cluster->peers.path(), kMaxDocumentBytes},
                {"routes", cluster->routes.path(),
                 runtime::cluster::kMaxListBytes},
                {"routes_signature", cluster->routes_signature.path(),
                 kSignatureBytes},
                {"signature", cluster->signature.path(), kSignatureBytes},
                {"state", cluster->state.path(),
                 runtime::cluster::kMaxStateBytes},
            }};
        for (const auto& [name, reference, maximum] : files) {
            check_section_file(base, "cluster", name, reference, maximum,
                               diagnostics);
        }
    }
    if (const auto& circuits = config.circuits()) {
        const std::array<std::tuple<std::string, std::string, std::size_t>, 4>
            files{{
                {"operator_key", circuits->operator_key.path(),
                 kMaxDocumentBytes},
                {"routes", circuits->routes.path(),
                 runtime::cluster::kMaxListBytes},
                {"routes_signature", circuits->routes_signature.path(),
                 kSignatureBytes},
                {"state", circuits->state.path(),
                 runtime::cluster::kMaxStateBytes},
            }};
        for (const auto& [name, reference, maximum] : files) {
            check_section_file(base, "circuits", name, reference, maximum,
                               diagnostics);
        }
    }

    std::vector<std::pair<std::string, std::string>> references;
    if (const auto* client =
            std::get_if<v1::ClientCredentials>(&config.credentials())) {
        references = {{"composite_key", client->composite_key().path()},
                      {"access_psk", client->access_psk().path()},
                      {"admission_key", client->admission_key().path()},
                      {"server_trust", client->server_trust().path()},
                      {"server_identity", client->server_identity().path()},
                      {"server_mlkem", client->server_mlkem().path()}};
    } else {
        const auto& server =
            std::get<v1::ServerCredentials>(config.credentials());
        references = {{"composite_key", server.composite_key().path()},
                      {"authorized_keys", server.authorized_keys().path()},
                      {"admin_keys", server.admin_keys().path()},
                      {"tls_certificate", server.tls_certificate().path()},
                      {"tls_key", server.tls_key().path()},
                      {"admission_key", server.admission_key().path()},
                      {"mlkem_key", server.mlkem_key().path()}};
    }
    std::map<std::string, fs::path> paths;
    std::map<std::string, SecretBytes> payloads;
    for (const auto& [name, reference] : references) {
        paths[name] = resolve(base, reference);
        collect(diagnostics, [&] {
            payloads.emplace(
                name, checked_bytes(paths[name], "/credentials/" + name));
        });
    }
    const auto* cover = std::get_if<v1::StaticCover>(&config.cover());

    std::optional<keys::KeyContext> context;
    try {
        context.emplace();
    } catch (const keys::KeyError&) {
        diagnostics.push_back(
            {"/compatibility/crypto_backend", "OpenSSL is unavailable"});
        if (cover != nullptr) check_cover(base, *cover, diagnostics);
        return diagnostics;
    }
    const auto payload = [&payloads](const char* name) -> const SecretBytes* {
        const auto found = payloads.find(name);
        return found == payloads.end() ? nullptr : &found->second;
    };

    if (const auto* composite = payload("composite_key")) {
        collect(diagnostics, [&] {
            check_composite_pair(*context, *composite, paths["composite_key"],
                                 diagnostics);
        });
    }

    if (config.role() == v1::Role::Client) {
        std::optional<Digest> access;
        if (const auto* psk = payload("access_psk")) {
            collect(diagnostics, [&] {
                access =
                    secret_digest(*context, *psk, "/credentials/access_psk");
            });
        }
        if (const auto* admission = payload("admission_key")) {
            collect(diagnostics, [&] {
                const auto digest = secret_digest(*context, *admission,
                                                  "/credentials/admission_key");
                if (access && equal_bytes(*access, digest)) {
                    fail("/credentials/admission_key",
                         "must differ from the per-identity access PSK");
                }
            });
        }
        if (const auto* trust = payload("server_trust")) {
            collect(diagnostics, [&] {
                check_trust(*context, *trust, "/credentials/server_trust");
            });
        }
        if (const auto* identity = payload("server_identity")) {
            collect(diagnostics, [&] {
                static_cast<void>(composite_public_ders(
                    *context, identity->text(), "/credentials/server_identity",
                    false));
            });
        }
        if (const auto* mlkem = payload("server_mlkem")) {
            collect(diagnostics, [&] {
                static_cast<void>(single_public_der(
                    *context, mlkem->text(), "/credentials/server_mlkem", false,
                    crypto::kMlKem1024Algorithm));
            });
        }
        return diagnostics;
    }

    std::optional<Digest> admission;
    if (const auto* key = payload("admission_key")) {
        collect(diagnostics, [&] {
            admission =
                secret_digest(*context, *key, "/credentials/admission_key");
        });
    }
    if (const auto* mlkem = payload("mlkem_key")) {
        collect(diagnostics, [&] {
            const std::string public_pointer = "/credentials/mlkem_key/public";
            const auto private_der = single_public_der(
                *context, mlkem->text(), "/credentials/mlkem_key", true,
                crypto::kMlKem1024Algorithm);
            const auto public_payload = checked_bytes(
                paths["mlkem_key"].parent_path() / "server-mlkem.pub.pem",
                public_pointer);
            const auto public_key = single_public_der(
                *context, public_payload.text(), public_pointer, false,
                crypto::kMlKem1024Algorithm);
            if (!equal_bytes(private_der, public_key)) {
                fail(public_pointer, "does not match the ML-KEM private key");
            }
        });
    }
    const auto* certificate = payload("tls_certificate");
    const auto* tls_key = payload("tls_key");
    if (certificate != nullptr && tls_key != nullptr) {
        collect(diagnostics, [&] {
            const auto trust = checked_bytes(
                paths["tls_certificate"].parent_path() / "server-trust.pem",
                "/credentials/tls_certificate/trust");
            check_certificate_and_key(*context, *certificate, *tls_key, trust);
        });
    }
    Services services;
    for (const auto& service : config.services()) {
        services.emplace(service.name(), kind_text(service.kind()));
    }
    std::set<std::string> authorized;
    if (const auto* store = payload("authorized_keys")) {
        collect(diagnostics, [&] {
            authorized = check_authorized_keys(
                *context, *store, paths["authorized_keys"], services,
                config.cluster().has_value(), admission, diagnostics);
        });
    }
    if (const auto* store = payload("admin_keys")) {
        collect(diagnostics, [&] {
            check_admin_keys(*context, *store, paths["admin_keys"], authorized,
                             diagnostics);
        });
    }
    if (cover != nullptr) check_cover(base, *cover, diagnostics);
    return diagnostics;
}

}  // namespace

DoctorReport diagnose(const fs::path& config_path) {
    DoctorReport report;
    std::optional<v1::Config> config;
    try {
        const auto payload = checked_bytes(config_path, "/config");
        config.emplace(v1::ParseJson(payload.text()));
    } catch (const Failure& failure) {
        report.diagnostics.push_back(failure.diagnostic);
        return report;
    } catch (const v1::ValidationError& error) {
        report.diagnostics.push_back(
            {error.json_pointer().empty() ? "/" : error.json_pointer(),
             error.detail()});
        return report;
    }
    report.diagnostics = check_files(*config, config_path.parent_path());
    report.preset = preset_of(config->limits());
    return report;
}

}  // namespace yume::setup
