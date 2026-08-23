/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "facade/keys/keys.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <limits>
#include <memory>
#include <sstream>
#include <string_view>
#include <system_error>

#if defined(_WIN32)
#  ifndef NOMINMAX
#    define NOMINMAX
#  endif
#  include <windows.h>
#  include <io.h>
#  include <fcntl.h>
#  include <sys/stat.h>
#else
#  include <fcntl.h>
#  include <sys/stat.h>
#  include <unistd.h>
#endif

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <nlohmann/json.hpp>

#include "core/security/crypto.hpp"
#include "core/runtime/atomic_file.hpp"
#include "core/runtime/file_transaction_lock.hpp"
#include "core/security/secure_erase.hpp"
#include "core/security/inner_crypto.hpp"
#include "core/security/secret_file.hpp"
#include "server/auth/auth.hpp"
#include "server/auth/auth_metadata_json.hpp"
#include "server/federation/types.hpp"

namespace yume::facade::keys {

namespace {

using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using BIO_ptr      = std::unique_ptr<BIO,      decltype(&BIO_free)>;

struct OpenSSLFreeDeleter {
    void operator()(unsigned char* p) const noexcept { OPENSSL_free(p); }
};
using OpenSSLBuf = std::unique_ptr<unsigned char, OpenSSLFreeDeleter>;

class BytesWiper {
public:
    explicit BytesWiper(crypto::Bytes& bytes) noexcept : bytes_(bytes) {}
    ~BytesWiper() { security::secure_erase(bytes_); }

    BytesWiper(const BytesWiper&) = delete;
    BytesWiper& operator=(const BytesWiper&) = delete;

private:
    crypto::Bytes& bytes_;
};

constexpr std::uintmax_t kMaximumKeyStoreBytes = 64U * 1024U * 1024U;
constexpr std::uintmax_t kMaximumMetadataBytes = 16U * 1024U * 1024U;

bool resource_paths_alias(const std::filesystem::path& lhs,
                          const std::filesystem::path& rhs) {
    if (lhs.empty() || rhs.empty()) return false;
    std::error_code path_error;
    if (std::filesystem::equivalent(lhs, rhs, path_error)) return true;

    path_error.clear();
    const auto absolute_lhs = std::filesystem::absolute(lhs, path_error);
    if (path_error) return lhs == rhs;
    const auto canonical_lhs =
        std::filesystem::weakly_canonical(absolute_lhs, path_error);
    if (path_error) return lhs == rhs;
    const auto absolute_rhs = std::filesystem::absolute(rhs, path_error);
    if (path_error) return lhs == rhs;
    const auto canonical_rhs =
        std::filesystem::weakly_canonical(absolute_rhs, path_error);
    if (path_error) return lhs == rhs;
#if defined(_WIN32)
    return CompareStringOrdinal(canonical_lhs.c_str(), -1,
                                canonical_rhs.c_str(), -1, TRUE) ==
           CSTR_EQUAL;
#else
    return canonical_lhs == canonical_rhs;
#endif
}

struct ParsedIdentity {
    crypto::Bytes canonical;
    std::string pem;
    std::string fingerprint;
};

bool read_bounded_file(const std::filesystem::path& path,
                       std::uintmax_t maximum_bytes,
                       bool allow_missing,
                       std::string* contents,
                       bool* existed,
                       std::string* error) {
    if (contents) contents->clear();
    if (existed) *existed = false;
    std::error_code status_error;
    const bool exists = std::filesystem::exists(path, status_error);
    if (status_error) {
        if (error) {
            *error = "cannot inspect '" + path.string() + "': " +
                     status_error.message();
        }
        return false;
    }
    if (!exists) {
        if (allow_missing) return true;
        if (error) *error = "file does not exist: " + path.string();
        return false;
    }
    if (existed) *existed = true;

    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        if (error) *error = "cannot open '" + path.string() + "'";
        return false;
    }
    const std::streamoff size = input.tellg();
    if (size < 0 || static_cast<std::uintmax_t>(size) > maximum_bytes) {
        if (error) *error = "file is too large: " + path.string();
        return false;
    }
    std::string value(static_cast<std::size_t>(size), '\0');
    input.seekg(0);
    if (size != 0 &&
        !input.read(value.data(), static_cast<std::streamsize>(size))) {
        if (error) *error = "cannot read '" + path.string() + "'";
        return false;
    }
    if (input.bad()) {
        if (error) *error = "cannot finish reading '" + path.string() + "'";
        return false;
    }
    if (contents) *contents = std::move(value);
    return true;
}

bool is_pem_whitespace(char value) noexcept {
    return value == ' ' || value == '\t' || value == '\r' || value == '\n';
}

std::optional<std::string_view> take_public_pem_block(
    std::string_view contents,
    std::size_t* cursor,
    std::string* error) {
    while (*cursor < contents.size() && is_pem_whitespace(contents[*cursor])) {
        ++*cursor;
    }
    if (*cursor == contents.size()) return std::nullopt;

    static constexpr std::string_view kBegin = "-----BEGIN PUBLIC KEY-----";
    static constexpr std::string_view kEnd = "-----END PUBLIC KEY-----";
    if (!contents.substr(*cursor).starts_with(kBegin)) {
        if (error) *error = "authorized key store contains non-PEM data";
        return std::nullopt;
    }
    const std::size_t start = *cursor;
    const std::size_t end = contents.find(kEnd, start + kBegin.size());
    if (end == std::string_view::npos) {
        if (error) {
            *error = "authorized key store contains an unterminated PEM block";
        }
        return std::nullopt;
    }
    *cursor = end + kEnd.size();
    if (*cursor < contents.size() && !is_pem_whitespace(contents[*cursor])) {
        if (error) {
            *error = "authorized key store has trailing data after a PEM block";
        }
        return std::nullopt;
    }
    return contents.substr(start, *cursor - start);
}

bool parse_identity_store(std::string_view contents,
                          std::vector<ParsedIdentity>* identities,
                          std::string* error) {
    if (!identities) return false;
    identities->clear();
    if (error) error->clear();
    std::size_t cursor = 0;
    while (true) {
        const auto classical = take_public_pem_block(contents, &cursor, error);
        if (!classical.has_value()) {
            if (cursor == contents.size()) return true;
            return false;
        }
        const auto pq = take_public_pem_block(contents, &cursor, error);
        if (!pq.has_value()) {
            if (error && error->empty()) {
                *error = "authorized key store contains an incomplete "
                         "composite identity";
            }
            return false;
        }
        crypto::Bytes bundle(classical->begin(), classical->end());
        bundle.push_back('\n');
        bundle.insert(bundle.end(), pq->begin(), pq->end());
        auto composite = crypto::parse_composite_identity(bundle);
        if (!composite.valid()) {
            if (error) {
                *error = "every authorized entry must be an Ed25519 public "
                         "key followed by an ML-DSA-87 public key";
            }
            return false;
        }
        ParsedIdentity identity;
        identity.canonical = crypto::composite_canonical_encoding(composite);
        identity.fingerprint =
            crypto::composite_fingerprint_from_canonical(identity.canonical);
        const auto normalized = crypto::encode_composite_identity(
            composite.classical.get(), composite.pq.get());
        identity.pem.assign(normalized.begin(), normalized.end());
        if (identity.pem.empty() || identity.pem.back() != '\n') {
            identity.pem.push_back('\n');
        }
        identities->push_back(std::move(identity));
    }
}

bool load_identity_store(const std::filesystem::path& path,
                         bool allow_missing,
                         std::vector<ParsedIdentity>* identities,
                         std::string* error,
                         std::string* original_contents = nullptr,
                         bool* existed = nullptr) {
    if (original_contents) original_contents->clear();
    std::string contents;
    if (!read_bounded_file(path, kMaximumKeyStoreBytes, allow_missing,
                           &contents, existed, error) ||
        !parse_identity_store(contents, identities, error)) {
        return false;
    }
    if (original_contents) *original_contents = std::move(contents);
    return true;
}

std::string serialize_identity_store(
    const std::vector<ParsedIdentity>& identities,
    std::optional<std::size_t> skip = std::nullopt) {
    std::string serialized;
    for (std::size_t i = 0; i < identities.size(); ++i) {
        if (skip.has_value() && *skip == i) continue;
        serialized += identities[i].pem;
    }
    return serialized;
}

bool load_metadata(const std::filesystem::path& path,
                   bool allow_missing,
                   nlohmann::json* metadata,
                   std::string* error,
                   std::string* original_contents = nullptr,
                   bool* existed = nullptr) {
    if (!metadata) return false;
    if (original_contents) original_contents->clear();
    std::string contents;
    bool file_existed = false;
    if (!read_bounded_file(path, kMaximumMetadataBytes, allow_missing,
                           &contents, &file_existed, error)) {
        return false;
    }
    if (existed) *existed = file_existed;
    if (!file_existed) {
        *metadata = nlohmann::json::object();
        return true;
    }
    try {
        *metadata = nlohmann::json::parse(contents);
    } catch (const std::exception& ex) {
        if (error) {
            *error = "cannot parse JSON file '" + path.string() + "': " +
                     ex.what();
        }
        return false;
    }
    if (!server::validate_auth_metadata_json_types(*metadata, error)) {
        return false;
    }
    try {
        (void)server::load_auth_policies(path.string());
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
    if (original_contents) *original_contents = std::move(contents);
    return true;
}

bool atomic_write(const std::filesystem::path& path,
                  std::string_view contents,
                  std::string* error) {
    return runtime::AtomicWriteFile(
        path, contents, error, runtime::ParentDirectoryPolicy::Create);
}

bool restore_snapshot(const std::filesystem::path& path,
                      bool existed,
                      std::string_view contents,
                      std::string* error) {
    if (existed) return atomic_write(path, contents, error);
    return runtime::DurableRemoveFile(path, error);
}

std::string hex_lower(const unsigned char* data, std::size_t n) {
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(n * 2);
    for (std::size_t i = 0; i < n; ++i) {
        out[2 * i] = kHex[(data[i] >> 4) & 0xF];
        out[2 * i + 1] = kHex[data[i] & 0xF];
    }
    return out;
}

// An authorized identity is a composite: two consecutive PEM blocks, classical
// then post-quantum. Fingerprinting a single block yields the classical value,
// which is not what the server authorizes on and does not commit to the
// post-quantum half at all. `crypto::composite_fingerprint` is what key
// generation records and what the AUTH v2 session looks up, so it is the only
// identity this file may report.
std::optional<std::string> fingerprint_composite_pem(const std::string& bundle,
                                                     std::string* err) {
    std::vector<ParsedIdentity> identities;
    if (!parse_identity_store(bundle, &identities, err) ||
        identities.size() != 1) {
        if (err && err->empty()) {
            *err = "expected exactly one composite identity";
        }
        return std::nullopt;
    }
    return identities.front().fingerprint;
}

// Classical SubjectPublicKeyInfo fingerprint. This is *not* an identity under
// AUTH v2 -- the server authorizes and looks up per-key permissions by
// composite fingerprint -- so it is deliberately not used for authorized keys.
// Kept for non-composite key material such as TLS leaf pinning, where the
// classical SPKI digest is the right and only value.
[[maybe_unused]] std::optional<std::string> fingerprint_pem_der(
    const std::string& pem, std::string* err) {
    BIO_ptr bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())),
                BIO_free);
    if (!bio) {
        if (err) *err = "BIO allocation failed";
        return std::nullopt;
    }
    EVP_PKEY_ptr pkey(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr),
                      EVP_PKEY_free);
    if (!pkey) {
        if (err) *err = "invalid public key PEM";
        return std::nullopt;
    }
    unsigned char* der = nullptr;
    const int der_len = i2d_PUBKEY(pkey.get(), &der);
    if (der_len <= 0 || der == nullptr) {
        if (err) *err = "could not encode public key";
        return std::nullopt;
    }
    OpenSSLBuf der_guard(der);

    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(der, static_cast<std::size_t>(der_len), digest);
    return hex_lower(digest, SHA256_DIGEST_LENGTH);
}

#ifndef _WIN32
void chmod_private_file(std::filesystem::path const& path) {
    std::error_code ec;
    std::filesystem::permissions(
        path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace, ec);
}
#else
void chmod_private_file(std::filesystem::path const&) {}
#endif

}  // namespace

std::optional<KeyPair> generate_identity(std::filesystem::path const& dir,
                                         std::string const& base_name,
                                         std::string* err) {
    if (base_name.empty()
        || base_name.find('/') != std::string::npos
        || base_name.find('\\') != std::string::npos) {
        if (err) *err = "base_name must be a simple filename";
        return std::nullopt;
    }

    const auto priv_path = dir / (base_name + ".key");
    const auto pub_path  = dir / (base_name + ".pub");
    if (std::filesystem::exists(priv_path) || std::filesystem::exists(pub_path)) {
        if (err) *err = "target file already exists";
        return std::nullopt;
    }

    crypto::Bytes private_pem;
    BytesWiper private_pem_wiper(private_pem);
    crypto::Bytes public_pem;
    std::string fingerprint;
    try {
        const auto keys = crypto::generate_composite_keypair();
        private_pem = crypto::encode_composite_private_pem(keys);
        public_pem = crypto::encode_composite_identity(
            keys.classical.public_key.get(), keys.pq.public_key.get());
        const auto parsed = crypto::parse_composite_identity(public_pem);
        if (!parsed.valid()) {
            if (err) *err = "generated identity did not parse as composite";
            security::secure_erase(private_pem);
            return std::nullopt;
        }
        fingerprint = crypto::composite_fingerprint(parsed);
    } catch (const std::exception& ex) {
        if (err) *err = std::string("composite keypair generation failed: ") + ex.what();
        security::secure_erase(private_pem);
        return std::nullopt;
    }

    // Serialize to memory first, then create both files exclusively at 0600.
    // Writing the private PEM through a normal stream would publish it at the
    // process umask and only tighten it afterwards, leaving a readable window.
    std::string write_error;
    const bool private_written =
        security::WriteFileExclusive0600(priv_path.string(), private_pem, &write_error);
    security::secure_erase(private_pem);
    if (!private_written) {
        if (err) {
            *err = "failed to write private key: " +
                   (write_error.empty() ? std::string("unknown error") : write_error);
        }
        return std::nullopt;
    }
    if (!security::WriteFileExclusive0600(pub_path.string(), public_pem, &write_error)) {
        // Never leave a private key behind for a pair that was never
        // completed; the next attempt needs the path free to create again.
        std::error_code remove_error;
        std::filesystem::remove(priv_path, remove_error);
        if (err) {
            *err = "failed to write public key: " +
                   (write_error.empty() ? std::string("unknown error") : write_error);
        }
        return std::nullopt;
    }

    KeyPair kp;
    kp.private_path = priv_path;
    kp.public_path = pub_path;
    kp.fingerprint = std::move(fingerprint);
    kp.algorithm = "composite-ed25519-mldsa87";
    return kp;
}

std::optional<KeyPair> generate_ml_kem_768(
    std::filesystem::path const& private_path,
    std::filesystem::path const& public_path,
    std::string* err) {
    std::error_code ec;
    std::filesystem::create_directories(private_path.parent_path(), ec);
    std::filesystem::create_directories(public_path.parent_path(), ec);

    std::string inner_err;
    if (!inner::generate_pq_keypair(private_path.string(),
                                    public_path.string(), &inner_err)) {
        if (err) *err = inner_err.empty() ? "PQ keypair generation failed"
                                          : std::move(inner_err);
        return std::nullopt;
    }
    chmod_private_file(private_path);

    KeyPair kp;
    kp.private_path = private_path;
    kp.public_path = public_path;
    kp.algorithm = "ml-kem-768";
    // No SubjectPublicKeyInfo fingerprint defined for ML-KEM-768 PEM here;
    // leave empty so callers don't show a misleading value. The auth layer
    // identifies PQ keys by their on-disk path, not fingerprint.
    return kp;
}

std::optional<std::string> fingerprint_pubkey_file(
    std::filesystem::path const& pub_path, std::string* err) {
    std::string contents;
    if (!read_bounded_file(pub_path, kMaximumKeyStoreBytes, false,
                           &contents, nullptr, err)) {
        return std::nullopt;
    }
    // Reports the same composite identity the server authorizes on. A single
    // classical block is not an identity here, and fingerprinting one would
    // hand back a value that never matches anything.
    return fingerprint_composite_pem(contents, err);
}

namespace {

// authorized_keys file format: concatenation of PEM blocks separated by
// blank lines. Each block is a PUBLIC KEY (Ed25519). The meta JSON has
// shape:
//   {
//     "<fingerprint>": {
//       "alias": "...",
//       "permissions": {
//         "allow_exec": true, "allow_local_ip": false, ...
//       }
//     }
//   }

void apply_meta_to_entry(nlohmann::json const& meta_root,
                         std::string const& fingerprint,
                         AuthorizedKeyEntry& e) {
    e.key_type = "individual";
    auto it = meta_root.find(fingerprint);
    if (it == meta_root.end() || !it->is_object()) return;
    if (auto a = it->find("alias"); a != it->end() && a->is_string()) {
        e.alias = a->get<std::string>();
    }
    if (auto p = it->find("federation_peer_id"); p != it->end() && p->is_string()) {
        e.federation_peer_id = p->get<std::string>();
    }
    if (auto p = it->find("key_type"); p != it->end() && p->is_string()) {
        e.key_type = p->get<std::string>();
    }
    if (auto p = it->find("weight"); p != it->end() && p->is_number()) {
        e.weight = p->get<double>();
    }
    if (auto p = it->find("max_sessions");
        p != it->end() && (p->is_number_integer() || p->is_number_unsigned())) {
        const auto value = p->get<std::int64_t>();
        if (value > 0 && static_cast<std::uint64_t>(value) <=
                             std::numeric_limits<std::uint32_t>::max()) {
            e.max_sessions = static_cast<std::uint32_t>(value);
        }
    }
    auto p_it = it->find("permissions");
    if (p_it == it->end() || !p_it->is_object()) return;
    auto const& p = *p_it;
    auto get_opt = [&](const char* k, std::optional<bool>& dst) {
        auto v = p.find(k);
        if (v != p.end() && v->is_boolean()) dst = v->get<bool>();
    };
    get_opt("allow_exec",           e.allow_exec);
    get_opt("allow_local_ip",       e.allow_local_ip);
    get_opt("control_full",         e.control_full);
    get_opt("allow_inbound_admin",  e.allow_inbound_admin);
    get_opt("allow_outbound_admin", e.allow_outbound_admin);
    get_opt("allow_chat",           e.allow_chat);
    get_opt("allow_file",           e.allow_file);
    get_opt("allow_bytes",          e.allow_bytes);
    auto read_codec_array = [&](nlohmann::json const& arr) {
        if (!arr.is_array()) return;
        for (auto const& item : arr) {
            if (item.is_string()) {
                e.allow_codecs.push_back(item.get<std::string>());
            }
        }
    };
    if (auto ac = p.find("allow_codecs"); ac != p.end()) {
        read_codec_array(*ac);
    }
    if (auto ac = it->find("allow_codecs"); ac != it->end()) {
        read_codec_array(*ac);
    }
    auto read_string_array = [](nlohmann::json const& arr, std::vector<std::string>& out) {
        if (!arr.is_array()) return;
        for (auto const& item : arr) {
            if (item.is_string()) {
                out.push_back(item.get<std::string>());
            }
        }
    };
    if (auto as = p.find("allow_services"); as != p.end()) {
        read_string_array(*as, e.allow_services);
    }
    if (auto as = it->find("allow_services"); as != it->end()) {
        read_string_array(*as, e.allow_services);
    }
}

void entry_meta_to_json(AuthorizedKeyEntry const& e, nlohmann::json& dst) {
    dst["alias"] = e.alias;
    if (!e.federation_peer_id.empty()) {
        dst["federation_peer_id"] = e.federation_peer_id;
    }
    dst["key_type"] = e.key_type.empty() ? "individual" : e.key_type;
    if (e.weight.has_value()) {
        dst["weight"] = *e.weight;
    }
    if (e.max_sessions.has_value()) {
        dst["max_sessions"] = *e.max_sessions;
    }
    nlohmann::json perms = nlohmann::json::object();
    auto put = [&](const char* k, std::optional<bool> const& v) {
        if (v.has_value()) perms[k] = *v;
    };
    put("allow_exec",           e.allow_exec);
    put("allow_local_ip",       e.allow_local_ip);
    put("control_full",         e.control_full);
    put("allow_inbound_admin",  e.allow_inbound_admin);
    put("allow_outbound_admin", e.allow_outbound_admin);
    put("allow_chat",           e.allow_chat);
    put("allow_file",           e.allow_file);
    put("allow_bytes",          e.allow_bytes);
    if (!e.allow_codecs.empty()) {
        perms["allow_codecs"] = e.allow_codecs;
    }
    if (!e.allow_services.empty()) {
        perms["allow_services"] = e.allow_services;
    }
    if (!perms.empty()) dst["permissions"] = std::move(perms);
}

bool validate_authorized_entry(const AuthorizedKeyEntry& entry,
                               std::string* error) {
    const std::string key_type =
        entry.key_type.empty() ? "individual" : entry.key_type;
    if (key_type != "individual" && key_type != "bulk") {
        if (error) *error = "key_type must be 'individual' or 'bulk'";
        return false;
    }
    if (entry.weight.has_value() &&
        (!std::isfinite(*entry.weight) || *entry.weight < 0.1 ||
         *entry.weight > 100.0)) {
        if (error) *error = "weight must be in 0.1..100";
        return false;
    }
    if (entry.max_sessions.has_value() &&
        (*entry.max_sessions == 0 || *entry.max_sessions > 65535)) {
        if (error) *error = "max_sessions must be in 1..65535";
        return false;
    }
    if (!entry.federation_peer_id.empty() &&
        !server::is_valid_federation_peer_id(entry.federation_peer_id)) {
        if (error) *error = "federation_peer_id has invalid syntax";
        return false;
    }
    if (entry.control_full.value_or(false) ||
        entry.allow_inbound_admin.value_or(false) ||
        entry.allow_outbound_admin.value_or(false)) {
        if (error) {
            *error = "visitor keys cannot grant admin or full-control "
                     "permissions";
        }
        return false;
    }
    if (key_type == "individual" &&
        entry.max_sessions.value_or(1) != 1) {
        if (error) {
            *error = "individual keys must have max_sessions=1; use bulk "
                     "for shared credentials";
        }
        return false;
    }
    if (key_type == "bulk" &&
        (entry.allow_exec.value_or(false) ||
         entry.allow_local_ip.value_or(false) ||
         !entry.allow_codecs.empty() || !entry.allow_services.empty() ||
         !entry.federation_peer_id.empty())) {
        if (error) {
            *error = "bulk keys cannot grant exec, local-IP, codec, service, "
                     "or federation permissions";
        }
        return false;
    }
    return true;
}

}  // namespace

std::vector<AuthorizedKeyEntry> list_authorized(
    std::filesystem::path const& auth_keys_file,
    std::filesystem::path const& meta_file) {
    std::vector<AuthorizedKeyEntry> out;
    std::error_code exists_error;
    if (!std::filesystem::exists(auth_keys_file, exists_error) ||
        exists_error) {
        return out;
    }
    std::string error;
    runtime::FileTransactionLock transaction_lock;
    if (!transaction_lock.Acquire({auth_keys_file, meta_file}, &error)) {
        return out;
    }
    std::vector<ParsedIdentity> identities;
    if (!load_identity_store(auth_keys_file, true, &identities, &error)) {
        return out;
    }
    nlohmann::json meta = nlohmann::json::object();
    if (!load_metadata(meta_file, true, &meta, &error)) return out;

    for (const auto& identity : identities) {
        AuthorizedKeyEntry e;
        e.pem = identity.pem;
        e.algorithm = "ed25519+ml-dsa-87";
        e.fingerprint = identity.fingerprint;
        apply_meta_to_entry(meta, e.fingerprint, e);
        out.push_back(std::move(e));
    }
    return out;
}

bool append_authorized(std::filesystem::path const& auth_keys_file,
                       std::filesystem::path const& meta_file,
                       std::filesystem::path const& admin_keys_file,
                       std::string const& pem,
                       AuthorizedKeyEntry const& entry_meta,
                       std::string* err) {
    if (err) err->clear();
    std::string error;
    std::vector<ParsedIdentity> candidates;
    if (!parse_identity_store(pem, &candidates, &error) ||
        candidates.size() != 1) {
        if (err) {
            *err = error.empty() ? "expected exactly one composite identity"
                                 : error;
        }
        return false;
    }
    ParsedIdentity candidate = std::move(candidates.front());

    runtime::FileTransactionLock transaction_lock;
    if (!transaction_lock.Acquire(
            {auth_keys_file, meta_file, admin_keys_file}, &error)) {
        if (err) *err = "cannot lock authorization transaction: " + error;
        return false;
    }
    if (!admin_keys_file.empty() &&
        resource_paths_alias(auth_keys_file, admin_keys_file)) {
        if (err) {
            *err = "auth_keys and admin_keys must be distinct files";
        }
        return false;
    }

    std::vector<ParsedIdentity> identities;
    std::string original_store;
    bool store_existed = false;
    if (!load_identity_store(auth_keys_file, true, &identities, &error,
                             &original_store, &store_existed)) {
        if (err) *err = "existing auth_keys is not usable: " + error;
        return false;
    }
    if (std::any_of(identities.begin(), identities.end(),
                    [&](const ParsedIdentity& identity) {
                        return identity.canonical == candidate.canonical;
                    })) {
        if (err) *err = "key already authorized";
        return false;
    }

    if (!admin_keys_file.empty()) {
        std::vector<ParsedIdentity> admin_identities;
        if (!load_identity_store(admin_keys_file, true, &admin_identities,
                                 &error)) {
            if (err) *err = "existing admin_keys is not usable: " + error;
            return false;
        }
        if (std::any_of(admin_identities.begin(), admin_identities.end(),
                        [&](const ParsedIdentity& identity) {
                            return identity.canonical == candidate.canonical;
                        })) {
            if (err) {
                *err = "refusing to enroll the same composite identity in "
                       "both visitor and admin stores";
            }
            return false;
        }
    }

    nlohmann::json meta = nlohmann::json::object();
    std::string original_metadata;
    bool metadata_existed = false;
    if (!load_metadata(meta_file, true, &meta, &error, &original_metadata,
                       &metadata_existed)) {
        if (err) *err = "existing auth metadata is not usable: " + error;
        return false;
    }
    AuthorizedKeyEntry entry = entry_meta;
    entry.fingerprint = candidate.fingerprint;
    if (!validate_authorized_entry(entry, &error)) {
        if (err) *err = error;
        return false;
    }
    nlohmann::json entry_json = nlohmann::json::object();
    entry_meta_to_json(entry, entry_json);
    meta[candidate.fingerprint] = std::move(entry_json);
    if (!server::validate_auth_metadata_json_types(meta, &error)) {
        if (err) *err = error;
        return false;
    }
    std::string serialized_metadata;
    try {
        serialized_metadata = meta.dump(2);
    } catch (const std::exception& ex) {
        if (err) *err = std::string("cannot serialize auth metadata: ") + ex.what();
        return false;
    }

    // Metadata precedes authorization. If the second publication fails, the
    // first is either rolled back or retained fail-closed if auth rollback
    // cannot be confirmed.
    if (!atomic_write(meta_file, serialized_metadata, &error)) {
        const std::string write_error = error;
        std::string rollback_error;
        if (!restore_snapshot(meta_file, metadata_existed, original_metadata,
                              &rollback_error)) {
            if (err) {
                *err = "cannot update auth metadata: " + write_error +
                       "; rollback failed: " + rollback_error;
            }
        } else if (err) {
            *err = "cannot update auth metadata: " + write_error;
        }
        return false;
    }

    identities.push_back(std::move(candidate));
    if (!atomic_write(auth_keys_file, serialize_identity_store(identities),
                      &error)) {
        const std::string write_error = error;
        std::string auth_rollback_error;
        const bool auth_restored = restore_snapshot(
            auth_keys_file, store_existed, original_store,
            &auth_rollback_error);
        std::string metadata_rollback_error;
        const bool metadata_restored =
            !auth_restored ||
            restore_snapshot(meta_file, metadata_existed, original_metadata,
                             &metadata_rollback_error);
        if (err) {
            *err = "cannot update auth_keys: " + write_error;
            if (!auth_restored) {
                *err += "; auth rollback failed: " + auth_rollback_error +
                        "; new metadata retained fail-closed";
            } else if (!metadata_restored) {
                *err += "; metadata rollback failed: " +
                        metadata_rollback_error;
            }
        }
        return false;
    }
    return true;
}

bool remove_authorized(std::filesystem::path const& auth_keys_file,
                       std::filesystem::path const& meta_file,
                       std::string const& fingerprint,
                       std::string* err) {
    if (err) err->clear();
    std::string error;
    runtime::FileTransactionLock transaction_lock;
    if (!transaction_lock.Acquire({auth_keys_file, meta_file}, &error)) {
        if (err) *err = "cannot lock authorization transaction: " + error;
        return false;
    }
    std::vector<ParsedIdentity> identities;
    if (!load_identity_store(auth_keys_file, false, &identities, &error)) {
        if (err) *err = "existing auth_keys is not usable: " + error;
        return false;
    }
    const auto match = std::find_if(
        identities.begin(), identities.end(), [&](const ParsedIdentity& entry) {
            return entry.fingerprint == fingerprint;
        });
    if (match == identities.end()) {
        if (err) *err = "fingerprint not found";
        return false;
    }
    nlohmann::json meta = nlohmann::json::object();
    if (!load_metadata(meta_file, true, &meta, &error)) {
        if (err) *err = "existing auth metadata is not usable: " + error;
        return false;
    }

    const auto index = static_cast<std::size_t>(
        std::distance(identities.begin(), match));
    if (!atomic_write(auth_keys_file,
                      serialize_identity_store(identities, index), &error)) {
        if (err) {
            *err = "authorization removal failed or could not be proven "
                   "durable: " + error;
        }
        return false;
    }
    // Revoke before cleanup. Stale metadata cannot authenticate after the
    // composite identity has been removed from the authorization store.
    meta.erase(fingerprint);
    std::string serialized_metadata;
    try {
        serialized_metadata = meta.dump(2);
    } catch (const std::exception& ex) {
        if (err) {
            *err = "key was revoked, but metadata serialization failed: " +
                   std::string(ex.what());
        }
        return false;
    }
    if (!atomic_write(meta_file, serialized_metadata, &error)) {
        if (err) {
            *err = "key was revoked, but metadata cleanup failed: " + error;
        }
        return false;
    }
    return true;
}

bool update_authorized(std::filesystem::path const& auth_keys_file,
                       std::filesystem::path const& meta_file,
                       std::string const& fingerprint,
                       AuthorizedKeyEntry const& patch,
                       std::string* err) {
    if (err) err->clear();
    std::string error;
    runtime::FileTransactionLock transaction_lock;
    if (!transaction_lock.Acquire({auth_keys_file, meta_file}, &error)) {
        if (err) *err = "cannot lock authorization transaction: " + error;
        return false;
    }
    std::vector<ParsedIdentity> identities;
    if (!load_identity_store(auth_keys_file, false, &identities, &error)) {
        if (err) *err = "existing auth_keys is not usable: " + error;
        return false;
    }
    const auto identity = std::find_if(
        identities.begin(), identities.end(), [&](const ParsedIdentity& entry) {
            return entry.fingerprint == fingerprint;
        });
    if (identity == identities.end()) {
        if (err) *err = "fingerprint not found";
        return false;
    }

    nlohmann::json meta = nlohmann::json::object();
    std::string original_metadata;
    bool metadata_existed = false;
    if (!load_metadata(meta_file, true, &meta, &error, &original_metadata,
                       &metadata_existed)) {
        if (err) *err = "existing auth metadata is not usable: " + error;
        return false;
    }

    AuthorizedKeyEntry current;
    current.pem = identity->pem;
    current.fingerprint = identity->fingerprint;
    current.algorithm = "ed25519+ml-dsa-87";
    apply_meta_to_entry(meta, fingerprint, current);

    AuthorizedKeyEntry merged = current;
    merged.alias = patch.alias;
    if (!patch.federation_peer_id.empty()) {
        merged.federation_peer_id = patch.federation_peer_id;
    }
    if (!patch.key_type.empty()) merged.key_type = patch.key_type;
    if (patch.weight.has_value()) merged.weight = patch.weight;
    if (patch.max_sessions.has_value()) merged.max_sessions = patch.max_sessions;
    if (!patch.allow_codecs.empty()) merged.allow_codecs = patch.allow_codecs;
    if (!patch.allow_services.empty()) merged.allow_services = patch.allow_services;
    if (patch.allow_exec.has_value()) merged.allow_exec = patch.allow_exec;
    if (patch.allow_local_ip.has_value()) merged.allow_local_ip = patch.allow_local_ip;
    if (patch.control_full.has_value()) merged.control_full = patch.control_full;
    if (patch.allow_inbound_admin.has_value()) {
        merged.allow_inbound_admin = patch.allow_inbound_admin;
    }
    if (patch.allow_outbound_admin.has_value()) {
        merged.allow_outbound_admin = patch.allow_outbound_admin;
    }
    if (patch.allow_chat.has_value()) merged.allow_chat = patch.allow_chat;
    if (patch.allow_file.has_value()) merged.allow_file = patch.allow_file;
    if (patch.allow_bytes.has_value()) merged.allow_bytes = patch.allow_bytes;

    if (!validate_authorized_entry(merged, &error)) {
        if (err) *err = error;
        return false;
    }
    nlohmann::json entry_json = nlohmann::json::object();
    entry_meta_to_json(merged, entry_json);
    meta[fingerprint] = std::move(entry_json);
    if (!server::validate_auth_metadata_json_types(meta, &error)) {
        if (err) *err = error;
        return false;
    }
    std::string serialized_metadata;
    try {
        serialized_metadata = meta.dump(2);
    } catch (const std::exception& ex) {
        if (err) *err = std::string("cannot serialize auth metadata: ") + ex.what();
        return false;
    }
    if (!atomic_write(meta_file, serialized_metadata, &error)) {
        const std::string write_error = error;
        std::string rollback_error;
        if (!restore_snapshot(meta_file, metadata_existed, original_metadata,
                              &rollback_error)) {
            if (err) {
                *err = "cannot update auth metadata: " + write_error +
                       "; rollback failed: " + rollback_error;
            }
        } else if (err) {
            *err = "cannot update auth metadata: " + write_error;
        }
        return false;
    }
    return true;
}

}  // namespace yume::facade::keys
