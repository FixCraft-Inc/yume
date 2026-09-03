/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/cli/key.hpp"

#include <algorithm>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <string_view>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <nlohmann/json.hpp>

#include "config/ratchet_profile_json.hpp"
#include "core/security/crypto.hpp"
#include "core/security/secret_file.hpp"
#include "core/security/secure_erase.hpp"
#include "core/protocol/runtime_policy.hpp"
#include "core/runtime/atomic_file.hpp"
#include "core/runtime/file_transaction_lock.hpp"
#include "server/auth/auth.hpp"
#include "server/auth/auth_metadata_json.hpp"
#include "server/cli/config_json_types.hpp"
#include "server/cli/numeric_parse.hpp"
#include "server/runtime/manager.hpp"
#include "util.hpp"

namespace yume::server::cli {
namespace {

constexpr std::uintmax_t kMaximumKeyStoreBytes = 64U * 1024U * 1024U;
constexpr std::uintmax_t kMaximumJsonFileBytes = 16U * 1024U * 1024U;

struct AuthorizedIdentity {
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
        if (error) *error = "authorized key store contains an unterminated PEM block";
        return std::nullopt;
    }
    *cursor = end + kEnd.size();
    if (*cursor < contents.size() && !is_pem_whitespace(contents[*cursor])) {
        if (error) *error = "authorized key store has trailing data after a PEM block";
        return std::nullopt;
    }
    return contents.substr(start, *cursor - start);
}

bool parse_authorized_identities(std::string_view contents,
                                 std::vector<AuthorizedIdentity>* identities,
                                 std::string* error) {
    if (!identities) return false;
    if (error) error->clear();
    identities->clear();
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
                *error = "authorized key store contains an incomplete composite "
                         "identity";
            }
            return false;
        }

        crypto::Bytes bundle(classical->begin(), classical->end());
        bundle.push_back('\n');
        bundle.insert(bundle.end(), pq->begin(), pq->end());
        auto composite = crypto::parse_composite_identity(bundle);
        if (!composite.valid()) {
            if (error) {
                *error = "every authorized entry must be an Ed25519 public key "
                         "followed by an ML-DSA-87 public key";
            }
            return false;
        }

        AuthorizedIdentity entry;
        entry.canonical = crypto::composite_canonical_encoding(composite);
        entry.fingerprint =
            crypto::composite_fingerprint_from_canonical(entry.canonical);
        const auto normalized = crypto::encode_composite_identity(
            composite.classical.get(), composite.pq.get());
        entry.pem.assign(normalized.begin(), normalized.end());
        if (entry.pem.empty() || entry.pem.back() != '\n') entry.pem.push_back('\n');
        identities->push_back(std::move(entry));
    }
}

bool load_authorized_store(const std::filesystem::path& path,
                           bool allow_missing,
                           std::vector<AuthorizedIdentity>* identities,
                           std::string* error,
                           std::string* original_contents = nullptr,
                           bool* existed = nullptr) {
    if (original_contents) original_contents->clear();
    std::string contents;
    if (!read_bounded_file(path, kMaximumKeyStoreBytes, allow_missing,
                           &contents, existed, error)) {
        return false;
    }
    if (!parse_authorized_identities(contents, identities, error)) {
        return false;
    }
    if (original_contents) *original_contents = std::move(contents);
    return true;
}

std::string serialize_authorized_store(
    const std::vector<AuthorizedIdentity>& identities,
    std::optional<std::size_t> skip = std::nullopt) {
    std::string contents;
    for (std::size_t i = 0; i < identities.size(); ++i) {
        if (skip.has_value() && *skip == i) continue;
        contents += identities[i].pem;
    }
    return contents;
}

bool load_json_object(const std::filesystem::path& path,
                      bool allow_missing,
                      nlohmann::json* document,
                      bool* existed,
                      std::string* error,
                      std::string* original_contents = nullptr) {
    if (!document) return false;
    if (error) error->clear();
    if (original_contents) original_contents->clear();
    std::string contents;
    bool file_existed = false;
    if (!read_bounded_file(path, kMaximumJsonFileBytes, allow_missing,
                           &contents, &file_existed, error)) {
        return false;
    }
    if (existed) *existed = file_existed;
    if (!file_existed) {
        *document = nlohmann::json::object();
        return true;
    }
    try {
        *document = nlohmann::json::parse(contents);
    } catch (const std::exception& ex) {
        if (error) {
            *error = "cannot parse JSON file '" + path.string() + "': " +
                     ex.what();
        }
        return false;
    }
    if (!document->is_object()) {
        if (error) *error = "JSON root must be an object: " + path.string();
        return false;
    }
    if (original_contents) *original_contents = std::move(contents);
    return true;
}

bool load_auth_metadata(const std::filesystem::path& path,
                        nlohmann::json* metadata,
                        std::string* error,
                        std::string* original_contents = nullptr,
                        bool* existed = nullptr) {
    if (path.empty()) {
        *metadata = nlohmann::json::object();
        if (original_contents) original_contents->clear();
        if (existed) *existed = false;
        return true;
    }
    if (!load_json_object(path, true, metadata, existed, error,
                          original_contents)) {
        return false;
    }
    if (!yume::server::validate_auth_metadata_json_types(*metadata, error)) {
        return false;
    }
    try {
        (void)yume::server::load_auth_policies(path.string());
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
    return true;
}

std::string metadata_alias(const nlohmann::json& metadata,
                           const std::string& fingerprint) {
    const auto it = metadata.find(fingerprint);
    if (it == metadata.end()) return {};
    const auto alias = it->find("alias");
    return alias != it->end() ? alias->get<std::string>() : std::string{};
}

std::optional<std::size_t> resolve_identity_selector(
    const std::vector<AuthorizedIdentity>& identities,
    const nlohmann::json& metadata,
    const std::string& selector,
    std::string* error) {
    std::optional<std::size_t> match;
    for (std::size_t i = 0; i < identities.size(); ++i) {
        if (identities[i].fingerprint != selector &&
            metadata_alias(metadata, identities[i].fingerprint) != selector) {
            continue;
        }
        if (match.has_value() && *match != i) {
            if (error) {
                *error = "authorized-key selector is ambiguous: " + selector;
            }
            return std::nullopt;
        }
        match = i;
    }
    if (!match.has_value() && error) {
        *error = "no authorized key matches fingerprint or alias: " + selector;
    }
    return match;
}

bool alias_is_available(const nlohmann::json& metadata,
                        const std::string& alias,
                        const std::string& target_fingerprint,
                        std::string* error) {
    if (alias.empty()) return true;
    for (auto it = metadata.begin(); it != metadata.end(); ++it) {
        if (it.key() != target_fingerprint &&
            metadata_alias(metadata, it.key()) == alias) {
            if (error) *error = "alias is already assigned: " + alias;
            return false;
        }
    }
    return true;
}

bool atomic_write(const std::filesystem::path& path,
                  std::string_view contents,
                  std::string* error) {
    return runtime::AtomicWriteFile(
        path, contents, error, runtime::ParentDirectoryPolicy::Create);
}

bool restore_file_snapshot(const std::filesystem::path& path,
                           bool existed,
                           std::string_view contents,
                           std::string* error) {
    if (existed) return atomic_write(path, contents, error);
    return runtime::DurableRemoveFile(path, error);
}


class BytesWiper {
public:
    explicit BytesWiper(crypto::Bytes& bytes) noexcept : bytes_(bytes) {}
    ~BytesWiper() { security::secure_erase(bytes_); }

    BytesWiper(const BytesWiper&) = delete;
    BytesWiper& operator=(const BytesWiper&) = delete;

private:
    crypto::Bytes& bytes_;
};

bool write_file_secure(const std::string& path,
                       const std::string& contents,
                       std::string* error) {
    const auto* bytes =
        reinterpret_cast<const std::uint8_t*>(contents.data());
    return security::WriteFileExclusive0600(
        path, std::span<const std::uint8_t>(bytes, contents.size()), error);
}

}  // namespace

bool ServerKeyCommand::has_action() const {
    return list || !add.empty() || !remove.empty() || !alias.empty() || !generate_prefix.empty();
}

bool file_readable(const std::string& path) {
    if (path.empty()) {
        return false;
    }
    std::error_code ec;
    return std::filesystem::exists(path, ec);
}

bool ensure_dir(const std::string& dir) {
    if (dir.empty()) {
        return false;
    }
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return !ec;
}

std::string load_or_create_secret(const std::string& path) {
    std::ifstream in(path);
    if (in) {
        std::string val;
        std::getline(in, val);
        if (!val.empty()) {
            return val;
        }
    }
    std::string secret = yume::util::random_hex(32);
    if (secret.empty()) {
        throw std::runtime_error("failed to generate secret");
    }
    std::string write_error;
    if (!write_file_secure(path, secret, &write_error)) {
        throw std::runtime_error(
            write_error.empty() ? "failed to write secret file"
                                : "failed to write secret file: " + write_error);
    }
    return secret;
}

bool generate_composite_keypair(const std::string& priv_path, const std::string& pub_path) {
    // A YUME identity is composite: Ed25519 alongside ML-DSA-87, both required.
    // Each file holds the two PEM blocks concatenated in that fixed order,
    // which is what crypto::load_composite_keypair and the authorized-key
    // stores expect. One file per half was rejected: two paths can drift out of
    // sync, and a half-present identity is exactly the state that must never
    // authenticate.
    crypto::Bytes private_pem;
    BytesWiper private_pem_wiper(private_pem);
    crypto::Bytes public_pem;
    try {
        const auto keys = crypto::generate_composite_keypair();
        private_pem = crypto::encode_composite_private_pem(keys);
        public_pem = crypto::encode_composite_identity(
            keys.classical.public_key.get(), keys.pq.public_key.get());
    } catch (const std::exception& ex) {
        std::cerr << "failed to generate composite keypair: " << ex.what() << "\n";
        return false;
    }

    // Serialize to memory first, then create both files exclusively. Writing
    // the private PEM through BIO_new_file would publish it at the process
    // umask and only tighten it afterwards, leaving a readable window and no
    // protection at all against a pre-placed file or symlink.
    std::string write_error;
    if (!security::WriteFileExclusive0600(priv_path, private_pem, &write_error)) {
        std::cerr << "failed to write composite private key: "
                  << (write_error.empty() ? "unknown error" : write_error)
                  << "\n";
        return false;
    }
    if (!security::WriteFileExclusive0600(pub_path, public_pem, &write_error)) {
        // Do not leave a private key behind for a pair that was never
        // completed; the next attempt needs the path free to create again.
        std::error_code remove_error;
        const bool private_removed =
            std::filesystem::remove(priv_path, remove_error);
        std::cerr << "failed to write composite public key: "
                  << (write_error.empty() ? "unknown error" : write_error)
                  << "\n";
        if (!private_removed && remove_error) {
            std::cerr << "failed to remove incomplete composite private key: "
                      << remove_error.message() << "\n";
        }
        return false;
    }
    return true;
}

std::string auth_keys_write_hint(const std::string& path) {
#if defined(_WIN32)
    (void)path;
    return "";
#else
    if (path.rfind("/etc/", 0) == 0 && geteuid() != 0) {
        return " (permission denied? run yumed --ui with sudo, or set --auth-keys to a writable file)";
    }
    return "";
#endif
}

bool append_authorized_public_key(const yume::server::ServerConfig& cfg,
                                  const std::string& public_key_path,
                                  const std::string& alias,
                                  std::string* out_fingerprint,
                                  bool to_admin_store) {
    if (out_fingerprint) out_fingerprint->clear();
    // The two stores are deliberately separate files and this is the only
    // place that chooses between them. Enrolling into the admin store grants
    // nothing by itself: an admin session still needs a distinct visitor key
    // as its first factor, and the server refuses to start if any identity
    // appears in both stores.
    const std::string& store =
        to_admin_store ? cfg.admin_keys : cfg.auth_keys;
    if (store.empty()) {
        yume::util::log_error(to_admin_store
            ? "admin_keys must be set (--admin-keys) before adding an admin key"
            : "auth_keys must be set before adding a key");
        return false;
    }
    // Read the whole candidate: a composite identity is two PEM blocks and must
    // be enrolled as a unit. Reading only the first block would append half an
    // identity, which the server correctly rejects at startup.
    std::string pem_text;
    std::string error;
    if (!read_bounded_file(public_key_path, kMaximumKeyStoreBytes, false,
                           &pem_text, nullptr, &error)) {
        yume::util::log_error(error);
        return false;
    }
    std::vector<AuthorizedIdentity> candidate_identities;
    if (!parse_authorized_identities(pem_text, &candidate_identities, &error) ||
        candidate_identities.size() != 1) {
        yume::util::log_error(
            "not a composite identity: " + public_key_path +
            " (expected exactly one Ed25519 public key followed by exactly one "
            "ML-DSA-87 public key; regenerate with 'yumed key --generate "
            "<prefix>')" + (error.empty() ? std::string{} : ": " + error));
        return false;
    }
    AuthorizedIdentity candidate = std::move(candidate_identities.front());

    const std::string fp = candidate.fingerprint;

    // Lock every authorization store that participates in the disjointness
    // check, plus visitor metadata. Sidecar locks survive destination renames,
    // and the shared sorted convention also coordinates facade/GUI mutations.
    runtime::FileTransactionLock transaction_lock;
    std::vector<std::filesystem::path> transaction_resources{
        cfg.auth_keys, cfg.admin_keys};
    if (!to_admin_store) transaction_resources.emplace_back(cfg.auth_keys_meta);
    if (!transaction_lock.Acquire(transaction_resources, &error)) {
        yume::util::log_error("cannot lock authorization transaction: " + error);
        return false;
    }

    // Parse the current store from one bounded snapshot. Mutation always writes
    // the complete validated set to an exclusive same-directory temporary and
    // atomically replaces the destination; ENOSPC or a short write therefore
    // cannot strand one half of a composite identity.
    std::vector<AuthorizedIdentity> identities;
    std::string original_store;
    bool store_existed = false;
    if (!load_authorized_store(store, true, &identities, &error,
                               &original_store, &store_existed)) {
        yume::util::log_error("existing auth_keys is not usable: " + error);
        return false;
    }
    const auto existing = std::find_if(
        identities.begin(), identities.end(), [&](const AuthorizedIdentity& entry) {
            return entry.canonical == candidate.canonical;
        });
    const bool already_authorized = existing != identities.end();

    const std::string& other_store =
        to_admin_store ? cfg.auth_keys : cfg.admin_keys;
    if (!other_store.empty() && other_store != store) {
        std::vector<AuthorizedIdentity> other_identities;
        if (!load_authorized_store(other_store, true, &other_identities,
                                   &error)) {
            yume::util::log_error(
                "the other authorization store is not usable: " + error);
            return false;
        }
        if (std::any_of(other_identities.begin(), other_identities.end(),
                        [&](const AuthorizedIdentity& entry) {
                            return entry.canonical == candidate.canonical;
                        })) {
            yume::util::log_error(
                "refusing to enroll the same composite identity in both "
                "visitor and admin stores");
            return false;
        }
    }

    nlohmann::json metadata = nlohmann::json::object();
    std::string original_metadata;
    bool metadata_existed = false;
    if (!to_admin_store) {
        if (cfg.auth_keys_meta.empty()) {
            yume::util::log_error(
                "auth_keys_meta must be set before adding a visitor key");
            return false;
        }
        if (!load_auth_metadata(cfg.auth_keys_meta, &metadata, &error,
                                &original_metadata, &metadata_existed)) {
            yume::util::log_error("existing auth_keys_meta is not usable: " + error);
            return false;
        }
        if (!alias_is_available(metadata, alias, fp, &error)) {
            yume::util::log_error(error);
            return false;
        }
    }

    // Publish visitor metadata before a new authorization. If the second write
    // fails, a stale metadata record grants nothing because the identity is not
    // in auth_keys. The reverse order could briefly authorize a key without the
    // restrictions the operator intended to attach to its fingerprint.
    if (!to_admin_store) {
        nlohmann::json entry = metadata.value(fp, nlohmann::json::object());
        if (!alias.empty()) entry["alias"] = alias;
        entry["last_seen"] = static_cast<long long>(std::time(nullptr));
        metadata[fp] = std::move(entry);
        std::string serialized_metadata;
        try {
            serialized_metadata = metadata.dump(2);
        } catch (const std::exception& ex) {
            yume::util::log_error(
                std::string("failed to serialize auth_keys_meta: ") + ex.what());
            return false;
        }
        if (!atomic_write(cfg.auth_keys_meta, serialized_metadata, &error)) {
            const std::string write_error = error;
            std::string rollback_error;
            if (!restore_file_snapshot(cfg.auth_keys_meta, metadata_existed,
                                       original_metadata, &rollback_error)) {
                yume::util::log_error(
                    "failed to update auth_keys_meta: " + write_error +
                    "; rollback failed: " + rollback_error);
            } else {
                yume::util::log_error(
                    "failed to update auth_keys_meta: " + write_error);
            }
            return false;
        }
    }

    if (!already_authorized) {
        identities.push_back(std::move(candidate));
        if (!atomic_write(store, serialize_authorized_store(identities), &error)) {
            const std::string write_error = error;
            std::vector<std::string> rollback_errors;
            std::string rollback_error;
            const bool authorization_restored = restore_file_snapshot(
                store, store_existed, original_store, &rollback_error);
            if (!authorization_restored) {
                rollback_errors.push_back("auth_keys: " + rollback_error);
            }
            // Metadata must remain in place unless authorization is known to
            // be back at its original snapshot. AtomicWriteFile can report a
            // parent-directory fsync failure after rename; removing metadata
            // after a failed auth rollback could leave the new key authorized
            // without the restrictions attached to its fingerprint.
            if (authorization_restored && !to_admin_store &&
                !restore_file_snapshot(cfg.auth_keys_meta, metadata_existed,
                                       original_metadata, &rollback_error)) {
                rollback_errors.push_back("auth_keys_meta: " + rollback_error);
            }
            std::string message = "failed to update auth_keys: " + write_error +
                                  auth_keys_write_hint(store);
            if (!authorization_restored && !to_admin_store) {
                message += "; auth rollback was not confirmed, so the newly "
                           "published metadata was retained fail-closed";
            }
            for (const auto& rollback : rollback_errors) {
                message += "; rollback failed for " + rollback;
            }
            yume::util::log_error(message);
            return false;
        }
    }
    if (out_fingerprint) *out_fingerprint = fp;
    std::cout << (already_authorized ? "Already authorized: " : "Authorized: ")
              << fp << "\n";
    if (!alias.empty()) {
        std::cout << "Alias: " << alias << "\n";
    }
    std::cout << (to_admin_store ? "admin_keys: " : "auth_keys: ") << store << "\n";
    return true;
}

CliCommandResult run_server_manager_ui(yume::server::ServerConfig& cfg, ServerKeyCommand& command) {
    std::cout << "\n\033[1;36mYUME Server Manager\033[0m\n";
    if (cfg.auth_keys.empty()) {
        cfg.auth_keys = "/etc/yume/authorized_keys";
    }
    if (cfg.auth_keys_meta.empty() && !cfg.auth_keys.empty()) {
        cfg.auth_keys_meta = cfg.auth_keys + ".json";
    }
    std::cout << "auth_keys: " << cfg.auth_keys << auth_keys_write_hint(cfg.auth_keys) << "\n";
    std::cout << "1) Generate keypair and authorize it\n";
    std::cout << "2) Add public key to auth_keys\n";
    std::cout << "3) Remove key (fingerprint or alias)\n";
    std::cout << "4) Set alias\n";
    std::cout << "5) List keys\n";
    std::cout << "6) Edit config\n";
    std::cout << "7) Generate keypair only\n";
    std::cout << "0) Exit\n";
    std::cout << "Select: ";
    std::string choice;
    std::getline(std::cin, choice);
    if (choice == "1") {
        std::cout << "Prefix (path without extension) [./yume-client]: ";
        std::getline(std::cin, command.generate_prefix);
        if (command.generate_prefix.empty()) {
            command.generate_prefix = "./yume-client";
        }
        std::cout << "Alias (optional): ";
        std::getline(std::cin, command.alias_value);
        command.generate_and_add = true;
    } else if (choice == "2") {
        std::cout << "Public key path: ";
        std::getline(std::cin, command.add);
        if (command.add.empty()) {
            yume::util::log_error("public key path is required");
            return {true, 1};
        }
        std::cout << "Alias (optional): ";
        std::getline(std::cin, command.alias_value);
    } else if (choice == "3") {
        std::cout << "Fingerprint or alias: ";
        std::getline(std::cin, command.remove);
        if (command.remove.empty()) {
            yume::util::log_error("fingerprint or alias is required");
            return {true, 1};
        }
    } else if (choice == "4") {
        std::cout << "Fingerprint or alias: ";
        std::getline(std::cin, command.alias);
        if (command.alias.empty()) {
            yume::util::log_error("fingerprint or alias is required");
            return {true, 1};
        }
        std::cout << "New alias: ";
        std::getline(std::cin, command.alias_value);
    } else if (choice == "5") {
        command.list = true;
    } else if (choice == "6") {
        std::string out_path = "config/yumed.json";
        std::cout << "Config path [config/yumed.json]: ";
        std::string input_path;
        std::getline(std::cin, input_path);
        if (!input_path.empty()) {
            out_path = input_path;
        }
        nlohmann::json json = nlohmann::json::object();
        std::string config_error;
        bool config_existed = false;
        if (!load_json_object(out_path, true, &json, &config_existed,
                              &config_error)) {
            yume::util::log_error(
                "refusing to overwrite unusable config: " + config_error);
            return {true, 1};
        }
        if (config_existed &&
            !validate_server_config_json_types(json, &config_error)) {
            yume::util::log_error(
                "refusing to overwrite unusable config: " + config_error);
            return {true, 1};
        }
        if (config_existed) {
            try {
                (void)yume::config::ParseSecurityProfile(json);
            } catch (const std::exception& ex) {
                yume::util::log_error(
                    std::string("refusing to overwrite unusable config: ") +
                    ex.what());
                return {true, 1};
            }
        }
        auto prompt = [&](const std::string& key, const std::string& current) {
            std::cout << key << " [" << current << "]: ";
            std::string v;
            std::getline(std::cin, v);
            return v.empty() ? current : v;
        };
        std::string listen = prompt("listen_port", std::to_string(cfg.listen_port));
        std::string reverse_min = prompt("reverse_port_min", std::to_string(cfg.reverse_port_min));
        std::string reverse_max = prompt("reverse_port_max", std::to_string(cfg.reverse_port_max));
        std::string cert = prompt("tls_cert", cfg.tls_cert);
        std::string key = prompt("tls_key", cfg.tls_key);
        std::string auth = prompt("auth_keys", cfg.auth_keys);
        std::string threads = prompt("threads", std::to_string(cfg.threads));
        std::string obfs = prompt("obfuscation (true/false)", cfg.obfuscation ? "true" : "false");
        std::string inner = prompt("inner_crypto (true/false)", cfg.inner_crypto ? "true" : "false");
        std::string inner_dual = prompt("inner_dual (true/false)", cfg.inner_dual ? "true" : "false");
        std::string inner_required = prompt("inner_required (true/false)", cfg.inner_required ? "true" : "false");
        std::string pq = prompt("pq_private_key", cfg.pq_private_key);
        std::string allow_embedded_master = prompt(
            "allow_embedded_master (true/false)",
            cfg.allow_embedded_master ? "true" : "false");
        std::string allow_exec = prompt("allow_exec (true/false)", cfg.allow_exec ? "true" : "false");
        std::string allow_local_ip = prompt("allow_local_ip (true/false)", cfg.allow_local_ip ? "true" : "false");
        std::string control_full = prompt("control_full (true/false)", cfg.control_full ? "true" : "false");
        std::string real_http = prompt("real_http (true/false)", cfg.real_http ? "true" : "false");
        std::string real_index = prompt("real_index_path", cfg.real_index_path);
        std::string real_secret_file = prompt("real_secret_file", cfg.real_secret_file);
        std::string anonym = prompt("anonym (true/false)", cfg.anonym ? "true" : "false");
        std::string anonym_proof_mode = prompt("anonym_proof_mode", cfg.anonym_proof_mode);
        std::string anonym_api = prompt("anonym_api", cfg.anonym_api);
        std::string anonym_token = prompt("anonym_token", cfg.anonym_token);
        std::string anonym_ca_key = prompt("anonym_ca_key", cfg.anonym_ca_key);
        std::string anonym_ca_cert = prompt("anonym_ca_cert", cfg.anonym_ca_cert);
        std::string anonym_sub_key = prompt("anonym_sub_key", cfg.anonym_sub_key);
        std::string anonym_sub_cert = prompt("anonym_sub_cert", cfg.anonym_sub_cert);
        std::string outbound_proxy = prompt("outbound_proxy", cfg.outbound_proxy_url);
        std::string federation_enable = prompt("federation_enable (true/false)",
                                               cfg.federation_enable ? "true" : "false");
        std::string federation_identity = prompt("federation_identity", cfg.federation_identity);
        std::string federation_operator_ca = prompt("federation_operator_ca", cfg.federation_operator_ca);
        std::string federation_peer = prompt("federation_peer_json",
                                             cfg.federation_peers.empty() ? "" : cfg.federation_peers.front());

        const auto require_int = [](std::string_view name,
                                    std::string_view value) {
            int parsed = 0;
            if (!parse_int_strict(value, &parsed)) {
                throw std::runtime_error(std::string(name) +
                                         " must be an integer");
            }
            return parsed;
        };
        const auto require_bool = [](std::string_view name,
                                     std::string_view value) {
            if (value == "true") return true;
            if (value == "false") return false;
            throw std::runtime_error(std::string(name) +
                                     " must be true or false");
        };
        try {
            json["listen_port"] = require_int("listen_port", listen);
            json["reverse_port_min"] =
                require_int("reverse_port_min", reverse_min);
            json["reverse_port_max"] =
                require_int("reverse_port_max", reverse_max);
            json["tls_cert"] = cert;
            json["tls_key"] = key;
            json["auth_keys"] = auth;
            json["threads"] = require_int("threads", threads);
            json["obfuscation"] = require_bool("obfuscation", obfs);
            json["inner_crypto"] = require_bool("inner_crypto", inner);
            json["inner_dual"] = require_bool("inner_dual", inner_dual);
            json["inner_required"] =
                require_bool("inner_required", inner_required);
            if (!pq.empty()) json["pq_private_key"] = pq;
            json["allow_embedded_master"] = require_bool(
                "allow_embedded_master", allow_embedded_master);
            json["allow_exec"] = require_bool("allow_exec", allow_exec);
            json["allow_local_ip"] =
                require_bool("allow_local_ip", allow_local_ip);
            json["control_full"] = require_bool("control_full", control_full);
            json["real_http"] = require_bool("real_http", real_http);
            if (!real_index.empty()) json["real_index_path"] = real_index;
            if (!real_secret_file.empty()) {
                json["real_secret_file"] = real_secret_file;
            }
            json["anonym"] = require_bool("anonym", anonym);
            json["anonym_proof_mode"] =
                yume::policy::normalize_anonym_proof_mode(anonym_proof_mode);
            if (!anonym_api.empty()) json["anonym_api"] = anonym_api;
            if (!anonym_token.empty()) json["anonym_token"] = anonym_token;
            if (!anonym_ca_key.empty()) json["anonym_ca_key"] = anonym_ca_key;
            if (!anonym_ca_cert.empty()) json["anonym_ca_cert"] = anonym_ca_cert;
            if (!anonym_sub_key.empty()) json["anonym_sub_key"] = anonym_sub_key;
            if (!anonym_sub_cert.empty()) json["anonym_sub_cert"] = anonym_sub_cert;
            if (!outbound_proxy.empty()) json["outbound_proxy"] = outbound_proxy;
            json["federation_enable"] =
                require_bool("federation_enable", federation_enable);
            if (!federation_identity.empty()) {
                json["federation_identity"] = federation_identity;
            }
            if (!federation_operator_ca.empty()) {
                json["federation_operator_ca"] = federation_operator_ca;
            }
            if (!federation_peer.empty()) {
                auto peer = nlohmann::json::parse(federation_peer);
                if (!peer.is_object()) {
                    throw std::runtime_error(
                        "federation_peer_json must be a JSON object");
                }
                json["federation_peers"] =
                    nlohmann::json::array({std::move(peer)});
            }
        } catch (const std::exception& ex) {
            yume::util::log_error(std::string("invalid config input: ") +
                                  ex.what());
            return {true, 1};
        }

        std::string serialized;
        try {
            serialized = json.dump(2);
        } catch (const std::exception& ex) {
            yume::util::log_error(
                std::string("failed to serialize config: ") + ex.what());
            return {true, 1};
        }
        if (!atomic_write(out_path, serialized, &config_error)) {
            yume::util::log_error("failed to write config: " + config_error);
            return {true, 1};
        }
        std::cout << "Saved config: " << out_path << "\n";
        return {true, 0};
    } else if (choice == "7") {
        std::cout << "Prefix (path without extension) [./yume-client]: ";
        std::getline(std::cin, command.generate_prefix);
        if (command.generate_prefix.empty()) {
            command.generate_prefix = "./yume-client";
        }
    } else {
        return {true, 0};
    }
    return {};
}

CliCommandResult run_server_key_command(yume::server::ServerConfig& cfg, const ServerKeyCommand& command) {
    if (!command.has_action()) {
        return {};
    }
    if (cfg.auth_keys.empty()) {
        std::string default_auth = "/etc/yume/authorized_keys";
        if (command.ui) {
            std::cout << "auth_keys path [/etc/yume/authorized_keys]: ";
            std::string input;
            std::getline(std::cin, input);
            if (!input.empty()) {
                default_auth = input;
            }
        }
        cfg.auth_keys = default_auth;
    }
    if (cfg.auth_keys_meta.empty() && !cfg.auth_keys.empty()) {
        cfg.auth_keys_meta = cfg.auth_keys + ".json";
    }

    if (command.list) {
        if (!file_readable(cfg.auth_keys)) {
            std::cout << "No auth_keys found at: " << cfg.auth_keys << "\n";
            std::cout << "Use option 2 to add a public key first.\n";
            return {true, 0};
        }
        std::string error;
        runtime::FileTransactionLock transaction_lock;
        if (!transaction_lock.Acquire(
                {cfg.auth_keys, cfg.admin_keys, cfg.auth_keys_meta}, &error)) {
            yume::util::log_error(
                "cannot lock authorization transaction: " + error);
            return {true, 1};
        }
        nlohmann::json meta = nlohmann::json::object();
        if (!load_auth_metadata(cfg.auth_keys_meta, &meta, &error)) {
            yume::util::log_error("failed to parse auth_keys_meta: " + error);
            return {true, 1};
        }
        yume::server::AuthKeyPolicyMap policies;
        try {
            policies = yume::server::load_auth_policies(cfg.auth_keys_meta);
        } catch (const std::exception& ex) {
            yume::util::log_error(std::string("failed to parse auth_keys_meta: ") + ex.what());
            return {true, 1};
        }

        std::vector<AuthorizedIdentity> identities;
        if (!load_authorized_store(cfg.auth_keys, false, &identities, &error)) {
            yume::util::log_error("failed to read auth_keys: " + error);
            return {true, 1};
        }
        for (const auto& identity : identities) {
            const std::string& fp = identity.fingerprint;
            const auto entry = meta.value(fp, nlohmann::json::object());
            std::string alias = entry.value("alias", "");
            long long last_seen = entry.value("last_seen", 0LL);
            yume::server::AuthKeyPolicy policy;
            auto it = policies.find(fp);
            if (it != policies.end()) {
                policy = it->second;
            }
            std::cout << fp;
            if (!alias.empty()) std::cout << "  alias=" << alias;
            if (last_seen > 0) std::cout << "  last_seen=" << last_seen;
            if (!policy.empty()) std::cout << "  policy=" << yume::server::summarize_auth_policy(policy);
            std::cout << "\n";
        }
        return {true, 0};
    }

    if (!command.add.empty()) {
        return {true, append_authorized_public_key(cfg, command.add, command.alias_value,
                                                   nullptr, command.admin) ? 0 : 1};
    }

    if (!command.generate_prefix.empty()) {
        std::filesystem::path base = std::filesystem::absolute(command.generate_prefix);
        std::string priv_path = base.string() + ".key";
        std::string pub_path = base.string() + ".pub";
        auto key_dir = base.parent_path();
        if (!key_dir.empty()) {
            ensure_dir(key_dir.string());
        }
        // Both files are created exclusively, so an existing identity is never
        // silently replaced. Say that plainly instead of leaving the caller
        // with a bare EEXIST from the writer.
        for (const std::string& existing : {priv_path, pub_path}) {
            std::error_code exists_error;
            if (std::filesystem::exists(existing, exists_error)) {
                yume::util::log_error(
                    "refusing to overwrite existing key file " + existing +
                    "; choose another prefix or remove it deliberately");
                return {true, 1};
            }
        }
        if (!generate_composite_keypair(priv_path, pub_path)) {
            yume::util::log_error("failed to generate keypair");
            return {true, 1};
        }
        std::cout << "Generated: " << priv_path << " and " << pub_path << "\n";
        std::cout << "Client auth key: " << priv_path << "\n";
        if (command.generate_and_add) {
            if (!append_authorized_public_key(cfg, pub_path, command.alias_value,
                                              nullptr, command.admin)) {
                return {true, 1};
            }
            std::cout << "Use this client flag: --auth " << priv_path << "\n";
        }
        return {true, 0};
    }

    if (!command.remove.empty() || !command.alias.empty()) {
        std::string error;
        runtime::FileTransactionLock transaction_lock;
        if (!transaction_lock.Acquire(
                {cfg.auth_keys, cfg.admin_keys, cfg.auth_keys_meta}, &error)) {
            yume::util::log_error(
                "cannot lock authorization transaction: " + error);
            return {true, 1};
        }
        std::vector<AuthorizedIdentity> identities;
        if (!load_authorized_store(cfg.auth_keys, false, &identities, &error)) {
            yume::util::log_error("failed to read auth_keys: " + error);
            return {true, 1};
        }
        nlohmann::json meta = nlohmann::json::object();
        std::string original_metadata;
        bool metadata_existed = false;
        if (!load_auth_metadata(cfg.auth_keys_meta, &meta, &error,
                                &original_metadata, &metadata_existed)) {
            yume::util::log_error("failed to parse auth_keys_meta: " + error);
            return {true, 1};
        }

        if (!command.alias.empty()) {
            const auto target = resolve_identity_selector(
                identities, meta, command.alias, &error);
            if (!target.has_value()) {
                yume::util::log_error(error);
                return {true, 1};
            }
            const std::string& fingerprint = identities[*target].fingerprint;
            if (!alias_is_available(meta, command.alias_value, fingerprint,
                                    &error)) {
                yume::util::log_error(error);
                return {true, 1};
            }
            auto entry = meta.value(fingerprint, nlohmann::json::object());
            if (command.alias_value.empty()) {
                entry.erase("alias");
            } else {
                entry["alias"] = command.alias_value;
            }
            meta[fingerprint] = std::move(entry);
            std::string serialized;
            try {
                serialized = meta.dump(2);
            } catch (const std::exception& ex) {
                yume::util::log_error(
                    std::string("failed to serialize auth_keys_meta: ") +
                    ex.what());
                return {true, 1};
            }
            if (!atomic_write(cfg.auth_keys_meta, serialized, &error)) {
                const std::string write_error = error;
                std::string rollback_error;
                if (!restore_file_snapshot(cfg.auth_keys_meta,
                                           metadata_existed,
                                           original_metadata,
                                           &rollback_error)) {
                    yume::util::log_error(
                        "failed to update auth_keys_meta: " + write_error +
                        "; rollback failed: " + rollback_error);
                } else {
                    yume::util::log_error(
                        "failed to update auth_keys_meta: " + write_error);
                }
                return {true, 1};
            }
            std::cout << "Updated alias for " << fingerprint << ": "
                      << command.alias_value << "\n";
            return {true, 0};
        }

        const auto target = resolve_identity_selector(
            identities, meta, command.remove, &error);
        if (!target.has_value()) {
            yume::util::log_error(error);
            return {true, 1};
        }
        const std::string fingerprint = identities[*target].fingerprint;
        if (!atomic_write(cfg.auth_keys,
                          serialize_authorized_store(identities, target),
                          &error)) {
            yume::util::log_error("failed to rewrite auth_keys: " + error +
                                  auth_keys_write_hint(cfg.auth_keys));
            return {true, 1};
        }
        // Revocation is published before metadata cleanup. If the cleanup
        // cannot be persisted, the stale record cannot authenticate because
        // its composite identity is already absent from auth_keys.
        meta.erase(fingerprint);
        if (!atomic_write(cfg.auth_keys_meta, meta.dump(2), &error)) {
            yume::util::log_error(
                "authorized key was removed, but metadata cleanup failed: " +
                error);
            return {true, 1};
        }
        std::cout << "Removed 1 authorized key from " << cfg.auth_keys << "\n";
        return {true, 0};
    }

    return {};
}

}  // namespace yume::server::cli
