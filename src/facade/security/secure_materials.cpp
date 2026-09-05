/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "facade/security/secure_materials.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <span>
#include <system_error>
#include <unordered_set>

#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "core/encoding/hex.hpp"
#include "core/runtime/atomic_file.hpp"
#include "core/runtime/bounded_file.hpp"
#include "core/runtime/file_transaction_lock.hpp"
#include "core/security/crypto.hpp"
#include "core/security/secret_file.hpp"
#include "core/security/secure_erase.hpp"
#include "facade/config/config_io.hpp"

namespace yume::facade::secure_materials {

namespace {

using nlohmann::json;

constexpr char kDefaultAnonymCaPem[] = R"(-----BEGIN CERTIFICATE-----
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
5pM0GOWr3uwEFGukOUg6Va4ibQNLS/0=
-----END CERTIFICATE-----
)";

std::filesystem::path metadata_path() {
    return store_dir() / "materials.json";
}

constexpr int kMetadataSchema = 1;
constexpr std::size_t kRandomIdBytes = 16;
constexpr unsigned kIdCreateAttempts = 128;

class StringWiper {
public:
    explicit StringWiper(std::string& value) noexcept : value_(value) {}
    ~StringWiper() { security::secure_erase(value_); }

    StringWiper(const StringWiper&) = delete;
    StringWiper& operator=(const StringWiper&) = delete;

private:
    std::string& value_;
};

void append_error(std::string* error, std::string_view detail) {
    if (!error) return;
    if (!error->empty()) error->append("; ");
    error->append(detail);
}

std::string normalize_pem(std::string text) {
    while (!text.empty() && (text.back() == '\n' || text.back() == '\r' ||
                             text.back() == ' ' || text.back() == '\t')) {
        text.pop_back();
    }
    return text.empty() ? std::string{} : text + "\n";
}

std::string wire_type(MaterialType type) {
    switch (type) {
        case MaterialType::AuthKey:      return "auth_key";
        case MaterialType::AnonymPubkey: return "anonym_pubkey";
        case MaterialType::TlsCa:        return "tls_ca";
        case MaterialType::AnonymCa:
        default:                         return "anonym_ca";
    }
}

std::optional<MaterialType> parse_type(std::string_view value) {
    if (value == "auth_key") return MaterialType::AuthKey;
    if (value == "anonym_pubkey") return MaterialType::AnonymPubkey;
    if (value == "tls_ca") return MaterialType::TlsCa;
    if (value == "anonym_ca") return MaterialType::AnonymCa;
    return std::nullopt;
}

const char* extension_for_type(MaterialType type) {
    switch (type) {
        case MaterialType::AuthKey: return ".key.pem";
        case MaterialType::AnonymPubkey: return ".pub.pem";
        case MaterialType::TlsCa: return ".tls.pem";
        case MaterialType::AnonymCa: return ".ca.pem";
    }
    return ".pem";
}

std::filesystem::path path_for(std::string_view id, MaterialType type) {
    return store_dir() /
           (std::string(id) + std::string(extension_for_type(type)));
}

bool is_lower_hex(std::string_view value) {
    return std::all_of(value.begin(), value.end(), [](char character) {
        return (character >= '0' && character <= '9') ||
               (character >= 'a' && character <= 'f');
    });
}

bool valid_material_id(std::string_view id) {
    return id.size() == kRandomIdBytes * 2U && is_lower_hex(id);
}

bool valid_fingerprint(std::string_view fingerprint) {
    return fingerprint.size() == 12U && is_lower_hex(fingerprint);
}

bool valid_label(std::string_view label) {
    return label.size() <= kMaximumMaterialLabelBytes;
}

std::string short_fingerprint(std::string const& text) {
    return crypto::sha256_hex(text).substr(0, 12U);
}

bool validate_ca(std::string const& pem, std::string* err) {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(
        BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    if (!bio) {
        if (err) *err = "OpenSSL BIO allocation failed";
        return false;
    }
    std::unique_ptr<X509, decltype(&X509_free)> cert(
        PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr), X509_free);
    if (!cert) {
        if (err) *err = "PEM does not contain a valid X.509 certificate";
        return false;
    }
    return true;
}

bool validate_auth_key(std::string const& pem, std::string* err) {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(
        BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    if (!bio) {
        if (err) *err = "OpenSSL BIO allocation failed";
        return false;
    }
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
        PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    if (!key) {
        if (err) *err = "PEM does not contain a readable private key";
        return false;
    }
    return true;
}

bool validate_pubkey(std::string const& pem, std::string* err) {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(
        BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    if (!bio) {
        if (err) *err = "OpenSSL BIO allocation failed";
        return false;
    }
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
        PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    if (!key) {
        if (err) *err = "PEM does not contain a readable public key";
        return false;
    }
    return true;
}

bool validate_material(MaterialType type, std::string const& pem, std::string* err) {
    if (pem.empty()) {
        if (err) *err = std::string(type_label(type)) + " PEM is empty";
        return false;
    }
    if (pem.size() > kMaximumPemBytes) {
        if (err) *err = std::string(type_label(type)) + " PEM exceeds 64 KiB";
        return false;
    }
    switch (type) {
        case MaterialType::AnonymCa:
        case MaterialType::TlsCa:        return validate_ca(pem, err);
        case MaterialType::AuthKey:      return validate_auth_key(pem, err);
        case MaterialType::AnonymPubkey: return validate_pubkey(pem, err);
    }
    if (err) *err = "secure material type is invalid";
    return false;
}

std::string make_id() {
    const crypto::Bytes random = crypto::random_bytes(kRandomIdBytes);
    return encoding::hex_lower(random);
}

long long now_ms() {
    auto now = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
}

struct MaterialStoreState {
    std::vector<MaterialSummary> materials_;
    bool embedded_anonym_ca_enabled_{true};
};

struct MetadataSnapshot {
    bool existed_{false};
    std::string serialized_;
};

bool read_string(const json& object,
                 const char* field,
                 bool required,
                 std::size_t maximum_bytes,
                 std::string* value,
                 std::string* error) {
    const auto iterator = object.find(field);
    if (iterator == object.end()) {
        if (required) {
            if (error) *error = std::string("missing material field: ") + field;
            return false;
        }
        value->clear();
        return true;
    }
    if (!iterator->is_string()) {
        if (error) *error = std::string("material field must be a string: ") + field;
        return false;
    }
    try {
        *value = iterator->get<std::string>();
    } catch (const json::exception& exception) {
        if (error) {
            *error = std::string("invalid material field ") + field + ": " +
                     exception.what();
        }
        return false;
    }
    if (value->size() > maximum_bytes) {
        if (error) *error = std::string("material field is too long: ") + field;
        return false;
    }
    return true;
}

bool parse_material_record(const json& item,
                           MaterialSummary* summary,
                           std::string* error) {
    if (!item.is_object()) {
        if (error) *error = "secure material record must be an object";
        return false;
    }

    std::string type_value;
    if (!read_string(item, "id", true, 64U, &summary->id, error) ||
        !read_string(item, "display_name", false,
                     kMaximumMaterialLabelBytes, &summary->display_name, error) ||
        !read_string(item, "type", true, 32U, &type_value, error) ||
        !read_string(item, "source_label", false,
                     kMaximumMaterialLabelBytes, &summary->source_label, error) ||
        !read_string(item, "fingerprint", true, 12U,
                     &summary->fingerprint, error)) {
        return false;
    }
    if (!valid_material_id(summary->id)) {
        if (error) *error = "secure material id is invalid";
        return false;
    }
    const auto parsed_type = parse_type(type_value);
    if (!parsed_type) {
        if (error) *error = "secure material type is invalid";
        return false;
    }
    summary->type = *parsed_type;
    if (!valid_fingerprint(summary->fingerprint)) {
        if (error) *error = "secure material fingerprint is invalid";
        return false;
    }

    if (item.contains("path")) {
        if (error) *error = "secure material records derive their path from id and type";
        return false;
    }
    if (const auto encrypted = item.find("imported_encrypted");
        encrypted != item.end()) {
        if (!encrypted->is_boolean()) {
            if (error) *error = "imported_encrypted must be a boolean";
            return false;
        }
        summary->imported_encrypted = encrypted->get<bool>();
    }
    if (const auto created = item.find("created_at_epoch_ms");
        created != item.end()) {
        if (!created->is_number_integer() && !created->is_number_unsigned()) {
            if (error) *error = "created_at_epoch_ms must be an integer";
            return false;
        }
        try {
            summary->created_at_epoch_ms = created->get<long long>();
        } catch (const json::exception& exception) {
            if (error) {
                *error = std::string("created_at_epoch_ms is out of range: ") +
                         exception.what();
            }
            return false;
        }
        if (summary->created_at_epoch_ms < 0) {
            if (error) *error = "created_at_epoch_ms must not be negative";
            return false;
        }
    }
    summary->path = path_for(summary->id, summary->type);
    return true;
}

bool read_store_state(MaterialStoreState* state, std::string* error) {
    if (error) error->clear();
    *state = MaterialStoreState{};
    if (!security::ensure_private_directory(store_dir(), error)) {
        return false;
    }

    std::error_code status_error;
    const auto status = std::filesystem::symlink_status(
        metadata_path(), status_error);
    if (status_error == std::errc::no_such_file_or_directory ||
        status.type() == std::filesystem::file_type::not_found) {
        return true;
    }
    if (status_error) {
        if (error) {
            *error = "cannot inspect secure material metadata: " +
                     status_error.message();
        }
        return false;
    }

    std::string serialized;
    if (!runtime::read_text_file_bounded(
            metadata_path(), kMaximumMetadataBytes, &serialized, error)) {
        if (error && !error->empty()) {
            *error = "invalid secure material metadata: " + *error;
        }
        return false;
    }

    json root;
    try {
        root = json::parse(serialized);
    } catch (const json::exception& exception) {
        if (error) {
            *error = std::string("invalid secure material metadata: ") +
                     exception.what();
        }
        return false;
    }
    if (!root.is_object()) {
        if (error) *error = "secure material metadata root must be an object";
        return false;
    }
    const auto schema = root.find("schema");
    if (schema == root.end() || !schema->is_number_integer() ||
        *schema != kMetadataSchema) {
        if (error) *error = "unsupported secure material metadata schema";
        return false;
    }
    if (const auto embedded = root.find("embedded_anonym_ca_enabled");
        embedded != root.end()) {
        if (!embedded->is_boolean()) {
            if (error) *error = "embedded_anonym_ca_enabled must be a boolean";
            return false;
        }
        state->embedded_anonym_ca_enabled_ = embedded->get<bool>();
    }

    auto items = root.find("materials");
    if (items == root.end()) return true;
    if (!items->is_array()) {
        if (error) *error = "secure material records must be an array";
        return false;
    }
    if (items->size() > kMaximumMaterialRecords) {
        if (error) *error = "secure material record limit exceeded";
        return false;
    }

    std::unordered_set<std::string> ids;
    state->materials_.reserve(items->size());
    for (auto const& item : *items) {
        MaterialSummary s;
        if (!parse_material_record(item, &s, error)) return false;
        if (!ids.insert(s.id).second) {
            if (error) *error = "duplicate secure material id";
            return false;
        }
        std::vector<std::uint8_t> contents;
        if (!runtime::read_file_bounded(
                s.path, kMaximumPemBytes, &contents, error)) {
            security::secure_erase(contents);
            if (error && !error->empty()) {
                *error = "invalid secure material file: " + *error;
            }
            return false;
        }
        security::secure_erase(contents);
        state->materials_.push_back(std::move(s));
    }
    return true;
}

bool write_store_state(MaterialStoreState const& state, std::string* err) {
    try {
        if (state.materials_.size() > kMaximumMaterialRecords) {
            if (err) *err = "secure material record limit exceeded";
            return false;
        }
        if (!security::ensure_private_directory(store_dir(), err)) {
            return false;
        }

        json arr = json::array();
        for (auto const& material : state.materials_) {
            if (material.is_default) continue;
            arr.push_back({
                {"id", material.id},
                {"display_name", material.display_name},
                {"type", wire_type(material.type)},
                {"source_label", material.source_label},
                {"fingerprint", material.fingerprint},
                {"imported_encrypted", material.imported_encrypted},
                {"created_at_epoch_ms", material.created_at_epoch_ms},
            });
        }
        json root = {
            {"schema", kMetadataSchema},
            {"embedded_anonym_ca_enabled",
             state.embedded_anonym_ca_enabled_},
            {"materials", std::move(arr)},
        };
        const std::string serialized = root.dump(2);
        return runtime::AtomicWriteFile(
            metadata_path(), serialized, err,
            runtime::ParentDirectoryPolicy::RequireExisting,
            runtime::FileProtection::OwnerOnly);
    } catch (const std::exception& exception) {
        if (err) {
            *err = std::string("cannot serialize secure material metadata: ") +
                   exception.what();
        }
        return false;
    }
}

bool capture_metadata_snapshot(MetadataSnapshot* snapshot,
                               std::string* error) {
    *snapshot = MetadataSnapshot{};
    std::error_code status_error;
    const auto status = std::filesystem::symlink_status(
        metadata_path(), status_error);
    if (status_error == std::errc::no_such_file_or_directory ||
        status.type() == std::filesystem::file_type::not_found) {
        return true;
    }
    if (status_error) {
        if (error) {
            *error = "cannot inspect secure material metadata: " +
                     status_error.message();
        }
        return false;
    }
    if (!runtime::read_text_file_bounded(
            metadata_path(), kMaximumMetadataBytes,
            &snapshot->serialized_, error)) {
        return false;
    }
    snapshot->existed_ = true;
    return true;
}

bool restore_metadata_snapshot(const MetadataSnapshot& snapshot,
                               std::string* error) {
    if (!snapshot.existed_) {
        return runtime::DurableRemoveFile(metadata_path(), error);
    }
    return runtime::AtomicWriteFile(
        metadata_path(), snapshot.serialized_, error,
        runtime::ParentDirectoryPolicy::RequireExisting,
        runtime::FileProtection::OwnerOnly);
}

bool state_contains_material(const MaterialStoreState& state,
                             std::string_view id) {
    return std::any_of(state.materials_.begin(), state.materials_.end(),
                       [&](const MaterialSummary& material) {
                           return material.id == id;
                       });
}

bool acquire_store_lock(runtime::FileTransactionLock* lock,
                        const std::vector<std::filesystem::path>& resources,
                        std::string* error) {
    if (!security::ensure_private_directory(store_dir(), error)) return false;
    return lock->Acquire(resources, error);
}

const char* default_display_name(MaterialType type) {
    switch (type) {
        case MaterialType::AuthKey: return "Imported auth key";
        case MaterialType::AnonymPubkey: return "Imported external proof key";
        case MaterialType::TlsCa: return "Imported TLS CA";
        case MaterialType::AnonymCa: return "Imported operator CA";
    }
    return "Imported material";
}

bool import_material(MaterialType type,
                     std::string const& display_name,
                     std::string const& source_label,
                     std::string pem,
                     MaterialSummary* out,
                     std::string* error) {
    StringWiper pem_wiper(pem);
    if (!valid_label(display_name) || !valid_label(source_label)) {
        if (error) *error = "secure material label exceeds 256 bytes";
        return false;
    }
    if (!validate_material(type, pem, error)) return false;

    runtime::FileTransactionLock lock;
    if (!acquire_store_lock(&lock, {metadata_path()}, error)) return false;

    MetadataSnapshot metadata_before;
    if (!capture_metadata_snapshot(&metadata_before, error)) return false;

    MaterialStoreState state;
    if (!read_store_state(&state, error)) return false;
    if (state.materials_.size() >= kMaximumMaterialRecords) {
        if (error) *error = "secure material record limit exceeded";
        return false;
    }

    MaterialSummary summary;
    summary.display_name =
        display_name.empty() ? default_display_name(type) : display_name;
    summary.type = type;
    summary.source_label = source_label;
    summary.fingerprint = short_fingerprint(pem);
    summary.created_at_epoch_ms = now_ms();

    const auto bytes = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(pem.data()), pem.size());
    std::string create_error;
    bool created = false;
    for (unsigned attempt = 0; attempt < kIdCreateAttempts; ++attempt) {
        try {
            summary.id = make_id();
        } catch (const std::exception& exception) {
            if (error) {
                *error = std::string("cannot generate secure material id: ") +
                         exception.what();
            }
            return false;
        }
        summary.path = path_for(summary.id, type);
        if (security::WriteFileExclusive0600(
                summary.path, bytes, &create_error)) {
            created = true;
            break;
        }
        std::error_code status_error;
        const auto status = std::filesystem::symlink_status(
            summary.path, status_error);
        const bool missing =
            status.type() == std::filesystem::file_type::not_found ||
            status_error == std::errc::no_such_file_or_directory;
        if (missing || status_error) {
            if (error) *error = create_error;
            return false;
        }
        if (status.type() != std::filesystem::file_type::regular) {
            if (error) *error = "secure material destination is not a regular file";
            return false;
        }
    }
    if (!created) {
        if (error) *error = "secure material id collision attempts exhausted";
        return false;
    }

    try {
        state.materials_.insert(state.materials_.begin(), summary);
    } catch (const std::exception& exception) {
        if (error) {
            *error = std::string("cannot stage secure material metadata: ") +
                     exception.what();
        }
        std::string cleanup_error;
        if (!runtime::DurableRemoveFile(summary.path, &cleanup_error)) {
            append_error(error, "cannot clean up unpublished material: " +
                                    cleanup_error);
        }
        return false;
    }
    if (!write_store_state(state, error)) {
        const std::string publication_error = error ? *error : std::string{};
        std::string rollback_error;
        bool metadata_rolled_back =
            restore_metadata_snapshot(metadata_before, &rollback_error);
        if (!metadata_rolled_back) {
            MaterialStoreState observed;
            std::string inspect_error;
            if (read_store_state(&observed, &inspect_error) &&
                !state_contains_material(observed, summary.id)) {
                metadata_rolled_back = true;
            }
        }
        if (error) *error = publication_error;
        if (metadata_rolled_back) {
            std::string cleanup_error;
            if (!runtime::DurableRemoveFile(summary.path, &cleanup_error)) {
                append_error(error, "cannot clean up unpublished material: " +
                                        cleanup_error);
            }
        } else {
            append_error(error,
                         "cannot restore prior metadata: " + rollback_error +
                             "; retained material to avoid a metadata record "
                             "that references a missing file");
        }
        return false;
    }
    if (out) *out = std::move(summary);
    return true;
}

std::filesystem::path ensure_default_anonym_ca_locked(std::string* err) {
    const auto path = store_dir() / "default_anonym_ca.pem";
    const std::string pem = normalize_pem(kDefaultAnonymCaPem);
    std::error_code status_error;
    const auto status = std::filesystem::symlink_status(path, status_error);
    const bool missing =
        status.type() == std::filesystem::file_type::not_found ||
        status_error == std::errc::no_such_file_or_directory;
    if (!missing && !status_error) {
        std::string existing;
        if (!runtime::read_text_file_bounded(
                path, kMaximumPemBytes, &existing, err)) {
            return {};
        }
        if (normalize_pem(std::move(existing)) == pem) return path;

        if (err) *err = "embedded operator CA file has unexpected contents";
        return {};
    }
    if (!missing && status_error) {
        if (err) *err = "cannot inspect embedded operator CA: " +
                        status_error.message();
        return {};
    }

    const auto bytes = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(pem.data()), pem.size());
    if (!security::WriteFileExclusive0600(path, bytes, err)) return {};
    return path;
}

}  // namespace

std::filesystem::path store_dir() {
    return config_io::default_data_dir() / "secure-materials";
}

std::filesystem::path ensure_default_anonym_ca(std::string* err) {
    const auto path = store_dir() / "default_anonym_ca.pem";
    if (!security::ensure_private_directory(store_dir(), err)) return {};

    runtime::FileTransactionLock lock;
    if (!lock.Acquire({metadata_path(), path}, err)) return {};
    return ensure_default_anonym_ca_locked(err);
}

std::vector<MaterialSummary> list(MaterialType type, std::string* err) {
    if (err) err->clear();
    std::vector<MaterialSummary> out;
    runtime::FileTransactionLock lock;
    if (type == MaterialType::AnonymCa &&
        !acquire_store_lock(
            &lock,
            {metadata_path(), store_dir() / "default_anonym_ca.pem"}, err)) {
        return out;
    }
    MaterialStoreState state;
    if (!read_store_state(&state, err)) return out;

    if (type == MaterialType::AnonymCa &&
        state.embedded_anonym_ca_enabled_) {
        std::string ca_err;
        auto ca_path = ensure_default_anonym_ca_locked(&ca_err);
        if (ca_path.empty()) {
            if (err && err->empty()) *err = ca_err;
        } else {
            MaterialSummary s;
            s.id = kDefaultAnonymCaId;
            s.display_name = "Built-in CA";
            s.type = MaterialType::AnonymCa;
            s.source_label = "Default";
            s.fingerprint = short_fingerprint(normalize_pem(kDefaultAnonymCaPem));
            s.path = ca_path;
            s.is_default = true;
            out.push_back(std::move(s));
        }
    }

    for (auto& s : state.materials_) {
        if (s.type == type) out.push_back(std::move(s));
    }
    return out;
}

std::optional<MaterialSummary> get(std::string const& id, std::string* err) {
    if (err) err->clear();
    if (id == kDefaultAnonymCaId) {
        auto items = list(MaterialType::AnonymCa, err);
        for (auto const& s : items) {
            if (s.id == id) return s;
        }
        return std::nullopt;
    }
    if (!valid_material_id(id)) {
        if (err) *err = "secure material id is invalid";
        return std::nullopt;
    }
    MaterialStoreState state;
    if (!read_store_state(&state, err)) return std::nullopt;
    for (auto const& s : state.materials_) {
        if (s.id == id) return s;
    }
    if (err) *err = "secure material not found: " + id;
    return std::nullopt;
}

std::optional<std::filesystem::path> material_path(std::string const& id, std::string* err) {
    auto item = get(id, err);
    if (!item) return std::nullopt;
    std::vector<std::uint8_t> contents;
    if (!runtime::read_file_bounded(
            item->path, kMaximumPemBytes, &contents, err)) {
        return std::nullopt;
    }
    security::secure_erase(contents);
    return item->path;
}

bool import_text(MaterialType type,
                 std::string const& display_name,
                 std::string const& pem_text,
                 MaterialSummary* out,
                 std::string* err) {
    if (pem_text.size() > kMaximumPemBytes) {
        if (err) *err = std::string(type_label(type)) + " PEM exceeds 64 KiB";
        return false;
    }
    return import_material(type, display_name, "Imported",
                           normalize_pem(pem_text), out, err);
}

bool import_file(MaterialType type,
                 std::string const& display_name,
                 std::filesystem::path const& source_path,
                 MaterialSummary* out,
                 std::string* err) {
    std::string pem;
    if (!runtime::read_text_file_bounded(
            source_path, kMaximumPemBytes, &pem, err)) {
        return false;
    }
    return import_material(type, display_name,
                           source_path.filename().string(),
                           normalize_pem(std::move(pem)), out, err);
}

bool remove(std::string const& id, std::string* err) {
    if (err) err->clear();
    runtime::FileTransactionLock lock;
    std::vector<std::filesystem::path> resources{metadata_path()};
    if (id == kDefaultAnonymCaId) {
        resources.push_back(store_dir() / "default_anonym_ca.pem");
    }
    if (!acquire_store_lock(&lock, resources, err)) return false;

    MetadataSnapshot metadata_before;
    if (!capture_metadata_snapshot(&metadata_before, err)) return false;

    MaterialStoreState state;
    if (!read_store_state(&state, err)) return false;

    auto restore_metadata_after_failure =
        [&](const std::string& primary_error) {
            std::string rollback_error;
            const bool restored =
                restore_metadata_snapshot(metadata_before, &rollback_error);
            if (err) *err = primary_error;
            if (!restored) {
                append_error(err, "cannot restore prior metadata: " +
                                      rollback_error);
            }
            return restored;
        };

    auto restore_removed_file =
        [&](const std::filesystem::path& path,
            std::span<const std::uint8_t> bytes,
            std::string* restore_error) {
            std::error_code status_error;
            const auto status =
                std::filesystem::symlink_status(path, status_error);
            const bool missing =
                status.type() == std::filesystem::file_type::not_found ||
                status_error == std::errc::no_such_file_or_directory;
            if (missing) {
                return security::WriteFileExclusive0600(
                    path, bytes, restore_error);
            }
            if (status_error) {
                if (restore_error) {
                    *restore_error = "cannot inspect removed material: " +
                                     status_error.message();
                }
                return false;
            }
            if (status.type() != std::filesystem::file_type::regular) {
                if (restore_error) {
                    *restore_error =
                        "removed material path is no longer a regular file";
                }
                return false;
            }
            return true;
        };

    if (id == kDefaultAnonymCaId) {
        if (!state.embedded_anonym_ca_enabled_) {
            if (err) *err = "embedded operator CA is already removed";
            return false;
        }
        const std::string default_pem = normalize_pem(kDefaultAnonymCaPem);
        const auto default_bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(default_pem.data()),
            default_pem.size());
        state.embedded_anonym_ca_enabled_ = false;
        std::string publication_error;
        if (!write_store_state(state, &publication_error)) {
            restore_metadata_after_failure(publication_error);
            return false;
        }

        const auto default_path = store_dir() / "default_anonym_ca.pem";
        std::string remove_error;
        if (runtime::DurableRemoveFile(default_path, &remove_error)) return true;

        const std::string primary_error =
            "cannot remove embedded operator CA: " + remove_error;
        std::string material_restore_error;
        if (!restore_removed_file(default_path, default_bytes,
                                  &material_restore_error)) {
            if (err) *err = primary_error;
            append_error(err, "cannot restore embedded operator CA: " +
                                  material_restore_error);
            return false;
        }
        restore_metadata_after_failure(primary_error);
        return false;
    }
    if (!valid_material_id(id)) {
        if (err) *err = "secure material id is invalid";
        return false;
    }
    auto it = std::find_if(state.materials_.begin(), state.materials_.end(),
                           [&](auto const& s) {
        return s.id == id;
    });
    if (it == state.materials_.end()) {
        if (err) *err = "secure material not found: " + id;
        return false;
    }
    const auto material_file = path_for(it->id, it->type);
    std::string serialized;
    if (!runtime::read_text_file_bounded(
            material_file, kMaximumPemBytes, &serialized, err)) {
        return false;
    }
    StringWiper serialized_wiper(serialized);

    state.materials_.erase(it);
    std::string publication_error;
    if (!write_store_state(state, &publication_error)) {
        restore_metadata_after_failure(publication_error);
        return false;
    }

    std::string remove_error;
    if (runtime::DurableRemoveFile(material_file, &remove_error)) return true;

    const auto bytes = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(serialized.data()),
        serialized.size());
    const std::string primary_error =
        "cannot remove secure material: " + remove_error;
    std::string material_restore_error;
    if (!restore_removed_file(material_file, bytes,
                              &material_restore_error)) {
        if (err) *err = primary_error;
        append_error(err, "cannot restore secure material: " +
                              material_restore_error);
        return false;
    }
    restore_metadata_after_failure(primary_error);
    return false;
}

char const* type_label(MaterialType type) {
    switch (type) {
        case MaterialType::AuthKey:      return "Auth key";
        case MaterialType::AnonymPubkey: return "External proof key";
        case MaterialType::TlsCa:        return "TLS CA";
        case MaterialType::AnonymCa:
        default:                         return "Operator CA";
    }
}

}  // namespace yume::facade::secure_materials
