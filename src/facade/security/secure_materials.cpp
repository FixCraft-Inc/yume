/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "facade/security/secure_materials.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <random>
#include <sstream>
#include <system_error>

#ifndef _WIN32
#include <sys/stat.h>
#endif

#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

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

MaterialType parse_type(std::string const& value) {
    if (value == "auth_key")      return MaterialType::AuthKey;
    if (value == "anonym_pubkey") return MaterialType::AnonymPubkey;
    if (value == "tls_ca")        return MaterialType::TlsCa;
    return MaterialType::AnonymCa;
}

std::string hex_lower(unsigned char const* data, std::size_t n) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out(n * 2, '0');
    for (std::size_t i = 0; i < n; ++i) {
        out[i * 2] = kHex[(data[i] >> 4) & 0x0f];
        out[i * 2 + 1] = kHex[data[i] & 0x0f];
    }
    return out;
}

std::string short_fingerprint(std::string const& text) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<unsigned char const*>(text.data()), text.size(), digest);
    return hex_lower(digest, 6);
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
    switch (type) {
        case MaterialType::AnonymCa:
        case MaterialType::TlsCa:        return validate_ca(pem, err);
        case MaterialType::AuthKey:      return validate_auth_key(pem, err);
        case MaterialType::AnonymPubkey: return validate_pubkey(pem, err);
    }
    return false;
}

std::string make_id() {
    auto now = std::chrono::system_clock::now().time_since_epoch().count();
    std::random_device rd;
    unsigned int r0 = rd();
    unsigned int r1 = rd();
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%llx-%08x%08x",
                  static_cast<unsigned long long>(now), r0, r1);
    return buf;
}

long long now_ms() {
    auto now = std::chrono::system_clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
}

std::vector<MaterialSummary> read_user_materials(std::string* err) {
    std::vector<MaterialSummary> out;
    std::ifstream in(metadata_path());
    if (!in) return out;

    json root;
    try {
        in >> root;
    } catch (std::exception const& e) {
        if (err) *err = std::string("invalid secure material metadata: ") + e.what();
        return out;
    }

    auto items = root.find("materials");
    if (items == root.end() || !items->is_array()) return out;
    for (auto const& item : *items) {
        MaterialSummary s;
        s.id = item.value("id", "");
        if (s.id.empty()) continue;
        s.display_name = item.value("display_name", "");
        s.type = parse_type(item.value("type", ""));
        s.source_label = item.value("source_label", "");
        s.fingerprint = item.value("fingerprint", "");
        s.path = item.value("path", "");
        s.imported_encrypted = item.value("imported_encrypted", false);
        s.created_at_epoch_ms = item.value("created_at_epoch_ms", 0LL);
        out.push_back(std::move(s));
    }
    return out;
}

bool write_user_materials(std::vector<MaterialSummary> const& items, std::string* err) {
    std::error_code ec;
    std::filesystem::create_directories(store_dir(), ec);

    json arr = json::array();
    for (auto const& s : items) {
        if (s.is_default) continue;
        arr.push_back({
            {"id", s.id},
            {"display_name", s.display_name},
            {"type", wire_type(s.type)},
            {"source_label", s.source_label},
            {"fingerprint", s.fingerprint},
            {"path", s.path.string()},
            {"imported_encrypted", s.imported_encrypted},
            {"created_at_epoch_ms", s.created_at_epoch_ms},
        });
    }
    json root = {{"materials", arr}};
    std::ofstream out(metadata_path());
    if (!out) {
        if (err) *err = "cannot write " + metadata_path().string();
        return false;
    }
    out << root.dump(2);
    return out.good();
}

void chmod_private(std::filesystem::path const& path) {
#ifndef _WIN32
    ::chmod(path.c_str(), S_IRUSR | S_IWUSR);
#else
    (void)path;
#endif
}

}  // namespace

std::filesystem::path store_dir() {
    return config_io::default_data_dir() / "secure-materials";
}

std::filesystem::path ensure_default_anonym_ca(std::string* err) {
    auto path = store_dir() / "default_anonym_ca.pem";
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        if (err) *err = "cannot create secure material directory: " + ec.message();
        return {};
    }

    const std::string pem = normalize_pem(kDefaultAnonymCaPem);
    std::ifstream existing(path);
    if (existing) {
        std::stringstream ss;
        ss << existing.rdbuf();
        if (normalize_pem(ss.str()) == pem) return path;
    }

    std::ofstream out(path);
    if (!out) {
        if (err) *err = "cannot write embedded anonym CA to " + path.string();
        return {};
    }
    out << pem;
    return out.good() ? path : std::filesystem::path{};
}

std::vector<MaterialSummary> list(MaterialType type, std::string* err) {
    std::vector<MaterialSummary> out;
    if (type == MaterialType::AnonymCa) {
        std::string ca_err;
        auto ca_path = ensure_default_anonym_ca(&ca_err);
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

    std::string load_err;
    auto user = read_user_materials(&load_err);
    if (!load_err.empty() && err) *err = load_err;
    for (auto& s : user) {
        if (s.type == type) out.push_back(std::move(s));
    }
    return out;
}

std::optional<MaterialSummary> get(std::string const& id, std::string* err) {
    if (id == kDefaultAnonymCaId) {
        auto items = list(MaterialType::AnonymCa, err);
        for (auto const& s : items) {
            if (s.id == id) return s;
        }
        return std::nullopt;
    }
    auto user = read_user_materials(err);
    for (auto const& s : user) {
        if (s.id == id) return s;
    }
    if (err) *err = "secure material not found: " + id;
    return std::nullopt;
}

std::optional<std::filesystem::path> material_path(std::string const& id, std::string* err) {
    auto item = get(id, err);
    if (!item) return std::nullopt;
    if (!std::filesystem::is_regular_file(item->path)) {
        if (err) *err = "secure material file missing: " + item->path.string();
        return std::nullopt;
    }
    return item->path;
}

bool import_text(MaterialType type,
                 std::string const& display_name,
                 std::string const& pem_text,
                 MaterialSummary* out,
                 std::string* err) {
    std::string pem = normalize_pem(pem_text);
    if (!validate_material(type, pem, err)) return false;

    auto id = make_id();
    auto ext = [&]() -> char const* {
        switch (type) {
            case MaterialType::AuthKey:      return ".key.pem";
            case MaterialType::AnonymPubkey: return ".pub.pem";
            case MaterialType::TlsCa:        return ".tls.pem";
            case MaterialType::AnonymCa:
            default:                         return ".ca.pem";
        }
    }();
    auto path = store_dir() / (id + ext);
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);

    std::ofstream file(path);
    if (!file) {
        if (err) *err = "cannot write " + path.string();
        return false;
    }
    file << pem;
    file.close();
    if (!file) {
        if (err) *err = "cannot finish writing " + path.string();
        return false;
    }
    if (type == MaterialType::AuthKey) chmod_private(path);

    auto default_name = [&]() -> char const* {
        switch (type) {
            case MaterialType::AuthKey:      return "Imported auth key";
            case MaterialType::AnonymPubkey: return "Imported anonym public key";
            case MaterialType::TlsCa:        return "Imported TLS CA";
            case MaterialType::AnonymCa:
            default:                         return "Imported anonym CA";
        }
    };
    MaterialSummary s;
    s.id = id;
    s.display_name = display_name.empty() ? default_name() : display_name;
    s.type = type;
    s.source_label = "Imported";
    s.fingerprint = short_fingerprint(pem);
    s.path = path;
    s.created_at_epoch_ms = now_ms();

    auto items = read_user_materials(err);
    items.insert(items.begin(), s);
    if (!write_user_materials(items, err)) return false;
    if (out) *out = std::move(s);
    return true;
}

bool import_file(MaterialType type,
                 std::string const& display_name,
                 std::filesystem::path const& source_path,
                 MaterialSummary* out,
                 std::string* err) {
    std::ifstream in(source_path);
    if (!in) {
        if (err) *err = "cannot open " + source_path.string();
        return false;
    }
    std::stringstream ss;
    ss << in.rdbuf();
    bool ok = import_text(type, display_name, ss.str(), out, err);
    if (ok && out) out->source_label = source_path.filename().string();
    if (ok && out) {
        auto items = read_user_materials(err);
        for (auto& item : items) {
            if (item.id == out->id) item.source_label = out->source_label;
        }
        (void)write_user_materials(items, err);
    }
    return ok;
}

bool remove(std::string const& id, std::string* err) {
    if (id == kDefaultAnonymCaId) {
        if (err) *err = "embedded anonym CA cannot be removed";
        return false;
    }
    auto items = read_user_materials(err);
    auto it = std::find_if(items.begin(), items.end(), [&](auto const& s) {
        return s.id == id;
    });
    if (it == items.end()) {
        if (err) *err = "secure material not found: " + id;
        return false;
    }
    std::error_code ec;
    std::filesystem::remove(it->path, ec);
    items.erase(it);
    return write_user_materials(items, err);
}

char const* type_label(MaterialType type) {
    switch (type) {
        case MaterialType::AuthKey:      return "Auth key";
        case MaterialType::AnonymPubkey: return "Anonym public key";
        case MaterialType::TlsCa:        return "TLS CA";
        case MaterialType::AnonymCa:
        default:                         return "Anonym CA";
    }
}

}  // namespace yume::facade::secure_materials
