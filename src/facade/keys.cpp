/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "facade/keys.hpp"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <memory>
#include <sstream>
#include <string_view>
#include <system_error>

#if defined(_WIN32)
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

#include "core/inner_crypto.hpp"
#include "server/auth/auth.hpp"

namespace yume::facade::keys {

namespace {

using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using BIO_ptr      = std::unique_ptr<BIO,      decltype(&BIO_free)>;

struct FileDeleter {
    void operator()(FILE* f) const noexcept { if (f) std::fclose(f); }
};
using FILE_ptr = std::unique_ptr<FILE, FileDeleter>;

struct OpenSSLFreeDeleter {
    void operator()(unsigned char* p) const noexcept { OPENSSL_free(p); }
};
using OpenSSLBuf = std::unique_ptr<unsigned char, OpenSSLFreeDeleter>;

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

std::optional<std::string> fingerprint_pem_der(const std::string& pem,
                                               std::string* err) {
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

bool write_pem(std::filesystem::path const& path, EVP_PKEY* key, bool is_private,
               std::string* err) {
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);

    // Open with O_CREAT|O_EXCL not needed for overwrites here, but we MUST set
    // an explicit mode. The default umask path through std::fopen leaves the
    // file at 0666 if umask is 0; private keys must be 0600 to keep them out
    // of group/other readers on shared hosts.
#if defined(_WIN32)
    FILE_ptr f(std::fopen(path.string().c_str(), "wb"));
#else
    int oflags = O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC;
    mode_t mode = is_private ? S_IRUSR | S_IWUSR                                          // 0600
                             : S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;                     // 0644
    int fd = ::open(path.string().c_str(), oflags, mode);
    if (fd < 0) {
        if (err) *err = "cannot create " + path.string();
        return false;
    }
    // If the file pre-existed with looser permissions, tighten them — open()
    // does not chmod() when O_CREAT finds an existing file.
    ::fchmod(fd, mode);
    FILE_ptr f(::fdopen(fd, "wb"));
    if (!f) {
        ::close(fd);
        if (err) *err = "cannot create " + path.string();
        return false;
    }
#endif
    if (!f) {
        if (err) *err = "cannot create " + path.string();
        return false;
    }
    int ok = 0;
    if (is_private) {
        ok = PEM_write_PrivateKey(f.get(), key, nullptr, nullptr, 0, nullptr,
                                  nullptr);
    } else {
        ok = PEM_write_PUBKEY(f.get(), key);
    }
    if (!ok) {
        if (err) *err = "failed to write PEM " + path.string();
        return false;
    }
    return true;
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

std::optional<KeyPair> generate_ed25519(std::filesystem::path const& dir,
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

    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr), EVP_PKEY_CTX_free);
    if (!ctx) {
        if (err) *err = "EVP_PKEY_CTX_new_id(ED25519) failed";
        return std::nullopt;
    }
    if (EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        if (err) *err = "EVP_PKEY_keygen_init failed";
        return std::nullopt;
    }
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &raw) <= 0 || raw == nullptr) {
        if (err) *err = "EVP_PKEY_keygen failed";
        return std::nullopt;
    }
    EVP_PKEY_ptr pkey(raw, EVP_PKEY_free);

    if (!write_pem(priv_path, pkey.get(), /*is_private=*/true, err)) {
        return std::nullopt;
    }
    chmod_private_file(priv_path);
    if (!write_pem(pub_path, pkey.get(), /*is_private=*/false, err)) {
        std::error_code ec;
        std::filesystem::remove(priv_path, ec);
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

    KeyPair kp;
    kp.private_path = priv_path;
    kp.public_path = pub_path;
    kp.fingerprint = hex_lower(digest, SHA256_DIGEST_LENGTH);
    kp.algorithm = "ed25519";
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
    std::ifstream in(pub_path);
    if (!in) {
        if (err) *err = "cannot open " + pub_path.string();
        return std::nullopt;
    }
    std::stringstream ss;
    ss << in.rdbuf();
    return fingerprint_pem_der(ss.str(), err);
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

std::vector<std::string> split_pem_blocks(std::string const& content) {
    std::vector<std::string> blocks;
    std::string current;
    std::istringstream iss(content);
    std::string line;
    bool in_block = false;
    while (std::getline(iss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.find("-----BEGIN ") == 0) {
            in_block = true;
            current.clear();
        }
        if (in_block) {
            current += line;
            current += '\n';
        }
        if (in_block && line.find("-----END ") == 0) {
            blocks.push_back(current);
            current.clear();
            in_block = false;
        }
    }
    return blocks;
}

nlohmann::json read_meta_json(std::filesystem::path const& meta_file) {
    std::ifstream in(meta_file);
    if (!in) return nlohmann::json::object();
    try {
        nlohmann::json j;
        in >> j;
        if (!j.is_object()) return nlohmann::json::object();
        return j;
    } catch (...) {
        return nlohmann::json::object();
    }
}

bool write_meta_json(std::filesystem::path const& meta_file,
                     nlohmann::json const& j, std::string* err) {
    std::error_code ec;
    std::filesystem::create_directories(meta_file.parent_path(), ec);
    std::ofstream out(meta_file);
    if (!out) {
        if (err) *err = "cannot write " + meta_file.string();
        return false;
    }
    out << j.dump(2);
    return out.good();
}

void apply_meta_to_entry(nlohmann::json const& meta_root,
                         std::string const& fingerprint,
                         AuthorizedKeyEntry& e) {
    auto it = meta_root.find(fingerprint);
    if (it == meta_root.end() || !it->is_object()) return;
    if (auto a = it->find("alias"); a != it->end() && a->is_string()) {
        e.alias = a->get<std::string>();
    }
    if (auto p = it->find("federation_peer_id"); p != it->end() && p->is_string()) {
        e.federation_peer_id = p->get<std::string>();
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
}

void entry_meta_to_json(AuthorizedKeyEntry const& e, nlohmann::json& dst) {
    dst["alias"] = e.alias;
    if (!e.federation_peer_id.empty()) {
        dst["federation_peer_id"] = e.federation_peer_id;
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
    if (!perms.empty()) dst["permissions"] = std::move(perms);
}

}  // namespace

std::vector<AuthorizedKeyEntry> list_authorized(
    std::filesystem::path const& auth_keys_file,
    std::filesystem::path const& meta_file) {
    std::vector<AuthorizedKeyEntry> out;
    std::ifstream in(auth_keys_file);
    if (!in) return out;
    std::stringstream ss;
    ss << in.rdbuf();
    auto blocks = split_pem_blocks(ss.str());

    const auto meta = read_meta_json(meta_file);

    for (auto const& pem : blocks) {
        AuthorizedKeyEntry e;
        e.pem = pem;
        e.algorithm = "ed25519";
        std::string err;
        if (auto fp = fingerprint_pem_der(pem, &err)) {
            e.fingerprint = *fp;
        } else {
            // skip malformed entries
            continue;
        }
        apply_meta_to_entry(meta, e.fingerprint, e);
        out.push_back(std::move(e));
    }
    return out;
}

bool append_authorized(std::filesystem::path const& auth_keys_file,
                       std::filesystem::path const& meta_file,
                       std::string const& pem,
                       AuthorizedKeyEntry const& entry_meta,
                       std::string* err) {
    std::string fp_err;
    auto fp = fingerprint_pem_der(pem, &fp_err);
    if (!fp) {
        if (err) *err = fp_err;
        return false;
    }

    auto existing = list_authorized(auth_keys_file, meta_file);
    if (std::any_of(existing.begin(), existing.end(),
                    [&](AuthorizedKeyEntry const& e) {
                        return e.fingerprint == *fp;
                    })) {
        if (err) *err = "key already authorized";
        return false;
    }

    std::error_code ec;
    std::filesystem::create_directories(auth_keys_file.parent_path(), ec);
    std::ofstream out(auth_keys_file, std::ios::app);
    if (!out) {
        if (err) *err = "cannot append to " + auth_keys_file.string();
        return false;
    }
    out << pem;
    if (!pem.empty() && pem.back() != '\n') out << '\n';
    out << '\n';
    if (!out) {
        if (err) *err = "write failed";
        return false;
    }

    auto meta = read_meta_json(meta_file);
    nlohmann::json entry_json = nlohmann::json::object();
    AuthorizedKeyEntry e = entry_meta;
    e.fingerprint = *fp;
    entry_meta_to_json(e, entry_json);
    meta[*fp] = entry_json;
    return write_meta_json(meta_file, meta, err);
}

bool remove_authorized(std::filesystem::path const& auth_keys_file,
                       std::filesystem::path const& meta_file,
                       std::string const& fingerprint,
                       std::string* err) {
    auto entries = list_authorized(auth_keys_file, meta_file);
    auto match = std::find_if(entries.begin(), entries.end(),
                              [&](AuthorizedKeyEntry const& e) {
                                  return e.fingerprint == fingerprint;
                              });
    if (match == entries.end()) {
        if (err) *err = "fingerprint not found";
        return false;
    }

    std::ofstream out(auth_keys_file, std::ios::trunc);
    if (!out) {
        if (err) *err = "cannot rewrite " + auth_keys_file.string();
        return false;
    }
    for (auto const& e : entries) {
        if (e.fingerprint == fingerprint) continue;
        out << e.pem;
        if (!e.pem.empty() && e.pem.back() != '\n') out << '\n';
        out << '\n';
    }
    if (!out) {
        if (err) *err = "rewrite failed";
        return false;
    }

    auto meta = read_meta_json(meta_file);
    meta.erase(fingerprint);
    return write_meta_json(meta_file, meta, err);
}

}  // namespace yume::facade::keys
