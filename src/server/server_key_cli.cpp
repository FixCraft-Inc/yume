/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "server/server_key_cli.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

#include <openssl/evp.h>
#include <openssl/pem.h>

#include "core/crypto.hpp"
#include "server/auth.hpp"
#include "server/manager.hpp"
#include "util.hpp"

namespace yume::server_cli {
namespace {

bool write_file_secure(const std::string& path, const std::string& contents) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return false;
    }
    out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    out.close();
    std::error_code ec;
    std::filesystem::permissions(path,
                                 std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace, ec);
    return !ec;
}

}  // namespace

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
    auto dir = std::filesystem::path(path).parent_path().string();
    if (!dir.empty()) {
        ensure_dir(dir);
    }
    if (!write_file_secure(path, secret)) {
        throw std::runtime_error("failed to write secret file");
    }
    return secret;
}

bool generate_ed25519_keypair(const std::string& priv_path, const std::string& pub_path) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!pctx) {
        return false;
    }
    if (EVP_PKEY_keygen_init(pctx) != 1) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx, &pkey) != 1) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    EVP_PKEY_CTX_free(pctx);

    BIO* priv = BIO_new_file(priv_path.c_str(), "w");
    BIO* pub = BIO_new_file(pub_path.c_str(), "w");
    if (!priv || !pub) {
        if (priv) BIO_free(priv);
        if (pub) BIO_free(pub);
        EVP_PKEY_free(pkey);
        return false;
    }
    bool ok = PEM_write_bio_PrivateKey(priv, pkey, nullptr, nullptr, 0, nullptr, nullptr) == 1 &&
              PEM_write_bio_PUBKEY(pub, pkey) == 1;
    BIO_free(priv);
    BIO_free(pub);
    EVP_PKEY_free(pkey);

    std::error_code ec;
    std::filesystem::permissions(priv_path,
                                 std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace, ec);
    return ok;
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
                                  std::string* out_fingerprint) {
    if (cfg.auth_keys.empty()) {
        yume::util::log_error("auth_keys must be set before adding a key");
        return false;
    }
    auto auth_dir = std::filesystem::path(cfg.auth_keys).parent_path();
    if (!auth_dir.empty() && !ensure_dir(auth_dir.string())) {
        yume::util::log_error("failed to create auth_keys directory: " + auth_dir.string() +
                              auth_keys_write_hint(cfg.auth_keys));
        return false;
    }

    BIO* inbio = BIO_new_file(public_key_path.c_str(), "r");
    if (!inbio) {
        yume::util::log_error("failed to open public key: " + public_key_path);
        return false;
    }
    yume::crypto::EVP_PKEY_ptr key{PEM_read_bio_PUBKEY(inbio, nullptr, nullptr, nullptr), EVP_PKEY_free};
    BIO_free(inbio);
    if (!key) {
        yume::util::log_error("failed to parse public key: " + public_key_path);
        return false;
    }

    const std::string fp = yume::server::fingerprint_pubkey(key.get());
    if (out_fingerprint) {
        *out_fingerprint = fp;
    }

    bool already_authorized = false;
    BIO* existing = BIO_new_file(cfg.auth_keys.c_str(), "r");
    if (existing) {
        while (true) {
            yume::crypto::EVP_PKEY_ptr existing_key{
                PEM_read_bio_PUBKEY(existing, nullptr, nullptr, nullptr), EVP_PKEY_free};
            if (!existing_key) {
                break;
            }
            if (yume::server::fingerprint_pubkey(existing_key.get()) == fp) {
                already_authorized = true;
                break;
            }
        }
        BIO_free(existing);
    }

    if (!already_authorized) {
        BIO* outbio = BIO_new_file(cfg.auth_keys.c_str(), "a");
        if (!outbio) {
            yume::util::log_error("failed to open auth_keys for append: " + cfg.auth_keys +
                                  auth_keys_write_hint(cfg.auth_keys));
            return false;
        }
        const bool wrote = PEM_write_bio_PUBKEY(outbio, key.get()) == 1;
        BIO_free(outbio);
        if (!wrote) {
            yume::util::log_error("failed to write public key to auth_keys: " + cfg.auth_keys);
            return false;
        }
    }

    yume::server::update_auth_meta(cfg.auth_keys_meta, fp, alias);
    std::cout << (already_authorized ? "Already authorized: " : "Authorized: ")
              << fp << "\n";
    if (!alias.empty()) {
        std::cout << "Alias: " << alias << "\n";
    }
    std::cout << "auth_keys: " << cfg.auth_keys << "\n";
    return true;
}

}  // namespace yume::server_cli
