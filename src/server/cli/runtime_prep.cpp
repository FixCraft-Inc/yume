/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/cli/runtime_prep.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <string>

#include "core/security/inner_crypto.hpp"
#include "server/runtime/manager.hpp"
#include "server/cli/anonym.hpp"
#include "server/cli/key.hpp"
#include "server/cli/misc.hpp"
#include "util.hpp"

namespace yume::server::cli {
namespace {

bool parse_env_bool_local(const char* name, bool fallback) {
    const char* raw = std::getenv(name);
    if (!raw || !*raw) {
        return fallback;
    }
    std::string value(raw);
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (value == "1" || value == "true" || value == "yes" || value == "on") {
        return true;
    }
    if (value == "0" || value == "false" || value == "no" || value == "off") {
        return false;
    }
    return fallback;
}

void try_set_file(std::string& out, const std::filesystem::path& base, const char* name) {
    if (!out.empty() || base.empty()) {
        return;
    }
    std::filesystem::path cand = base / name;
    if (file_readable(cand.string())) {
        out = cand.string();
    }
}

bool require_file(const char* label, const std::string& path) {
    if (path.empty()) {
        return true;
    }
    if (!file_readable(path)) {
        yume::util::log_error(std::string(label) + " not found: " + path);
        return false;
    }
    return true;
}

}  // namespace

int prepare_server_runtime_files(yume::server::ServerConfig& cfg, const char* argv0, bool key_command_active) {
    if (key_command_active) {
        return 0;
    }

    std::error_code ec;
    std::filesystem::path runtime_dir = std::filesystem::current_path(ec);
    std::filesystem::path exe_path_dir;
    std::string self_path = get_self_path(argv0);
    if (!self_path.empty()) {
        exe_path_dir = std::filesystem::path(self_path).parent_path();
    }

    if (cfg.anonym && (cfg.anonym_sub_key.empty() || cfg.anonym_sub_cert.empty())) {
        try_set_file(cfg.anonym_sub_key, runtime_dir, "anonym_sub.key");
        try_set_file(cfg.anonym_sub_cert, runtime_dir, "anonym_sub.pem");
        try_set_file(cfg.anonym_sub_key, exe_path_dir, "anonym_sub.key");
        try_set_file(cfg.anonym_sub_cert, exe_path_dir, "anonym_sub.pem");
        if (!cfg.anonym_sub_key.empty() && !cfg.anonym_sub_cert.empty()) {
            yume::util::log_info("using anonym sub key/cert from runtime directory");
        }
    }

    if (cfg.inner_crypto && cfg.pq_private_key.empty()) {
        try_set_file(cfg.pq_private_key, runtime_dir, "pq_private.key");
        try_set_file(cfg.pq_private_key, exe_path_dir, "pq_private.key");
        std::filesystem::path secret_dir = runtime_dir / ".secrets";
        try_set_file(cfg.pq_private_key, secret_dir, "pq_private.key");
        if (!cfg.pq_private_key.empty()) {
            yume::util::log_info("using discovered pq_private_key: " + cfg.pq_private_key);
        } else if (cfg.pq_auto_generate) {
            std::filesystem::path priv_path = secret_dir / "pq_private.key";
            std::filesystem::path pub_path = secret_dir / "pq_public.key";
            std::string err;
            if (yume::inner::generate_pq_keypair(priv_path.string(), pub_path.string(), &err)) {
                cfg.pq_private_key = priv_path.string();
                yume::util::log_info("generated PQ keypair at ./.secrets (copy pq_public.key to clients)");
            } else {
                yume::util::log_error("PQ keypair generation failed: " + err);
                return 1;
            }
        }
    }

    const bool validate_pq_on_start = parse_env_bool_local("YUME_VALIDATE_PQ_ON_START", cfg.pq_auto_generate);
    if (cfg.inner_crypto && !cfg.pq_private_key.empty() && validate_pq_on_start) {
        std::string pq_public_path = derive_pq_public_path(cfg.pq_private_key);
        if (file_readable(cfg.pq_private_key) && file_readable(pq_public_path)) {
            std::string err;
            if (!yume::inner::validate_pq_keypair(cfg.pq_private_key, pq_public_path, &err)) {
                if (!cfg.pq_auto_generate) {
                    yume::util::log_error("PQ keypair mismatch: " + err +
                                          " (run with --pq-auto-generate to regenerate)");
                    return 1;
                }
                yume::util::log_warn("PQ keypair mismatch; regenerating: " + err);
                if (!yume::inner::generate_pq_keypair(cfg.pq_private_key, pq_public_path, &err)) {
                    yume::util::log_error("PQ keypair regeneration failed: " + err);
                    return 1;
                }
                yume::util::log_info("regenerated PQ keypair at " + pq_public_path);
            }
        }
    }

    if (cfg.tls_cert.empty() || cfg.tls_key.empty()) {
        yume::util::log_error("tls_cert and tls_key must be set in config");
        return 1;
    }
    if (cfg.auth_keys.empty()) {
        yume::util::log_error("auth_keys must be set in config");
        return 1;
    }
    if (!require_file("tls_cert", cfg.tls_cert) ||
        !require_file("tls_key", cfg.tls_key) ||
        !require_file("auth_keys", cfg.auth_keys)) {
        return 1;
    }
    if (cfg.inner_crypto && cfg.pq_private_key.empty() && !cfg.allow_embedded_master) {
        yume::util::log_error(
            "inner_crypto enabled but pq_private_key is not set "
            "(set --pq-key, provide pq_private.key, enable --pq-auto-generate, or use --use-embedded-master)");
        return 1;
    }
    if ((cfg.inner_crypto && !require_file("pq_private_key", cfg.pq_private_key)) ||
        (cfg.anonym && !require_file("anonym_ca_key", cfg.anonym_ca_key)) ||
        (cfg.anonym && !require_file("anonym_ca_cert", cfg.anonym_ca_cert)) ||
        (cfg.anonym && !require_file("anonym_sub_key", cfg.anonym_sub_key)) ||
        (cfg.anonym && !require_file("anonym_sub_cert", cfg.anonym_sub_cert)) ||
        (cfg.real_http && !require_file("real_index_path", cfg.real_index_path))) {
        return 1;
    }

    if (cfg.auth_keys_meta.empty() && !cfg.auth_keys.empty()) {
        cfg.auth_keys_meta = cfg.auth_keys + ".json";
    }
    return 0;
}

}  // namespace yume::server::cli
