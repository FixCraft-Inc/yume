/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/cli/runtime_prep.hpp"

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
            yume::util::log_info("using delegated server identity key/certificate from runtime directory");
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
        !require_file("auth_keys", cfg.auth_keys) ||
        (!cfg.operator_keys.empty() &&
         !require_file("operator_keys", cfg.operator_keys))) {
        return 1;
    }
    if ((cfg.anonym && !require_file("anonym_ca_key", cfg.anonym_ca_key)) ||
        (cfg.anonym && !require_file("anonym_ca_cert", cfg.anonym_ca_cert)) ||
        (cfg.anonym && !require_file("anonym_sub_key", cfg.anonym_sub_key)) ||
        (cfg.anonym && !require_file("anonym_sub_cert", cfg.anonym_sub_cert)) ||
        (cfg.real_http && cfg.real_backend.empty() &&
         !require_file("real_index_path", cfg.real_index_path))) {
        return 1;
    }


    if (cfg.auth_keys_meta.empty() && !cfg.auth_keys.empty()) {
        cfg.auth_keys_meta = cfg.auth_keys + ".json";
    }
    if (cfg.operator_keys_meta.empty() && !cfg.operator_keys.empty()) {
        cfg.operator_keys_meta = cfg.operator_keys + ".json";
    }
    return 0;
}

}  // namespace yume::server::cli
