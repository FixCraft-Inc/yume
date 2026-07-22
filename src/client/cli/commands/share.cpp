/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/commands/share.hpp"

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#include <sys/stat.h>
#endif

#include "client/cli/entry.hpp"
#include "client/cli/config/input.hpp"
#include "client/transfer/share_file.hpp"
#include "core/version.hpp"
#include "util.hpp"

namespace yume::client {
namespace {

bool write_with_owner_only_mode(const std::string& path,
                                const std::vector<std::uint8_t>& data,
                                std::string* error) {
#ifndef _WIN32
    mode_t prior = ::umask(0077);
#endif
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
#ifndef _WIN32
    ::umask(prior);
#endif
    if (!f) {
        if (error) *error = "cannot write " + path;
        return false;
    }
    f.write(reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size()));
    if (!f) {
        if (error) *error = "write to " + path + " failed";
        return false;
    }
#ifndef _WIN32
    (void)::chmod(path.c_str(), 0600);
#endif
    return true;
}

bool prompt_share_password(const std::string& purpose,
                           bool from_stdin,
                           std::string* out,
                           std::string* error) {
    if (from_stdin) {
        std::string line;
        if (!std::getline(std::cin, line)) {
            if (error) *error = "could not read password from stdin";
            return false;
        }
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) {
            if (error) *error = "password must not be empty";
            return false;
        }
        if (purpose == "export" && line.size() < yume::share::kPasswordMin) {
            if (error) {
                *error = "password must be at least " +
                         std::to_string(yume::share::kPasswordMin) + " characters";
            }
            return false;
        }
        *out = std::move(line);
        return true;
    }

    if (purpose == "export") {
        std::string first, second;
        if (!prompt_hidden_input("Set a password to protect the export: ", &first, error)) {
            return false;
        }
        if (first.size() < yume::share::kPasswordMin) {
            if (error) {
                *error = "password must be at least " +
                         std::to_string(yume::share::kPasswordMin) + " characters";
            }
            return false;
        }
        if (!prompt_hidden_input("Confirm the password: ", &second, error)) {
            return false;
        }
        if (first != second) {
            if (error) *error = "passwords don't match";
            return false;
        }
        *out = std::move(first);
        return true;
    }
    return prompt_hidden_input("Password for the share file: ", out, error);
}

}  // namespace

int run_export_share(const std::string& out_path,
                     const ClientConfig& cfg,
                     bool password_stdin) {
    if (cfg.server.empty() || cfg.identity.empty()) {
        util::log_error("export: nothing to export — load a config first (--config <path>) or pass --server + --auth.");
        return 1;
    }

    yume::share::BackupInputs in;
    in.label = cfg.server + (cfg.port > 0 ? ":" + std::to_string(cfg.port) : std::string());
    in.created_by = std::string("yume ") + yume::kVersion;
    in.server_host = cfg.server;
    in.server_port = cfg.port > 0 ? cfg.port : 443;
    in.identity_path = cfg.identity;
    in.anonym_ca_cert_path = cfg.anonym_ca_cert;
    in.tls_ca_cert_path = cfg.tls_ca_cert;
    in.pq_public_key_path = cfg.pq_public_key;
    in.obfuscation = cfg.obfuscation;
    in.obfs_secret_path = cfg.obfs_secret_file;
    in.inner_psk_path = cfg.inner_psk_file;
    in.obfs_secret = cfg.obfs_secret;
    in.obfs_pad_multiple = cfg.obfs_pad_multiple;
    in.obfs_jitter_ms = cfg.obfs_jitter_ms;
    in.tls_pin_sha256 = cfg.tls_pin_sha256;
    in.tls_stealth_profile = cfg.tls_stealth_profile;
    in.tls_server_name = cfg.tls_server_name;
    in.anonym_pubkey = cfg.anonym_pubkey;
    in.inner_crypto = cfg.inner_crypto;
    in.inner_heavy = cfg.inner_heavy;
    in.inner_hop = cfg.inner_hop;
    in.hop_interval_ms = cfg.hop_interval_ms;
    in.tunnel_count = static_cast<std::uint8_t>(
        std::clamp(cfg.tunnel_count, 1, 16));
    in.require_operator_identity = cfg.require_anonym;
    in.allow_udp = cfg.allow_udp;
    in.allow_local_ip = cfg.allow_local_ip;

    yume::share::ShareBundle bundle;
    std::string err;
    if (!yume::share::build_backup_bundle(in, &bundle, &err)) {
        util::log_error("export: " + err);
        return 1;
    }

    std::string password;
    if (!prompt_share_password("export", password_stdin, &password, &err)) {
        util::log_error("export: " + err);
        return 1;
    }
    auto bytes = yume::share::encode_share(bundle, password, &err);
    std::fill(password.begin(), password.end(), '\0');
    if (bytes.empty()) {
        util::log_error("export: " + err);
        return 1;
    }
    if (!write_with_owner_only_mode(out_path, bytes, &err)) {
        util::log_error("export: " + err);
        return 1;
    }
    util::log_info("Exported " + std::to_string(bytes.size()) + "-byte share file to " + out_path +
                   " (owner-readable only). Keep the password safe — it's the only way to decrypt.");
    return 0;
}

int run_import_share(const std::string& in_path, bool password_stdin) {
    std::ifstream in(in_path, std::ios::binary);
    if (!in) {
        util::log_error("import: cannot open " + in_path);
        return 1;
    }
    std::vector<std::uint8_t> blob((std::istreambuf_iterator<char>(in)),
                                    std::istreambuf_iterator<char>());
    yume::share::ShareFileHeader hdr{};
    if (!yume::share::peek_share_header(blob, &hdr)) {
        util::log_error("import: " + in_path + " is not a .yss file (bad magic or unsupported version)");
        return 1;
    }
    util::log_info("import: detected .yss format v" + std::to_string(hdr.version) +
                   " (type=" + (hdr.type == yume::share::BundleType::Backup ? "backup" : "?") + ").");

    std::string err;
    std::string password;
    if (!prompt_share_password("import", password_stdin, &password, &err)) {
        util::log_error("import: " + err);
        return 1;
    }
    auto bundle_opt = yume::share::decode_share(blob, password, &err);
    std::fill(password.begin(), password.end(), '\0');
    if (!bundle_opt) {
        util::log_error("import: " + err);
        return 1;
    }
    const auto& bundle = *bundle_opt;

    std::cout << "\n────────── share-file summary ──────────\n";
    if (!bundle.label.empty())           std::cout << "Label:        " << bundle.label << "\n";
    std::cout                             << "Server:       " << bundle.server_host << ":" << bundle.server_port << "\n";
    if (!bundle.created_at_iso8601.empty()) std::cout << "Created at:   " << bundle.created_at_iso8601 << "\n";
    if (!bundle.created_by.empty())      std::cout << "Created by:   " << bundle.created_by << "\n";
    std::cout                             << "Auth key:     " << (bundle.auth_private_key_pem.empty() ? "(none)" : "PRESENT") << "\n";
    std::cout                             << "Operator CA:  " << (bundle.anonym_ca_cert_pem.empty() ? "(none)" : "PRESENT") << "\n";
    std::cout                             << "TLS CA:       " << (bundle.tls_ca_cert_pem.empty() ? "system trust" : "PRESENT") << "\n";
    if (!bundle.tls_server_name.empty()) std::cout << "TLS name:     " << bundle.tls_server_name << "\n";
    std::cout                             << "PQ pubkey:    " << (bundle.pq_public_key_pem.empty() ? "(none)" : "PRESENT") << "\n";
    std::cout                             << "Obfs secret:  " << (bundle.obfs_secret.empty() ? "(none)" : "PRESENT") << "\n";
    std::cout                             << "Inner PSK:    " << (bundle.inner_psk.empty() ? "(none)" : "PRESENT") << "\n";
    std::cout                             << "Inner crypto: " << (bundle.inner_crypto ? (bundle.inner_heavy ? "heavy" : "light") : "off")
                                          << "; hop=" << (bundle.inner_hop ? "on" : "off") << "\n";
    std::cout                             << "Tunnels:      " << static_cast<unsigned>(bundle.tunnel_count) << "\n";
    std::cout << "─────────────────────────────────────────\n\n";

    if (!password_stdin) {
        if (!is_tty_stdin()) {
            util::log_error("import: confirmation requires a TTY; pass --password-stdin to skip the prompt");
            return 1;
        }
        std::cout << "Write extracted files to ~/.yume/imported/" << bundle.server_host
                  << "/ and a ready-to-use config.json there? [y/N]: " << std::flush;
        std::string answer;
        std::getline(std::cin, answer);
        if (answer.empty() || (answer[0] != 'y' && answer[0] != 'Y')) {
            util::log_info("import: cancelled, nothing was written.");
            return 0;
        }
    }

    yume::share::ApplyResult applied;
    if (!yume::share::apply_imported_bundle(bundle, &applied, &err)) {
        util::log_error("import: " + err);
        return 1;
    }
    util::log_info("Import complete.");
    util::log_info("  Wrote: " + applied.target_dir + "/ (mode 0700)");
    util::log_info("  Connect with: yume --config " + applied.config_path);
    return 0;
}

}  // namespace yume::client
