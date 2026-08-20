/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/cli/key.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#else
#include <unistd.h>
#endif

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <nlohmann/json.hpp>

#include "core/security/crypto.hpp"
#include "core/security/secret_file.hpp"
#include "core/security/secure_erase.hpp"
#include "core/protocol/runtime_policy.hpp"
#include "server/auth/auth.hpp"
#include "server/runtime/manager.hpp"
#include "util.hpp"

namespace yume::server::cli {
namespace {


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
    auto auth_dir = std::filesystem::path(store).parent_path();
    if (!auth_dir.empty() && !ensure_dir(auth_dir.string())) {
        yume::util::log_error("failed to create auth_keys directory: " + auth_dir.string() +
                              auth_keys_write_hint(store));
        return false;
    }

    // Read the whole file: a composite identity is two PEM blocks and must be
    // enrolled as a unit. Reading only the first block would append half an
    // identity, which load_authorized_keys then rejects as incomplete -- a
    // failure the operator would only see at server start.
    std::string pem_text;
    {
        std::ifstream in(public_key_path, std::ios::binary);
        if (!in) {
            yume::util::log_error("failed to open public key: " + public_key_path);
            return false;
        }
        pem_text.assign(std::istreambuf_iterator<char>(in),
                        std::istreambuf_iterator<char>());
    }
    const yume::crypto::Bytes pem_bytes(pem_text.begin(), pem_text.end());
    const auto identity = yume::crypto::parse_composite_identity(pem_bytes);
    if (!identity.valid()) {
        yume::util::log_error(
            "not a composite identity: " + public_key_path +
            " (expected an Ed25519 public key followed by an ML-DSA-87 public "
            "key; regenerate with 'yumed key --generate <prefix>')");
        return false;
    }

    const std::string fp = yume::crypto::composite_fingerprint(identity);
    if (out_fingerprint) {
        *out_fingerprint = fp;
    }

    bool already_authorized = false;
    try {
        // A store that does not exist yet is not an error here -- the first
        // enrolment creates it. Only an existing but unreadable or half-written
        // store is refused, because appending to that would produce a file the
        // server then rejects at start.
        const auto existing = std::filesystem::exists(store)
            ? yume::server::load_authorized_keys(store)
            : std::vector<yume::crypto::Bytes>{};
        for (const auto& entry : existing) {
            if (entry == yume::crypto::composite_canonical_encoding(identity)) {
                already_authorized = true;
                break;
            }
        }
    } catch (const std::exception& ex) {
        // An unreadable or half-written store must not be silently appended to.
        yume::util::log_error(std::string("existing auth_keys is not usable: ") +
                              ex.what());
        return false;
    }

    if (!already_authorized) {
        std::ofstream out(store, std::ios::binary | std::ios::app);
        if (!out) {
            yume::util::log_error("failed to open auth_keys for append: " + store +
                                  auth_keys_write_hint(store));
            return false;
        }
        out << pem_text;
        if (!pem_text.empty() && pem_text.back() != '\n') out << '\n';
        if (!out) {
            yume::util::log_error("failed to write public key to auth_keys: " + store);
            return false;
        }
    }

    // Only the visitor store has policy metadata. Admin keys carry no policy
    // by design -- privileges come from the verified second factor, not from a
    // flag attached to a key, which is what the whole change exists to enforce.
    if (!to_admin_store) {
        yume::server::update_auth_meta(cfg.auth_keys_meta, fp, alias);
    }
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
        nlohmann::json json;
        std::ifstream in(out_path);
        if (in) {
            try { in >> json; } catch (...) { json = nlohmann::json::object(); }
        } else {
            json = nlohmann::json::object();
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
        std::string inner_heavy = prompt("inner_heavy (true/false)", cfg.inner_heavy ? "true" : "false");
        std::string inner_dual = prompt("inner_dual (true/false)", cfg.inner_dual ? "true" : "false");
        std::string inner_required = prompt("inner_required (true/false)", cfg.inner_required ? "true" : "false");
        std::string inner_hop = prompt("inner_hop (true/false)", cfg.inner_hop ? "true" : "false");
        std::string hop_interval = prompt("hop_interval_ms", std::to_string(cfg.hop_interval_ms));
        std::string pq = prompt("pq_private_key", cfg.pq_private_key);
        std::string use_embedded_master = prompt("use_embedded_master (true/false)",
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
        std::string federation_auth_key = prompt("federation_auth_key", cfg.federation_auth_key);
        std::string federation_anonym_ca = prompt("federation_anonym_ca", cfg.federation_anonym_ca);
        std::string federation_peer = prompt("federation_peer_json",
                                             cfg.federation_peers.empty() ? "" : cfg.federation_peers.front());

        json["listen_port"] = std::stoi(listen);
        json["reverse_port_min"] = std::stoi(reverse_min);
        json["reverse_port_max"] = std::stoi(reverse_max);
        json["tls_cert"] = cert;
        json["tls_key"] = key;
        json["auth_keys"] = auth;
        json["threads"] = std::stoi(threads);
        json["obfuscation"] = (obfs == "true");
        json["inner_crypto"] = (inner == "true");
        json["inner_heavy"] = (inner_heavy == "true");
        json["inner_dual"] = (inner_dual == "true");
        json["inner_required"] = (inner_required == "true");
        json["inner_hop"] = (inner_hop == "true");
        json["hop_interval_ms"] = std::stoi(hop_interval);
        if (!pq.empty()) json["pq_private_key"] = pq;
        json["use_embedded_master"] = (use_embedded_master == "true");
        json["allow_exec"] = (allow_exec == "true");
        json["allow_local_ip"] = (allow_local_ip == "true");
        json["control_full"] = (control_full == "true");
        json["real_http"] = (real_http == "true");
        if (!real_index.empty()) json["real_index_path"] = real_index;
        if (!real_secret_file.empty()) json["real_secret_file"] = real_secret_file;
        json["anonym"] = (anonym == "true");
        json["anonym_proof_mode"] = yume::policy::normalize_anonym_proof_mode(anonym_proof_mode);
        if (!anonym_api.empty()) json["anonym_api"] = anonym_api;
        if (!anonym_token.empty()) json["anonym_token"] = anonym_token;
        if (!anonym_ca_key.empty()) json["anonym_ca_key"] = anonym_ca_key;
        if (!anonym_ca_cert.empty()) json["anonym_ca_cert"] = anonym_ca_cert;
        if (!anonym_sub_key.empty()) json["anonym_sub_key"] = anonym_sub_key;
        if (!anonym_sub_cert.empty()) json["anonym_sub_cert"] = anonym_sub_cert;
        if (!outbound_proxy.empty()) json["outbound_proxy"] = outbound_proxy;
        json["federation_enable"] = (federation_enable == "true");
        if (!federation_auth_key.empty()) json["federation_auth_key"] = federation_auth_key;
        if (!federation_anonym_ca.empty()) json["federation_anonym_ca"] = federation_anonym_ca;
        if (!federation_peer.empty()) {
            json["federation_peers"] = nlohmann::json::array({nlohmann::json::parse(federation_peer)});
        }

        ensure_dir(std::filesystem::path(out_path).parent_path().string());
        std::ofstream out(out_path);
        if (!out) {
            yume::util::log_error("failed to write config: " + out_path);
            return {true, 1};
        }
        out << json.dump(2);
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

    std::vector<EVP_PKEY*> keys;
    BIO* bio = BIO_new_file(cfg.auth_keys.c_str(), "r");
    if (bio) {
        while (true) {
            EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
            if (!key) {
                break;
            }
            keys.push_back(key);
        }
        BIO_free(bio);
    }
    auto free_keys = [&]() {
        for (auto* key : keys) {
            EVP_PKEY_free(key);
        }
        keys.clear();
    };

    if (command.list) {
        if (!file_readable(cfg.auth_keys)) {
            std::cout << "No auth_keys found at: " << cfg.auth_keys << "\n";
            std::cout << "Use option 2 to add a public key first.\n";
            free_keys();
            return {true, 0};
        }
        nlohmann::json meta = nlohmann::json::object();
        yume::server::AuthKeyPolicyMap policies;
        std::ifstream in(cfg.auth_keys_meta);
        if (in) {
            try { in >> meta; } catch (...) { meta = nlohmann::json::object(); }
        }
        try {
            policies = yume::server::load_auth_policies(cfg.auth_keys_meta);
        } catch (const std::exception& ex) {
            yume::util::log_error(std::string("failed to parse auth_keys_meta: ") + ex.what());
            free_keys();
            return {true, 1};
        }
        for (auto* key : keys) {
            std::string fp = yume::server::fingerprint_pubkey(key);
            auto entry = meta.value(fp, nlohmann::json::object());
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
        free_keys();
        return {true, 0};
    }

    if (!command.add.empty()) {
        free_keys();
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
                free_keys();
                yume::util::log_error(
                    "refusing to overwrite existing key file " + existing +
                    "; choose another prefix or remove it deliberately");
                return {true, 1};
            }
        }
        if (!generate_composite_keypair(priv_path, pub_path)) {
            free_keys();
            yume::util::log_error("failed to generate keypair");
            return {true, 1};
        }
        std::cout << "Generated: " << priv_path << " and " << pub_path << "\n";
        std::cout << "Client auth key: " << priv_path << "\n";
        if (command.generate_and_add) {
            free_keys();
            if (!append_authorized_public_key(cfg, pub_path, command.alias_value,
                                              nullptr, command.admin)) {
                return {true, 1};
            }
            std::cout << "Use this client flag: --auth " << priv_path << "\n";
        } else {
            free_keys();
        }
        return {true, 0};
    }

    if (!command.remove.empty() || !command.alias.empty()) {
        nlohmann::json meta = nlohmann::json::object();
        std::ifstream in(cfg.auth_keys_meta);
        if (in) {
            try { in >> meta; } catch (...) { meta = nlohmann::json::object(); }
        }

        if (!command.alias.empty()) {
            std::string target = command.alias;
            bool matched = false;
            for (auto it = meta.begin(); it != meta.end(); ++it) {
                if (it.value().value("alias", "") == command.alias) {
                    target = it.key();
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                for (auto* key : keys) {
                    std::string fp = yume::server::fingerprint_pubkey(key);
                    if (fp == command.alias) {
                        matched = true;
                        break;
                    }
                }
            }
            if (!matched) {
                free_keys();
                yume::util::log_error("no authorized key matches fingerprint or alias: " + command.alias);
                return {true, 1};
            }
            yume::server::update_auth_meta(cfg.auth_keys_meta, target, command.alias_value);
            std::cout << "Updated alias for " << target << ": " << command.alias_value << "\n";
            free_keys();
            return {true, 0};
        }

        std::vector<EVP_PKEY*> remaining;
        std::size_t removed = 0;
        for (auto* key : keys) {
            std::string fp = yume::server::fingerprint_pubkey(key);
            if (fp == command.remove ||
                meta.value(fp, nlohmann::json::object()).value("alias", "") == command.remove) {
                EVP_PKEY_free(key);
                meta.erase(fp);
                ++removed;
                continue;
            }
            remaining.push_back(key);
        }
        keys.clear();
        if (removed == 0) {
            for (auto* key : remaining) EVP_PKEY_free(key);
            yume::util::log_error("no authorized key matches fingerprint or alias: " + command.remove);
            return {true, 1};
        }
        BIO* outbio = BIO_new_file(cfg.auth_keys.c_str(), "w");
        if (!outbio) {
            for (auto* key : remaining) EVP_PKEY_free(key);
            yume::util::log_error("failed to rewrite auth_keys: " + cfg.auth_keys +
                                  auth_keys_write_hint(cfg.auth_keys));
            return {true, 1};
        }
        for (auto* key : remaining) {
            PEM_write_bio_PUBKEY(outbio, key);
            EVP_PKEY_free(key);
        }
        BIO_free(outbio);
        std::ofstream meta_out(cfg.auth_keys_meta);
        meta_out << meta.dump(2);
        std::cout << "Removed " << removed << " authorized key"
                  << (removed == 1 ? "" : "s") << " from " << cfg.auth_keys << "\n";
        return {true, 0};
    }

    free_keys();
    return {};
}

}  // namespace yume::server::cli
