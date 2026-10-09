/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <string_view>
#include <utility>
#include <vector>

#include <openssl/crypto.h>
#include <unistd.h>

#include "common/version.hpp"
#include "setup/actions.hpp"
#include "setup/files.hpp"
#include "setup/kit_layout.hpp"
#include "setup/material.hpp"
#include "setup/provision.hpp"

namespace yume::setup {
namespace {

namespace fs = std::filesystem;

constexpr std::size_t kPskBytes = 32U;

// The material of one new client, which the server's store must list.
struct ClientBundle final {
    std::string fingerprint;
    std::string public_pem;
    SecretBytes access_psk;
};

SecretBytes new_psk(const Material& material) {
    SecretBytes psk(kPskBytes);
    material.random({psk.data(), psk.size()});
    return psk;
}

void write_text(const fs::path& path, std::string_view text,
                mode_t mode = 0600) {
    write_new_file(path, as_bytes(text), mode);
}

// A complete client directory for one new identity at client, which exists.
ClientBundle write_client_bundle(const Material& material,
                                 const fs::path& client,
                                 const fs::path& server_credentials,
                                 const std::string& host, std::int64_t port,
                                 const Json& tuning) {
    const fs::path credentials = client / "credentials";
    make_private_directory(credentials);
    auto identity = material.composite();
    write_new_file(credentials / "client-composite.pem",
                   identity.private_pem.bytes());
    write_text(credentials / "client-composite.pub.pem", identity.public_pem);
    auto psk = new_psk(material);
    write_new_file(credentials / "client-access.psk", psk.bytes());
    for (const auto name : kClientServerMaterial) {
        copy_private_file(server_credentials / name, credentials / name);
    }
    write_json(client / "yume.json", client_config(host, port, tuning));
    make_private_directory(client / "adapters");
    write_json(client / "adapters/socks5.json",
               Json{{"schema", 1}, {"adapter", socks5_adapter()}});
    write_text(client / "start-client", kClientLauncher, 0700);
    return {std::move(identity.fingerprint), std::move(identity.public_pem),
            std::move(psk)};
}

bool same_secret(std::span<const std::uint8_t> left,
                 std::span<const std::uint8_t> right) {
    return left.size() == right.size() &&
           CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0;
}

void write_cover_site(const fs::path& root) {
    make_private_directory(root);
    make_private_directory(root / "assets");
    for (const auto& page : kCoverSite) write_text(root / page.path, page.text);
}

// The keys of the server's limits that a preset sets, with the server's
// values where they have the preset's types, so a new client matches it.
Json server_tuning(const Json& config) {
    Json tuning = find_preset(default_preset())->limits;
    if (!config.contains("limits") || !config.at("limits").is_object())
        return tuning;
    const auto& limits = config.at("limits");
    for (auto& [key, value] : tuning.items()) {
        if (!limits.contains(key)) continue;
        const auto& configured = limits.at(key);
        const bool same_type = value.is_boolean()
                                   ? configured.is_boolean()
                                   : configured.is_number_integer();
        if (same_type) value = configured;
    }
    return tuning;
}

Json read_store(const fs::path& path) {
    auto store = read_json(path);
    if (!store.is_object() || !store.contains("schema") ||
        store.at("schema") != 1 || !store.contains("keys") ||
        !store.at("keys").is_array()) {
        throw SetupError("authorized-keys store is not a schema-1 key list");
    }
    return store;
}

bool entry_named(const Json& entry, const std::string& name) {
    return entry.is_object() && entry.contains("name") &&
           entry.at("name") == name;
}

// Gives a client bundle its circuits section and the kit copies it needs.
// The operator key verifies every routes view, and the node's current view
// and signature are the kit's copy. Circuits carry TCP only, so the SOCKS5
// adapter loses its UDP service.
void add_client_circuits(const fs::path& client, const fs::path& server,
                         const Json& config) {
    const fs::path material = client / kClientCircuitsDirectory;
    make_private_directory(material);
    constexpr std::array<std::pair<std::string_view, std::string_view>, 3>
        kCopies{{
            {"operator_key", "operator.pub.pem"},
            {"routes", "cluster-routes.json"},
            {"routes_signature", "cluster-routes.sig"},
        }};
    for (const auto& [key, target] : kCopies) {
        const auto source = config_reference(server, config, "cluster", key);
        if (!file_at(source)) {
            throw SetupError(
                source.string() +
                " is missing; sign the cluster with cluster-sign first");
        }
        copy_private_file(source, material / target);
    }
    auto client_config = read_json(client / "yume.json");
    if (!client_config.is_object()) {
        throw SetupError("the new client configuration is not an object");
    }
    client_config["circuits"] = circuits_section();
    if (client_config.contains("adapters") &&
        client_config.at("adapters").is_array()) {
        for (auto& adapter : client_config.at("adapters")) {
            if (adapter.is_object() && adapter.contains("kind") &&
                adapter.at("kind") == "socks5") {
                adapter.erase("udp_service");
            }
        }
    }
    remove_file(client / "yume.json");
    write_json(client / "yume.json", client_config);
}

}  // namespace

fs::path init_kit(const InitOptions& options) {
    const auto host = require_host(options.host);
    const auto client_name = require_client_name(options.client_name);
    const auto* preset = find_preset(options.preset);
    if (preset == nullptr)
        throw SetupError("unknown tuning preset: " + options.preset);
    require_max_sessions(options.max_sessions);
    require_weight(options.weight);
    require_max_egress_mbps(options.max_egress_mbps);
    if (options.port < 1 || options.port > 65535) {
        throw SetupError("port must be in 1..65535");
    }
    const fs::path output = require_output_path(options.output);
    const fs::path parent = output.parent_path();
    Staging staging(parent);
    const Material material;

    const fs::path server = staging.path() / "server";
    const fs::path client = staging.path() / "client";
    const fs::path server_credentials = server / "credentials";
    const fs::path authorized = server_credentials / "authorized";
    for (const auto& directory :
         {server, client, server_credentials, authorized}) {
        make_private_directory(directory);
    }

    const auto server_identity = material.composite();
    write_new_file(server_credentials / "server-composite.pem",
                   server_identity.private_pem.bytes());
    write_text(server_credentials / "server-composite.pub.pem",
               server_identity.public_pem);
    const auto server_mlkem = material.mlkem();
    write_new_file(server_credentials / "server-mlkem.key.pem",
                   server_mlkem.private_pem.bytes());
    write_text(server_credentials / "server-mlkem.pub.pem",
               server_mlkem.public_pem);
    const auto tls = material.tls(host);
    write_new_file(server_credentials / "server-tls.key.pem",
                   tls.key_pem.bytes());
    write_text(server_credentials / "server-tls.pem", tls.certificate_pem);
    write_text(server_credentials / "server-trust.pem", tls.trust_pem);
    write_new_file(server_credentials / "admission.key",
                   new_psk(material).bytes());

    const auto bundle =
        write_client_bundle(material, client, server_credentials, host,
                            options.port, preset->limits);
    write_new_file(authorized / (client_name + "-access.psk"),
                   bundle.access_psk.bytes());
    write_text(authorized / (client_name + "-composite.pub.pem"),
               bundle.public_pem);
    write_json(
        server_credentials / "authorized-keys.json",
        Json{{"schema", 1},
             {"keys", Json::array({authorized_entry(
                          client_name, bundle.fingerprint, options.max_sessions,
                          options.weight, false)})}});
    // The separate second-factor store starts empty on purpose. Admin is
    // proved by a distinct identity from this store in addition to an
    // authorized traffic identity, so a fresh kit has no administrator until
    // an operator deliberately adds one.
    write_json(server_credentials / "admin-keys.json",
               Json{{"schema", 1}, {"keys", Json::array()}});

    write_json(
        server / "yumed.json",
        server_config(options.port, preset->limits, options.max_egress_mbps));
    write_cover_site(server / "cover-site");
    make_private_directory(server / "services");
    for (const auto& service : standard_services()) {
        write_json(
            server / "services" /
                (service.at("name").get<std::string>() + ".json"),
            Json{{"schema", 1},
                 {"service", service},
                 {"adapter",
                  direct_adapter(service.at("kind") == "stream" ? "direct_tcp"
                                                                : "direct_udp",
                                 service.at("name").get<std::string>())}});
    }
    write_text(server / "start-server", kServerLauncher, 0700);
    write_json(staging.path() / "manifest.json",
               kit_manifest(host, options.port, client_name));

    fsync_tree(staging.path());
    staging.publish(staging.path(), output);
    fsync_directory(parent);
    return output;
}

fs::path add_client(const AddClientOptions& options) {
    const auto host = require_host(options.host);
    const auto client_name = require_client_name(options.client_name);
    require_max_sessions(options.max_sessions);
    require_weight(options.weight);
    const auto resolved = resolve_existing(options.server);
    if (!resolved) throw SetupError("server directory does not exist");
    const fs::path& server = *resolved;
    const auto config = read_server_config(server, "server directory");
    const Json* port = nullptr;
    if (config.contains("endpoint") && config.at("endpoint").is_object() &&
        config.at("endpoint").contains("port")) {
        port = &config.at("endpoint").at("port");
    }
    if (port == nullptr || !port->is_number_integer() || *port < 1 ||
        *port > 65535) {
        throw SetupError("server configuration has no valid endpoint.port");
    }
    if (!declares_standard_services(config)) {
        throw SetupError(
            "server configuration does not declare the standard tcp and udp "
            "services");
    }
    if (options.circuits &&
        !(config.contains("cluster") && config.at("cluster").is_object())) {
        throw SetupError("--circuits needs a server that belongs to a cluster");
    }
    // A new client takes the server's tuning, so both sides of the kit match.
    const Json tuning = server_tuning(config);

    const fs::path store_path =
        config_reference(server, config, "credentials", "authorized_keys");
    const fs::path admission_path =
        config_reference(server, config, "credentials", "admission_key");
    const Json store = read_store(store_path);
    const auto& keys = store.at("keys");
    if (keys.size() >= kMaxAuthorizedIdentities) {
        throw SetupError("authorized-keys store is full");
    }
    if (std::any_of(keys.begin(), keys.end(), [&](const Json& entry) {
            return entry_named(entry, client_name);
        })) {
        throw SetupError("client name is already authorized: " + client_name);
    }
    const fs::path server_credentials = admission_path.parent_path();
    for (const auto name : kClientServerMaterial) {
        if (!file_at(server_credentials / name)) {
            throw SetupError("server credentials lack " + std::string(name) +
                             "; add-client needs the layout init writes");
        }
    }

    const fs::path store_directory = store_path.parent_path();
    const fs::path authorized = store_directory / "authorized";
    const fs::path authorized_public =
        authorized / (client_name + "-composite.pub.pem");
    const fs::path authorized_psk = authorized / (client_name + "-access.psk");
    const fs::path output = require_output_path(options.output);
    const fs::path parent = output.parent_path();
    Staging staging(parent);
    const Material material;

    std::vector<fs::path> created;
    bool new_directory = false;
    std::optional<fs::path> replacement;
    bool published = false;
    try {
        const fs::path client = staging.path() / "client";
        make_private_directory(client);
        const auto bundle =
            write_client_bundle(material, client, server_credentials, host,
                                port->get<std::int64_t>(), tuning);
        if (options.circuits) add_client_circuits(client, server, config);
        if (std::any_of(keys.begin(), keys.end(), [&](const Json& entry) {
                return entry.is_object() && entry.contains("identity") &&
                       entry.at("identity").is_object() &&
                       entry.at("identity").contains("sha256") &&
                       entry.at("identity").at("sha256") == bundle.fingerprint;
            })) {
            throw SetupError("generated identity is already authorized");
        }
        if (same_secret(bundle.access_psk.bytes(),
                        read_secret(admission_path, kPskBytes).bytes())) {
            throw SetupError("generated access PSK equals the admission key");
        }

        // Files added to the server tree keep the store's owner, so a root
        // operator does not lock the daemon's account out of its own store.
        const Owner owner = owner_of(store_path);
        if (!directory_at(authorized)) {
            make_private_directory(authorized);
            new_directory = true;
        }
        write_text(authorized_public, bundle.public_pem);
        created.push_back(authorized_public);
        write_new_file(authorized_psk, bundle.access_psk.bytes());
        created.push_back(authorized_psk);
        Json updated = store;
        updated["keys"].push_back(authorized_entry(
            client_name, bundle.fingerprint, options.max_sessions,
            options.weight, options.circuits));
        replacement = replacement_path(store_path);
        write_json(*replacement, updated);
        if (running_as_root()) {
            for (const auto& path : created) give_to(path, owner);
            give_to(*replacement, owner);
            if (new_directory) give_to(authorized, owner);
        }
        fsync_directory(authorized);

        fsync_tree(client);
        staging.publish(client, output);
        published = true;
        fsync_directory(parent);
        rename_replace(*replacement, store_path);
        replacement.reset();
        fsync_directory(store_directory);
        return output;
    } catch (...) {
        if (replacement) remove_file(*replacement);
        for (const auto& path : created) remove_file(path);
        if (new_directory) static_cast<void>(::rmdir(authorized.c_str()));
        if (published) remove_tree(output);
        throw;
    }
}

fs::path remove_client(const fs::path& server_path, const std::string& name) {
    const auto client_name = require_client_name(name);
    const auto resolved = resolve_existing(server_path);
    if (!resolved) throw SetupError("server directory does not exist");
    const auto config = read_server_config(*resolved, "server directory");
    const fs::path store_path =
        config_reference(*resolved, config, "credentials", "authorized_keys");
    const Json store = read_store(store_path);
    const auto& keys = store.at("keys");
    const auto match = std::find_if(
        keys.begin(), keys.end(),
        [&](const Json& entry) { return entry_named(entry, client_name); });
    if (match == keys.end())
        throw SetupError("client name is not authorized: " + client_name);
    if (keys.size() == 1U) {
        throw SetupError(
            "the store must keep at least one client; add another first");
    }
    const auto store_directory = resolve_existing(store_path.parent_path());
    if (!store_directory)
        throw SetupError("cannot resolve " + store_path.parent_path().string());
    // Only files below the store's own directory are this client's to delete.
    std::vector<fs::path> owned;
    for (const auto* field : {"identity", "access_psk"}) {
        if (!match->contains(field) || !match->at(field).is_object() ||
            !match->at(field).contains("file") ||
            !match->at(field).at("file").is_string()) {
            continue;
        }
        const fs::path relative(match->at(field).at("file").get<std::string>());
        if (relative.empty() || relative.is_absolute()) continue;
        std::error_code error;
        const auto candidate =
            fs::weakly_canonical(*store_directory / relative, error);
        if (error) continue;
        const auto [mismatch, unused] =
            std::mismatch(store_directory->begin(), store_directory->end(),
                          candidate.begin(), candidate.end());
        if (mismatch == store_directory->end() &&
            candidate != *store_directory) {
            owned.push_back(candidate);
        }
    }
    Json updated = store;
    updated["keys"].erase(static_cast<std::size_t>(match - keys.begin()));
    const Owner owner = owner_of(store_path);
    const auto replacement = replacement_path(store_path);
    try {
        write_json(replacement, updated);
        if (running_as_root()) give_to(replacement, owner);
        rename_replace(replacement, store_path);
    } catch (...) {
        remove_file(replacement);
        throw;
    }
    fsync_directory(*store_directory);
    for (const auto& path : owned) {
        if (::unlink(path.c_str()) != 0 && errno != ENOENT) {
            throw SetupError("cannot remove " + path.string() + ": " +
                             std::strerror(errno));
        }
        fsync_directory(path.parent_path());
    }
    return store_path;
}

}  // namespace yume::setup
