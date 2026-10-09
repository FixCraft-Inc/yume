/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// Clusters. An operator directory holds the composite operator key, which
// never goes to a node, the key network tags are made under, and
// cluster.json, the operator's record of its nodes: each node's name, the
// server directory it was added from, its host and an optional address to
// dial. cluster-sign builds the signed list from the node directories' public
// material, so the list always matches their keys.

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <utility>
#include <vector>

#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "common/hex.hpp"
#include "providers/composite_keys.hpp"
#include "providers/ytp1_crypto.hpp"
#include "runtime/cluster_list.hpp"
#include "setup/actions.hpp"
#include "setup/files.hpp"
#include "setup/material.hpp"
#include "setup/provision.hpp"

namespace yume::setup {
namespace {

namespace fs = std::filesystem;
namespace keys = providers::keys;
namespace cluster = runtime::cluster;

constexpr std::size_t kLinkPskBytes = 32U;
constexpr std::size_t kTagKeyBytes = 32U;
constexpr std::string_view kTagKeyFile = "routes-tag.key";
// Where a node keeps its cluster files, relative to its server directory,
// and where yumed saves the highest list serial, next to yumed.json.
constexpr std::string_view kNodeClusterDirectory = "credentials/cluster";
constexpr std::string_view kNodeClusterState = "cluster-state.json";

std::string read_ascii(const fs::path& path) {
    const auto bytes = read_bounded(path, kMaxJsonBytes);
    if (std::any_of(bytes.begin(), bytes.end(),
                    [](std::uint8_t byte) { return byte > 0x7FU; })) {
        throw SetupError(path.string() + " is not ASCII text");
    }
    return {bytes.begin(), bytes.end()};
}

std::string identity_of(const keys::KeyContext& context, const fs::path& path,
                        const std::string& pem) {
    try {
        return keys::composite_public_from_pem(context, pem).fingerprint;
    } catch (const keys::KeyError&) {
        throw SetupError(
            path.string() +
            " must hold a composite Ed25519 and ML-DSA-87 public key");
    }
}

// A server directory in the init layout, as a cluster sees it.
struct Node final {
    fs::path server;
    fs::path config_path;
    Json config;
    std::int64_t port{0};
    fs::path credentials;
    fs::path admission;
    std::string identity_key;
    std::string identity;
    fs::path cluster;
    fs::path peers_path;
    Owner owner;

    Json peers() const {
        std::error_code missing;
        if (!fs::exists(peers_path, missing)) return Json::array();
        const auto store = read_json(peers_path);
        if (!store.is_object() || !store.contains("schema") ||
            store.at("schema") != 1 || !store.contains("keys") ||
            !store.at("keys").is_array()) {
            throw SetupError(peers_path.string() +
                             " is not a schema-1 peer store");
        }
        return store.at("keys");
    }
};

Node load_node(const keys::KeyContext& context, const fs::path& server_path) {
    const auto resolved = resolve_existing(server_path);
    if (!resolved)
        throw SetupError("server directory does not exist: " +
                         server_path.string());
    Node node;
    node.server = *resolved;
    node.config_path = node.server / "yumed.json";
    node.config = read_server_config(node.server, node.server.string());
    const Json* port = nullptr;
    if (node.config.contains("endpoint") &&
        node.config.at("endpoint").is_object() &&
        node.config.at("endpoint").contains("port")) {
        port = &node.config.at("endpoint").at("port");
    }
    if (port == nullptr || !port->is_number_integer() || *port < 1 ||
        *port > 65535) {
        throw SetupError(node.config_path.string() +
                         " has no valid endpoint.port");
    }
    node.port = port->get<std::int64_t>();
    node.admission = config_reference(node.server, node.config, "credentials",
                                      "admission_key");
    node.credentials = node.admission.parent_path();
    for (const auto* name : {"server-composite.pub.pem", "server-mlkem.pub.pem",
                             "server-trust.pem", "server-tls.pem"}) {
        if (!file_at(node.credentials / name)) {
            throw SetupError(node.credentials.string() + " lacks " + name +
                             "; clusters need the layout init writes");
        }
    }
    const auto identity_path = node.credentials / "server-composite.pub.pem";
    node.identity_key = read_ascii(identity_path);
    node.identity = identity_of(context, identity_path, node.identity_key);
    node.cluster = node.server / kNodeClusterDirectory;
    node.peers_path = node.cluster / "peers.json";
    node.owner = owner_of(node.config_path);
    return node;
}

// Files a cluster command creates and stores it replaces. New files are
// created exclusively and replacements are staged beside their targets, so
// nothing a node reads changes until commit(). Until then, rollback()
// removes everything created. After a commit that fails part way, the nodes
// it names may need another run.
class Changes final {
public:
    Changes() = default;
    Changes(const Changes&) = delete;
    Changes& operator=(const Changes&) = delete;
    ~Changes() { rollback(); }

    void directory(const fs::path& path, const Owner& owner) {
        if (directory_at(path)) return;
        directory(path.parent_path(), owner);
        make_private_directory(path);
        record(path, owner);
    }

    void create(const fs::path& path, std::span<const std::uint8_t> contents,
                const Owner& owner) {
        directory(path.parent_path(), owner);
        write_new_file(path, contents);
        record(path, owner);
    }

    void copy(const fs::path& source, const fs::path& path,
              const Owner& owner) {
        directory(path.parent_path(), owner);
        copy_private_file(source, path);
        record(path, owner);
    }

    void replace(const fs::path& path, std::string_view contents,
                 const Owner& owner) {
        directory(path.parent_path(), owner);
        auto temporary = replacement_path(path);
        write_new_file(temporary, as_bytes(contents));
        replacements_.emplace_back(temporary, path);
        owners_.emplace_back(std::move(temporary), owner);
    }

    void commit() {
        if (running_as_root()) {
            for (const auto& [path, owner] : owners_) give_to(path, owner);
        }
        for (const auto& path : created_) fsync_directory(path.parent_path());
        for (const auto& [temporary, path] : replacements_) {
            rename_replace(temporary, path);
            fsync_directory(path.parent_path());
        }
        replacements_.clear();
        created_.clear();
        owners_.clear();
    }

    void rollback() noexcept {
        for (const auto& [temporary, path] : replacements_)
            remove_file(temporary);
        for (auto it = created_.rbegin(); it != created_.rend(); ++it) {
            std::error_code ignored;
            if (directory_at(*it) && !fs::is_symlink(*it, ignored)) {
                static_cast<void>(::rmdir(it->c_str()));
            } else {
                remove_file(*it);
            }
        }
        replacements_.clear();
        created_.clear();
        owners_.clear();
    }

private:
    void record(const fs::path& path, const Owner& owner) {
        created_.push_back(path);
        owners_.emplace_back(path, owner);
    }

    std::vector<fs::path> created_;
    std::vector<std::pair<fs::path, fs::path>> replacements_;
    std::vector<std::pair<fs::path, Owner>> owners_;
};

struct ClusterRecord final {
    fs::path root;
    Json state;
};

bool optional_string(const Json& node, const char* key) {
    return !node.contains(key) || node.at(key).is_string();
}

ClusterRecord read_cluster(const fs::path& directory) {
    const auto root = resolve_existing(directory);
    if (!root)
        throw SetupError("cluster directory does not exist: " +
                         directory.string());
    auto state = read_json(*root / "cluster.json");
    const auto valid_node = [](const Json& node) {
        if (!node.is_object()) return false;
        for (const auto& [key, value] : node.items()) {
            static_cast<void>(value);
            if (key != "name" && key != "server" && key != "host" &&
                key != "address" && key != "exit") {
                return false;
            }
        }
        return node.contains("name") && node.at("name").is_string() &&
               node.contains("server") && node.at("server").is_string() &&
               node.contains("host") && node.at("host").is_string() &&
               optional_string(node, "address") &&
               (!node.contains("exit") || node.at("exit").is_boolean());
    };
    if (!state.is_object() || !state.contains("schema") ||
        state.at("schema") != 1 || !state.contains("cluster") ||
        !state.at("cluster").is_string() || !state.contains("serial") ||
        !state.at("serial").is_number_integer() || state.at("serial") < 0 ||
        !state.contains("nodes") || !state.at("nodes").is_array() ||
        !std::all_of(state.at("nodes").begin(), state.at("nodes").end(),
                     valid_node)) {
        throw SetupError((*root / "cluster.json").string() +
                         " is not a schema-1 cluster record");
    }
    return {*root, std::move(state)};
}

Json peer_entry(const std::string& name, const std::string& identity) {
    return {
        {"identity", identity},
        {"outbound_psk", {{"file", "peers/" + name + "-outbound.psk"}}},
        {"inbound_psk", {{"file", "peers/" + name + "-inbound.psk"}}},
        {"admission_key", {{"file", "peers/" + name + "-admission.key"}}},
    };
}

Json cluster_section(const std::optional<std::string>& exit_service) {
    const std::string base(kNodeClusterDirectory);
    const auto file = [](std::string path) {
        return Json{{"file", std::move(path)}};
    };
    Json section{
        {"operator_key", file(base + "/operator.pub.pem")},
        {"list", file(base + "/cluster-list.json")},
        {"signature", file(base + "/cluster-list.sig")},
        {"peers", file(base + "/peers.json")},
        {"routes", file(base + "/cluster-routes.json")},
        {"routes_signature", file(base + "/cluster-routes.sig")},
        // yumed writes this itself, so it stays outside the credentials that
        // the operator deploys.
        {"state", file(std::string(kNodeClusterState))},
    };
    if (exit_service) section["exit"] = {{"service", *exit_service}};
    return section;
}

// The one direct_tcp service an exit carries circuits' streams through.
std::string exit_service(const Node& node) {
    std::vector<const Json*> services;
    if (node.config.contains("adapters") &&
        node.config.at("adapters").is_array()) {
        for (const auto& adapter : node.config.at("adapters")) {
            if (adapter.is_object() && adapter.contains("kind") &&
                adapter.at("kind") == "direct_tcp") {
                services.push_back(adapter.contains("service")
                                       ? &adapter.at("service")
                                       : nullptr);
            }
        }
    }
    if (services.size() != 1U || services.front() == nullptr ||
        !services.front()->is_string()) {
        throw SetupError(node.config_path.string() +
                         " needs exactly one direct_tcp adapter to be an exit");
    }
    return services.front()->get<std::string>();
}

bool certificate_names_host(const keys::KeyContext& context,
                            const fs::path& path, const std::string& host) {
    const auto certificates = read_certificates(context, read_ascii(path));
    return !certificates.empty() &&
           certificate_names(certificates.front().get(), host);
}

std::string address_text(const sockaddr* address) {
    std::array<char, INET6_ADDRSTRLEN> text{};
    const void* bytes =
        address->sa_family == AF_INET
            ? static_cast<const void*>(
                  &reinterpret_cast<const sockaddr_in*>(address)->sin_addr)
            : static_cast<const void*>(
                  &reinterpret_cast<const sockaddr_in6*>(address)->sin6_addr);
    if (::inet_ntop(address->sa_family, bytes, text.data(),
                    static_cast<socklen_t>(text.size())) == nullptr) {
        return {};
    }
    return text.data();
}

// The node's address, or without one, its host resolved now, preferring an
// IPv4 address.
std::string tag_address(const std::string& host,
                        const std::optional<std::string>& address) {
    if (address) return *address;
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* answers = nullptr;
    if (::getaddrinfo(host.c_str(), nullptr, &hints, &answers) != 0) {
        throw SetupError("cannot resolve " + host +
                         " for its network tag; give the node an --address");
    }
    std::vector<std::pair<bool, std::string>> found;
    for (const addrinfo* answer = answers; answer != nullptr;
         answer = answer->ai_next) {
        if (answer->ai_family != AF_INET && answer->ai_family != AF_INET6)
            continue;
        auto text = address_text(answer->ai_addr);
        if (!text.empty())
            found.emplace_back(answer->ai_family == AF_INET6, std::move(text));
    }
    ::freeaddrinfo(answers);
    if (found.empty()) {
        throw SetupError(host +
                         " resolves to no address; give the node an --address");
    }
    return std::min_element(found.begin(), found.end())->second;
}

// The network tag of a node: the first bytes of an HMAC of its IPv4 /16 or
// IPv6 /32 under the operator's tag key. The text is the network's exploded
// form, which only setup computes, so tags stay equal from one signing to
// the next.
std::string network_tag(const keys::KeyContext& context,
                        std::span<const std::uint8_t> key,
                        const std::string& host,
                        const std::optional<std::string>& address) {
    const auto ip = tag_address(host, address);
    std::array<unsigned char, 16> bytes{};
    std::string text;
    if (::inet_pton(AF_INET, ip.c_str(), bytes.data()) == 1) {
        text = std::to_string(bytes[0]) + "." + std::to_string(bytes[1]) +
               ".0.0/16";
    } else if (::inet_pton(AF_INET6, ip.c_str(), bytes.data()) == 1) {
        std::array<char, 8> group{};
        for (std::size_t index = 0; index < 8U; ++index) {
            const unsigned value =
                index < 2U ? (bytes[2U * index] << 8U) | bytes[2U * index + 1U]
                           : 0U;
            static_cast<void>(
                std::snprintf(group.data(), group.size(), "%04x", value));
            text += (index == 0U ? "" : ":") + std::string(group.data());
        }
        text += "/32";
    } else {
        throw SetupError("node address must be an IP literal");
    }
    std::array<unsigned char, 32> mac{};
    std::size_t size = 0;
    const auto digest = std::string(providers::ytp1_crypto::kSha256Algorithm);
    if (EVP_Q_mac(context.context(),
                  providers::ytp1_crypto::kHmacAlgorithm.data(),
                  providers::ytp1_crypto::kOpenSslPropertyQuery.data(),
                  digest.c_str(), nullptr, key.data(), key.size(),
                  reinterpret_cast<const unsigned char*>(text.data()),
                  text.size(), mac.data(), mac.size(), &size) == nullptr ||
        size != mac.size()) {
        throw SetupError("OpenSSL could not compute a network tag");
    }
    return encoding::hex_lower(
        std::span<const std::uint8_t>(mac.data(), cluster::kNetworkTagBytes));
}

std::string utc_after_days(std::int64_t days) {
    const auto now = std::chrono::floor<std::chrono::seconds>(
        std::chrono::system_clock::now());
    const std::time_t when =
        std::chrono::system_clock::to_time_t(now + std::chrono::days(days));
    std::tm parts{};
    std::array<char, 32> text{};
    if (::gmtime_r(&when, &parts) == nullptr ||
        std::strftime(text.data(), text.size(), "%Y-%m-%dT%H:%M:%SZ", &parts) ==
            0) {
        throw SetupError("cannot format the list's expiry");
    }
    return text.data();
}

std::vector<std::byte> signed_message(std::string_view domain,
                                      std::string_view document) {
    std::vector<std::byte> message;
    message.reserve(domain.size() + 1U + document.size());
    for (const char ch : domain) message.push_back(static_cast<std::byte>(ch));
    message.push_back(std::byte{0});
    for (const char ch : document)
        message.push_back(static_cast<std::byte>(ch));
    return message;
}

std::span<const std::byte> byte_view(std::string_view text) {
    return std::as_bytes(std::span(text.data(), text.size()));
}

}  // namespace

std::pair<fs::path, std::string> cluster_init(const fs::path& output_path) {
    const fs::path output = require_output_path(output_path);
    const fs::path parent = output.parent_path();
    Staging staging(parent);
    const Material material;
    const auto identity = material.composite();
    write_new_file(staging.path() / "operator-composite.pem",
                   identity.private_pem.bytes());
    write_new_file(staging.path() / "operator-composite.pub.pem",
                   as_bytes(identity.public_pem));
    SecretBytes tag_key(kTagKeyBytes);
    material.random({tag_key.data(), tag_key.size()});
    write_new_file(staging.path() / kTagKeyFile, tag_key.bytes());
    write_json(staging.path() / "cluster.json",
               Json{{"schema", 1},
                    {"cluster", identity.fingerprint},
                    {"serial", 0},
                    {"nodes", Json::array()}});
    fsync_tree(staging.path());
    staging.publish(staging.path(), output);
    fsync_directory(parent);
    return {output, identity.fingerprint};
}

fs::path cluster_add(const ClusterAddOptions& options) {
    const auto name = require_node_name(options.name);
    const auto host = require_host(options.host);
    std::optional<std::string> address;
    if (options.address) {
        address = canonical_ip(*options.address);
        if (!address) throw SetupError("node address must be an IP literal");
    }
    const auto record = read_cluster(options.cluster);
    const auto& records = record.state.at("nodes");
    if (records.size() >= cluster::kMaxNodes) {
        throw SetupError("a cluster holds at most " +
                         std::to_string(cluster::kMaxNodes) + " nodes");
    }
    if (std::any_of(records.begin(), records.end(), [&](const Json& other) {
            return other.at("name") == name;
        })) {
        throw SetupError("the cluster already has a node named " + name);
    }
    const Material material;
    const auto node = load_node(material.keys(), options.server);
    if (node.config.contains("cluster") &&
        !node.config.at("cluster").is_null()) {
        throw SetupError(node.config_path.string() +
                         " already belongs to a cluster");
    }
    if (!certificate_names_host(material.keys(),
                                node.credentials / "server-tls.pem", host)) {
        throw SetupError("the node's TLS certificate does not name " + host);
    }
    std::optional<std::string> exit;
    if (options.exit) exit = exit_service(node);
    std::vector<Node> existing;
    for (const auto& other : records) {
        existing.push_back(
            load_node(material.keys(), other.at("server").get<std::string>()));
    }
    if (std::any_of(existing.begin(), existing.end(), [&](const Node& other) {
            return other.identity == node.identity ||
                   other.server == node.server;
        })) {
        throw SetupError("that server directory is already in the cluster");
    }

    Changes changes;
    Json new_entries = Json::array();
    for (std::size_t index = 0; index < records.size(); ++index) {
        const auto other_name = records.at(index).at("name").get<std::string>();
        const auto& other = existing[index];
        SecretBytes outbound(kLinkPskBytes);
        SecretBytes inbound(kLinkPskBytes);
        material.random({outbound.data(), outbound.size()});
        material.random({inbound.data(), inbound.size()});
        if (std::memcmp(outbound.data(), inbound.data(), kLinkPskBytes) == 0) {
            throw SetupError("generated link PSKs are equal");
        }
        const fs::path peers = node.cluster / "peers";
        changes.create(peers / (other_name + "-outbound.psk"), outbound.bytes(),
                       node.owner);
        changes.create(peers / (other_name + "-inbound.psk"), inbound.bytes(),
                       node.owner);
        changes.copy(other.admission, peers / (other_name + "-admission.key"),
                     node.owner);
        new_entries.push_back(peer_entry(other_name, other.identity));
        // The other node's inbound PSK from this node is this node's
        // outbound PSK, and the other way round.
        const fs::path other_peers = other.cluster / "peers";
        changes.create(other_peers / (name + "-outbound.psk"), inbound.bytes(),
                       other.owner);
        changes.create(other_peers / (name + "-inbound.psk"), outbound.bytes(),
                       other.owner);
        changes.copy(node.admission, other_peers / (name + "-admission.key"),
                     other.owner);
        auto other_keys = other.peers();
        other_keys.push_back(peer_entry(name, node.identity));
        changes.replace(other.peers_path,
                        json_text(Json{{"schema", 1}, {"keys", other_keys}}),
                        other.owner);
    }
    changes.replace(node.peers_path,
                    json_text(Json{{"schema", 1}, {"keys", new_entries}}),
                    node.owner);
    changes.copy(record.root / "operator-composite.pub.pem",
                 node.cluster / "operator.pub.pem", node.owner);
    Json config = node.config;
    config["cluster"] = cluster_section(exit);
    changes.replace(node.config_path, json_text(config), node.owner);
    Json entry{
        {"name", name}, {"server", node.server.string()}, {"host", host}};
    if (address) entry["address"] = *address;
    if (options.exit) entry["exit"] = true;
    Json updated = record.state;
    updated["nodes"].push_back(entry);
    changes.replace(record.root / "cluster.json", json_text(updated),
                    owner_of(record.root / "cluster.json"));
    changes.commit();
    return node.server;
}

fs::path cluster_remove(const fs::path& cluster_path,
                        const std::string& name_text) {
    const auto name = require_node_name(name_text);
    const auto record = read_cluster(cluster_path);
    const auto& records = record.state.at("nodes");
    const auto removed =
        std::find_if(records.begin(), records.end(),
                     [&](const Json& node) { return node.at("name") == name; });
    if (removed == records.end())
        throw SetupError("the cluster has no node named " + name);
    const Material material;
    const auto leaving =
        load_node(material.keys(), removed->at("server").get<std::string>());
    Json remaining = Json::array();
    for (auto it = records.begin(); it != records.end(); ++it) {
        if (it != removed) remaining.push_back(*it);
    }
    Changes changes;
    std::vector<fs::path> stale;
    for (const auto& other_record : remaining) {
        const auto other = load_node(
            material.keys(), other_record.at("server").get<std::string>());
        Json kept = Json::array();
        for (const auto& entry : other.peers()) {
            if (!(entry.is_object() && entry.contains("identity") &&
                  entry.at("identity") == leaving.identity)) {
                kept.push_back(entry);
            }
        }
        changes.replace(other.peers_path,
                        json_text(Json{{"schema", 1}, {"keys", kept}}),
                        other.owner);
        for (const auto* kind :
             {"outbound.psk", "inbound.psk", "admission.key"}) {
            stale.push_back(other.cluster / "peers" / (name + "-" + kind));
        }
    }
    // Only a state file inside the server directory is this node's to remove.
    const Json* section = leaving.config.contains("cluster")
                              ? &leaving.config.at("cluster")
                              : nullptr;
    if (section != nullptr && section->is_object() &&
        section->contains("state") && section->at("state").is_object() &&
        section->at("state").contains("file") &&
        section->at("state").at("file").is_string()) {
        const fs::path state(
            section->at("state").at("file").get<std::string>());
        if (!state.is_absolute()) {
            const auto saved = leaving.server / state;
            stale.push_back(saved);
            stale.push_back(saved.parent_path() /
                            (saved.filename().string() + ".new"));
        }
    }
    Json config = leaving.config;
    config.erase("cluster");
    changes.replace(leaving.config_path, json_text(config), leaving.owner);
    Json updated = record.state;
    updated["nodes"] = remaining;
    changes.replace(record.root / "cluster.json", json_text(updated),
                    owner_of(record.root / "cluster.json"));
    changes.commit();
    for (const auto& path : stale) remove_file(path);
    if (directory_at(leaving.cluster) && !fs::is_symlink(leaving.cluster)) {
        remove_tree(leaving.cluster);
    }
    return leaving.server;
}

std::pair<std::uint64_t, std::string> cluster_sign(const fs::path& cluster_path,
                                                   std::int64_t days) {
    if (days < 1 || days > kMaxClusterDays) {
        throw SetupError("days must be in 1.." +
                         std::to_string(kMaxClusterDays));
    }
    const auto record = read_cluster(cluster_path);
    const auto& records = record.state.at("nodes");
    if (records.empty())
        throw SetupError("the cluster has no nodes; add one with cluster-add");
    const Material material;
    const auto& context = material.keys();
    const auto operator_public_path =
        record.root / "operator-composite.pub.pem";
    const auto operator_public = read_ascii(operator_public_path);
    if (identity_of(context, operator_public_path, operator_public) !=
        record.state.at("cluster").get<std::string>()) {
        throw SetupError("the operator key does not match cluster.json");
    }
    const auto tag_key_path = record.root / kTagKeyFile;
    const auto tag_key = read_secret(tag_key_path, kTagKeyBytes);
    if (tag_key.size() != kTagKeyBytes) {
        throw SetupError(tag_key_path.string() + " must hold 32 bytes");
    }
    std::vector<Node> nodes;
    Json entries = Json::array();
    Json routes = Json::array();
    for (const auto& node_record : records) {
        nodes.push_back(
            load_node(context, node_record.at("server").get<std::string>()));
        const auto& node = nodes.back();
        Json entry{
            {"name", node_record.at("name")},
            {"identity", node.identity},
            {"host", node_record.at("host")},
            {"port", node.port},
            {"identity_key", node.identity_key},
            {"mlkem_key",
             read_ascii(node.credentials / "server-mlkem.pub.pem")},
            {"tls_trust", read_ascii(node.credentials / "server-trust.pem")},
        };
        std::optional<std::string> address;
        if (node_record.contains("address")) {
            address = node_record.at("address").get<std::string>();
            entry["address"] = *address;
        }
        entries.push_back(std::move(entry));
        routes.push_back({
            {"name", node_record.at("name")},
            {"identity", node.identity},
            {"identity_key", node.identity_key},
            {"exit", node_record.contains("exit") &&
                         node_record.at("exit").get<bool>()},
            {"network",
             network_tag(context, tag_key.bytes(),
                         node_record.at("host").get<std::string>(), address)},
        });
    }
    const auto serial = record.state.at("serial").get<std::uint64_t>() + 1U;
    const auto not_after = utc_after_days(days);
    const Json header{{"schema", 1},
                      {"cluster", record.state.at("cluster")},
                      {"serial", serial},
                      {"not_after", not_after}};
    Json list = header;
    list["nodes"] = entries;
    Json view = header;
    view["nodes"] = routes;
    const auto document = json_text(list);
    const auto view_document = json_text(view);

    std::vector<std::byte> signature;
    std::vector<std::byte> view_signature;
    {
        const auto private_pem =
            read_secret(record.root / "operator-composite.pem", kMaxJsonBytes);
        try {
            const auto signer =
                keys::composite_private_from_pem(context, private_pem.text());
            signature = keys::sign_composite(
                context, signer,
                signed_message(cluster::kListDomain, document));
            view_signature = keys::sign_composite(
                context, signer,
                signed_message(cluster::kRoutesDomain, view_document));
        } catch (const keys::KeyError& error) {
            throw SetupError(std::string("the operator key cannot sign: ") +
                             error.what());
        }
    }
    // A node reads the list and the view with these functions, so nothing is
    // published that a node would refuse.
    const auto now = std::chrono::system_clock::now();
    const auto verified_list = cluster::verify_list(
        byte_view(document), signature, operator_public, now);
    if (!verified_list.ok()) {
        throw SetupError("the signed cluster list does not verify: " +
                         verified_list.status().message());
    }
    const auto verified_routes = cluster::verify_routes(
        byte_view(view_document), view_signature, operator_public, now);
    if (!verified_routes.ok()) {
        throw SetupError("the signed routes view does not verify: " +
                         verified_routes.status().message());
    }
    const auto matched =
        cluster::check_routes(verified_list.value(), verified_routes.value());
    if (!matched.ok()) {
        throw SetupError("the routes view does not match the list: " +
                         matched.message());
    }

    const auto signature_text = std::string_view(
        reinterpret_cast<const char*>(signature.data()), signature.size());
    const auto view_signature_text =
        std::string_view(reinterpret_cast<const char*>(view_signature.data()),
                         view_signature.size());
    const std::array<std::pair<std::string_view, std::string_view>, 4>
        published{{
            {"cluster-list.json", document},
            {"cluster-list.sig", signature_text},
            {"cluster-routes.json", view_document},
            {"cluster-routes.sig", view_signature_text},
        }};
    Changes changes;
    const auto owner = owner_of(record.root / "cluster.json");
    for (const auto& [name, contents] : published) {
        for (const auto& node : nodes)
            changes.replace(node.cluster / name, contents, node.owner);
        changes.replace(record.root / name, contents, owner);
    }
    Json updated = record.state;
    updated["serial"] = serial;
    changes.replace(record.root / "cluster.json", json_text(updated), owner);
    changes.commit();
    return {serial, not_after};
}

}  // namespace yume::setup
