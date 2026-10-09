/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <utility>

namespace yume::setup {

// What yume-setup does. Each action checks its inputs before it changes
// anything and throws SetupError with an operator-facing message. Paths are
// the operator's own, as given on the command line.

struct InitOptions final {
    std::string host;
    std::filesystem::path output;
    std::int64_t port{443};
    std::string client_name{"client1"};
    std::optional<std::int64_t> max_sessions;
    std::optional<double> weight;
    std::optional<std::int64_t> max_egress_mbps;
    std::string preset;
};
// A server directory and its first client bundle in one new kit directory,
// published by an atomic no-replace rename. Returns the kit's path.
std::filesystem::path init_kit(const InitOptions& options);

struct AddClientOptions final {
    std::filesystem::path server;
    std::string host;
    std::filesystem::path output;
    std::string client_name;
    std::optional<std::int64_t> max_sessions;
    std::optional<double> weight;
    bool circuits{false};
};
// One more client bundle for an existing server directory. The server's
// authorized-keys store gains the client last, and every earlier step is
// undone when a later one fails. Returns the bundle's path.
std::filesystem::path add_client(const AddClientOptions& options);

// Takes a client out of a server's authorized-keys store, then deletes its
// public key and access PSK. Returns the store's path.
std::filesystem::path remove_client(const std::filesystem::path& server,
                                    const std::string& client_name);

// A new operator directory with a composite operator key, the routes tag
// key and an empty cluster record. Returns the directory and the cluster ID.
std::pair<std::filesystem::path, std::string> cluster_init(
    const std::filesystem::path& output);

struct ClusterAddOptions final {
    std::filesystem::path cluster;
    std::filesystem::path server;
    std::string name;
    std::string host;
    std::optional<std::string> address;
    bool exit{false};
};
// Enters a server into a cluster with pairwise link secrets to every other
// node. Returns the server directory.
std::filesystem::path cluster_add(const ClusterAddOptions& options);

// Takes a node out of a cluster. Returns its server directory.
std::filesystem::path cluster_remove(const std::filesystem::path& cluster,
                                     const std::string& name);

inline constexpr std::int64_t kDefaultClusterDays = 30;
inline constexpr std::int64_t kMaxClusterDays = 366;
// Signs the next list and routes view and gives them to every node. Returns
// the serial and not_after.
std::pair<std::uint64_t, std::string> cluster_sign(
    const std::filesystem::path& cluster, std::int64_t days);

}  // namespace yume::setup
