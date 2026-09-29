/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <boost/asio/ip/tcp.hpp>

#include "config/v1/config.hpp"
#include "engine/status.hpp"
#include "providers/asio_execution_context.hpp"
#include "runtime/native_client_runtime.hpp"

namespace yume::runtime {

// One cluster peer as this node sees it: its outbound link's keeper status,
// the sessions the peer holds to this node, and the circuits that arrive
// over the peer's link and leave over this node's link to it, counted apart.
struct NativeLinkStatus final {
    std::string peer_name;
    std::string peer_identity;
    NativeClientStatus outbound;
    std::size_t inbound_sessions{0U};
    // When the oldest inbound session was admitted.
    std::chrono::steady_clock::time_point inbound_since{};
    std::size_t circuits_in{0U};
    std::size_t circuits_out{0U};
};

// The node's circuit service in counts. No count names a circuit or joins
// the two neighbours of one. Refusals are since start, by the bound that
// refused them, and refused is their sum.
struct NativeCircuitStatus final {
    bool exit{false};
    std::size_t circuits{0U};
    std::size_t entry_circuits{0U};
    std::size_t relayed_circuits{0U};
    std::size_t exit_streams{0U};
    std::uint64_t refused{0U};
    std::uint64_t refused_client_circuits{0U};
    std::uint64_t refused_circuit_rate{0U};
    std::uint64_t refused_handshakes{0U};
    std::uint64_t refused_streams{0U};
    std::uint64_t failed{0U};
};

struct NativeClusterStatus final {
    std::string cluster;
    std::uint64_t serial{0U};
    std::chrono::system_clock::time_point not_after;
    std::string self_name;
    bool expired{false};
    std::vector<NativeLinkStatus> links;
    NativeCircuitStatus circuits;
};

struct NativeServerStatus final {
    std::vector<boost::asio::ip::tcp::endpoint> listeners;
    // Authenticated sessions other than cluster peers'.
    std::size_t client_sessions{0U};
    std::optional<NativeClusterStatus> cluster;
};

struct NativeServerRuntimeOptions final {
    // The SystemResolver helper for destination names of direct adapters.
    // Empty refuses those names, while numeric destinations still work.
    std::filesystem::path resolver_program;
    // Launches configured modules, run as yume-module. Required with a module
    // adapter.
    std::filesystem::path module_launcher;
    // Module starts, exits and restarts, for the operator. Runs on the
    // context and must not throw.
    std::function<void(std::string_view)> report;
};

// Runs one schema-1 server configuration as a standalone daemon. Every
// configured service needs a direct_tcp, direct_udp, module or managed packet
// adapter. Other named services need application handlers from an embedder.
// Each module adapter runs its program under a ModuleSupervisor, which starts
// before the listeners accept and stops with the runtime.
// With a cluster section, the runtime keeps one outbound link to every peer
// once the listeners accept, reconnecting with SessionKeeper's backoff. When
// the list's not_after passes, the links close and the peers' sessions end
// until a reload loads a newer list. A cluster member also serves circuit 1
// on yume.circuit, extending circuits over its links and, when its cluster
// section names an exit, carrying their streams through that direct_tcp
// service's destination policy, and serves the routes view on yume.routes.
// Circuits sign with the composite key loaded at start: a changed node
// identity needs a restart, since the list names the old one anyway.
// Destinations are enforced by NativeEgressPolicy for the request and for
// every resolved address. Each packet adapter admits one authenticated stream
// across all sessions and enforces local/peer address policy in both
// directions. The endpoint's accept loop serves every listener.
//
// All calls run on the supplied single-runner context. on_stopped runs once if
// the endpoint stops accepting or managed network cleanup fails. The caller
// closes the runtime, calls finish() and drains managed packet I/O/networking.
class NativeServerRuntime final {
public:
    using Stopped = std::function<void(engine::Status)>;

    static engine::Result<std::shared_ptr<NativeServerRuntime>> create(
        std::shared_ptr<providers::AsioExecutionContext> context,
        const config::v1::Config& config,
        const std::filesystem::path& config_base_directory,
        Stopped on_stopped,
        NativeServerRuntimeOptions options = {});

    NativeServerRuntime(const NativeServerRuntime&) = delete;
    NativeServerRuntime& operator=(const NativeServerRuntime&) = delete;
    ~NativeServerRuntime() noexcept;

    engine::Status start();
    std::vector<boost::asio::ip::tcp::endpoint> listener_endpoints() const;
    // Applies changed credential stores without dropping other sessions. See
    // NativeEndpoint::reload_credentials. With a cluster, every link then
    // restarts with the reloaded list and peer store.
    engine::Status reload();
    // On the context: listeners, sessions and cluster links.
    NativeServerStatus status() const;
    void close() noexcept;

private:
    struct State;
    explicit NativeServerRuntime(std::shared_ptr<State> state) noexcept;
    std::shared_ptr<State> state_;
};

}  // namespace yume::runtime
