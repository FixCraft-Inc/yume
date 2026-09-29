/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "common/service_name.hpp"
#include "engine/byte_channel.hpp"
#include "engine/stream_handler.hpp"
#include "providers/asio_execution_context.hpp"
#include "providers/circuit_crypto.hpp"
#include "providers/composite_keys.hpp"
#include "ytp/protocol.hpp"

// The node side of circuit 1 (docs/protocol/CIRCUIT_1.md): the yume.circuit
// service that answers CREATE, extends circuits over this node's links,
// relays cells in both directions and, at an exit, carries a circuit's
// streams to their destinations.
namespace yume::runtime::circuit {

inline constexpr std::string_view kServiceName = common::kCircuitServiceName;

using Fingerprint = providers::circuit::Fingerprint;

struct NodeLimits final {
    // Circuits one client identity may hold here as its entry, and how fast
    // it may open new ones.
    std::size_t circuits_per_client{4U};
    double client_circuits_per_second{12.0 / 60.0};
    double client_circuit_burst{4.0};
    // New circuits per second on one peer's link, with a burst.
    double link_circuits_per_second{20.0};
    double link_circuit_burst{64.0};
    // Handshakes this node answers per second, with a burst. Each costs one
    // composite signature on the node's single execution thread.
    double handshakes_per_second{200.0};
    double handshake_burst{64.0};
    std::size_t streams_per_circuit{256U};
    // The window an exit grants a circuit's stream for data toward its
    // destination, returned as it drains.
    std::uint32_t stream_window{256U * 1024U};
    // The window an exit grants across one circuit's streams, so a client
    // with slow destinations makes it hold at most this much per circuit.
    // With the stream window above it allows 32 streams at once.
    std::uint64_t circuit_window{std::uint64_t{8} * 1024U * 1024U};
    std::chrono::milliseconds extend_timeout{10'000};
    // A circuit whose cell has waited this long for the next hop, or for its
    // previous hop, ends, so a stalled circuit gives its share of a link's
    // credit back.
    std::chrono::milliseconds stall_timeout{30'000};
    // Backward cells an exit queues before it stops reading destinations.
    std::size_t backward_queue_cells{16U};
};

// A snapshot for status displays. It counts circuits and names none, since a
// node must not keep which neighbour a circuit came from or went to.
struct NodeStatus final {
    // Circuits a peer's link carries to this node, and circuits this node
    // extended over its link to that peer, counted apart so that no count
    // joins the two sides of one circuit.
    struct Link final {
        std::string peer_identity;
        std::size_t inbound{0U};
        std::size_t outbound{0U};
    };

    std::size_t circuits{0U};
    std::size_t entry_circuits{0U};
    std::size_t relayed_circuits{0U};
    std::size_t exit_streams{0U};
    // Refusals since start, by the bound that refused: circuits one client
    // holds, the new-circuit rate of a client or a link, the handshake rate
    // and streams per circuit. refused is their sum.
    std::uint64_t refused{0U};
    std::uint64_t refused_client_circuits{0U};
    std::uint64_t refused_circuit_rate{0U};
    std::uint64_t refused_handshakes{0U};
    std::uint64_t refused_streams{0U};
    std::uint64_t failed{0U};
    std::vector<Link> links;
};

using StreamOpened = std::function<void(
    engine::Result<std::shared_ptr<engine::StreamResponder>>)>;
using ChannelOpened =
    std::function<void(engine::Result<std::unique_ptr<engine::ByteChannel>>)>;

// What the service needs from the daemon around it.
struct NodeEnvironment final {
    std::shared_ptr<providers::AsioExecutionContext> context;
    std::shared_ptr<const providers::circuit::CircuitCrypto> crypto;
    // This node's composite identity, parsed in crypto's key context.
    std::shared_ptr<const providers::keys::CompositePrivate> identity;
    // Whether an authenticated identity is a cluster peer rather than a
    // client.
    std::function<bool(std::string_view identity)> is_peer;
    // Opens a circuit stream on this node's outbound link to the peer with
    // this fingerprint. NotFound when the list does not name it,
    // FailedPrecondition when no link to it is up.
    std::function<void(std::string_view peer_identity,
                       engine::CancellationToken cancellation,
                       StreamOpened done)>
        open_next;
    // Connects a circuit's stream to its TCP destination after this node's
    // exit policy allowed it. PermissionDenied when the policy refuses. The
    // exit never learns the client: carried_by is how the previous hop's node
    // opened the stream that carries the circuit here. Empty when this node
    // is not an exit.
    std::function<void(const engine::StreamOpenContext& carried_by,
                       const ytp1::Destination& destination,
                       engine::CancellationToken cancellation,
                       ChannelOpened done)>
        open_exit;
    NodeLimits limits;
};

class CircuitService final
    : public engine::StreamHandler,
      public std::enable_shared_from_this<CircuitService> {
public:
    static engine::Result<std::shared_ptr<CircuitService>> create(
        NodeEnvironment environment);

    CircuitService(const CircuitService&) = delete;
    CircuitService& operator=(const CircuitService&) = delete;
    ~CircuitService() override;

    const engine::ProviderDescriptor& descriptor() const noexcept override;
    engine::ServiceKind service_kind() const noexcept override {
        return engine::ServiceKind::PacketChannel;
    }
    engine::Status authorize(const engine::StreamOpenContext& context) override;
    void async_open(engine::StreamOpenContext context,
                    std::shared_ptr<engine::StreamResponder> stream,
                    AcceptanceCompletion completion) override;
    void on_open(engine::StreamOpenContext context,
                 std::shared_ptr<engine::StreamResponder> stream) override;

    // On the context.
    NodeStatus status() const;
    // On the context. Ends every circuit and refuses new ones.
    void close() noexcept;

    struct Node;

private:
    explicit CircuitService(std::shared_ptr<Node> node) noexcept;
    std::shared_ptr<Node> node_;
};

}  // namespace yume::runtime::circuit
