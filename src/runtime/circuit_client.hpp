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
#include <optional>
#include <vector>

#include "circuit/protocol.hpp"
#include "engine/stream_handler.hpp"
#include "providers/asio_execution_context.hpp"
#include "providers/circuit_crypto.hpp"
#include "providers/composite_keys.hpp"
#include "ytp/protocol.hpp"

// The client side of circuit 1 (docs/protocol/CIRCUIT_1.md): builds a circuit
// hop by hop over a yume.circuit stream to the entry and carries streams to
// destinations through its exit, each one an ordinary byte stream.
namespace yume::runtime::circuit {

using Fingerprint = providers::circuit::Fingerprint;

struct ClientLimits final {
    // The window this client grants the exit for each stream's data at
    // first. Each time the application drains half of it the window doubles,
    // up to max_stream_window, while the circuit's stream windows total at
    // most circuit_window.
    std::uint32_t stream_window{256U * 1024U};
    std::uint32_t max_stream_window{1024U * 1024U};
    std::uint64_t circuit_window{8U * 1024U * 1024U};
    std::size_t streams_per_circuit{256U};
    std::chrono::milliseconds build_timeout{30'000};
    // Forward cells queued toward the entry before stream writes wait.
    std::size_t forward_queue_cells{16U};
};

// Why a circuit ended, with hops counted from 1 at the entry. While it was
// being built, hop names the hop that could not be reached, did not answer
// or answered wrongly. Once it was built, hop names the hop that reported
// the break. 0 when the client or the entry's stream ended it.
struct CircuitFailure final {
    std::size_t hop{0U};
    circuit1::CircuitReason reason{circuit1::CircuitReason::Protocol};
};

// The status a refused stream open reports. PermissionDenied is the exit's
// policy and ResourceExhausted a bound. A destination whose name did not
// resolve, that could not be reached, did not answer or refused the
// connection is Internal, as a failed route on the direct session reports.
engine::Status status_for(circuit1::StreamReason reason) noexcept;

class ClientCircuit final : public std::enable_shared_from_this<ClientCircuit> {
public:
    using Opened = std::function<void(
        engine::Result<std::shared_ptr<engine::StreamResponder>>)>;

    // hops are the identities the routes view gives for each position, the
    // entry first. entry is a yume.circuit stream on the client's session to
    // hops[0]. Every call and callback runs on the context.
    static engine::Result<std::shared_ptr<ClientCircuit>> create(
        std::shared_ptr<providers::AsioExecutionContext> context,
        std::shared_ptr<const providers::circuit::CircuitCrypto> crypto,
        std::shared_ptr<engine::StreamResponder> entry,
        std::vector<providers::keys::CompositePublic> hops,
        ClientLimits limits);

    ClientCircuit(const ClientCircuit&) = delete;
    ClientCircuit& operator=(const ClientCircuit&) = delete;
    ~ClientCircuit();

    // Runs the handshakes with every hop in order. done runs once: success
    // when the last hop answered, otherwise the failure, with failure()
    // naming the hop.
    void build(std::function<void(engine::Status)> done) noexcept;
    // Opens a TCP stream to destination through the exit. done runs once,
    // with the stream after the exit connected or with status_for the exit's
    // reason.
    void open_stream(const ytp1::Destination& destination,
                     Opened done) noexcept;

    std::optional<CircuitFailure> failure() const noexcept;
    // How long each hop's handshake took, in hop order, as far as the build
    // got.
    std::vector<std::chrono::milliseconds> hop_times() const;
    std::size_t hops() const noexcept;
    bool ready() const noexcept;
    bool closed() const noexcept;
    std::size_t streams() const noexcept;
    // One observer, run once when the circuit ends.
    void on_closed(std::function<void()> observer) noexcept;
    void close() noexcept;

    struct State;

private:
    explicit ClientCircuit(std::shared_ptr<State> state) noexcept;
    std::shared_ptr<State> state_;
};

}  // namespace yume::runtime::circuit
