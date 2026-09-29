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
#include <string>
#include <string_view>
#include <vector>

#include "engine/route_provider.hpp"
#include "engine/session_engine.hpp"
#include "providers/asio_execution_context.hpp"
#include "runtime/circuit_client.hpp"
#include "runtime/circuit_status.hpp"
#include "runtime/native_credentials.hpp"

// The client's circuits (CLUSTER_DESIGN 6b): it fetches the routes view from
// its entry, builds circuits through routes the RouteChooser picks and opens
// every TCP stream through one of them. It never shortens a route on its
// own: when no route of the configured length can be built it proposes a
// shorter one, and only the user's acceptance or circuits.min_hops lets it
// use that length.
namespace yume::runtime {

struct CircuitPoolOptions final {
    std::size_t hops{3U};
    std::size_t min_hops{3U};
    bool plain_http_allowed{false};
    // New streams use a circuit this long after its first stream.
    std::chrono::milliseconds rotation{std::chrono::minutes(10)};
    // A circuit without streams closes after this long, except one spare.
    std::chrono::milliseconds idle{std::chrono::minutes(5)};
    // While a shorter route is in use, the configured length is tried again
    // this often.
    std::chrono::milliseconds recheck{std::chrono::minutes(5)};
    // Routes of one length tried before a shorter one is considered.
    std::size_t attempts{3U};
    std::chrono::milliseconds tick{std::chrono::seconds(30)};
    circuit::ClientLimits limits{};
};

class CircuitPool final {
public:
    using Opened = std::function<void(
        engine::Result<std::shared_ptr<engine::StreamResponder>>)>;
    using Report = std::function<void(std::string_view)>;

    // options.hops is 2 or 3 and options.min_hops 1 to hops. A circuit
    // carries at most 32 streams at once, what an exit's 8 MiB window total
    // allows, so the limits' streams_per_circuit is lowered to that. report
    // tells the user about stops, shorter routes and proposals, on the
    // context.
    static engine::Result<std::shared_ptr<CircuitPool>> create(
        std::shared_ptr<providers::AsioExecutionContext> context,
        NativeCircuitCredentials credentials, CircuitPoolOptions options,
        Report report);

    CircuitPool(const CircuitPool&) = delete;
    CircuitPool& operator=(const CircuitPool&) = delete;
    ~CircuitPool();

    // On the context: the client's current session, or null when it has
    // none. A new session's view is fetched again and earlier circuits end.
    void set_session(std::shared_ptr<engine::SessionEngine> session) noexcept;
    // On the context: opens a TCP stream to destination through a circuit,
    // or through direct_service on the session when the route in use is one
    // hop. PermissionDenied when the route needs the user's consent or the
    // stream is plain HTTP, FailedPrecondition without a session or a
    // trusted view, and the exit's reason otherwise.
    void open(const engine::RouteDestination& destination,
              std::string direct_service,
              engine::CancellationToken cancellation, Opened done) noexcept;
    CircuitPoolStatus status() const;
    // Accepts the current proposal. NotFound when id is not its id.
    engine::Status accept(std::string_view id) noexcept;
    // On the context. Ends every circuit and refuses later opens.
    void close() noexcept;

    struct State;

private:
    explicit CircuitPool(std::shared_ptr<State> state) noexcept;
    std::shared_ptr<State> state_;
};

}  // namespace yume::runtime
