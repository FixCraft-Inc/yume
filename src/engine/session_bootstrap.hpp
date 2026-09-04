/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <functional>
#include <memory>

#include "engine/front_door.hpp"
#include "engine/session_engine.hpp"

namespace yume::engine {

enum class SessionBootstrapState : std::uint8_t {
    Created,
    AcquiringByteChannel,
    SecuringByteChannel,
    AcceptingCarrier,
    CreatingCarrier,
    CreatingSession,
    StartingSession,
    Succeeded,
    Cancelled,
    Failed,
};

// One bootstrap object performs exactly one YTP/1 session startup. The client
// path consumes ByteChannel -> SecureChannel -> Carrier providers from its
// frozen EngineGraph. The server path borrows a shared, persistent FrontDoor;
// one successful accept transfers a ready Carrier whose HTTP/2/admission state
// is already intact. A server bootstrap never cancels or closes the FrontDoor.
//
// Each accepted provider operation owns its input until its one completion.
// Cancellation requests the operation's token and waits for that completion
// before reporting terminal failure, so a returned late object is closed before
// the user's completion. Affinity is established by the client ByteChannel or
// the server FrontDoor and every later layer must match it exactly. Bootstrap
// does not redispatch callbacks: a successful completion runs from
// SessionEngine's start completion on that affinity.
class SessionBootstrap final
    : public std::enable_shared_from_this<SessionBootstrap> {
public:
    using Completion =
        std::function<void(Result<std::shared_ptr<SessionEngine>>)>;

    // Client form. A server graph is rejected before any provider is called.
    static Result<std::shared_ptr<SessionBootstrap>> create(
        std::shared_ptr<const EngineGraph> graph,
        SessionLimits limits = {});

    // Server form. The caller keeps shared ownership of a reusable FrontDoor;
    // this bootstrap retains it only until one accept settles.
    static Result<std::shared_ptr<SessionBootstrap>> create(
        std::shared_ptr<const EngineGraph> graph,
        std::shared_ptr<FrontDoor> front_door,
        SessionLimits limits = {});

    SessionBootstrap(const SessionBootstrap&) = delete;
    SessionBootstrap& operator=(const SessionBootstrap&) = delete;
    ~SessionBootstrap() noexcept;

    SessionBootstrapState state() const noexcept;
    ExecutorAffinity executor_affinity() const noexcept;

    // Returns only synchronous admission errors. Once accepted, completion is
    // delivered exactly once with an Active SessionEngine or terminal status.
    // Providers may complete inline; callers must permit callback re-entry.
    Status async_start(CancellationToken cancellation,
                       Completion completion);

    // Idempotent. An in-flight provider operation is allowed to settle on its
    // declared executor before the terminal completion is delivered.
    void cancel() noexcept;

private:
    class Impl;
    explicit SessionBootstrap(std::unique_ptr<Impl> impl) noexcept;

    std::unique_ptr<Impl> impl_;
};

}  // namespace yume::engine
