/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string_view>

#include <boost/asio/basic_waitable_timer.hpp>

#include "engine/session_engine.hpp"
#include "engine/status.hpp"
#include "providers/asio_execution_context.hpp"
#include "runtime/native_client_runtime.hpp"
#include "runtime/native_endpoint.hpp"

namespace yume::runtime {

struct SessionKeeperOptions final {
    std::chrono::milliseconds reconnect_initial{1'000};
    // Also how long a session must stay up before its end resets the backoff
    // and reconnects at once. A shorter session counts as a failed attempt.
    std::chrono::milliseconds reconnect_max{30'000};
    // Progress lines such as "session authenticated". Exceptions are contained.
    std::function<void(std::string_view)> report;
    // Runs on the context after each state change, with the new status.
    // Exceptions are contained. Traffic changes do not call it.
    std::function<void(const NativeClientStatus&)> on_status;
    // Runs on the context when a session has authenticated and is published
    // as active. Exceptions are contained.
    std::function<void(const std::shared_ptr<engine::SessionEngine>&)>
        on_authenticated;
};

// Keeps one outbound session of a client endpoint up. It starts a session,
// and after a failed attempt or a session shorter than reconnect_max it waits
// with exponential backoff, doubling up to reconnect_max. A session that
// stayed up that long is replaced at once. It publishes a status snapshot
// that any thread may read. Every other call and every callback runs on the
// context.
//
// The endpoint's NativeEndpointOptions::session_ended must be session_ended()
// of this keeper, set before the endpoint is created. on_failure runs at most
// once, for a failure the keeper cannot retry, and the owner then stops
// everything, closing this keeper among the rest.
class SessionKeeper final : public std::enable_shared_from_this<SessionKeeper> {
public:
    using Failure = std::function<void(engine::Status)>;
    using SessionEnded = std::function<void(
        std::shared_ptr<engine::SessionEngine>, engine::Status)>;

    SessionKeeper(std::shared_ptr<providers::AsioExecutionContext> context,
                  SessionKeeperOptions options, Failure on_failure);
    SessionKeeper(const SessionKeeper&) = delete;
    SessionKeeper& operator=(const SessionKeeper&) = delete;
    ~SessionKeeper() noexcept;

    SessionEnded session_ended();
    void attach(std::shared_ptr<NativeEndpoint> endpoint) noexcept;
    // Makes the first attempt.
    void start() noexcept;
    // The authenticated session, or nullptr while none is active.
    std::shared_ptr<engine::SessionEngine> active_session() const noexcept;
    // Callable from any thread, including after close.
    NativeClientStatus status() const;
    // Records a failure the owner stops for, as the status's last failure.
    void record_failure(const engine::Status& failure) noexcept;
    // On the context: when the keeper is waiting to retry, starts that
    // attempt now and restarts the backoff, for an owner that learns the
    // network is back. At most one per reconnect_initial, so repeated calls
    // cannot redial faster than a first retry would. Returns whether an
    // attempt started.
    bool retry_now() noexcept;
    // Ends the loop without closing the endpoint, which its owner closes.
    void close() noexcept;

private:
    using Clock = std::chrono::steady_clock;
    using Timer = boost::asio::basic_waitable_timer<
        Clock, boost::asio::wait_traits<Clock>,
        providers::AsioExecutionContext::Executor>;

    void say(std::string_view text) noexcept;
    template <typename Change>
    void transition(Change change) noexcept;
    engine::SessionTraffic traffic_locked() const noexcept;
    void retire_counted_session() noexcept;
    void connect() noexcept;
    void on_session(
        engine::Result<std::shared_ptr<engine::SessionEngine>> result) noexcept;
    void on_session_ended(const std::shared_ptr<engine::SessionEngine>& ended,
                          const engine::Status& reason) noexcept;
    void schedule_reconnect(const engine::Status* failure = nullptr) noexcept;
    void fail(engine::Status status) noexcept;

    std::shared_ptr<providers::AsioExecutionContext> context_;
    SessionKeeperOptions options_;
    Failure on_failure_;
    Timer timer_;
    std::chrono::milliseconds backoff_;
    Clock::time_point authenticated_at_{};
    // A retry wait is pending. Each wait carries its number, so a wait that
    // retry_now() replaced does nothing when its cancellation is delivered.
    bool waiting_{false};
    std::uint64_t wait_generation_{0U};
    bool nudged_{false};
    Clock::time_point last_nudge_{};
    std::shared_ptr<NativeEndpoint> endpoint_;
    std::shared_ptr<engine::SessionEngine> session_;
    bool closing_{false};
    // Guards the published status, read from any thread by status().
    mutable std::mutex status_mutex_;
    NativeClientStatus published_;
    engine::SessionTraffic finished_traffic_;
    std::shared_ptr<engine::SessionEngine> counted_session_;
};

}  // namespace yume::runtime
