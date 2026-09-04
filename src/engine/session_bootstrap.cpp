/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "engine/session_bootstrap.hpp"

#include <mutex>
#include <new>
#include <optional>
#include <utility>

namespace yume::engine {
namespace {

bool terminal_state(SessionBootstrapState state) noexcept {
    return state == SessionBootstrapState::Succeeded ||
           state == SessionBootstrapState::Cancelled ||
           state == SessionBootstrapState::Failed;
}

void invoke_noexcept(
    SessionBootstrap::Completion& completion,
    Result<std::shared_ptr<SessionEngine>> result) noexcept {
    if (!completion) {
        return;
    }
    try {
        completion(std::move(result));
    } catch (...) {
        // The bootstrap is a provider/user callback containment boundary. Its
        // state and ownership are settled before invoking unknown code.
    }
}

template <typename Transport>
void close_transport(std::unique_ptr<Transport> transport) noexcept {
    if (!transport) {
        return;
    }
    try {
        transport->cancel();
    } catch (...) {
    }
    try {
        transport->close();
    } catch (...) {
    }
}

void close_accepted_carrier(AcceptedCarrier accepted) noexcept {
    close_transport(std::move(accepted).take_carrier());
}

Status validate_graph(const std::shared_ptr<const EngineGraph>& graph,
                      EndpointRole expected_role) {
    if (!graph) {
        return Status(StatusCode::InvalidArgument,
                      "session bootstrap requires a frozen engine graph");
    }
    if (graph->local_role() != expected_role) {
        return Status(StatusCode::InvalidArgument,
                      "session bootstrap form does not match graph role");
    }
    if (graph->suite().wire_protocol() != "YTP/1") {
        return Status(StatusCode::ProviderMismatch,
                      "session bootstrap requires an exact YTP/1 graph");
    }
    if (!graph->carrier_provider() ||
        !graph->session_security_provider_factory()) {
        return Status(StatusCode::FailedPrecondition,
                      "session bootstrap graph is incomplete");
    }
    if (expected_role == EndpointRole::Client &&
        (!graph->byte_channel_provider() ||
         !graph->secure_channel_provider())) {
        return Status(StatusCode::FailedPrecondition,
                      "client bootstrap graph lacks transport providers");
    }
    if (!graph->suite().provider_requirement(ProviderKind::Carrier)) {
        return Status(StatusCode::FailedPrecondition,
                      "session bootstrap graph lacks a carrier requirement");
    }
    const ProviderRequirement* secure_requirement =
        graph->suite().provider_requirement(ProviderKind::SecureChannel);
    if (!secure_requirement ||
        !secure_requirement->required_capabilities().contains(
            Capability::Tls13)) {
        return Status(StatusCode::ProviderMismatch,
                      "YTP/1 bootstrap requires an exact TLS 1.3 secure channel");
    }
    return Status::success();
}

Status validate_accepted_carrier(
    const EngineGraph& graph,
    const ProviderDescriptor& descriptor) {
    const ProviderRequirement* requirement =
        graph.suite().provider_requirement(ProviderKind::Carrier);
    if (!requirement) {
        return Status(StatusCode::FailedPrecondition,
                      "engine graph lacks its carrier requirement");
    }
    if (descriptor.kind() != ProviderKind::Carrier ||
        descriptor.provider_id() != requirement->provider_id() ||
        descriptor.api_version() != requirement->api_version()) {
        return Status(StatusCode::ProviderMismatch,
                      "front door promoted the wrong carrier provider");
    }
    if (!descriptor.capabilities().contains_all(
            requirement->required_capabilities())) {
        return Status(StatusCode::FailedPrecondition,
                      "promoted carrier lacks required suite capabilities");
    }
    return Status::success();
}

}  // namespace

class SessionBootstrap::Impl final {
public:
    Impl(std::shared_ptr<const EngineGraph> graph,
         std::shared_ptr<FrontDoor> front_door,
         SessionLimits limits) noexcept
        : graph_(std::move(graph)),
          front_door_(std::move(front_door)),
          limits_(limits) {
        if (front_door_) {
            affinity_ = front_door_->executor_affinity();
        }
    }

    ~Impl() noexcept {
        external_cancellation_.unregister();
        cancellation_.cancel();
        if (starting_engine_) {
            try {
                starting_engine_->stop(
                    Status(StatusCode::Closed,
                           "session bootstrap destroyed"));
            } catch (...) {
            }
        }
    }

    void bind(SessionBootstrap* owner) noexcept { owner_ = owner; }

    SessionBootstrapState state() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return state_;
    }

    ExecutorAffinity executor_affinity() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return affinity_;
    }

    Status async_start(CancellationToken external,
                       Completion completion) {
        if (!completion) {
            return Status(StatusCode::InvalidArgument,
                          "session bootstrap completion must not be empty");
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (state_ != SessionBootstrapState::Created) {
                return Status(StatusCode::FailedPrecondition,
                              "session bootstrap starts exactly once");
            }
            completion_ = std::move(completion);
            state_ = graph_->local_role() == EndpointRole::Client
                ? SessionBootstrapState::AcquiringByteChannel
                : SessionBootstrapState::AcceptingCarrier;
        }

        Result<CancellationRegistration> registration(Status(
            StatusCode::Internal,
            "external cancellation registration did not run"));
        try {
            std::weak_ptr<SessionBootstrap> weak =
                owner_->shared_from_this();
            registration = external.register_callback([weak]() noexcept {
                if (const auto bootstrap = weak.lock()) {
                    bootstrap->cancel();
                }
            });
        } catch (const std::bad_alloc&) {
            finish_failure(Status(
                StatusCode::ResourceExhausted,
                "bootstrap cancellation registration allocation failed"));
            return Status::success();
        } catch (...) {
            finish_failure(Status(
                StatusCode::Internal,
                "bootstrap cancellation registration failed"));
            return Status::success();
        }
        if (!registration.ok()) {
            finish_failure(registration.status());
            return Status::success();
        }

        bool stopped = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!terminal_state(state_)) {
                external_cancellation_ =
                    std::move(registration).take_value();
                stopped = stop_reason_.has_value();
            }
        }
        if (terminal_state(state())) {
            return Status::success();
        }
        if (stopped) {
            finish_failure(Status(StatusCode::Cancelled,
                                  "session bootstrap cancelled"));
            return Status::success();
        }

        if (graph_->local_role() == EndpointRole::Client) {
            begin_byte_channel();
        } else {
            begin_front_door_accept();
        }
        return Status::success();
    }

    void cancel() noexcept {
        std::shared_ptr<SessionEngine> engine;
        bool created = false;
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            if (terminal_state(state_)) {
                return;
            }
            if (state_ == SessionBootstrapState::Created) {
                state_ = SessionBootstrapState::Cancelled;
                created = true;
            } else if (!stop_reason_.has_value()) {
                stop_reason_.emplace(
                    StatusCode::Cancelled,
                    "session bootstrap cancelled");
            }
            engine = starting_engine_;
        } catch (...) {
            // The ordinary cancellation status is deliberately short and uses
            // bounded Status storage. If even that allocation fails, the
            // internal token still tears down the active provider operation.
        }
        cancellation_.cancel();
        if (engine) {
            try {
                engine->stop(Status(StatusCode::Cancelled,
                                    "session bootstrap cancelled"));
            } catch (...) {
            }
        }
        (void)created;
    }

private:
    bool callback_expected(SessionBootstrapState expected) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return state_ == expected && !terminal_state(state_);
    }

    std::optional<Status> requested_stop() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return stop_reason_;
    }

    void request_failure(Status status) noexcept {
        std::shared_ptr<SessionEngine> engine;
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            if (terminal_state(state_)) {
                return;
            }
            if (!stop_reason_.has_value()) {
                stop_reason_.emplace(std::move(status));
            }
            engine = starting_engine_;
        } catch (...) {
        }
        cancellation_.cancel();
        if (engine) {
            try {
                engine->stop(Status(StatusCode::Internal,
                                    "session bootstrap provider failed"));
            } catch (...) {
            }
        }
    }

    void finish_failure(Status fallback) noexcept {
        Completion completion;
        CancellationRegistration external_registration;
        std::shared_ptr<SessionEngine> engine;
        Status reason = std::move(fallback);
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            if (terminal_state(state_)) {
                return;
            }
            if (stop_reason_.has_value()) {
                reason = *stop_reason_;
            }
            state_ = reason.code() == StatusCode::Cancelled
                ? SessionBootstrapState::Cancelled
                : SessionBootstrapState::Failed;
            completion = std::move(completion_);
            external_registration = std::move(external_cancellation_);
            engine = std::move(starting_engine_);
            front_door_.reset();
        } catch (...) {
            // No exception may escape a provider callback. Cancellation below
            // still prevents partially constructed transport from continuing.
        }

        external_registration.unregister();
        cancellation_.cancel();
        if (engine) {
            try {
                engine->stop(Status(reason.code(), reason.message()));
            } catch (...) {
            }
        }
        invoke_noexcept(completion,
                        Result<std::shared_ptr<SessionEngine>>(
                            std::move(reason)));
    }

    void handle_invocation_failure(SessionBootstrapState expected,
                                   Status status) noexcept {
        if (callback_expected(expected)) {
            finish_failure(std::move(status));
            return;
        }
        request_failure(std::move(status));
    }

    void unexpected_callback() noexcept {
        request_failure(Status(
            StatusCode::ProviderMismatch,
            "provider completed a bootstrap layer more than once or out of order"));
    }

    void begin_byte_channel() noexcept {
        const auto provider = graph_->byte_channel_provider();
        const auto self = owner_->shared_from_this();
        try {
            provider->async_create(
                EndpointRole::Client, cancellation_.token(),
                [self](Result<std::unique_ptr<ByteChannel>> result) mutable {
                    try {
                        self->impl_->on_byte_channel(std::move(result));
                    } catch (const std::bad_alloc&) {
                        self->impl_->request_failure(Status(
                            StatusCode::ResourceExhausted,
                            "byte-channel bootstrap callback allocation failed"));
                    } catch (...) {
                        self->impl_->request_failure(Status(
                            StatusCode::Internal,
                            "byte-channel bootstrap callback failed"));
                    }
                });
        } catch (const std::bad_alloc&) {
            handle_invocation_failure(
                SessionBootstrapState::AcquiringByteChannel,
                Status(StatusCode::ResourceExhausted,
                       "byte-channel provider allocation failed"));
        } catch (...) {
            handle_invocation_failure(
                SessionBootstrapState::AcquiringByteChannel,
                Status(StatusCode::Internal,
                       "byte-channel provider threw"));
        }
    }

    void on_byte_channel(
        Result<std::unique_ptr<ByteChannel>> result) {
        if (!callback_expected(
                SessionBootstrapState::AcquiringByteChannel)) {
            if (result.ok()) {
                close_transport(std::move(result).take_value());
            }
            unexpected_callback();
            return;
        }
        if (const auto stopped = requested_stop()) {
            if (result.ok()) {
                close_transport(std::move(result).take_value());
            }
            finish_failure(*stopped);
            return;
        }
        if (!result.ok()) {
            finish_failure(result.status());
            return;
        }
        std::unique_ptr<ByteChannel> channel =
            std::move(result).take_value();
        if (!channel || !channel->executor_affinity().valid()) {
            close_transport(std::move(channel));
            finish_failure(Status(
                StatusCode::ProviderMismatch,
                "byte-channel provider returned an invalid channel"));
            return;
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            affinity_ = channel->executor_affinity();
            state_ = SessionBootstrapState::SecuringByteChannel;
        }
        begin_secure_channel(std::move(channel));
    }

    void begin_secure_channel(
        std::unique_ptr<ByteChannel> channel) noexcept {
        const auto provider = graph_->secure_channel_provider();
        const auto self = owner_->shared_from_this();
        try {
            provider->async_wrap(
                std::move(channel), EndpointRole::Client,
                cancellation_.token(),
                [self](Result<std::unique_ptr<SecureChannel>> result) mutable {
                    try {
                        self->impl_->on_secure_channel(std::move(result));
                    } catch (const std::bad_alloc&) {
                        self->impl_->request_failure(Status(
                            StatusCode::ResourceExhausted,
                            "secure-channel bootstrap callback allocation failed"));
                    } catch (...) {
                        self->impl_->request_failure(Status(
                            StatusCode::Internal,
                            "secure-channel bootstrap callback failed"));
                    }
                });
        } catch (const std::bad_alloc&) {
            handle_invocation_failure(
                SessionBootstrapState::SecuringByteChannel,
                Status(StatusCode::ResourceExhausted,
                       "secure-channel provider allocation failed"));
        } catch (...) {
            handle_invocation_failure(
                SessionBootstrapState::SecuringByteChannel,
                Status(StatusCode::Internal,
                       "secure-channel provider threw"));
        }
    }

    void on_secure_channel(
        Result<std::unique_ptr<SecureChannel>> result) {
        if (!callback_expected(
                SessionBootstrapState::SecuringByteChannel)) {
            if (result.ok()) {
                close_transport(std::move(result).take_value());
            }
            unexpected_callback();
            return;
        }
        if (const auto stopped = requested_stop()) {
            if (result.ok()) {
                close_transport(std::move(result).take_value());
            }
            finish_failure(*stopped);
            return;
        }
        if (!result.ok()) {
            finish_failure(result.status());
            return;
        }
        std::unique_ptr<SecureChannel> channel =
            std::move(result).take_value();
        if (!channel || channel->executor_affinity() != affinity_) {
            close_transport(std::move(channel));
            finish_failure(Status(
                StatusCode::ProviderMismatch,
                "secure channel changed bootstrap executor affinity"));
            return;
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            state_ = SessionBootstrapState::CreatingCarrier;
        }
        begin_client_carrier(std::move(channel));
    }

    void begin_client_carrier(
        std::unique_ptr<SecureChannel> channel) noexcept {
        const auto provider = graph_->carrier_provider();
        const auto self = owner_->shared_from_this();
        try {
            provider->async_create(
                std::move(channel), EndpointRole::Client,
                cancellation_.token(),
                [self](Result<std::unique_ptr<Carrier>> result) mutable {
                    try {
                        self->impl_->on_client_carrier(std::move(result));
                    } catch (const std::bad_alloc&) {
                        self->impl_->request_failure(Status(
                            StatusCode::ResourceExhausted,
                            "carrier bootstrap callback allocation failed"));
                    } catch (...) {
                        self->impl_->request_failure(Status(
                            StatusCode::Internal,
                            "carrier bootstrap callback failed"));
                    }
                });
        } catch (const std::bad_alloc&) {
            handle_invocation_failure(
                SessionBootstrapState::CreatingCarrier,
                Status(StatusCode::ResourceExhausted,
                       "carrier provider allocation failed"));
        } catch (...) {
            handle_invocation_failure(
                SessionBootstrapState::CreatingCarrier,
                Status(StatusCode::Internal,
                       "carrier provider threw"));
        }
    }

    void on_client_carrier(
        Result<std::unique_ptr<Carrier>> result) {
        if (!callback_expected(SessionBootstrapState::CreatingCarrier)) {
            if (result.ok()) {
                close_transport(std::move(result).take_value());
            }
            unexpected_callback();
            return;
        }
        if (const auto stopped = requested_stop()) {
            if (result.ok()) {
                close_transport(std::move(result).take_value());
            }
            finish_failure(*stopped);
            return;
        }
        if (!result.ok()) {
            finish_failure(result.status());
            return;
        }
        std::unique_ptr<Carrier> carrier =
            std::move(result).take_value();
        if (!carrier || carrier->executor_affinity() != affinity_ ||
            carrier->secure_channel().executor_affinity() != affinity_) {
            close_transport(std::move(carrier));
            finish_failure(Status(
                StatusCode::ProviderMismatch,
                "carrier changed bootstrap executor affinity"));
            return;
        }
        create_session(std::move(carrier));
    }

    void begin_front_door_accept() noexcept {
        const auto front_door = front_door_;
        const auto self = owner_->shared_from_this();
        try {
            front_door->async_accept(
                cancellation_.token(),
                [self](Result<AcceptedCarrier> result) mutable {
                    try {
                        self->impl_->on_accepted_carrier(std::move(result));
                    } catch (const std::bad_alloc&) {
                        self->impl_->request_failure(Status(
                            StatusCode::ResourceExhausted,
                            "front-door bootstrap callback allocation failed"));
                    } catch (...) {
                        self->impl_->request_failure(Status(
                            StatusCode::Internal,
                            "front-door bootstrap callback failed"));
                    }
                });
        } catch (const std::bad_alloc&) {
            handle_invocation_failure(
                SessionBootstrapState::AcceptingCarrier,
                Status(StatusCode::ResourceExhausted,
                       "front-door provider allocation failed"));
        } catch (...) {
            handle_invocation_failure(
                SessionBootstrapState::AcceptingCarrier,
                Status(StatusCode::Internal,
                       "front door threw while accepting"));
        }
    }

    void on_accepted_carrier(Result<AcceptedCarrier> result) {
        if (!callback_expected(SessionBootstrapState::AcceptingCarrier)) {
            if (result.ok()) {
                close_accepted_carrier(std::move(result).take_value());
            }
            unexpected_callback();
            return;
        }
        if (const auto stopped = requested_stop()) {
            if (result.ok()) {
                close_accepted_carrier(std::move(result).take_value());
            }
            finish_failure(*stopped);
            return;
        }
        if (!result.ok()) {
            finish_failure(result.status());
            return;
        }
        AcceptedCarrier accepted = std::move(result).take_value();
        const Status provenance = validate_accepted_carrier(
            *graph_, accepted.descriptor());
        if (!provenance.ok()) {
            close_accepted_carrier(std::move(accepted));
            finish_failure(provenance);
            return;
        }
        if (accepted.carrier().executor_affinity() != affinity_ ||
            accepted.carrier().secure_channel().executor_affinity() !=
                affinity_) {
            close_accepted_carrier(std::move(accepted));
            finish_failure(Status(
                StatusCode::ProviderMismatch,
                "front door changed bootstrap executor affinity"));
            return;
        }
        create_session(std::move(accepted).take_carrier());
    }

    void create_session(std::unique_ptr<Carrier> carrier) noexcept {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            state_ = SessionBootstrapState::CreatingSession;
        }

        Result<std::shared_ptr<SessionEngine>> created(Status(
            StatusCode::Internal,
            "session engine construction did not run"));
        try {
            created = SessionEngine::create(
                graph_, std::move(carrier), limits_);
        } catch (const std::bad_alloc&) {
            created = Result<std::shared_ptr<SessionEngine>>(Status(
                StatusCode::ResourceExhausted,
                "session engine bootstrap allocation failed"));
        } catch (...) {
            created = Result<std::shared_ptr<SessionEngine>>(Status(
                StatusCode::Internal,
                "session engine bootstrap construction failed"));
        }

        if (const auto stopped = requested_stop()) {
            if (created.ok()) {
                const auto engine = std::move(created).take_value();
                engine->stop(Status(stopped->code(), stopped->message()));
            }
            finish_failure(*stopped);
            return;
        }
        if (!created.ok()) {
            finish_failure(created.status());
            return;
        }
        std::shared_ptr<SessionEngine> engine =
            std::move(created).take_value();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            starting_engine_ = engine;
            state_ = SessionBootstrapState::StartingSession;
        }
        if (const auto stopped = requested_stop()) {
            finish_failure(*stopped);
            return;
        }

        const auto self = owner_->shared_from_this();
        try {
            engine->async_start([self](Status status) mutable {
                try {
                    self->impl_->on_session_started(std::move(status));
                } catch (const std::bad_alloc&) {
                    self->impl_->request_failure(Status(
                        StatusCode::ResourceExhausted,
                        "session-start bootstrap callback allocation failed"));
                } catch (...) {
                    self->impl_->request_failure(Status(
                        StatusCode::Internal,
                        "session-start bootstrap callback failed"));
                }
            });
        } catch (const std::bad_alloc&) {
            handle_invocation_failure(
                SessionBootstrapState::StartingSession,
                Status(StatusCode::ResourceExhausted,
                       "session start allocation failed"));
        } catch (...) {
            handle_invocation_failure(
                SessionBootstrapState::StartingSession,
                Status(StatusCode::Internal,
                       "session start threw"));
        }
    }

    void on_session_started(Status status) noexcept {
        if (!callback_expected(SessionBootstrapState::StartingSession)) {
            unexpected_callback();
            return;
        }
        if (const auto stopped = requested_stop()) {
            finish_failure(*stopped);
            return;
        }
        if (!status.ok()) {
            finish_failure(std::move(status));
            return;
        }

        Completion completion;
        CancellationRegistration external_registration;
        std::shared_ptr<SessionEngine> engine;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stop_reason_.has_value()) {
                // Cancellation won the race after the start callback entered.
            } else if (starting_engine_ &&
                       starting_engine_->state() == SessionState::Active) {
                state_ = SessionBootstrapState::Succeeded;
                completion = std::move(completion_);
                external_registration =
                    std::move(external_cancellation_);
                engine = std::move(starting_engine_);
                front_door_.reset();
            }
        }
        if (!engine) {
            if (const auto stopped = requested_stop()) {
                finish_failure(*stopped);
            } else {
                finish_failure(Status(
                    StatusCode::ProviderMismatch,
                    "session start succeeded without an active engine"));
            }
            return;
        }

        external_registration.unregister();
        invoke_noexcept(completion,
                        Result<std::shared_ptr<SessionEngine>>(
                            std::move(engine)));
    }

    SessionBootstrap* owner_{nullptr};
    std::shared_ptr<const EngineGraph> graph_;
    std::shared_ptr<FrontDoor> front_door_;
    SessionLimits limits_;

    mutable std::mutex mutex_;
    SessionBootstrapState state_{SessionBootstrapState::Created};
    ExecutorAffinity affinity_;
    std::optional<Status> stop_reason_;
    Completion completion_;
    CancellationRegistration external_cancellation_;
    CancellationSource cancellation_;
    std::shared_ptr<SessionEngine> starting_engine_;
};

Result<std::shared_ptr<SessionBootstrap>> SessionBootstrap::create(
    std::shared_ptr<const EngineGraph> graph,
    SessionLimits limits) {
    const Status validation = validate_graph(graph, EndpointRole::Client);
    if (!validation.ok()) {
        return Result<std::shared_ptr<SessionBootstrap>>(validation);
    }
    try {
        auto impl = std::make_unique<Impl>(
            std::move(graph), std::shared_ptr<FrontDoor>{}, limits);
        auto bootstrap = std::shared_ptr<SessionBootstrap>(
            new SessionBootstrap(std::move(impl)));
        bootstrap->impl_->bind(bootstrap.get());
        return Result<std::shared_ptr<SessionBootstrap>>(
            std::move(bootstrap));
    } catch (const std::bad_alloc&) {
        return Result<std::shared_ptr<SessionBootstrap>>(Status(
            StatusCode::ResourceExhausted,
            "client session bootstrap allocation failed"));
    } catch (...) {
        return Result<std::shared_ptr<SessionBootstrap>>(Status(
            StatusCode::Internal,
            "client session bootstrap construction failed"));
    }
}

Result<std::shared_ptr<SessionBootstrap>> SessionBootstrap::create(
    std::shared_ptr<const EngineGraph> graph,
    std::shared_ptr<FrontDoor> front_door,
    SessionLimits limits) {
    const Status validation = validate_graph(graph, EndpointRole::Server);
    if (!validation.ok()) {
        return Result<std::shared_ptr<SessionBootstrap>>(validation);
    }
    if (!front_door) {
        return Result<std::shared_ptr<SessionBootstrap>>(Status(
            StatusCode::InvalidArgument,
            "server session bootstrap requires a front door"));
    }
    if (!front_door->executor_affinity().valid()) {
        return Result<std::shared_ptr<SessionBootstrap>>(Status(
            StatusCode::ProviderMismatch,
            "server front door has no executor affinity"));
    }
    try {
        auto impl = std::make_unique<Impl>(
            std::move(graph), std::move(front_door), limits);
        auto bootstrap = std::shared_ptr<SessionBootstrap>(
            new SessionBootstrap(std::move(impl)));
        bootstrap->impl_->bind(bootstrap.get());
        return Result<std::shared_ptr<SessionBootstrap>>(
            std::move(bootstrap));
    } catch (const std::bad_alloc&) {
        return Result<std::shared_ptr<SessionBootstrap>>(Status(
            StatusCode::ResourceExhausted,
            "server session bootstrap allocation failed"));
    } catch (...) {
        return Result<std::shared_ptr<SessionBootstrap>>(Status(
            StatusCode::Internal,
            "server session bootstrap construction failed"));
    }
}

SessionBootstrap::SessionBootstrap(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

SessionBootstrap::~SessionBootstrap() noexcept = default;

SessionBootstrapState SessionBootstrap::state() const noexcept {
    return impl_->state();
}

ExecutorAffinity SessionBootstrap::executor_affinity() const noexcept {
    return impl_->executor_affinity();
}

Status SessionBootstrap::async_start(CancellationToken cancellation,
                                     Completion completion) {
    return impl_->async_start(std::move(cancellation),
                              std::move(completion));
}

void SessionBootstrap::cancel() noexcept {
    impl_->cancel();
}

}  // namespace yume::engine
