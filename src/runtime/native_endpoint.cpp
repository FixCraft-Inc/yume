/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/native_endpoint.hpp"

#include <algorithm>
#include <atomic>
#include <limits>
#include <optional>
#include <utility>

#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>

#include "runtime/accept_scheduler.hpp"
#include "runtime/native_credentials.hpp"
#include "runtime/native_egress_policy.hpp"
#include "providers/ytp1_front_door.hpp"
#include "providers/ytp1_security_provider.hpp"
#include "providers/asio_direct_route_provider.hpp"
#include "providers/direct_route_handler.hpp"
#include "ytp/security.hpp"
#include "core/stealth/cover_profile.hpp"

namespace yume::runtime {
namespace {
using namespace engine;
using namespace providers;
using Timer = boost::asio::basic_waitable_timer<
    std::chrono::steady_clock, boost::asio::wait_traits<std::chrono::steady_clock>,
    AsioExecutionContext::Executor>;

constexpr std::chrono::seconds kMaxAcceptRetryDelay{10};

template <typename T>
T require(Result<T> result) {
    if (!result.ok()) throw result.status();
    return std::move(result).take_value();
}

void require(Status status) {
    if (!status.ok()) throw std::move(status);
}

Status diagnostic(StatusCode code, std::string_view message) noexcept {
    try { return Status(code, message); }
    catch (...) { return Status(code); }
}

Status copy_status(const Status& status) noexcept {
    return diagnostic(status.code(), status.message());
}

void complete_noexcept(NativeEndpoint::Completion completion,
                       Result<std::shared_ptr<SessionEngine>> result) noexcept {
    if (!completion) return;
    try { completion(std::move(result)); } catch (...) {}
}

// Authentication chooses an identity; it never grants all advertised services.
// Both the immutable credential policy and the application's policy must pass.
class AuthorizedHandler final : public StreamHandler {
public:
    AuthorizedHandler(std::shared_ptr<StreamHandler> handler,
                      std::shared_ptr<const NativeAuthorizationPolicy> policy)
        : handler_(std::move(handler)), policy_(std::move(policy)) {}
    const ProviderDescriptor& descriptor() const noexcept override {
        return handler_->descriptor();
    }
    ServiceKind service_kind() const noexcept override { return handler_->service_kind(); }
    Status authorize(const StreamOpenContext& context) override {
        auto status = policy_->authorize(context);
        return status.ok() ? handler_->authorize(context) : std::move(status);
    }
    void on_open(StreamOpenContext context,
                 std::shared_ptr<StreamResponder> stream) override {
        handler_->on_open(std::move(context), std::move(stream));
    }
    void async_open(StreamOpenContext context,
                    std::shared_ptr<StreamResponder> stream,
                    AcceptanceCompletion completion) override {
        handler_->async_open(std::move(context), std::move(stream), std::move(completion));
    }
    void async_route(AuthorizedRouteRequest request,
                     std::shared_ptr<RouteProvider> route_provider,
                     std::shared_ptr<StreamResponder> stream,
                     AcceptanceCompletion completion) override {
        handler_->async_route(std::move(request), std::move(route_provider),
                              std::move(stream), std::move(completion));
    }
private:
    std::shared_ptr<StreamHandler> handler_;
    std::shared_ptr<const NativeAuthorizationPolicy> policy_;
};

ProviderRequirement requirement(ProviderKind kind, std::string_view id) {
    auto capabilities = mandatory_capabilities(kind);
    if (kind == ProviderKind::SecureChannel) capabilities = capabilities.with(Capability::Tls13);
    return require(ProviderRequirement::create(kind, std::string(id), 1U, capabilities));
}

SessionLimits session_limits(const config::v1::ResourceLimits& config) {
    SessionLimits limits;
    limits.max_frame_payload = config.max_frame_bytes();
    limits.max_streams = config.max_streams();
    limits.max_pending_opens = config.max_pending_opens();
    limits.max_control_messages = config.max_control_messages();
    limits.max_queued_bytes = config.max_queued_bytes();
    limits.max_stream_queued_bytes = std::min(limits.max_stream_queued_bytes,
                                              limits.max_queued_bytes);
    limits.max_packet_size = config.max_packet_bytes();
    limits.max_concurrent_rekeys = config.max_rekey_jobs();
    // Never advertise more receive credit than the configured byte budget.
    limits.initial_connection_credit = std::min(limits.initial_connection_credit,
                                                config.max_queued_bytes());
    limits.max_connection_credit = std::min(limits.max_connection_credit,
                                            config.max_queued_bytes());
    limits.initial_stream_credit = static_cast<std::uint32_t>(std::min(
        static_cast<std::size_t>(limits.initial_stream_credit), limits.max_stream_queued_bytes));
    limits.max_stream_credit = static_cast<std::uint32_t>(std::min(
        static_cast<std::size_t>(limits.max_stream_credit), limits.max_stream_queued_bytes));
    return limits;
}
}  // namespace

struct NativeEndpoint::State final : std::enable_shared_from_this<State>, AcceptScheduler::Driver {
    // The engine can stop on another thread. Reserve its delivery task before
    // publishing the session, so shutdown does not allocate an Asio handler.
    struct SessionEnd final {
        SessionEnd(std::shared_ptr<AsioExecutionContext> execution,
                   std::weak_ptr<State> endpoint, std::size_t slot, std::uint64_t version)
            : context(std::move(execution)), owner(std::move(endpoint)), index(slot), generation(version),
              delivery([](void* value) noexcept {
                  auto& notice = *static_cast<SessionEnd*>(value);
                  if (const auto endpoint_owner = notice.owner.lock())
                      endpoint_owner->ended(notice.index, notice.generation, std::move(notice.reason));
              }) {}
        std::shared_ptr<AsioExecutionContext> context;
        std::weak_ptr<State> owner;
        std::size_t index;
        std::uint64_t generation;
        Status reason;
        ControlTask delivery;
    };

    struct Slot final {
        explicit Slot(AsioExecutionContext::Executor executor) : timer(executor) {}
        Timer timer;
        std::shared_ptr<SessionBootstrap> bootstrap;
        std::shared_ptr<SessionEngine> session;
        Completion completion;
        std::uint64_t generation{0U};
        bool starting{false};
        bool timed_out{false};
        bool deadline_armed{false};
        Timer::time_point deadline{};
        // Automatic accepts settle through the scheduler, not a completion.
        AcceptScheduler::Clock::time_point armed_at{};
        std::size_t listener{0U};
        bool automatic{false};
    };

    State(std::shared_ptr<AsioExecutionContext> execution,
          EndpointRole endpoint_role, NativeEndpointOptions bounds, SessionLimits limits)
        : context(std::move(execution)), role(endpoint_role), options(std::move(bounds)),
          session_bounds(limits), close_task([](void* value) noexcept {
              static_cast<State*>(value)->close_on_context();
          }) {
        slots.reserve(options.max_sessions);
        for (std::size_t index = 0U; index < options.max_sessions; ++index)
            slots.push_back(std::make_unique<Slot>(context->executor()));
    }

    ~State() noexcept {
        // Also covers construction failing after a listener has been opened.
        for (const auto& listener : listeners) listener->close();
        if (tcp) tcp->cancel();
    }

    void request_close() noexcept {
        if (closing.exchange(true, std::memory_order_acq_rel)) return;
        context->submit(close_task, shared_from_this());
    }

    void close_on_context() noexcept {
        for (const auto& listener : listeners) listener->close();
        for (const auto& timer : retry_timers) {
            boost::system::error_code ignored;
            timer->cancel(ignored);
        }
        for (const auto& slot : slots) {
            boost::system::error_code ignored;
            slot->timer.cancel(ignored);
            if (slot->bootstrap) slot->bootstrap->cancel();
            if (slot->session) slot->session->stop(Status(StatusCode::Closed));
        }
        if (tcp) tcp->cancel();
        if (owns_route_provider) options.route_provider->cancel();
    }

    void settled(std::size_t index, std::uint64_t generation,
                 Result<std::shared_ptr<SessionEngine>> result) noexcept {
        auto& slot = *slots[index];
        if (!slot.starting || slot.generation != generation) {
            if (result.ok()) result.value()->stop(Status(StatusCode::Closed));
            return;
        }
        boost::system::error_code ignored;
        slot.timer.cancel(ignored);
        slot.starting = false;
        --pending_starts;
        auto bootstrap = std::move(slot.bootstrap);
        auto completion = std::move(slot.completion);
        // A busy executor can deliver completion before an expired timer's
        // handler. Cancellation of that handler must not turn an overrun into
        // success. Idle server accepts have no armed deadline to inspect.
        slot.timed_out = slot.timed_out ||
            (slot.deadline_armed && Timer::clock_type::now() >= slot.deadline);
        if (closing.load(std::memory_order_acquire) || slot.timed_out) {
            if (result.ok()) result.value()->stop(Status(StatusCode::Cancelled));
            result = Result<std::shared_ptr<SessionEngine>>(diagnostic(
                slot.timed_out ? StatusCode::Cancelled : StatusCode::Closed,
                slot.timed_out ? "native session start deadline expired" : "native endpoint closed"));
        }
        if (result.ok()) {
            auto status = observe_session(index, result.value());
            if (status.ok()) slot.session = result.value();
            else {
                result.value()->stop(copy_status(status));
                result = Result<std::shared_ptr<SessionEngine>>(std::move(status));
            }
        }
        if (slot.automatic) {
            accepts->settled(slot.listener, slot.armed_at, result.ok());
            return;
        }
        complete_noexcept(std::move(completion), std::move(result));
    }

    Status observe_session(std::size_t index, const std::shared_ptr<SessionEngine>& session) noexcept {
        try {
            auto notice = std::make_shared<SessionEnd>(context, weak_from_this(), index, slots[index]->generation);
            return session->notify_when_closed([notice](Status reason) noexcept {
                notice->reason = std::move(reason);
                notice->context->submit(notice->delivery, notice);
            });
        } catch (const std::bad_alloc&) {
            return Status(StatusCode::ResourceExhausted);
        } catch (...) {
            return Status(StatusCode::Internal);
        }
    }

    void ended(std::size_t index, std::uint64_t generation, Status reason) noexcept {
        auto& slot = *slots[index];
        if (slot.generation != generation || !slot.session) return;
        auto session = std::move(slot.session);
        if (options.session_ended) {
            try { options.session_ended(std::move(session), std::move(reason)); } catch (...) {}
        }
    }

    Status arm_deadline(std::size_t index, std::uint64_t generation) noexcept {
        try {
            auto& slot = *slots[index];
            const auto self = shared_from_this();
            slot.deadline = Timer::clock_type::now() + options.start_timeout;
            slot.timer.expires_at(slot.deadline);
            slot.timer.async_wait([self, index, generation](boost::system::error_code error) noexcept {
                auto& current = *self->slots[index];
                if (error || !current.starting || current.generation != generation) return;
                current.timed_out = true;
                if (current.bootstrap) current.bootstrap->cancel();
            });
            slot.deadline_armed = true;
            return Status::success();
        } catch (const std::bad_alloc&) {
            return Status(StatusCode::ResourceExhausted);
        } catch (...) {
            return Status(StatusCode::Internal);
        }
    }

    Status start(Completion completion, std::size_t listener_index) {
        context->require_context();
        if (!completion || (role == EndpointRole::Client ? listener_index != 0U
                                  : listener_index >= listeners.size()))
            return Status(StatusCode::InvalidArgument);
        if (closing.load(std::memory_order_acquire)) return Status(StatusCode::Closed);
        if (accepts && accepts->started()) return Status(StatusCode::FailedPrecondition);
        return begin_start(std::move(completion), listener_index, false, {});
    }

    // Manual starts deliver their completion. Automatic starts report to the
    // accept scheduler and carry no completion.
    Status begin_start(Completion completion, std::size_t listener_index, bool automatic,
                       AcceptScheduler::Clock::time_point armed_at) {
        if (closing.load(std::memory_order_acquire)) return Status(StatusCode::Closed);
        if (pending_starts >= options.max_pending_starts)
            return Status(StatusCode::ResourceExhausted);
        std::size_t index = 0U;
        for (; index < slots.size(); ++index)
            if (!slots[index]->starting && !slots[index]->session) break;
        if (index == slots.size()) return Status(StatusCode::ResourceExhausted);
        auto& slot = *slots[index];
        // Never wrap a generation while cancelled timer callbacks may exist.
        if (slot.generation == std::numeric_limits<std::uint64_t>::max())
            return Status(StatusCode::ResourceExhausted);
        slot.session.reset();
        slot.deadline_armed = false;
        Completion handler;
        SessionBootstrap::CarrierReady carrier_ready;
        const auto generation = ++slot.generation;
        try {
            auto bootstrap = role == EndpointRole::Client
                ? SessionBootstrap::create(graph, session_bounds)
                : SessionBootstrap::create(graph, listeners[listener_index], session_bounds);
            if (!bootstrap.ok()) return copy_status(bootstrap.status());
            const auto self = shared_from_this();
            // Prepare callback ownership before accepting the operation. The
            // server arms its deadline only after FrontDoor promotes a carrier;
            // failing to arm it then refuses startup and closes that carrier.
            handler = [self, index, generation](auto result) noexcept {
                self->settled(index, generation, std::move(result));
            };
            if (role == EndpointRole::Server) {
                carrier_ready = [self, index, generation]() noexcept {
                    const auto& current = *self->slots[index];
                    if (self->closing.load(std::memory_order_acquire) ||
                        !current.starting || current.generation != generation)
                        return Status(StatusCode::Closed);
                    return self->arm_deadline(index, generation);
                };
            } else {
                const auto armed = arm_deadline(index, generation);
                if (!armed.ok()) return armed;
            }
            slot.bootstrap = std::move(bootstrap).take_value();
            slot.completion = std::move(completion);
            slot.armed_at = armed_at;
            slot.listener = listener_index;
            slot.automatic = automatic;
            slot.starting = true;
            slot.timed_out = false;
            ++pending_starts;
        } catch (const std::bad_alloc&) {
            return Status(StatusCode::ResourceExhausted);
        } catch (...) {
            return Status(StatusCode::Internal);
        }
        auto owner = slot.bootstrap; // Completion is permitted inline.
        // Bootstrap contains failures after accepting completion and waits for
        // owned provider settlement. Only synchronous refusal permits local
        // settlement. Never translate a post-acceptance exception into refusal
        // or cancellation into early slot reuse.
        const auto status = owner->async_start({}, std::move(handler),
                                               std::move(carrier_ready));
        if (!status.ok()) settled(index, generation,
            Result<std::shared_ptr<SessionEngine>>(copy_status(status)));
        return Status::success();
    }

    Status start_accepting(NativeAcceptOptions accept, NativeEndpoint::AcceptFailure on_failure) {
        context->require_context();
        if (!accepts || !on_failure || accept.pending_per_listener == 0U ||
            accept.pending_per_listener > options.max_pending_starts / listeners.size() ||
            accept.retry_delay <= std::chrono::milliseconds::zero() ||
            accept.retry_delay > kMaxAcceptRetryDelay)
            return Status(StatusCode::InvalidArgument);
        if (closing.load(std::memory_order_acquire)) return Status(StatusCode::Closed);
        if (accepts->started() || pending_starts != 0U)
            return Status(StatusCode::FailedPrecondition);
        accept_failure = std::move(on_failure);
        auto started = accepts->start(accept.pending_per_listener, accept.retry_delay);
        if (!started.ok()) accept_failure = nullptr;
        return started;
    }

    // AcceptScheduler::Driver. Every call runs on the endpoint context.
    Status start_accept(std::size_t lane, AcceptScheduler::Clock::time_point armed_at) noexcept override {
        try {
            return begin_start({}, lane, true, armed_at);
        } catch (...) {
            return diagnostic(StatusCode::Internal, "automatic native accept could not start");
        }
    }
    bool schedule_retry(std::size_t lane, std::chrono::milliseconds delay) noexcept override {
        try {
            auto& timer = *retry_timers[lane];
            const auto self = shared_from_this();
            timer.expires_after(delay);
            // Close cancels this wait. Its handler still runs during drain and
            // then starts nothing, releasing the state it retains.
            timer.async_wait([self, lane](boost::system::error_code) noexcept {
                self->accepts->retry_due(lane);
            });
            return true;
        } catch (...) {
            return false;
        }
    }
    bool listener_stopped(std::size_t lane) const noexcept override {
        return listeners[lane]->closed();
    }
    bool owner_closing() const noexcept override {
        return closing.load(std::memory_order_acquire);
    }
    AcceptScheduler::Clock::time_point now() const noexcept override {
        return AcceptScheduler::Clock::now();
    }
    void failed(Status status) noexcept override {
        request_close();
        auto report = std::move(accept_failure);
        if (!report) return;
        try { report(std::move(status)); } catch (...) {}
    }

    std::shared_ptr<AsioExecutionContext> context;
    EndpointRole role;
    NativeEndpointOptions options;
    SessionLimits session_bounds;
    std::shared_ptr<const EngineGraph> graph;
    std::shared_ptr<AsioTcpByteChannelProvider> tcp;
    std::vector<std::shared_ptr<Ytp1FrontDoor>> listeners;
    std::vector<std::unique_ptr<Slot>> slots;
    std::vector<std::unique_ptr<Timer>> retry_timers; // One per server listener.
    std::optional<AcceptScheduler> accepts; // Servers with listeners only.
    NativeEndpoint::AcceptFailure accept_failure;
    std::size_t pending_starts{0U};
    std::atomic<bool> closing{false};
    bool owns_route_provider{false}; // Acquired only after endpoint publication can succeed.
    ControlTask close_task;
};

Result<std::shared_ptr<NativeEndpoint>> NativeEndpoint::create(
    std::shared_ptr<AsioExecutionContext> context, const config::v1::Config& config,
    const std::filesystem::path& base_directory, std::vector<NativeServiceBinding> services,
    NativeEndpointOptions options) {
    if (!context || options.max_sessions == 0U || options.max_sessions > 1024U ||
        options.max_pending_starts == 0U || options.max_pending_starts > 32U ||
        options.max_pending_starts > options.max_sessions ||
        options.start_timeout <= std::chrono::milliseconds::zero() ||
        options.start_timeout > std::chrono::minutes(5))
        return Result<std::shared_ptr<NativeEndpoint>>(Status(StatusCode::InvalidArgument));
    context->require_context();
    if (services.size() > config.services().size())
        return Result<std::shared_ptr<NativeEndpoint>>(Status(StatusCode::InvalidArgument));
    std::shared_ptr<State> state;
    try {
        const auto egress = require(NativeEgressPolicy::create(config.adapters()));
        if (options.caller_runs_socks5_adapters &&
            std::none_of(config.adapters().begin(), config.adapters().end(), [](const auto& adapter) {
                return std::holds_alternative<config::v1::Socks5Adapter>(adapter);
            }))
            throw Status(StatusCode::InvalidArgument, "no configured SOCKS5 adapter needs a caller");
        for (const auto& adapter : config.adapters()) {
            const auto* tcp = std::get_if<config::v1::DirectTcpAdapter>(&adapter);
            const auto* udp = std::get_if<config::v1::DirectUdpAdapter>(&adapter);
            if (std::holds_alternative<config::v1::Socks5Adapter>(adapter) &&
                options.caller_runs_socks5_adapters)
                continue;
            if (!tcp && !udp)
                throw Status(StatusCode::FailedPrecondition,
                    "native packet/TUN adapters are not implemented, and SOCKS5 adapters need a caller that runs them");
            if (!options.route_provider)
                throw Status(StatusCode::FailedPrecondition,
                    "direct adapters require an explicit route provider");
            const auto& name = tcp ? tcp->service() : udp->service();
            const auto kind = tcp ? ServiceKind::ByteStream : ServiceKind::PacketChannel;
            if (std::any_of(services.begin(), services.end(), [&](const auto& binding) {
                    return binding.name == name && binding.handler &&
                        binding.handler->service_kind() == kind;
                }))
                throw Status(StatusCode::InvalidArgument,
                    "direct adapter service already has a handler binding");
            auto capabilities = mandatory_capabilities(ProviderKind::StreamHandler)
                .with(tcp ? Capability::DirectTcp : Capability::DirectUdp);
            if (udp) capabilities = capabilities.with(Capability::PacketChannels);
            auto descriptor = require(ProviderDescriptor::create(
                tcp ? "yume.direct-tcp" : "yume.direct-udp",
                ProviderKind::StreamHandler, 1U, capabilities));
            // Configured destinations decide first. The application callback
            // can only refuse more.
            DirectRouteHandler::AuthorizationPolicy authorization =
                [egress, application = options.route_authorization](
                    const StreamOpenContext& context) -> Status {
                    auto status = egress->authorize_request(context);
                    if (!status.ok() || !application) return status;
                    return application(context);
                };
            services.push_back({name, require(DirectRouteHandler::create(
                std::move(descriptor), kind, std::move(authorization)))});
        }
        if (services.size() != config.services().size() ||
            (config.adapters().empty() && options.route_authorization))
            throw Status(StatusCode::InvalidArgument,
                "service bindings or route policy do not match configured adapters");
        const auto role = config.role() == config::v1::Role::Client
            ? EndpointRole::Client : EndpointRole::Server;
        const std::string_view server_name = role == EndpointRole::Client
            ? std::get<config::v1::ClientEndpoint>(config.endpoint()).host() : std::string_view{};
        auto credentials = require(load_native_credentials(config, base_directory, server_name));
        const auto limits = session_limits(config.limits());
        require(validate_session_limits(limits));
        if (limits.max_frame_payload < ytp1::kMaxAuthRecordSize)
            throw Status(StatusCode::InvalidArgument,
                "native session frame limit must fit the complete YTP/1 AUTH envelope");
        state = std::make_shared<State>(context, role, std::move(options), limits);
        std::vector<ProviderRequirement> requirements;
        requirements.push_back(requirement(ProviderKind::ByteChannel, kAsioTcpByteChannelProviderId));
        requirements.push_back(requirement(ProviderKind::SecureChannel, kYtp1Tls13SecureChannelProviderId));
        requirements.push_back(requirement(ProviderKind::FrontDoor, config::v1::kFrontDoorProvider));
        requirements.push_back(requirement(ProviderKind::Carrier, kYtp1H2CarrierProviderId));
        requirements.push_back(requirement(ProviderKind::SessionSecurity, kYtp1OpenSslSecurityProviderId));
        requirements.push_back(requirement(ProviderKind::RouteProvider, kAsioDirectRouteProviderId));
        std::vector<ServiceRequirement> service_requirements;
        std::vector<NativeServiceBinding> handlers;
        for (const auto& service : config.services()) {
            const auto kind = service.kind() == config::v1::ServiceKind::Stream
                ? ServiceKind::ByteStream : ServiceKind::PacketChannel;
            auto match = std::find_if(services.begin(), services.end(), [&](const auto& binding) {
                return binding.name == service.name() && binding.handler &&
                    binding.handler->service_kind() == kind;
            });
            if (match == services.end())
                throw Status(StatusCode::InvalidArgument, "configured service has no matching handler");
            const auto& descriptor = match->handler->descriptor();
            if (!state->options.route_provider &&
                (descriptor.capabilities().contains(Capability::DirectTcp) ||
                 descriptor.capabilities().contains(Capability::DirectUdp)))
                throw Status(StatusCode::FailedPrecondition, "destination routing requires a composed route adapter");
            service_requirements.push_back(require(ServiceRequirement::create(service.name(), kind,
                descriptor.provider_id(), descriptor.api_version(), service.max_concurrent_streams(),
                descriptor.capabilities())));
            handlers.push_back({service.name(), std::make_shared<AuthorizedHandler>(
                std::move(match->handler), credentials.authorization)});
        }
        auto suite = require(TransportSuiteDescriptor::create(std::string(config.suite().id()),
            "YTP/1", std::move(requirements), std::move(service_requirements)));
        EngineBuilder builder(role, std::move(suite));
        require(builder.register_session_security_provider_factory(credentials.security_factory));
        if (state->options.route_provider)
            require(builder.register_route_provider(state->options.route_provider));
        for (auto& handler : handlers)
            require(builder.register_stream_handler(std::move(handler.name), std::move(handler.handler)));
        if (role == EndpointRole::Client) {
            const auto& endpoint = std::get<config::v1::ClientEndpoint>(config.endpoint());
            const auto& configured_dial = endpoint.connect_address();
            if (!state->options.connection_address.empty() && configured_dial &&
                *configured_dial != state->options.connection_address)
                throw Status(StatusCode::InvalidArgument,
                    "dial address conflicts with the configured connect_address");
            const std::string& dial = !state->options.connection_address.empty()
                ? state->options.connection_address
                : configured_dial ? *configured_dial : endpoint.host();
            state->tcp = require(AsioTcpByteChannelProvider::create(context,
                dial, endpoint.port(), {}, state->options.socket_protector));
            require(builder.register_byte_channel_provider(state->tcp));
            require(builder.register_secure_channel_provider(credentials.tls_provider));
            Ytp1H2Dispatch dispatch{
                [context](std::function<void()> task) { boost::asio::post(context->executor(), std::move(task)); },
                [context](ControlTask& task, std::shared_ptr<void> owner) noexcept {
                    context->submit(task, std::move(owner));
                }};
            require(builder.register_carrier_provider(require(Ytp1H2CarrierProvider::create(context->affinity(),
                std::move(dispatch), {endpoint.host(), endpoint.port(), {}}, credentials.admission_key.bytes()))));
        }
        state->graph = require(builder.build());
        if (role == EndpointRole::Server) {
            if (!state->options.connection_address.empty() || state->options.socket_protector)
                throw Status(StatusCode::InvalidArgument);
            const auto* cover_config = std::get_if<config::v1::StaticCover>(&config.cover());
            if (!cover_config) throw Status(StatusCode::FailedPrecondition,
                "native reverse-proxy cover is not implemented");
            auto root = std::filesystem::path(cover_config->root().path());
            if (root.is_relative()) root = base_directory / root;
            auto cover = require(Ytp1CoverSite::load_directory(root));
            for (const auto& asset : cover_profile::active().assets) {
                if (cover->respond("GET", asset.path).status_code != 200)
                    throw Status(StatusCode::InvalidArgument,
                        "cover site is missing a required browser profile asset");
            }
            auto replay = std::make_shared<admission::ReplayCache>();
            const auto& endpoint = std::get<config::v1::ServerEndpoint>(config.endpoint());
            state->listeners.reserve(endpoint.listen_addresses().size());
            for (const auto& address : endpoint.listen_addresses()) {
                boost::system::error_code error;
                auto numeric = boost::asio::ip::make_address(address, error);
                if (error) throw Status(StatusCode::InvalidArgument);
                Ytp1FrontDoorConfig ingress;
                ingress.listen_endpoint = {numeric, endpoint.port()};
                ingress.limits.max_promoted_carriers = state->options.max_sessions;
                state->listeners.push_back(require(Ytp1FrontDoor::create(context, std::move(ingress),
                    credentials.tls_provider, cover, replay, credentials.admission_key.bytes())));
            }
            // Automatic accept state is allocated with the listeners, before
            // the endpoint is published.
            if (!state->listeners.empty()) {
                state->retry_timers.reserve(state->listeners.size());
                for (std::size_t index = 0U; index < state->listeners.size(); ++index)
                    state->retry_timers.push_back(std::make_unique<Timer>(context->executor()));
                state->accepts.emplace(*state, state->listeners.size());
            }
        }
        auto endpoint = std::shared_ptr<NativeEndpoint>(new NativeEndpoint(state));
        state->owns_route_provider = static_cast<bool>(state->options.route_provider);
        return Result<std::shared_ptr<NativeEndpoint>>(std::move(endpoint));
    } catch (const Status& status) {
        if (state) state->request_close();
        return Result<std::shared_ptr<NativeEndpoint>>(copy_status(status));
    } catch (const std::bad_alloc&) {
        if (state) state->request_close();
        return Result<std::shared_ptr<NativeEndpoint>>(Status(StatusCode::ResourceExhausted));
    } catch (...) {
        if (state) state->request_close();
        return Result<std::shared_ptr<NativeEndpoint>>(Status(StatusCode::Internal));
    }
}

NativeEndpoint::NativeEndpoint(std::shared_ptr<State> state) noexcept : state_(std::move(state)) {}
NativeEndpoint::~NativeEndpoint() noexcept { close(); }
Status NativeEndpoint::async_start_session(Completion completion, std::size_t listener_index) {
    return state_->start(std::move(completion), listener_index);
}
Status NativeEndpoint::start_accepting(NativeAcceptOptions accept, AcceptFailure on_failure) {
    return state_->start_accepting(accept, std::move(on_failure));
}
std::size_t NativeEndpoint::listener_count() const noexcept { return state_->listeners.size(); }
boost::asio::ip::tcp::endpoint NativeEndpoint::listener_endpoint(std::size_t index) const {
    state_->context->require_context();
    if (index >= state_->listeners.size()) throw std::out_of_range("native listener index");
    return state_->listeners[index]->local_endpoint();
}
void NativeEndpoint::close() noexcept { state_->request_close(); }

}  // namespace yume::runtime
