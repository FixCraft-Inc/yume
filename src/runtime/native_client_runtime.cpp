/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/native_client_runtime.hpp"

#include <algorithm>
#include <new>
#include <string>
#include <utility>
#include <variant>

#include <boost/asio/basic_waitable_timer.hpp>

#include "engine/session_engine.hpp"
#include "engine/stream_handler.hpp"
#include "runtime/native_endpoint.hpp"

namespace yume::runtime {
namespace {
using engine::Result;
using engine::ServiceKind;
using engine::Status;
using engine::StatusCode;
using Clock = std::chrono::steady_clock;
using Timer = boost::asio::basic_waitable_timer<
    Clock, boost::asio::wait_traits<Clock>, providers::AsioExecutionContext::Executor>;

constexpr std::chrono::seconds kSessionWatchInterval{1};

// The client offers its configured services for authenticated capability
// exchange but accepts no server-initiated OPEN.
class RefusingHandler final : public engine::StreamHandler {
public:
    RefusingHandler(engine::ProviderDescriptor descriptor, ServiceKind kind) noexcept
        : descriptor_(std::move(descriptor)), kind_(kind) {}

    const engine::ProviderDescriptor& descriptor() const noexcept override { return descriptor_; }
    ServiceKind service_kind() const noexcept override { return kind_; }
    Status authorize(const engine::StreamOpenContext&) override {
        return Status(StatusCode::FailedPrecondition,
                      "this client accepts no server-initiated streams");
    }
    void on_open(engine::StreamOpenContext,
                 std::shared_ptr<engine::StreamResponder> stream) override {
        if (stream) stream->close(Status(StatusCode::FailedPrecondition));
    }

private:
    engine::ProviderDescriptor descriptor_;
    ServiceKind kind_;
};

std::string describe(std::string_view prefix, const Status& status) {
    std::string text(prefix);
    if (!status.message().empty()) {
        text += ": ";
        text += status.message();
    }
    return text;
}

}  // namespace

struct NativeClientRuntime::State final : std::enable_shared_from_this<State> {
    State(std::shared_ptr<providers::AsioExecutionContext> execution, Report sink,
          NativeClientRuntimeOptions bounds)
        : context(std::move(execution)),
          report(std::move(sink)),
          options(bounds),
          timer(context->executor()),
          backoff(bounds.reconnect_initial) {}

    void say(std::string_view text) noexcept {
        if (!report) return;
        try {
            report(text);
        } catch (...) {
        }
    }

    std::shared_ptr<engine::SessionEngine> active_session() const noexcept {
        return session && session->state() == engine::SessionState::Active ? session : nullptr;
    }

    void connect() noexcept {
        if (closing) return;
        Status status;
        try {
            status = endpoint->async_start_session(
                [weak = weak_from_this()](Result<std::shared_ptr<engine::SessionEngine>> result) {
                    if (const auto self = weak.lock()) self->on_session(std::move(result));
                });
        } catch (const std::bad_alloc&) {
            status = Status(StatusCode::ResourceExhausted);
        } catch (...) {
            status = Status(StatusCode::Internal);
        }
        if (!status.ok()) {
            try { say(describe("session start refused", status)); } catch (...) {}
            schedule(backoff, false);
        }
    }

    void on_session(Result<std::shared_ptr<engine::SessionEngine>> result) noexcept {
        if (closing) {
            if (result.ok() && result.value()) result.value()->stop(Status(StatusCode::Closed));
            return;
        }
        if (!result.ok()) {
            try { say(describe("session failed", result.status())); } catch (...) {}
            schedule(backoff, false);
            return;
        }
        session = std::move(result).take_value();
        backoff = options.reconnect_initial;
        say("session authenticated");
        schedule(kSessionWatchInterval, true);
    }

    // Watching polls the session state. Reconnecting doubles the delay up to
    // the configured maximum.
    void schedule(std::chrono::milliseconds delay, bool watching) noexcept {
        if (closing) return;
        if (!watching) backoff = std::min(backoff * 2, options.reconnect_max);
        try {
            timer.expires_after(delay);
            timer.async_wait([weak = weak_from_this(), watching](const boost::system::error_code& error) {
                const auto self = weak.lock();
                if (!self || error || self->closing) return;
                if (!watching) {
                    self->connect();
                    return;
                }
                if (self->active_session()) {
                    self->schedule(kSessionWatchInterval, true);
                    return;
                }
                self->session.reset();
                self->say("session ended, reconnecting");
                self->connect();
            });
        } catch (...) {
            say("session timer unavailable, stopping");
            close();
        }
    }

    void close() noexcept {
        if (closing) return;
        closing = true;
        boost::system::error_code ignored;
        timer.cancel(ignored);
        for (const auto& adapter : adapters) adapter->close();
        if (endpoint) endpoint->close();
        session.reset();
    }

    std::shared_ptr<providers::AsioExecutionContext> context;
    Report report;
    NativeClientRuntimeOptions options;
    Timer timer;
    std::chrono::milliseconds backoff;
    std::shared_ptr<NativeEndpoint> endpoint;
    std::vector<config::v1::Socks5Adapter> socks5;
    std::vector<std::shared_ptr<NativeSocks5Adapter>> adapters;
    std::shared_ptr<engine::SessionEngine> session;
    bool started{false};
    bool closing{false};
};

engine::Result<std::shared_ptr<NativeClientRuntime>> NativeClientRuntime::create(
    std::shared_ptr<providers::AsioExecutionContext> context,
    const config::v1::Config& config,
    const std::filesystem::path& config_base_directory,
    Report report,
    NativeClientRuntimeOptions options) {
    using Created = engine::Result<std::shared_ptr<NativeClientRuntime>>;
    if (!context || config.role() != config::v1::Role::Client ||
        options.reconnect_initial <= std::chrono::milliseconds::zero() ||
        options.reconnect_max < options.reconnect_initial) {
        return Created(Status(StatusCode::InvalidArgument, "a client configuration is required"));
    }
    context->require_context();
    try {
        auto state = std::make_shared<State>(context, std::move(report), options);
        std::vector<NativeServiceBinding> bindings;
        for (const auto& service : config.services()) {
            const bool packet = service.kind() == config::v1::ServiceKind::Packet;
            auto capabilities = engine::mandatory_capabilities(engine::ProviderKind::StreamHandler);
            if (packet) capabilities = capabilities.with(engine::Capability::PacketChannels);
            auto descriptor = engine::ProviderDescriptor::create(
                "yume.client-refuse", engine::ProviderKind::StreamHandler, 1U, capabilities);
            if (!descriptor.ok()) return Created(descriptor.status());
            bindings.push_back({service.name(), std::make_shared<RefusingHandler>(
                std::move(descriptor).take_value(),
                packet ? ServiceKind::PacketChannel : ServiceKind::ByteStream)});
        }
        for (const auto& adapter : config.adapters()) {
            if (const auto* socks = std::get_if<config::v1::Socks5Adapter>(&adapter)) {
                state->socks5.push_back(*socks);
            }
        }
        NativeEndpointOptions endpoint_options;
        endpoint_options.max_sessions = 1U;
        endpoint_options.max_pending_starts = 1U;
        endpoint_options.start_timeout = options.start_timeout;
        endpoint_options.caller_runs_socks5_adapters = !state->socks5.empty();
        auto endpoint = NativeEndpoint::create(context, config, config_base_directory,
                                               std::move(bindings), std::move(endpoint_options));
        if (!endpoint.ok()) return Created(endpoint.status());
        state->endpoint = std::move(endpoint).take_value();
        return Created(std::shared_ptr<NativeClientRuntime>(new NativeClientRuntime(std::move(state))));
    } catch (const std::bad_alloc&) {
        return Created(Status(StatusCode::ResourceExhausted));
    }
}

NativeClientRuntime::NativeClientRuntime(std::shared_ptr<State> state) noexcept
    : state_(std::move(state)) {}

NativeClientRuntime::~NativeClientRuntime() noexcept { close(); }

engine::Status NativeClientRuntime::start() {
    state_->context->require_context();
    if (state_->started || state_->closing) return Status(StatusCode::FailedPrecondition);
    state_->started = true;
    try {
        for (const auto& adapter : state_->socks5) {
            auto created = NativeSocks5Adapter::create(
                state_->context, adapter,
                [weak = std::weak_ptr<State>(state_)]() -> std::shared_ptr<engine::SessionEngine> {
                    const auto self = weak.lock();
                    return self ? self->active_session() : nullptr;
                },
                state_->options.socks5);
            if (!created.ok()) {
                state_->close();
                return created.status();
            }
            state_->adapters.push_back(std::move(created).take_value());
        }
    } catch (const std::bad_alloc&) {
        state_->close();
        return Status(StatusCode::ResourceExhausted);
    }
    state_->connect();
    return Status::success();
}

std::vector<boost::asio::ip::tcp::endpoint> NativeClientRuntime::socks5_endpoints() const {
    std::vector<boost::asio::ip::tcp::endpoint> endpoints;
    for (const auto& adapter : state_->adapters) endpoints.push_back(adapter->local_endpoint());
    return endpoints;
}

void NativeClientRuntime::close() noexcept { state_->close(); }

}  // namespace yume::runtime
