/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "engine/engine_builder.hpp"

#include "engine/session_engine.hpp"

#include <algorithm>
#include <mutex>
#include <new>
#include <type_traits>
#include <utility>

namespace yume::engine {
namespace {

Status frozen_status() {
    return Status(StatusCode::FailedPrecondition,
                  "engine builder is frozen");
}

template <typename Provider>
Status validate_registration(
    const std::shared_ptr<Provider>& provider,
    ProviderKind expected_kind) {
    if (!provider) {
        return Status(StatusCode::InvalidArgument,
                      "provider must not be null");
    }
    const ProviderDescriptor& descriptor = provider->descriptor();
    if (descriptor.kind() != expected_kind) {
        return Status(StatusCode::ProviderMismatch,
                      "provider kind does not match its registration slot");
    }
    return Status::success();
}

template <typename Map>
Result<typename Map::mapped_type> select_exact_provider(
    const ProviderRequirement& requirement,
    const Map& providers) {
    const auto it = providers.find(requirement.provider_id());
    if (it == providers.end()) {
        return Result<typename Map::mapped_type>(Status(
            providers.empty() ? StatusCode::NotFound
                              : StatusCode::ProviderMismatch,
            providers.empty()
                ? "required provider is not registered"
                : "registered providers do not match the suite's exact ID"));
    }
    const ProviderDescriptor& descriptor = it->second->descriptor();
    if (descriptor.api_version() != requirement.api_version()) {
        return Result<typename Map::mapped_type>(Status(
            StatusCode::ProviderMismatch,
            "provider API version does not match the suite"));
    }
    if (!descriptor.capabilities().contains_all(
            requirement.required_capabilities())) {
        return Result<typename Map::mapped_type>(Status(
            StatusCode::FailedPrecondition,
            "provider is missing a required capability"));
    }
    return Result<typename Map::mapped_type>(it->second);
}

}  // namespace

EngineGraph::EngineGraph(
    EndpointRole local_role,
    TransportSuiteDescriptor suite,
    std::shared_ptr<ByteChannelProvider> byte_channel_provider,
    std::shared_ptr<SecureChannelProvider> secure_channel_provider,
    std::shared_ptr<FrontDoorProvider> front_door_provider,
    std::shared_ptr<CarrierProvider> carrier_provider,
    std::shared_ptr<SessionSecurityProviderFactory>
        session_security_provider_factory,
    std::shared_ptr<RouteProvider> route_provider,
    std::map<std::pair<std::string, ServiceKind>,
             std::shared_ptr<StreamHandler>>
        stream_handlers) noexcept
    : local_role_(local_role),
      suite_(std::move(suite)),
      byte_channel_provider_(std::move(byte_channel_provider)),
      secure_channel_provider_(std::move(secure_channel_provider)),
      front_door_provider_(std::move(front_door_provider)),
      carrier_provider_(std::move(carrier_provider)),
      session_security_provider_factory_(
          std::move(session_security_provider_factory)),
      route_provider_(std::move(route_provider)),
      stream_handlers_(std::move(stream_handlers)) {}

std::shared_ptr<StreamHandler> EngineGraph::stream_handler(
    std::string_view service_name,
    ServiceKind service_kind) const noexcept {
    for (const auto& [key, handler] : stream_handlers_) {
        if (key.first == service_name && key.second == service_kind) {
            return handler;
        }
    }
    return {};
}

struct EngineBuilder::Impl {
    Impl(EndpointRole role, TransportSuiteDescriptor descriptor)
        : local_role(role), suite(std::move(descriptor)) {}

    mutable std::mutex mutex;
    EndpointRole local_role;
    TransportSuiteDescriptor suite;
    std::unordered_map<std::string, std::shared_ptr<ByteChannelProvider>>
        byte_channel_providers;
    std::unordered_map<std::string, std::shared_ptr<SecureChannelProvider>>
        secure_channel_providers;
    std::unordered_map<std::string, std::shared_ptr<FrontDoorProvider>>
        front_door_providers;
    std::unordered_map<std::string, std::shared_ptr<CarrierProvider>>
        carrier_providers;
    std::unordered_map<
        std::string, std::shared_ptr<SessionSecurityProviderFactory>>
        session_security_provider_factories;
    std::unordered_map<std::string, std::shared_ptr<RouteProvider>>
        route_providers;
    std::map<std::pair<std::string, ServiceKind>,
             std::shared_ptr<StreamHandler>>
        stream_handlers;
    bool frozen{false};
};

EngineBuilder::EngineBuilder(EndpointRole local_role,
                             TransportSuiteDescriptor suite)
    : impl_(std::make_unique<Impl>(local_role, std::move(suite))) {}

EngineBuilder::~EngineBuilder() = default;

Status EngineBuilder::register_byte_channel_provider(
    std::shared_ptr<ByteChannelProvider> provider) {
    const Status validation = validate_registration(
        provider, ProviderKind::ByteChannel);
    if (!validation.ok()) {
        return validation;
    }
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->frozen) {
        return frozen_status();
    }
    try {
        const auto [_, inserted] = impl_->byte_channel_providers.emplace(
            provider->descriptor().provider_id(), std::move(provider));
        return inserted
            ? Status::success()
            : Status(StatusCode::AlreadyExists,
                     "byte-channel provider ID is already registered");
    } catch (const std::bad_alloc&) {
        return Status(StatusCode::ResourceExhausted,
                      "byte-channel provider registration allocation failed");
    }
}

Status EngineBuilder::register_secure_channel_provider(
    std::shared_ptr<SecureChannelProvider> provider) {
    const Status validation = validate_registration(
        provider, ProviderKind::SecureChannel);
    if (!validation.ok()) {
        return validation;
    }
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->frozen) {
        return frozen_status();
    }
    try {
        const auto [_, inserted] = impl_->secure_channel_providers.emplace(
            provider->descriptor().provider_id(), std::move(provider));
        return inserted
            ? Status::success()
            : Status(StatusCode::AlreadyExists,
                     "secure-channel provider ID is already registered");
    } catch (const std::bad_alloc&) {
        return Status(StatusCode::ResourceExhausted,
                      "secure-channel provider registration allocation failed");
    }
}

Status EngineBuilder::register_front_door_provider(
    std::shared_ptr<FrontDoorProvider> provider) {
    const Status validation = validate_registration(
        provider, ProviderKind::FrontDoor);
    if (!validation.ok()) {
        return validation;
    }
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->frozen) {
        return frozen_status();
    }
    try {
        const auto [_, inserted] = impl_->front_door_providers.emplace(
            provider->descriptor().provider_id(), std::move(provider));
        return inserted
            ? Status::success()
            : Status(StatusCode::AlreadyExists,
                     "front-door provider ID is already registered");
    } catch (const std::bad_alloc&) {
        return Status(StatusCode::ResourceExhausted,
                      "front-door provider registration allocation failed");
    }
}

Status EngineBuilder::register_carrier_provider(
    std::shared_ptr<CarrierProvider> provider) {
    const Status validation = validate_registration(
        provider, ProviderKind::Carrier);
    if (!validation.ok()) {
        return validation;
    }
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->frozen) {
        return frozen_status();
    }
    try {
        const auto [_, inserted] = impl_->carrier_providers.emplace(
            provider->descriptor().provider_id(), std::move(provider));
        return inserted
            ? Status::success()
            : Status(StatusCode::AlreadyExists,
                     "carrier provider ID is already registered");
    } catch (const std::bad_alloc&) {
        return Status(StatusCode::ResourceExhausted,
                      "carrier provider registration allocation failed");
    }
}

Status EngineBuilder::register_session_security_provider_factory(
    std::shared_ptr<SessionSecurityProviderFactory> provider) {
    const Status validation = validate_registration(
        provider, ProviderKind::SessionSecurity);
    if (!validation.ok()) {
        return validation;
    }
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->frozen) {
        return frozen_status();
    }
    try {
        const auto [_, inserted] =
            impl_->session_security_provider_factories.emplace(
                provider->descriptor().provider_id(), std::move(provider));
        return inserted
            ? Status::success()
            : Status(StatusCode::AlreadyExists,
                     "session-security provider ID is already registered");
    } catch (const std::bad_alloc&) {
        return Status(
            StatusCode::ResourceExhausted,
            "session-security provider registration allocation failed");
    }
}

Status EngineBuilder::register_route_provider(
    std::shared_ptr<RouteProvider> provider) {
    const Status validation = validate_registration(
        provider, ProviderKind::RouteProvider);
    if (!validation.ok()) {
        return validation;
    }
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->frozen) {
        return frozen_status();
    }
    try {
        const auto [_, inserted] = impl_->route_providers.emplace(
            provider->descriptor().provider_id(), std::move(provider));
        return inserted
            ? Status::success()
            : Status(StatusCode::AlreadyExists,
                     "route provider ID is already registered");
    } catch (const std::bad_alloc&) {
        return Status(StatusCode::ResourceExhausted,
                      "route provider registration allocation failed");
    }
}

Status EngineBuilder::register_stream_handler(
    std::string service_name,
    std::shared_ptr<StreamHandler> handler) {
    const Status validation = validate_registration(
        handler, ProviderKind::StreamHandler);
    if (!validation.ok()) {
        return validation;
    }
    if (!valid_service_name(service_name)) {
        return Status(StatusCode::InvalidArgument,
                      "stream-handler service name is invalid");
    }
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->frozen) {
        return frozen_status();
    }
    try {
        const ServiceKind service_kind = handler->service_kind();
        const auto [_, inserted] = impl_->stream_handlers.emplace(
            std::make_pair(std::move(service_name), service_kind),
            std::move(handler));
        return inserted
            ? Status::success()
            : Status(StatusCode::AlreadyExists,
                     "service and kind already have a registered stream handler");
    } catch (const std::bad_alloc&) {
        return Status(StatusCode::ResourceExhausted,
                      "stream-handler registration allocation failed");
    }
}

Result<std::shared_ptr<const EngineGraph>> EngineBuilder::build() {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->frozen) {
        return Result<std::shared_ptr<const EngineGraph>>(frozen_status());
    }

    const ProviderRequirement* byte_requirement =
        impl_->suite.provider_requirement(ProviderKind::ByteChannel);
    const ProviderRequirement* secure_requirement =
        impl_->suite.provider_requirement(ProviderKind::SecureChannel);
    const ProviderRequirement* front_door_requirement =
        impl_->suite.provider_requirement(ProviderKind::FrontDoor);
    const ProviderRequirement* carrier_requirement =
        impl_->suite.provider_requirement(ProviderKind::Carrier);
    const ProviderRequirement* session_security_requirement =
        impl_->suite.provider_requirement(ProviderKind::SessionSecurity);
    const ProviderRequirement* route_requirement =
        impl_->suite.provider_requirement(ProviderKind::RouteProvider);
    if (!byte_requirement || !secure_requirement || !front_door_requirement ||
        !carrier_requirement || !session_security_requirement ||
        !route_requirement) {
        return Result<std::shared_ptr<const EngineGraph>>(Status(
            StatusCode::FailedPrecondition,
            "suite composition is incomplete"));
    }

    auto byte_provider = select_exact_provider(
        *byte_requirement, impl_->byte_channel_providers);
    if (!byte_provider.ok()) {
        return Result<std::shared_ptr<const EngineGraph>>(
            byte_provider.status());
    }
    auto secure_provider = select_exact_provider(
        *secure_requirement, impl_->secure_channel_providers);
    if (!secure_provider.ok()) {
        return Result<std::shared_ptr<const EngineGraph>>(
            secure_provider.status());
    }
    auto carrier_provider = select_exact_provider(
        *carrier_requirement, impl_->carrier_providers);
    if (!carrier_provider.ok()) {
        return Result<std::shared_ptr<const EngineGraph>>(
            carrier_provider.status());
    }
    auto front_door_provider = select_exact_provider(
        *front_door_requirement, impl_->front_door_providers);
    if (!front_door_provider.ok()) {
        return Result<std::shared_ptr<const EngineGraph>>(
            front_door_provider.status());
    }
    auto session_security_provider_factory = select_exact_provider(
        *session_security_requirement,
        impl_->session_security_provider_factories);
    if (!session_security_provider_factory.ok()) {
        return Result<std::shared_ptr<const EngineGraph>>(
            session_security_provider_factory.status());
    }
    auto route_provider = select_exact_provider(
        *route_requirement, impl_->route_providers);
    if (!route_provider.ok()) {
        return Result<std::shared_ptr<const EngineGraph>>(
            route_provider.status());
    }

    std::map<std::pair<std::string, ServiceKind>,
             std::shared_ptr<StreamHandler>>
        selected_handlers;
    try {
        for (const ServiceRequirement& requirement : impl_->suite.services()) {
            const auto handler_it = impl_->stream_handlers.find(
                std::make_pair(requirement.service_name(),
                               requirement.service_kind()));
            if (handler_it == impl_->stream_handlers.end()) {
                const bool name_registered = std::any_of(
                    impl_->stream_handlers.begin(),
                    impl_->stream_handlers.end(),
                    [&](const auto& entry) {
                        return entry.first.first ==
                               requirement.service_name();
                    });
                return Result<std::shared_ptr<const EngineGraph>>(Status(
                    name_registered ? StatusCode::ProviderMismatch
                                    : StatusCode::NotFound,
                    name_registered
                        ? "registered stream handler has the wrong service kind"
                        : "required stream handler is not registered"));
            }
            const auto& handler = handler_it->second;
            const ProviderDescriptor& descriptor = handler->descriptor();
            if (descriptor.provider_id() != requirement.provider_id() ||
                descriptor.api_version() != requirement.api_version() ||
                handler->service_kind() != requirement.service_kind()) {
                return Result<std::shared_ptr<const EngineGraph>>(Status(
                    StatusCode::ProviderMismatch,
                    "stream handler does not exactly match its service requirement"));
            }
            if (!descriptor.capabilities().contains_all(
                    requirement.required_capabilities())) {
                return Result<std::shared_ptr<const EngineGraph>>(Status(
                    StatusCode::FailedPrecondition,
                    "stream handler is missing a required capability"));
            }
            selected_handlers.emplace(
                std::make_pair(requirement.service_name(),
                               requirement.service_kind()),
                handler);
        }

        auto mutable_graph = std::shared_ptr<EngineGraph>(new EngineGraph(
            impl_->local_role,
            impl_->suite,
            std::move(byte_provider).take_value(),
            std::move(secure_provider).take_value(),
            std::move(front_door_provider).take_value(),
            std::move(carrier_provider).take_value(),
            std::move(session_security_provider_factory).take_value(),
            std::move(route_provider).take_value(),
            std::move(selected_handlers)));
        std::shared_ptr<const EngineGraph> graph = std::move(mutable_graph);
        impl_->frozen = true;
        return Result<std::shared_ptr<const EngineGraph>>(std::move(graph));
    } catch (const std::bad_alloc&) {
        return Result<std::shared_ptr<const EngineGraph>>(Status(
            StatusCode::ResourceExhausted,
            "engine graph allocation failed"));
    }
}

bool EngineBuilder::frozen() const noexcept {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->frozen;
}

}  // namespace yume::engine
