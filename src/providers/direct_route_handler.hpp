/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <functional>
#include <memory>

#include "engine/stream_handler.hpp"

namespace yume::providers {

// Policy-bearing adapter from an authenticated YTP service stream to one
// explicit RouteProvider. SessionEngine remains the only authority capable of
// creating the request passed to on_route().
class DirectRouteHandler final : public engine::StreamHandler {
public:
    using AuthorizationPolicy =
        std::function<engine::Status(const engine::StreamOpenContext&)>;

    static engine::Result<std::shared_ptr<DirectRouteHandler>> create(
        engine::ProviderDescriptor descriptor,
        engine::ServiceKind service_kind,
        std::shared_ptr<engine::RouteProvider> route_provider,
        AuthorizationPolicy authorization_policy);

    DirectRouteHandler(const DirectRouteHandler&) = delete;
    DirectRouteHandler& operator=(const DirectRouteHandler&) = delete;
    ~DirectRouteHandler() override = default;

    const engine::ProviderDescriptor& descriptor() const noexcept override;
    engine::ServiceKind service_kind() const noexcept override;
    engine::Status authorize(
        const engine::StreamOpenContext& context) override;
    void on_open(engine::StreamOpenContext context,
                 std::shared_ptr<engine::StreamResponder> stream) override;
    void on_route(engine::AuthorizedRouteRequest request,
                  std::shared_ptr<engine::StreamResponder> stream) override;

private:
    DirectRouteHandler(
        engine::ProviderDescriptor descriptor,
        engine::ServiceKind service_kind,
        std::shared_ptr<engine::RouteProvider> route_provider,
        AuthorizationPolicy authorization_policy) noexcept;

    engine::ProviderDescriptor descriptor_;
    engine::ServiceKind service_kind_;
    std::shared_ptr<engine::RouteProvider> route_provider_;
    AuthorizationPolicy authorization_policy_;
};

}  // namespace yume::providers
