/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>

#include "engine/byte_channel.hpp"
#include "engine/carrier.hpp"
#include "engine/front_door.hpp"
#include "engine/route_provider.hpp"
#include "engine/secure_channel.hpp"
#include "engine/stream_handler.hpp"
#include "engine/transport_suite.hpp"
#include "engine/types.hpp"

namespace yume::engine {

class SessionSecurityProviderFactory;

// Immutable provider selection and service mapping. Client graphs require
// byte-channel, secure-channel and carrier factories. Server graphs may omit
// those factories because externally owned ingress supplies a ready carrier;
// its instance provenance must still match the complete suite requirements.
// The front-door factory is optional for both roles. Any registered optional
// factory must match its suite requirement exactly like a required factory.
// Session security and declared service handlers remain required. A routing
// factory is required only when a selected handler advertises DirectTcp or
// DirectUdp; it must support the handler's corresponding route capabilities.
class EngineGraph final {
public:
    EndpointRole local_role() const noexcept { return local_role_; }
    const TransportSuiteDescriptor& suite() const noexcept { return suite_; }

    std::shared_ptr<ByteChannelProvider> byte_channel_provider() const noexcept {
        return byte_channel_provider_;
    }
    std::shared_ptr<SecureChannelProvider> secure_channel_provider() const noexcept {
        return secure_channel_provider_;
    }
    std::shared_ptr<FrontDoorProvider> front_door_provider() const noexcept {
        return front_door_provider_;
    }
    std::shared_ptr<CarrierProvider> carrier_provider() const noexcept {
        return carrier_provider_;
    }
    std::shared_ptr<SessionSecurityProviderFactory>
    session_security_provider_factory() const noexcept {
        return session_security_provider_factory_;
    }
    std::shared_ptr<RouteProvider> route_provider() const noexcept {
        return route_provider_;
    }
    std::shared_ptr<StreamHandler> stream_handler(
        std::string_view service_name,
        ServiceKind service_kind) const noexcept;

private:
    friend class EngineBuilder;
    EngineGraph(
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
            stream_handlers) noexcept;

    EndpointRole local_role_;
    TransportSuiteDescriptor suite_;
    std::shared_ptr<ByteChannelProvider> byte_channel_provider_;
    std::shared_ptr<SecureChannelProvider> secure_channel_provider_;
    std::shared_ptr<FrontDoorProvider> front_door_provider_;
    std::shared_ptr<CarrierProvider> carrier_provider_;
    std::shared_ptr<SessionSecurityProviderFactory>
        session_security_provider_factory_;
    std::shared_ptr<RouteProvider> route_provider_;
    std::map<std::pair<std::string, ServiceKind>,
             std::shared_ptr<StreamHandler>>
        stream_handlers_;
};

// Registration is instance-local and exact-ID only. A successful build freezes
// the builder; later registration and rebuild attempts fail instead of
// replacing providers or selecting a fallback. Missing server transport or
// front-door factories never select placeholders or weaken suite provenance.
class EngineBuilder final {
public:
    EngineBuilder(EndpointRole local_role, TransportSuiteDescriptor suite);
    ~EngineBuilder();

    EngineBuilder(const EngineBuilder&) = delete;
    EngineBuilder& operator=(const EngineBuilder&) = delete;
    EngineBuilder(EngineBuilder&&) = delete;
    EngineBuilder& operator=(EngineBuilder&&) = delete;

    Status register_byte_channel_provider(
        std::shared_ptr<ByteChannelProvider> provider);
    Status register_secure_channel_provider(
        std::shared_ptr<SecureChannelProvider> provider);
    Status register_front_door_provider(
        std::shared_ptr<FrontDoorProvider> provider);
    Status register_carrier_provider(
        std::shared_ptr<CarrierProvider> provider);
    Status register_session_security_provider_factory(
        std::shared_ptr<SessionSecurityProviderFactory> provider);
    Status register_route_provider(std::shared_ptr<RouteProvider> provider);
    Status register_stream_handler(
        std::string service_name,
        std::shared_ptr<StreamHandler> handler);

    Result<std::shared_ptr<const EngineGraph>> build();
    bool frozen() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace yume::engine
