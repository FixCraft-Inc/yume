/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

#include "common/service_name.hpp"
#include "engine/status.hpp"
#include "engine/types.hpp"

namespace yume::engine {

inline constexpr std::size_t kMaxProviderIdBytes = 128U;
inline constexpr std::size_t kMaxSuiteIdBytes = 128U;
inline constexpr std::size_t kMaxWireProtocolBytes = 64U;
inline constexpr std::size_t kMaxServiceNameBytes =
    common::kMaxServiceNameBytes;
inline constexpr std::size_t kMaxSuiteServices = 256U;
inline constexpr std::uint32_t kMaxServiceConcurrentStreams = 1U << 20U;

enum class ProviderKind : std::uint8_t {
    ByteChannel,
    SecureChannel,
    FrontDoor,
    Carrier,
    SessionSecurity,
    StreamHandler,
    RouteProvider,
};

enum class Capability : std::uint64_t {
    ReliableOrderedBytes = 1ULL << 0U,
    AsynchronousIo = 1ULL << 1U,
    Cancellation = 1ULL << 2U,
    ExecutorAffinity = 1ULL << 3U,
    BoundedWrites = 1ULL << 4U,
    SecureChannelPeerEvidence = 1ULL << 5U,
    ExporterBinding = 1ULL << 6U,
    Tls13 = 1ULL << 7U,
    DuplexRecords = 1ULL << 8U,
    OuterFlowCredit = 1ULL << 9U,
    NamedByteStreams = 1ULL << 10U,
    PacketChannels = 1ULL << 11U,
    IdentityBoundRouting = 1ULL << 12U,
    DirectTcp = 1ULL << 13U,
    DirectUdp = 1ULL << 14U,
    GenuineCoverTraffic = 1ULL << 15U,
    ReplayProtectedAdmission = 1ULL << 16U,
    CompositeAuthentication = 1ULL << 17U,
    HybridEstablishment = 1ULL << 18U,
    DirectionalRatchet = 1ULL << 19U,
    OneUseAeadKeys = 1ULL << 20U,
};

class CapabilitySet final {
public:
    constexpr CapabilitySet() noexcept = default;

    static constexpr CapabilitySet of(
        std::initializer_list<Capability> capabilities) noexcept {
        CapabilitySet set;
        for (const Capability capability : capabilities) {
            set.bits_ |= static_cast<std::uint64_t>(capability);
        }
        return set;
    }

    constexpr bool contains(Capability capability) const noexcept {
        const std::uint64_t bit = static_cast<std::uint64_t>(capability);
        return (bits_ & bit) == bit;
    }
    constexpr bool contains_all(CapabilitySet required) const noexcept {
        return (bits_ & required.bits_) == required.bits_;
    }
    constexpr bool empty() const noexcept { return bits_ == 0U; }
    constexpr std::uint64_t bits() const noexcept { return bits_; }

    constexpr CapabilitySet with(Capability capability) const noexcept {
        CapabilitySet result = *this;
        result.bits_ |= static_cast<std::uint64_t>(capability);
        return result;
    }

    friend constexpr bool operator==(CapabilitySet,
                                     CapabilitySet) noexcept = default;

private:
    explicit constexpr CapabilitySet(std::uint64_t bits) noexcept
        : bits_(bits) {}

    std::uint64_t bits_{0U};
};

CapabilitySet mandatory_capabilities(ProviderKind kind) noexcept;

class ProviderDescriptor final {
public:
    static Result<ProviderDescriptor> create(
        std::string provider_id,
        ProviderKind kind,
        std::uint32_t api_version,
        CapabilitySet capabilities);

    const std::string& provider_id() const noexcept { return provider_id_; }
    ProviderKind kind() const noexcept { return kind_; }
    std::uint32_t api_version() const noexcept { return api_version_; }
    CapabilitySet capabilities() const noexcept { return capabilities_; }

private:
    ProviderDescriptor(std::string provider_id,
                       ProviderKind kind,
                       std::uint32_t api_version,
                       CapabilitySet capabilities) noexcept;

    std::string provider_id_;
    ProviderKind kind_;
    std::uint32_t api_version_{0U};
    CapabilitySet capabilities_;
};

class ProviderRequirement final {
public:
    static Result<ProviderRequirement> create(
        ProviderKind kind,
        std::string provider_id,
        std::uint32_t api_version,
        CapabilitySet required_capabilities);

    ProviderKind kind() const noexcept { return kind_; }
    const std::string& provider_id() const noexcept { return provider_id_; }
    std::uint32_t api_version() const noexcept { return api_version_; }
    CapabilitySet required_capabilities() const noexcept {
        return required_capabilities_;
    }

private:
    ProviderRequirement(ProviderKind kind,
                        std::string provider_id,
                        std::uint32_t api_version,
                        CapabilitySet required_capabilities) noexcept;

    ProviderKind kind_;
    std::string provider_id_;
    std::uint32_t api_version_{0U};
    CapabilitySet required_capabilities_;
};

class ServiceRequirement final {
public:
    static Result<ServiceRequirement> create(
        std::string service_name,
        ServiceKind service_kind,
        std::string provider_id,
        std::uint32_t api_version,
        std::uint32_t max_concurrent_streams,
        CapabilitySet required_capabilities);

    const std::string& service_name() const noexcept { return service_name_; }
    ServiceKind service_kind() const noexcept { return service_kind_; }
    const std::string& provider_id() const noexcept { return provider_id_; }
    std::uint32_t api_version() const noexcept { return api_version_; }
    std::uint32_t max_concurrent_streams() const noexcept {
        return max_concurrent_streams_;
    }
    CapabilitySet required_capabilities() const noexcept {
        return required_capabilities_;
    }

private:
    ServiceRequirement(std::string service_name,
                       ServiceKind service_kind,
                       std::string provider_id,
                       std::uint32_t api_version,
                       std::uint32_t max_concurrent_streams,
                       CapabilitySet required_capabilities) noexcept;

    std::string service_name_;
    ServiceKind service_kind_;
    std::string provider_id_;
    std::uint32_t api_version_{0U};
    std::uint32_t max_concurrent_streams_{0U};
    CapabilitySet required_capabilities_;
};

// A descriptor has no setters. Creation validates one exact provider for each
// layer in ByteChannel -> SecureChannel -> FrontDoor/Carrier ->
// SessionSecurity plus one identity-fenced RouteProvider. Service handlers
// are also exact, named requirements.
class TransportSuiteDescriptor final {
public:
    static Result<TransportSuiteDescriptor> create(
        std::string suite_id,
        std::string wire_protocol,
        std::vector<ProviderRequirement> providers,
        std::vector<ServiceRequirement> services = {});

    const std::string& suite_id() const noexcept { return suite_id_; }
    const std::string& wire_protocol() const noexcept {
        return wire_protocol_;
    }
    const std::vector<ProviderRequirement>& providers() const noexcept {
        return providers_;
    }
    const std::vector<ServiceRequirement>& services() const noexcept {
        return services_;
    }

    const ProviderRequirement* provider_requirement(
        ProviderKind kind) const noexcept;

private:
    TransportSuiteDescriptor(
        std::string suite_id,
        std::string wire_protocol,
        std::vector<ProviderRequirement> providers,
        std::vector<ServiceRequirement> services) noexcept;

    std::string suite_id_;
    std::string wire_protocol_;
    std::vector<ProviderRequirement> providers_;
    std::vector<ServiceRequirement> services_;
};

bool valid_provider_id(std::string_view value) noexcept;
bool valid_service_name(std::string_view value) noexcept;

}  // namespace yume::engine
