/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "engine/transport_suite.hpp"

#include <algorithm>
#include <array>
#include <new>
#include <set>
#include <utility>

namespace yume::engine {
namespace {

bool valid_identifier(std::string_view value, std::size_t max_size) noexcept {
    if (value.empty() || value.size() > max_size) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](unsigned char byte) {
        return (byte >= 'a' && byte <= 'z') ||
               (byte >= 'A' && byte <= 'Z') ||
               (byte >= '0' && byte <= '9') || byte == '.' || byte == '_' ||
               byte == '-' || byte == ':' || byte == '/';
    });
}

constexpr std::array<ProviderKind, 6> kCompositionProviderKinds{
    ProviderKind::ByteChannel,
    ProviderKind::SecureChannel,
    ProviderKind::FrontDoor,
    ProviderKind::Carrier,
    ProviderKind::SessionSecurity,
    ProviderKind::RouteProvider,
};

}  // namespace

CapabilitySet mandatory_capabilities(ProviderKind kind) noexcept {
    switch (kind) {
        case ProviderKind::ByteChannel:
            return CapabilitySet::of({
                Capability::ReliableOrderedBytes,
                Capability::AsynchronousIo,
                Capability::Cancellation,
                Capability::ExecutorAffinity,
                Capability::BoundedWrites,
            });
        case ProviderKind::SecureChannel:
            return CapabilitySet::of({
                Capability::ReliableOrderedBytes,
                Capability::AsynchronousIo,
                Capability::Cancellation,
                Capability::ExecutorAffinity,
                Capability::BoundedWrites,
                Capability::SecureChannelPeerEvidence,
                Capability::ExporterBinding,
            });
        case ProviderKind::FrontDoor:
            return CapabilitySet::of({
                Capability::AsynchronousIo,
                Capability::Cancellation,
                Capability::ExecutorAffinity,
                Capability::GenuineCoverTraffic,
                Capability::ReplayProtectedAdmission,
            });
        case ProviderKind::Carrier:
            return CapabilitySet::of({
                Capability::AsynchronousIo,
                Capability::Cancellation,
                Capability::ExecutorAffinity,
                Capability::BoundedWrites,
                Capability::DuplexRecords,
                Capability::OuterFlowCredit,
            });
        case ProviderKind::SessionSecurity:
            return CapabilitySet::of({
                Capability::CompositeAuthentication,
                Capability::HybridEstablishment,
                Capability::DirectionalRatchet,
                Capability::OneUseAeadKeys,
            });
        case ProviderKind::StreamHandler:
            return CapabilitySet::of({Capability::NamedByteStreams});
        case ProviderKind::RouteProvider:
            return CapabilitySet::of({
                Capability::AsynchronousIo,
                Capability::Cancellation,
                Capability::IdentityBoundRouting,
            });
    }
    return {};
}

bool valid_provider_id(std::string_view value) noexcept {
    return valid_identifier(value, kMaxProviderIdBytes);
}

bool valid_service_name(std::string_view value) noexcept {
    return common::valid_service_name(value);
}

ProviderDescriptor::ProviderDescriptor(std::string provider_id,
                                       ProviderKind kind,
                                       std::uint32_t api_version,
                                       CapabilitySet capabilities) noexcept
    : provider_id_(std::move(provider_id)),
      kind_(kind),
      api_version_(api_version),
      capabilities_(capabilities) {}

Result<ProviderDescriptor> ProviderDescriptor::create(
    std::string provider_id,
    ProviderKind kind,
    std::uint32_t api_version,
    CapabilitySet capabilities) {
    if (!valid_provider_id(provider_id)) {
        return Result<ProviderDescriptor>(Status(
            StatusCode::InvalidArgument,
            "provider ID is empty, too long, or contains unsafe bytes"));
    }
    if (api_version == 0U) {
        return Result<ProviderDescriptor>(Status(
            StatusCode::InvalidArgument,
            "provider API version must be non-zero"));
    }
    return Result<ProviderDescriptor>(ProviderDescriptor(
        std::move(provider_id), kind, api_version, capabilities));
}

ProviderRequirement::ProviderRequirement(
    ProviderKind kind,
    std::string provider_id,
    std::uint32_t api_version,
    CapabilitySet required_capabilities) noexcept
    : kind_(kind),
      provider_id_(std::move(provider_id)),
      api_version_(api_version),
      required_capabilities_(required_capabilities) {}

Result<ProviderRequirement> ProviderRequirement::create(
    ProviderKind kind,
    std::string provider_id,
    std::uint32_t api_version,
    CapabilitySet required_capabilities) {
    if (kind == ProviderKind::StreamHandler) {
        return Result<ProviderRequirement>(Status(
            StatusCode::InvalidArgument,
            "stream handlers must be declared as named service requirements"));
    }
    if (!valid_provider_id(provider_id) || api_version == 0U) {
        return Result<ProviderRequirement>(Status(
            StatusCode::InvalidArgument,
            "provider requirement has an invalid ID or API version"));
    }
    const CapabilitySet mandatory = mandatory_capabilities(kind);
    if (!required_capabilities.contains_all(mandatory)) {
        return Result<ProviderRequirement>(Status(
            StatusCode::FailedPrecondition,
            "provider requirement omits mandatory engine capabilities"));
    }
    return Result<ProviderRequirement>(ProviderRequirement(
        kind, std::move(provider_id), api_version, required_capabilities));
}

ServiceRequirement::ServiceRequirement(
    std::string service_name,
    ServiceKind service_kind,
    std::string provider_id,
    std::uint32_t api_version,
    std::uint32_t max_concurrent_streams,
    CapabilitySet required_capabilities) noexcept
    : service_name_(std::move(service_name)),
      service_kind_(service_kind),
      provider_id_(std::move(provider_id)),
      api_version_(api_version),
      max_concurrent_streams_(max_concurrent_streams),
      required_capabilities_(required_capabilities) {}

Result<ServiceRequirement> ServiceRequirement::create(
    std::string service_name,
    ServiceKind service_kind,
    std::string provider_id,
    std::uint32_t api_version,
    std::uint32_t max_concurrent_streams,
    CapabilitySet required_capabilities) {
    if (!valid_service_name(service_name) ||
        !valid_provider_id(provider_id) || api_version == 0U ||
        max_concurrent_streams == 0U ||
        max_concurrent_streams > kMaxServiceConcurrentStreams) {
        return Result<ServiceRequirement>(Status(
            StatusCode::InvalidArgument,
            "service requirement has an invalid name, provider, version, or stream bound"));
    }
    CapabilitySet mandatory = mandatory_capabilities(
        ProviderKind::StreamHandler);
    if (service_kind == ServiceKind::PacketChannel) {
        mandatory = mandatory.with(Capability::PacketChannels);
    }
    if (!required_capabilities.contains_all(mandatory)) {
        return Result<ServiceRequirement>(Status(
            StatusCode::FailedPrecondition,
            "service requirement omits mandatory handler capabilities"));
    }
    return Result<ServiceRequirement>(ServiceRequirement(
        std::move(service_name), service_kind, std::move(provider_id),
        api_version, max_concurrent_streams, required_capabilities));
}

TransportSuiteDescriptor::TransportSuiteDescriptor(
    std::string suite_id,
    std::string wire_protocol,
    std::vector<ProviderRequirement> providers,
    std::vector<ServiceRequirement> services) noexcept
    : suite_id_(std::move(suite_id)),
      wire_protocol_(std::move(wire_protocol)),
      providers_(std::move(providers)),
      services_(std::move(services)) {}

Result<TransportSuiteDescriptor> TransportSuiteDescriptor::create(
    std::string suite_id,
    std::string wire_protocol,
    std::vector<ProviderRequirement> providers,
    std::vector<ServiceRequirement> services) {
    if (!valid_identifier(suite_id, kMaxSuiteIdBytes) ||
        !valid_identifier(wire_protocol, kMaxWireProtocolBytes)) {
        return Result<TransportSuiteDescriptor>(Status(
            StatusCode::InvalidArgument,
            "suite or wire-protocol identifier is invalid"));
    }
    if (services.size() > kMaxSuiteServices) {
        return Result<TransportSuiteDescriptor>(Status(
            StatusCode::ResourceExhausted,
            "suite declares too many services"));
    }

    for (const ProviderKind required_kind : kCompositionProviderKinds) {
        const std::size_t count = static_cast<std::size_t>(std::count_if(
            providers.begin(), providers.end(),
            [required_kind](const ProviderRequirement& requirement) {
                return requirement.kind() == required_kind;
            }));
        if (count != 1U) {
            return Result<TransportSuiteDescriptor>(Status(
                StatusCode::FailedPrecondition,
                "suite must declare exactly one provider for every engine layer"));
        }
    }
    if (providers.size() != kCompositionProviderKinds.size()) {
        return Result<TransportSuiteDescriptor>(Status(
            StatusCode::FailedPrecondition,
            "suite contains an unsupported or duplicate provider layer"));
    }

    try {
        std::set<std::pair<std::string, ServiceKind>> service_keys;
        for (const ServiceRequirement& service : services) {
            if (!service_keys.emplace(service.service_name(),
                                      service.service_kind()).second) {
                return Result<TransportSuiteDescriptor>(Status(
                    StatusCode::AlreadyExists,
                    "suite declares the same service and kind more than once"));
            }
        }
    } catch (const std::bad_alloc&) {
        return Result<TransportSuiteDescriptor>(Status(
            StatusCode::ResourceExhausted,
            "suite validation allocation failed"));
    }

    return Result<TransportSuiteDescriptor>(TransportSuiteDescriptor(
        std::move(suite_id), std::move(wire_protocol),
        std::move(providers), std::move(services)));
}

const ProviderRequirement* TransportSuiteDescriptor::provider_requirement(
    ProviderKind kind) const noexcept {
    const auto it = std::find_if(
        providers_.begin(), providers_.end(),
        [kind](const ProviderRequirement& requirement) {
            return requirement.kind() == kind;
        });
    return it == providers_.end() ? nullptr : &*it;
}

}  // namespace yume::engine
