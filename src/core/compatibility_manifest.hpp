/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <string_view>

#include "core/version.hpp"

namespace yume {

// One immutable view is used by the ABI, CLIs, setup/doctor output, and
// release tooling. Keeping the composition fields separate makes provider
// substitution visible instead of hiding it behind a product version.
struct CompatibilityManifest {
    std::string_view product_version;
    std::string_view runtime_transport;
    std::string_view runtime_transport_wire_version;
    std::string_view ytp_version;
    std::string_view ytp_maturity;
    std::uint32_t config_schema;
    std::uint32_t abi_version;
    std::string_view transport_suite;
    std::string_view secure_channel_provider;
    std::string_view front_door_provider;
    std::string_view carrier_provider;
    std::string_view session_component;
    std::string_view session_security_provider;
    std::string_view crypto_backend;
    std::string_view evidence_profile;
    std::uint32_t evidence_profile_version;
};

inline constexpr CompatibilityManifest kCompatibilityManifest{
    kVersion,
    kRuntimeTransport,
    kTransportVersion,
    kYtpVersion,
    kYtpMaturity,
    kConfigSchema,
    kAbiVersion,
    kTransportSuite,
    kSecureChannelProvider,
    kFrontDoorProvider,
    kCarrierProvider,
    kSessionComponent,
    kSessionSecurityProvider,
    kCryptoBackend,
    kEvidenceProfile,
    kEvidenceProfileVersion,
};

}  // namespace yume
