/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <string_view>

#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
#include "basefwx/constants.hpp"
#endif

namespace yume {

// Product maturity is independent from every wire and embedding contract.
// The 0.3 development line currently ships the working transport-v2 product
// while YTP/1 is built and tested as an experimental replacement foundation.
inline constexpr char kVersion[] = "0.3.0-dev1";

// Do not derive this exact transport-v2 wire value from kVersion. It is
// authenticated by AUTH v2 and admission, so changing product maturity must
// not silently create a new wire protocol. These compatibility names remain
// for the current transport-v2 implementation until YTP/1 reaches parity.
inline constexpr std::string_view kRuntimeTransport = "transport-v2";
inline constexpr std::string_view kTransportVersion = "0.2.0-dev6";

// Profile geometry is evidence-backed and shared by today's transport-v2
// runtime and the YTP/1 development suite, but it is not a YTP wire version.
inline constexpr std::string_view kEvidenceProfile =
    "chrome151-node24-v1";
inline constexpr std::string_view kTransportProfile = kEvidenceProfile;
inline constexpr std::uint32_t kEvidenceProfileVersion = 1;

// YTP/1, schema 1, and the role-neutral ABI are development contracts. The
// ABI remains build-tree-only and the provider is not wired into a live
// endpoint, so none of these constants imply replacement-product parity.
inline constexpr std::string_view kYtpVersion = "YTP/1";
inline constexpr std::uint32_t kYtpVersionNumber = 1;
inline constexpr std::string_view kYtpMaturity = "experimental-unwired";
inline constexpr std::uint32_t kConfigSchema = 1;
inline constexpr std::uint32_t kAbiVersion = 1;

// YTP/1 has one mandatory composition. There is no suite negotiation,
// provider fallback, or backend-selection configuration in this wire version.
inline constexpr std::string_view kTransportSuite = "ytp1-tls13-h2";
inline constexpr std::string_view kSecureChannelProvider = "tls13-native";
inline constexpr std::string_view kFrontDoorProvider = "h2-web";
inline constexpr std::string_view kCarrierProvider = "h2-duplex";
inline constexpr std::string_view kSessionComponent = "ytp1-hybrid";

// The suite component names the required behavior; this value identifies the
// concrete key-holding implementation actually wired into the reporting
// target. Development scaffolds must say "unwired" rather than borrowing the
// identity of a provider that merely exists elsewhere in the build tree.
#if defined(YUME_SESSION_SECURITY_PROVIDER)
inline constexpr std::string_view kSessionSecurityProvider =
    YUME_SESSION_SECURITY_PROVIDER;
#else
inline constexpr std::string_view kSessionSecurityProvider = "unwired";
#endif

#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
inline constexpr std::string_view kBasefwxVersion = basefwx::constants::kEngineVersion;
#else
inline constexpr std::string_view kBasefwxVersion = "disabled";
#endif

// The live YTP/1 endpoint and compatibility manifest do not yet link a
// key-holding provider. The isolated opt-in provider target does not make that
// runtime component active; a wired target must define the complete reviewed
// backend identity rather than implying configured algorithms are usable.
#if defined(YUME_CRYPTO_BACKEND)
inline constexpr std::string_view kCryptoBackend = YUME_CRYPTO_BACKEND;
#else
inline constexpr std::string_view kCryptoBackend = "unwired";
#endif

}  // namespace yume
