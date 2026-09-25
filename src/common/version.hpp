/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <string_view>

namespace yume {

// Product maturity is independent of the wire and embedding versions.
inline constexpr char kVersion[] = "0.3.0-dev1";

// The captured evidence profile the outer TLS and HTTP/2 layers follow. It is
// evidence-backed geometry, not a YTP wire version.
inline constexpr std::string_view kEvidenceProfile =
    "chrome151-node24-v1";
inline constexpr std::uint32_t kEvidenceProfileVersion = 1;

// YTP/1, schema 1, and the role-neutral ABI are development contracts. Native
// endpoints carry traffic, and the build-tree ABI and remaining application
// migration have not passed the complete replacement and release gates.
inline constexpr std::string_view kYtpVersion = "YTP/1";
inline constexpr std::uint32_t kYtpVersionNumber = 1;
inline constexpr std::string_view kYtpMaturity = "experimental";
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

// A target that links no key-holding YTP/1 provider reports "unwired". The C
// ABI asks its linked schema-1 backend for the concrete library identity
// instead, so a provider that merely exists in the build tree never lends its
// name. A wired target must report the complete backend identity rather than
// implying that configured algorithms are usable.
#if defined(YUME_CRYPTO_BACKEND)
inline constexpr std::string_view kCryptoBackend = YUME_CRYPTO_BACKEND;
#else
inline constexpr std::string_view kCryptoBackend = "unwired";
#endif

}  // namespace yume
