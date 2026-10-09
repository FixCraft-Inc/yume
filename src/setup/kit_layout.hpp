/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "providers/openssl_security_provider.hpp"
#include "setup/provision.hpp"

// What a kit holds: its configurations, stores, cover site and launchers.
// yume, yumed and yume-doctor read these files, and the layout here is the
// one the operations guide and the configuration reference describe.
namespace yume::setup {

// The bound of a server's authorized-keys store, as the daemon reads it.
inline constexpr std::size_t kMaxAuthorizedIdentities =
    providers::kMaxAuthorizedIdentities;

// Server public material every client bundle carries, under the same names
// in a server's and a client's credentials directory.
inline constexpr std::array<std::string_view, 4> kClientServerMaterial{
    "admission.key", "server-trust.pem", "server-composite.pub.pem",
    "server-mlkem.pub.pem"};

// Where a circuits client keeps its kit copies, and the state it writes.
inline constexpr std::string_view kClientCircuitsDirectory =
    "credentials/circuits";
inline constexpr std::string_view kClientCircuitsState = "circuits-state.json";

inline constexpr std::string_view kServerLauncher =
    "#!/bin/sh\n"
    "set -eu\n"
    "cd \"$(dirname \"$0\")\"\n"
    "exec \"${YUMED_BIN:-yumed}\" --config yumed.json\n";
inline constexpr std::string_view kClientLauncher =
    "#!/bin/sh\n"
    "set -eu\n"
    "cd \"$(dirname \"$0\")\"\n"
    "exec \"${YUME_BIN:-yume}\" --config yume.json\n";

struct CoverPage final {
    std::string_view path;
    std::string_view text;
};
// The static cover site a server shows to anyone who is not a client. It
// holds the assets the browser profile loads and says nothing of YUME.
extern const std::array<CoverPage, 5> kCoverSite;

// The kit's services: TCP streams and UDP packets. Managed TUN is
// configured explicitly, because its addresses, routes, DNS and directional
// policy belong to the operator.
Json standard_services();
bool declares_standard_services(const Json& config);
// A direct adapter that reaches globally reachable unicast addresses only.
// Private, loopback and other special-purpose networks need an explicit
// operator entry.
Json direct_adapter(std::string_view kind, const std::string& service);
Json socks5_adapter();

Json server_config(std::int64_t port, const Json& tuning,
                   std::optional<std::int64_t> max_egress_mbps);
Json client_config(const std::string& host, std::int64_t port,
                   const Json& tuning);
// One authorized-keys entry with the kit's services, and yume.circuit for a
// client of circuits.
Json authorized_entry(const std::string& name, const std::string& fingerprint,
                      std::optional<std::int64_t> max_sessions,
                      std::optional<double> weight, bool circuits);
// A client's circuits section of three hops with the kit's copies.
Json circuits_section();
Json kit_manifest(const std::string& host, std::int64_t port,
                  const std::string& client_name);

}  // namespace yume::setup
