/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */
#pragma once

#include <memory>
#include <optional>
#include <string_view>

#include "config/v1/config.hpp"
#include "engine/route_provider.hpp"
#include "providers/asio_execution_context.hpp"

namespace yume::runtime {

// Owns an ephemeral TUN and its networking. Startup is transactional: addresses
// and routes use exclusive netlink additions; DNS changes belong only to this
// new link. The numeric transport host, the client's first hop, is excluded
// from these routes so its existing route remains untouched. Default routing
// requires that address.
// IPv6 address generation is disabled before static addresses and link-up.
// close reverts DNS, attempts link removal and closes the ephemeral TUN even
// when cleanup fails. It reports the error and never retries a cached index
// after closing the device. Repeated calls retain the original status code.
// Destruction makes best-effort cleanup; callers must check close.
// No shell runs. The operator must not reconfigure these owned resources.
//
// create and channel operations run on the supplied context. close must also
// run there after consumers cancel/drain packet I/O. Retain this owner across
// reconnects to keep selected traffic on the TUN while no session is available.
class LinuxTunNetwork final {
public:
    static engine::Result<std::shared_ptr<LinuxTunNetwork>> create(
        std::shared_ptr<providers::AsioExecutionContext> context,
        const config::v1::PacketAdapter& adapter,
        std::optional<common::IpInterfaceAddress> transport_address = std::nullopt);
    ~LinuxTunNetwork() noexcept;
    LinuxTunNetwork(const LinuxTunNetwork&) = delete;
    LinuxTunNetwork& operator=(const LinuxTunNetwork&) = delete;

    engine::PacketChannel& channel() noexcept;
    std::string_view interface_name() const noexcept;
    unsigned interface_index() const noexcept;
    [[nodiscard]] engine::Status close() noexcept;

private:
    struct State;
    explicit LinuxTunNetwork(std::unique_ptr<State> state) noexcept;
    std::unique_ptr<State> state_;
};

}  // namespace yume::runtime
