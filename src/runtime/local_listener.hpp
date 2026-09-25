/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string_view>
#include <variant>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "engine/byte_channel.hpp"
#include "engine/status.hpp"
#include "providers/asio_execution_context.hpp"
#include "providers/asio_tcp_byte_channel_provider.hpp"

namespace yume::runtime {

// A local adapter's listening socket and accept loop.
//
// A loopback TCP listener serves every local process. A UNIX listener serves
// only processes of this user: the socket's directory must belong to the user
// and be closed to writes by group and others, the socket file is mode 0600,
// and a connection whose peer credentials carry another user ID is closed. A
// socket file left by an earlier run is replaced, a live listener at the path
// refuses the new one with AddressInUse, and any other file refuses it with
// AlreadyExists. Close removes the socket file while it is still this one.
//
// Each connection becomes a channel of the supplied owner, whose capacity
// bounds the adapter's connections. Accepting pauses while full() holds and
// continues on resume(). A failed accept is retried after one second. If the
// retry cannot be scheduled, the listener closes and on_failure runs once.
//
// Creation, start, resume, close and every callback run on the context.
class LocalListener final {
public:
    struct Loopback final {
        boost::asio::ip::address address;
        std::uint16_t port;
    };
    struct Unix final {
        std::filesystem::path path;
    };
    using Address = std::variant<Loopback, Unix>;

    struct Connection final {
        std::unique_ptr<engine::ByteChannel> channel;
        // The client's address, for a TCP listener only.
        std::optional<boost::asio::ip::address> peer_address;
    };
    using Accepted = std::function<void(Connection)>;
    using Full = std::function<bool()>;
    using Failed = std::function<void(engine::Status)>;

    // name begins creation diagnostics, as in "SOCKS5 listener".
    static engine::Result<std::shared_ptr<LocalListener>> open(
        std::shared_ptr<providers::AsioExecutionContext> context,
        const Address& address,
        std::shared_ptr<providers::AsioTcpAcceptedChannelOwner> channels,
        std::string_view name);

    LocalListener(const LocalListener&) = delete;
    LocalListener& operator=(const LocalListener&) = delete;
    ~LocalListener() noexcept;

    // Begins accepting. Callbacks must not throw. on_failure may run before
    // start returns.
    void start(Accepted accepted, Full full, Failed on_failure) noexcept;
    void resume() noexcept;
    // The bound endpoint of a TCP listener, or a default endpoint.
    boost::asio::ip::tcp::endpoint tcp_endpoint() const noexcept;
    void close() noexcept;

    class Loop;

private:
    explicit LocalListener(std::shared_ptr<Loop> loop) noexcept;
    std::shared_ptr<Loop> loop_;
};

}  // namespace yume::runtime
