/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <boost/asio/ip/tcp.hpp>

#include "engine/status.hpp"
#include "providers/asio_execution_context.hpp"
#include "runtime/circuit_status.hpp"
#include "runtime/native_client_runtime.hpp"
#include "runtime/native_server_runtime.hpp"

namespace yume::runtime {

// Local control protocol 1, served on the control.socket of yume or yumed.
//
// A connection sends one request line, the JSON object
// {"control":1,"request":"status"} and a newline, of at most
// kControlRequestBytes, within kControlRequestTimeout. The server answers
// with one JSON object and a newline, then closes the connection. The status
// reply carries "control":1, "program" and the fields client_status_reply or
// server_status_reply writes. A client with circuits also takes
// {"control":1,"request":"accept-route","id":ID}, the only request that
// changes anything, and answers {"control":1,"accepted":ID}. Any other
// request, or a malformed one, gets {"control":1,"error":TEXT}. Replies hold
// no key, credential or payload.
inline constexpr std::uint32_t kControlProtocol = 1U;
inline constexpr std::size_t kControlRequestBytes = 512U;
inline constexpr std::size_t kControlReplyBytes = std::size_t{64} * 1024U;
inline constexpr std::size_t kControlConnections = 4U;
inline constexpr std::chrono::milliseconds kControlRequestTimeout{2'000};

// Returns the status reply, one JSON object without the newline. It runs on
// the server's context for each status request.
using ControlStatusSource = std::function<std::string()>;

// Accepts a client's route proposal by its id. NotFound when no proposal
// has that id. It runs on the server's context.
using ControlRouteAcceptance =
    std::function<engine::Status(std::string_view id)>;

// A control socket. LocalListener's UNIX rules apply: the socket's
// directory must belong to this user and be closed to writes by group and
// others, the socket is mode 0600, and a peer of another user is closed. At
// most kControlConnections connections are open, and each ends after one
// reply or kControlRequestTimeout.
//
// open, close and every callback run on the context. on_failure runs once if
// the listener stops on its own.
class ControlServer final {
public:
    static engine::Result<std::shared_ptr<ControlServer>> open(
        std::shared_ptr<providers::AsioExecutionContext> context,
        const std::filesystem::path& path, ControlStatusSource status,
        std::function<void(engine::Status)> on_failure = {},
        ControlRouteAcceptance accept_route = {});

    ControlServer(const ControlServer&) = delete;
    ControlServer& operator=(const ControlServer&) = delete;
    ~ControlServer() noexcept;

    void close() noexcept;

private:
    struct State;
    explicit ControlServer(std::shared_ptr<State> state) noexcept;
    std::shared_ptr<State> state_;
};

// What a client's status reply names besides its runtime status.
struct ClientControlView final {
    std::string server_host;
    std::uint16_t server_port{0U};
    std::vector<boost::asio::ip::tcp::endpoint> socks5;
    std::vector<boost::asio::ip::tcp::endpoint> forwards;
    std::vector<std::string> unix_forwards;
};

// The status reply for a client runtime at time now, with its circuits'
// routes, lengths and any proposal of a shorter route when it has them.
std::string client_status_reply(
    const NativeClientStatus& status, const ClientControlView& view,
    std::chrono::steady_clock::time_point now,
    const std::optional<CircuitPoolStatus>& circuits = std::nullopt);

// The status reply for a server runtime at time now: listeners, client
// sessions and, with a cluster, the list's serial and expiry and each peer's
// outbound link and inbound sessions.
std::string server_status_reply(const NativeServerStatus& status,
                                std::chrono::steady_clock::time_point now);

// Sends a status request to the control socket at path and returns the reply
// without its newline. Refuses a socket whose peer runs as another user.
// Blocks for at most timeout. NotFound means no process listens there.
engine::Result<std::string> query_control_status(
    const std::filesystem::path& path, std::chrono::milliseconds timeout);

// Sends an accept-route request for id, 1 to 64 lowercase hexadecimal
// digits, and returns the reply as query_control_status does. The reply is
// an error when no proposal has that id.
engine::Result<std::string> query_control_accept_route(
    const std::filesystem::path& path, std::string_view id,
    std::chrono::milliseconds timeout);

// The lines yume --status or yumed --status prints for a status reply, or an
// error for a reply that is not one.
engine::Result<std::string> status_reply_text(std::string_view reply);

}  // namespace yume::runtime
