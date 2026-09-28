/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/control_socket.hpp"

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstring>
#include <iterator>
#include <list>
#include <new>
#include <span>
#include <utility>

#include <boost/asio/basic_waitable_timer.hpp>
#include <nlohmann/json.hpp>

#include "common/version.hpp"
#include "engine/buffer.hpp"
#include "providers/asio_tcp_byte_channel_provider.hpp"
#include "runtime/local_listener.hpp"

namespace yume::runtime {
namespace {
using engine::Buffer;
using engine::ByteChannel;
using engine::Result;
using engine::Status;
using engine::StatusCode;
using Json = nlohmann::json;
using Clock = std::chrono::steady_clock;
using Timer = boost::asio::basic_waitable_timer<
    Clock, boost::asio::wait_traits<Clock>,
    providers::AsioExecutionContext::Executor>;
using Error = boost::system::error_code;

// Text from a status or a peer may hold bytes that are not UTF-8, and the
// reply must still be one JSON line.
std::string dump(const Json& value) {
    return value.dump(-1, ' ', false, Json::error_handler_t::replace);
}

std::string error_reply(std::string_view text) {
    return dump(Json{{"control", kControlProtocol}, {"error", text}});
}

std::string_view state_name(NativeClientState state) noexcept {
    switch (state) {
        case NativeClientState::Idle:
            return "idle";
        case NativeClientState::Connecting:
            return "connecting";
        case NativeClientState::Connected:
            return "connected";
        case NativeClientState::Waiting:
            return "waiting";
        case NativeClientState::Closed:
            return "closed";
    }
    return "unknown";
}

std::string_view code_name(StatusCode code) noexcept {
    switch (code) {
        case StatusCode::Ok:
            return "ok";
        case StatusCode::InvalidArgument:
            return "invalid-argument";
        case StatusCode::ResourceExhausted:
            return "resource-exhausted";
        case StatusCode::Cancelled:
            return "cancelled";
        case StatusCode::Closed:
            return "closed";
        case StatusCode::FailedPrecondition:
            return "failed-precondition";
        case StatusCode::NotFound:
            return "not-found";
        case StatusCode::AlreadyExists:
            return "already-exists";
        case StatusCode::ProviderMismatch:
            return "provider-mismatch";
        case StatusCode::Internal:
            return "internal";
        case StatusCode::EndOfStream:
            return "end-of-stream";
        case StatusCode::PermissionDenied:
            return "permission-denied";
        case StatusCode::AddressInUse:
            return "address-in-use";
    }
    return "unknown";
}

std::string endpoint_text(const boost::asio::ip::tcp::endpoint& endpoint) {
    const auto address = endpoint.address().to_string();
    const auto port = std::to_string(endpoint.port());
    return endpoint.address().is_v6() ? "[" + address + "]:" + port
                                      : address + ":" + port;
}

// Waits until fd is ready for events or the deadline passes.
bool wait_ready(int fd, short events, Clock::time_point deadline) noexcept {
    for (;;) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - Clock::now());
        if (left.count() <= 0) return false;
        pollfd entry{fd, events, 0};
        const int ready = ::poll(
            &entry, 1U,
            static_cast<int>(std::min<long long>(left.count() + 1, INT_MAX)));
        if (ready > 0) return true;
        if (ready < 0 && errno != EINTR) return false;
    }
}

std::string byte_text(std::uint64_t bytes) {
    if (bytes < 1024U) return std::to_string(bytes) + " bytes";
    constexpr const char* units[] = {"KiB", "MiB", "GiB", "TiB"};
    double value = static_cast<double>(bytes) / 1024.0;
    std::size_t unit = 0U;
    while (value >= 1024.0 && unit + 1U < std::size(units)) {
        value /= 1024.0;
        ++unit;
    }
    char text[32];
    static_cast<void>(
        std::snprintf(text, sizeof(text), "%.1f %s", value, units[unit]));
    return text;
}

std::string duration_text(std::uint64_t milliseconds) {
    const std::uint64_t seconds = milliseconds / 1000U;
    const std::uint64_t hours = seconds / 3600U;
    const std::uint64_t minutes = seconds / 60U % 60U;
    std::string text;
    if (hours) text += std::to_string(hours) + " h ";
    if (hours || minutes) text += std::to_string(minutes) + " min ";
    return text + std::to_string(seconds % 60U) + " s";
}

}  // namespace

struct ControlServer::State final : std::enable_shared_from_this<State> {
    class Connection;

    void adopt(LocalListener::Connection accepted) noexcept;
    void remove(const Connection* connection) noexcept;
    void stop(Status status) noexcept;
    void close() noexcept;
    std::string reply_to(std::string_view line);

    std::shared_ptr<providers::AsioExecutionContext> context;
    ControlStatusSource status;
    std::function<void(Status)> on_failure;
    std::shared_ptr<providers::AsioTcpAcceptedChannelOwner> channels;
    std::shared_ptr<LocalListener> listener;
    std::list<std::shared_ptr<Connection>> connections;
    bool closing{false};
    StatusCode failure{StatusCode::Ok};
};

// One control connection: a request line, one reply, then close. A single
// deadline covers both.
class ControlServer::State::Connection final
    : public std::enable_shared_from_this<Connection> {
public:
    Connection(std::weak_ptr<State> owner, std::unique_ptr<ByteChannel> channel,
               providers::AsioExecutionContext::Executor executor)
        : owner_(std::move(owner)),
          channel_(std::move(channel)),
          timer_(executor) {}

    void start() noexcept {
        try {
            timer_.expires_after(kControlRequestTimeout);
            timer_.async_wait(
                [self = shared_from_this()](const Error& error) noexcept {
                    if (!error) self->finish();
                });
        } catch (...) {
            finish();
            return;
        }
        read();
    }

    void close() noexcept { finish(); }

private:
    void read() noexcept {
        if (done_) return;
        try {
            channel_->async_read(
                kControlRequestBytes - request_.size(), {},
                [self = shared_from_this()](Result<Buffer> result) noexcept {
                    self->on_read(std::move(result));
                });
        } catch (...) {
            finish();
        }
    }

    void on_read(Result<Buffer> result) noexcept {
        if (done_ || replying_) return;
        if (!result.ok() || result.value().size() == 0U) {
            finish();
            return;
        }
        try {
            const auto bytes = result.value().bytes();
            request_.append(reinterpret_cast<const char*>(bytes.data()),
                            bytes.size());
            const auto end = request_.find('\n');
            if (end != std::string::npos) {
                const auto owner = owner_.lock();
                if (!owner) {
                    finish();
                    return;
                }
                send(owner->reply_to(
                    std::string_view(request_).substr(0U, end)));
                return;
            }
            if (request_.size() >= kControlRequestBytes) {
                send(error_reply("the request is too long"));
                return;
            }
        } catch (...) {
            finish();
            return;
        }
        read();
    }

    void send(std::string reply) noexcept {
        try {
            reply.push_back('\n');
            auto buffer = Buffer::copy_from(std::as_bytes(std::span(reply)),
                                            reply.size());
            if (!buffer.ok()) {
                finish();
                return;
            }
            replying_ = true;
            channel_->async_write(
                std::move(buffer).take_value(), {},
                [self = shared_from_this()](Status, std::size_t) noexcept {
                    if (self->channel_)
                        static_cast<void>(self->channel_->shutdown_write());
                    self->finish();
                });
        } catch (...) {
            finish();
        }
    }

    void finish() noexcept {
        if (done_) return;
        done_ = true;
        const auto self = shared_from_this();
        Error ignored;
        timer_.cancel(ignored);
        if (channel_) {
            channel_->cancel();
            channel_->close();
        }
        if (const auto owner = owner_.lock()) owner->remove(this);
    }

    std::weak_ptr<State> owner_;
    std::unique_ptr<ByteChannel> channel_;
    Timer timer_;
    std::string request_;
    bool replying_{false};
    bool done_{false};
};

std::string ControlServer::State::reply_to(std::string_view line) {
    const Json request = Json::parse(line, nullptr, false);
    if (request.is_discarded() || !request.is_object()) {
        return error_reply("the request is not a JSON object");
    }
    const auto version = request.find("control");
    if (version == request.end() || !version->is_number_unsigned() ||
        version->get<std::uint64_t>() != kControlProtocol) {
        return error_reply("unsupported control protocol");
    }
    const auto name = request.find("request");
    if (name == request.end() || !name->is_string() || request.size() != 2U) {
        return error_reply("a request holds exactly control and request");
    }
    if (name->get_ref<const std::string&>() != "status") {
        return error_reply("unknown request");
    }
    std::string reply;
    try {
        reply = status();
    } catch (...) {
        return error_reply("status is unavailable");
    }
    if (reply.size() >= kControlReplyBytes)
        return error_reply("status is too large");
    return reply;
}

void ControlServer::State::adopt(LocalListener::Connection accepted) noexcept {
    try {
        auto connection = std::make_shared<Connection>(
            weak_from_this(), std::move(accepted.channel), context->executor());
        connections.push_back(connection);
        connection->start();
    } catch (...) {
    }
}

void ControlServer::State::remove(const Connection* connection) noexcept {
    connections.remove_if(
        [connection](const auto& value) { return value.get() == connection; });
    if (listener && !closing) listener->resume();
}

void ControlServer::State::stop(Status status) noexcept {
    if (closing) return;
    failure = status.code();
    auto stopped = std::move(on_failure);
    close();
    if (stopped) {
        try {
            stopped(std::move(status));
        } catch (...) {
        }
    }
}

void ControlServer::State::close() noexcept {
    if (closing) return;
    closing = true;
    if (listener) listener->close();
    auto current = std::move(connections);
    connections.clear();
    for (const auto& connection : current) connection->close();
    if (channels) channels->cancel();
    on_failure = {};
}

Result<std::shared_ptr<ControlServer>> ControlServer::open(
    std::shared_ptr<providers::AsioExecutionContext> context,
    const std::filesystem::path& path, ControlStatusSource status,
    std::function<void(Status)> on_failure) {
    using Opened = Result<std::shared_ptr<ControlServer>>;
    if (!context || !status || path.empty())
        return Opened(Status(StatusCode::InvalidArgument));
    try {
        providers::AsioTcpChannelLimits limits;
        limits.max_active_channels = kControlConnections;
        auto channels =
            providers::AsioTcpAcceptedChannelOwner::create(context, limits);
        if (!channels.ok()) return Opened(channels.status());
        auto state = std::make_shared<State>();
        state->context = std::move(context);
        state->status = std::move(status);
        state->channels = std::move(channels).take_value();
        auto listener =
            LocalListener::open(state->context, LocalListener::Unix{path},
                                state->channels, "control socket");
        if (!listener.ok()) return Opened(listener.status());
        state->listener = std::move(listener).take_value();
        auto result = std::shared_ptr<ControlServer>(new ControlServer(state));
        const std::weak_ptr<State> weak = state;
        state->listener->start(
            [weak](LocalListener::Connection connection) {
                if (const auto self = weak.lock())
                    self->adopt(std::move(connection));
            },
            [weak] {
                const auto self = weak.lock();
                return !self || self->closing ||
                       self->connections.size() >= kControlConnections;
            },
            [weak](Status failed) {
                if (const auto self = weak.lock())
                    self->stop(std::move(failed));
            });
        if (state->closing) return Opened(Status(state->failure));
        state->on_failure = std::move(on_failure);
        return Opened(std::move(result));
    } catch (const std::bad_alloc&) {
        return Opened(Status(StatusCode::ResourceExhausted));
    } catch (...) {
        return Opened(Status(StatusCode::Internal));
    }
}

ControlServer::ControlServer(std::shared_ptr<State> state) noexcept
    : state_(std::move(state)) {}

ControlServer::~ControlServer() noexcept {
    close();
}

void ControlServer::close() noexcept {
    state_->close();
}

std::string client_status_reply(const NativeClientStatus& status,
                                const ClientControlView& view,
                                Clock::time_point now) {
    Json reply{
        {"control", kControlProtocol},
        {"program", "yume"},
        {"version", kVersion},
        {"state", state_name(status.state)},
        {"server", {{"host", view.server_host}, {"port", view.server_port}}},
        {"sessions", status.sessions},
        {"failed_attempts", status.failed_attempts},
        {"traffic",
         {{"payload_bytes_sent", status.traffic.payload_bytes_sent},
          {"payload_bytes_received", status.traffic.payload_bytes_received},
          {"record_bytes_sent", status.traffic.record_bytes_sent},
          {"record_bytes_received", status.traffic.record_bytes_received}}}};
    if (status.state == NativeClientState::Connected) {
        reply["server_identity"] = status.server_identity;
        const auto up = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - status.connected_since);
        reply["connected_ms"] = std::max<std::int64_t>(up.count(), 0);
    }
    if (status.state == NativeClientState::Waiting) {
        reply["retry_ms"] =
            std::max<std::int64_t>(status.retry_delay.count(), 0);
    }
    if (status.last_failure.ok()) {
        reply["last_failure"] = nullptr;
    } else {
        reply["last_failure"] = {
            {"code", code_name(status.last_failure.code())},
            {"message", status.last_failure.message()}};
    }
    Json socks5 = Json::array();
    for (const auto& endpoint : view.socks5)
        socks5.push_back(endpoint_text(endpoint));
    reply["socks5"] = std::move(socks5);
    Json forwards = Json::array();
    for (const auto& endpoint : view.forwards)
        forwards.push_back(endpoint_text(endpoint));
    for (const auto& path : view.unix_forwards) forwards.push_back(path);
    reply["forwards"] = std::move(forwards);
    return dump(reply);
}

Result<std::string> query_control_status(const std::filesystem::path& path,
                                         std::chrono::milliseconds timeout) {
    using Queried = Result<std::string>;
    const std::string& name = path.native();
    sockaddr_un address{};
    if (name.empty() || name.size() >= sizeof(address.sun_path)) {
        return Queried(Status::diagnostic(
            StatusCode::InvalidArgument,
            "the control socket path does not fit a socket"));
    }
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, name.data(), name.size());
    const int fd =
        ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        return Queried(Status::diagnostic(StatusCode::ResourceExhausted,
                                          "cannot create a socket"));
    }
    struct Descriptor final {
        int fd;
        ~Descriptor() { ::close(fd); }
    } descriptor{fd};
    const auto deadline = Clock::now() + timeout;
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&address),
                  sizeof(address)) != 0) {
        if (errno == ENOENT || errno == ECONNREFUSED) {
            return Queried(Status::diagnostic(
                StatusCode::NotFound, "nothing listens on the control socket"));
        }
        if (errno == EACCES || errno == EPERM) {
            return Queried(
                Status::diagnostic(StatusCode::PermissionDenied,
                                   "the control socket is not accessible"));
        }
        if (errno == EAGAIN) {
            return Queried(Status::diagnostic(StatusCode::ResourceExhausted,
                                              "the control socket is busy"));
        }
        return Queried(Status::diagnostic(
            StatusCode::Internal, "cannot connect to the control socket"));
    }
    ucred peer{};
    socklen_t size = sizeof(peer);
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) != 0 ||
        size != sizeof(peer) || peer.uid != ::geteuid()) {
        return Queried(
            Status::diagnostic(StatusCode::PermissionDenied,
                               "the control socket belongs to another user"));
    }
    constexpr std::string_view request =
        "{\"control\":1,\"request\":\"status\"}\n";
    std::size_t sent = 0U;
    while (sent < request.size()) {
        if (!wait_ready(fd, POLLOUT, deadline)) {
            return Queried(Status::diagnostic(
                StatusCode::Cancelled,
                "the control socket did not answer in time"));
        }
        const auto count = ::send(fd, request.data() + sent,
                                  request.size() - sent, MSG_NOSIGNAL);
        if (count < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (count <= 0) {
            return Queried(Status::diagnostic(
                StatusCode::Closed, "the control socket closed the request"));
        }
        sent += static_cast<std::size_t>(count);
    }
    std::string reply;
    char chunk[4096];
    for (;;) {
        if (!wait_ready(fd, POLLIN, deadline)) {
            return Queried(Status::diagnostic(
                StatusCode::Cancelled,
                "the control socket did not answer in time"));
        }
        const auto count = ::recv(fd, chunk, sizeof(chunk), 0);
        if (count < 0 && (errno == EAGAIN || errno == EINTR)) continue;
        if (count < 0) {
            return Queried(Status::diagnostic(
                StatusCode::Closed, "the control socket failed the reply"));
        }
        if (count == 0) break;
        reply.append(chunk, static_cast<std::size_t>(count));
        if (reply.size() > kControlReplyBytes) {
            return Queried(
                Status::diagnostic(StatusCode::ResourceExhausted,
                                   "the control reply is too large"));
        }
    }
    if (reply.empty() || reply.back() != '\n' ||
        reply.find('\n') != reply.size() - 1U) {
        return Queried(Status::diagnostic(StatusCode::Closed,
                                          "the control reply is incomplete"));
    }
    reply.pop_back();
    return Queried(std::move(reply));
}

Result<std::string> status_reply_text(std::string_view reply) {
    using Text = Result<std::string>;
    const Json status = Json::parse(reply, nullptr, false);
    const auto version =
        status.is_object() ? status.find("control") : status.end();
    if (status.is_discarded() || !status.is_object() ||
        version == status.end() || !version->is_number_unsigned() ||
        version->get<std::uint64_t>() != kControlProtocol) {
        return Text(
            Status::diagnostic(StatusCode::FailedPrecondition,
                               "the control reply is not control protocol 1"));
    }
    if (const auto error = status.find("error"); error != status.end()) {
        return Text(Status::diagnostic(
            StatusCode::FailedPrecondition,
            "the control socket refused the request: " +
                (error->is_string() ? error->get<std::string>()
                                    : std::string("?"))));
    }
    try {
        const auto& server = status.at("server");
        const auto& traffic = status.at("traffic");
        const std::string state = status.at("state").get<std::string>();
        std::string text = status.at("program").get<std::string>() + " " +
                           status.at("version").get<std::string>() + "\n";
        text += "state: " + state;
        if (state == "connected") {
            text +=
                " for " +
                duration_text(status.at("connected_ms").get<std::uint64_t>());
        } else if (state == "waiting") {
            text += ", next attempt in " +
                    duration_text(status.at("retry_ms").get<std::uint64_t>());
        }
        text += "\nserver: " + server.at("host").get<std::string>() + " port " +
                std::to_string(server.at("port").get<std::uint32_t>()) + "\n";
        if (const auto identity = status.find("server_identity");
            identity != status.end()) {
            text += "server identity: " + identity->get<std::string>() + "\n";
        }
        text +=
            "sessions: " +
            std::to_string(status.at("sessions").get<std::uint64_t>()) +
            ", failed attempts since the last: " +
            std::to_string(status.at("failed_attempts").get<std::uint64_t>()) +
            "\n";
        text +=
            "sent: " +
            byte_text(traffic.at("payload_bytes_sent").get<std::uint64_t>()) +
            " of payload in " +
            byte_text(traffic.at("record_bytes_sent").get<std::uint64_t>()) +
            " of records\n";
        text += "received: " +
                byte_text(
                    traffic.at("payload_bytes_received").get<std::uint64_t>()) +
                " of payload in " +
                byte_text(
                    traffic.at("record_bytes_received").get<std::uint64_t>()) +
                " of records\n";
        for (const auto& endpoint : status.at("socks5")) {
            text += "SOCKS5: " + endpoint.get<std::string>() + "\n";
        }
        for (const auto& forward : status.at("forwards")) {
            text += "forward: " + forward.get<std::string>() + "\n";
        }
        if (const auto& failure = status.at("last_failure");
            !failure.is_null()) {
            text += "last failure: " + failure.at("code").get<std::string>();
            const auto message = failure.at("message").get<std::string>();
            if (!message.empty()) text += ", " + message;
            text += "\n";
        }
        return Text(std::move(text));
    } catch (const std::bad_alloc&) {
        return Text(Status(StatusCode::ResourceExhausted));
    } catch (...) {
        return Text(
            Status::diagnostic(StatusCode::FailedPrecondition,
                               "the control reply is missing a status field"));
    }
}

}  // namespace yume::runtime
