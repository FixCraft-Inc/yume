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
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
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
#include "providers/openssl_security_provider.hpp"
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

// code is what a client acts on, and text is for people.
std::string error_reply(std::string_view code, std::string_view text) {
    return dump(
        Json{{"control", kControlProtocol}, {"error", text}, {"code", code}});
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

std::string utc_text(std::chrono::system_clock::time_point when) {
    const std::time_t seconds = std::chrono::system_clock::to_time_t(when);
    std::tm parts{};
    char text[32] = "?";
    if (::gmtime_r(&seconds, &parts) != nullptr)
        static_cast<void>(
            std::strftime(text, sizeof(text), "%Y-%m-%dT%H:%M:%SZ", &parts));
    return text;
}

// UTC with milliseconds, "2026-09-30T12:00:00.250Z".
std::string utc_ms_text(std::chrono::system_clock::time_point when) {
    const auto since = when.time_since_epoch();
    const auto seconds = std::chrono::floor<std::chrono::seconds>(since);
    const auto millis =
        std::chrono::duration_cast<std::chrono::milliseconds>(since - seconds)
            .count();
    std::string text = utc_text(std::chrono::system_clock::time_point(
        std::chrono::duration_cast<std::chrono::system_clock::duration>(
            seconds)));
    if (text.size() != 20U) return text;
    char fraction[8];
    static_cast<void>(std::snprintf(fraction, sizeof(fraction), ".%03dZ",
                                    static_cast<int>(millis)));
    text.pop_back();
    return text + fraction;
}

std::int64_t elapsed_ms(Clock::time_point since, Clock::time_point now) {
    return std::max<std::int64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now - since)
            .count(),
        0);
}

// A failure's code and message, the message cut to a bound so that a
// reply naming every cluster peer stays within kControlReplyBytes.
Json failure_json(const Status& failure) {
    if (failure.ok()) return nullptr;
    constexpr std::size_t kMaxMessage = 160U;
    return {{"code", code_name(failure.code())},
            {"message", failure.message().substr(0U, kMaxMessage)}};
}

std::string failure_text(const Json& failure) {
    std::string text = failure.at("code").get<std::string>();
    const auto message = failure.at("message").get<std::string>();
    if (!message.empty()) text += ", " + message;
    return text;
}

// A client's circuits: the length in use against the configured one, each
// route by name and any proposal of a shorter route.
std::string circuits_client_text(const Json& circuits) {
    const auto count = [&](const Json& value, const char* key) {
        return std::to_string(value.at(key).get<std::uint64_t>());
    };
    const auto names = [](const Json& nodes) {
        std::string text;
        for (const auto& node : nodes) {
            if (!text.empty()) text += " > ";
            text += node.get<std::string>();
        }
        return text;
    };
    const auto hops = [&](const Json& value, const char* key) {
        const auto number = value.at(key).get<std::uint64_t>();
        return std::to_string(number) + (number == 1U ? " hop" : " hops");
    };
    std::string text = circuits.at("current_hops").get<std::uint64_t>() == 0U
                           ? "circuits: no route in use, " +
                                 hops(circuits, "hops") + " configured"
                           : "circuits: " + hops(circuits, "current_hops") +
                                 " in use of " + count(circuits, "hops") +
                                 " configured";
    if (circuits.at("accepted_hops").get<std::uint64_t>() != 0U)
        text += ", " + count(circuits, "accepted_hops") + " accepted";
    if (circuits.at("min_hops").get<std::uint64_t>() <
        circuits.at("hops").get<std::uint64_t>())
        text += ", down to " + count(circuits, "min_hops") +
                " approved in the configuration";
    text += ", plain HTTP " +
            std::string(circuits.at("plain_http") == "allow" ? "allowed"
                                                             : "refused") +
            ", routes view serial " + count(circuits, "serial") + "\n";
    if (const auto& stopped = circuits.at("stopped"); !stopped.is_null())
        text += "circuits stopped: " + stopped.get<std::string>() + "\n";
    for (const auto& route : circuits.at("routes")) {
        text += "circuit " + names(route.at("nodes")) + ": " +
                duration_text(route.at("age_ms").get<std::uint64_t>()) +
                " old, " + count(route, "streams") + " streams\n";
    }
    if (const auto& proposal = circuits.at("proposal"); !proposal.is_null()) {
        text += "proposed route of " + hops(proposal, "hops") + ": " +
                names(proposal.at("nodes"));
        if (const auto latency = proposal.find("latency_ms");
            latency != proposal.end())
            text += ", measured " +
                    std::to_string(latency->get<std::uint64_t>()) + " ms";
        text += "\n  " + proposal.at("gives_up").get<std::string>() +
                "\n  accept it with: yume --config <path> --accept-route " +
                proposal.at("id").get<std::string>() + "\n";
    }
    return text;
}

std::string client_text(const Json& status) {
    const auto& server = status.at("server");
    const auto& traffic = status.at("traffic");
    const std::string state = status.at("state").get<std::string>();
    std::string text = status.at("program").get<std::string>() + " " +
                       status.at("version").get<std::string>() + "\n";
    text += "state: " + state;
    if (state == "connected") {
        text += " for " +
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
    text += "sessions: " +
            std::to_string(status.at("sessions").get<std::uint64_t>()) +
            ", failed attempts since the last: " +
            std::to_string(status.at("failed_attempts").get<std::uint64_t>()) +
            "\n";
    text += "sent: " +
            byte_text(traffic.at("payload_bytes_sent").get<std::uint64_t>()) +
            " of payload in " +
            byte_text(traffic.at("record_bytes_sent").get<std::uint64_t>()) +
            " of records\n";
    text +=
        "received: " +
        byte_text(traffic.at("payload_bytes_received").get<std::uint64_t>()) +
        " of payload in " +
        byte_text(traffic.at("record_bytes_received").get<std::uint64_t>()) +
        " of records\n";
    for (const auto& endpoint : status.at("socks5")) {
        text += "SOCKS5: " + endpoint.get<std::string>() + "\n";
    }
    for (const auto& forward : status.at("forwards")) {
        text += "forward: " + forward.get<std::string>() + "\n";
    }
    if (const auto& failure = status.at("last_failure"); !failure.is_null()) {
        text += "last failure: " + failure_text(failure) + "\n";
    }
    if (const auto circuits = status.find("circuits");
        circuits != status.end() && !circuits->is_null()) {
        text += circuits_client_text(*circuits);
    }
    return text;
}

std::string link_text(const Json& link) {
    const auto& outbound = link.at("outbound");
    const auto& inbound = link.at("inbound");
    const std::string state = outbound.at("state").get<std::string>();
    std::string text =
        "link " + link.at("peer").get<std::string>() + ": outbound " + state;
    if (state == "connected") {
        text += " for " +
                duration_text(outbound.at("connected_ms").get<std::uint64_t>());
    } else if (state == "waiting") {
        text += ", next attempt in " +
                duration_text(outbound.at("retry_ms").get<std::uint64_t>());
    }
    if (const auto& failure = outbound.at("last_failure");
        !failure.is_null() && state != "connected") {
        text += " (last failure: " + failure_text(failure) + ")";
    }
    const auto sessions = inbound.at("sessions").get<std::uint64_t>();
    if (sessions == 0U) {
        text += ", inbound none";
    } else {
        text +=
            ", inbound " + std::to_string(sessions) +
            (sessions == 1U ? " session for " : " sessions, the oldest for ") +
            duration_text(inbound.at("connected_ms").get<std::uint64_t>());
    }
    const auto& circuits = link.at("circuits");
    text += ", circuits in " +
            std::to_string(circuits.at("in").get<std::uint64_t>()) + " out " +
            std::to_string(circuits.at("out").get<std::uint64_t>());
    return text + "\n";
}

std::string circuits_text(const Json& circuits) {
    const auto count = [&](const Json& value, const char* key) {
        return std::to_string(value.at(key).get<std::uint64_t>());
    };
    const auto& refused = circuits.at("refused");
    return "circuits: " + count(circuits, "open") + " open, " +
           count(circuits, "entry") + " as entry, " +
           count(circuits, "relayed") + " relayed, " +
           (circuits.at("exit").get<bool>()
                ? count(circuits, "exit_streams") + " exit streams"
                : std::string("not an exit")) +
           "\ncircuits refused: " + count(refused, "total") +
           " (client circuits " + count(refused, "client_circuits") +
           ", circuit rate " + count(refused, "circuit_rate") +
           ", handshakes " + count(refused, "handshakes") + ", streams " +
           count(refused, "streams") + "), failed " +
           count(circuits, "failed") + "\n";
}

std::string server_text(const Json& status) {
    std::string text = status.at("program").get<std::string>() + " " +
                       status.at("version").get<std::string>() + "\n";
    for (const auto& listener : status.at("listeners")) {
        text += "listening: " + listener.get<std::string>() + "\n";
    }
    text += "client sessions: " +
            std::to_string(status.at("client_sessions").get<std::uint64_t>()) +
            "\n";
    const auto& cluster = status.at("cluster");
    if (cluster.is_null()) return text;
    text += "cluster: " + cluster.at("id").get<std::string>() + " serial " +
            std::to_string(cluster.at("serial").get<std::uint64_t>()) +
            (cluster.at("expired").get<bool>() ? ", expired at "
                                               : ", valid until ") +
            cluster.at("not_after").get<std::string>() + "\n";
    text += "this node: " + cluster.at("self").get<std::string>() + "\n";
    text += circuits_text(cluster.at("circuits"));
    for (const auto& link : cluster.at("links")) text += link_text(link);
    return text;
}

}  // namespace

struct ControlServer::State final : std::enable_shared_from_this<State> {
    class Connection;

    // A reply, and whether the program stops once it has been written.
    struct Reply final {
        std::string text;
        bool stop{false};
    };

    void adopt(LocalListener::Connection accepted) noexcept;
    void remove(const Connection* connection) noexcept;
    void stop(Status status) noexcept;
    void close() noexcept;
    void stop_requested() noexcept;
    std::string requests_field() const;
    Reply reply_to(std::string_view line);

    std::shared_ptr<providers::AsioExecutionContext> context;
    ControlStatusSource status;
    ControlRequests requests;
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
                send({error_reply("malformed", "the request is too long")});
                return;
            }
        } catch (...) {
            finish();
            return;
        }
        read();
    }

    // A stop reply stops the program once it is written, or once writing
    // fails because the client left, since the request itself was valid.
    void send(State::Reply reply) noexcept {
        const bool stop = reply.stop;
        try {
            reply.text.push_back('\n');
            auto buffer = Buffer::copy_from(
                std::as_bytes(std::span(reply.text)), reply.text.size());
            if (!buffer.ok()) {
                finish();
                if (stop) stop_owner();
                return;
            }
            replying_ = true;
            channel_->async_write(
                std::move(buffer).take_value(), {},
                [self = shared_from_this(), stop](Status,
                                                  std::size_t) noexcept {
                    if (self->channel_)
                        static_cast<void>(self->channel_->shutdown_write());
                    self->finish();
                    if (stop) self->stop_owner();
                });
        } catch (...) {
            finish();
            if (stop) stop_owner();
        }
    }

    void stop_owner() noexcept {
        if (const auto owner = owner_.lock()) owner->stop_requested();
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

// The requests this server takes, as the status reply's "requests" member.
std::string ControlServer::State::requests_field() const {
    std::string field = R"("requests":["status")";
    if (requests.accept_route) field += R"(,"accept-route")";
    if (requests.messages) field += R"(,"messages")";
    if (requests.stop) field += R"(,"stop")";
    return field + "]";
}

ControlServer::State::Reply ControlServer::State::reply_to(
    std::string_view line) {
    const Json request = Json::parse(line, nullptr, false);
    if (request.is_discarded() || !request.is_object()) {
        return {error_reply("malformed", "the request is not a JSON object")};
    }
    const auto version = request.find("control");
    if (version == request.end() || !version->is_number_unsigned() ||
        version->get<std::uint64_t>() != kControlProtocol) {
        return {error_reply("unsupported", "unsupported control protocol")};
    }
    const auto name = request.find("request");
    if (name == request.end() || !name->is_string()) {
        return {error_reply("malformed",
                            "a request holds exactly control and request")};
    }
    const auto& requested = name->get_ref<const std::string&>();
    if (requested == "accept-route" && requests.accept_route) {
        const auto id = request.find("id");
        if (request.size() != 3U || id == request.end() || !id->is_string() ||
            id->get_ref<const std::string&>().size() > 64U) {
            return {error_reply(
                "malformed",
                "accept-route holds exactly control, request and id")};
        }
        Status accepted(StatusCode::Internal);
        try {
            accepted = requests.accept_route(id->get_ref<const std::string&>());
        } catch (...) {
        }
        if (!accepted.ok()) {
            return {
                accepted.code() == StatusCode::NotFound
                    ? error_reply("not_found", "no route proposal has that id")
                    : error_reply("failed", "the route could not be accepted")};
        }
        return {Json{{"control", kControlProtocol}, {"accepted", *id}}.dump()};
    }
    if (requested == "messages" && requests.messages) {
        const auto after = request.find("after");
        if (request.size() != 3U || after == request.end() ||
            !after->is_number_unsigned()) {
            return {error_reply(
                "malformed",
                "messages holds exactly control, request and after")};
        }
        return {
            messages_reply(*requests.messages, after->get<std::uint64_t>())};
    }
    if (requested == "stop" && requests.stop) {
        if (request.size() != 2U) {
            return {error_reply("malformed",
                                "a request holds exactly control and request")};
        }
        return {Json{{"control", kControlProtocol}, {"stopping", true}}.dump(),
                true};
    }
    if (requested != "status") {
        return {error_reply("unknown_request", "unknown request")};
    }
    if (request.size() != 2U) {
        return {error_reply("malformed",
                            "a request holds exactly control and request")};
    }
    std::string reply;
    try {
        reply = status();
    } catch (...) {
        return {error_reply("unavailable", "status is unavailable")};
    }
    // Every status reply names the requests this server takes, so a client
    // can tell what an older program lacks before it asks.
    if (reply.size() < 2U || reply.front() != '{' || reply.back() != '}')
        return {error_reply("unavailable", "status is unavailable")};
    reply.insert(1U, requests_field() + (reply.size() > 2U ? "," : ""));
    if (reply.size() >= kControlReplyBytes)
        return {error_reply("unavailable", "status is too large")};
    return {std::move(reply)};
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

void ControlServer::State::stop_requested() noexcept {
    if (closing || !requests.stop) return;
    try {
        requests.stop();
    } catch (...) {
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
    std::function<void(Status)> on_failure, ControlRequests requests) {
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
        state->requests = std::move(requests);
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

std::string client_status_reply(
    const NativeClientStatus& status, const ClientControlView& view,
    Clock::time_point now, const std::optional<CircuitPoolStatus>& circuits) {
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
    Json posture{
        {"transport", kYtpVersion},
        {"suite", kTransportSuite},
        {"evidence_profile", kEvidenceProfile},
        {"security", providers::kOpenSslSecurityProviderId},
        {"crypto_backend", providers::openssl_crypto_backend()},
        {"limits",
         {{"max_queued_bytes", view.max_queued_bytes},
          {"max_epoch_bytes", view.max_epoch_bytes},
          {"credit_returns_per_window", view.credit_returns_per_window},
          {"idle_epoch_rotation", view.idle_epoch_rotation}}}};
    if (status.state == NativeClientState::Connected && status.epoch_bytes)
        posture["epoch_bytes"] = *status.epoch_bytes;
    reply["posture"] = std::move(posture);
    reply["circuits"] = nullptr;
    if (circuits) {
        Json routes = Json::array();
        for (const auto& route : circuits->circuits) {
            routes.push_back({{"nodes", route.nodes},
                              {"age_ms", elapsed_ms(route.built, now)},
                              {"streams", route.streams}});
        }
        Json proposal = nullptr;
        if (const auto& offered = circuits->proposal) {
            proposal = {{"id", offered->id},
                        {"hops", offered->hops},
                        {"nodes", offered->nodes},
                        {"serial", offered->serial},
                        {"gives_up", shorter_route_cost(offered->hops)}};
            if (offered->latency)
                proposal["latency_ms"] = offered->latency->count();
        }
        reply["circuits"] = {
            {"hops", circuits->hops},
            {"min_hops", circuits->min_hops},
            {"accepted_hops", circuits->accepted_hops},
            {"current_hops", circuits->current_hops},
            {"plain_http", circuits->plain_http_allowed ? "allow" : "refuse"},
            {"serial", circuits->serial},
            {"stopped", circuits->stopped.empty() ? Json(nullptr)
                                                  : Json(circuits->stopped)},
            {"routes", std::move(routes)},
            {"proposal", std::move(proposal)}};
    }
    return dump(reply);
}

std::string server_status_reply(const NativeServerStatus& status,
                                Clock::time_point now) {
    Json listeners = Json::array();
    for (const auto& endpoint : status.listeners)
        listeners.push_back(endpoint_text(endpoint));
    Json reply{{"control", kControlProtocol},
               {"program", "yumed"},
               {"version", kVersion},
               {"listeners", std::move(listeners)},
               {"client_sessions", status.client_sessions},
               {"cluster", nullptr}};
    if (!status.cluster) return dump(reply);
    const auto& cluster = *status.cluster;
    Json links = Json::array();
    for (const auto& link : cluster.links) {
        const auto& outbound = link.outbound;
        Json out{{"state", state_name(outbound.state)},
                 {"sessions", outbound.sessions},
                 {"failed_attempts", outbound.failed_attempts},
                 {"last_failure", failure_json(outbound.last_failure)}};
        if (outbound.state == NativeClientState::Connected)
            out["connected_ms"] = elapsed_ms(outbound.connected_since, now);
        if (outbound.state == NativeClientState::Waiting)
            out["retry_ms"] =
                std::max<std::int64_t>(outbound.retry_delay.count(), 0);
        Json in{{"sessions", link.inbound_sessions}};
        if (link.inbound_sessions != 0U)
            in["connected_ms"] = elapsed_ms(link.inbound_since, now);
        links.push_back(
            {{"peer", link.peer_name},
             {"identity", link.peer_identity},
             {"outbound", std::move(out)},
             {"inbound", std::move(in)},
             {"circuits",
              {{"in", link.circuits_in}, {"out", link.circuits_out}}}});
    }
    const auto& circuits = cluster.circuits;
    reply["cluster"] = {
        {"id", cluster.cluster},
        {"serial", cluster.serial},
        {"not_after", utc_text(cluster.not_after)},
        {"expired", cluster.expired},
        {"self", cluster.self_name},
        {"links", std::move(links)},
        {"circuits",
         {{"exit", circuits.exit},
          {"open", circuits.circuits},
          {"entry", circuits.entry_circuits},
          {"relayed", circuits.relayed_circuits},
          {"exit_streams", circuits.exit_streams},
          {"failed", circuits.failed},
          {"refused",
           {{"total", circuits.refused},
            {"client_circuits", circuits.refused_client_circuits},
            {"circuit_rate", circuits.refused_circuit_rate},
            {"handshakes", circuits.refused_handshakes},
            {"streams", circuits.refused_streams}}}}}};
    return dump(reply);
}

std::string messages_reply(const MessageLog& log, std::uint64_t after) {
    const auto page = log.after(after);
    // The members around the messages, whose size the budget includes.
    const std::string head = R"({"control":1,"instance":")" +
                             std::string(log.instance()) + R"(","messages":[)";
    std::string body;
    std::size_t sent = 0U;
    for (const auto& entry : page.entries) {
        std::string item = dump(Json{{"seq", entry.seq},
                                     {"time", utc_ms_text(entry.time)},
                                     {"text", entry.text}});
        // 64 bytes cover the closing members and a separating comma.
        if (head.size() + body.size() + item.size() + 64U >
            kControlMessagesReplyBytes)
            break;
        if (!body.empty()) body.push_back(',');
        body += item;
        ++sent;
    }
    return head + body + R"(],"missed":)" + std::to_string(page.missed) +
           R"(,"more":)" + (sent < page.entries.size() ? "true" : "false") +
           "}";
}

namespace {

Result<std::string> query_control(const std::filesystem::path& path,
                                  std::string_view request,
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

}  // namespace

Result<std::string> query_control_status(const std::filesystem::path& path,
                                         std::chrono::milliseconds timeout) {
    return query_control(path, "{\"control\":1,\"request\":\"status\"}\n",
                         timeout);
}

Result<std::string> query_control_accept_route(
    const std::filesystem::path& path, std::string_view id,
    std::chrono::milliseconds timeout) {
    if (id.empty() || id.size() > 64U ||
        !std::all_of(id.begin(), id.end(), [](char ch) {
            return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
        })) {
        return Result<std::string>(
            Status::diagnostic(StatusCode::InvalidArgument,
                               "a route id is lowercase hexadecimal"));
    }
    const auto request = Json{{"control", kControlProtocol},
                              {"request", "accept-route"},
                              {"id", std::string(id)}}
                             .dump() +
                         "\n";
    return query_control(path, request, timeout);
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
    if (const auto accepted = status.find("accepted");
        accepted != status.end() && accepted->is_string()) {
        return Text("accepted route " + accepted->get<std::string>() + "\n");
    }
    try {
        const auto& program = status.at("program");
        return Text(program == "yumed" ? server_text(status)
                                       : client_text(status));
    } catch (const std::bad_alloc&) {
        return Text(Status(StatusCode::ResourceExhausted));
    } catch (...) {
        return Text(
            Status::diagnostic(StatusCode::FailedPrecondition,
                               "the control reply is missing a status field"));
    }
}

}  // namespace yume::runtime
