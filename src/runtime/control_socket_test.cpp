/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/control_socket.hpp"

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <future>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <boost/asio/post.hpp>
#include <nlohmann/json.hpp>

#include "common/version.hpp"

namespace {
using namespace std::chrono_literals;
using yume::engine::ExecutorAffinity;
using yume::engine::Result;
using yume::engine::Status;
using yume::engine::StatusCode;
using yume::providers::AsioExecutionContext;
using yume::runtime::ClientControlView;
using yume::runtime::ControlServer;
using yume::runtime::NativeClientState;
using yume::runtime::NativeClientStatus;
using yume::runtime::NativeLinkStatus;
using yume::runtime::NativeServerStatus;
using Json = nlohmann::json;

void check(bool condition, const char* description) {
    if (!condition) throw std::runtime_error(description);
}

template <typename T>
T require(Result<T> result) {
    check(result.ok(), "unexpected failure result");
    return std::move(result).take_value();
}

// A private directory under /tmp. Socket paths must stay short.
class Directory final {
public:
    Directory() {
        std::string pattern = "/tmp/yume-control-XXXXXX";
        check(::mkdtemp(pattern.data()) != nullptr, "mkdtemp failed");
        path = pattern;
    }
    ~Directory() {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }
    std::filesystem::path path;
};

class Runner final {
public:
    Runner()
        : context(
              require(AsioExecutionContext::create(ExecutorAffinity(17U)))) {
        thread_ = std::thread([this] { context->run(); });
    }
    ~Runner() {
        context->finish();
        if (thread_.joinable()) thread_.join();
    }
    template <typename F>
    auto sync(F fn) {
        using T = std::invoke_result_t<F>;
        std::promise<T> promise;
        auto future = promise.get_future();
        boost::asio::post(context->executor(), [&] {
            try {
                if constexpr (std::is_void_v<T>) {
                    fn();
                    promise.set_value();
                } else {
                    promise.set_value(fn());
                }
            } catch (...) {
                promise.set_exception(std::current_exception());
            }
        });
        return future.get();
    }
    std::shared_ptr<AsioExecutionContext> context;

private:
    std::thread thread_;
};

// A raw client: sends bytes, then reads until the server closes or a second
// passes. Returns what it read.
std::string exchange(const std::filesystem::path& path,
                     const std::string& request,
                     std::chrono::milliseconds quiet = 1000ms) {
    const int fd = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    check(fd >= 0, "socket failed");
    sockaddr_un address{};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path.c_str(), path.native().size());
    timeval wait{static_cast<time_t>(quiet.count() / 1000),
                 static_cast<suseconds_t>(quiet.count() % 1000 * 1000)};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &wait, sizeof(wait));
    check(::connect(fd, reinterpret_cast<const sockaddr*>(&address),
                    sizeof(address)) == 0,
          "connect failed");
    if (!request.empty()) {
        check(::send(fd, request.data(), request.size(), MSG_NOSIGNAL) ==
                  static_cast<ssize_t>(request.size()),
              "send failed");
    }
    std::string reply;
    char chunk[4096];
    for (;;) {
        const auto count = ::recv(fd, chunk, sizeof(chunk), 0);
        if (count <= 0) break;
        reply.append(chunk, static_cast<std::size_t>(count));
    }
    ::close(fd);
    return reply;
}

// An error reply's code and text, as "code: text".
std::string error_of(const std::string& reply) {
    check(!reply.empty() && reply.back() == '\n', "the reply is not one line");
    const Json value = Json::parse(reply);
    check(value.at("control") == 1 && value.size() == 3U,
          "the error reply has other keys");
    return value.at("code").get<std::string>() + ": " +
           value.at("error").get<std::string>();
}

NativeClientStatus connected_status(std::chrono::steady_clock::time_point now) {
    NativeClientStatus status;
    status.state = NativeClientState::Connected;
    status.server_identity = "sha256:0123";
    status.connected_since = now - 3723s;
    status.sessions = 3U;
    status.failed_attempts = 0U;
    status.last_failure = Status(StatusCode::Closed, "peer closed \xff");
    status.traffic.payload_bytes_sent = 1536U;
    status.traffic.payload_bytes_received = std::uint64_t{3} * 1024U * 1024U;
    status.traffic.record_bytes_sent = 2048U;
    status.traffic.record_bytes_received =
        std::uint64_t{3} * 1024U * 1024U + 4096U;
    return status;
}

ClientControlView view() {
    ClientControlView result;
    result.server_host = "origin.example.net";
    result.server_port = 443U;
    result.socks5.emplace_back(boost::asio::ip::make_address("127.0.0.1"),
                               1080U);
    result.forwards.emplace_back(boost::asio::ip::make_address("::1"), 2222U);
    result.unix_forwards.emplace_back("/run/user/1000/yume/chat.sock");
    return result;
}

// The reply names the state and only the fields that state has. Bytes that
// are not UTF-8 are replaced so the reply stays one JSON line.
void test_status_reply_fields() {
    const auto now = std::chrono::steady_clock::now();
    const Json connected = Json::parse(
        yume::runtime::client_status_reply(connected_status(now), view(), now));
    check(connected.at("control") == 1 && connected.at("program") == "yume" &&
              connected.at("state") == "connected" &&
              connected.at("connected_ms") == 3723000 &&
              connected.at("server_identity") == "sha256:0123" &&
              !connected.contains("retry_ms"),
          "the connected reply is wrong");
    check(connected.at("server") ==
              Json({{"host", "origin.example.net"}, {"port", 443}}),
          "the reply names the wrong server");
    check(connected.at("socks5") == Json::array({"127.0.0.1:1080"}) &&
              connected.at("forwards") ==
                  Json::array({"[::1]:2222", "/run/user/1000/yume/chat.sock"}),
          "the reply lists the wrong local listeners");
    check(connected.at("last_failure").at("code") == "closed" &&
              connected.at("last_failure").at("message") ==
                  "peer closed \xef\xbf\xbd",
          "the failure was not reported with its invalid byte replaced");
    NativeClientStatus waiting;
    waiting.state = NativeClientState::Waiting;
    waiting.retry_delay = 4000ms;
    const Json retry =
        Json::parse(yume::runtime::client_status_reply(waiting, view(), now));
    check(retry.at("state") == "waiting" && retry.at("retry_ms") == 4000 &&
              retry.at("last_failure").is_null() &&
              !retry.contains("server_identity"),
          "the waiting reply is wrong");
}

void test_status_text() {
    const auto now = std::chrono::steady_clock::now();
    const auto text = require(
        yume::runtime::status_reply_text(yume::runtime::client_status_reply(
            connected_status(now), view(), now)));
    const std::string expected =
        std::string("yume ") + yume::kVersion +
        "\n"
        "state: connected for 1 h 2 min 3 s\n"
        "server: origin.example.net port 443\n"
        "server identity: sha256:0123\n"
        "sessions: 3, failed attempts since the last: 0\n"
        "sent: 1.5 KiB of payload in 2.0 KiB of records\n"
        "received: 3.0 MiB of payload in 3.0 MiB of records\n"
        "SOCKS5: 127.0.0.1:1080\n"
        "forward: [::1]:2222\n"
        "forward: /run/user/1000/yume/chat.sock\n"
        "last failure: closed, peer closed \xef\xbf\xbd\n";
    check(text == expected, "the status text is wrong");
    const auto refused = yume::runtime::status_reply_text(
        R"({"control":1,"error":"unknown request"})");
    check(!refused.ok() && refused.status().message().find("unknown request") !=
                               std::string::npos,
          "an error reply was not reported");
    for (const char* reply :
         {"", "[]", R"({"control":"1"})", R"({"control":2})",
          R"({"control":1,"state":"idle"})"}) {
        check(!yume::runtime::status_reply_text(reply).ok(),
              "a bad reply was rendered");
    }

    // A client with circuits: the length in use, each route by name and a
    // proposal with what it gives up and how to accept it.
    yume::runtime::CircuitPoolStatus circuits;
    circuits.hops = 3U;
    circuits.min_hops = 2U;
    circuits.current_hops = 0U;
    circuits.serial = 7U;
    yume::runtime::CircuitRoute route;
    route.nodes = {"north", "east", "west"};
    route.built = now - 90s;
    route.streams = 2U;
    circuits.circuits.push_back(route);
    yume::runtime::RouteProposal proposal;
    proposal.id = "0011223344556677";
    proposal.hops = 1U;
    proposal.nodes = {"north"};
    proposal.serial = 7U;
    circuits.proposal = proposal;
    const Json reply = Json::parse(yume::runtime::client_status_reply(
        connected_status(now), view(), now, circuits));
    const auto& section = reply.at("circuits");
    check(
        section.at("hops") == 3 && section.at("min_hops") == 2 &&
            section.at("current_hops") == 0 &&
            section.at("plain_http") == "refuse" &&
            section.at("stopped").is_null() &&
            section.at("routes") ==
                Json::parse(
                    R"([{"nodes":["north","east","west"],"age_ms":90000,"streams":2}])") &&
            section.at("proposal").at("id") == "0011223344556677" &&
            section.at("proposal").at("hops") == 1 &&
            !section.at("proposal").contains("latency_ms"),
        "the circuits fields are wrong");
    check(Json::parse(yume::runtime::client_status_reply(connected_status(now),
                                                         view(), now))
              .at("circuits")
              .is_null(),
          "a client without circuits reported some");
    const auto shown = require(yume::runtime::status_reply_text(reply.dump()));
    check(
        shown.find(
            "circuits: no route in use, 3 hops configured, down to 2 approved "
            "in "
            "the configuration, plain HTTP refused, routes view serial 7\n"
            "circuit north > east > west: 1 min 30 s old, 2 streams\n"
            "proposed route of 1 hop: north\n"
            "  Your entry server sees both who you are") != std::string::npos &&
            shown.find("accept it with: yume --config <path> --accept-route "
                       "0011223344556677\n") != std::string::npos,
        "the circuits text is wrong");
}

// A server reply names its listeners and client sessions, and with a cluster
// the list's serial and expiry and each peer's outbound link and inbound
// sessions.
void test_server_status() {
    const auto now = std::chrono::steady_clock::now();
    NativeServerStatus status;
    status.listeners.emplace_back(boost::asio::ip::make_address("192.0.2.1"),
                                  443U);
    status.listeners.emplace_back(boost::asio::ip::make_address("2001:db8::1"),
                                  443U);
    status.client_sessions = 5U;
    const Json plain =
        Json::parse(yume::runtime::server_status_reply(status, now));
    check(plain.at("program") == "yumed" && plain.at("client_sessions") == 5 &&
              plain.at("listeners") ==
                  Json::array({"192.0.2.1:443", "[2001:db8::1]:443"}) &&
              plain.at("cluster").is_null(),
          "the server reply without a cluster is wrong");
    const std::string expected_plain = std::string("yumed ") + yume::kVersion +
                                       "\n"
                                       "listening: 192.0.2.1:443\n"
                                       "listening: [2001:db8::1]:443\n"
                                       "client sessions: 5\n";
    check(
        require(yume::runtime::status_reply_text(
            yume::runtime::server_status_reply(status, now))) == expected_plain,
        "the server status text without a cluster is wrong");

    auto& cluster = status.cluster.emplace();
    cluster.cluster = std::string(64, 'c');
    cluster.serial = 7U;
    cluster.not_after = std::chrono::system_clock::from_time_t(4102444800);
    cluster.self_name = "gloomy-data";
    NativeLinkStatus up;
    up.peer_name = "sweet-fox";
    up.peer_identity = std::string(64, 'a');
    up.outbound = connected_status(now);
    up.inbound_sessions = 2U;
    up.inbound_since = now - 65s;
    up.circuits_in = 3U;
    up.circuits_out = 1U;
    NativeLinkStatus down;
    down.peer_name = "far-owl";
    down.peer_identity = std::string(64, 'b');
    down.outbound.state = NativeClientState::Waiting;
    down.outbound.retry_delay = 4000ms;
    down.outbound.failed_attempts = 2U;
    down.outbound.last_failure =
        Status(StatusCode::Closed, std::string(400, 'x'));
    cluster.links = {up, down};
    auto& circuits = cluster.circuits;
    circuits.exit = true;
    circuits.circuits = 5U;
    circuits.entry_circuits = 2U;
    circuits.relayed_circuits = 1U;
    circuits.exit_streams = 9U;
    circuits.refused = 6U;
    circuits.refused_client_circuits = 1U;
    circuits.refused_circuit_rate = 2U;
    circuits.refused_handshakes = 3U;
    circuits.failed = 4U;
    const Json reply =
        Json::parse(yume::runtime::server_status_reply(status, now));
    const auto& links = reply.at("cluster").at("links");
    check(reply.at("cluster").at("serial") == 7 &&
              reply.at("cluster").at("not_after") == "2100-01-01T00:00:00Z" &&
              reply.at("cluster").at("expired") == false &&
              reply.at("cluster").at("self") == "gloomy-data" &&
              links.size() == 2U,
          "the cluster header is wrong");
    check(links[0].at("peer") == "sweet-fox" &&
              links[0].at("outbound").at("state") == "connected" &&
              links[0].at("outbound").at("connected_ms") == 3723000 &&
              links[0].at("inbound") ==
                  Json({{"sessions", 2}, {"connected_ms", 65000}}),
          "the connected link is wrong");
    check(links[1].at("outbound").at("state") == "waiting" &&
              links[1].at("outbound").at("retry_ms") == 4000 &&
              links[1].at("outbound")
                      .at("last_failure")
                      .at("message")
                      .get<std::string>()
                      .size() == 160U &&
              links[1].at("inbound") == Json({{"sessions", 0}}),
          "the waiting link is wrong");
    check(links[0].at("circuits") == Json({{"in", 3}, {"out", 1}}) &&
              links[1].at("circuits") == Json({{"in", 0}, {"out", 0}}) &&
              reply.at("cluster").at("circuits") ==
                  Json({{"exit", true},
                        {"open", 5},
                        {"entry", 2},
                        {"relayed", 1},
                        {"exit_streams", 9},
                        {"failed", 4},
                        {"refused",
                         {{"total", 6},
                          {"client_circuits", 1},
                          {"circuit_rate", 2},
                          {"handshakes", 3},
                          {"streams", 0}}}}),
          "the circuit counts are wrong");
    down.outbound.last_failure = Status(StatusCode::Closed, "peer closed");
    cluster.links = {up, down};
    cluster.expired = true;
    const std::string expected =
        expected_plain + "cluster: " + std::string(64, 'c') +
        " serial 7, expired at 2100-01-01T00:00:00Z\n"
        "this node: gloomy-data\n"
        "circuits: 5 open, 2 as entry, 1 relayed, 9 exit streams\n"
        "circuits refused: 6 (client circuits 1, circuit rate 2, handshakes 3, "
        "streams 0), failed 4\n"
        "link sweet-fox: outbound connected for 1 h 2 min 3 s, "
        "inbound 2 sessions, the oldest for 1 min 5 s, circuits in 3 out 1\n"
        "link far-owl: outbound waiting, next attempt in 4 s "
        "(last failure: closed, peer closed), inbound none, circuits in 0 out "
        "0\n";
    check(require(yume::runtime::status_reply_text(
              yume::runtime::server_status_reply(status, now))) == expected,
          "the cluster status text is wrong");
}

// A status request gets the source's reply and nothing else answers it.
void test_requests_and_errors() {
    Directory directory;
    Runner runner;
    const auto path = directory.path / "control.sock";
    std::atomic<int> calls{0};
    auto server = runner.sync([&] {
        return require(ControlServer::open(runner.context, path, [&calls] {
            if (calls++ == 1) throw std::runtime_error("status failed");
            return std::string(R"({"control":1,"state":"idle"})");
        }));
    });
    struct stat info{};
    check(::stat(path.c_str(), &info) == 0 && (info.st_mode & 0777) == 0600,
          "the control socket is not mode 0600");
    // The server names the requests it takes in every status reply.
    check(require(yume::runtime::query_control_status(path, 2000ms)) ==
              R"({"requests":["status"],"control":1,"state":"idle"})",
          "the status reply was not returned");
    check(
        error_of(exchange(path, "{\"control\":1,\"request\":\"status\"}\n")) ==
            "unavailable: status is unavailable",
        "a failed status source was not reported");
    const std::pair<std::string, std::string> cases[] = {
        {"not json\n", "malformed: the request is not a JSON object"},
        {"[1]\n", "malformed: the request is not a JSON object"},
        {"{\"control\":2,\"request\":\"status\"}\n",
         "unsupported: unsupported control protocol"},
        {"{\"control\":\"1\",\"request\":\"status\"}\n",
         "unsupported: unsupported control protocol"},
        {"{\"control\":1}\n",
         "malformed: a request holds exactly control and request"},
        {"{\"control\":1,\"request\":\"status\",\"all\":true}\n",
         "malformed: a request holds exactly control and request"},
        {"{\"control\":1,\"request\":\"stop\"}\n",
         "unknown_request: unknown request"},
        {"{\"control\":1,\"request\":\"stop\",\"now\":true}\n",
         "unknown_request: unknown request"},
        {std::string(600U, ' '), "malformed: the request is too long"},
    };
    for (const auto& [request, error] : cases) {
        check(error_of(exchange(path, request)) == error,
              "a bad request got the wrong error");
    }
    check(calls == 2, "a bad request reached the status source");
    // A server without route acceptance knows no accept-route request.
    check(
        error_of(exchange(
            path,
            "{\"control\":1,\"request\":\"accept-route\",\"id\":\"ab\"}\n")) ==
            "unknown_request: unknown request",
        "accept-route reached a server without acceptance");
    runner.sync([&] { server->close(); });
    check(!std::filesystem::exists(path), "close left the control socket");
    const auto gone = yume::runtime::query_control_status(path, 500ms);
    check(!gone.ok() && gone.status().code() == StatusCode::NotFound,
          "a missing control socket was not NotFound");
}

// A client with circuits accepts a proposal by its id over the socket, and
// only that id.
void test_accept_route() {
    Directory directory;
    Runner runner;
    const auto path = directory.path / "control.sock";
    std::vector<std::string> accepted;
    auto server = runner.sync([&] {
        return require(ControlServer::open(
            runner.context, path,
            [] { return std::string(R"({"control":1})"); }, {},
            [&accepted](std::string_view id) {
                if (id != "00112233aabbccdd")
                    return Status(StatusCode::NotFound);
                accepted.emplace_back(id);
                return Status::success();
            }));
    });
    const auto reply = yume::runtime::query_control_accept_route(
        path, "00112233aabbccdd", 2000ms);
    check(
        reply.ok() &&
            reply.value() == R"({"accepted":"00112233aabbccdd","control":1})" &&
            require(yume::runtime::status_reply_text(reply.value())) ==
                "accepted route 00112233aabbccdd\n",
        "a proposal's id was not accepted");
    check(require(yume::runtime::query_control_status(path, 2000ms)) ==
              R"({"requests":["status","accept-route"],"control":1})",
          "the status reply does not name accept-route");
    const auto stale = yume::runtime::query_control_accept_route(
        path, "ffffffffffffffff", 2000ms);
    check(
        stale.ok() &&
            error_of(stale.value() + "\n") ==
                "not_found: no route proposal has that id" &&
            !yume::runtime::status_reply_text(stale.value()).ok(),
        "another id was accepted");
    check(!yume::runtime::query_control_accept_route(path, "NOT-HEX", 500ms)
                  .ok() &&
              !yume::runtime::query_control_accept_route(path, "", 500ms).ok(),
          "a malformed id was sent");
    const std::pair<std::string, std::string> cases[] = {
        {"{\"control\":1,\"request\":\"accept-route\"}\n",
         "malformed: accept-route holds exactly control, request and id"},
        {"{\"control\":1,\"request\":\"accept-route\",\"id\":7}\n",
         "malformed: accept-route holds exactly control, request and id"},
        {"{\"control\":1,\"request\":\"accept-route\",\"id\":\"00\",\"x\":1}\n",
         "malformed: accept-route holds exactly control, request and id"},
    };
    for (const auto& [request, error] : cases) {
        check(error_of(exchange(path, request)) == error,
              "a bad accept-route got the wrong error");
    }
    check(accepted == std::vector<std::string>{"00112233aabbccdd"},
          "acceptance saw something other than the one valid id");
    runner.sync([&] { server->close(); });
}

// A silent connection ends at the request deadline, and connections beyond
// the limit wait until one ends.
void test_deadline_and_limit() {
    Directory directory;
    Runner runner;
    const auto path = directory.path / "control.sock";
    auto server = runner.sync([&] {
        return require(ControlServer::open(runner.context, path, [] {
            return std::string(R"({"control":1})");
        }));
    });
    std::vector<std::future<std::string>> silent;
    const auto started = std::chrono::steady_clock::now();
    for (std::size_t index = 0; index < yume::runtime::kControlConnections;
         ++index) {
        silent.push_back(std::async(std::launch::async, [&path] {
            return exchange(path, "", 5000ms);
        }));
    }
    std::this_thread::sleep_for(300ms);
    const auto waiting = yume::runtime::query_control_status(path, 500ms);
    check(!waiting.ok() && waiting.status().code() == StatusCode::Cancelled,
          "a fifth connection was served while four were open");
    for (auto& connection : silent) {
        check(connection.get().empty(), "a silent connection got a reply");
    }
    const auto waited = std::chrono::steady_clock::now() - started;
    check(waited >= 1800ms && waited < 4500ms,
          "silent connections did not end at the request deadline");
    check(require(yume::runtime::query_control_status(path, 2000ms)) ==
              R"({"requests":["status"],"control":1})",
          "the server did not resume after the deadline");
    runner.sync([&] { server->close(); });
}

// A directory that others can write refuses the socket, as LocalListener
// requires.
void test_open_refusals() {
    Directory directory;
    Runner runner;
    std::filesystem::permissions(directory.path,
                                 std::filesystem::perms::others_write,
                                 std::filesystem::perm_options::add);
    const auto refused = runner.sync([&] {
        return ControlServer::open(runner.context,
                                   directory.path / "control.sock",
                                   [] { return std::string("{}"); });
    });
    check(!refused.ok(), "a world-writable directory was accepted");
    const auto empty = runner.sync([&] {
        return ControlServer::open(runner.context,
                                   directory.path / "control.sock", {});
    });
    check(!empty.ok() && empty.status().code() == StatusCode::InvalidArgument,
          "a server without a status source was accepted");
}

}  // namespace

int main() {
    try {
        test_status_reply_fields();
        test_status_text();
        test_server_status();
        test_requests_and_errors();
        test_accept_route();
        test_deadline_and_limit();
        test_open_refusals();
    } catch (const std::exception& error) {
        std::cerr << "control socket test failure: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "control socket tests passed\n";
    return EXIT_SUCCESS;
}
