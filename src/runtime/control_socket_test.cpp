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

std::string error_of(const std::string& reply) {
    check(!reply.empty() && reply.back() == '\n', "the reply is not one line");
    const Json value = Json::parse(reply);
    check(value.at("control") == 1 && value.size() == 2U,
          "the error reply has other keys");
    return value.at("error").get<std::string>();
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
    check(require(yume::runtime::query_control_status(path, 2000ms)) ==
              R"({"control":1,"state":"idle"})",
          "the status reply was not returned");
    check(
        error_of(exchange(path, "{\"control\":1,\"request\":\"status\"}\n")) ==
            "status is unavailable",
        "a failed status source was not reported");
    const std::pair<std::string, std::string> cases[] = {
        {"not json\n", "the request is not a JSON object"},
        {"[1]\n", "the request is not a JSON object"},
        {"{\"control\":2,\"request\":\"status\"}\n",
         "unsupported control protocol"},
        {"{\"control\":\"1\",\"request\":\"status\"}\n",
         "unsupported control protocol"},
        {"{\"control\":1}\n", "a request holds exactly control and request"},
        {"{\"control\":1,\"request\":\"status\",\"all\":true}\n",
         "a request holds exactly control and request"},
        {"{\"control\":1,\"request\":\"stop\"}\n", "unknown request"},
        {std::string(600U, ' '), "the request is too long"},
    };
    for (const auto& [request, error] : cases) {
        check(error_of(exchange(path, request)) == error,
              "a bad request got the wrong error");
    }
    check(calls == 2, "a bad request reached the status source");
    runner.sync([&] { server->close(); });
    check(!std::filesystem::exists(path), "close left the control socket");
    const auto gone = yume::runtime::query_control_status(path, 500ms);
    check(!gone.ok() && gone.status().code() == StatusCode::NotFound,
          "a missing control socket was not NotFound");
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
              R"({"control":1})",
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
        test_requests_and_errors();
        test_deadline_and_limit();
        test_open_refusals();
    } catch (const std::exception& error) {
        std::cerr << "control socket test failure: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "control socket tests passed\n";
    return EXIT_SUCCESS;
}
