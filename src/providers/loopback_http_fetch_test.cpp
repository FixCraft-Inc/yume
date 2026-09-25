/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/loopback_http_fetch.hpp"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <boost/asio/buffers_iterator.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/write.hpp>

namespace {
using boost::asio::ip::address;
using boost::asio::ip::make_address;
using boost::asio::ip::tcp;
using yume::engine::ExecutorAffinity;
using yume::engine::Result;
using yume::engine::StatusCode;
using yume::providers::AsioExecutionContext;
using yume::providers::LoopbackHttpFetch;
using yume::providers::LoopbackHttpLimits;
using yume::providers::LoopbackHttpResponse;
using namespace std::chrono_literals;

#define CHECK(condition) do { if (!(condition)) { \
    std::cerr << "loopback fetch check failed at " << __LINE__ << ": " #condition "\n"; \
    std::abort(); \
} } while (false)

std::shared_ptr<AsioExecutionContext> context() {
    auto created = AsioExecutionContext::create(ExecutorAffinity(61U));
    CHECK(created.ok());
    return std::move(created).take_value();
}

// Runs one step on the context, as start() and cancel() require.
template <typename Function>
void on_context(const std::shared_ptr<AsioExecutionContext>& io, Function&& function) {
    bool ran = false;
    boost::asio::post(io->executor(), [&] {
        function();
        ran = true;
    });
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!ran && std::chrono::steady_clock::now() < deadline) io->poll();
    CHECK(ran);
}

// A backend on the test's own context. It reads one request head and then
// sends `reply`, sends it and closes, or holds the connection open.
class Backend final : public std::enable_shared_from_this<Backend> {
public:
    enum class After { Close, Hold };

    Backend(const std::shared_ptr<AsioExecutionContext>& context, std::string reply,
            After after = After::Close, const char* host = "127.0.0.1")
        : acceptor(context->executor(), tcp::endpoint(make_address(host), 0)),
          socket(context->executor()), response(std::move(reply)), mode(after) {}

    void serve() {
        acceptor.async_accept(socket, [self = shared_from_this()](const boost::system::error_code& error) {
            if (error) return;
            ++self->accepted;
            boost::asio::async_read_until(self->socket, self->input, "\r\n\r\n",
                [self](const boost::system::error_code& read, std::size_t) {
                    if (read) return;
                    self->request.assign(boost::asio::buffers_begin(self->input.data()),
                                         boost::asio::buffers_end(self->input.data()));
                    if (self->response.empty()) {
                        if (self->mode == After::Close) self->socket.close();
                        return;
                    }
                    boost::asio::async_write(self->socket, boost::asio::buffer(self->response),
                        [self](const boost::system::error_code&, std::size_t) {
                            if (self->mode == After::Close) {
                                boost::system::error_code ignored;
                                self->socket.shutdown(tcp::socket::shutdown_both, ignored);
                                self->socket.close(ignored);
                            }
                        });
                });
        });
    }

    std::uint16_t port() const { return acceptor.local_endpoint().port(); }

    tcp::acceptor acceptor;
    tcp::socket socket;
    boost::asio::streambuf input;
    std::string response;
    After mode;
    std::string request;
    int accepted{0};
};

struct Outcome final {
    std::optional<Result<LoopbackHttpResponse>> result;
    int calls{0};
};

std::shared_ptr<LoopbackHttpFetch> start_fetch(const std::shared_ptr<AsioExecutionContext>& io,
                                         const std::shared_ptr<Outcome>& outcome, std::uint16_t port,
                                         const char* method = "GET", const char* target = "/",
                                         LoopbackHttpLimits limits = {},
                                         const char* host = "127.0.0.1") {
    std::shared_ptr<LoopbackHttpFetch> handle;
    on_context(io, [&] {
        auto started = LoopbackHttpFetch::start(io, make_address(host), port, method, target, limits,
            [outcome](Result<LoopbackHttpResponse> result) {
                ++outcome->calls;
                outcome->result.emplace(std::move(result));
            });
        CHECK(started.ok());
        CHECK(outcome->calls == 0);  // never inside start()
        handle = std::move(started).take_value();
    });
    return handle;
}

void run_until(const std::shared_ptr<AsioExecutionContext>& io, const Outcome& outcome,
               std::chrono::milliseconds limit = 5s) {
    const auto deadline = std::chrono::steady_clock::now() + limit;
    while (outcome.calls == 0 && std::chrono::steady_clock::now() < deadline) io->poll();
    CHECK(outcome.calls == 1);
}

const LoopbackHttpResponse& success(const Outcome& outcome) {
    CHECK(outcome.result && outcome.result->ok());
    return outcome.result->value();
}

void expect_failure(const Outcome& outcome, StatusCode code, const std::string& fragment) {
    CHECK(outcome.result && !outcome.result->ok());
    CHECK(outcome.result->status().code() == code);
    if (outcome.result->status().message().find(fragment) == std::string::npos) {
        std::cerr << "unexpected message: " << outcome.result->status().message() << "\n";
        std::abort();
    }
}

std::optional<std::string> header(const LoopbackHttpResponse& response, const std::string& name) {
    std::optional<std::string> found;
    for (const auto& [key, value] : response.headers) {
        if (key == name) {
            CHECK(!found);  // one field of each name in these fixtures
            found = value;
        }
    }
    return found;
}

// One fetch against a scripted reply.
Outcome fetch(const std::string& reply, const char* method = "GET", const char* target = "/",
              LoopbackHttpLimits limits = {}, std::string* request = nullptr) {
    auto io = context();
    auto backend = std::make_shared<Backend>(io, reply);
    backend->serve();
    auto outcome = std::make_shared<Outcome>();
    const auto handle = start_fetch(io, outcome, backend->port(), method, target, limits);
    run_until(io, *outcome);
    if (request) *request = backend->request;
    return std::move(*outcome);
}

void test_get_relays_status_headers_and_body() {
    std::string request;
    const auto outcome = fetch("HTTP/1.1 203 Non-Authoritative Information\r\nContent-Length: 2\r\n"
                               "Connection: close\r\nKeep-Alive: timeout=5\r\nX-Test: a\r\n"
                               "Set-Cookie: b=1\r\n\r\nok",
                               "GET", "/page?q=1", {}, &request);
    const auto& response = success(outcome);
    CHECK(response.status == 203U);
    CHECK(response.body == std::vector<std::uint8_t>({'o', 'k'}));
    CHECK(header(response, "x-test") == "a");
    CHECK(header(response, "set-cookie") == "b=1");
    CHECK(header(response, "content-length") == "2");
    CHECK(!header(response, "connection") && !header(response, "keep-alive"));
    // The request carries the method and target and nothing from a client.
    CHECK(request.rfind("GET /page?q=1 HTTP/1.1\r\n", 0) == 0);
    CHECK(request.find("Host: 127.0.0.1:") != std::string::npos);
    CHECK(request.find("Connection: close\r\n") != std::string::npos);
}

void test_head_keeps_the_reported_length() {
    const auto outcome = fetch("HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n", "HEAD");
    const auto& response = success(outcome);
    CHECK(response.body.empty());
    CHECK(header(response, "content-length") == "1234");
}

void test_chunked_and_eof_bodies() {
    auto response = success(fetch("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                                  "3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"));
    CHECK(response.body == std::vector<std::uint8_t>({'a', 'b', 'c', 'd', 'e'}));
    CHECK(!header(response, "transfer-encoding"));
    CHECK(header(response, "content-length") == "5");
    response = success(fetch("HTTP/1.1 200 OK\r\n\r\nhello"));
    CHECK(response.body == std::vector<std::uint8_t>({'h', 'e', 'l', 'l', 'o'}));
}

void test_limits() {
    LoopbackHttpLimits limits;
    limits.response_body = 4U;
    expect_failure(fetch("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789", "GET", "/", limits),
                   StatusCode::ResourceExhausted, "limit");
    limits = {};
    limits.response_headers = 64U;
    expect_failure(fetch("HTTP/1.1 200 OK\r\nX-Large: " + std::string(200U, 'x') +
                         "\r\nContent-Length: 0\r\n\r\n", "GET", "/", limits),
                   StatusCode::ResourceExhausted, "limit");
}

void test_backend_failures() {
    expect_failure(fetch(""), StatusCode::Closed, "backend response failed");
    expect_failure(fetch("HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nshort"), StatusCode::Closed,
                   "backend response failed");
    expect_failure(fetch("HTTP/1.1 101 Switching Protocols\r\nUpgrade: x\r\n\r\n"), StatusCode::Closed,
                   "no final response");

    // Nothing listens on a port whose acceptor was closed.
    auto io = context();
    std::uint16_t port = 0;
    {
        tcp::acceptor probe(io->executor(), tcp::endpoint(make_address("127.0.0.1"), 0));
        port = probe.local_endpoint().port();
    }
    auto outcome = std::make_shared<Outcome>();
    const auto refused = start_fetch(io, outcome, port);
    run_until(io, *outcome);
    expect_failure(*outcome, StatusCode::Closed, "backend connect failed");

    // A backend that never answers meets the response deadline.
    auto held = std::make_shared<Backend>(io, "", Backend::After::Hold);
    held->serve();
    LoopbackHttpLimits limits;
    limits.response_timeout = 200ms;
    auto slow = std::make_shared<Outcome>();
    const auto handle = start_fetch(io, slow, held->port(), "GET", "/", limits);
    run_until(io, *slow);
    expect_failure(*slow, StatusCode::Closed, "timed out");
}

void test_cancellation() {
    auto io = context();
    auto held = std::make_shared<Backend>(io, "", Backend::After::Hold);
    held->serve();
    auto outcome = std::make_shared<Outcome>();
    const auto fetch_handle = start_fetch(io, outcome, held->port(), "GET", "/slow");
    const auto started = std::chrono::steady_clock::now();
    const auto deadline = started + 5s;
    while (held->request.empty() && std::chrono::steady_clock::now() < deadline) io->poll();
    CHECK(!held->request.empty());
    on_context(io, [&] {
        fetch_handle->cancel();
        fetch_handle->cancel();
        CHECK(outcome->calls == 0);  // never inside cancel()
    });
    run_until(io, *outcome);
    expect_failure(*outcome, StatusCode::Cancelled, "cancelled");
    CHECK(std::chrono::steady_clock::now() - started < 1s);
    on_context(io, [&] { fetch_handle->cancel(); });
    for (int round = 0; round < 10; ++round) io->poll();
    CHECK(outcome->calls == 1);

    // Cancelled before its posted start, a fetch never connects.
    auto idle = std::make_shared<Backend>(io, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    idle->serve();
    auto early = std::make_shared<Outcome>();
    on_context(io, [&] {
        auto started = LoopbackHttpFetch::start(io, make_address("127.0.0.1"), idle->port(), "GET", "/",
            {}, [early](Result<LoopbackHttpResponse> result) {
                ++early->calls;
                early->result.emplace(std::move(result));
            });
        CHECK(started.ok());
        started.value()->cancel();
    });
    run_until(io, *early);
    expect_failure(*early, StatusCode::Cancelled, "cancelled");
    for (int round = 0; round < 10; ++round) io->poll();
    CHECK(idle->accepted == 0);
}

void test_completion_exceptions_are_contained() {
    auto io = context();
    auto backend = std::make_shared<Backend>(io, "HTTP/1.1 204 No Content\r\n\r\n");
    backend->serve();
    int calls = 0;
    on_context(io, [&] {
        auto started = LoopbackHttpFetch::start(io, make_address("127.0.0.1"), backend->port(), "GET",
            "/", {}, [&calls](Result<LoopbackHttpResponse>) {
                ++calls;
                throw std::runtime_error("owner failure");
            });
        CHECK(started.ok());
    });
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (calls == 0 && std::chrono::steady_clock::now() < deadline) io->poll();
    CHECK(calls == 1);
}

void test_invalid_requests() {
    auto io = context();
    const auto refused = [&](const char* host, std::uint16_t port, const char* method,
                             const std::string& target, const std::string& fragment) {
        on_context(io, [&] {
            auto started = LoopbackHttpFetch::start(io, make_address(host), port, method, target, {},
                                                    [](Result<LoopbackHttpResponse>) { std::abort(); });
            CHECK(!started.ok() && started.status().code() == StatusCode::InvalidArgument);
            CHECK(started.status().message().find(fragment) != std::string::npos);
        });
    };
    refused("192.0.2.1", 80U, "GET", "/", "not loopback");
    refused("::ffff:127.0.0.1", 80U, "GET", "/", "not loopback");
    refused("127.0.0.1", 0U, "GET", "/", "port");
    refused("127.0.0.1", 80U, "POST", "/", "GET or HEAD");
    refused("127.0.0.1", 80U, "get", "/", "GET or HEAD");
    refused("127.0.0.1", 80U, "GET", "page", "origin-form");
    refused("127.0.0.1", 80U, "GET", "/a b", "origin-form");
    refused("127.0.0.1", 80U, "GET", "/a\r\nX: y", "origin-form");
    refused("127.0.0.1", 80U, "GET", "/" + std::string(8192U, 'a'), "origin-form");
    on_context(io, [&] {
        auto missing = LoopbackHttpFetch::start(io, make_address("127.0.0.1"), 80U, "GET", "/", {}, {});
        CHECK(!missing.ok() && missing.status().code() == StatusCode::InvalidArgument);
    });
    // Off the context, start() refuses before it accepts anything.
    bool threw = false;
    try {
        (void)LoopbackHttpFetch::start(io, make_address("127.0.0.1"), 80U, "GET", "/", {},
                                       [](Result<LoopbackHttpResponse>) { std::abort(); });
    } catch (const std::logic_error&) {
        threw = true;
    }
    CHECK(threw);
    for (int round = 0; round < 10; ++round) io->poll();
}

// The probe blocks, so its backend runs on another thread.
void test_probe() {
    const auto probe_with = [](const std::string& reply) {
        boost::asio::io_context server;
        tcp::acceptor acceptor(server, tcp::endpoint(make_address("127.0.0.1"), 0));
        const auto port = acceptor.local_endpoint().port();
        std::thread thread([&] {
            tcp::socket socket(server);
            acceptor.accept(socket);
            boost::asio::streambuf input;
            boost::asio::read_until(socket, input, "\r\n\r\n");
            boost::asio::write(socket, boost::asio::buffer(reply));
        });
        const auto status = yume::providers::probe_loopback_http(make_address("127.0.0.1"), port);
        thread.join();
        return status;
    };
    CHECK(probe_with("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n").ok());
    CHECK(probe_with("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").ok());
    const auto unavailable = probe_with("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n");
    CHECK(unavailable.code() == StatusCode::FailedPrecondition);
    CHECK(unavailable.message().find("503") != std::string::npos);

    boost::asio::io_context unused;
    std::uint16_t port = 0;
    {
        tcp::acceptor closed(unused, tcp::endpoint(make_address("127.0.0.1"), 0));
        port = closed.local_endpoint().port();
    }
    CHECK(yume::providers::probe_loopback_http(make_address("127.0.0.1"), port).code() ==
          StatusCode::Closed);
}

// The IPv6 loopback works the same way, where the host has IPv6.
void test_ipv6_loopback() {
    auto io = context();
    std::shared_ptr<Backend> backend;
    try {
        backend = std::make_shared<Backend>(io, "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n6", Backend::After::Close,
                                            "::1");
    } catch (const boost::system::system_error& error) {
        std::cout << "IPv6 loopback unavailable, case not run: " << error.what() << "\n";
        return;
    }
    backend->serve();
    auto outcome = std::make_shared<Outcome>();
    const auto handle = start_fetch(io, outcome, backend->port(), "GET", "/", {}, "::1");
    run_until(io, *outcome);
    CHECK(success(*outcome).body == std::vector<std::uint8_t>({'6'}));
    CHECK(backend->request.find("Host: [::1]:") != std::string::npos);
}

}  // namespace

int main() {
    test_get_relays_status_headers_and_body();
    test_head_keeps_the_reported_length();
    test_chunked_and_eof_bodies();
    test_limits();
    test_backend_failures();
    test_cancellation();
    test_completion_exceptions_are_contained();
    test_invalid_requests();
    test_probe();
    test_ipv6_loopback();
    std::cout << "loopback fetch checks passed\n";
    return 0;
}
