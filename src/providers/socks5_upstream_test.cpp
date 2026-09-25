/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/socks5_upstream.hpp"

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>

#include "providers/asio_tcp_byte_channel_provider.hpp"

namespace {
using boost::asio::ip::make_address;
using boost::asio::ip::tcp;
using yume::engine::Buffer;
using yume::engine::ByteChannel;
using yume::engine::CancellationSource;
using yume::engine::CancellationToken;
using yume::engine::EndpointRole;
using yume::engine::ExecutorAffinity;
using yume::engine::Result;
using yume::engine::Status;
using yume::engine::StatusCode;
using yume::providers::AsioExecutionContext;
using yume::providers::AsioTcpByteChannelProvider;
using yume::providers::Socks5Credentials;
using yume::providers::Socks5UpstreamLimits;
using yume::providers::Socks5UpstreamProvider;
using namespace std::chrono_literals;

#define CHECK(condition) do { if (!(condition)) { \
    std::cerr << "SOCKS5 upstream check failed at " << __LINE__ << ": " #condition "\n"; \
    std::abort(); \
} } while (false)

std::shared_ptr<AsioExecutionContext> context() {
    auto created = AsioExecutionContext::create(ExecutorAffinity(62U));
    CHECK(created.ok());
    return std::move(created).take_value();
}

template <typename Function>
void on_context(const std::shared_ptr<AsioExecutionContext>& io, Function&& function) {
    bool ran = false;
    boost::asio::post(io->executor(), [&] {
        function();
        ran = true;
    });
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (!ran && std::chrono::steady_clock::now() < deadline) io->poll();
    CHECK(ran);
}

template <typename Predicate>
void poll_until(const std::shared_ptr<AsioExecutionContext>& io, Predicate&& done) {
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (!done() && std::chrono::steady_clock::now() < deadline) io->poll();
    CHECK(done());
}

std::string bytes(std::initializer_list<unsigned> values) {
    std::string out;
    for (const unsigned value : values) out.push_back(static_cast<char>(value));
    return out;
}

std::string port_bytes(unsigned port) { return bytes({port >> 8U, port & 0xffU}); }

// A proxy that follows a script: each step reads an exact number of bytes and
// then writes a reply. After the script it echoes, or holds the connection.
class FakeProxy final : public std::enable_shared_from_this<FakeProxy> {
public:
    struct Step final {
        std::size_t read;
        std::string write;
    };

    FakeProxy(const std::shared_ptr<AsioExecutionContext>& io, std::vector<Step> script, bool echo = false,
              bool close_after = false)
        : acceptor(io->executor(), tcp::endpoint(make_address("127.0.0.1"), 0)), socket(io->executor()),
          steps(std::move(script)), echo_after(echo), close_at_end(close_after) {}

    void serve() {
        acceptor.async_accept(socket, [self = shared_from_this()](const boost::system::error_code& error) {
            if (error) return;
            self->connected = true;
            self->run(0U);
        });
    }

    std::uint16_t port() const { return acceptor.local_endpoint().port(); }

    tcp::acceptor acceptor;
    tcp::socket socket;
    std::vector<Step> steps;
    bool echo_after;
    bool close_at_end;
    bool connected{false};
    std::string received;
    std::string scratch;

private:
    void run(std::size_t index) {
        if (index == steps.size()) {
            if (close_at_end) {
                boost::system::error_code ignored;
                socket.shutdown(tcp::socket::shutdown_both, ignored);
                socket.close(ignored);
            } else if (echo_after) {
                echo();
            }
            return;
        }
        const auto write_then_next = [self = shared_from_this(), index] {
            const auto& reply = self->steps[index].write;
            if (reply.empty()) return self->run(index + 1U);
            boost::asio::async_write(self->socket, boost::asio::buffer(reply),
                [self, index](const boost::system::error_code& error, std::size_t) {
                    if (!error) self->run(index + 1U);
                });
        };
        if (steps[index].read == 0U) return write_then_next();
        scratch.assign(steps[index].read, '\0');
        boost::asio::async_read(socket, boost::asio::buffer(scratch),
            [self = shared_from_this(), write_then_next](const boost::system::error_code& error, std::size_t) {
                if (error) return;
                self->received += self->scratch;
                write_then_next();
            });
    }

    void echo() {
        scratch.assign(256U, '\0');
        socket.async_read_some(boost::asio::buffer(scratch),
            [self = shared_from_this()](const boost::system::error_code& error, std::size_t count) {
                if (error) return;
                auto data = std::make_shared<std::string>(self->scratch.substr(0U, count));
                boost::asio::async_write(self->socket, boost::asio::buffer(*data),
                    [self, data](const boost::system::error_code& written, std::size_t) {
                        if (!written) self->echo();
                    });
            });
    }
};

struct Created final {
    std::optional<Result<std::unique_ptr<ByteChannel>>> result;
    int calls{0};
};

std::shared_ptr<Socks5UpstreamProvider> provider_for(const std::shared_ptr<AsioExecutionContext>& io,
                                                     std::uint16_t proxy_port, std::string target,
                                                     std::uint16_t target_port,
                                                     std::optional<Socks5Credentials> credentials = std::nullopt,
                                                     Socks5UpstreamLimits limits = {}) {
    auto tcp_provider = AsioTcpByteChannelProvider::create(io, "127.0.0.1", proxy_port);
    CHECK(tcp_provider.ok());
    auto created = Socks5UpstreamProvider::create(io, std::move(tcp_provider).take_value(), std::move(target),
                                                  target_port, std::move(credentials), limits);
    CHECK(created.ok());
    return std::move(created).take_value();
}

std::shared_ptr<Created> start(const std::shared_ptr<AsioExecutionContext>& io,
                               const std::shared_ptr<Socks5UpstreamProvider>& provider,
                               CancellationToken token = {}) {
    auto created = std::make_shared<Created>();
    on_context(io, [&] {
        provider->async_create(EndpointRole::Client, token,
            [created](Result<std::unique_ptr<ByteChannel>> result) {
                ++created->calls;
                created->result.emplace(std::move(result));
            });
    });
    return created;
}

std::unique_ptr<ByteChannel> channel_of(const std::shared_ptr<AsioExecutionContext>& io,
                                        const std::shared_ptr<Created>& created) {
    poll_until(io, [&] { return created->calls != 0; });
    CHECK(created->calls == 1);
    if (!created->result->ok()) {
        std::cerr << "handshake failed: " << created->result->status().message() << "\n";
        std::abort();
    }
    return std::move(*created->result).take_value();
}

void expect_failure(const std::shared_ptr<AsioExecutionContext>& io, const std::shared_ptr<Created>& created,
                    StatusCode code, const std::string& fragment) {
    poll_until(io, [&] { return created->calls != 0; });
    for (int round = 0; round < 20; ++round) io->poll();
    CHECK(created->calls == 1);
    CHECK(!created->result->ok());
    if (created->result->status().code() != code ||
        created->result->status().message().find(fragment) == std::string::npos) {
        std::cerr << "unexpected failure " << static_cast<int>(created->result->status().code()) << ": "
                  << created->result->status().message() << "\n";
        std::abort();
    }
}

std::string read_some(const std::shared_ptr<AsioExecutionContext>& io, ByteChannel& channel) {
    std::optional<std::string> text;
    on_context(io, [&] {
        channel.async_read(64U, {}, [&text](Result<Buffer> received) {
            CHECK(received.ok());
            std::string out;
            for (const std::byte byte : received.value().bytes()) out.push_back(static_cast<char>(byte));
            text = std::move(out);
        });
    });
    poll_until(io, [&] { return text.has_value(); });
    return *text;
}

void write_all(const std::shared_ptr<AsioExecutionContext>& io, ByteChannel& channel, const std::string& text) {
    bool written = false;
    on_context(io, [&] {
        auto buffer = Buffer::copy_from(std::as_bytes(std::span(text.data(), text.size())), text.size());
        CHECK(buffer.ok());
        channel.async_write(std::move(buffer).take_value(), {}, [&](Status status, std::size_t count) {
            CHECK(status.ok() && count == text.size());
            written = true;
        });
    });
    poll_until(io, [&] { return written; });
}

void close_channel(const std::shared_ptr<AsioExecutionContext>& io, std::unique_ptr<ByteChannel> channel) {
    on_context(io, [&] { channel->close(); });
    for (int round = 0; round < 20; ++round) io->poll();
}

const std::string kIpv4Reply = bytes({0x05, 0x00, 0x00, 0x01, 192, 0, 2, 1}) + port_bytes(4444U);

void test_name_target_without_authentication() {
    auto io = context();
    const std::string name = "server.example";
    const std::string request = bytes({0x05, 0x01, 0x00, 0x03, static_cast<unsigned>(name.size())}) + name +
                                port_bytes(443U);
    auto proxy = std::make_shared<FakeProxy>(io, std::vector<FakeProxy::Step>{
        {3U, bytes({0x05, 0x00})},
        // The reply is followed by bytes from the target, which the
        // handshake must leave in the channel.
        {request.size(), kIpv4Reply + "early"}}, true);
    proxy->serve();
    const auto provider = provider_for(io, proxy->port(), name, 443U);
    auto channel = channel_of(io, start(io, provider));
    CHECK(proxy->received == bytes({0x05, 0x01, 0x00}) + request);
    CHECK(read_some(io, *channel) == "early");
    write_all(io, *channel, "ping");
    CHECK(read_some(io, *channel) == "ping");
    close_channel(io, std::move(channel));
}

void test_password_and_address_targets() {
    auto io = context();
    auto credentials = Socks5Credentials::create("user", "secret");
    CHECK(credentials.ok());
    const std::string request = bytes({0x05, 0x01, 0x00, 0x04, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0,
                                       0, 0, 0, 1}) + port_bytes(8443U);
    const std::string bound = bytes({0x05, 0x00, 0x00, 0x03, 11}) + "bnd.example" + port_bytes(1U);
    auto proxy = std::make_shared<FakeProxy>(io, std::vector<FakeProxy::Step>{
        {3U, bytes({0x05, 0x02})},
        {13U, bytes({0x01, 0x00})},
        {request.size(), bound}});
    proxy->serve();
    const auto provider = provider_for(io, proxy->port(), "2001:db8::1", 8443U,
                                       std::move(credentials).take_value());
    auto channel = channel_of(io, start(io, provider));
    CHECK(proxy->received == bytes({0x05, 0x01, 0x02}) + bytes({0x01, 4}) + "user" + bytes({6}) + "secret" +
                                 request);
    close_channel(io, std::move(channel));

    auto io4 = context();
    const std::string request4 = bytes({0x05, 0x01, 0x00, 0x01, 192, 0, 2, 10}) + port_bytes(80U);
    auto proxy4 = std::make_shared<FakeProxy>(io4, std::vector<FakeProxy::Step>{
        {3U, bytes({0x05, 0x00})},
        {request4.size(), bytes({0x05, 0x00, 0x00, 0x04}) + std::string(16U, '\0') + port_bytes(1U)}});
    proxy4->serve();
    auto channel4 = channel_of(io4, start(io4, provider_for(io4, proxy4->port(), "192.0.2.10", 80U)));
    CHECK(proxy4->received == bytes({0x05, 0x01, 0x00}) + request4);
    close_channel(io4, std::move(channel4));
}

// Each refused or malformed exchange fails the create and never returns a channel.
void test_refusals() {
    const std::string request = bytes({0x05, 0x01, 0x00, 0x03, 4}) + "host" + port_bytes(443U);
    const auto refused = [&](std::vector<FakeProxy::Step> script, bool with_password, StatusCode code,
                             const std::string& fragment, bool close_after = false) {
        auto io = context();
        auto proxy = std::make_shared<FakeProxy>(io, std::move(script), false, close_after);
        proxy->serve();
        std::optional<Socks5Credentials> credentials;
        if (with_password) {
            auto made = Socks5Credentials::create("user", "wrong");
            CHECK(made.ok());
            credentials.emplace(std::move(made).take_value());
        }
        const auto provider = provider_for(io, proxy->port(), "host", 443U, std::move(credentials));
        expect_failure(io, start(io, provider), code, fragment);
    };
    refused({{3U, bytes({0x05, 0x02})}, {12U, bytes({0x01, 0x01})}}, true, StatusCode::PermissionDenied,
            "refused the SOCKS5 credentials");
    refused({{3U, bytes({0x05, 0xff})}}, false, StatusCode::PermissionDenied, "requires authentication");
    refused({{3U, bytes({0x05, 0xff})}}, true, StatusCode::PermissionDenied, "does not accept");
    refused({{3U, bytes({0x05, 0x02})}}, false, StatusCode::Closed, "did not answer as SOCKS5");
    refused({{3U, bytes({0x04, 0x00})}}, false, StatusCode::Closed, "did not answer as SOCKS5");
    refused({{3U, bytes({0x05, 0x00})}, {request.size(), bytes({0x05, 0x05, 0x00, 0x01})}}, false,
            StatusCode::Closed, "proxy refused CONNECT: connection refused");
    refused({{3U, bytes({0x05, 0x00})}, {request.size(), bytes({0x05, 0x00, 0x00, 0x09})}}, false,
            StatusCode::Closed, "did not answer as SOCKS5");
    refused({{3U, bytes({0x05, 0x00})}, {request.size(), bytes({0x05, 0x00, 0x01, 0x01})}}, false,
            StatusCode::Closed, "did not answer as SOCKS5");
    refused({{3U, bytes({0x05, 0x00})}, {request.size(), bytes({0x05, 0x00, 0x00, 0x01, 1})}}, false,
            StatusCode::Closed, "", true);
}

void test_deadline_and_cancellation() {
    auto io = context();
    auto stalled = std::make_shared<FakeProxy>(io, std::vector<FakeProxy::Step>{{3U, ""}});
    stalled->serve();
    Socks5UpstreamLimits limits;
    limits.handshake_timeout = 200ms;
    const auto started = std::chrono::steady_clock::now();
    expect_failure(io, start(io, provider_for(io, stalled->port(), "host", 443U, std::nullopt, limits)),
                   StatusCode::Closed, "timed out");
    CHECK(std::chrono::steady_clock::now() - started < 3s);

    auto held = std::make_shared<FakeProxy>(io, std::vector<FakeProxy::Step>{{3U, ""}});
    held->serve();
    CancellationSource source;
    const auto created = start(io, provider_for(io, held->port(), "host", 443U), source.token());
    poll_until(io, [&] { return held->received.size() == 3U; });
    CHECK(created->calls == 0);
    source.cancel();
    expect_failure(io, created, StatusCode::Cancelled, "");

    // Cancelled before it starts, the create never reaches the proxy.
    auto idle = std::make_shared<FakeProxy>(io, std::vector<FakeProxy::Step>{{3U, bytes({0x05, 0x00})}});
    idle->serve();
    CancellationSource early;
    early.cancel();
    expect_failure(io, start(io, provider_for(io, idle->port(), "host", 443U), early.token()),
                   StatusCode::Cancelled, "");
    CHECK(!idle->connected);

    // No proxy listens on a port whose acceptor was closed.
    std::uint16_t port = 0U;
    {
        tcp::acceptor closed(io->executor(), tcp::endpoint(make_address("127.0.0.1"), 0));
        port = closed.local_endpoint().port();
    }
    auto unreachable = start(io, provider_for(io, port, "host", 443U));
    poll_until(io, [&] { return unreachable->calls != 0; });
    CHECK(unreachable->calls == 1 && !unreachable->result->ok());
}

void test_creation_rules() {
    auto io = context();
    auto tcp_provider = AsioTcpByteChannelProvider::create(io, "127.0.0.1", 1080U);
    CHECK(tcp_provider.ok());
    std::shared_ptr<yume::engine::ByteChannelProvider> proxy = std::move(tcp_provider).take_value();
    const auto invalid = [&](std::shared_ptr<AsioExecutionContext> with_context,
                             std::shared_ptr<yume::engine::ByteChannelProvider> with_proxy, std::string host,
                             std::uint16_t port, Socks5UpstreamLimits limits = {}) {
        auto created = Socks5UpstreamProvider::create(std::move(with_context), std::move(with_proxy),
                                                      std::move(host), port, std::nullopt, limits);
        CHECK(!created.ok() && created.status().code() == StatusCode::InvalidArgument);
    };
    invalid(io, proxy, "", 443U);
    invalid(io, proxy, std::string(256U, 'h'), 443U);
    invalid(io, proxy, "host", 0U);
    invalid(nullptr, proxy, "host", 443U);
    invalid(io, nullptr, "host", 443U);
    Socks5UpstreamLimits zero;
    zero.handshake_timeout = 0ms;
    invalid(io, proxy, "host", 443U, zero);

    auto provider = Socks5UpstreamProvider::create(io, proxy, std::string(255U, 'h'), 443U);
    CHECK(provider.ok());
    CHECK(&provider.value()->descriptor() == &proxy->descriptor());

    CHECK(!Socks5Credentials::create("", "secret").ok());
    CHECK(!Socks5Credentials::create("user", std::string(256U, 'p')).ok());
    auto credentials = Socks5Credentials::create("user", "secret");
    CHECK(credentials.ok());
    auto source = std::move(credentials).take_value();
    Socks5Credentials moved(std::move(source));
    CHECK(moved.username() == "user" && moved.password() == "secret");
    CHECK(source.username().empty() && source.password().empty());
    auto other = Socks5Credentials::create("second", "value");
    CHECK(other.ok());
    moved = std::move(other).take_value();
    CHECK(moved.username() == "second" && moved.password() == "value");
}

}  // namespace

int main() {
    test_name_target_without_authentication();
    test_password_and_address_targets();
    test_refusals();
    test_deadline_and_cancellation();
    test_creation_rules();
    std::cout << "SOCKS5 upstream checks passed\n";
    return 0;
}
