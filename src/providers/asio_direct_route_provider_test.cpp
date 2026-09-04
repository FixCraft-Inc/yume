/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <future>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/error_code.hpp>

#include "engine/front_door.hpp"
#include "engine/session_engine.hpp"
#include "providers/asio_direct_route_provider.hpp"
#include "ytp/protocol.hpp"
#include "ytp/security.hpp"

namespace yume::providers {
namespace {

using namespace std::chrono_literals;
using namespace engine;
using Tcp = boost::asio::ip::tcp;
using Udp = boost::asio::ip::udp;

class TestFailure final : public std::runtime_error {
public:
    explicit TestFailure(std::string message)
        : std::runtime_error(std::move(message)) {}
};

#define CHECK(expression)                                                     \
    do {                                                                      \
        if (!(expression)) {                                                  \
            throw TestFailure(std::string("check failed: ") + #expression); \
        }                                                                     \
    } while (false)

template <typename T>
T require(Result<T> result) {
    if (!result.ok()) {
        throw TestFailure(result.status().message());
    }
    return std::move(result).take_value();
}

Buffer make_buffer(std::string_view text,
                   std::size_t limit = kAbsoluteMaxBufferBytes) {
    return require(Buffer::copy_from(
        {reinterpret_cast<const std::byte*>(text.data()), text.size()},
        limit));
}

std::string buffer_text(const Buffer& buffer) {
    return std::string(
        reinterpret_cast<const char*>(buffer.bytes().data()), buffer.size());
}

ProviderDescriptor make_descriptor(std::string id,
                                   ProviderKind kind,
                                   CapabilitySet capabilities) {
    return require(ProviderDescriptor::create(
        std::move(id), kind, 1U, capabilities));
}

ProviderRequirement requirement(std::string id,
                                ProviderKind kind,
                                CapabilitySet capabilities) {
    return require(ProviderRequirement::create(
        kind, std::move(id), 1U, capabilities));
}

Buffer copy_bytes(std::span<const std::uint8_t> bytes) {
    return require(Buffer::copy_from(
        {reinterpret_cast<const std::byte*>(bytes.data()), bytes.size()},
        128U * 1024U));
}

Buffer copy_bytes(std::span<const std::byte> bytes) {
    return require(Buffer::copy_from(bytes, 128U * 1024U));
}

Buffer frame(ytp1::RecordType type,
             std::uint32_t stream_id,
             std::span<const std::byte> payload) {
    const auto id = ytp1::StreamId::FromWire(stream_id);
    CHECK(id.ok());
    const ytp1::FrameHeader header{
        type, 0U, *id.value, static_cast<std::uint32_t>(payload.size())};
    std::array<std::uint8_t, ytp1::kFrameHeaderSize> encoded{};
    CHECK(ytp1::EncodeFrameHeader(header, encoded).ok());
    Buffer output = require(Buffer::allocate(
        encoded.size() + payload.size(), encoded.size() + payload.size()));
    std::memcpy(output.mutable_bytes().data(), encoded.data(), encoded.size());
    if (!payload.empty()) {
        std::memcpy(output.mutable_bytes().data() + encoded.size(),
                    payload.data(), payload.size());
    }
    return output;
}

Buffer protected_wire(std::uint64_t sequence, Buffer plaintext) {
    Buffer output = require(Buffer::allocate(
        16U + plaintext.size(), 16U + plaintext.size()));
    auto bytes = output.mutable_bytes();
    bytes[0] = std::byte{1};
    for (std::size_t index = 1U; index < 8U; ++index) {
        bytes[index] = std::byte{0};
    }
    for (std::size_t index = 0U; index < 8U; ++index) {
        bytes[8U + index] = static_cast<std::byte>(
            sequence >> ((7U - index) * 8U));
    }
    std::memcpy(bytes.data() + 16U, plaintext.bytes().data(),
                plaintext.size());
    return output;
}

Buffer auth_message(ytp1::AuthMessageType type, ytp1::EndpointRole role) {
    ytp1::AuthRecord record;
    record.type = type;
    record.sender_role = role;
    const auto encoded = ytp1::EncodeAuthRecord(record);
    CHECK(encoded.ok());
    return copy_bytes(*encoded.value);
}

std::vector<std::byte> capability_manifest() {
    const ytp1::CapabilityManifest manifest{{
        {"packet", ytp1::ServiceKind::Packet, 64U},
        {"stream", ytp1::ServiceKind::ByteStream, 64U},
    }};
    const auto encoded = ytp1::EncodeCapabilityManifest(manifest);
    CHECK(encoded.ok());
    std::vector<std::byte> output(encoded.value->size());
    std::memcpy(output.data(), encoded.value->data(), output.size());
    return output;
}

class NullByteProvider final : public ByteChannelProvider {
public:
    NullByteProvider()
        : descriptor_(make_descriptor(
              "test.bytes", ProviderKind::ByteChannel,
              mandatory_capabilities(ProviderKind::ByteChannel))) {}
    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }
    void async_create(EndpointRole,
                      CancellationToken,
                      Completion completion) override {
        completion(Result<std::unique_ptr<ByteChannel>>(Status(
            StatusCode::FailedPrecondition, "unused")));
    }
private:
    ProviderDescriptor descriptor_;
};

class NullSecureProvider final : public SecureChannelProvider {
public:
    NullSecureProvider()
        : descriptor_(make_descriptor(
              "test.tls", ProviderKind::SecureChannel,
              mandatory_capabilities(ProviderKind::SecureChannel)
                  .with(Capability::Tls13))) {}
    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }
    void async_wrap(std::unique_ptr<ByteChannel>,
                    EndpointRole,
                    CancellationToken,
                    Completion completion) override {
        completion(Result<std::unique_ptr<SecureChannel>>(Status(
            StatusCode::FailedPrecondition, "unused")));
    }
private:
    ProviderDescriptor descriptor_;
};

class NullFrontDoorProvider final : public FrontDoorProvider {
public:
    NullFrontDoorProvider()
        : descriptor_(make_descriptor(
              "test.front", ProviderKind::FrontDoor,
              mandatory_capabilities(ProviderKind::FrontDoor))) {}
    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }
    void async_create(EndpointRole,
                      CancellationToken,
                      Completion completion) override {
        completion(Result<std::unique_ptr<FrontDoor>>(Status(
            StatusCode::FailedPrecondition, "unused")));
    }
private:
    ProviderDescriptor descriptor_;
};

class NullCarrierProvider final : public CarrierProvider {
public:
    NullCarrierProvider()
        : descriptor_(make_descriptor(
              "test.carrier", ProviderKind::Carrier,
              mandatory_capabilities(ProviderKind::Carrier))) {}
    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }
    void async_create(std::unique_ptr<SecureChannel>,
                      EndpointRole,
                      CancellationToken,
                      Completion completion) override {
        completion(Result<std::unique_ptr<Carrier>>(Status(
            StatusCode::FailedPrecondition, "unused")));
    }
private:
    ProviderDescriptor descriptor_;
};

class NullRouteProvider final : public RouteProvider {
public:
    NullRouteProvider()
        : descriptor_(make_descriptor(
              "test.route", ProviderKind::RouteProvider,
              mandatory_capabilities(ProviderKind::RouteProvider)
                  .with(Capability::DirectTcp)
                  .with(Capability::DirectUdp))) {}
    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }
    void async_open(const AuthorizedRouteRequest&,
                    CancellationToken,
                    Completion completion) override {
        completion(Result<RouteConnection>(Status(
            StatusCode::FailedPrecondition, "unused")));
    }
    void cancel() noexcept override {}
private:
    ProviderDescriptor descriptor_;
};

class CaptureHandler final : public StreamHandler {
public:
    explicit CaptureHandler(ServiceKind kind)
        : kind_(kind),
          descriptor_(make_descriptor(
              kind == ServiceKind::ByteStream
                  ? "test.capture.stream"
                  : "test.capture.packet",
              ProviderKind::StreamHandler,
              kind == ServiceKind::ByteStream
                  ? mandatory_capabilities(ProviderKind::StreamHandler)
                        .with(Capability::DirectTcp)
                  : mandatory_capabilities(ProviderKind::StreamHandler)
                        .with(Capability::PacketChannels)
                        .with(Capability::DirectUdp))) {}
    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }
    ServiceKind service_kind() const noexcept override { return kind_; }
    Status authorize(const StreamOpenContext&) override {
        return Status::success();
    }
    void on_open(StreamOpenContext,
                 std::shared_ptr<StreamResponder> stream) override {
        stream->close(Status(StatusCode::Internal,
                             "expected routed OPEN"));
    }
    void on_route(AuthorizedRouteRequest route,
                  std::shared_ptr<StreamResponder> stream) override {
        request.emplace(std::move(route));
        responder = std::move(stream);
    }

    std::optional<AuthorizedRouteRequest> request;
    std::shared_ptr<StreamResponder> responder;
private:
    ServiceKind kind_;
    ProviderDescriptor descriptor_;
};

class TestSecurity final : public SessionSecurityProvider {
public:
    TestSecurity() : manifest_(capability_manifest()) {}
    std::string_view provider_id() const noexcept override {
        return "test.security";
    }
    std::string_view suite_id() const noexcept override {
        return ytp1::kSuiteId;
    }
    std::span<const std::byte> security_parameters() const noexcept override {
        const auto parameters = ytp1::RequiredSecurityParameters();
        return {reinterpret_cast<const std::byte*>(parameters.data()),
                parameters.size()};
    }
    std::size_t max_sealed_overhead() const noexcept override { return 0U; }
    Status initialize(const SessionAuthenticationContext&) override {
        return Status::success();
    }
    Result<AuthenticationOutput> start_authentication() override {
        AuthenticationOutput output;
        output.outbound_kind = AuthenticationMessageKind::Challenge;
        output.outbound_message = auth_message(
            ytp1::AuthMessageType::Challenge, ytp1::EndpointRole::Server);
        return Result<AuthenticationOutput>(std::move(output));
    }
    Result<AuthenticationOutput> process_authentication(
        AuthenticationMessageKind kind,
        std::span<const std::byte>) override {
        CHECK(kind == AuthenticationMessageKind::Response);
        AuthenticationOutput output;
        output.outbound_kind = AuthenticationMessageKind::Accepted;
        output.outbound_message = auth_message(
            ytp1::AuthMessageType::Accepted, ytp1::EndpointRole::Server);
        output.established = true;
        output.authenticated_peer = require(PeerEvidence::create(
            EndpointRole::Client, "device-1", "test-composite",
            std::vector<std::byte>{std::byte{1}}));
        output.authenticated_peer_capability_manifest = manifest_;
        return Result<AuthenticationOutput>(std::move(output));
    }
    Result<Buffer> seal_record(
        RecordKeyToken,
        std::span<const std::byte> plaintext) override {
        return Result<Buffer>(copy_bytes(plaintext));
    }
    Result<Buffer> open_record(
        RecordKeyToken,
        std::span<const std::byte> ciphertext) override {
        return Result<Buffer>(copy_bytes(ciphertext));
    }
    Result<Buffer> begin_outbound_rekey(std::uint32_t) override {
        return Result<Buffer>(Status(StatusCode::FailedPrecondition,
                                     "unused"));
    }
    Result<Buffer> accept_inbound_rekey(
        std::uint32_t,
        std::span<const std::byte>) override {
        return Result<Buffer>(Status(StatusCode::FailedPrecondition,
                                     "unused"));
    }
    Status finish_outbound_rekey(
        std::uint32_t,
        std::span<const std::byte>) override {
        return Status(StatusCode::FailedPrecondition, "unused");
    }
    void cancel() noexcept override {}
private:
    std::vector<std::byte> manifest_;
};

class TestSecurityFactory final : public SessionSecurityProviderFactory {
public:
    TestSecurityFactory()
        : descriptor_(make_descriptor(
              "test.security", ProviderKind::SessionSecurity,
              mandatory_capabilities(ProviderKind::SessionSecurity))) {}
    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }
    Result<std::unique_ptr<SessionSecurityProvider>> create(
        EndpointRole) override {
        std::unique_ptr<SessionSecurityProvider> provider =
            std::make_unique<TestSecurity>();
        return Result<std::unique_ptr<SessionSecurityProvider>>(
            std::move(provider));
    }
private:
    ProviderDescriptor descriptor_;
};

class TestSecureChannel final : public SecureChannel {
public:
    TestSecureChannel()
        : descriptor_(make_descriptor(
              "test.tls", ProviderKind::SecureChannel,
              mandatory_capabilities(ProviderKind::SecureChannel)
                  .with(Capability::Tls13))),
          peer_(SecureChannelPeerEvidence::anonymous_client()) {}
    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }
    ExecutorAffinity executor_affinity() const noexcept override {
        return ExecutorAffinity(71U);
    }
    std::size_t max_read_size() const noexcept override {
        return 128U * 1024U;
    }
    std::size_t max_write_size() const noexcept override {
        return 128U * 1024U;
    }
    void async_read(std::size_t,
                    CancellationToken,
                    ReadCompletion completion) override {
        completion(Result<Buffer>(Status(
            StatusCode::FailedPrecondition, "unused")));
    }
    void async_write(Buffer,
                     CancellationToken,
                     WriteCompletion completion) override {
        completion(Status(StatusCode::FailedPrecondition, "unused"), 0U);
    }
    Status shutdown_write() noexcept override { return Status::success(); }
    void cancel() noexcept override {}
    void close() noexcept override {}
    const SecureChannelPeerEvidence& peer_evidence() const noexcept override {
        return peer_;
    }
    Result<Buffer> export_keying_material(
        std::string_view,
        std::span<const std::byte>,
        std::size_t size) override {
        return Buffer::allocate(size, size);
    }
private:
    ProviderDescriptor descriptor_;
    SecureChannelPeerEvidence peer_;
};

class TestCarrier final : public Carrier {
public:
    TestCarrier()
        : descriptor_(make_descriptor(
              "test.carrier", ProviderKind::Carrier,
              mandatory_capabilities(ProviderKind::Carrier))) {}
    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }
    ExecutorAffinity executor_affinity() const noexcept override {
        return ExecutorAffinity(71U);
    }
    std::size_t max_record_size() const noexcept override {
        return 128U * 1024U;
    }
    SecureChannel& secure_channel() noexcept override { return secure_; }
    const SecureChannel& secure_channel() const noexcept override {
        return secure_;
    }
    void async_receive(CancellationToken,
                       ReceiveCompletion completion) override {
        CHECK(!receive_);
        receive_ = std::move(completion);
    }
    void async_send(Buffer record,
                    CancellationToken,
                    SendCompletion completion) override {
        const std::size_t size = record.size();
        sent.push_back(std::move(record));
        completion(Status::success(), size);
    }
    void cancel() noexcept override {}
    void close() noexcept override { closed_ = true; }
    void deliver(Buffer record) {
        CHECK(receive_);
        auto completion = std::move(receive_);
        receive_ = {};
        const std::size_t size = record.size();
        completion(Result<ReceivedRecord>(ReceivedRecord(
            std::move(record), CarrierCredit(size, [](std::size_t) {}))));
    }

    std::vector<Buffer> sent;
private:
    ProviderDescriptor descriptor_;
    TestSecureChannel secure_;
    ReceiveCompletion receive_;
    bool closed_{false};
};

std::shared_ptr<const EngineGraph> request_graph(
    const std::shared_ptr<CaptureHandler>& stream_handler,
    const std::shared_ptr<CaptureHandler>& packet_handler) {
    std::vector<ProviderRequirement> providers;
    providers.push_back(requirement(
        "test.bytes", ProviderKind::ByteChannel,
        mandatory_capabilities(ProviderKind::ByteChannel)));
    providers.push_back(requirement(
        "test.tls", ProviderKind::SecureChannel,
        mandatory_capabilities(ProviderKind::SecureChannel)
            .with(Capability::Tls13)));
    providers.push_back(requirement(
        "test.front", ProviderKind::FrontDoor,
        mandatory_capabilities(ProviderKind::FrontDoor)));
    providers.push_back(requirement(
        "test.carrier", ProviderKind::Carrier,
        mandatory_capabilities(ProviderKind::Carrier)));
    providers.push_back(requirement(
        "test.security", ProviderKind::SessionSecurity,
        mandatory_capabilities(ProviderKind::SessionSecurity)));
    providers.push_back(requirement(
        "test.route", ProviderKind::RouteProvider,
        mandatory_capabilities(ProviderKind::RouteProvider)
            .with(Capability::DirectTcp)
            .with(Capability::DirectUdp)));

    std::vector<ServiceRequirement> services;
    services.push_back(require(ServiceRequirement::create(
        "packet", ServiceKind::PacketChannel, "test.capture.packet", 1U,
        64U, mandatory_capabilities(ProviderKind::StreamHandler)
                 .with(Capability::PacketChannels)
                 .with(Capability::DirectUdp))));
    services.push_back(require(ServiceRequirement::create(
        "stream", ServiceKind::ByteStream, "test.capture.stream", 1U,
        64U, mandatory_capabilities(ProviderKind::StreamHandler)
                 .with(Capability::DirectTcp))));

    EngineBuilder builder(
        EndpointRole::Server,
        require(TransportSuiteDescriptor::create(
            "test.ytp1", "YTP/1", std::move(providers),
            std::move(services))));
    CHECK(builder.register_byte_channel_provider(
              std::make_shared<NullByteProvider>()).ok());
    CHECK(builder.register_secure_channel_provider(
              std::make_shared<NullSecureProvider>()).ok());
    CHECK(builder.register_front_door_provider(
              std::make_shared<NullFrontDoorProvider>()).ok());
    CHECK(builder.register_carrier_provider(
              std::make_shared<NullCarrierProvider>()).ok());
    CHECK(builder.register_session_security_provider_factory(
              std::make_shared<TestSecurityFactory>()).ok());
    CHECK(builder.register_route_provider(
              std::make_shared<NullRouteProvider>()).ok());
    CHECK(builder.register_stream_handler("stream", stream_handler).ok());
    CHECK(builder.register_stream_handler("packet", packet_handler).ok());
    return require(builder.build());
}

class RequestFactory final {
public:
    RequestFactory()
        : stream_handler_(
              std::make_shared<CaptureHandler>(ServiceKind::ByteStream)),
          packet_handler_(
              std::make_shared<CaptureHandler>(ServiceKind::PacketChannel)) {
        auto carrier_owner = std::make_unique<TestCarrier>();
        carrier_ = carrier_owner.get();
        session_ = require(SessionEngine::create(
            request_graph(stream_handler_, packet_handler_),
            std::move(carrier_owner)));
        int starts = 0;
        session_->async_start([&](Status status) {
            CHECK(status.ok());
            ++starts;
        });
        CHECK(carrier_->sent.size() == 1U);
        Buffer response = auth_message(
            ytp1::AuthMessageType::Response, ytp1::EndpointRole::Client);
        carrier_->deliver(frame(ytp1::RecordType::Auth, 0U,
                                response.bytes()));
        CHECK(carrier_->sent.size() == 4U);
        carrier_->deliver(copy_bytes(carrier_->sent[2].bytes()));
        CHECK(starts == 1);
        CHECK(session_->state() == SessionState::Active);
    }

    ~RequestFactory() noexcept {
        if (session_) {
            session_->stop();
        }
    }

    AuthorizedRouteRequest make(ytp1::Destination destination) {
        const bool tcp =
            destination.transport == ytp1::TransportProtocol::Tcp;
        const ytp1::OpenRequest open{
            tcp ? ytp1::ServiceKind::ByteStream
                : ytp1::ServiceKind::Packet,
            tcp ? "stream" : "packet",
            std::move(destination)};
        const auto encoded = ytp1::EncodeOpen(open);
        CHECK(encoded.ok());
        const std::uint32_t stream_id = next_stream_id_;
        next_stream_id_ += 2U;
        carrier_->deliver(protected_wire(
            next_sequence_++,
            frame(ytp1::RecordType::Open, stream_id,
                  {reinterpret_cast<const std::byte*>(encoded.value->data()),
                   encoded.value->size()})));

        auto& capture = tcp ? stream_handler_ : packet_handler_;
        CHECK(capture->request.has_value());
        AuthorizedRouteRequest result = std::move(*capture->request);
        capture->request.reset();
        if (capture->responder) {
            capture->responder->close(Status(
                StatusCode::Closed, "request-factory stream retired"));
            capture->responder.reset();
        }
        return result;
    }

private:
    std::shared_ptr<CaptureHandler> stream_handler_;
    std::shared_ptr<CaptureHandler> packet_handler_;
    TestCarrier* carrier_{nullptr};
    std::shared_ptr<SessionEngine> session_;
    std::uint32_t next_stream_id_{1U};
    std::uint64_t next_sequence_{1U};
};

ytp1::Destination ipv4_destination(ytp1::TransportProtocol protocol,
                                   std::uint16_t port) {
    ytp1::Destination destination;
    destination.transport = protocol;
    destination.address_kind = ytp1::AddressKind::Ipv4;
    destination.address[0] = 127U;
    destination.address[1] = 0U;
    destination.address[2] = 0U;
    destination.address[3] = 1U;
    destination.address_length = 4U;
    destination.port = port;
    return destination;
}

ytp1::Destination dns_destination(ytp1::TransportProtocol protocol,
                                  std::string name,
                                  std::uint16_t port) {
    ytp1::Destination destination;
    destination.transport = protocol;
    destination.address_kind = ytp1::AddressKind::Dns;
    destination.dns_name = std::move(name);
    destination.port = port;
    return destination;
}

class IoRuntime final {
public:
    IoRuntime()
        : guard_(boost::asio::make_work_guard(context_)) {
        threads_.emplace_back([this]() { context_.run(); });
        threads_.emplace_back([this]() { context_.run(); });
    }
    IoRuntime(const IoRuntime&) = delete;
    IoRuntime& operator=(const IoRuntime&) = delete;
    ~IoRuntime() noexcept {
        guard_.reset();
        context_.stop();
        for (std::thread& thread : threads_) {
            if (thread.joinable()) {
                thread.join();
            }
        }
    }
    boost::asio::io_context& context() noexcept { return context_; }
private:
    boost::asio::io_context context_;
    boost::asio::executor_work_guard<
        boost::asio::io_context::executor_type> guard_;
    std::vector<std::thread> threads_;
};

template <typename T>
struct AsyncTicket final {
    std::shared_ptr<std::promise<T>> promise =
        std::make_shared<std::promise<T>>();
    std::future<T> future = promise->get_future();
    std::shared_ptr<std::atomic<unsigned int>> calls =
        std::make_shared<std::atomic<unsigned int>>(0U);
};

AsyncTicket<Result<RouteConnection>> start_open(
    const std::shared_ptr<AsioDirectRouteProvider>& provider,
    const AuthorizedRouteRequest& request,
    CancellationToken cancellation = {}) {
    AsyncTicket<Result<RouteConnection>> ticket;
    provider->async_open(
        request, std::move(cancellation),
        [promise = ticket.promise, calls = ticket.calls](
            Result<RouteConnection> result) mutable {
            calls->fetch_add(1U, std::memory_order_relaxed);
            promise->set_value(std::move(result));
        });
    return ticket;
}

template <typename T>
T await(AsyncTicket<T>& ticket, std::chrono::milliseconds timeout = 3s) {
    if (ticket.future.wait_for(timeout) != std::future_status::ready) {
        throw TestFailure("asynchronous operation timed out");
    }
    T result = ticket.future.get();
    CHECK(ticket.calls->load(std::memory_order_relaxed) == 1U);
    return result;
}

Result<RouteConnection> open_route(
    const std::shared_ptr<AsioDirectRouteProvider>& provider,
    const AuthorizedRouteRequest& request,
    CancellationToken cancellation = {}) {
    auto ticket = start_open(provider, request, std::move(cancellation));
    return await(ticket);
}

class TcpServer final {
public:
    using Handler = std::function<void(Tcp::socket&)>;

    explicit TcpServer(Handler handler,
                       boost::asio::ip::address address =
                           boost::asio::ip::make_address("127.0.0.1"))
        : acceptor_(context_), socket_(context_), handler_(std::move(handler)) {
        boost::system::error_code error;
        acceptor_.open(address.is_v4() ? Tcp::v4() : Tcp::v6(), error);
        CHECK(!error);
        acceptor_.set_option(Tcp::acceptor::reuse_address(true), error);
        CHECK(!error);
        acceptor_.bind(Tcp::endpoint(address, 0U), error);
        CHECK(!error);
        acceptor_.listen(4, error);
        CHECK(!error);
        port_ = acceptor_.local_endpoint().port();
        future_ = promise_.get_future();
        thread_ = std::thread([this]() noexcept {
            try {
                boost::system::error_code error;
                acceptor_.accept(socket_, error);
                if (error) {
                    throw TestFailure("TCP accept failed: " +
                                      error.message());
                }
                handler_(socket_);
                promise_.set_value(nullptr);
            } catch (...) {
                try {
                    promise_.set_value(std::current_exception());
                } catch (...) {
                }
            }
        });
    }

    TcpServer(const TcpServer&) = delete;
    TcpServer& operator=(const TcpServer&) = delete;
    ~TcpServer() noexcept {
        boost::system::error_code ignored;
        acceptor_.cancel(ignored);
        acceptor_.close(ignored);
        socket_.cancel(ignored);
        socket_.shutdown(Tcp::socket::shutdown_both, ignored);
        socket_.close(ignored);
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    std::uint16_t port() const noexcept { return port_; }

    void wait() {
        if (future_.wait_for(3s) != std::future_status::ready) {
            throw TestFailure("TCP server timed out");
        }
        if (std::exception_ptr error = future_.get()) {
            std::rethrow_exception(error);
        }
    }

private:
    boost::asio::io_context context_;
    Tcp::acceptor acceptor_;
    Tcp::socket socket_;
    Handler handler_;
    std::promise<std::exception_ptr> promise_;
    std::future<std::exception_ptr> future_;
    std::thread thread_;
    std::uint16_t port_{0U};
};

class UdpServer final {
public:
    using Handler = std::function<void(Udp::socket&)>;

    explicit UdpServer(Handler handler)
        : socket_(context_, Udp::endpoint(Udp::v4(), 0U)),
          handler_(std::move(handler)) {
        port_ = socket_.local_endpoint().port();
        future_ = promise_.get_future();
        thread_ = std::thread([this]() noexcept {
            try {
                handler_(socket_);
                promise_.set_value(nullptr);
            } catch (...) {
                try {
                    promise_.set_value(std::current_exception());
                } catch (...) {
                }
            }
        });
    }

    UdpServer(const UdpServer&) = delete;
    UdpServer& operator=(const UdpServer&) = delete;
    ~UdpServer() noexcept {
        boost::system::error_code ignored;
        socket_.cancel(ignored);
        socket_.close(ignored);
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    std::uint16_t port() const noexcept { return port_; }

    void wait() {
        if (future_.wait_for(3s) != std::future_status::ready) {
            throw TestFailure("UDP server timed out");
        }
        if (std::exception_ptr error = future_.get()) {
            std::rethrow_exception(error);
        }
    }

private:
    boost::asio::io_context context_;
    Udp::socket socket_;
    Handler handler_;
    std::promise<std::exception_ptr> promise_;
    std::future<std::exception_ptr> future_;
    std::thread thread_;
    std::uint16_t port_{0U};
};

std::shared_ptr<AsioDirectRouteProvider> make_provider(
    IoRuntime& runtime,
    AsioDirectRouteLimits limits = {},
    SocketProtector protector = {}) {
    return require(AsioDirectRouteProvider::create(
        runtime.context().get_executor(), ExecutorAffinity(91U), limits,
        std::move(protector)));
}

AsyncTicket<Result<Buffer>> start_read(ByteChannel& channel,
                                       std::size_t max_bytes,
                                       CancellationToken cancellation = {}) {
    AsyncTicket<Result<Buffer>> ticket;
    channel.async_read(
        max_bytes, std::move(cancellation),
        [promise = ticket.promise, calls = ticket.calls](
            Result<Buffer> result) mutable {
            calls->fetch_add(1U, std::memory_order_relaxed);
            promise->set_value(std::move(result));
        });
    return ticket;
}

struct TransferResult final {
    Status status;
    std::size_t transferred{0U};
};

AsyncTicket<TransferResult> start_write(ByteChannel& channel,
                                        Buffer buffer,
                                        CancellationToken cancellation = {}) {
    AsyncTicket<TransferResult> ticket;
    channel.async_write(
        std::move(buffer), std::move(cancellation),
        [promise = ticket.promise, calls = ticket.calls](
            Status status, std::size_t transferred) mutable {
            calls->fetch_add(1U, std::memory_order_relaxed);
            promise->set_value(
                TransferResult{std::move(status), transferred});
        });
    return ticket;
}

AsyncTicket<Result<Buffer>> start_receive(
    PacketChannel& channel,
    CancellationToken cancellation = {}) {
    AsyncTicket<Result<Buffer>> ticket;
    channel.async_receive(
        std::move(cancellation),
        [promise = ticket.promise, calls = ticket.calls](
            Result<Buffer> result) mutable {
            calls->fetch_add(1U, std::memory_order_relaxed);
            promise->set_value(std::move(result));
        });
    return ticket;
}

AsyncTicket<TransferResult> start_send(
    PacketChannel& channel,
    Buffer packet,
    CancellationToken cancellation = {}) {
    AsyncTicket<TransferResult> ticket;
    channel.async_send(
        std::move(packet), std::move(cancellation),
        [promise = ticket.promise, calls = ticket.calls](
            Status status, std::size_t transferred) mutable {
            calls->fetch_add(1U, std::memory_order_relaxed);
            promise->set_value(
                TransferResult{std::move(status), transferred});
        });
    return ticket;
}

void run_barrier(IoRuntime& runtime) {
    auto promise = std::make_shared<std::promise<void>>();
    std::future<void> future = promise->get_future();
    boost::asio::post(runtime.context(), [promise]() {
        promise->set_value();
    });
    CHECK(future.wait_for(3s) == std::future_status::ready);
    future.get();
}

void test_creation_and_limits() {
    IoRuntime runtime;
    auto provider = make_provider(runtime);
    CHECK(provider->descriptor().provider_id() ==
          kAsioDirectRouteProviderId);
    CHECK(provider->descriptor().kind() == ProviderKind::RouteProvider);
    CHECK(provider->descriptor().api_version() ==
          kAsioDirectRouteProviderApiVersion);
    CHECK(provider->descriptor().capabilities().contains_all(
        mandatory_capabilities(ProviderKind::RouteProvider)));
    CHECK(provider->descriptor().capabilities().contains(
        Capability::DirectTcp));
    CHECK(provider->descriptor().capabilities().contains(
        Capability::DirectUdp));
    CHECK(provider->executor_affinity() == ExecutorAffinity(91U));

    std::thread cancel_thread([provider]() { provider->cancel(); });
    cancel_thread.join();
    auto post_cancel_provider = make_provider(runtime);
    CHECK(post_cancel_provider);

    auto rejected = [&](AsioDirectRouteLimits limits) {
        const auto result = AsioDirectRouteProvider::create(
            runtime.context().get_executor(), ExecutorAffinity(1U), limits);
        CHECK(!result.ok());
        CHECK(result.status().code() == StatusCode::InvalidArgument);
    };

    AsioDirectRouteLimits invalid;
    invalid.max_pending_opens = 0U;
    rejected(invalid);
    invalid = {};
    invalid.max_active_connections = 0U;
    rejected(invalid);
    invalid = {};
    invalid.max_resolved_endpoints = 0U;
    rejected(invalid);
    invalid = {};
    invalid.max_tcp_read_bytes = 0U;
    rejected(invalid);
    invalid = {};
    invalid.max_tcp_write_bytes = kAbsoluteMaxBufferBytes + 1U;
    rejected(invalid);
    invalid = {};
    invalid.max_udp_packet_bytes = 65'508U;
    rejected(invalid);
    invalid = {};
    invalid.resolve_timeout = 0ms;
    rejected(invalid);
    invalid = {};
    invalid.connect_timeout = 601s;
    rejected(invalid);

    auto bad_executor = AsioDirectRouteProvider::create(
        boost::asio::any_io_executor{}, ExecutorAffinity(1U));
    CHECK(!bad_executor.ok());
    CHECK(bad_executor.status().code() == StatusCode::InvalidArgument);
    auto bad_affinity = AsioDirectRouteProvider::create(
        runtime.context().get_executor(), ExecutorAffinity{});
    CHECK(!bad_affinity.ok());
    CHECK(bad_affinity.status().code() == StatusCode::InvalidArgument);
}

void test_tcp_round_trip_and_half_close(RequestFactory& requests) {
    TcpServer server([](Tcp::socket& socket) {
        std::array<char, 4> input{};
        boost::system::error_code error;
        const std::size_t received = boost::asio::read(
            socket, boost::asio::buffer(input), error);
        CHECK(!error);
        CHECK(received == input.size());
        CHECK(std::string_view(input.data(), input.size()) == "ping");
        CHECK(boost::asio::write(socket, boost::asio::buffer("pong", 4U),
                                 error) == 4U);
        CHECK(!error);

        std::array<char, 1> eof_probe{};
        const std::size_t after_fin = socket.read_some(
            boost::asio::buffer(eof_probe), error);
        CHECK(after_fin == 0U);
        CHECK(error == boost::asio::error::eof);
        error.clear();
        CHECK(boost::asio::write(socket, boost::asio::buffer("tail", 4U),
                                 error) == 4U);
        CHECK(!error);
        socket.shutdown(Tcp::socket::shutdown_send, error);
    });

    IoRuntime runtime;
    std::atomic<unsigned int> protector_calls{0U};
    std::atomic<bool> protected_tcp{false};
    AsioDirectRouteLimits limits;
    limits.max_tcp_read_bytes = 8U;
    limits.max_tcp_write_bytes = 8U;
    auto provider = make_provider(
        runtime, limits,
        [&](NativeSocket socket) {
            protector_calls.fetch_add(1U, std::memory_order_relaxed);
            protected_tcp.store(socket.protocol == NetworkProtocol::Tcp,
                                std::memory_order_relaxed);
            return Status::success();
        });
    std::thread provider_cancel_before_open(
        [provider]() { provider->cancel(); });
    provider_cancel_before_open.join();
    auto request = requests.make(ipv4_destination(
        ytp1::TransportProtocol::Tcp, server.port()));
    auto opened = open_route(provider, request);
    CHECK(opened.ok());
    RouteConnection connection = std::move(opened).take_value();
    CHECK(connection.kind() == ServiceKind::ByteStream);
    std::unique_ptr<ByteChannel> channel = connection.take_byte_channel();
    CHECK(channel);
    CHECK(channel->executor_affinity() == ExecutorAffinity(91U));
    CHECK(channel->max_read_size() == 8U);
    CHECK(channel->max_write_size() == 8U);
    CHECK(protector_calls.load(std::memory_order_relaxed) == 1U);
    CHECK(protected_tcp.load(std::memory_order_relaxed));

    std::promise<std::thread::id> immediate_callback_thread;
    std::future<std::thread::id> immediate_callback_future =
        immediate_callback_thread.get_future();
    channel->async_read(
        0U, {}, [&immediate_callback_thread](Result<Buffer>) {
            immediate_callback_thread.set_value(std::this_thread::get_id());
        });
    CHECK(immediate_callback_future.wait_for(3s) ==
          std::future_status::ready);
    CHECK(immediate_callback_future.get() != std::this_thread::get_id());

    auto invalid_read = start_read(*channel, 0U);
    auto invalid_read_result = await(invalid_read);
    CHECK(!invalid_read_result.ok());
    CHECK(invalid_read_result.status().code() ==
          StatusCode::InvalidArgument);

    auto oversized_write = start_write(
        *channel, make_buffer("123456789", 9U));
    TransferResult oversized = await(oversized_write);
    CHECK(!oversized.status.ok());
    CHECK(oversized.status.code() == StatusCode::ResourceExhausted);
    CHECK(oversized.transferred == 0U);

    auto write = start_write(*channel, make_buffer("ping", 8U));
    TransferResult written = await(write);
    CHECK(written.status.ok());
    CHECK(written.transferred == 4U);
    auto first_read = start_read(*channel, 4U);
    auto pong = await(first_read);
    CHECK(pong.ok());
    CHECK(buffer_text(*pong.value_if()) == "pong");

    CHECK(channel->shutdown_write().ok());
    CHECK(channel->shutdown_write().ok());
    auto tail_read = start_read(*channel, 4U);
    auto tail = await(tail_read);
    CHECK(tail.ok());
    CHECK(buffer_text(*tail.value_if()) == "tail");
    auto eof_read = start_read(*channel, 4U);
    auto eof = await(eof_read);
    CHECK(!eof.ok());
    CHECK(eof.status().code() == StatusCode::Closed);
    auto after_shutdown = start_write(*channel, make_buffer("x", 8U));
    TransferResult rejected = await(after_shutdown);
    CHECK(!rejected.status.ok());
    CHECK(rejected.status.code() == StatusCode::Closed);

    channel->close();
    server.wait();
}

void test_udp_round_trip_and_truncation(RequestFactory& requests) {
    UdpServer server([](Udp::socket& socket) {
        std::array<char, 32> input{};
        Udp::endpoint peer;
        boost::system::error_code error;
        std::size_t received = socket.receive_from(
            boost::asio::buffer(input), peer, 0, error);
        CHECK(!error);
        CHECK(std::string_view(input.data(), received) == "ping");
        CHECK(socket.send_to(boost::asio::buffer("pong", 4U), peer, 0,
                             error) == 4U);
        CHECK(!error);
        received = socket.receive_from(
            boost::asio::buffer(input), peer, 0, error);
        CHECK(!error);
        CHECK(std::string_view(input.data(), received) == "x");
        CHECK(socket.send_to(boost::asio::buffer("12345", 5U), peer, 0,
                             error) == 5U);
        CHECK(!error);
    });

    IoRuntime runtime;
    std::atomic<unsigned int> protector_calls{0U};
    AsioDirectRouteLimits limits;
    limits.max_udp_packet_bytes = 4U;
    auto provider = make_provider(
        runtime, limits,
        [&](NativeSocket socket) {
            CHECK(socket.protocol == NetworkProtocol::Udp);
            protector_calls.fetch_add(1U, std::memory_order_relaxed);
            return Status::success();
        });
    auto request = requests.make(ipv4_destination(
        ytp1::TransportProtocol::Udp, server.port()));
    auto opened = open_route(provider, request);
    CHECK(opened.ok());
    RouteConnection connection = std::move(opened).take_value();
    CHECK(connection.kind() == ServiceKind::PacketChannel);
    std::unique_ptr<PacketChannel> channel =
        connection.take_packet_channel();
    CHECK(channel);
    CHECK(channel->max_packet_size() == 4U);
    CHECK(channel->executor_affinity() == ExecutorAffinity(91U));
    CHECK(protector_calls.load(std::memory_order_relaxed) == 1U);

    auto oversized_send = start_send(
        *channel, make_buffer("12345", 5U));
    TransferResult oversized = await(oversized_send);
    CHECK(!oversized.status.ok());
    CHECK(oversized.status.code() == StatusCode::ResourceExhausted);
    CHECK(oversized.transferred == 0U);

    auto send = start_send(*channel, make_buffer("ping", 4U));
    TransferResult sent = await(send);
    CHECK(sent.status.ok());
    CHECK(sent.transferred == 4U);
    auto receive = start_receive(*channel);
    auto pong = await(receive);
    CHECK(pong.ok());
    CHECK(buffer_text(*pong.value_if()) == "pong");

    auto trigger = start_send(*channel, make_buffer("x", 4U));
    CHECK(await(trigger).status.ok());
    auto truncated = start_receive(*channel);
    auto oversized_packet = await(truncated);
    CHECK(!oversized_packet.ok());
    CHECK(oversized_packet.status().code() ==
          StatusCode::ResourceExhausted);

    channel->close();
    server.wait();
}

boost::asio::ip::address first_localhost_address() {
    boost::asio::io_context context;
    Tcp::resolver resolver(context);
    boost::system::error_code error;
    const auto results = resolver.resolve(
        "localhost", "0", Tcp::resolver::numeric_service, error);
    CHECK(!error);
    CHECK(results.begin() != results.end());
    return results.begin()->endpoint().address();
}

void test_dns_and_connect_errors(RequestFactory& requests) {
    const boost::asio::ip::address localhost = first_localhost_address();
    TcpServer server([](Tcp::socket& socket) {
        boost::system::error_code error;
        std::array<char, 1> byte{};
        const std::size_t received = socket.read_some(
            boost::asio::buffer(byte), error);
        CHECK(received == 0U);
        CHECK(error == boost::asio::error::eof);
    }, localhost);

    IoRuntime runtime;
    AsioDirectRouteLimits limits;
    limits.max_resolved_endpoints = 1U;
    limits.resolve_timeout = 500ms;
    limits.connect_timeout = 500ms;
    auto provider = make_provider(runtime, limits);
    auto request = requests.make(dns_destination(
        ytp1::TransportProtocol::Tcp, "localhost", server.port()));
    auto opened = open_route(provider, request);
    CHECK(opened.ok());
    RouteConnection connection = std::move(opened).take_value();
    CHECK(connection.kind() == ServiceKind::ByteStream);
    auto channel = connection.take_byte_channel();
    channel->close();
    server.wait();

    Tcp::acceptor unused(runtime.context());
    boost::system::error_code error;
    unused.open(Tcp::v4(), error);
    CHECK(!error);
    unused.bind(Tcp::endpoint(Tcp::v4(), 0U), error);
    CHECK(!error);
    const std::uint16_t closed_port = unused.local_endpoint().port();
    unused.close(error);
    CHECK(!error);
    auto closed_request = requests.make(ipv4_destination(
        ytp1::TransportProtocol::Tcp, closed_port));
    auto refused = open_route(provider, closed_request);
    CHECK(!refused.ok());
    CHECK(refused.status().code() == StatusCode::NotFound);

    auto missing_request = requests.make(dns_destination(
        ytp1::TransportProtocol::Tcp,
        "definitely-missing.invalid", 443U));
    auto missing = open_route(provider, missing_request);
    CHECK(!missing.ok());
    CHECK(missing.status().code() == StatusCode::NotFound);
}

void test_active_capacity_and_release(RequestFactory& requests) {
    auto drain = [](Tcp::socket& socket) {
        std::array<char, 32> bytes{};
        boost::system::error_code error;
        while (socket.read_some(boost::asio::buffer(bytes), error) > 0U) {
        }
        CHECK(error == boost::asio::error::eof ||
              error == boost::asio::error::operation_aborted);
    };
    TcpServer first_server(drain);
    IoRuntime runtime;
    AsioDirectRouteLimits limits;
    limits.max_active_connections = 1U;
    limits.max_pending_opens = 1U;
    auto provider = make_provider(runtime, limits);
    auto first_request = requests.make(ipv4_destination(
        ytp1::TransportProtocol::Tcp, first_server.port()));
    auto first_open = open_route(provider, first_request);
    CHECK(first_open.ok());
    RouteConnection first_connection = std::move(first_open).take_value();
    auto first_channel = first_connection.take_byte_channel();

    auto second_request = requests.make(ipv4_destination(
        ytp1::TransportProtocol::Tcp, first_server.port()));
    auto second_open = open_route(provider, second_request);
    CHECK(!second_open.ok());
    CHECK(second_open.status().code() == StatusCode::ResourceExhausted);

    first_channel->close();
    first_server.wait();
    run_barrier(runtime);

    TcpServer second_server(drain);
    auto third_request = requests.make(ipv4_destination(
        ytp1::TransportProtocol::Tcp, second_server.port()));
    auto third_open = open_route(provider, third_request);
    CHECK(third_open.ok());
    RouteConnection third_connection = std::move(third_open).take_value();
    auto third_channel = third_connection.take_byte_channel();
    third_channel->close();
    second_server.wait();
}

class BlockingProtector final {
public:
    Status operator()(NativeSocket) {
        std::unique_lock<std::mutex> lock(mutex_);
        ++calls_;
        entered_ = true;
        condition_.notify_all();
        condition_.wait(lock, [this]() { return released_; });
        return status_;
    }

    void wait_until_entered() {
        std::unique_lock<std::mutex> lock(mutex_);
        CHECK(condition_.wait_for(lock, 3s,
                                  [this]() { return entered_; }));
    }

    void release() {
        std::lock_guard<std::mutex> lock(mutex_);
        released_ = true;
        condition_.notify_all();
    }

    unsigned int calls() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return calls_;
    }

private:
    mutable std::mutex mutex_;
    std::condition_variable condition_;
    Status status_{};
    unsigned int calls_{0U};
    bool entered_{false};
    bool released_{false};
};

void test_pending_capacity(RequestFactory& requests) {
    TcpServer server([](Tcp::socket& socket) {
        std::array<char, 8> bytes{};
        boost::system::error_code error;
        while (socket.read_some(boost::asio::buffer(bytes), error) > 0U) {
        }
    });
    IoRuntime runtime;
    AsioDirectRouteLimits limits;
    limits.max_pending_opens = 1U;
    limits.max_active_connections = 2U;
    auto blocker = std::make_shared<BlockingProtector>();
    auto provider = make_provider(
        runtime, limits,
        [blocker](NativeSocket socket) { return (*blocker)(socket); });
    auto first_request = requests.make(ipv4_destination(
        ytp1::TransportProtocol::Tcp, server.port()));
    auto second_request = requests.make(ipv4_destination(
        ytp1::TransportProtocol::Tcp, server.port()));
    auto first = start_open(provider, first_request);
    blocker->wait_until_entered();
    auto second = start_open(provider, second_request);
    blocker->release();

    auto first_result = await(first);
    auto second_result = await(second);
    CHECK(first_result.ok());
    CHECK(!second_result.ok());
    CHECK(second_result.status().code() == StatusCode::ResourceExhausted);
    CHECK(blocker->calls() == 1U);
    RouteConnection connection = std::move(first_result).take_value();
    connection.byte_channel_if()->close();
    server.wait();
}

void test_open_and_channel_cancellation(RequestFactory& requests) {
    IoRuntime runtime;
    auto provider = make_provider(runtime);
    CancellationSource already_cancelled;
    CHECK(already_cancelled.cancel());
    auto cancelled_request = requests.make(ipv4_destination(
        ytp1::TransportProtocol::Tcp, 9U));
    auto cancelled = open_route(
        provider, cancelled_request, already_cancelled.token());
    CHECK(!cancelled.ok());
    CHECK(cancelled.status().code() == StatusCode::Cancelled);

    struct SendGate final {
        std::mutex mutex;
        std::condition_variable condition;
        bool accepted{false};
        bool send{false};
    };
    auto gate = std::make_shared<SendGate>();
    TcpServer server([gate](Tcp::socket& socket) {
        {
            std::unique_lock<std::mutex> lock(gate->mutex);
            gate->accepted = true;
            gate->condition.notify_all();
            gate->condition.wait(lock, [&]() { return gate->send; });
        }
        boost::system::error_code error;
        CHECK(boost::asio::write(socket, boost::asio::buffer("ok", 2U),
                                 error) == 2U);
        CHECK(!error);
        std::array<char, 8> bytes{};
        while (socket.read_some(boost::asio::buffer(bytes), error) > 0U) {
        }
    });
    auto active_request = requests.make(ipv4_destination(
        ytp1::TransportProtocol::Tcp, server.port()));
    auto active = open_route(provider, active_request);
    CHECK(active.ok());
    RouteConnection connection = std::move(active).take_value();
    auto channel = connection.take_byte_channel();
    {
        std::unique_lock<std::mutex> lock(gate->mutex);
        CHECK(gate->condition.wait_for(
            lock, 3s, [&]() { return gate->accepted; }));
    }

    CancellationSource read_cancel;
    auto pending_read = start_read(*channel, 2U, read_cancel.token());
    CHECK(read_cancel.cancel());
    auto read_result = await(pending_read);
    CHECK(!read_result.ok());
    CHECK(read_result.status().code() == StatusCode::Cancelled);

    {
        std::lock_guard<std::mutex> lock(gate->mutex);
        gate->send = true;
        gate->condition.notify_all();
    }
    auto next_read = start_read(*channel, 2U);
    auto recovered = await(next_read);
    CHECK(recovered.ok());
    CHECK(buffer_text(*recovered.value_if()) == "ok");

    auto provider_cancelled_read = start_read(*channel, 2U);
    provider->cancel();
    auto provider_cancelled = await(provider_cancelled_read);
    CHECK(!provider_cancelled.ok());
    CHECK(provider_cancelled.status().code() == StatusCode::Cancelled);
    channel->close();
    server.wait();
}

void test_provider_cancel_pending_open(RequestFactory& requests) {
    TcpServer server([](Tcp::socket& socket) {
        std::array<char, 8> bytes{};
        boost::system::error_code error;
        while (socket.read_some(boost::asio::buffer(bytes), error) > 0U) {
        }
    });
    IoRuntime runtime;
    auto blocker = std::make_shared<BlockingProtector>();
    auto provider = make_provider(
        runtime, {},
        [blocker](NativeSocket socket) { return (*blocker)(socket); });
    auto request = requests.make(ipv4_destination(
        ytp1::TransportProtocol::Tcp, server.port()));
    auto pending = start_open(provider, request);
    blocker->wait_until_entered();
    provider->cancel();
    blocker->release();
    auto result = await(pending);
    CHECK(!result.ok());
    CHECK(result.status().code() == StatusCode::Cancelled);
    server.wait();
}

void test_socket_protector_failures(RequestFactory& requests) {
    IoRuntime runtime;
    std::atomic<unsigned int> calls{0U};
    auto denied_provider = make_provider(
        runtime, {},
        [&](NativeSocket socket) {
            CHECK(socket.protocol == NetworkProtocol::Tcp);
            calls.fetch_add(1U, std::memory_order_relaxed);
            return Status(StatusCode::FailedPrecondition,
                          "test socket policy denied egress");
        });
    auto denied_request = requests.make(ipv4_destination(
        ytp1::TransportProtocol::Tcp, 9U));
    auto denied = open_route(denied_provider, denied_request);
    CHECK(!denied.ok());
    CHECK(denied.status().code() == StatusCode::FailedPrecondition);
    CHECK(calls.load(std::memory_order_relaxed) == 1U);

    auto throwing_provider = make_provider(
        runtime, {}, [](NativeSocket) -> Status {
            throw std::runtime_error("test protector exception");
        });
    auto throwing_request = requests.make(ipv4_destination(
        ytp1::TransportProtocol::Tcp, 9U));
    auto failed = open_route(throwing_provider, throwing_request);
    CHECK(!failed.ok());
    CHECK(failed.status().code() == StatusCode::Internal);
}

}  // namespace
}  // namespace yume::providers

int main() {
    try {
        yume::providers::test_creation_and_limits();
        yume::providers::RequestFactory requests;
        yume::providers::test_tcp_round_trip_and_half_close(requests);
        yume::providers::test_udp_round_trip_and_truncation(requests);
        yume::providers::test_dns_and_connect_errors(requests);
        yume::providers::test_active_capacity_and_release(requests);
        yume::providers::test_pending_capacity(requests);
        yume::providers::test_open_and_channel_cancellation(requests);
        yume::providers::test_provider_cancel_pending_open(requests);
        yume::providers::test_socket_protector_failures(requests);
        std::cout << "Asio direct-route provider tests passed\n";
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << "Asio direct-route provider test failed: "
                  << exception.what() << '\n';
        return 1;
    }
}
