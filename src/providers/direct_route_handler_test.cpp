/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "engine/front_door.hpp"
#include "engine/session_engine.hpp"
#include "providers/direct_route_handler.hpp"
#include "ytp/protocol.hpp"
#include "ytp/security.hpp"

namespace yume::providers {
namespace {

using namespace engine;

class TestFailure final : public std::runtime_error {
public:
    explicit TestFailure(std::string message)
        : std::runtime_error(std::move(message)) {}
};

#define CHECK(expression)                                                     \
    do {                                                                      \
        if (!(expression)) {                                                  \
            throw TestFailure(std::string("check failed: ") + #expression);  \
        }                                                                     \
    } while (false)

template <typename T>
T require(Result<T> result) {
    if (!result.ok()) {
        throw TestFailure(result.status().message());
    }
    return std::move(result).take_value();
}

Buffer buffer(std::string_view text,
              std::size_t limit = kAbsoluteMaxBufferBytes) {
    return require(Buffer::copy_from(
        {reinterpret_cast<const std::byte*>(text.data()), text.size()},
        limit));
}

std::string text(const Buffer& value) {
    return std::string(
        reinterpret_cast<const char*>(value.bytes().data()), value.size());
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
        {"packet", ytp1::ServiceKind::Packet, 4U},
        {"stream", ytp1::ServiceKind::ByteStream, 4U},
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
    void async_create(EndpointRole, CancellationToken,
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
    void async_wrap(std::unique_ptr<ByteChannel>, EndpointRole,
                    CancellationToken, Completion completion) override {
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
    void async_create(EndpointRole, CancellationToken,
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
    void async_create(std::unique_ptr<SecureChannel>, EndpointRole,
                      CancellationToken, Completion completion) override {
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
    void async_open(const AuthorizedRouteRequest&, CancellationToken,
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
                             "expected a routed open"));
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
        AuthenticationMessageKind kind, std::span<const std::byte>) override {
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
    Result<Buffer> seal_record(RecordKeyToken,
                               std::span<const std::byte> plaintext) override {
        return Result<Buffer>(copy_bytes(plaintext));
    }
    Result<Buffer> open_record(RecordKeyToken,
                               std::span<const std::byte> ciphertext) override {
        return Result<Buffer>(copy_bytes(ciphertext));
    }
    Result<Buffer> begin_outbound_rekey(std::uint32_t) override {
        return Result<Buffer>(Status(StatusCode::FailedPrecondition,
                                     "unused"));
    }
    Result<Buffer> accept_inbound_rekey(
        std::uint32_t, std::span<const std::byte>) override {
        return Result<Buffer>(Status(StatusCode::FailedPrecondition,
                                     "unused"));
    }
    Status finish_outbound_rekey(
        std::uint32_t, std::span<const std::byte>) override {
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
        return ExecutorAffinity(11U);
    }
    std::size_t max_read_size() const noexcept override {
        return 128U * 1024U;
    }
    std::size_t max_write_size() const noexcept override {
        return 128U * 1024U;
    }
    void async_read(std::size_t, CancellationToken,
                    ReadCompletion completion) override {
        completion(Result<Buffer>(Status(StatusCode::FailedPrecondition,
                                          "unused")));
    }
    void async_write(Buffer, CancellationToken,
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
        std::string_view, std::span<const std::byte>,
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
        return ExecutorAffinity(11U);
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
    void async_send(Buffer record, CancellationToken,
                    SendCompletion completion) override {
        const std::size_t size = record.size();
        sent.push_back(std::move(record));
        completion(Status::success(), size);
    }
    void cancel() noexcept override {}
    void close() noexcept override { closed = true; }
    void deliver(Buffer record) {
        CHECK(receive_);
        auto completion = std::move(receive_);
        receive_ = {};
        const std::size_t size = record.size();
        completion(Result<ReceivedRecord>(ReceivedRecord(
            std::move(record), CarrierCredit(size, [](std::size_t) {}))));
    }
    std::vector<Buffer> sent;
    bool closed{false};
private:
    ProviderDescriptor descriptor_;
    TestSecureChannel secure_;
    ReceiveCompletion receive_;
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
        4U, mandatory_capabilities(ProviderKind::StreamHandler)
                .with(Capability::PacketChannels)
                .with(Capability::DirectUdp))));
    services.push_back(require(ServiceRequirement::create(
        "stream", ServiceKind::ByteStream, "test.capture.stream", 1U,
        4U, mandatory_capabilities(ProviderKind::StreamHandler)
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
    CHECK(builder.register_stream_handler(
              "stream", stream_handler).ok());
    CHECK(builder.register_stream_handler(
              "packet", packet_handler).ok());
    return require(builder.build());
}

AuthorizedRouteRequest authorized_request(ServiceKind kind) {
    auto stream_handler =
        std::make_shared<CaptureHandler>(ServiceKind::ByteStream);
    auto packet_handler =
        std::make_shared<CaptureHandler>(ServiceKind::PacketChannel);
    auto carrier_owner = std::make_unique<TestCarrier>();
    TestCarrier* carrier = carrier_owner.get();
    auto session = require(SessionEngine::create(
        request_graph(stream_handler, packet_handler),
        std::move(carrier_owner)));

    int starts = 0;
    session->async_start([&](Status status) {
        CHECK(status.ok());
        ++starts;
    });
    CHECK(carrier->sent.size() == 1U);
    Buffer response = auth_message(
        ytp1::AuthMessageType::Response, ytp1::EndpointRole::Client);
    carrier->deliver(frame(ytp1::RecordType::Auth, 0U,
                           response.bytes()));
    CHECK(carrier->sent.size() == 4U);
    carrier->deliver(copy_bytes(carrier->sent[2].bytes()));
    CHECK(starts == 1);
    CHECK(session->state() == SessionState::Active);

    ytp1::Destination destination;
    destination.transport = kind == ServiceKind::ByteStream
        ? ytp1::TransportProtocol::Tcp
        : ytp1::TransportProtocol::Udp;
    destination.address_kind = ytp1::AddressKind::Dns;
    destination.dns_name = "example.com";
    destination.port = kind == ServiceKind::ByteStream ? 443U : 53U;
    const ytp1::OpenRequest open{
        kind == ServiceKind::ByteStream
            ? ytp1::ServiceKind::ByteStream
            : ytp1::ServiceKind::Packet,
        kind == ServiceKind::ByteStream ? "stream" : "packet",
        destination};
    const auto encoded = ytp1::EncodeOpen(open);
    CHECK(encoded.ok());
    carrier->deliver(protected_wire(
        1U, frame(
            ytp1::RecordType::Open, 1U,
            {reinterpret_cast<const std::byte*>(encoded.value->data()),
             encoded.value->size()})));

    auto& capture = kind == ServiceKind::ByteStream
        ? stream_handler
        : packet_handler;
    CHECK(capture->request.has_value());
    AuthorizedRouteRequest result = std::move(*capture->request);
    session->stop();
    return result;
}

class ManualStream final : public StreamResponder {
public:
    explicit ManualStream(ServiceKind kind, std::size_t max_write = 32U)
        : kind_(kind), max_write_(max_write) {}
    ExecutorAffinity executor_affinity() const noexcept override {
        return ExecutorAffinity(21U);
    }
    ServiceKind service_kind() const noexcept override { return kind_; }
    std::size_t max_write_size() const noexcept override {
        return max_write_;
    }
    void async_read(CancellationToken,
                    ReadCompletion completion) override {
        CHECK(!read_);
        if (closed_) {
            completion(Result<ReceivedRecord>(Status(
                StatusCode::Closed, "manual stream is closed")));
            return;
        }
        read_ = std::move(completion);
        ++read_issues;
    }
    void async_write(Buffer payload, CancellationToken,
                     WriteCompletion completion) override {
        CHECK(!write_);
        if (closed_) {
            completion(Status(StatusCode::Closed,
                              "manual stream is closed"), 0U);
            return;
        }
        writes.push_back(text(payload));
        write_size_ = payload.size();
        write_ = std::move(completion);
        ++write_issues;
    }
    Status shutdown_write() noexcept override {
        ++shutdown_calls;
        return shutdown_status;
    }
    void close(Status reason) noexcept override {
        if (closed_) {
            return;
        }
        closed_ = true;
        ++close_calls;
        close_code = reason.code();
        auto read = std::move(read_);
        auto write = std::move(write_);
        read_ = {};
        write_ = {};
        if (read) {
            read(Result<ReceivedRecord>(reason));
        }
        if (write) {
            write(reason, 0U);
        }
    }
    void deliver(std::string_view payload,
                 CarrierCredit::ReleaseHandler release) {
        CHECK(read_);
        auto completion = std::move(read_);
        read_ = {};
        completion(Result<ReceivedRecord>(ReceivedRecord(
            buffer(payload), CarrierCredit(payload.size(),
                                           std::move(release)))));
    }
    void end(Status status = Status(
                 StatusCode::Closed, "manual stream EOF")) {
        CHECK(read_);
        auto completion = std::move(read_);
        read_ = {};
        completion(Result<ReceivedRecord>(std::move(status)));
    }
    void complete_write(Status status = Status::success(),
                        std::optional<std::size_t> transferred = std::nullopt) {
        CHECK(write_);
        auto completion = std::move(write_);
        write_ = {};
        completion(std::move(status), transferred.value_or(write_size_));
    }
    int read_issues{0};
    int write_issues{0};
    int shutdown_calls{0};
    int close_calls{0};
    StatusCode close_code{StatusCode::Ok};
    Status shutdown_status{};
    std::vector<std::string> writes;
private:
    ServiceKind kind_;
    std::size_t max_write_;
    std::size_t write_size_{0U};
    ReadCompletion read_;
    WriteCompletion write_;
    bool closed_{false};
};

struct ChannelTrace final {
    int cancel_calls{0};
    int close_calls{0};
    int shutdown_calls{0};
    std::vector<std::string> writes;
};

class ManualByteChannel final : public ByteChannel {
public:
    explicit ManualByteChannel(std::shared_ptr<ChannelTrace> trace,
                               std::size_t max_write = 3U)
        : trace_(std::move(trace)), max_write_(max_write) {}
    ExecutorAffinity executor_affinity() const noexcept override {
        return ExecutorAffinity(22U);
    }
    std::size_t max_read_size() const noexcept override { return 32U; }
    std::size_t max_write_size() const noexcept override {
        return max_write_;
    }
    void async_read(std::size_t, CancellationToken,
                    ReadCompletion completion) override {
        CHECK(!read_);
        if (closed_) {
            completion(Result<Buffer>(Status(
                StatusCode::Closed, "manual byte channel is closed")));
            return;
        }
        read_ = std::move(completion);
        ++read_issues;
    }
    void async_write(Buffer payload, CancellationToken,
                     WriteCompletion completion) override {
        CHECK(!write_);
        if (closed_ || write_shutdown_) {
            completion(Status(StatusCode::Closed,
                              "manual byte write side is closed"), 0U);
            return;
        }
        trace_->writes.push_back(text(payload));
        write_size_ = payload.size();
        write_ = std::move(completion);
        ++write_issues;
    }
    Status shutdown_write() noexcept override {
        ++trace_->shutdown_calls;
        write_shutdown_ = true;
        return shutdown_status;
    }
    void cancel() noexcept override {
        ++trace_->cancel_calls;
        settle(Status(StatusCode::Cancelled,
                      "manual byte channel cancelled"));
    }
    void close() noexcept override {
        if (closed_) {
            return;
        }
        closed_ = true;
        ++trace_->close_calls;
        settle(Status(StatusCode::Closed,
                      "manual byte channel closed"));
    }
    void deliver(std::string_view payload) {
        CHECK(read_);
        auto completion = std::move(read_);
        read_ = {};
        completion(Result<Buffer>(buffer(payload)));
    }
    void end() {
        CHECK(read_);
        auto completion = std::move(read_);
        read_ = {};
        completion(Result<Buffer>(Status(
            StatusCode::Closed, "manual byte channel EOF")));
    }
    void complete_write(Status status = Status::success(),
                        std::optional<std::size_t> transferred = std::nullopt) {
        CHECK(write_);
        auto completion = std::move(write_);
        write_ = {};
        completion(std::move(status), transferred.value_or(write_size_));
    }
    int read_issues{0};
    int write_issues{0};
    Status shutdown_status{};
private:
    void settle(Status status) noexcept {
        auto read = std::move(read_);
        auto write = std::move(write_);
        read_ = {};
        write_ = {};
        if (read) {
            read(Result<Buffer>(status));
        }
        if (write) {
            write(status, 0U);
        }
    }
    std::shared_ptr<ChannelTrace> trace_;
    std::size_t max_write_;
    std::size_t write_size_{0U};
    ReadCompletion read_;
    WriteCompletion write_;
    bool write_shutdown_{false};
    bool closed_{false};
};

class ManualPacketChannel final : public PacketChannel {
public:
    explicit ManualPacketChannel(std::shared_ptr<ChannelTrace> trace)
        : trace_(std::move(trace)) {}
    ExecutorAffinity executor_affinity() const noexcept override {
        return ExecutorAffinity(23U);
    }
    std::size_t max_packet_size() const noexcept override { return 32U; }
    void async_receive(CancellationToken,
                       ReceiveCompletion completion) override {
        CHECK(!receive_);
        if (closed_) {
            completion(Result<Buffer>(Status(
                StatusCode::Closed, "manual packet channel closed")));
            return;
        }
        receive_ = std::move(completion);
        ++receive_issues;
    }
    void async_send(Buffer packet, CancellationToken,
                    SendCompletion completion) override {
        CHECK(!send_);
        trace_->writes.push_back(text(packet));
        send_size_ = packet.size();
        send_ = std::move(completion);
        ++send_issues;
    }
    void cancel() noexcept override {
        ++trace_->cancel_calls;
        settle(Status(StatusCode::Cancelled,
                      "manual packet channel cancelled"));
    }
    void close() noexcept override {
        if (closed_) {
            return;
        }
        closed_ = true;
        ++trace_->close_calls;
        settle(Status(StatusCode::Closed,
                      "manual packet channel closed"));
    }
    void deliver(std::string_view packet) {
        CHECK(receive_);
        auto completion = std::move(receive_);
        receive_ = {};
        completion(Result<Buffer>(buffer(packet)));
    }
    void complete_send(Status status = Status::success(),
                       std::optional<std::size_t> transferred = std::nullopt) {
        CHECK(send_);
        auto completion = std::move(send_);
        send_ = {};
        completion(std::move(status), transferred.value_or(send_size_));
    }
    int receive_issues{0};
    int send_issues{0};
private:
    void settle(Status status) noexcept {
        auto receive = std::move(receive_);
        auto send = std::move(send_);
        receive_ = {};
        send_ = {};
        if (receive) {
            receive(Result<Buffer>(status));
        }
        if (send) {
            send(status, 0U);
        }
    }
    std::shared_ptr<ChannelTrace> trace_;
    std::size_t send_size_{0U};
    ReceiveCompletion receive_;
    SendCompletion send_;
    bool closed_{false};
};

class ManualRouteProvider final : public RouteProvider {
public:
    using Factory = std::function<Result<RouteConnection>()>;
    explicit ManualRouteProvider(Factory factory)
        : descriptor_(make_descriptor(
              "test.manual-route", ProviderKind::RouteProvider,
              mandatory_capabilities(ProviderKind::RouteProvider)
                  .with(Capability::DirectTcp)
                  .with(Capability::DirectUdp))),
          factory_(std::move(factory)) {}
    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }
    void async_open(const AuthorizedRouteRequest& request,
                    CancellationToken, Completion completion) override {
        CHECK(request.peer_evidence().identity() == "device-1");
        ++open_calls;
        if (throw_on_open) {
            throw std::runtime_error("manual provider throw");
        }
        completion(factory_());
    }
    void cancel() noexcept override { ++cancel_calls; }
    int open_calls{0};
    int cancel_calls{0};
    bool throw_on_open{false};
private:
    ProviderDescriptor descriptor_;
    Factory factory_;
};

ProviderDescriptor handler_descriptor(ServiceKind kind) {
    CapabilitySet capabilities =
        mandatory_capabilities(ProviderKind::StreamHandler)
            .with(kind == ServiceKind::ByteStream
                      ? Capability::DirectTcp
                      : Capability::DirectUdp);
    if (kind == ServiceKind::PacketChannel) {
        capabilities = capabilities.with(Capability::PacketChannels);
    }
    return make_descriptor(
        kind == ServiceKind::ByteStream
            ? "test.direct-stream"
            : "test.direct-packet",
        ProviderKind::StreamHandler, capabilities);
}

std::shared_ptr<DirectRouteHandler> direct_handler(
    ServiceKind kind, std::shared_ptr<RouteProvider> provider) {
    return require(DirectRouteHandler::create(
        handler_descriptor(kind), kind, std::move(provider),
        [](const StreamOpenContext&) { return Status::success(); }));
}

void test_open_failure_kind_mismatch_and_exception() {
    {
        auto provider = std::make_shared<ManualRouteProvider>([] {
            return Result<RouteConnection>(Status(
                StatusCode::NotFound, "route open failed"));
        });
        auto stream = std::make_shared<ManualStream>(
            ServiceKind::ByteStream);
        direct_handler(ServiceKind::ByteStream, provider)->on_route(
            authorized_request(ServiceKind::ByteStream), stream);
        CHECK(provider->open_calls == 1);
        CHECK(stream->close_calls == 1);
        CHECK(stream->close_code == StatusCode::NotFound);
    }
    {
        auto trace = std::make_shared<ChannelTrace>();
        auto provider = std::make_shared<ManualRouteProvider>([trace] {
            std::unique_ptr<PacketChannel> channel =
                std::make_unique<ManualPacketChannel>(trace);
            return RouteConnection::packet_channel(std::move(channel));
        });
        auto stream = std::make_shared<ManualStream>(
            ServiceKind::ByteStream);
        direct_handler(ServiceKind::ByteStream, provider)->on_route(
            authorized_request(ServiceKind::ByteStream), stream);
        CHECK(stream->close_calls == 1);
        CHECK(stream->close_code == StatusCode::ProviderMismatch);
        CHECK(trace->cancel_calls == 1);
        CHECK(trace->close_calls == 1);
    }
    {
        auto provider = std::make_shared<ManualRouteProvider>([] {
            return Result<RouteConnection>(Status(
                StatusCode::Internal, "unreachable"));
        });
        provider->throw_on_open = true;
        auto stream = std::make_shared<ManualStream>(
            ServiceKind::ByteStream);
        direct_handler(ServiceKind::ByteStream, provider)->on_route(
            authorized_request(ServiceKind::ByteStream), stream);
        CHECK(provider->open_calls == 1);
        CHECK(stream->close_calls == 1);
        CHECK(stream->close_code == StatusCode::Internal);
    }
}

void test_byte_bridge_credit_duplex_and_half_close() {
    auto trace = std::make_shared<ChannelTrace>();
    ManualByteChannel* channel = nullptr;
    auto provider = std::make_shared<ManualRouteProvider>([&] {
        auto owned = std::make_unique<ManualByteChannel>(trace, 3U);
        channel = owned.get();
        std::unique_ptr<ByteChannel> base = std::move(owned);
        return RouteConnection::byte_stream(std::move(base));
    });
    auto stream = std::make_shared<ManualStream>(
        ServiceKind::ByteStream, 32U);
    auto handler = direct_handler(ServiceKind::ByteStream, provider);
    handler->on_route(authorized_request(ServiceKind::ByteStream), stream);
    CHECK(channel);
    CHECK(stream->read_issues == 1);
    CHECK(channel->read_issues == 1);

    std::size_t released = 0U;
    int release_calls = 0;
    stream->deliver("abcdef", [&](std::size_t bytes) {
        ++release_calls;
        released += bytes;
    });
    CHECK((trace->writes == std::vector<std::string>{"abc"}));
    CHECK(release_calls == 0);
    channel->complete_write();
    CHECK((trace->writes == std::vector<std::string>{"abc", "def"}));
    CHECK(release_calls == 0);
    channel->complete_write();
    CHECK(release_calls == 1);
    CHECK(released == 6U);
    CHECK(stream->read_issues == 2);

    channel->deliver("reply");
    CHECK((stream->writes == std::vector<std::string>{"reply"}));
    CHECK(channel->read_issues == 1);
    stream->complete_write();
    CHECK(channel->read_issues == 2);

    stream->end();
    CHECK(trace->shutdown_calls == 1);
    CHECK(channel->read_issues == 2);
    CHECK(stream->close_calls == 0);
    channel->end();
    CHECK(stream->shutdown_calls == 1);
    CHECK(trace->close_calls == 1);
    CHECK(trace->cancel_calls == 0);
    CHECK(stream->close_calls == 0);
}

void test_partial_completion_and_cancellation_close_once() {
    {
        auto trace = std::make_shared<ChannelTrace>();
        ManualByteChannel* channel = nullptr;
        auto provider = std::make_shared<ManualRouteProvider>([&] {
            auto owned = std::make_unique<ManualByteChannel>(trace, 8U);
            channel = owned.get();
            std::unique_ptr<ByteChannel> base = std::move(owned);
            return RouteConnection::byte_stream(std::move(base));
        });
        auto stream = std::make_shared<ManualStream>(
            ServiceKind::ByteStream);
        auto handler = direct_handler(ServiceKind::ByteStream, provider);
        handler->on_route(
            authorized_request(ServiceKind::ByteStream), stream);
        int releases = 0;
        stream->deliver("data", [&](std::size_t bytes) {
            CHECK(bytes == 4U);
            ++releases;
        });
        channel->complete_write(Status::success(), 3U);
        CHECK(releases == 1);
        CHECK(stream->close_calls == 1);
        CHECK(stream->close_code == StatusCode::ProviderMismatch);
        CHECK(trace->cancel_calls == 1);
        CHECK(trace->close_calls == 1);
    }
    {
        auto trace = std::make_shared<ChannelTrace>();
        ManualByteChannel* channel = nullptr;
        auto provider = std::make_shared<ManualRouteProvider>([&] {
            auto owned = std::make_unique<ManualByteChannel>(trace);
            channel = owned.get();
            std::unique_ptr<ByteChannel> base = std::move(owned);
            return RouteConnection::byte_stream(std::move(base));
        });
        auto stream = std::make_shared<ManualStream>(
            ServiceKind::ByteStream);
        auto handler = direct_handler(ServiceKind::ByteStream, provider);
        handler->on_route(
            authorized_request(ServiceKind::ByteStream), stream);
        stream->end(Status(StatusCode::Cancelled,
                           "application cancelled"));
        CHECK(stream->close_calls == 1);
        CHECK(stream->close_code == StatusCode::Cancelled);
        CHECK(trace->cancel_calls == 1);
        CHECK(trace->close_calls == 1);
        CHECK(provider->cancel_calls == 0);
        (void)channel;
    }
}

void test_route_to_stream_partial_completion() {
    auto trace = std::make_shared<ChannelTrace>();
    ManualByteChannel* channel = nullptr;
    auto provider = std::make_shared<ManualRouteProvider>([&] {
        auto owned = std::make_unique<ManualByteChannel>(trace);
        channel = owned.get();
        std::unique_ptr<ByteChannel> base = std::move(owned);
        return RouteConnection::byte_stream(std::move(base));
    });
    auto stream = std::make_shared<ManualStream>(
        ServiceKind::ByteStream);
    auto handler = direct_handler(ServiceKind::ByteStream, provider);
    handler->on_route(authorized_request(ServiceKind::ByteStream), stream);
    channel->deliver("reply");
    stream->complete_write(Status::success(), 4U);
    CHECK(stream->close_calls == 1);
    CHECK(stream->close_code == StatusCode::ProviderMismatch);
    CHECK(trace->cancel_calls == 1);
    CHECK(trace->close_calls == 1);
}

void test_packet_boundaries_and_credit() {
    auto trace = std::make_shared<ChannelTrace>();
    ManualPacketChannel* channel = nullptr;
    auto provider = std::make_shared<ManualRouteProvider>([&] {
        auto owned = std::make_unique<ManualPacketChannel>(trace);
        channel = owned.get();
        std::unique_ptr<PacketChannel> base = std::move(owned);
        return RouteConnection::packet_channel(std::move(base));
    });
    auto stream = std::make_shared<ManualStream>(
        ServiceKind::PacketChannel);
    auto handler = direct_handler(ServiceKind::PacketChannel, provider);
    handler->on_route(authorized_request(ServiceKind::PacketChannel), stream);
    CHECK(channel);
    CHECK(channel->receive_issues == 1);

    int releases = 0;
    stream->deliver("one-packet", [&](std::size_t bytes) {
        CHECK(bytes == 10U);
        ++releases;
    });
    CHECK(channel->send_issues == 1);
    CHECK((trace->writes == std::vector<std::string>{"one-packet"}));
    CHECK(releases == 0);
    channel->complete_send();
    CHECK(releases == 1);
    CHECK(stream->read_issues == 2);

    channel->deliver("reply-packet");
    CHECK(stream->write_issues == 1);
    CHECK((stream->writes == std::vector<std::string>{"reply-packet"}));
    stream->complete_write();
    CHECK(channel->receive_issues == 2);

    stream->end();
    CHECK(stream->close_calls == 1);
    CHECK(trace->cancel_calls == 1);
    CHECK(trace->close_calls == 1);
    CHECK(trace->shutdown_calls == 0);
}

void test_authorization_is_fail_closed() {
    auto trace = std::make_shared<ChannelTrace>();
    auto provider = std::make_shared<ManualRouteProvider>([trace] {
        std::unique_ptr<ByteChannel> channel =
            std::make_unique<ManualByteChannel>(trace);
        return RouteConnection::byte_stream(std::move(channel));
    });
    auto peer = require(PeerEvidence::create(
        EndpointRole::Client, "device-1", "test-composite",
        std::vector<std::byte>{std::byte{1}}));
    auto destination = require(RouteDestination::dns_name(
        NetworkProtocol::Tcp, "example.com", 443U));
    auto context = require(StreamOpenContext::create(
        require(StreamId::application(1U, EndpointRole::Client)),
        "stream", ServiceKind::ByteStream, std::move(peer),
        std::move(destination)));
    auto handler = require(DirectRouteHandler::create(
        handler_descriptor(ServiceKind::ByteStream),
        ServiceKind::ByteStream, provider,
        [](const StreamOpenContext&) -> Status {
            throw std::runtime_error("policy failure");
        }));
    CHECK(handler->authorize(context).code() == StatusCode::Internal);
}

}  // namespace
}  // namespace yume::providers

int main() {
    using namespace yume::providers;
    try {
        test_open_failure_kind_mismatch_and_exception();
        test_byte_bridge_credit_duplex_and_half_close();
        test_partial_completion_and_cancellation_close_once();
        test_route_to_stream_partial_completion();
        test_packet_boundaries_and_credit();
        test_authorization_is_fail_closed();
        std::cout << "direct route handler tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
