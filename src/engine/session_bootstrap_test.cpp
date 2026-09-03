/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "engine/session_bootstrap.hpp"
#include "ytp/protocol.hpp"
#include "ytp/security.hpp"

namespace yume::engine {
namespace {

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
        throw TestFailure(std::string(result.status().message()));
    }
    return std::move(result).take_value();
}

ProviderDescriptor make_descriptor(std::string id, ProviderKind kind) {
    CapabilitySet capabilities = mandatory_capabilities(kind);
    if (kind == ProviderKind::SecureChannel) {
        capabilities = capabilities.with(Capability::Tls13);
    }
    return require(ProviderDescriptor::create(
        std::move(id), kind, 1U, capabilities));
}

ProviderRequirement requirement(std::string id, ProviderKind kind) {
    return require(ProviderRequirement::create(
        kind, std::move(id), 1U, mandatory_capabilities(kind)));
}

Buffer copy_bytes(std::span<const std::byte> bytes,
                  std::size_t limit = 128U * 1024U) {
    return require(Buffer::copy_from(bytes, limit));
}

Buffer copy_bytes(std::span<const std::uint8_t> bytes,
                  std::size_t limit = 128U * 1024U) {
    return copy_bytes(
        {reinterpret_cast<const std::byte*>(bytes.data()), bytes.size()},
        limit);
}

Buffer auth_message(ytp1::AuthMessageType kind,
                    ytp1::EndpointRole role) {
    ytp1::AuthRecord record;
    record.type = kind;
    record.sender_role = role;
    auto encoded = ytp1::EncodeAuthRecord(record);
    CHECK(encoded.ok());
    return copy_bytes(*encoded.value);
}

Buffer frame(ytp1::RecordType type,
             std::span<const std::byte> payload) {
    auto stream_id = ytp1::StreamId::FromWire(0U);
    CHECK(stream_id.ok());
    const ytp1::FrameHeader header{
        type, 0U, *stream_id.value,
        static_cast<std::uint32_t>(payload.size())};
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

std::vector<std::byte> capability_bytes() {
    const ytp1::CapabilityManifest manifest{{
        {"echo", ytp1::ServiceKind::ByteStream, 4U}}};
    auto encoded = ytp1::EncodeCapabilityManifest(manifest);
    CHECK(encoded.ok());
    std::vector<std::byte> output(encoded.value->size());
    std::memcpy(output.data(), encoded.value->data(), encoded.value->size());
    return output;
}

struct Trace final {
    std::vector<std::string> layers;
    int byte_cancelled{0};
    int byte_closed{0};
    int secure_cancelled{0};
    int secure_closed{0};
    int carrier_cancelled{0};
    int carrier_closed{0};
    int front_cancelled{0};
    int front_closed{0};
    bool fail_security_factory{false};
    bool fail_security_initialize{false};
    class FakeCarrier* carrier{nullptr};
};

class FakeByteChannel final : public ByteChannel {
public:
    FakeByteChannel(std::shared_ptr<Trace> trace,
                    ExecutorAffinity affinity) noexcept
        : trace_(std::move(trace)), affinity_(affinity) {}

    ~FakeByteChannel() override { close(); }

    ExecutorAffinity executor_affinity() const noexcept override {
        return affinity_;
    }
    std::size_t max_read_size() const noexcept override { return 128U * 1024U; }
    std::size_t max_write_size() const noexcept override { return 128U * 1024U; }
    void async_read(std::size_t,
                    CancellationToken,
                    ReadCompletion completion) override {
        completion(Result<Buffer>(Status(StatusCode::Closed, "test byte read")));
    }
    void async_write(Buffer,
                     CancellationToken,
                     WriteCompletion completion) override {
        completion(Status(StatusCode::Closed, "test byte write"), 0U);
    }
    Status shutdown_write() noexcept override { return Status::success(); }
    void cancel() noexcept override {
        if (!cancelled_) {
            cancelled_ = true;
            ++trace_->byte_cancelled;
        }
    }
    void close() noexcept override {
        if (!closed_) {
            closed_ = true;
            ++trace_->byte_closed;
        }
    }

private:
    std::shared_ptr<Trace> trace_;
    ExecutorAffinity affinity_;
    bool cancelled_{false};
    bool closed_{false};
};

class FakeSecureChannel final : public SecureChannel {
public:
    FakeSecureChannel(std::shared_ptr<Trace> trace,
                      ExecutorAffinity affinity,
                      EndpointRole local_role,
                      ProviderDescriptor descriptor,
                      std::unique_ptr<ByteChannel> inner = {})
        : trace_(std::move(trace)),
          affinity_(affinity),
          descriptor_(std::move(descriptor)),
          peer_(make_peer(local_role)),
          inner_(std::move(inner)) {}

    ~FakeSecureChannel() override { close(); }

    ExecutorAffinity executor_affinity() const noexcept override {
        return affinity_;
    }
    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }
    std::size_t max_read_size() const noexcept override { return 128U * 1024U; }
    std::size_t max_write_size() const noexcept override { return 128U * 1024U; }
    void async_read(std::size_t,
                    CancellationToken,
                    ReadCompletion completion) override {
        completion(Result<Buffer>(Status(StatusCode::Closed, "test secure read")));
    }
    void async_write(Buffer,
                     CancellationToken,
                     WriteCompletion completion) override {
        completion(Status(StatusCode::Closed, "test secure write"), 0U);
    }
    Status shutdown_write() noexcept override { return Status::success(); }
    void cancel() noexcept override {
        if (!cancelled_) {
            cancelled_ = true;
            ++trace_->secure_cancelled;
        }
        if (inner_) {
            inner_->cancel();
        }
    }
    void close() noexcept override {
        if (!closed_) {
            closed_ = true;
            ++trace_->secure_closed;
        }
        if (inner_) {
            inner_->close();
        }
    }
    const SecureChannelPeerEvidence& peer_evidence() const noexcept override {
        return peer_;
    }
    Result<Buffer> export_keying_material(
        std::string_view,
        std::span<const std::byte>,
        std::size_t output_size) override {
        return Buffer::allocate(output_size, output_size);
    }

private:
    static SecureChannelPeerEvidence make_peer(EndpointRole local_role) {
        if (local_role == EndpointRole::Server) {
            return SecureChannelPeerEvidence::anonymous_client();
        }
        return require(SecureChannelPeerEvidence::authenticated(
            EndpointRole::Server, "server", "tls13",
            std::vector<std::byte>{std::byte{1}}));
    }

    std::shared_ptr<Trace> trace_;
    ExecutorAffinity affinity_;
    ProviderDescriptor descriptor_;
    SecureChannelPeerEvidence peer_;
    std::unique_ptr<ByteChannel> inner_;
    bool cancelled_{false};
    bool closed_{false};
};

class FakeCarrier final : public Carrier {
public:
    FakeCarrier(std::shared_ptr<Trace> trace,
                ExecutorAffinity affinity,
                ProviderDescriptor descriptor,
                std::unique_ptr<SecureChannel> secure) noexcept
        : trace_(std::move(trace)),
          affinity_(affinity),
          descriptor_(std::move(descriptor)),
          secure_(std::move(secure)) {
        trace_->carrier = this;
    }

    ~FakeCarrier() override {
        close();
        if (trace_->carrier == this) {
            trace_->carrier = nullptr;
        }
    }

    ExecutorAffinity executor_affinity() const noexcept override {
        return affinity_;
    }
    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }
    std::size_t max_record_size() const noexcept override {
        return 128U * 1024U;
    }
    SecureChannel& secure_channel() noexcept override { return *secure_; }
    const SecureChannel& secure_channel() const noexcept override {
        return *secure_;
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
    void cancel() noexcept override {
        if (!cancelled_) {
            cancelled_ = true;
            ++trace_->carrier_cancelled;
        }
        secure_->cancel();
    }
    void close() noexcept override {
        if (!closed_) {
            closed_ = true;
            ++trace_->carrier_closed;
        }
        receive_ = {};
        secure_->close();
    }

    void deliver(Buffer record) {
        CHECK(receive_);
        ReceiveCompletion completion = std::move(receive_);
        receive_ = {};
        const std::size_t size = record.size();
        completion(Result<ReceivedRecord>(ReceivedRecord(
            std::move(record), CarrierCredit(size, [](std::size_t) {}))));
    }

    std::vector<Buffer> sent;

private:
    std::shared_ptr<Trace> trace_;
    ExecutorAffinity affinity_;
    ProviderDescriptor descriptor_;
    std::unique_ptr<SecureChannel> secure_;
    ReceiveCompletion receive_;
    bool cancelled_{false};
    bool closed_{false};
};

class FakeByteProvider final : public ByteChannelProvider {
public:
    FakeByteProvider(std::shared_ptr<Trace> trace,
                     ExecutorAffinity affinity)
        : descriptor_(make_descriptor("test.bytes", ProviderKind::ByteChannel)),
          trace_(std::move(trace)),
          affinity_(affinity) {}

    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }
    void async_create(EndpointRole role,
                      CancellationToken,
                      Completion completion) override {
        CHECK(role == EndpointRole::Client);
        trace_->layers.emplace_back("byte");
        std::unique_ptr<ByteChannel> channel =
            std::make_unique<FakeByteChannel>(trace_, affinity_);
        completion(Result<std::unique_ptr<ByteChannel>>(std::move(channel)));
    }

private:
    ProviderDescriptor descriptor_;
    std::shared_ptr<Trace> trace_;
    ExecutorAffinity affinity_;
};

class DeferredByteProvider final : public ByteChannelProvider {
public:
    DeferredByteProvider(std::shared_ptr<Trace> trace,
                         ExecutorAffinity affinity)
        : descriptor_(make_descriptor("test.bytes", ProviderKind::ByteChannel)),
          trace_(std::move(trace)),
          affinity_(affinity) {}

    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }
    void async_create(EndpointRole role,
                      CancellationToken cancellation,
                      Completion completion) override {
        CHECK(role == EndpointRole::Client);
        trace_->layers.emplace_back("byte-pending");
        cancellation_ = std::move(cancellation);
        completion_ = std::move(completion);
    }
    bool cancelled() const noexcept { return cancellation_.is_cancelled(); }
    void complete_cancelled() {
        CHECK(completion_);
        completion_(Result<std::unique_ptr<ByteChannel>>(Status(
            StatusCode::Cancelled, "deferred byte cancelled")));
    }
    void complete_duplicate_success() {
        CHECK(completion_);
        std::unique_ptr<ByteChannel> channel =
            std::make_unique<FakeByteChannel>(trace_, affinity_);
        completion_(Result<std::unique_ptr<ByteChannel>>(std::move(channel)));
    }
    void clear() { completion_ = {}; }

private:
    ProviderDescriptor descriptor_;
    std::shared_ptr<Trace> trace_;
    ExecutorAffinity affinity_;
    CancellationToken cancellation_;
    Completion completion_;
};

class FakeSecureProvider final : public SecureChannelProvider {
public:
    FakeSecureProvider(std::shared_ptr<Trace> trace,
                       ExecutorAffinity affinity)
        : descriptor_(make_descriptor("test.secure", ProviderKind::SecureChannel)),
          trace_(std::move(trace)),
          affinity_(affinity) {}

    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }
    void async_wrap(std::unique_ptr<ByteChannel> channel,
                    EndpointRole role,
                    CancellationToken,
                    Completion completion) override {
        trace_->layers.emplace_back("secure");
        std::unique_ptr<SecureChannel> secure =
            std::make_unique<FakeSecureChannel>(
                trace_, affinity_, role, descriptor_, std::move(channel));
        completion(Result<std::unique_ptr<SecureChannel>>(std::move(secure)));
    }

private:
    ProviderDescriptor descriptor_;
    std::shared_ptr<Trace> trace_;
    ExecutorAffinity affinity_;
};

class FakeCarrierProvider final : public CarrierProvider {
public:
    FakeCarrierProvider(std::shared_ptr<Trace> trace,
                        ExecutorAffinity affinity)
        : descriptor_(make_descriptor("test.carrier", ProviderKind::Carrier)),
          trace_(std::move(trace)),
          affinity_(affinity) {}

    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }
    void async_create(std::unique_ptr<SecureChannel> channel,
                      EndpointRole role,
                      CancellationToken,
                      Completion completion) override {
        CHECK(role == EndpointRole::Client);
        trace_->layers.emplace_back("carrier");
        std::unique_ptr<Carrier> carrier = std::make_unique<FakeCarrier>(
            trace_, affinity_, descriptor_, std::move(channel));
        completion(Result<std::unique_ptr<Carrier>>(std::move(carrier)));
    }

private:
    ProviderDescriptor descriptor_;
    std::shared_ptr<Trace> trace_;
    ExecutorAffinity affinity_;
};

class NullFrontDoorProvider final : public FrontDoorProvider {
public:
    NullFrontDoorProvider()
        : descriptor_(make_descriptor("test.front", ProviderKind::FrontDoor)) {}
    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }
    void async_create(EndpointRole,
                      CancellationToken,
                      Completion completion) override {
        completion(Result<std::unique_ptr<FrontDoor>>(Status(
            StatusCode::FailedPrecondition, "front-door creation unused")));
    }

private:
    ProviderDescriptor descriptor_;
};

class FakeFrontDoor final : public FrontDoor {
public:
    FakeFrontDoor(std::shared_ptr<Trace> trace,
                  ExecutorAffinity front_affinity,
                  ExecutorAffinity carrier_affinity,
                  ProviderDescriptor promoted_descriptor)
        : trace_(std::move(trace)),
          front_affinity_(front_affinity),
          carrier_affinity_(carrier_affinity),
          promoted_descriptor_(std::move(promoted_descriptor)) {}

    ExecutorAffinity executor_affinity() const noexcept override {
        return front_affinity_;
    }
    void async_accept(CancellationToken,
                      AcceptCompletion completion) override {
        trace_->layers.emplace_back("front-door");
        std::unique_ptr<SecureChannel> secure =
            std::make_unique<FakeSecureChannel>(
                trace_, carrier_affinity_, EndpointRole::Server,
                make_descriptor("test.secure",
                                ProviderKind::SecureChannel));
        std::unique_ptr<Carrier> carrier = std::make_unique<FakeCarrier>(
            trace_, carrier_affinity_,
            make_descriptor("test.carrier", ProviderKind::Carrier),
            std::move(secure));
        completion(AcceptedCarrier::create(
            promoted_descriptor_, std::move(carrier)));
    }
    void cancel() noexcept override { ++trace_->front_cancelled; }
    void close() noexcept override { ++trace_->front_closed; }

private:
    std::shared_ptr<Trace> trace_;
    ExecutorAffinity front_affinity_;
    ExecutorAffinity carrier_affinity_;
    ProviderDescriptor promoted_descriptor_;
};

class FakeSecurity final : public SessionSecurityProvider {
public:
    FakeSecurity(std::shared_ptr<Trace> trace, EndpointRole role)
        : trace_(std::move(trace)),
          role_(role),
          capabilities_(capability_bytes()) {}

    std::string_view provider_id() const noexcept override {
        return "test.security";
    }
    std::string_view suite_id() const noexcept override {
        return ytp1::kSuiteId;
    }
    std::span<const std::byte> security_parameters() const noexcept override {
        const auto required = ytp1::RequiredSecurityParameters();
        return {reinterpret_cast<const std::byte*>(required.data()),
                required.size()};
    }
    std::size_t max_sealed_overhead() const noexcept override { return 0U; }
    Status initialize(const SessionAuthenticationContext& context) override {
        CHECK(context.local_role == role_);
        if (trace_->fail_security_initialize) {
            return Status(StatusCode::Internal,
                          "configured security initialization failure");
        }
        return Status::success();
    }
    Result<AuthenticationOutput> start_authentication() override {
        AuthenticationOutput output;
        if (role_ == EndpointRole::Server) {
            output.outbound_kind = AuthenticationMessageKind::Challenge;
            output.outbound_message = auth_message(
                ytp1::AuthMessageType::Challenge,
                ytp1::EndpointRole::Server);
        }
        return Result<AuthenticationOutput>(std::move(output));
    }
    Result<AuthenticationOutput> process_authentication(
        AuthenticationMessageKind kind,
        std::span<const std::byte>) override {
        AuthenticationOutput output;
        if (role_ == EndpointRole::Client &&
            kind == AuthenticationMessageKind::Challenge) {
            output.outbound_kind = AuthenticationMessageKind::Response;
            output.outbound_message = auth_message(
                ytp1::AuthMessageType::Response,
                ytp1::EndpointRole::Client);
            return Result<AuthenticationOutput>(std::move(output));
        }

        const EndpointRole peer = role_ == EndpointRole::Client
            ? EndpointRole::Server
            : EndpointRole::Client;
        if (role_ == EndpointRole::Server) {
            CHECK(kind == AuthenticationMessageKind::Response);
            output.outbound_kind = AuthenticationMessageKind::Accepted;
            output.outbound_message = auth_message(
                ytp1::AuthMessageType::Accepted,
                ytp1::EndpointRole::Server);
        } else {
            CHECK(kind == AuthenticationMessageKind::Accepted);
        }
        output.established = true;
        output.authenticated_peer = require(PeerEvidence::create(
            peer, peer == EndpointRole::Client ? "device" : "server",
            "test-composite", std::vector<std::byte>{std::byte{1}}));
        output.authenticated_peer_capability_manifest = capabilities_;
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
                                     "rekey unused"));
    }
    Result<Buffer> accept_inbound_rekey(
        std::uint32_t,
        std::span<const std::byte>) override {
        return Result<Buffer>(Status(StatusCode::FailedPrecondition,
                                     "rekey unused"));
    }
    Status finish_outbound_rekey(
        std::uint32_t,
        std::span<const std::byte>) override {
        return Status(StatusCode::FailedPrecondition, "rekey unused");
    }
    void cancel() noexcept override {}

private:
    std::shared_ptr<Trace> trace_;
    EndpointRole role_;
    std::vector<std::byte> capabilities_;
};

class FakeSecurityFactory final : public SessionSecurityProviderFactory {
public:
    explicit FakeSecurityFactory(std::shared_ptr<Trace> trace)
        : descriptor_(make_descriptor(
              "test.security", ProviderKind::SessionSecurity)),
          trace_(std::move(trace)) {}
    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }
    Result<std::unique_ptr<SessionSecurityProvider>> create(
        EndpointRole role) override {
        if (trace_->fail_security_factory) {
            return Result<std::unique_ptr<SessionSecurityProvider>>(Status(
                StatusCode::Internal,
                "configured security factory failure"));
        }
        std::unique_ptr<SessionSecurityProvider> security =
            std::make_unique<FakeSecurity>(trace_, role);
        return Result<std::unique_ptr<SessionSecurityProvider>>(
            std::move(security));
    }

private:
    ProviderDescriptor descriptor_;
    std::shared_ptr<Trace> trace_;
};

class NullRouteProvider final : public RouteProvider {
public:
    NullRouteProvider()
        : descriptor_(make_descriptor("test.route", ProviderKind::RouteProvider)) {}
    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }
    void async_open(const AuthorizedRouteRequest&,
                    CancellationToken,
                    Completion completion) override {
        completion(Result<RouteConnection>(Status(
            StatusCode::FailedPrecondition, "route unused")));
    }
    void cancel() noexcept override {}

private:
    ProviderDescriptor descriptor_;
};

class NullHandler final : public StreamHandler {
public:
    NullHandler()
        : descriptor_(make_descriptor("test.echo", ProviderKind::StreamHandler)) {}
    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }
    ServiceKind service_kind() const noexcept override {
        return ServiceKind::ByteStream;
    }
    Status authorize(const StreamOpenContext&) override {
        return Status::success();
    }
    void on_open(StreamOpenContext,
                 std::shared_ptr<StreamResponder>) override {}
    void on_route(AuthorizedRouteRequest,
                  std::shared_ptr<StreamResponder>) override {}

private:
    ProviderDescriptor descriptor_;
};

struct GraphFixture final {
    std::shared_ptr<const EngineGraph> graph;
    std::shared_ptr<FakeCarrierProvider> carrier_provider;
};

GraphFixture make_graph(
    EndpointRole role,
    const std::shared_ptr<Trace>& trace,
    ExecutorAffinity byte_affinity = ExecutorAffinity(17U),
    ExecutorAffinity secure_affinity = ExecutorAffinity(17U),
    ExecutorAffinity carrier_affinity = ExecutorAffinity(17U),
    std::shared_ptr<ByteChannelProvider> byte_override = {},
    bool require_tls13 = true) {
    std::vector<ProviderRequirement> providers;
    providers.push_back(requirement("test.bytes", ProviderKind::ByteChannel));
    CapabilitySet secure_capabilities =
        mandatory_capabilities(ProviderKind::SecureChannel);
    if (require_tls13) {
        secure_capabilities = secure_capabilities.with(Capability::Tls13);
    }
    providers.push_back(require(ProviderRequirement::create(
        ProviderKind::SecureChannel, "test.secure", 1U,
        secure_capabilities)));
    providers.push_back(requirement("test.front", ProviderKind::FrontDoor));
    providers.push_back(requirement("test.carrier", ProviderKind::Carrier));
    providers.push_back(requirement("test.security", ProviderKind::SessionSecurity));
    providers.push_back(requirement("test.route", ProviderKind::RouteProvider));
    std::vector<ServiceRequirement> services;
    services.push_back(require(ServiceRequirement::create(
        "echo", ServiceKind::ByteStream, "test.echo", 1U, 4U,
        CapabilitySet::of({Capability::NamedByteStreams}))));
    TransportSuiteDescriptor suite = require(
        TransportSuiteDescriptor::create(
            "test.ytp1", "YTP/1", std::move(providers),
            std::move(services)));

    EngineBuilder builder(role, std::move(suite));
    if (!byte_override) {
        byte_override = std::make_shared<FakeByteProvider>(
            trace, byte_affinity);
    }
    auto carrier_provider = std::make_shared<FakeCarrierProvider>(
        trace, carrier_affinity);
    CHECK(builder.register_byte_channel_provider(
              std::move(byte_override)).ok());
    CHECK(builder.register_secure_channel_provider(
              std::make_shared<FakeSecureProvider>(
                  trace, secure_affinity)).ok());
    CHECK(builder.register_front_door_provider(
              std::make_shared<NullFrontDoorProvider>()).ok());
    CHECK(builder.register_carrier_provider(carrier_provider).ok());
    CHECK(builder.register_session_security_provider_factory(
              std::make_shared<FakeSecurityFactory>(trace)).ok());
    CHECK(builder.register_route_provider(
              std::make_shared<NullRouteProvider>()).ok());
    CHECK(builder.register_stream_handler(
              "echo", std::make_shared<NullHandler>()).ok());
    return {require(builder.build()), std::move(carrier_provider)};
}

struct CompletionCapture final {
    int count{0};
    StatusCode failure{StatusCode::Ok};
    std::shared_ptr<SessionEngine> engine;

    void accept(Result<std::shared_ptr<SessionEngine>> result) {
        ++count;
        if (result.ok()) {
            engine = std::move(result).take_value();
        } else {
            failure = result.status().code();
        }
    }
};

void activate(EndpointRole role,
              const std::shared_ptr<Trace>& trace,
              CompletionCapture& completion) {
    FakeCarrier* carrier = trace->carrier;
    CHECK(carrier != nullptr);
    CHECK(completion.count == 0);

    if (role == EndpointRole::Server) {
        CHECK(carrier->sent.size() == 1U);
        Buffer response = auth_message(
            ytp1::AuthMessageType::Response,
            ytp1::EndpointRole::Client);
        carrier->deliver(frame(ytp1::RecordType::Auth,
                               response.bytes()));
        CHECK(carrier->sent.size() == 4U);
        carrier->deliver(copy_bytes(carrier->sent[2].bytes()));
    } else {
        CHECK(carrier->sent.empty());
        Buffer challenge = auth_message(
            ytp1::AuthMessageType::Challenge,
            ytp1::EndpointRole::Server);
        carrier->deliver(frame(ytp1::RecordType::Auth,
                               challenge.bytes()));
        CHECK(carrier->sent.size() == 1U);
        Buffer accepted = auth_message(
            ytp1::AuthMessageType::Accepted,
            ytp1::EndpointRole::Server);
        carrier->deliver(frame(ytp1::RecordType::AuthResult,
                               accepted.bytes()));
        CHECK(carrier->sent.size() == 3U);
        carrier->deliver(copy_bytes(carrier->sent[1].bytes()));
    }
    CHECK(completion.count == 1);
    CHECK(completion.engine);
    CHECK(completion.engine->state() == SessionState::Active);
}

void test_client_bootstrap_to_active() {
    const auto trace = std::make_shared<Trace>();
    GraphFixture fixture = make_graph(EndpointRole::Client, trace);
    auto bootstrap = require(SessionBootstrap::create(fixture.graph));
    CHECK(!bootstrap->executor_affinity().valid());

    CompletionCapture completion;
    CHECK(bootstrap->async_start(
              {}, [&completion](auto result) {
                  completion.accept(std::move(result));
              }).ok());
    CHECK((trace->layers ==
           std::vector<std::string>{"byte", "secure", "carrier"}));
    CHECK(bootstrap->executor_affinity() == ExecutorAffinity(17U));
    CHECK(bootstrap->state() == SessionBootstrapState::StartingSession);
    activate(EndpointRole::Client, trace, completion);
    CHECK(bootstrap->state() == SessionBootstrapState::Succeeded);
    completion.engine->stop();
}

void test_server_bootstrap_preserves_promoted_carrier() {
    const auto trace = std::make_shared<Trace>();
    GraphFixture fixture = make_graph(EndpointRole::Server, trace);
    auto front_door = std::make_shared<FakeFrontDoor>(
        trace, ExecutorAffinity(17U), ExecutorAffinity(17U),
        make_descriptor("test.carrier", ProviderKind::Carrier));
    auto bootstrap = require(SessionBootstrap::create(
        fixture.graph, front_door));

    CompletionCapture completion;
    CHECK(bootstrap->async_start(
              {}, [&completion](auto result) {
                  completion.accept(std::move(result));
              }).ok());
    CHECK((trace->layers == std::vector<std::string>{"front-door"}));
    CHECK(bootstrap->executor_affinity() == ExecutorAffinity(17U));
    activate(EndpointRole::Server, trace, completion);
    CHECK(bootstrap->state() == SessionBootstrapState::Succeeded);
    CHECK(trace->front_cancelled == 0);
    CHECK(trace->front_closed == 0);
    CHECK(front_door.use_count() == 1);
    completion.engine->stop();
}

void test_role_provenance_and_affinity_rejection() {
    const auto trace = std::make_shared<Trace>();
    GraphFixture client = make_graph(EndpointRole::Client, trace);
    GraphFixture server = make_graph(EndpointRole::Server, trace);
    auto ordinary_front = std::make_shared<FakeFrontDoor>(
        trace, ExecutorAffinity(17U), ExecutorAffinity(17U),
        make_descriptor("test.carrier", ProviderKind::Carrier));

    CHECK(!SessionBootstrap::create(client.graph, ordinary_front).ok());
    CHECK(!SessionBootstrap::create(server.graph).ok());
    CHECK(!SessionBootstrap::create(
              server.graph, std::shared_ptr<FrontDoor>{}).ok());

    auto wrong_front = std::make_shared<FakeFrontDoor>(
        trace, ExecutorAffinity(17U), ExecutorAffinity(17U),
        make_descriptor("wrong.carrier", ProviderKind::Carrier));
    auto wrong_bootstrap = require(SessionBootstrap::create(
        server.graph, wrong_front));
    CompletionCapture wrong_completion;
    CHECK(wrong_bootstrap->async_start(
              {}, [&wrong_completion](auto result) {
                  wrong_completion.accept(std::move(result));
              }).ok());
    CHECK(wrong_completion.count == 1);
    CHECK(wrong_completion.failure == StatusCode::ProviderMismatch);
    CHECK(trace->carrier_closed >= 1);

    const int closed_before = trace->carrier_closed;
    auto affinity_front = std::make_shared<FakeFrontDoor>(
        trace, ExecutorAffinity(17U), ExecutorAffinity(19U),
        make_descriptor("test.carrier", ProviderKind::Carrier));
    auto affinity_bootstrap = require(SessionBootstrap::create(
        server.graph, affinity_front));
    CompletionCapture affinity_completion;
    CHECK(affinity_bootstrap->async_start(
              {}, [&affinity_completion](auto result) {
                  affinity_completion.accept(std::move(result));
              }).ok());
    CHECK(affinity_completion.count == 1);
    CHECK(affinity_completion.failure == StatusCode::ProviderMismatch);
    CHECK(trace->carrier_closed == closed_before + 1);
    CHECK(trace->front_cancelled == 0);
    CHECK(trace->front_closed == 0);
}

void test_bootstrap_rejects_non_tls13_ytp1_graph() {
    const auto trace = std::make_shared<Trace>();
    GraphFixture fixture = make_graph(
        EndpointRole::Client, trace, ExecutorAffinity(17U),
        ExecutorAffinity(17U), ExecutorAffinity(17U), {}, false);
    auto rejected = SessionBootstrap::create(fixture.graph);
    CHECK(!rejected.ok());
    CHECK(rejected.status().code() == StatusCode::ProviderMismatch);
    CHECK(trace->layers.empty());
}

void test_client_layer_cleanup_and_session_failures() {
    {
        const auto trace = std::make_shared<Trace>();
        GraphFixture fixture = make_graph(
            EndpointRole::Client, trace, ExecutorAffinity(17U),
            ExecutorAffinity(18U), ExecutorAffinity(18U));
        auto bootstrap = require(SessionBootstrap::create(fixture.graph));
        CompletionCapture completion;
        CHECK(bootstrap->async_start(
                  {}, [&completion](auto result) {
                      completion.accept(std::move(result));
                  }).ok());
        CHECK(completion.count == 1);
        CHECK(completion.failure == StatusCode::ProviderMismatch);
        CHECK(trace->secure_cancelled == 1);
        CHECK(trace->secure_closed == 1);
        CHECK(trace->byte_closed == 1);
    }
    {
        const auto trace = std::make_shared<Trace>();
        GraphFixture fixture = make_graph(
            EndpointRole::Client, trace, ExecutorAffinity(17U),
            ExecutorAffinity(17U), ExecutorAffinity(19U));
        auto bootstrap = require(SessionBootstrap::create(fixture.graph));
        CompletionCapture completion;
        CHECK(bootstrap->async_start(
                  {}, [&completion](auto result) {
                      completion.accept(std::move(result));
                  }).ok());
        CHECK(completion.count == 1);
        CHECK(completion.failure == StatusCode::ProviderMismatch);
        CHECK(trace->carrier_cancelled == 1);
        CHECK(trace->carrier_closed == 1);
        CHECK(trace->secure_closed == 1);
    }
    {
        const auto trace = std::make_shared<Trace>();
        trace->fail_security_factory = true;
        GraphFixture fixture = make_graph(EndpointRole::Client, trace);
        auto bootstrap = require(SessionBootstrap::create(fixture.graph));
        CompletionCapture completion;
        CHECK(bootstrap->async_start(
                  {}, [&completion](auto result) {
                      completion.accept(std::move(result));
                  }).ok());
        CHECK(completion.count == 1);
        CHECK(completion.failure == StatusCode::Internal);
        CHECK(trace->carrier_closed == 1);
    }
    {
        const auto trace = std::make_shared<Trace>();
        trace->fail_security_initialize = true;
        GraphFixture fixture = make_graph(EndpointRole::Client, trace);
        auto bootstrap = require(SessionBootstrap::create(fixture.graph));
        CompletionCapture completion;
        CHECK(bootstrap->async_start(
                  {}, [&completion](auto result) {
                      completion.accept(std::move(result));
                  }).ok());
        CHECK(completion.count == 1);
        CHECK(completion.failure == StatusCode::Internal);
        CHECK(trace->carrier_cancelled == 1);
        CHECK(trace->carrier_closed == 1);
    }
}

void test_cancellation_waits_for_settlement_and_ignores_duplicate() {
    const auto trace = std::make_shared<Trace>();
    auto deferred = std::make_shared<DeferredByteProvider>(
        trace, ExecutorAffinity(17U));
    GraphFixture fixture = make_graph(
        EndpointRole::Client, trace, ExecutorAffinity(17U),
        ExecutorAffinity(17U), ExecutorAffinity(17U), deferred);
    auto bootstrap = require(SessionBootstrap::create(fixture.graph));
    CancellationSource cancellation;
    CompletionCapture completion;
    CHECK(bootstrap->async_start(
              cancellation.token(), [&completion](auto result) {
                  completion.accept(std::move(result));
              }).ok());
    CHECK(completion.count == 0);
    CHECK(cancellation.cancel());
    CHECK(deferred->cancelled());
    CHECK(completion.count == 0);

    deferred->complete_cancelled();
    CHECK(completion.count == 1);
    CHECK(completion.failure == StatusCode::Cancelled);
    CHECK(bootstrap->state() == SessionBootstrapState::Cancelled);

    deferred->complete_duplicate_success();
    CHECK(completion.count == 1);
    CHECK(trace->byte_cancelled == 1);
    CHECK(trace->byte_closed == 1);
    deferred->clear();
}

void test_completion_exception_is_contained() {
    const auto trace = std::make_shared<Trace>();
    trace->fail_security_factory = true;
    GraphFixture fixture = make_graph(EndpointRole::Client, trace);
    auto bootstrap = require(SessionBootstrap::create(fixture.graph));
    int calls = 0;
    CHECK(bootstrap->async_start(
              {}, [&calls](auto) {
                  ++calls;
                  throw TestFailure("completion escape");
              }).ok());
    CHECK(calls == 1);
    CHECK(bootstrap->state() == SessionBootstrapState::Failed);
}

}  // namespace
}  // namespace yume::engine

int main() {
    try {
        yume::engine::test_client_bootstrap_to_active();
        yume::engine::test_server_bootstrap_preserves_promoted_carrier();
        yume::engine::test_role_provenance_and_affinity_rejection();
        yume::engine::test_bootstrap_rejects_non_tls13_ytp1_graph();
        yume::engine::test_client_layer_cleanup_and_session_failures();
        yume::engine::test_cancellation_waits_for_settlement_and_ignores_duplicate();
        yume::engine::test_completion_exception_is_contained();
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    return 0;
}
