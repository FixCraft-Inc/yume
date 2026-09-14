/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "engine/front_door.hpp"
#include "engine/secure_erase.hpp"
#include "engine/session_engine.hpp"
#include "ytp/protocol.hpp"
#include "ytp/security.hpp"

namespace test_allocation_failure {

constexpr std::size_t kDisabled =
    std::numeric_limits<std::size_t>::max();
std::atomic<std::size_t> failure_size{kDisabled};
std::atomic<std::size_t> countdown{kDisabled};
std::atomic<bool> sustained{false};
std::atomic<bool> fail_all{false};

class Scope final {
public:
    Scope(std::size_t nth, bool keep_failing = false) noexcept {
        countdown.store(nth, std::memory_order_relaxed);
        sustained.store(keep_failing, std::memory_order_relaxed);
    }
    ~Scope() {
        countdown.store(kDisabled, std::memory_order_relaxed);
        fail_all.store(false, std::memory_order_relaxed);
    }
    bool fired() const noexcept {
        return countdown.load(std::memory_order_relaxed) == 0U;
    }
};

void fail_once_for_size(std::size_t size) noexcept {
    failure_size.store(size, std::memory_order_release);
}

bool armed() noexcept {
    return failure_size.load(std::memory_order_acquire) != kDisabled;
}

bool consume_if_matching(std::size_t size) noexcept {
    if (fail_all.load(std::memory_order_relaxed)) return true;
    const auto remaining = countdown.load(std::memory_order_relaxed);
    if (remaining != kDisabled && remaining != 0U &&
        countdown.fetch_sub(1U, std::memory_order_relaxed) == 1U) {
        fail_all.store(sustained.load(std::memory_order_relaxed),
                       std::memory_order_relaxed);
        return true;
    }
    std::size_t expected = size;
    return failure_size.compare_exchange_strong(
        expected, kDisabled, std::memory_order_acq_rel);
}

}  // namespace test_allocation_failure

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmismatched-new-delete"
#endif

void* operator new(std::size_t size) {
    if (test_allocation_failure::consume_if_matching(size)) {
        throw std::bad_alloc();
    }
    if (void* allocation = std::malloc(size == 0U ? 1U : size)) {
        return allocation;
    }
    throw std::bad_alloc();
}

void* operator new[](std::size_t size) {
    return ::operator new(size);
}

void operator delete(void* allocation) noexcept {
    std::free(allocation);
}

void operator delete[](void* allocation) noexcept {
    ::operator delete(allocation);
}

void operator delete(void* allocation, std::size_t) noexcept {
    ::operator delete(allocation);
}

void operator delete[](void* allocation, std::size_t) noexcept {
    ::operator delete[](allocation);
}

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

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
            throw TestFailure(std::string(__func__) + ": " + #expression);  \
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
    CapabilitySet capabilities = mandatory_capabilities(kind);
    if (kind == ProviderKind::SecureChannel) {
        capabilities = capabilities.with(Capability::Tls13);
    }
    return require(ProviderRequirement::create(
        kind, std::move(id), 1U, capabilities));
}

Buffer copy_bytes(std::span<const std::uint8_t> bytes,
                  std::size_t limit = 128U * 1024U) {
    return require(Buffer::copy_from(
        {reinterpret_cast<const std::byte*>(bytes.data()), bytes.size()},
        limit));
}

Buffer copy_bytes(std::span<const std::byte> bytes,
                  std::size_t limit = 128U * 1024U) {
    return require(Buffer::copy_from(bytes, limit));
}

std::vector<std::byte> capability_bytes() {
    ytp1::CapabilityManifest manifest{{
        {"echo", ytp1::ServiceKind::ByteStream, 4U}}};
    auto encoded = ytp1::EncodeCapabilityManifest(manifest);
    CHECK(encoded.ok());
    std::vector<std::byte> bytes(encoded.value->size());
    std::memcpy(bytes.data(), encoded.value->data(), encoded.value->size());
    return bytes;
}

Buffer auth_message(ytp1::AuthMessageType kind, ytp1::EndpointRole role) {
    ytp1::AuthRecord record;
    record.type = kind;
    record.sender_role = role;
    auto encoded = ytp1::EncodeAuthRecord(record);
    CHECK(encoded.ok());
    return copy_bytes(*encoded.value);
}

void test_scoped_byte_wipe() {
    std::array<std::byte, kSessionExporterBytes> normal{};
    normal.fill(std::byte{0xa5});
    {
        ScopedByteWipe wipe(normal);
    }
    CHECK(std::all_of(normal.begin(), normal.end(), [](std::byte value) {
        return value == std::byte{0};
    }));

    std::array<std::byte, kSessionExporterBytes> exceptional{};
    exceptional.fill(std::byte{0x5a});
    try {
        ScopedByteWipe wipe(exceptional);
        throw std::runtime_error("test exception");
    } catch (const std::runtime_error&) {
    }
    CHECK(std::all_of(
        exceptional.begin(), exceptional.end(), [](std::byte value) {
            return value == std::byte{0};
        }));
}

Buffer frame(ytp1::RecordType type,
             std::uint32_t stream_id,
             std::span<const std::byte> payload) {
    auto id = ytp1::StreamId::FromWire(stream_id);
    CHECK(id.ok());
    ytp1::FrameHeader header{type, 0U, *id.value,
                             static_cast<std::uint32_t>(payload.size())};
    std::array<std::uint8_t, ytp1::kFrameHeaderSize> encoded{};
    CHECK(ytp1::EncodeFrameHeader(header, encoded).ok());
    auto output = require(Buffer::allocate(encoded.size() + payload.size(),
                                           encoded.size() + payload.size()));
    std::memcpy(output.mutable_bytes().data(), encoded.data(), encoded.size());
    if (!payload.empty()) {
        std::memcpy(output.mutable_bytes().data() + encoded.size(),
                    payload.data(), payload.size());
    }
    return output;
}

Buffer credit_frame(ytp1::RecordType type,
                    std::uint32_t stream_id,
                    std::uint32_t increment) {
    auto encoded = ytp1::EncodeCreditUpdate(increment);
    CHECK(encoded.ok());
    return frame(
        type, stream_id,
        {reinterpret_cast<const std::byte*>(encoded.value->data()),
         encoded.value->size()});
}

Buffer protected_wire(std::uint32_t epoch,
                      std::uint64_t sequence,
                      Buffer plaintext) {
    auto output = require(Buffer::allocate(16U + plaintext.size(),
                                           16U + plaintext.size()));
    auto bytes = output.mutable_bytes();
    bytes[0] = std::byte{1};
    bytes[1] = bytes[2] = bytes[3] = std::byte{0};
    bytes[4] = static_cast<std::byte>(epoch >> 24U);
    bytes[5] = static_cast<std::byte>(epoch >> 16U);
    bytes[6] = static_cast<std::byte>(epoch >> 8U);
    bytes[7] = static_cast<std::byte>(epoch);
    for (std::size_t index = 0U; index < 8U; ++index) {
        bytes[8U + index] = static_cast<std::byte>(
            sequence >> ((7U - index) * 8U));
    }
    std::memcpy(bytes.data() + 16U, plaintext.bytes().data(),
                plaintext.size());
    return output;
}

ytp1::RecordView protected_record(const Buffer& wire) {
    CHECK(wire.size() > 16U);
    const auto plaintext = wire.bytes().subspan(16U);
    const auto decoded = ytp1::DecodeRecord(
        {reinterpret_cast<const std::uint8_t*>(plaintext.data()),
         plaintext.size()},
        ytp1::kDefaultMaxFramePayload);
    CHECK(decoded.ok());
    return *decoded.value;
}

ytp1::RecordType protected_record_type(const Buffer& wire) {
    return protected_record(wire).header.type;
}

ytp1::OpenRequest protected_open_request(const Buffer& wire) {
    CHECK(wire.size() > 16U);
    const auto plaintext = wire.bytes().subspan(16U);
    const auto decoded = ytp1::DecodeRecord(
        {reinterpret_cast<const std::uint8_t*>(plaintext.data()),
         plaintext.size()},
        ytp1::kDefaultMaxFramePayload);
    CHECK(decoded.ok());
    CHECK(decoded.value->header.type == ytp1::RecordType::Open);
    auto open = ytp1::DecodeOpen(decoded.value->payload);
    CHECK(open.ok());
    return *open.value;
}

ytp1::RecordView raw_record(const Buffer& wire) {
    const auto decoded = ytp1::DecodeRecord(
        {reinterpret_cast<const std::uint8_t*>(wire.bytes().data()),
         wire.size()},
        ytp1::kDefaultMaxFramePayload);
    CHECK(decoded.ok());
    return *decoded.value;
}

Buffer rekey_payload(std::uint32_t epoch, std::byte provider_marker) {
    std::array<std::byte, 5> payload{
        static_cast<std::byte>(epoch >> 24U),
        static_cast<std::byte>(epoch >> 16U),
        static_cast<std::byte>(epoch >> 8U),
        static_cast<std::byte>(epoch),
        provider_marker,
    };
    return copy_bytes(payload);
}

class NullByteProvider final : public ByteChannelProvider {
public:
    NullByteProvider() : descriptor_(make_descriptor("test.bytes", ProviderKind::ByteChannel)) {}
    const ProviderDescriptor& descriptor() const noexcept override { return descriptor_; }
    void async_create(EndpointRole, CancellationToken, Completion completion) override {
        completion(Result<std::unique_ptr<ByteChannel>>(Status(StatusCode::FailedPrecondition, "unused")));
    }
private:
    ProviderDescriptor descriptor_;
};

class NullSecureProvider final : public SecureChannelProvider {
public:
    NullSecureProvider() : descriptor_(make_descriptor("test.tls", ProviderKind::SecureChannel)) {}
    const ProviderDescriptor& descriptor() const noexcept override { return descriptor_; }
    void async_wrap(std::unique_ptr<ByteChannel>, EndpointRole, CancellationToken,
                    Completion completion) override {
        completion(Result<std::unique_ptr<SecureChannel>>(Status(StatusCode::FailedPrecondition, "unused")));
    }
private:
    ProviderDescriptor descriptor_;
};

class NullFrontDoorProvider final : public FrontDoorProvider {
public:
    NullFrontDoorProvider() : descriptor_(make_descriptor("test.front", ProviderKind::FrontDoor)) {}
    const ProviderDescriptor& descriptor() const noexcept override { return descriptor_; }
    void async_create(EndpointRole, CancellationToken, Completion completion) override {
        completion(Result<std::unique_ptr<FrontDoor>>(Status(StatusCode::FailedPrecondition, "unused")));
    }
private:
    ProviderDescriptor descriptor_;
};

class NullCarrierProvider final : public CarrierProvider {
public:
    NullCarrierProvider() : descriptor_(make_descriptor("test.carrier", ProviderKind::Carrier)) {}
    const ProviderDescriptor& descriptor() const noexcept override { return descriptor_; }
    void async_create(std::unique_ptr<SecureChannel>, EndpointRole, CancellationToken,
                      Completion completion) override {
        completion(Result<std::unique_ptr<Carrier>>(Status(StatusCode::FailedPrecondition, "unused")));
    }
private:
    ProviderDescriptor descriptor_;
};

class NullRouteProvider final : public RouteProvider {
public:
    NullRouteProvider()
        : descriptor_(require(ProviderDescriptor::create(
              "test.route", ProviderKind::RouteProvider, 1U,
              mandatory_capabilities(ProviderKind::RouteProvider)
                  .with(Capability::DirectTcp)))) {}
    const ProviderDescriptor& descriptor() const noexcept override { return descriptor_; }
    void async_open(const AuthorizedRouteRequest&, CancellationToken,
                    Completion completion) override {
        completion(Result<RouteConnection>(Status(StatusCode::FailedPrecondition, "unused")));
    }
    void cancel() noexcept override {}
private:
    ProviderDescriptor descriptor_;
};

struct SecurityTrace final {
    std::vector<RecordKeyToken> sealed;
    std::vector<RecordKeyToken> opened;
    std::vector<std::uint32_t> rekey_begun;
    std::vector<std::uint32_t> rekey_accepted;
    std::vector<std::uint32_t> rekey_finished;
    int initialized{0};
    bool cancelled{false};
};

class FakeSecurity final : public SessionSecurityProvider {
public:
    explicit FakeSecurity(std::shared_ptr<SecurityTrace> trace)
        : trace_(std::move(trace)), capabilities_(capability_bytes()) {}
    std::string_view provider_id() const noexcept override { return "test.security"; }
    std::string_view suite_id() const noexcept override { return ytp1::kSuiteId; }
    std::span<const std::byte> security_parameters() const noexcept override {
        const auto required = ytp1::RequiredSecurityParameters();
        return {reinterpret_cast<const std::byte*>(required.data()), required.size()};
    }
    std::size_t max_sealed_overhead() const noexcept override { return 0U; }
    Status initialize(const SessionAuthenticationContext& context) override {
        CHECK(context.local_role == EndpointRole::Server);
        CHECK(context.channel_exporter.size() == kSessionExporterBytes);
        CHECK(context.secure_channel_peer.peer_role() == EndpointRole::Client);
        CHECK(!context.secure_channel_peer.authenticated());
        CHECK(context.secure_channel_peer.identity().empty());
        ++trace_->initialized;
        return Status::success();
    }
    Result<AuthenticationOutput> start_authentication() override {
        AuthenticationOutput output;
        output.outbound_kind = AuthenticationMessageKind::Challenge;
        output.outbound_message = auth_message(ytp1::AuthMessageType::Challenge,
                                               ytp1::EndpointRole::Server);
        return Result<AuthenticationOutput>(std::move(output));
    }
    Result<AuthenticationOutput> process_authentication(
        AuthenticationMessageKind kind, std::span<const std::byte>) override {
        CHECK(kind == AuthenticationMessageKind::Response);
        AuthenticationOutput output;
        output.outbound_kind = AuthenticationMessageKind::Accepted;
        output.outbound_message = auth_message(ytp1::AuthMessageType::Accepted,
                                               ytp1::EndpointRole::Server);
        output.established = true;
        output.authenticated_peer = require(PeerEvidence::create(
            EndpointRole::Client, "device-1", "composite-ed25519-mldsa87",
            std::vector<std::byte>{std::byte{1}}));
        output.authenticated_peer_capability_manifest = capabilities_;
        return Result<AuthenticationOutput>(std::move(output));
    }
    Result<Buffer> seal_record(RecordKeyToken token,
                               std::span<const std::byte> plaintext) override {
        trace_->sealed.push_back(token);
        return Result<Buffer>(copy_bytes(plaintext));
    }
    Result<Buffer> open_record(RecordKeyToken token,
                               std::span<const std::byte> ciphertext) override {
        trace_->opened.push_back(token);
        return Result<Buffer>(copy_bytes(ciphertext));
    }
    Result<Buffer> begin_outbound_rekey(std::uint32_t epoch) override {
        trace_->rekey_begun.push_back(epoch);
        return Result<Buffer>(copy_bytes(std::span<const std::byte>(
            std::array<std::byte, 1>{std::byte{1}})));
    }
    Result<Buffer> accept_inbound_rekey(
        std::uint32_t epoch,
        std::span<const std::byte> initiation) override {
        CHECK(initiation.size() == 1U);
        CHECK(initiation[0] == std::byte{1});
        trace_->rekey_accepted.push_back(epoch);
        return Result<Buffer>(copy_bytes(std::span<const std::byte>(
            std::array<std::byte, 1>{std::byte{2}})));
    }
    Status finish_outbound_rekey(
        std::uint32_t epoch,
        std::span<const std::byte> acknowledgement) override {
        CHECK(acknowledgement.size() == 1U);
        CHECK(acknowledgement[0] == std::byte{2});
        trace_->rekey_finished.push_back(epoch);
        return Status::success();
    }
    void cancel() noexcept override { trace_->cancelled = true; }
private:
    std::shared_ptr<SecurityTrace> trace_;
    std::vector<std::byte> capabilities_;
};

class FakeSecurityFactory final : public SessionSecurityProviderFactory {
public:
    explicit FakeSecurityFactory(std::shared_ptr<SecurityTrace> trace)
        : descriptor_(make_descriptor("test.security", ProviderKind::SessionSecurity)),
          trace_(std::move(trace)) {}
    const ProviderDescriptor& descriptor() const noexcept override { return descriptor_; }
    Result<std::unique_ptr<SessionSecurityProvider>> create(EndpointRole role) override {
        CHECK(role == EndpointRole::Server);
        std::unique_ptr<SessionSecurityProvider> provider =
            std::make_unique<FakeSecurity>(trace_);
        return Result<std::unique_ptr<SessionSecurityProvider>>(std::move(provider));
    }
private:
    ProviderDescriptor descriptor_;
    std::shared_ptr<SecurityTrace> trace_;
};

class EchoHandler final : public StreamHandler {
public:
    explicit EchoHandler(bool routes = false)
        : descriptor_(require(ProviderDescriptor::create(
              "test.echo", ProviderKind::StreamHandler, 1U,
              routes
                  ? CapabilitySet::of({Capability::NamedByteStreams,
                                       Capability::DirectTcp})
                  : CapabilitySet::of({Capability::NamedByteStreams})))) {}
    const ProviderDescriptor& descriptor() const noexcept override { return descriptor_; }
    ServiceKind service_kind() const noexcept override { return ServiceKind::ByteStream; }
    Status authorize(const StreamOpenContext& context) override {
        CHECK(context.peer_evidence().identity() == "device-1");
        if (context.destination_if()) {
            destination = *context.destination_if();
        } else {
            destination.reset();
        }
        ++authorized;
        return Status::success();
    }
    void on_open(StreamOpenContext,
                 std::shared_ptr<StreamResponder> stream) override {
        responder = std::move(stream);
        ++opened;
    }
    void async_open(StreamOpenContext context,
                    std::shared_ptr<StreamResponder> stream,
                    AcceptanceCompletion completion) override {
        on_open(std::move(context), std::move(stream));
        if (defer_acceptance) {
            pending_acceptance = std::move(completion);
        } else {
            completion(Status::success());
        }
    }
    void on_route(AuthorizedRouteRequest request,
                  std::shared_ptr<RouteProvider> route_provider,
                  std::shared_ptr<StreamResponder> stream) override {
        CHECK(authorized == 1);
        selected_route = std::move(route_provider);
        route_request.emplace(std::move(request));
        responder = std::move(stream);
        ++routed;
    }
    int authorized{0};
    int opened{0};
    int routed{0};
    std::optional<RouteDestination> destination;
    std::optional<AuthorizedRouteRequest> route_request;
    std::shared_ptr<RouteProvider> selected_route;
    std::shared_ptr<StreamResponder> responder;
    bool defer_acceptance{false};
    AcceptanceCompletion pending_acceptance;
private:
    ProviderDescriptor descriptor_;
};

class FakeSecureChannel final : public SecureChannel {
public:
    explicit FakeSecureChannel(bool exporter_available = true,
                               std::string provider_id = "test.tls")
        : descriptor_(make_descriptor(
              std::move(provider_id), ProviderKind::SecureChannel)),
          exporter_available_(exporter_available),
          peer_(SecureChannelPeerEvidence::anonymous_client()) {}
    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }
    ExecutorAffinity executor_affinity() const noexcept override { return ExecutorAffinity(7U); }
    std::size_t max_read_size() const noexcept override { return 128U * 1024U; }
    std::size_t max_write_size() const noexcept override { return 128U * 1024U; }
    void async_read(std::size_t, CancellationToken, ReadCompletion completion) override {
        completion(Result<Buffer>(Status(StatusCode::FailedPrecondition, "unused")));
    }
    void async_write(Buffer, CancellationToken, WriteCompletion completion) override {
        completion(Status(StatusCode::FailedPrecondition, "unused"), 0U);
    }
    Status shutdown_write() noexcept override { return Status::success(); }
    void cancel() noexcept override {}
    void close() noexcept override {}
    const SecureChannelPeerEvidence& peer_evidence() const noexcept override {
        return peer_;
    }
    Result<Buffer> export_keying_material(std::string_view,
        std::span<const std::byte>, std::size_t size) override {
        if (!exporter_available_) {
            return Result<Buffer>(Status(
                StatusCode::ProviderMismatch,
                "secure-channel exporter is unavailable"));
        }
        return Buffer::allocate(size, size);
    }
private:
    ProviderDescriptor descriptor_;
    bool exporter_available_{true};
    SecureChannelPeerEvidence peer_;
};

class FakeCarrier final : public Carrier {
public:
    explicit FakeCarrier(bool exporter_available = true,
                         std::string provider_id = "test.carrier",
                         std::string secure_provider_id = "test.tls")
        : descriptor_(make_descriptor(
              std::move(provider_id), ProviderKind::Carrier)),
          secure_(exporter_available, std::move(secure_provider_id)) {}
    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }
    ExecutorAffinity executor_affinity() const noexcept override { return ExecutorAffinity(7U); }
    std::size_t max_record_size() const noexcept override { return 128U * 1024U; }
    SecureChannel& secure_channel() noexcept override { return secure_; }
    const SecureChannel& secure_channel() const noexcept override { return secure_; }
    void async_receive(CancellationToken, ReceiveCompletion completion) override {
        CHECK(!receive_);
        receive_ = std::move(completion);
    }
    void async_send(Buffer record, CancellationToken,
                    SendCompletion completion) override {
        const std::size_t size = record.size();
        sent.push_back(std::move(record));
        if (hold_sends) {
            CHECK(!held_send_);
            held_send_ = std::move(completion);
        } else {
            completion(Status::success(), size);
        }
    }
    void cancel() noexcept override {}
    void close() noexcept override {
        closed = true;
        held_send_ = {};
        receive_ = {};
    }
    void deliver(Buffer record) {
        CHECK(receive_);
        auto completion = std::move(receive_);
        receive_ = {};
        const std::size_t size = record.size();
        completion(Result<ReceivedRecord>(ReceivedRecord(
            std::move(record), CarrierCredit(size,
                [this](std::size_t bytes) { released += bytes; }))));
    }
    std::vector<Buffer> sent;
    std::size_t released{0U};
    bool closed{false};
    bool hold_sends{false};
private:
    ProviderDescriptor descriptor_;
    FakeSecureChannel secure_;
    ReceiveCompletion receive_;
    SendCompletion held_send_;
};

std::shared_ptr<const EngineGraph> graph(
    const std::shared_ptr<FakeSecurityFactory>& security,
    const std::shared_ptr<EchoHandler>& echo) {
    std::vector<ProviderRequirement> providers;
    providers.push_back(requirement("test.bytes", ProviderKind::ByteChannel));
    providers.push_back(requirement("test.tls", ProviderKind::SecureChannel));
    providers.push_back(requirement("test.front", ProviderKind::FrontDoor));
    providers.push_back(requirement("test.carrier", ProviderKind::Carrier));
    providers.push_back(requirement("test.security", ProviderKind::SessionSecurity));
    providers.push_back(requirement("test.route", ProviderKind::RouteProvider));
    std::vector<ServiceRequirement> services;
    services.push_back(require(ServiceRequirement::create(
        "echo", ServiceKind::ByteStream, "test.echo", 1U, 8U,
        CapabilitySet::of({Capability::NamedByteStreams}))));
    auto suite = require(TransportSuiteDescriptor::create(
        "test.ytp1", "YTP/1", std::move(providers), std::move(services)));
    EngineBuilder builder(EndpointRole::Server, std::move(suite));
    CHECK(builder.register_byte_channel_provider(std::make_shared<NullByteProvider>()).ok());
    CHECK(builder.register_secure_channel_provider(std::make_shared<NullSecureProvider>()).ok());
    CHECK(builder.register_front_door_provider(std::make_shared<NullFrontDoorProvider>()).ok());
    CHECK(builder.register_carrier_provider(std::make_shared<NullCarrierProvider>()).ok());
    CHECK(builder.register_session_security_provider_factory(security).ok());
    CHECK(builder.register_route_provider(std::make_shared<NullRouteProvider>()).ok());
    CHECK(builder.register_stream_handler("echo", echo).ok());
    return require(builder.build());
}

class TestSession final {
public:
    explicit TestSession(bool exporter_available = true,
                         bool routes = false)
        : trace(std::make_shared<SecurityTrace>()),
          factory(std::make_shared<FakeSecurityFactory>(trace)),
          handler(std::make_shared<EchoHandler>(routes)) {
        auto owned_carrier =
            std::make_unique<FakeCarrier>(exporter_available);
        carrier = owned_carrier.get();
        SessionLimits limits;
        limits.max_streams = 4U;
        limits.max_pending_opens = 2U;
        limits.max_frame_payload = 64U * 1024U;
        auto selected_graph = graph(factory, handler);
        selected_route = selected_graph->route_provider();
        engine = require(SessionEngine::create(
            std::move(selected_graph), std::move(owned_carrier), limits));
    }

    std::shared_ptr<RouteProvider> selected_route;

    void start_to_active() {
        engine->async_start([this](Status status) {
            ++start_completions;
            start_status = std::move(status);
        });
        CHECK(carrier->sent.size() == 1U);

        Buffer response = auth_message(ytp1::AuthMessageType::Response,
                                       ytp1::EndpointRole::Client);
        carrier->deliver(frame(ytp1::RecordType::Auth, 0U,
                               response.bytes()));
        CHECK(carrier->sent.size() == 4U);
        CHECK(start_completions == 0);
        CHECK(trace->sealed.size() == 2U);
        CHECK((trace->sealed[0] == RecordKeyToken{0U, 0U}));
        CHECK((trace->sealed[1] == RecordKeyToken{0U, 1U}));

        carrier->deliver(copy_bytes(carrier->sent[2].bytes()));
        CHECK(start_completions == 1);
        CHECK(start_status.ok());
        CHECK(trace->initialized == 1);
        CHECK(engine->state() == SessionState::Active);
        CHECK((trace->opened.back() == RecordKeyToken{0U, 0U}));
    }

    void open_peer_stream(std::uint64_t sequence = 1U) {
        ytp1::OpenRequest open{
            ytp1::ServiceKind::ByteStream, "echo", {}};
        auto encoded_open = ytp1::EncodeOpen(open);
        CHECK(encoded_open.ok());
        carrier->deliver(protected_wire(
            0U, sequence, frame(
                ytp1::RecordType::Open, 1U,
                {reinterpret_cast<const std::byte*>(
                     encoded_open.value->data()),
                 encoded_open.value->size()})));
        CHECK(handler->authorized == 1);
        CHECK(handler->opened == 1);
        CHECK(handler->responder);
    }

    std::shared_ptr<SecurityTrace> trace;
    std::shared_ptr<FakeSecurityFactory> factory;
    std::shared_ptr<EchoHandler> handler;
    FakeCarrier* carrier{nullptr};
    std::shared_ptr<SessionEngine> engine;
    int start_completions{0};
    Status start_status{StatusCode::Internal,
                        "session start did not complete"};
};

void test_one_use_records_and_cancellation() {
    TestSession session;
    session.start_to_active();
    session.open_peer_stream();

    const std::array<std::byte, 4> data{
        std::byte{'p'}, std::byte{'i'}, std::byte{'n'}, std::byte{'g'}};
    int read_cancellations = 0;
    CancellationSource read_cancellation;
    session.handler->responder->async_read(
        read_cancellation.token(),
        [&read_cancellations](Result<ReceivedRecord> result) {
            CHECK(!result.ok());
            CHECK(result.status().code() == StatusCode::Cancelled);
            ++read_cancellations;
        });
    CHECK(read_cancellation.cancel());
    CHECK(read_cancellations == 1);

    int write_cancellations = 0;
    CancellationSource write_cancellation;
    session.handler->responder->async_write(
        copy_bytes(data), write_cancellation.token(),
        [&write_cancellations](Status status, std::size_t transferred) {
            CHECK(status.code() == StatusCode::Cancelled);
            CHECK(transferred == 0U);
            ++write_cancellations;
        });
    CHECK(write_cancellation.cancel());
    CHECK(write_cancellations == 1);

    session.carrier->deliver(protected_wire(
        0U, 2U, frame(ytp1::RecordType::Data, 1U, data)));
    bool read = false;
    session.handler->responder->async_read(
        {}, [&read](Result<ReceivedRecord> result) {
            CHECK(result.ok());
            CHECK(result.value().payload().size() == 4U);
            read = true;
        });
    CHECK(read);
    CHECK((session.trace->opened.back() == RecordKeyToken{0U, 2U}));

    // A duplicate token is rejected before AEAD/provider work and terminates
    // the session, proving strict ordered one-use inbound keys.
    const std::size_t opened_before = session.trace->opened.size();
    session.carrier->deliver(protected_wire(
        0U, 2U, frame(ytp1::RecordType::Data, 1U, data)));
    CHECK(session.engine->state() == SessionState::Failed);
    CHECK(session.trace->opened.size() == opened_before);
    CHECK(session.trace->cancelled);
    CHECK(session.carrier->closed);
    CHECK(read_cancellations == 1);
    CHECK(write_cancellations == 1);
}

void test_write_half_close_preserves_reads() {
    TestSession session;
    session.start_to_active();
    session.open_peer_stream();

    const std::size_t sent_before_shutdown = session.carrier->sent.size();
    CHECK(session.handler->responder->shutdown_write().ok());
    CHECK(session.handler->responder->shutdown_write().ok());
    CHECK(session.carrier->sent.size() == sent_before_shutdown + 1U);
    CHECK(session.engine->state() == SessionState::Active);

    int rejected_writes = 0;
    const std::array<std::byte, 1> outbound{std::byte{'x'}};
    session.handler->responder->async_write(
        copy_bytes(outbound), {},
        [&rejected_writes](Status status, std::size_t transferred) {
            CHECK(status.code() == StatusCode::Closed);
            CHECK(transferred == 0U);
            ++rejected_writes;
        });
    CHECK(rejected_writes == 1);

    int reads = 0;
    session.handler->responder->async_read(
        {}, [&reads](Result<ReceivedRecord> result) {
            CHECK(result.ok());
            CHECK(result.value().payload().size() == 4U);
            ++reads;
        });
    const std::array<std::byte, 4> inbound{
        std::byte{'p'}, std::byte{'o'}, std::byte{'n'}, std::byte{'g'}};
    session.carrier->deliver(protected_wire(
        0U, 2U, frame(ytp1::RecordType::Data, 1U, inbound)));
    CHECK(reads == 1);
    CHECK(session.engine->state() == SessionState::Active);

    int end_of_stream = 0;
    const auto read_end = [&session, &end_of_stream] {
        session.handler->responder->async_read(
            {}, [&end_of_stream](Result<ReceivedRecord> result) {
                CHECK(!result.ok());
                CHECK(result.status().code() == StatusCode::EndOfStream);
                ++end_of_stream;
            });
    };
    read_end();
    const std::array<std::byte, 1> normal_close{std::byte{0}};
    session.carrier->deliver(protected_wire(
        0U, 3U, frame(ytp1::RecordType::Close, 1U, normal_close)));
    CHECK(end_of_stream == 1);
    CHECK(session.engine->state() == SessionState::Active);
    // Both directions are finished, so the engine has retired the entry. The
    // responder still reports the clean end instead of a closed stream.
    read_end();
    CHECK(end_of_stream == 2);

    session.engine->stop();
    CHECK(end_of_stream == 2);
    int closed_reads = 0;
    session.handler->responder->async_read(
        {}, [&closed_reads](Result<ReceivedRecord> result) {
            CHECK(!result.ok() && result.status().code() == StatusCode::Closed);
            ++closed_reads;
        });
    CHECK(closed_reads == 1);
    CHECK(rejected_writes == 1);
}

void test_shutdown_orders_fin_after_queued_writes() {
    TestSession session;
    session.start_to_active();
    session.open_peer_stream();

    const std::size_t sent_before_write = session.carrier->sent.size();
    const std::array<std::byte, 4> outbound{
        std::byte{'d'}, std::byte{'a'}, std::byte{'t'}, std::byte{'a'}};
    int write_completions = 0;
    session.handler->responder->async_write(
        copy_bytes(outbound), {},
        [&write_completions](Status status, std::size_t transferred) {
            CHECK(status.ok());
            CHECK(transferred == 4U);
            ++write_completions;
        });
    CHECK(write_completions == 0);
    CHECK(session.handler->responder->shutdown_write().ok());
    CHECK(session.carrier->sent.size() == sent_before_write);

    session.carrier->deliver(protected_wire(
        0U, 2U, credit_frame(
            ytp1::RecordType::ConnectionCredit, 0U, 16U)));
    CHECK(write_completions == 0);
    CHECK(session.carrier->sent.size() == sent_before_write);

    session.carrier->deliver(protected_wire(
        0U, 3U, credit_frame(
            ytp1::RecordType::StreamCredit, 1U, 16U)));
    CHECK(write_completions == 1);
    CHECK(session.carrier->sent.size() == sent_before_write + 2U);
    CHECK(protected_record_type(
              session.carrier->sent[sent_before_write]) ==
          ytp1::RecordType::Data);
    CHECK(protected_record_type(
              session.carrier->sent[sent_before_write + 1U]) ==
          ytp1::RecordType::Close);

    const std::array<std::byte, 1> normal_close{std::byte{0}};
    session.carrier->deliver(protected_wire(
        0U, 4U, frame(ytp1::RecordType::Close, 1U, normal_close)));
    CHECK(session.engine->state() == SessionState::Active);
    CHECK(write_completions == 1);
}

void test_peer_half_close_preserves_writes() {
    TestSession session;
    session.start_to_active();
    session.open_peer_stream();

    session.carrier->deliver(protected_wire(
        0U, 2U, credit_frame(
            ytp1::RecordType::ConnectionCredit, 0U, 16U)));
    session.carrier->deliver(protected_wire(
        0U, 3U, credit_frame(
            ytp1::RecordType::StreamCredit, 1U, 16U)));

    const std::array<std::byte, 1> normal_close{std::byte{0}};
    session.carrier->deliver(protected_wire(
        0U, 4U, frame(ytp1::RecordType::Close, 1U, normal_close)));

    int end_of_stream = 0;
    session.handler->responder->async_read(
        {}, [&end_of_stream](Result<ReceivedRecord> result) {
            CHECK(!result.ok());
            CHECK(result.status().code() == StatusCode::EndOfStream);
            ++end_of_stream;
        });
    CHECK(end_of_stream == 1);

    const std::array<std::byte, 4> outbound{
        std::byte{'l'}, std::byte{'a'}, std::byte{'s'}, std::byte{'t'}};
    int write_completions = 0;
    session.handler->responder->async_write(
        copy_bytes(outbound), {},
        [&write_completions](Status status, std::size_t transferred) {
            CHECK(status.ok());
            CHECK(transferred == 4U);
            ++write_completions;
        });
    CHECK(write_completions == 1);
    CHECK(session.engine->state() == SessionState::Active);
    CHECK(session.handler->responder->shutdown_write().ok());
}

StatusCode read_code(StreamResponder& responder) {
    StatusCode code = StatusCode::Internal;
    int completions = 0;
    responder.async_read({}, [&code, &completions](Result<ReceivedRecord> result) {
        code = result.ok() ? StatusCode::Ok : result.status().code();
        ++completions;
    });
    CHECK(completions == 1);
    return code;
}

void test_end_of_stream_is_distinct_from_abort_and_session_end() {
    const std::array<std::byte, 4> data{
        std::byte{'d'}, std::byte{'a'}, std::byte{'t'}, std::byte{'a'}};
    {
        // Data accepted before the FIN arrives first. The clean end repeats
        // until a local close, which then reports closure instead.
        TestSession session;
        session.start_to_active();
        session.open_peer_stream();
        session.carrier->deliver(protected_wire(
            0U, 2U, frame(ytp1::RecordType::Data, 1U, data)));
        const std::array<std::byte, 1> fin{std::byte{0}};
        session.carrier->deliver(protected_wire(
            0U, 3U, frame(ytp1::RecordType::Close, 1U, fin)));
        auto& responder = *session.handler->responder;
        CHECK(read_code(responder) == StatusCode::Ok);
        CHECK(read_code(responder) == StatusCode::EndOfStream);
        CHECK(read_code(responder) == StatusCode::EndOfStream);
        responder.close(Status(StatusCode::Cancelled));
        const StatusCode closed = read_code(responder);
        CHECK(closed != StatusCode::Ok && closed != StatusCode::EndOfStream);
        CHECK(session.engine->state() == SessionState::Active);
    }
    {
        // A peer abort discards queued data and is never a clean end.
        TestSession session;
        session.start_to_active();
        session.open_peer_stream();
        session.carrier->deliver(protected_wire(
            0U, 2U, frame(ytp1::RecordType::Data, 1U, data)));
        const std::array<std::byte, 1> aborted{std::byte{4}};
        session.carrier->deliver(protected_wire(
            0U, 3U, frame(ytp1::RecordType::Close, 1U, aborted)));
        const StatusCode code = read_code(*session.handler->responder);
        CHECK(code != StatusCode::Ok && code != StatusCode::EndOfStream);
        CHECK(session.engine->state() == SessionState::Active);
    }
    {
        // Session termination settles a pending read without a clean end,
        // even when the termination reason itself is Closed.
        TestSession session;
        session.start_to_active();
        session.open_peer_stream();
        StatusCode pending = StatusCode::Ok;
        session.handler->responder->async_read(
            {}, [&pending](Result<ReceivedRecord> result) {
                pending = result.ok() ? StatusCode::Ok : result.status().code();
            });
        session.engine->stop(Status(StatusCode::Closed, "endpoint closed"));
        CHECK(pending == StatusCode::Closed);
        const StatusCode later = read_code(*session.handler->responder);
        CHECK(later != StatusCode::Ok && later != StatusCode::EndOfStream);
    }
}

void test_authenticated_peer_is_available_only_while_active() {
    TestSession session;
    const auto before = session.engine->authenticated_peer();
    CHECK(!before.ok() &&
          before.status().code() == StatusCode::FailedPrecondition);
    session.start_to_active();
    const auto active = session.engine->authenticated_peer();
    CHECK(active.ok());
    CHECK(active.value().peer_role() == EndpointRole::Client);
    CHECK(active.value().identity() == "device-1");
    CHECK(active.value().credential_evidence().size() == 1U);
    session.engine->stop();
    const auto after = session.engine->authenticated_peer();
    CHECK(!after.ok() &&
          after.status().code() == StatusCode::FailedPrecondition);
}

void test_termination_overrides_an_earlier_fin() {
    for (unsigned ending = 0U; ending < 4U; ++ending) {
        TestSession session;
        session.start_to_active();
        session.open_peer_stream();
        const auto responder = session.handler->responder;
        const std::array<std::byte, 1> fin{std::byte{0}};
        session.carrier->deliver(protected_wire(
            0U, 2U, frame(ytp1::RecordType::Close, 1U, fin)));
        CHECK(!responder->terminated());
        CHECK(read_code(*responder) == StatusCode::EndOfStream);
        if (ending == 0U) {
            const std::array<std::byte, 1> abort{std::byte{1}};
            session.carrier->deliver(protected_wire(
                0U, 3U, frame(ytp1::RecordType::Close, 1U, abort)));
            CHECK(session.engine->state() == SessionState::Active);
        } else if (ending == 1U) {
            session.engine->stop();
        } else if (ending == 2U) {
            session.engine.reset();
        } else {
            // Clean settlement can retire the entry. The retained responder
            // must still see subsequent session loss without a stream entry.
            CHECK(responder->shutdown_write().ok());
            const std::array<std::byte, 1> settled{std::byte{5}};
            session.carrier->deliver(protected_wire(
                0U, 3U, frame(ytp1::RecordType::Close, 1U, settled)));
            CHECK(!responder->terminated());
            CHECK(read_code(*responder) == StatusCode::EndOfStream);
            session.engine->stop();
        }
        CHECK(responder->terminated());
        CHECK(read_code(*responder) == StatusCode::Closed);
        CHECK(read_code(*responder) == StatusCode::Closed);
    }
}

void test_partial_credit_does_not_reorder_queued_writes() {
    TestSession session;
    session.start_to_active();
    session.open_peer_stream();
    session.carrier->deliver(protected_wire(
        0U, 2U, credit_frame(ytp1::RecordType::ConnectionCredit, 0U, 32U)));
    session.carrier->deliver(protected_wire(
        0U, 3U, credit_frame(ytp1::RecordType::StreamCredit, 1U, 4U)));
    const auto before = session.carrier->sent.size();
    const std::array<std::byte, 8U> first{
        std::byte{'a'}, std::byte{'a'}, std::byte{'a'}, std::byte{'a'},
        std::byte{'a'}, std::byte{'a'}, std::byte{'a'}, std::byte{'a'}};
    const std::array<std::byte, 2U> second{std::byte{'b'}, std::byte{'b'}};
    int completed = 0;
    session.handler->responder->async_write(copy_bytes(first), {},
        [&](Status status, std::size_t size) {
            CHECK(status.ok());
            CHECK(size == first.size());
            CHECK(completed == 0);
            ++completed;
        });
    session.handler->responder->async_write(copy_bytes(second), {},
        [&](Status status, std::size_t size) {
            CHECK(status.ok());
            CHECK(size == second.size());
            CHECK(completed == 1);
            ++completed;
        });
    CHECK(completed == 0);
    CHECK(session.carrier->sent.size() == before);
    session.carrier->deliver(protected_wire(
        0U, 4U, credit_frame(ytp1::RecordType::StreamCredit, 1U, 8U)));
    CHECK(completed == 2);
    CHECK(session.carrier->sent.size() == before + 2U);
    const auto first_record = protected_record(session.carrier->sent[before]);
    const auto second_record = protected_record(session.carrier->sent[before + 1U]);
    CHECK(first_record.header.type == ytp1::RecordType::Data);
    CHECK(second_record.header.type == ytp1::RecordType::Data);
    CHECK(std::equal(first_record.payload.begin(), first_record.payload.end(),
                     reinterpret_cast<const std::uint8_t*>(first.data()),
                     reinterpret_cast<const std::uint8_t*>(first.data()) + first.size()));
    CHECK(std::equal(second_record.payload.begin(), second_record.payload.end(),
                     reinterpret_cast<const std::uint8_t*>(second.data()),
                     reinterpret_cast<const std::uint8_t*>(second.data()) + second.size()));
}

void test_stop_retains_engine_through_owner_releasing_callbacks() {
    for (const bool active : {false, true}) {
        TestSession session;
        const std::weak_ptr<SessionEngine> lifetime = session.engine;
        int completed = 0;
        bool alive_during_callback = false;
        auto release_owner = [&] {
            ++completed;
            session.engine.reset();
            alive_during_callback = !lifetime.expired();
        };
        if (active) {
            session.start_to_active();
            session.open_peer_stream();
            session.handler->responder->async_read({},
                [&](Result<ReceivedRecord> result) {
                    CHECK(!result.ok());
                    release_owner();
                });
        } else {
            session.engine->async_start([&](Status status) {
                CHECK(!status.ok());
                release_owner();
            });
        }
        session.engine->stop();
        CHECK(completed == 1);
        CHECK(alive_during_callback);
        CHECK(lifetime.expired());
    }
}

void test_pending_read_settled_after_allocation_failure() {
    TestSession session;
    session.start_to_active();
    session.open_peer_stream();

    constexpr std::size_t kFailurePayloadBytes = 4093U;
    const std::vector<std::byte> payload(
        kFailurePayloadBytes, std::byte{0x5a});
    Buffer wire = protected_wire(
        0U, 2U, frame(ytp1::RecordType::Data, 1U, payload));

    int completions = 0;
    StatusCode completion_code = StatusCode::Ok;
    session.handler->responder->async_read(
        {}, [&completions, &completion_code](
                Result<ReceivedRecord> result) {
            CHECK(!result.ok());
            completion_code = result.status().code();
            ++completions;
        });

    test_allocation_failure::fail_once_for_size(kFailurePayloadBytes);
    session.carrier->deliver(std::move(wire));
    CHECK(!test_allocation_failure::armed());
    CHECK(session.engine->state() == SessionState::Failed);
    CHECK(completions == 1);
    CHECK(completion_code == StatusCode::ResourceExhausted);

    session.engine->stop();
    CHECK(completions == 1);
}

void test_stop_and_destruction_under_allocation_failure() {
    for (const bool sustained : {false, true}) {
        for (const bool last_owner : {false, true}) {
            TestSession session;
            session.start_to_active();
            session.open_peer_stream();
            int reads = 0;
            int writes = 0;
            StatusCode read_code = StatusCode::Ok;
            StatusCode write_code = StatusCode::Ok;
            std::size_t write_bytes = 99U;
            session.handler->responder->async_read({}, [&](auto result) {
                ++reads;
                read_code = result.status().code();
            });
            const std::array<std::byte, 4> payload{};
            for (int count = 0; count < 2; ++count) {
                session.handler->responder->async_write(
                    copy_bytes(payload), {}, [&](Status status, std::size_t bytes) {
                        ++writes;
                        write_code = status.code();
                        write_bytes = bytes;
                        // Re-entry must observe terminal state and cannot take
                        // another completion from the drain in progress.
                        if (session.engine) session.engine->stop();
                    });
            }
            CHECK(reads == 0);
            CHECK(writes == 0);
            Status reason(StatusCode::Cancelled, std::string(512U, 'x'));
            {
                test_allocation_failure::Scope failure(1U, sustained);
                if (sustained) {
                    test_allocation_failure::fail_all.store(
                        true, std::memory_order_relaxed);
                }
                if (last_owner) {
                    session.engine.reset();
                } else {
                    session.engine->stop(std::move(reason));
                    CHECK(session.engine->state() == SessionState::Closed);
                    session.engine.reset();
                }
            }
            const auto expected = last_owner ? StatusCode::Closed
                                             : StatusCode::Cancelled;
            CHECK(reads == 1);
            CHECK(writes == 2);
            CHECK(read_code == expected);
            CHECK(write_code == expected);
            CHECK(write_bytes == 0U);
            CHECK(session.trace->cancelled);
        }
    }
}

void test_start_completion_survives_long_failure_status() {
    for (const bool sustained : {false, true}) {
        TestSession session;
        int completions = 0;
        StatusCode code = StatusCode::Ok;
        session.engine->async_start([&](Status status) {
            ++completions;
            code = status.code();
        });
        CHECK(completions == 0);
        Status reason(StatusCode::Closed, std::string(512U, 'x'));
        {
            test_allocation_failure::Scope failure(1U, sustained);
            session.engine->stop(std::move(reason));
            session.engine.reset();
        }
        CHECK(completions == 1);
        CHECK(code == StatusCode::Closed);
        CHECK(session.trace->cancelled);
    }
}

void test_stream_cleanup_under_allocation_failure() {
    for (const bool sustained : {false, true}) {
        for (const bool return_credit : {false, true}) {
            TestSession session;
            session.start_to_active();
            session.open_peer_stream();
            std::optional<ReceivedRecord> retained;
            if (return_credit) {
                session.handler->responder->async_read({}, [&](auto result) {
                    CHECK(result.ok());
                    retained.emplace(std::move(result).take_value());
                });
                const std::array<std::byte, 4U> payload{};
                session.carrier->deliver(protected_wire(
                    0U, 2U, frame(ytp1::RecordType::Data, 1U, payload)));
                CHECK(retained.has_value());
            }
            int completions = 0;
            StatusCode code = StatusCode::Ok;
            session.handler->responder->async_read({}, [&](auto result) {
                ++completions;
                code = result.status().code();
            });
            {
                test_allocation_failure::Scope failure(1U, sustained);
                if (return_credit) {
                    retained.reset();
                } else {
                    session.handler->responder->close(Status(StatusCode::Cancelled));
                }
            }
            CHECK(completions == 1);
            CHECK(code == (return_credit ? StatusCode::ResourceExhausted
                                         : StatusCode::Cancelled));
            CHECK(session.engine->state() == SessionState::Failed);
            CHECK(session.trace->cancelled);
            CHECK(session.carrier->closed);
        }
    }
}

void test_stop_drains_active_queued_and_rekey_deferred_writes() {
    for (const bool sustained : {false, true}) {
        TestSession session;
        session.start_to_active();
        session.open_peer_stream();
        session.carrier->deliver(protected_wire(
            0U, 2U, credit_frame(ytp1::RecordType::ConnectionCredit, 0U, 16U)));
        session.carrier->deliver(protected_wire(
            0U, 3U, credit_frame(ytp1::RecordType::StreamCredit, 1U, 16U)));
        session.carrier->hold_sends = true;
        std::array<int, 3U> completions{};
        std::array<StatusCode, 3U> codes{};
        const std::array<std::byte, 4U> payload{};
        for (std::size_t i = 0U; i < completions.size(); ++i) {
            if (i == 2U) CHECK(session.engine->initiate_rekey().ok());
            session.handler->responder->async_write(
                copy_bytes(payload), {}, [&, i](Status status, std::size_t bytes) {
                    ++completions[i];
                    codes[i] = status.code();
                    CHECK(bytes == 0U);
                });
        }
        CHECK((completions == std::array<int, 3U>{0, 0, 0}));
        Status reason(StatusCode::Cancelled, std::string(512U, 'x'));
        {
            test_allocation_failure::Scope failure(1U, sustained);
            session.engine->stop(std::move(reason));
        }
        CHECK((completions == std::array<int, 3U>{1, 1, 1}));
        for (const auto code : codes) CHECK(code == StatusCode::Cancelled);
        CHECK(session.carrier->closed);
        CHECK(session.trace->cancelled);
    }
}

void test_peer_stream_construction_allocation_failures() {
    for (const bool sustained : {false, true}) {
        bool completed_sweep = false;
        std::size_t failures = 0U;
        for (std::size_t nth = 1U; nth <= 128U; ++nth) {
            TestSession session;
            session.start_to_active();
            auto encoded = ytp1::EncodeOpen(
                {ytp1::ServiceKind::ByteStream, "echo", {}});
            CHECK(encoded.ok());
            Buffer open = protected_wire(0U, 1U, frame(
                ytp1::RecordType::Open, 1U,
                {reinterpret_cast<const std::byte*>(encoded.value->data()),
                 encoded.value->size()}));
            bool fired = false;
            SessionState after_delivery = SessionState::Created;
            {
                test_allocation_failure::Scope failure(nth, sustained);
                session.carrier->deliver(std::move(open));
                fired = failure.fired();
                after_delivery = session.engine->state();
                if (fired) session.engine->stop();
            }
            if (!fired) {
                CHECK(session.engine->state() == SessionState::Active);
                CHECK(session.handler->opened == 1);
                completed_sweep = true;
                break;
            }
            // Before a one-use record token is consumed, a failed handler
            // acceptance can be refused without terminating the session.
            CHECK(after_delivery == SessionState::Failed ||
                  (after_delivery == SessionState::Active &&
                   protected_record_type(session.carrier->sent.back()) ==
                       ytp1::RecordType::Close));
            CHECK(session.trace->cancelled);
            CHECK(session.carrier->closed);
            ++failures;
        }
        CHECK(completed_sweep);
        CHECK(failures >= 10U);
    }
}

void test_outer_channel_identity_and_exporter_boundary() {
    TestSession missing_exporter(false);
    missing_exporter.engine->async_start(
        [&missing_exporter](Status status) {
            ++missing_exporter.start_completions;
            missing_exporter.start_status = std::move(status);
        });
    CHECK(missing_exporter.start_completions == 1);
    CHECK(missing_exporter.start_status.code() ==
          StatusCode::ProviderMismatch);
    CHECK(missing_exporter.trace->initialized == 0);
    CHECK(missing_exporter.trace->cancelled);
    CHECK(missing_exporter.carrier->closed);
    CHECK(missing_exporter.engine->state() == SessionState::Failed);
}

void test_transport_instance_provenance() {
    auto trace = std::make_shared<SecurityTrace>();
    auto factory = std::make_shared<FakeSecurityFactory>(trace);
    auto handler = std::make_shared<EchoHandler>();

    auto wrong_carrier = SessionEngine::create(
        graph(factory, handler),
        std::make_unique<FakeCarrier>(
            true, "wrong.carrier", "test.tls"));
    CHECK(!wrong_carrier.ok());
    CHECK(wrong_carrier.status().code() == StatusCode::ProviderMismatch);

    auto wrong_secure_channel = SessionEngine::create(
        graph(factory, handler),
        std::make_unique<FakeCarrier>(
            true, "test.carrier", "wrong.tls"));
    CHECK(!wrong_secure_channel.ok());
    CHECK(wrong_secure_channel.status().code() ==
          StatusCode::ProviderMismatch);
}

void test_rekey_resource_limit_contract() {
    auto trace = std::make_shared<SecurityTrace>();
    auto factory = std::make_shared<FakeSecurityFactory>(trace);
    auto handler = std::make_shared<EchoHandler>();

    SessionLimits supported;
    supported.max_concurrent_rekeys = 4U;
    auto supported_carrier = std::make_unique<FakeCarrier>();
    CHECK(SessionEngine::create(
              graph(factory, handler), std::move(supported_carrier),
              supported).ok());

    SessionLimits excessive;
    excessive.max_concurrent_rekeys =
        kMaxSessionConcurrentRekeys + 1U;
    auto excessive_carrier = std::make_unique<FakeCarrier>();
    auto rejected = SessionEngine::create(
        graph(factory, handler), std::move(excessive_carrier), excessive);
    CHECK(!rejected.ok());
    CHECK(rejected.status().code() == StatusCode::InvalidArgument);
}

void test_rekey_ack_wire_contract() {
    TestSession session;
    session.start_to_active();

    const std::size_t sent_before_rekey = session.carrier->sent.size();
    CHECK(session.engine->initiate_rekey().ok());
    CHECK(session.trace->rekey_begun.size() == 1U);
    CHECK(session.trace->rekey_begun.back() == 1U);
    CHECK(session.carrier->sent.size() == sent_before_rekey + 1U);
    CHECK(session.trace->sealed.size() == 3U);
    CHECK((session.trace->sealed.back() == RecordKeyToken{0U, 2U}));
    const auto outbound_init = protected_record(
        session.carrier->sent.back());
    CHECK(outbound_init.header.type == ytp1::RecordType::RekeyInit);
    CHECK(outbound_init.header.stream_id.is_control());
    CHECK(outbound_init.payload.size() == 5U);
    CHECK(outbound_init.payload[4] == 1U);

    // Cross a peer INIT while the local outbound ratchet is pending. INIT is
    // opened under the old inbound epoch, but the generated ACK is a raw YTP
    // control record and therefore consumes no outbound AEAD token.
    Buffer peer_init = rekey_payload(1U, std::byte{1});
    const std::size_t sealed_before_peer_init =
        session.trace->sealed.size();
    session.carrier->deliver(protected_wire(
        0U, 1U, frame(ytp1::RecordType::RekeyInit, 0U,
                      peer_init.bytes())));
    CHECK(session.engine->state() == SessionState::Active);
    CHECK(session.trace->rekey_accepted.size() == 1U);
    CHECK(session.trace->rekey_accepted.back() == 1U);
    CHECK((session.trace->opened.back() == RecordKeyToken{0U, 1U}));
    CHECK(session.trace->sealed.size() == sealed_before_peer_init);
    CHECK(session.carrier->sent.size() == sent_before_rekey + 2U);
    const auto outbound_ack = raw_record(session.carrier->sent.back());
    CHECK(outbound_ack.header.type == ytp1::RecordType::RekeyAck);
    CHECK(outbound_ack.header.stream_id.is_control());
    CHECK(outbound_ack.payload.size() == 5U);
    CHECK(outbound_ack.payload[4] == 2U);

    // The fake peer emits the same authenticated provider marker. A raw ACK
    // completes the pending outbound ratchet without open_record() or a seal
    // token, which is the property needed for simultaneous opposite-direction
    // rekeys.
    Buffer peer_ack = copy_bytes(session.carrier->sent.back().bytes());
    const std::size_t opened_before_ack = session.trace->opened.size();
    const std::size_t sealed_before_ack = session.trace->sealed.size();
    session.carrier->deliver(std::move(peer_ack));
    CHECK(session.engine->state() == SessionState::Active);
    CHECK(session.trace->rekey_finished.size() == 1U);
    CHECK(session.trace->rekey_finished.back() == 1U);
    CHECK(session.trace->opened.size() == opened_before_ack);
    CHECK(session.trace->sealed.size() == sealed_before_ack);

    // Epochs advance while sequence numbers remain monotonic for the entire
    // direction. Neither side restarts its sequence at zero after rekey.
    const std::array<std::byte, 8> ping{};
    const std::size_t sent_before_ping = session.carrier->sent.size();
    session.carrier->deliver(protected_wire(
        1U, 2U, frame(ytp1::RecordType::Ping, 0U, ping)));
    CHECK(session.engine->state() == SessionState::Active);
    CHECK((session.trace->opened.back() == RecordKeyToken{1U, 2U}));
    CHECK((session.trace->sealed.back() == RecordKeyToken{1U, 3U}));
    CHECK(session.carrier->sent.size() == sent_before_ping + 1U);
    CHECK(protected_record_type(session.carrier->sent.back()) ==
          ytp1::RecordType::Pong);
}

void test_rekey_ack_admission_fail_closed() {
    {
        TestSession protected_ack;
        protected_ack.start_to_active();
        CHECK(protected_ack.engine->initiate_rekey().ok());
        Buffer payload = rekey_payload(1U, std::byte{2});
        const std::size_t opened_before =
            protected_ack.trace->opened.size();
        protected_ack.carrier->deliver(protected_wire(
            0U, 1U, frame(ytp1::RecordType::RekeyAck, 0U,
                          payload.bytes())));
        CHECK(protected_ack.engine->state() == SessionState::Failed);
        CHECK(protected_ack.trace->opened.size() == opened_before + 1U);
        CHECK(protected_ack.trace->rekey_finished.empty());
    }
    {
        TestSession raw_ping;
        raw_ping.start_to_active();
        const std::array<std::byte, 8> ping{};
        const std::size_t opened_before = raw_ping.trace->opened.size();
        raw_ping.carrier->deliver(
            frame(ytp1::RecordType::Ping, 0U, ping));
        CHECK(raw_ping.engine->state() == SessionState::Failed);
        CHECK(raw_ping.trace->opened.size() == opened_before);
        CHECK(raw_ping.trace->rekey_finished.empty());
    }
    {
        TestSession wrong_stream;
        wrong_stream.start_to_active();
        CHECK(wrong_stream.engine->initiate_rekey().ok());
        Buffer payload = rekey_payload(1U, std::byte{2});
        Buffer ack = frame(ytp1::RecordType::RekeyAck, 0U,
                           payload.bytes());
        ack.mutable_bytes()[7] = std::byte{1};
        const std::size_t opened_before = wrong_stream.trace->opened.size();
        wrong_stream.carrier->deliver(std::move(ack));
        CHECK(wrong_stream.engine->state() == SessionState::Failed);
        CHECK(wrong_stream.trace->opened.size() == opened_before);
        CHECK(wrong_stream.trace->rekey_finished.empty());
    }
    {
        TestSession wrong_epoch;
        wrong_epoch.start_to_active();
        CHECK(wrong_epoch.engine->initiate_rekey().ok());
        Buffer payload = rekey_payload(2U, std::byte{2});
        const std::size_t opened_before = wrong_epoch.trace->opened.size();
        wrong_epoch.carrier->deliver(frame(
            ytp1::RecordType::RekeyAck, 0U, payload.bytes()));
        CHECK(wrong_epoch.engine->state() == SessionState::Failed);
        CHECK(wrong_epoch.trace->opened.size() == opened_before);
        CHECK(wrong_epoch.trace->rekey_finished.empty());
    }
    {
        TestSession short_payload;
        short_payload.start_to_active();
        CHECK(short_payload.engine->initiate_rekey().ok());
        const std::array<std::byte, 4> epoch{
            std::byte{0}, std::byte{0}, std::byte{0}, std::byte{1}};
        const std::size_t opened_before =
            short_payload.trace->opened.size();
        short_payload.carrier->deliver(frame(
            ytp1::RecordType::RekeyAck, 0U, epoch));
        CHECK(short_payload.engine->state() == SessionState::Failed);
        CHECK(short_payload.trace->opened.size() == opened_before);
        CHECK(short_payload.trace->rekey_finished.empty());
    }
    {
        TestSession truncated;
        truncated.start_to_active();
        CHECK(truncated.engine->initiate_rekey().ok());
        Buffer payload = rekey_payload(1U, std::byte{2});
        Buffer complete = frame(ytp1::RecordType::RekeyAck, 0U,
                                payload.bytes());
        Buffer wire = copy_bytes(
            complete.bytes().first(complete.size() - 1U));
        const std::size_t opened_before = truncated.trace->opened.size();
        truncated.carrier->deliver(std::move(wire));
        CHECK(truncated.engine->state() == SessionState::Failed);
        CHECK(truncated.trace->opened.size() == opened_before);
        CHECK(truncated.trace->rekey_finished.empty());
    }
    {
        TestSession oversized;
        oversized.start_to_active();
        CHECK(oversized.engine->initiate_rekey().ok());
        std::vector<std::byte> payload(
            64U * 1024U + 1U, std::byte{0});
        payload[3] = std::byte{1};
        payload[4] = std::byte{2};
        const std::size_t opened_before = oversized.trace->opened.size();
        oversized.carrier->deliver(frame(
            ytp1::RecordType::RekeyAck, 0U, payload));
        CHECK(oversized.engine->state() == SessionState::Failed);
        CHECK(oversized.trace->opened.size() == opened_before);
        CHECK(oversized.trace->rekey_finished.empty());
    }
}

void test_open_acceptance_refusal_and_pending_cancellation() {
    TestSession session;
    session.start_to_active();
    int completions = 0;
    StatusCode status = StatusCode::Ok;
    std::shared_ptr<StreamResponder> opened;
    auto capture = [&](Result<std::shared_ptr<StreamResponder>> result) {
        ++completions;
        status = result.status().code();
        if (result.ok()) opened = std::move(result).take_value();
    };
    const auto before = session.carrier->sent.size();
    session.engine->async_open("echo", ServiceKind::ByteStream, capture);
    CHECK(completions == 0);
    CHECK(session.carrier->sent.size() == before + 1U);
    const std::array<std::byte, 1U> unauthorized{std::byte{1}};
    session.carrier->deliver(protected_wire(
        0U, 1U, frame(ytp1::RecordType::Close, 2U, unauthorized)));
    CHECK(completions == 1);
    CHECK(status == StatusCode::FailedPrecondition);
    CHECK(session.engine->state() == SessionState::Active);
    session.engine->async_open("echo", ServiceKind::ByteStream, capture);
    CHECK(completions == 1);
    session.carrier->deliver(protected_wire(
        0U, 2U, credit_frame(ytp1::RecordType::StreamCredit, 4U, 16U)));
    CHECK(completions == 2);
    CHECK(opened);
    CHECK(session.engine->state() == SessionState::Active);

    CancellationSource cancellation;
    session.engine->async_open("echo", ServiceKind::ByteStream, std::nullopt,
                               cancellation.token(), capture);
    CHECK(completions == 2);
    CHECK(cancellation.cancel());
    CHECK(completions == 3);
    CHECK(status == StatusCode::Cancelled);
    // Acceptance crossed the abort; it must not revive or complete the OPEN.
    session.carrier->deliver(protected_wire(
        0U, 3U, credit_frame(ytp1::RecordType::StreamCredit, 6U, 16U)));
    CHECK(completions == 3);
    const std::array<std::byte, 1U> settled{std::byte{5}};
    session.carrier->deliver(protected_wire(
        0U, 4U, frame(ytp1::RecordType::Close, 6U, settled)));
    CHECK(session.engine->state() == SessionState::Active);
    session.engine->async_open("echo", ServiceKind::ByteStream, capture);
    session.engine->stop();
    CHECK(completions == 4);
    CHECK(status == StatusCode::Cancelled);
}

void test_receiver_waits_for_handler_acceptance() {
    for (const auto outcome : {StatusCode::Ok, StatusCode::FailedPrecondition,
                               StatusCode::Cancelled}) {
        TestSession session;
        session.start_to_active();
        session.handler->defer_acceptance = true;
        const auto before = session.carrier->sent.size();
        session.open_peer_stream();
        CHECK(session.handler->pending_acceptance);
        CHECK(session.carrier->sent.size() == before);
        if (outcome == StatusCode::Cancelled) {
            const std::array<std::byte, 1U> abort{std::byte{4}};
            session.carrier->deliver(protected_wire(
                0U, 2U, frame(ytp1::RecordType::Close, 1U, abort)));
            CHECK(session.engine->state() == SessionState::Active);
        }
        auto completion = std::move(session.handler->pending_acceptance);
        // A provider completing after peer cancellation cannot publish credit
        // or revive the removed application owner.
        completion(Status(outcome == StatusCode::FailedPrecondition
                              ? outcome : StatusCode::Ok));
        CHECK(session.engine->state() == SessionState::Active);
        CHECK(session.carrier->sent.size() == before + 1U);
        CHECK(protected_record_type(session.carrier->sent.back()) ==
              (outcome == StatusCode::Ok ? ytp1::RecordType::StreamCredit
                                        : ytp1::RecordType::Close));
    }
}

void test_crossed_abort_data_credit_and_terminal_barrier() {
    TestSession session;
    session.start_to_active();
    session.open_peer_stream();
    session.handler->responder->close(Status(StatusCode::Cancelled));
    CHECK(session.engine->state() == SessionState::Active);
    const std::array<std::byte, 4U> payload{};
    session.carrier->deliver(protected_wire(
        0U, 2U, frame(ytp1::RecordType::Data, 1U, payload)));
    session.carrier->deliver(protected_wire(
        0U, 3U, credit_frame(ytp1::RecordType::StreamCredit, 1U, 16U)));
    const std::array<std::byte, 1U> aborted{std::byte{4}};
    session.carrier->deliver(protected_wire(
        0U, 4U, frame(ytp1::RecordType::Close, 1U, aborted)));
    CHECK(session.engine->state() == SessionState::Active);
    const std::array<std::byte, 1U> settled{std::byte{5}};
    session.carrier->deliver(protected_wire(
        0U, 5U, frame(ytp1::RecordType::Close, 1U, settled)));
    CHECK(session.engine->state() == SessionState::Active);
    session.carrier->deliver(protected_wire(
        0U, 6U, credit_frame(ytp1::RecordType::StreamCredit, 1U, 16U)));
    CHECK(session.engine->state() == SessionState::Failed);
}

void test_graceful_settlement_keeps_crossed_credit_ordered() {
    TestSession session;
    session.start_to_active();
    session.open_peer_stream();
    CHECK(session.handler->responder->shutdown_write().ok());
    const std::array<std::byte, 1U> fin{std::byte{0}};
    session.carrier->deliver(protected_wire(
        0U, 2U, frame(ytp1::RecordType::Close, 1U, fin)));
    session.carrier->deliver(protected_wire(
        0U, 3U, credit_frame(ytp1::RecordType::StreamCredit, 1U, 16U)));
    CHECK(session.engine->state() == SessionState::Active);
    const std::array<std::byte, 1U> settled{std::byte{5}};
    session.carrier->deliver(protected_wire(
        0U, 4U, frame(ytp1::RecordType::Close, 1U, settled)));
    CHECK(session.engine->state() == SessionState::Active);
}

void test_unacknowledged_streams_remain_bounded() {
    TestSession session;
    session.start_to_active();
    int completions = 0;
    StatusCode code = StatusCode::Ok;
    for (int i = 0; i < 4; ++i) {
        CancellationSource cancellation;
        session.engine->async_open("echo", ServiceKind::ByteStream, std::nullopt,
            cancellation.token(), [&](auto result) {
                ++completions;
                code = result.status().code();
            });
        CHECK(cancellation.cancel());
        CHECK(code == StatusCode::Cancelled);
    }
    CHECK(completions == 4);
    session.engine->async_open("echo", ServiceKind::ByteStream, [&](auto result) {
        ++completions;
        code = result.status().code();
    });
    CHECK(completions == 5);
    CHECK(code == StatusCode::ResourceExhausted);
    CHECK(session.engine->state() == SessionState::Active);
}

void test_cancel_unpublished_open_behind_rekey() {
    TestSession session;
    session.start_to_active();
    CHECK(session.engine->initiate_rekey().ok());
    const auto before_open = session.carrier->sent.size();
    CancellationSource cancellation;
    int completions = 0;
    StatusCode code = StatusCode::Ok;
    session.engine->async_open("echo", ServiceKind::ByteStream, std::nullopt,
        cancellation.token(), [&](auto result) {
            ++completions;
            code = result.status().code();
        });
    CHECK(completions == 0);
    CHECK(session.carrier->sent.size() == before_open);
    CHECK(cancellation.cancel());
    CHECK(completions == 1);
    CHECK(code == StatusCode::Cancelled);
    Buffer acknowledgement = rekey_payload(1U, std::byte{2});
    session.carrier->deliver(frame(ytp1::RecordType::RekeyAck, 0U,
                                   acknowledgement.bytes()));
    CHECK(session.engine->state() == SessionState::Active);
    // The peer never received OPEN, so neither OPEN nor orphaned CLOSE may
    // be emitted when the rekey barrier releases its deferred queue.
    CHECK(session.carrier->sent.size() == before_open);
    session.engine->async_open("echo", ServiceKind::ByteStream, [&](auto result) {
        CHECK(result.ok());
        ++completions;
    });
    CHECK(session.carrier->sent.size() == before_open + 1U);
    session.carrier->deliver(protected_wire(
        0U, 1U, credit_frame(ytp1::RecordType::StreamCredit, 4U, 16U)));
    CHECK(completions == 2);
    CHECK(session.engine->state() == SessionState::Active);
}

void test_destination_policy_and_canonical_outbound_open() {
    TestSession inbound;
    inbound.start_to_active();

    ytp1::Destination incoming_destination;
    incoming_destination.transport = ytp1::TransportProtocol::Tcp;
    incoming_destination.address_kind = ytp1::AddressKind::Dns;
    incoming_destination.dns_name = "example.com";
    incoming_destination.port = 443U;
    ytp1::OpenRequest incoming{
        ytp1::ServiceKind::ByteStream, "echo", incoming_destination};
    auto encoded_incoming = ytp1::EncodeOpen(incoming);
    CHECK(encoded_incoming.ok());
    const std::size_t sent_before = inbound.carrier->sent.size();
    inbound.carrier->deliver(protected_wire(
        0U, 1U,
        frame(ytp1::RecordType::Open, 1U,
              {reinterpret_cast<const std::byte*>(
                   encoded_incoming.value->data()),
               encoded_incoming.value->size()})));
    CHECK(inbound.handler->authorized == 1);
    CHECK(inbound.handler->opened == 0);
    CHECK(inbound.handler->destination.has_value());
    CHECK(inbound.handler->destination->protocol() == NetworkProtocol::Tcp);
    CHECK(inbound.handler->destination->address_kind() ==
          RouteAddressKind::DnsName);
    CHECK(inbound.handler->destination->dns_name() == "example.com");
    CHECK(inbound.handler->destination->port() == 443U);
    CHECK(inbound.carrier->sent.size() == sent_before + 1U);
    CHECK(protected_record_type(inbound.carrier->sent.back()) ==
          ytp1::RecordType::Close);

    TestSession routed(true, true);
    routed.start_to_active();
    auto encoded_routed = ytp1::EncodeOpen(incoming);
    CHECK(encoded_routed.ok());
    const std::size_t routed_before = routed.carrier->sent.size();
    routed.carrier->deliver(protected_wire(
        0U, 1U,
        frame(ytp1::RecordType::Open, 1U,
              {reinterpret_cast<const std::byte*>(
                   encoded_routed.value->data()),
               encoded_routed.value->size()})));
    CHECK(routed.handler->authorized == 1);
    CHECK(routed.handler->opened == 0);
    CHECK(routed.handler->routed == 1);
    CHECK(routed.handler->selected_route == routed.selected_route);
    CHECK(routed.handler->responder);
    CHECK(routed.handler->route_request.has_value());
    CHECK(routed.handler->route_request->stream_id().value() == 1U);
    CHECK(routed.handler->route_request->service_name() == "echo");
    CHECK(routed.handler->route_request->peer_evidence().identity() ==
          "device-1");
    CHECK(routed.handler->route_request->destination().dns_name() ==
          "example.com");
    CHECK(routed.carrier->sent.size() == routed_before + 1U);
    CHECK(protected_record_type(routed.carrier->sent.back()) ==
          ytp1::RecordType::StreamCredit);

    TestSession outbound;
    outbound.start_to_active();
    auto route = require(RouteDestination::ipv4(
        NetworkProtocol::Tcp, {203U, 0U, 113U, 9U}, 8443U));
    const std::size_t outbound_before = outbound.carrier->sent.size();
    int completions = 0;
    outbound.engine->async_open(
        "echo", ServiceKind::ByteStream,
        std::optional<RouteDestination>(std::move(route)),
        [&completions](Result<std::shared_ptr<StreamResponder>> result) {
            CHECK(result.ok());
            ++completions;
        });
    CHECK(completions == 0);
    CHECK(outbound.carrier->sent.size() == outbound_before + 1U);
    outbound.carrier->deliver(protected_wire(
        0U, 1U, credit_frame(ytp1::RecordType::StreamCredit, 2U, 16U)));
    CHECK(completions == 1);
    CHECK(outbound.carrier->sent.size() == outbound_before + 2U);
    const auto outbound_open = protected_open_request(
        outbound.carrier->sent[outbound_before]);
    CHECK(outbound_open.destination.transport ==
          ytp1::TransportProtocol::Tcp);
    CHECK(outbound_open.destination.address_kind ==
          ytp1::AddressKind::Ipv4);
    CHECK(outbound_open.destination.address_length == 4U);
    CHECK(outbound_open.destination.address[0] == 203U);
    CHECK(outbound_open.destination.address[1] == 0U);
    CHECK(outbound_open.destination.address[2] == 113U);
    CHECK(outbound_open.destination.address[3] == 9U);
    CHECK(outbound_open.destination.port == 8443U);
}

void run_test() {
    test_scoped_byte_wipe();
    test_one_use_records_and_cancellation();
    test_write_half_close_preserves_reads();
    test_shutdown_orders_fin_after_queued_writes();
    test_peer_half_close_preserves_writes();
    test_end_of_stream_is_distinct_from_abort_and_session_end();
    test_authenticated_peer_is_available_only_while_active();
    test_termination_overrides_an_earlier_fin();
    test_partial_credit_does_not_reorder_queued_writes();
    test_stop_retains_engine_through_owner_releasing_callbacks();
    test_pending_read_settled_after_allocation_failure();
    test_stop_and_destruction_under_allocation_failure();
    test_start_completion_survives_long_failure_status();
    test_stream_cleanup_under_allocation_failure();
    test_stop_drains_active_queued_and_rekey_deferred_writes();
    test_peer_stream_construction_allocation_failures();
    test_outer_channel_identity_and_exporter_boundary();
    test_transport_instance_provenance();
    test_rekey_resource_limit_contract();
    test_rekey_ack_wire_contract();
    test_rekey_ack_admission_fail_closed();
    test_destination_policy_and_canonical_outbound_open();
    test_open_acceptance_refusal_and_pending_cancellation();
    test_receiver_waits_for_handler_acceptance();
    test_crossed_abort_data_credit_and_terminal_barrier();
    test_graceful_settlement_keeps_crossed_credit_ordered();
    test_unacknowledged_streams_remain_bounded();
    test_cancel_unpublished_open_behind_rekey();
}

}  // namespace
}  // namespace yume::engine

int main() {
    try {
        yume::engine::run_test();
        std::cout << "session_engine_test: PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "session_engine_test: FAIL: " << error.what() << '\n';
        return 1;
    }
}
