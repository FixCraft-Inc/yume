/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <iostream>
#include <memory>
#include <new>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "engine/engine_builder.hpp"
#include "engine/session_engine.hpp"

namespace yume::engine {
namespace {

static_assert(!std::is_copy_constructible_v<Buffer>);
static_assert(!std::is_copy_assignable_v<Buffer>);
static_assert(std::is_nothrow_move_constructible_v<Buffer>);
static_assert(!std::is_copy_constructible_v<CarrierCredit>);
static_assert(std::is_nothrow_move_constructible_v<CarrierCredit>);
static_assert(!std::is_constructible_v<
              AuthorizedRouteRequest,
              StreamId,
              std::string,
              PeerEvidence,
              RouteDestination>);

class TestFailure final : public std::runtime_error {
public:
    explicit TestFailure(std::string message)
        : std::runtime_error(std::move(message)) {}
};

std::exception_ptr callback_test_failure;

[[noreturn]] void fail(std::string_view expression,
                       std::string_view file,
                       int line) {
    throw TestFailure(std::string(file) + ":" + std::to_string(line) +
                      ": check failed: " + std::string(expression));
}

#define CHECK(expression)                                                     \
    do {                                                                      \
        if (!(expression)) {                                                  \
            fail(#expression, __FILE__, __LINE__);                            \
        }                                                                     \
    } while (false)

void check_code(const Status& status, StatusCode expected) {
    if (status.code() != expected) {
        throw TestFailure(
            "unexpected status code " +
            std::to_string(static_cast<unsigned>(status.code())) +
            " (expected " +
            std::to_string(static_cast<unsigned>(expected)) + "): " +
            status.message());
    }
}

template <typename T>
T require_value(Result<T> result) {
    if (!result.ok()) {
        throw TestFailure("unexpected failed result: " +
                          std::string(result.status().message()));
    }
    return std::move(result).take_value();
}

Buffer make_buffer(std::string_view text,
                   std::size_t limit = 64U) {
    const auto* begin = reinterpret_cast<const std::byte*>(text.data());
    return require_value(Buffer::copy_from(
        std::span<const std::byte>(begin, text.size()), limit));
}

std::string buffer_text(const Buffer& buffer) {
    const auto bytes = buffer.bytes();
    return std::string(reinterpret_cast<const char*>(bytes.data()),
                       bytes.size());
}

template <typename Callback, typename... Args>
void invoke_noexcept(Callback& callback, Args&&... args) noexcept {
    if (!callback) {
        return;
    }
    try {
        callback(std::forward<Args>(args)...);
    } catch (const TestFailure&) {
        if (!callback_test_failure) {
            callback_test_failure = std::current_exception();
        }
    } catch (...) {
        // The fake is itself a contract implementation: application callback
        // exceptions cannot unwind into channel state transitions.
    }
}

void rethrow_callback_test_failure() {
    if (!callback_test_failure) {
        return;
    }
    std::exception_ptr failure =
        std::exchange(callback_test_failure, std::exception_ptr{});
    std::rethrow_exception(failure);
}

class InMemoryByteChannel final : public ByteChannel {
public:
    static constexpr std::size_t kMaxIoBytes = 32U;
    static constexpr std::size_t kMaxPendingOperations = 8U;

    ~InMemoryByteChannel() override { close(); }

    ExecutorAffinity executor_affinity() const noexcept override {
        return ExecutorAffinity(0x594d4501U);
    }

    std::size_t max_read_size() const noexcept override {
        return kMaxIoBytes;
    }

    std::size_t max_write_size() const noexcept override {
        return kMaxIoBytes;
    }

    void async_read(std::size_t max_bytes,
                    CancellationToken cancellation,
                    ReadCompletion completion) override {
        if (max_bytes == 0U || max_bytes > kMaxIoBytes) {
            complete_read(std::move(completion), Status(
                StatusCode::InvalidArgument,
                "in-memory read exceeds its declared bound"));
            return;
        }
        if (cancellation.is_cancelled()) {
            complete_read(std::move(completion), cancelled_status());
            return;
        }
        if (closed_) {
            complete_read(std::move(completion), closed_status());
            return;
        }
        if (!inbound_.empty()) {
            Buffer payload = std::move(inbound_.front());
            inbound_.pop_front();
            deliver_payload(max_bytes, std::move(completion),
                            std::move(payload));
            return;
        }
        if (pending_reads_.size() >= kMaxPendingOperations) {
            complete_read(std::move(completion), Status(
                StatusCode::ResourceExhausted,
                "in-memory pending-read capacity exhausted"));
            return;
        }

        const std::uint64_t operation_id = next_operation_id_++;
        PendingRead pending_read{
            operation_id, max_bytes, std::move(completion), {}};
        try {
            pending_reads_.push_back(std::move(pending_read));
        } catch (const std::bad_alloc&) {
            complete_read(std::move(pending_read.completion), Status(
                StatusCode::ResourceExhausted,
                "in-memory pending-read allocation failed"));
            return;
        }

        auto registration = cancellation.register_callback(
            [this, operation_id] {
                settle_pending_read(operation_id, cancelled_status());
            });
        auto pending = find_pending_read(operation_id);
        if (pending == pending_reads_.end()) {
            return;
        }
        if (!registration.ok()) {
            const Status status = registration.status();
            settle_pending_read(operation_id, status);
            return;
        }
        pending->registration = std::move(registration).take_value();
    }

    void async_write(Buffer buffer,
                     CancellationToken cancellation,
                     WriteCompletion completion) override {
        if (buffer.size() > kMaxIoBytes) {
            complete_write(std::move(completion), Status(
                StatusCode::ResourceExhausted,
                "in-memory write exceeds its declared bound"), 0U);
            return;
        }
        if (cancellation.is_cancelled()) {
            complete_write(std::move(completion), cancelled_status(), 0U);
            return;
        }
        if (closed_) {
            complete_write(std::move(completion), closed_status(), 0U);
            return;
        }
        if (write_shutdown_) {
            complete_write(std::move(completion), Status(
                StatusCode::Closed,
                "in-memory write side is shut down"), 0U);
            return;
        }

        const std::size_t accepted = buffer.size();
        if (pending_reads_.empty()) {
            if (inbound_.size() >= kMaxPendingOperations) {
                complete_write(std::move(completion), Status(
                    StatusCode::ResourceExhausted,
                    "in-memory queued-write capacity exhausted"), 0U);
                return;
            }
            try {
                inbound_.push_back(std::move(buffer));
            } catch (const std::bad_alloc&) {
                complete_write(std::move(completion), Status(
                    StatusCode::ResourceExhausted,
                    "in-memory queued-write allocation failed"), 0U);
                return;
            }
        } else {
            PendingRead pending = std::move(pending_reads_.front());
            pending_reads_.pop_front();
            deliver_payload(pending.max_bytes, std::move(pending.completion),
                            std::move(buffer));
        }
        complete_write(std::move(completion), Status::success(), accepted);
    }

    Status shutdown_write() noexcept override {
        write_shutdown_ = true;
        return Status::success();
    }

    void cancel() noexcept override {
        settle_all(cancelled_status());
    }

    void close() noexcept override {
        if (closed_) {
            return;
        }
        closed_ = true;
        inbound_.clear();
        settle_all(closed_status());
    }

private:
    struct PendingRead {
        std::uint64_t operation_id;
        std::size_t max_bytes;
        ReadCompletion completion;
        CancellationRegistration registration;
    };

    using PendingIterator = std::deque<PendingRead>::iterator;

    static Status cancelled_status() {
        return Status(StatusCode::Cancelled,
                      "in-memory operation was cancelled");
    }

    static Status closed_status() {
        return Status(StatusCode::Closed,
                      "in-memory channel is closed");
    }

    PendingIterator find_pending_read(std::uint64_t operation_id) {
        return std::find_if(
            pending_reads_.begin(), pending_reads_.end(),
            [operation_id](const PendingRead& pending) {
                return pending.operation_id == operation_id;
            });
    }

    static void complete_read(ReadCompletion completion,
                              Status status) noexcept {
        Result<Buffer> result(std::move(status));
        invoke_noexcept(completion, std::move(result));
    }

    static void complete_read(ReadCompletion completion,
                              Buffer buffer) noexcept {
        Result<Buffer> result(std::move(buffer));
        invoke_noexcept(completion, std::move(result));
    }

    static void complete_write(WriteCompletion completion,
                               Status status,
                               std::size_t bytes) noexcept {
        invoke_noexcept(completion, std::move(status), bytes);
    }

    void deliver_payload(std::size_t max_bytes,
                         ReadCompletion completion,
                         Buffer payload) noexcept {
        if (payload.size() <= max_bytes) {
            complete_read(std::move(completion), std::move(payload));
            return;
        }

        const auto bytes = payload.bytes();
        auto head = Buffer::copy_from(bytes.first(max_bytes), max_bytes);
        auto tail = Buffer::copy_from(bytes.subspan(max_bytes), kMaxIoBytes);
        if (!head.ok() || !tail.ok()) {
            complete_read(std::move(completion), Status(
                StatusCode::ResourceExhausted,
                "in-memory read split allocation failed"));
            return;
        }
        try {
            inbound_.push_front(std::move(tail).take_value());
        } catch (const std::bad_alloc&) {
            complete_read(std::move(completion), Status(
                StatusCode::ResourceExhausted,
                "in-memory read-tail allocation failed"));
            return;
        }
        complete_read(std::move(completion),
                      std::move(head).take_value());
    }

    void settle_pending_read(std::uint64_t operation_id,
                             Status status) noexcept {
        const auto pending = find_pending_read(operation_id);
        if (pending == pending_reads_.end()) {
            return;
        }
        ReadCompletion completion = std::move(pending->completion);
        pending_reads_.erase(pending);
        complete_read(std::move(completion), std::move(status));
    }

    void settle_all(const Status& status) noexcept {
        while (!pending_reads_.empty()) {
            ReadCompletion completion =
                std::move(pending_reads_.front().completion);
            pending_reads_.pop_front();
            complete_read(std::move(completion), status);
        }
    }

    std::deque<Buffer> inbound_;
    std::deque<PendingRead> pending_reads_;
    std::uint64_t next_operation_id_{1U};
    bool closed_{false};
    bool write_shutdown_{false};
};

ProviderDescriptor make_descriptor(
    std::string provider_id,
    ProviderKind kind,
    std::uint32_t api_version,
    CapabilitySet capabilities) {
    return require_value(ProviderDescriptor::create(
        std::move(provider_id), kind, api_version, capabilities));
}

class FakeByteChannelProvider final : public ByteChannelProvider {
public:
    explicit FakeByteChannelProvider(ProviderDescriptor descriptor)
        : descriptor_(std::move(descriptor)) {}

    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }

    void async_create(EndpointRole,
                      CancellationToken cancellation,
                      Completion completion) override {
        if (cancellation.is_cancelled()) {
            Result<std::unique_ptr<ByteChannel>> result(Status(
                StatusCode::Cancelled, "provider creation cancelled"));
            invoke_noexcept(completion, std::move(result));
            return;
        }
        try {
            std::unique_ptr<ByteChannel> channel =
                std::make_unique<InMemoryByteChannel>();
            Result<std::unique_ptr<ByteChannel>> result(std::move(channel));
            invoke_noexcept(completion, std::move(result));
        } catch (const std::bad_alloc&) {
            Result<std::unique_ptr<ByteChannel>> result(Status(
                StatusCode::ResourceExhausted,
                "provider channel allocation failed"));
            invoke_noexcept(completion, std::move(result));
        }
    }

private:
    ProviderDescriptor descriptor_;
};

class FakeSecureChannelProvider final : public SecureChannelProvider {
public:
    explicit FakeSecureChannelProvider(ProviderDescriptor descriptor)
        : descriptor_(std::move(descriptor)) {}

    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }

    void async_wrap(std::unique_ptr<ByteChannel>,
                    EndpointRole,
                    CancellationToken,
                    Completion completion) override {
        Result<std::unique_ptr<SecureChannel>> result(Status(
            StatusCode::Internal,
            "secure-channel construction is outside this graph test"));
        invoke_noexcept(completion, std::move(result));
    }

private:
    ProviderDescriptor descriptor_;
};

class FakeCarrierProvider final : public CarrierProvider {
public:
    explicit FakeCarrierProvider(ProviderDescriptor descriptor)
        : descriptor_(std::move(descriptor)) {}

    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }

    void async_create(std::unique_ptr<SecureChannel>,
                      EndpointRole,
                      CancellationToken,
                      Completion completion) override {
        Result<std::unique_ptr<Carrier>> result(Status(
            StatusCode::Internal,
            "carrier construction is outside this graph test"));
        invoke_noexcept(completion, std::move(result));
    }

private:
    ProviderDescriptor descriptor_;
};

class FakeFrontDoorProvider final : public FrontDoorProvider {
public:
    explicit FakeFrontDoorProvider(ProviderDescriptor descriptor)
        : descriptor_(std::move(descriptor)) {}

    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }

    void async_create(EndpointRole,
                      CancellationToken,
                      Completion completion) override {
        Result<std::unique_ptr<FrontDoor>> result(Status(
            StatusCode::Internal,
            "front-door construction is outside this graph test"));
        invoke_noexcept(completion, std::move(result));
    }

private:
    ProviderDescriptor descriptor_;
};

class FakeSessionSecurityProviderFactory final
    : public SessionSecurityProviderFactory {
public:
    explicit FakeSessionSecurityProviderFactory(
        ProviderDescriptor descriptor)
        : descriptor_(std::move(descriptor)) {}

    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }

    Result<std::unique_ptr<SessionSecurityProvider>> create(
        EndpointRole) override {
        return Result<std::unique_ptr<SessionSecurityProvider>>(Status(
            StatusCode::Internal,
            "session-security construction is outside this graph test"));
    }

private:
    ProviderDescriptor descriptor_;
};

class FakeRouteProvider final : public RouteProvider {
public:
    explicit FakeRouteProvider(ProviderDescriptor descriptor)
        : descriptor_(std::move(descriptor)) {}

    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }

    void async_open(const AuthorizedRouteRequest&,
                    CancellationToken,
                    Completion completion) override {
        Result<RouteConnection> result(Status(
            StatusCode::Internal,
            "route creation is outside this graph test"));
        invoke_noexcept(completion, std::move(result));
    }

    void cancel() noexcept override {}

private:
    ProviderDescriptor descriptor_;
};

class FakeStreamHandler final : public StreamHandler {
public:
    FakeStreamHandler(ProviderDescriptor descriptor, ServiceKind service_kind)
        : descriptor_(std::move(descriptor)), service_kind_(service_kind) {}

    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }

    ServiceKind service_kind() const noexcept override {
        return service_kind_;
    }

    Status authorize(const StreamOpenContext&) override {
        return Status::success();
    }

    void on_open(StreamOpenContext,
                 std::shared_ptr<StreamResponder>) override {}

private:
    ProviderDescriptor descriptor_;
    ServiceKind service_kind_;
};

ProviderRequirement make_requirement(
    ProviderKind kind,
    std::string provider_id,
    CapabilitySet capabilities,
    std::uint32_t api_version = 1U) {
    return require_value(ProviderRequirement::create(
        kind, std::move(provider_id), api_version, capabilities));
}

TransportSuiteDescriptor make_suite(bool include_packet_echo = false) {
    std::vector<ProviderRequirement> providers;
    providers.push_back(make_requirement(
        ProviderKind::ByteChannel, "memory.bytes",
        mandatory_capabilities(ProviderKind::ByteChannel)));
    providers.push_back(make_requirement(
        ProviderKind::SecureChannel, "test.tls13",
        mandatory_capabilities(ProviderKind::SecureChannel)
            .with(Capability::Tls13)));
    providers.push_back(make_requirement(
        ProviderKind::FrontDoor, "test.front-door",
        mandatory_capabilities(ProviderKind::FrontDoor)));
    providers.push_back(make_requirement(
        ProviderKind::Carrier, "test.h2",
        mandatory_capabilities(ProviderKind::Carrier)));
    providers.push_back(make_requirement(
        ProviderKind::SessionSecurity, "test.ytp1-security",
        mandatory_capabilities(ProviderKind::SessionSecurity)));
    providers.push_back(make_requirement(
        ProviderKind::RouteProvider, "test.direct",
        mandatory_capabilities(ProviderKind::RouteProvider)
            .with(Capability::DirectTcp)));

    std::vector<ServiceRequirement> services;
    services.push_back(require_value(ServiceRequirement::create(
        "echo", ServiceKind::ByteStream, "test.echo", 1U, 8U,
        mandatory_capabilities(ProviderKind::StreamHandler))));
    if (include_packet_echo) {
        services.push_back(require_value(ServiceRequirement::create(
            "echo", ServiceKind::PacketChannel, "test.echo.packet", 1U, 4U,
            mandatory_capabilities(ProviderKind::StreamHandler)
                .with(Capability::PacketChannels))));
    }
    return require_value(TransportSuiteDescriptor::create(
        "ytp1.tls13.h2", "YTP/1", std::move(providers),
        std::move(services)));
}

struct ProviderSet {
    std::shared_ptr<FakeByteChannelProvider> bytes;
    std::shared_ptr<FakeSecureChannelProvider> secure;
    std::shared_ptr<FakeFrontDoorProvider> front_door;
    std::shared_ptr<FakeCarrierProvider> carrier;
    std::shared_ptr<FakeSessionSecurityProviderFactory> session_security;
    std::shared_ptr<FakeRouteProvider> route;
    std::shared_ptr<FakeStreamHandler> handler;
};

ProviderSet make_provider_set() {
    return ProviderSet{
        std::make_shared<FakeByteChannelProvider>(make_descriptor(
            "memory.bytes", ProviderKind::ByteChannel, 1U,
            mandatory_capabilities(ProviderKind::ByteChannel))),
        std::make_shared<FakeSecureChannelProvider>(make_descriptor(
            "test.tls13", ProviderKind::SecureChannel, 1U,
            mandatory_capabilities(ProviderKind::SecureChannel)
                .with(Capability::Tls13))),
        std::make_shared<FakeFrontDoorProvider>(make_descriptor(
            "test.front-door", ProviderKind::FrontDoor, 1U,
            mandatory_capabilities(ProviderKind::FrontDoor))),
        std::make_shared<FakeCarrierProvider>(make_descriptor(
            "test.h2", ProviderKind::Carrier, 1U,
            mandatory_capabilities(ProviderKind::Carrier))),
        std::make_shared<FakeSessionSecurityProviderFactory>(make_descriptor(
            "test.ytp1-security", ProviderKind::SessionSecurity, 1U,
            mandatory_capabilities(ProviderKind::SessionSecurity))),
        std::make_shared<FakeRouteProvider>(make_descriptor(
            "test.direct", ProviderKind::RouteProvider, 1U,
            mandatory_capabilities(ProviderKind::RouteProvider)
                .with(Capability::DirectTcp))),
        std::make_shared<FakeStreamHandler>(make_descriptor(
            "test.echo", ProviderKind::StreamHandler, 1U,
            mandatory_capabilities(ProviderKind::StreamHandler)),
            ServiceKind::ByteStream),
    };
}

void register_composition(EngineBuilder& builder,
                          const ProviderSet& providers) {
    CHECK(builder.register_byte_channel_provider(providers.bytes).ok());
    CHECK(builder.register_secure_channel_provider(providers.secure).ok());
    CHECK(builder.register_front_door_provider(providers.front_door).ok());
    CHECK(builder.register_carrier_provider(providers.carrier).ok());
    CHECK(builder.register_session_security_provider_factory(
              providers.session_security).ok());
    CHECK(builder.register_route_provider(providers.route).ok());
}

void test_buffer_bounds() {
    check_code(Buffer::allocate(0U, 0U).status(),
               StatusCode::InvalidArgument);
    check_code(Buffer::allocate(0U, kAbsoluteMaxBufferBytes + 1U).status(),
               StatusCode::InvalidArgument);
    check_code(Buffer::allocate(5U, 4U).status(),
               StatusCode::ResourceExhausted);

    Buffer buffer = require_value(Buffer::allocate(2U, 4U));
    const std::array<std::byte, 2> suffix{
        std::byte{0x31}, std::byte{0x32}};
    CHECK(buffer.append(suffix).ok());
    CHECK(buffer.size() == 4U);
    const std::array<std::byte, 1> overflow{std::byte{0x33}};
    check_code(buffer.append(overflow), StatusCode::ResourceExhausted);
    CHECK(buffer.size() == 4U);
    check_code(buffer.resize(5U), StatusCode::ResourceExhausted);
    CHECK(buffer.size() == 4U);

    Buffer moved = std::move(buffer);
    CHECK(moved.max_size() == 4U);
    CHECK(buffer.max_size() == 0U);
    check_code(buffer.append(overflow), StatusCode::ResourceExhausted);
}

void test_stream_ids() {
    const StreamId control = StreamId::control();
    CHECK(control.is_control());
    CHECK(!control.owner().has_value());

    const StreamId client = require_value(
        StreamId::application(1U, EndpointRole::Client));
    const StreamId server = require_value(
        StreamId::application(2U, EndpointRole::Server));
    CHECK(client.owned_by(EndpointRole::Client));
    CHECK(server.owned_by(EndpointRole::Server));
    CHECK(require_value(StreamId::application(
              StreamId::kMaxApplicationValue, EndpointRole::Client))
              .value() == StreamId::kMaxApplicationValue);

    check_code(StreamId::application(0U, EndpointRole::Client).status(),
               StatusCode::InvalidArgument);
    check_code(StreamId::application(2U, EndpointRole::Client).status(),
               StatusCode::InvalidArgument);
    check_code(StreamId::application(1U, EndpointRole::Server).status(),
               StatusCode::InvalidArgument);
    check_code(StreamId::application(
                   StreamId::kMaxApplicationValue + 1U,
                   EndpointRole::Server).status(),
               StatusCode::InvalidArgument);
    CHECK(StreamId::peer_application(2U, EndpointRole::Client).ok());
    check_code(StreamId::peer_application(
                   1U, EndpointRole::Client).status(),
               StatusCode::InvalidArgument);
}

void test_cancellation() {
    CancellationSource source;
    const CancellationToken token = source.token();
    int normal_calls = 0;
    int reentrant_calls = 0;
    bool reentrant_cancel_result = true;
    int throwing_calls = 0;
    auto normal = token.register_callback([&] { ++normal_calls; });
    auto throwing = token.register_callback([&] {
        ++throwing_calls;
        throw std::runtime_error("contained cancellation callback");
    });
    auto reentrant = token.register_callback([&] {
        ++reentrant_calls;
        reentrant_cancel_result = source.cancel();
    });
    CHECK(normal.ok() && throwing.ok() && reentrant.ok());
    CHECK(source.cancel());
    CHECK(!source.cancel());
    CHECK(normal_calls == 1);
    CHECK(throwing_calls == 1);
    CHECK(reentrant_calls == 1);
    CHECK(!reentrant_cancel_result);
    CHECK(token.is_cancelled());

    int immediate_calls = 0;
    auto immediate = token.register_callback([&] { ++immediate_calls; });
    CHECK(immediate.ok());
    CHECK(!immediate.value().active());
    CHECK(immediate_calls == 1);

    int unregistered_calls = 0;
    CancellationSource unregister_source;
    {
        auto registration = unregister_source.token().register_callback(
            [&] { ++unregistered_calls; });
        CHECK(registration.ok());
    }
    CHECK(unregister_source.cancel());
    CHECK(unregistered_calls == 0);

    int destruction_calls = 0;
    CancellationRegistration retained_registration;
    CancellationToken retained_token;
    {
        CancellationSource destruction_source;
        retained_token = destruction_source.token();
        auto registration = retained_token.register_callback(
            [&] { ++destruction_calls; });
        CHECK(registration.ok());
        retained_registration = std::move(registration).take_value();
    }
    CHECK(destruction_calls == 1);
    CHECK(retained_token.is_cancelled());
}

void test_carrier_credit() {
    std::size_t released_bytes = 0U;
    int release_calls = 0;
    {
        CarrierCredit first(17U, [&](std::size_t bytes) {
            ++release_calls;
            released_bytes += bytes;
        });
        CarrierCredit second = std::move(first);
        CHECK(!first);
        CHECK(second.size() == 17U);
        second.release_now();
        second.release_now();
    }
    CHECK(release_calls == 1);
    CHECK(released_bytes == 17U);

    bool survived_throw = false;
    {
        CarrierCredit throwing(1U, [](std::size_t) {
            throw std::runtime_error("contained credit callback");
        });
        throwing.release_now();
        survived_throw = true;
    }
    CHECK(survived_throw);
}

void test_in_memory_channel() {
    InMemoryByteChannel channel;
    CHECK(channel.executor_affinity().valid());
    CHECK(channel.executor_affinity() == channel.executor_affinity());
    CHECK(channel.max_read_size() == InMemoryByteChannel::kMaxIoBytes);

    int oversized_completions = 0;
    channel.async_write(
        require_value(Buffer::allocate(33U, 64U)), {},
        [&](Status status, std::size_t bytes) {
            ++oversized_completions;
            check_code(status, StatusCode::ResourceExhausted);
            CHECK(bytes == 0U);
        });
    CHECK(oversized_completions == 1);

    std::vector<std::string> received;
    channel.async_read(32U, {}, [&](Result<Buffer> result) {
        CHECK(result.ok());
        received.push_back(buffer_text(result.value()));
    });
    channel.async_read(32U, {}, [&](Result<Buffer> result) {
        CHECK(result.ok());
        received.push_back(buffer_text(result.value()));
    });
    channel.async_write(make_buffer("first"), {},
                        [](Status status, std::size_t bytes) {
                            CHECK(status.ok());
                            CHECK(bytes == 5U);
                        });
    channel.async_write(make_buffer("second"), {},
                        [](Status status, std::size_t bytes) {
                            CHECK(status.ok());
                            CHECK(bytes == 6U);
                        });
    CHECK((received == std::vector<std::string>{"first", "second"}));

    std::vector<std::string> split;
    channel.async_write(make_buffer("abcdef"), {},
                        [](Status status, std::size_t bytes) {
                            CHECK(status.ok());
                            CHECK(bytes == 6U);
                        });
    channel.async_read(2U, {}, [&](Result<Buffer> result) {
        CHECK(result.ok());
        split.push_back(buffer_text(result.value()));
    });
    channel.async_read(8U, {}, [&](Result<Buffer> result) {
        CHECK(result.ok());
        split.push_back(buffer_text(result.value()));
    });
    CHECK((split == std::vector<std::string>{"ab", "cdef"}));

    CancellationSource operation_source;
    int cancellation_completions = 0;
    channel.async_read(
        8U, operation_source.token(), [&](Result<Buffer> result) {
            ++cancellation_completions;
            CHECK(!result.ok());
            check_code(result.status(), StatusCode::Cancelled);
        });
    CHECK(operation_source.cancel());
    channel.cancel();
    CHECK(cancellation_completions == 1);

    int channel_cancel_completions = 0;
    channel.async_read(8U, {}, [&](Result<Buffer> result) {
        ++channel_cancel_completions;
        check_code(result.status(), StatusCode::Cancelled);
    });
    channel.cancel();
    CHECK(channel_cancel_completions == 1);

    int nested_write_completions = 0;
    channel.async_read(8U, {}, [&](Result<Buffer> result) {
        CHECK(result.ok());
        channel.async_write(
            make_buffer("nested"), {},
            [&](Status status, std::size_t bytes) {
                ++nested_write_completions;
                CHECK(status.ok());
                CHECK(bytes == 6U);
            });
    });
    channel.async_write(make_buffer("outer"), {},
                        [](Status status, std::size_t) {
                            CHECK(status.ok());
                        });
    CHECK(nested_write_completions == 1);
    channel.async_read(8U, {}, [](Result<Buffer> result) {
        CHECK(result.ok());
        CHECK(buffer_text(result.value()) == "nested");
    });

    int write_after_throw = 0;
    channel.async_read(8U, {}, [](Result<Buffer>) {
        throw std::runtime_error("contained read callback");
    });
    channel.async_write(make_buffer("throw"), {},
                        [&](Status status, std::size_t bytes) {
                            ++write_after_throw;
                            CHECK(status.ok());
                            CHECK(bytes == 5U);
                        });
    CHECK(write_after_throw == 1);

    channel.async_write(make_buffer("before-fin"), {},
                        [](Status status, std::size_t bytes) {
                            CHECK(status.ok());
                            CHECK(bytes == 10U);
                        });
    CHECK(channel.shutdown_write().ok());
    CHECK(channel.shutdown_write().ok());
    channel.async_read(16U, {}, [](Result<Buffer> result) {
        CHECK(result.ok());
        CHECK(buffer_text(result.value()) == "before-fin");
    });
    channel.async_write(make_buffer("after-fin"), {},
                        [](Status status, std::size_t bytes) {
                            check_code(status, StatusCode::Closed);
                            CHECK(bytes == 0U);
                        });

    int close_completions = 0;
    channel.async_read(8U, {}, [&](Result<Buffer> result) {
        ++close_completions;
        check_code(result.status(), StatusCode::Closed);
    });
    channel.close();
    channel.close();
    CHECK(close_completions == 1);
    channel.async_write(make_buffer("closed"), {},
                        [](Status status, std::size_t bytes) {
                            check_code(status, StatusCode::Closed);
                            CHECK(bytes == 0U);
                        });
}

void test_validated_boundaries() {
    CHECK(valid_service_name("echo"));
    CHECK(valid_service_name("org.example.echo-v1"));
    CHECK(valid_service_name("packet_service"));
    CHECK(valid_service_name(std::string(kMaxServiceNameBytes, 'a')));
    CHECK(!valid_service_name("Uppercase"));
    CHECK(!valid_service_name("bad/name"));
    CHECK(!valid_service_name(".leading"));
    CHECK(!valid_service_name("trailing."));
    CHECK(!valid_service_name("bad.-segment"));
    CHECK(!valid_service_name("bad_segment-"));
    CHECK(!valid_service_name("\xc3\xa9"));
    CHECK(!valid_service_name(std::string(kMaxServiceNameBytes + 1U, 'a')));

    const auto anonymous_client =
        SecureChannelPeerEvidence::anonymous_client();
    CHECK(anonymous_client.peer_role() == EndpointRole::Client);
    CHECK(!anonymous_client.authenticated());
    CHECK(anonymous_client.identity().empty());

    auto bad_channel_evidence = SecureChannelPeerEvidence::authenticated(
        EndpointRole::Server, "", "tls13", {std::byte{0x01}});
    check_code(bad_channel_evidence.status(), StatusCode::InvalidArgument);
    auto channel_evidence = SecureChannelPeerEvidence::authenticated(
        EndpointRole::Server, "server.example", "tls13",
        {std::byte{0x01}, std::byte{0x02}});
    CHECK(channel_evidence.ok());
    CHECK(channel_evidence.value().authenticated());

    auto bad_evidence = PeerEvidence::create(
        EndpointRole::Server, "", "tls13", {std::byte{0x01}});
    check_code(bad_evidence.status(), StatusCode::InvalidArgument);
    auto evidence = PeerEvidence::create(
        EndpointRole::Server, "server.example", "tls13",
        {std::byte{0x01}, std::byte{0x02}});
    CHECK(evidence.ok());

    check_code(RouteDestination::dns_name(
                   NetworkProtocol::Tcp, "example.com", 0U).status(),
               StatusCode::InvalidArgument);
    CHECK(RouteDestination::dns_name(
              NetworkProtocol::Tcp, "example.com", 443U).ok());
    check_code(RouteDestination::dns_name(
                   static_cast<NetworkProtocol>(0xffU),
                   "example.com", 443U).status(),
               StatusCode::InvalidArgument);
    check_code(RouteDestination::dns_name(
                   NetworkProtocol::Tcp, "Example.com", 443U).status(),
               StatusCode::InvalidArgument);
    const auto ipv4 = RouteDestination::ipv4(
        NetworkProtocol::Tcp, {127U, 0U, 0U, 1U}, 443U);
    CHECK(ipv4.ok());
    CHECK(ipv4.value().address_kind() == RouteAddressKind::Ipv4);
    CHECK(ipv4.value().address_bytes().size() == 4U);
    CHECK(ipv4.value().dns_name().empty());

    auto zero = StreamOpenContext::create(
        StreamId::control(), "echo", ServiceKind::ByteStream,
        std::move(evidence).take_value());
    check_code(zero.status(), StatusCode::InvalidArgument);
}

void test_engine_builder() {
    EngineBuilder missing(EndpointRole::Client, make_suite());
    auto missing_result = missing.build();
    check_code(missing_result.status(), StatusCode::NotFound);
    CHECK(!missing.frozen());

    auto wrong_kind = std::make_shared<FakeByteChannelProvider>(
        make_descriptor(
            "wrong.kind", ProviderKind::SecureChannel, 1U,
            mandatory_capabilities(ProviderKind::SecureChannel)));
    check_code(missing.register_byte_channel_provider(wrong_kind),
               StatusCode::ProviderMismatch);

    auto wrong_id = std::make_shared<FakeByteChannelProvider>(
        make_descriptor(
            "other.bytes", ProviderKind::ByteChannel, 1U,
            mandatory_capabilities(ProviderKind::ByteChannel)));
    CHECK(missing.register_byte_channel_provider(wrong_id).ok());
    auto wrong_id_result = missing.build();
    check_code(wrong_id_result.status(), StatusCode::ProviderMismatch);
    CHECK(!missing.frozen());

    EngineBuilder wrong_version(EndpointRole::Client, make_suite());
    auto versioned = std::make_shared<FakeByteChannelProvider>(
        make_descriptor(
            "memory.bytes", ProviderKind::ByteChannel, 2U,
            mandatory_capabilities(ProviderKind::ByteChannel)));
    CHECK(wrong_version.register_byte_channel_provider(versioned).ok());
    check_code(wrong_version.build().status(), StatusCode::ProviderMismatch);
    CHECK(!wrong_version.frozen());

    EngineBuilder missing_capability(EndpointRole::Client, make_suite());
    auto incomplete = std::make_shared<FakeByteChannelProvider>(
        make_descriptor("memory.bytes", ProviderKind::ByteChannel, 1U, {}));
    CHECK(missing_capability.register_byte_channel_provider(incomplete).ok());
    check_code(missing_capability.build().status(),
               StatusCode::FailedPrecondition);
    CHECK(!missing_capability.frozen());

    EngineBuilder no_handler(EndpointRole::Client, make_suite());
    ProviderSet providers = make_provider_set();
    register_composition(no_handler, providers);
    check_code(no_handler.build().status(), StatusCode::NotFound);
    CHECK(!no_handler.frozen());

    auto mismatched_handler = std::make_shared<FakeStreamHandler>(
        make_descriptor(
            "other.echo", ProviderKind::StreamHandler, 1U,
            mandatory_capabilities(ProviderKind::StreamHandler)),
        ServiceKind::ByteStream);
    CHECK(no_handler.register_stream_handler(
              "echo", mismatched_handler).ok());
    check_code(no_handler.build().status(), StatusCode::ProviderMismatch);
    CHECK(!no_handler.frozen());

    EngineBuilder wrong_service_kind(EndpointRole::Client, make_suite());
    ProviderSet kind_providers = make_provider_set();
    register_composition(wrong_service_kind, kind_providers);
    auto packet_handler = std::make_shared<FakeStreamHandler>(
        make_descriptor(
            "test.echo", ProviderKind::StreamHandler, 1U,
            mandatory_capabilities(ProviderKind::StreamHandler)
                .with(Capability::PacketChannels)),
        ServiceKind::PacketChannel);
    CHECK(wrong_service_kind.register_stream_handler(
              "echo", packet_handler).ok());
    check_code(wrong_service_kind.build().status(),
               StatusCode::ProviderMismatch);

    EngineBuilder success(EndpointRole::Server, make_suite());
    ProviderSet selected = make_provider_set();
    register_composition(success, selected);
    CHECK(success.register_stream_handler("echo", selected.handler).ok());
    auto graph_result = success.build();
    CHECK(graph_result.ok());
    const std::shared_ptr<const EngineGraph> graph =
        std::move(graph_result).take_value();
    CHECK(success.frozen());
    CHECK(graph->local_role() == EndpointRole::Server);
    CHECK(graph->suite().wire_protocol() == "YTP/1");
    CHECK(graph->byte_channel_provider() == selected.bytes);
    CHECK(graph->secure_channel_provider() == selected.secure);
    CHECK(graph->front_door_provider() == selected.front_door);
    CHECK(graph->carrier_provider() == selected.carrier);
    CHECK(graph->session_security_provider_factory() ==
          selected.session_security);
    CHECK(graph->route_provider() == selected.route);
    CHECK(graph->stream_handler("echo", ServiceKind::ByteStream) ==
          selected.handler);
    CHECK(!graph->stream_handler("echo", ServiceKind::PacketChannel));
    CHECK(!graph->stream_handler("unknown", ServiceKind::ByteStream));

    check_code(success.register_stream_handler(
                   "late", selected.handler),
               StatusCode::FailedPrecondition);
    check_code(success.build().status(), StatusCode::FailedPrecondition);

    EngineBuilder dual_kind(EndpointRole::Server, make_suite(true));
    ProviderSet dual_providers = make_provider_set();
    register_composition(dual_kind, dual_providers);
    auto packet_echo = std::make_shared<FakeStreamHandler>(
        make_descriptor(
            "test.echo.packet", ProviderKind::StreamHandler, 1U,
            mandatory_capabilities(ProviderKind::StreamHandler)
                .with(Capability::PacketChannels)),
        ServiceKind::PacketChannel);
    CHECK(dual_kind.register_stream_handler(
              "echo", dual_providers.handler).ok());
    CHECK(dual_kind.register_stream_handler("echo", packet_echo).ok());
    auto dual_graph_result = dual_kind.build();
    CHECK(dual_graph_result.ok());
    const auto dual_graph = std::move(dual_graph_result).take_value();
    CHECK(dual_graph->stream_handler("echo", ServiceKind::ByteStream) ==
          dual_providers.handler);
    CHECK(dual_graph->stream_handler("echo", ServiceKind::PacketChannel) ==
          packet_echo);

    EngineBuilder isolated(EndpointRole::Server, make_suite());
    check_code(isolated.build().status(), StatusCode::NotFound);
    CHECK(!isolated.frozen());
}

}  // namespace
}  // namespace yume::engine

int main() {
    using namespace yume::engine;
    try {
        test_buffer_bounds();
        rethrow_callback_test_failure();
        test_stream_ids();
        rethrow_callback_test_failure();
        test_cancellation();
        rethrow_callback_test_failure();
        test_carrier_credit();
        rethrow_callback_test_failure();
        test_in_memory_channel();
        rethrow_callback_test_failure();
        test_validated_boundaries();
        rethrow_callback_test_failure();
        test_engine_builder();
        rethrow_callback_test_failure();
    } catch (const std::exception& error) {
        std::cerr << "engine contract test failed: " << error.what() << '\n';
        return 1;
    }
    std::cout << "engine in-memory contract test passed\n";
    return 0;
}
