/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#define YUME_TEST_ALIGNED_ALLOCATIONS 1
#include "test_support/allocation_failure.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <new>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
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

#include "providers/h2_duplex_carrier.hpp"
#include "providers/ytp1_h2_admission.hpp"

namespace test_allocation_failure {

// One-shot injection targets a selected actor turn. Sustained injection covers
// every thread and both allocation routes used by Boost.Asio.
thread_local std::ptrdiff_t remaining = -1;
std::atomic<bool> sustained{false};

class Scope final {
public:
    explicit Scope(std::ptrdiff_t count) noexcept { remaining = count; }
    ~Scope() { remaining = -1; }
};

class SustainedScope final {
public:
    explicit SustainedScope(bool enabled = true) noexcept {
        sustained.store(enabled, std::memory_order_release);
    }
    ~SustainedScope() { sustained.store(false, std::memory_order_release); }
};

bool consume() noexcept {
    if (sustained.load(std::memory_order_acquire)) return true;
    if (remaining < 0) {
        return false;
    }
    if (remaining == 0) {
        remaining = -1;
        return true;
    }
    --remaining;
    return false;
}

}  // namespace test_allocation_failure

namespace {
void check_test_allocation(std::size_t) {
    if (test_allocation_failure::consume()) throw std::bad_alloc();
}
}


namespace yume::providers {
namespace {

using engine::Buffer;
using engine::CancellationRegistration;
using engine::CancellationSource;
using engine::CancellationToken;
using engine::Carrier;
using engine::EndpointRole;
using engine::ExecutorAffinity;
using engine::ProviderDescriptor;
using engine::ProviderKind;
using engine::ReceivedRecord;
using engine::Result;
using engine::SecureChannel;
using engine::SecureChannelPeerEvidence;
using engine::Status;
using engine::StatusCode;

constexpr std::array<std::byte, kYtp1H2AdmissionKeyBytes> kTestAdmissionKey{
    std::byte{0x9a}, std::byte{0x42}, std::byte{0xe1}};

class TestFailure final : public std::runtime_error {
public:
    explicit TestFailure(std::string message)
        : std::runtime_error(std::move(message)) {}
};

#define CHECK(expression)                                                     \
    do {                                                                      \
        if (!(expression)) {                                                  \
            throw TestFailure(std::string(__FILE__) + ":" +                 \
                              std::to_string(__LINE__) +                      \
                              ": check failed: " #expression);               \
        }                                                                     \
    } while (false)

template <typename T>
T require(Result<T> result) {
    if (!result.ok()) {
        throw TestFailure("unexpected failure: " + result.status().message());
    }
    return std::move(result).take_value();
}

Buffer make_buffer(std::span<const std::uint8_t> bytes,
                   std::size_t limit = 2U * 1024U * 1024U) {
    return require(Buffer::copy_from(std::as_bytes(bytes), limit));
}

Buffer make_buffer(std::string_view text) {
    return make_buffer(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(text.data()), text.size()));
}

std::string buffer_text(const Buffer& buffer) {
    return std::string(
        reinterpret_cast<const char*>(buffer.bytes().data()), buffer.size());
}

ProviderDescriptor make_secure_descriptor(bool tls13 = true) {
    auto capabilities = engine::mandatory_capabilities(ProviderKind::SecureChannel);
    if (tls13) capabilities = capabilities.with(engine::Capability::Tls13);
    return require(ProviderDescriptor::create(
        "test.tls13", ProviderKind::SecureChannel, 1U, capabilities));
}

class TestExecutor final {
public:
    void post(std::function<void()> task) {
        if (!task) {
            throw TestFailure("empty executor task");
        }
        if (reject_) {
            throw TestFailure("executor rejected task");
        }
        tasks_.push_back(std::move(task));
    }

    H2Dispatch dispatch() {
        return {
            [this](std::function<void()> task) { post(std::move(task)); },
            [this](ControlTask& task, std::shared_ptr<void> owner) noexcept {
                controls_.push(task, std::move(owner));
            }};
    }

    void run() {
        std::size_t turns = 0U;
        while (!tasks_.empty() || !controls_.empty()) {
            running_ = true;
            if (controls_.run_one()) { running_ = false; continue; }
            if (++turns > 1'000'000U) {
                throw TestFailure("executor did not quiesce");
            }
            std::function<void()> task = std::move(tasks_.front());
            tasks_.pop_front();
            running_ = true;
            task();
            running_ = false;
        }
    }

    bool running() const noexcept { return running_; }
    bool empty() const noexcept { return tasks_.empty() && controls_.empty(); }
    void reject_new_tasks() noexcept { reject_ = true; }
    void accept_new_tasks() noexcept { reject_ = false; }

private:
    ControlTaskQueue controls_;
    std::deque<std::function<void()>> tasks_;
    bool running_{false};
    bool reject_{false};
};

struct TestPipe final : public std::enable_shared_from_this<TestPipe> {
    struct PendingRead {
        std::size_t max_bytes{0U};
        SecureChannel::ReadCompletion completion;
        CancellationRegistration cancellation;
    };

    struct HeldWrite {
        SecureChannel::WriteCompletion completion;
        std::size_t bytes;
    };
    struct Endpoint {
        std::optional<HeldWrite> held_write;
        bool hold_writes{false};
        std::deque<std::vector<std::byte>> inbound;
        std::optional<PendingRead> pending;
        bool closed{false};
        bool write_shutdown{false};
    };

    explicit TestPipe(TestExecutor& executor) : executor(executor) {}

    void fulfill(std::size_t side) {
        Endpoint& endpoint = endpoints[side];
        if (!endpoint.pending.has_value()) {
            return;
        }
        if (endpoint.inbound.empty()) {
            if (!endpoint.closed) {
                return;
            }
            auto completion = std::move(endpoint.pending->completion);
            endpoint.pending.reset();
            completion(Result<Buffer>(Status(
                StatusCode::Closed, "test secure channel is closed")));
            return;
        }

        const std::size_t max_bytes = endpoint.pending->max_bytes;
        auto completion = std::move(endpoint.pending->completion);
        endpoint.pending.reset();
        std::vector<std::byte> bytes = std::move(endpoint.inbound.front());
        endpoint.inbound.pop_front();
        if (bytes.size() > max_bytes) {
            std::vector<std::byte> tail(
                bytes.begin() + static_cast<std::ptrdiff_t>(max_bytes),
                bytes.end());
            bytes.resize(max_bytes);
            endpoint.inbound.push_front(std::move(tail));
        }
        completion(Result<Buffer>(require(Buffer::copy_from(
            bytes, std::max<std::size_t>(1U, bytes.size())))));
    }

    TestExecutor& executor;
    std::array<Endpoint, 2> endpoints;
    std::size_t fragment_bytes{7U};
    std::array<bool, 2> partial_next_write{false, false};
    std::array<unsigned int, 2> destroyed{};
    std::size_t callback_count{0U};
    std::size_t write_calls{0U};
    std::size_t exporter_calls{0U};
    bool exporter_fails{false};
    bool exporter_wrong_length{false};
    bool tls13{true};
    bool server_authenticated{true};
    std::string server_identity{"cover.example"};
    std::function<void()> after_export;
};

class FakeSecureChannel final : public SecureChannel {
public:
    FakeSecureChannel(std::shared_ptr<TestPipe> pipe, std::size_t side)
        : pipe_(std::move(pipe)), side_(side),
          descriptor_(make_secure_descriptor(pipe_->tls13)),
          peer_(make_peer(side, pipe_->server_identity,
                          pipe_->server_authenticated)) {}
    ~FakeSecureChannel() noexcept override { close(); ++pipe_->destroyed[side_]; }

    const ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }
    ExecutorAffinity executor_affinity() const noexcept override {
        return ExecutorAffinity(77U);
    }
    std::size_t max_read_size() const noexcept override { return 64U * 1024U; }
    std::size_t max_write_size() const noexcept override { return 64U * 1024U; }

    void async_read(std::size_t max_bytes,
                    CancellationToken cancellation,
                    ReadCompletion completion) override {
        CHECK(pipe_->executor.running());
        auto& endpoint = pipe_->endpoints[side_];
        if (endpoint.pending.has_value() || max_bytes == 0U ||
            max_bytes > max_read_size()) {
            completion(Result<Buffer>(Status(
                StatusCode::InvalidArgument, "invalid test secure read")));
            return;
        }
        if (cancellation.is_cancelled()) {
            completion(Result<Buffer>(Status(
                StatusCode::Cancelled, "test secure read cancelled")));
            return;
        }
        endpoint.pending.emplace(
            TestPipe::PendingRead{max_bytes, std::move(completion), {}});
        const std::weak_ptr<TestPipe> weak = pipe_;
        auto registration = cancellation.register_callback([weak, side = side_] {
            if (auto pipe = weak.lock()) {
                pipe->executor.post([weak, side] {
                    if (auto current = weak.lock()) {
                        auto& pending = current->endpoints[side].pending;
                        if (!pending.has_value()) {
                            return;
                        }
                        auto callback = std::move(pending->completion);
                        pending.reset();
                        callback(Result<Buffer>(Status(
                            StatusCode::Cancelled,
                            "test secure read cancelled")));
                    }
                });
            }
        });
        if (!registration.ok()) {
            auto failed = std::move(endpoint.pending->completion);
            endpoint.pending.reset();
            failed(Result<Buffer>(registration.status()));
            return;
        }
        endpoint.pending->cancellation =
            std::move(registration).take_value();
        const auto shared = pipe_;
        pipe_->executor.post([shared, side = side_] {
            ++shared->callback_count;
            shared->fulfill(side);
        });
    }

    void async_write(Buffer buffer,
                     CancellationToken cancellation,
                     WriteCompletion completion) override {
        CHECK(pipe_->executor.running());
        ++pipe_->write_calls;
        if (pipe_->endpoints[side_].hold_writes) {
            pipe_->endpoints[side_].held_write.emplace(TestPipe::HeldWrite{
                std::move(completion), buffer.size()});
            return;
        }
        const auto shared = pipe_;
        const std::size_t side = side_;
        pipe_->executor.post(
            [shared, side, buffer = std::make_shared<std::optional<Buffer>>(
                               std::move(buffer)),
             cancellation = std::move(cancellation),
             completion = std::move(completion)]() mutable {
                ++shared->callback_count;
                if (cancellation.is_cancelled()) {
                    completion(Status(StatusCode::Cancelled,
                                      "test secure write cancelled"),
                               0U);
                    return;
                }
                const std::size_t size = (*buffer)->size();
                if (shared->partial_next_write[side]) {
                    shared->partial_next_write[side] = false;
                    completion(Status::success(), size == 0U ? 0U : size - 1U);
                    return;
                }
                const auto bytes = (*buffer)->bytes();
                std::size_t offset = 0U;
                while (offset < bytes.size()) {
                    const std::size_t count = std::min(
                        shared->fragment_bytes, bytes.size() - offset);
                    shared->endpoints[1U - side].inbound.emplace_back(
                        bytes.begin() + static_cast<std::ptrdiff_t>(offset),
                        bytes.begin() +
                            static_cast<std::ptrdiff_t>(offset + count));
                    offset += count;
                }
                buffer->reset();
                completion(Status::success(), size);
                shared->executor.post([shared, peer = 1U - side] {
                    ++shared->callback_count;
                    shared->fulfill(peer);
                });
            });
    }

    Status shutdown_write() noexcept override {
        pipe_->endpoints[side_].write_shutdown = true;
        return Status::success();
    }

    void cancel() noexcept override {
        auto held_write = std::move(pipe_->endpoints[side_].held_write);
        pipe_->endpoints[side_].held_write.reset();
        auto& pending = pipe_->endpoints[side_].pending;
        if (pending.has_value()) {
            auto callback = std::move(pending->completion);
            pending.reset();
            callback(Result<Buffer>(Status(StatusCode::Cancelled)));
        }
        if (held_write) held_write->completion(Status(StatusCode::Cancelled), 0U);
    }

    void close() noexcept override {
        if (closed_) {
            return;
        }
        closed_ = true;
        pipe_->endpoints[side_].closed = true;
        cancel();
    }

    const SecureChannelPeerEvidence& peer_evidence() const noexcept override {
        return peer_;
    }

    Result<Buffer> export_keying_material(
        std::string_view label,
        std::span<const std::byte> context,
        std::size_t output_size) override {
        CHECK(pipe_->executor.running());
        CHECK(label == kYtp1H2AdmissionExporterLabel);
        CHECK(context.empty());
        CHECK(output_size == kYtp1H2AdmissionExporterBytes);
        ++pipe_->exporter_calls;
        if (pipe_->after_export) pipe_->after_export();
        if (pipe_->exporter_fails) {
            return Result<Buffer>(Status(StatusCode::FailedPrecondition,
                                         "injected exporter failure"));
        }
        if (pipe_->exporter_wrong_length) --output_size;
        return Buffer::allocate(output_size, output_size);
    }

private:
    static SecureChannelPeerEvidence make_peer(std::size_t side,
                                               std::string_view server_name,
                                               bool authenticated) {
        if (side == 1U || !authenticated) {
            return SecureChannelPeerEvidence::anonymous_client();
        }
        return require(SecureChannelPeerEvidence::authenticated(
            EndpointRole::Server, std::string(server_name), "tls13",
            std::vector<std::byte>{std::byte{1}}));
    }

    std::shared_ptr<TestPipe> pipe_;
    std::size_t side_;
    ProviderDescriptor descriptor_;
    SecureChannelPeerEvidence peer_;
    bool closed_{false};
};

class ServerOpening final
    : public std::enable_shared_from_this<ServerOpening> {
public:
    ServerOpening(TestExecutor& executor,
                  std::unique_ptr<SecureChannel> channel,
                  std::vector<std::uint8_t> injected_binary = {})
        : executor_(executor), channel_(std::move(channel)),
          h2_(std::make_unique<obfs::H2Carrier>(
              obfs::H2CarrierRole::Server)),
          injected_binary_(std::move(injected_binary)) {}

    void start() {
        const auto self = shared_from_this();
        executor_.post([self] { self->pump(); });
    }

    std::unique_ptr<Carrier> take_carrier() {
        return std::move(carrier_);
    }

    const std::string& admission_path() const noexcept { return admission_path_; }

private:
    void collect_output() {
        auto wire = h2_->TakeOutbound();
        if (wire.empty()) {
            return;
        }
        auto copy = Buffer::copy_from(
            std::as_bytes(std::span<const std::uint8_t>(wire)),
            std::max<std::size_t>(1U, wire.size()));
        CHECK(copy.ok());
        writes_.push_back(std::move(copy).take_value());
    }

    void start_write() {
        if (writing_ || writes_.empty()) {
            return;
        }
        Buffer wire = std::move(writes_.front());
        writes_.pop_front();
        const std::size_t size = wire.size();
        writing_ = true;
        const auto self = shared_from_this();
        channel_->async_write(
            std::move(wire), {},
            [self, size](Status status, std::size_t transferred) {
                CHECK(status.ok());
                CHECK(transferred == size);
                self->writing_ = false;
                self->pump();
            });
    }

    void start_read() {
        if (reading_ || accepted_) {
            return;
        }
        reading_ = true;
        const auto self = shared_from_this();
        channel_->async_read(
            channel_->max_read_size(), {},
            [self](Result<Buffer> result) {
                CHECK(result.ok());
                self->reading_ = false;
                Buffer plaintext = std::move(result).take_value();
                const auto bytes = plaintext.bytes();
                self->h2_->Feed(
                    reinterpret_cast<const std::uint8_t*>(bytes.data()),
                    bytes.size());
                CHECK(!self->h2_->failed());
                for (auto& request : self->h2_->TakeRequests()) {
                    if (request.method == "CONNECT" &&
                        request.protocol == "websocket") {
                        const std::array<std::byte, kYtp1H2AdmissionExporterBytes>
                            exporter{};
                        CHECK(verify_ytp1_h2_admission_path(
                            kTestAdmissionKey, request.authority, "cover.example",
                            exporter, request.path, 443U));
                        CHECK(self->admission_path_.empty());
                        self->admission_path_ = request.path;
                        CHECK(self->h2_->AcceptCarrier(request.stream_id));
                        if (!self->injected_binary_.empty()) {
                            CHECK(self->h2_->SendBinary(
                                self->injected_binary_));
                        }
                        self->accepted_ = true;
                    } else {
                        CHECK(request.method == "GET");
                        CHECK(self->h2_->RespondHttp(
                            request.stream_id, 200U, {}, {}, false));
                    }
                }
                self->pump();
            });
    }

    void promote() {
        if (!accepted_ || promoted_ || writing_ || !writes_.empty() ||
            h2_->queued_output_bytes() != 0U) {
            return;
        }
        auto promoted = make_admitted_h2_duplex_server_carrier(
            std::move(channel_), std::move(h2_), ExecutorAffinity(77U),
            executor_.dispatch());
        CHECK(promoted.ok());
        carrier_ = std::move(promoted).take_value();
        promoted_ = true;
    }

    void pump() {
        collect_output();
        start_write();
        if (!writing_ && writes_.empty()) {
            promote();
        }
        start_read();
    }

    TestExecutor& executor_;
    std::unique_ptr<SecureChannel> channel_;
    std::unique_ptr<obfs::H2Carrier> h2_;
    std::unique_ptr<Carrier> carrier_;
    std::deque<Buffer> writes_;
    std::vector<std::uint8_t> injected_binary_;
    std::string admission_path_;
    bool reading_{false};
    bool writing_{false};
    bool accepted_{false};
    bool promoted_{false};
};

struct OpenedPair final {
    OpenedPair() = default;
    OpenedPair(OpenedPair&&) noexcept = default;
    OpenedPair& operator=(OpenedPair&&) noexcept = default;
    OpenedPair(const OpenedPair&) = delete;
    OpenedPair& operator=(const OpenedPair&) = delete;

    ~OpenedPair() noexcept {
        if (!executor) {
            return;
        }
        try {
            // Individual tests can reject submissions to verify synchronous
            // failure settlement. Teardown is a separate lifecycle phase:
            // permit the carrier's executor-confined close tasks again.
            executor->accept_new_tasks();
            if (client) client->close();
            if (server) server->close();
            executor->run();
            // Already settled handles must release their state without a
            // second drain, even when the dispatch retains its executor.
            client.reset();
            server.reset();
        } catch (...) {
            // Test teardown must not throw while another assertion unwinds.
        }
    }

    std::shared_ptr<TestExecutor> executor;
    std::shared_ptr<TestPipe> pipe;
    std::shared_ptr<ServerOpening> server_opening;
    std::unique_ptr<Carrier> client;
    std::unique_ptr<Carrier> server;
    Status client_open_status{
        StatusCode::Closed, "client opening did not complete"};
};

OpenedPair open_pair(std::vector<std::uint8_t> injected_binary = {},
                     bool expect_success = true,
                     std::shared_ptr<TestExecutor> executor = {},
                     std::shared_ptr<H2DuplexCarrierProvider> provider = {}) {
    OpenedPair pair;
    pair.executor = executor ? std::move(executor) : std::make_shared<TestExecutor>();
    pair.pipe = std::make_shared<TestPipe>(*pair.executor);
    std::unique_ptr<SecureChannel> client_channel =
        std::make_unique<FakeSecureChannel>(pair.pipe, 0U);
    std::unique_ptr<SecureChannel> server_channel =
        std::make_unique<FakeSecureChannel>(pair.pipe, 1U);
    pair.server_opening = std::make_shared<ServerOpening>(
        *pair.executor, std::move(server_channel),
        std::move(injected_binary));
    pair.server_opening->start();

    if (!provider) {
        auto mutable_key = kTestAdmissionKey;
        provider = require(H2DuplexCarrierProvider::create(
            ExecutorAffinity(77U),
            pair.executor->dispatch(),
            H2DuplexClientConfig{"COVER.EXAMPLE", 443U, {}}, mutable_key));
        mutable_key.fill(std::byte{0});
    }
    bool completed = false;
    provider->async_create(
        std::move(client_channel), EndpointRole::Client, {},
        [&pair, &completed](Result<std::unique_ptr<Carrier>> result) {
            CHECK(pair.executor->running());
            if (result.ok()) {
                pair.client = std::move(result).take_value();
                pair.client_open_status = Status::success();
            } else {
                pair.client_open_status = result.status();
            }
            completed = true;
        });
    // Queued creation owns the key independently of caller storage and the
    // provider facade. The server verifies against the original fixed key.
    provider.reset();
    pair.executor->run();
    CHECK(completed);
    pair.server = pair.server_opening->take_carrier();
    CHECK(pair.server != nullptr);
    CHECK(pair.server->descriptor().provider_id() ==
          kH2DuplexCarrierProviderId);
    if (expect_success) {
        CHECK(pair.client_open_status.ok());
        CHECK(pair.client != nullptr);
        CHECK(pair.client->descriptor().provider_id() ==
              kH2DuplexCarrierProviderId);
    }
    return pair;
}

void test_limits_cover_envelope_and_receive_window() {
    auto executor = std::make_shared<TestExecutor>();
    const auto post = executor->dispatch();

    H2DuplexClientConfig retained_too_small{
        "cover.example", 443U, {}};
    retained_too_small.limits.max_retained_receive_bytes =
        retained_too_small.limits.max_record_bytes;
    auto retained = H2DuplexCarrierProvider::create(
        ExecutorAffinity(77U), post, std::move(retained_too_small), kTestAdmissionKey);
    CHECK(!retained.ok());
    CHECK(retained.status().code() == StatusCode::InvalidArgument);

    H2DuplexClientConfig record_too_large{
        "cover.example", 443U, {}};
    record_too_large.limits.max_record_bytes =
        obfs::kAdmittedH2ReceiveWindowBytes -
        kH2DuplexEnvelopeBytes + 1U;
    auto oversized = H2DuplexCarrierProvider::create(
        ExecutorAffinity(77U), post, std::move(record_too_large), kTestAdmissionKey);
    CHECK(!oversized.ok());
    CHECK(oversized.status().code() == StatusCode::InvalidArgument);
}

void test_admission_configuration_rejects_invalid_inputs() {
    TestExecutor executor;
    const auto post = executor.dispatch();
    const H2DuplexClientConfig valid{"cover.example", 443U, {}};
    const std::array<std::byte, kYtp1H2AdmissionKeyBytes + 1U> oversized_key{};
    for (std::size_t size : {0U, 1U, 31U, 33U}) {
        auto result = H2DuplexCarrierProvider::create(
            ExecutorAffinity(77U), post, valid,
            std::span(oversized_key).first(size));
        CHECK(!result.ok());
        CHECK(result.status().code() == StatusCode::InvalidArgument);
    }
    for (const auto& config : {
             H2DuplexClientConfig{"cover.example", 0U, {}},
             H2DuplexClientConfig{"cover.example/path", 443U, {}},
             H2DuplexClientConfig{"cover.example.", 443U, {}}}) {
        auto result = H2DuplexCarrierProvider::create(
            ExecutorAffinity(77U), post, config, kTestAdmissionKey);
        CHECK(!result.ok());
        CHECK(result.status().code() == StatusCode::InvalidArgument);
    }
}

void test_admission_failures_close_before_http_output() {
    enum class Failure {
        WrongName, AnonymousPeer, MissingTls13, ExporterFailure,
        ExporterLength, CancelBeforeDispatch, CancelDuringExporter
    };
    for (const auto failure : {
             Failure::WrongName, Failure::AnonymousPeer, Failure::MissingTls13,
             Failure::ExporterFailure, Failure::ExporterLength,
             Failure::CancelBeforeDispatch, Failure::CancelDuringExporter}) {
        TestExecutor executor;
        auto pipe = std::make_shared<TestPipe>(executor);
        CancellationSource cancellation;
        StatusCode expected = StatusCode::ProviderMismatch;
        std::size_t expected_exporter_calls = 0U;
        switch (failure) {
            case Failure::WrongName: pipe->server_identity = "other.example"; break;
            case Failure::AnonymousPeer: pipe->server_authenticated = false; break;
            case Failure::MissingTls13: pipe->tls13 = false; break;
            case Failure::ExporterFailure:
                pipe->exporter_fails = true;
                expected = StatusCode::FailedPrecondition;
                expected_exporter_calls = 1U;
                break;
            case Failure::ExporterLength:
                pipe->exporter_wrong_length = true;
                expected_exporter_calls = 1U;
                break;
            case Failure::CancelBeforeDispatch:
                cancellation.cancel();
                expected = StatusCode::Cancelled;
                break;
            case Failure::CancelDuringExporter:
                pipe->after_export = [&cancellation] { cancellation.cancel(); };
                expected = StatusCode::Cancelled;
                expected_exporter_calls = 1U;
                break;
        }
        auto provider = require(H2DuplexCarrierProvider::create(
            ExecutorAffinity(77U),
            executor.dispatch(),
            H2DuplexClientConfig{"cover.example", 443U, {}}, kTestAdmissionKey));
        unsigned int completions = 0U;
        std::optional<StatusCode> actual;
        provider->async_create(
            std::make_unique<FakeSecureChannel>(pipe, 0U), EndpointRole::Client,
            cancellation.token(),
            [&](Result<std::unique_ptr<Carrier>> result) {
                ++completions;
                if (!result.ok()) actual = result.status().code();
            });
        executor.run();
        CHECK(completions == 1U);
        CHECK(actual == expected);
        CHECK(pipe->endpoints[0].closed);
        CHECK(pipe->exporter_calls == expected_exporter_calls);
        CHECK(pipe->write_calls == 0U);
        CHECK(pipe->endpoints[1].inbound.empty());
    }
}

void test_admission_uses_fresh_nonce_and_exporter_binding() {
    auto executor = std::make_shared<TestExecutor>();
    auto provider = require(H2DuplexCarrierProvider::create(
        ExecutorAffinity(77U),
        executor->dispatch(),
        H2DuplexClientConfig{"cover.example", 443U, {}}, kTestAdmissionKey));
    OpenedPair first = open_pair({}, true, executor, provider);
    OpenedPair second = open_pair({}, true, executor, provider);
    const auto& first_path = first.server_opening->admission_path();
    const auto& second_path = second.server_opening->admission_path();
    CHECK(first.pipe->exporter_calls == 1U);
    CHECK(second.pipe->exporter_calls == 1U);
    CHECK(!first_path.empty() && !second_path.empty());
    CHECK(first_path != second_path);
    const auto first_proof = admission::parse_path(first_path);
    const auto second_proof = admission::parse_path(second_path);
    CHECK(first_proof.has_value() && second_proof.has_value());
    CHECK(first_proof->nonce != second_proof->nonce);
    std::array<std::byte, kYtp1H2AdmissionExporterBytes> another_connection{};
    another_connection[0] = std::byte{1};
    CHECK(!verify_ytp1_h2_admission_path(
        kTestAdmissionKey, "cover.example", "cover.example",
        another_connection, first_path, 443U));
}

void test_opening_fragmentation_and_bidirectional_records() {
    OpenedPair pair = open_pair();
    CHECK(pair.pipe->callback_count > 20U);

    bool send_done = false;
    bool receive_done = false;
    std::optional<ReceivedRecord> received;
    pair.server->async_receive(
        {}, [&pair, &receive_done, &received](Result<ReceivedRecord> result) {
            CHECK(pair.executor->running());
            received.emplace(require(std::move(result)));
            receive_done = true;
        });
    pair.client->async_send(
        make_buffer("client-record"), {},
        [&pair, &send_done](Status status, std::size_t bytes) {
            CHECK(pair.executor->running());
            CHECK(status.ok());
            CHECK(bytes == std::string_view("client-record").size());
            send_done = true;
        });
    pair.executor->run();
    CHECK(send_done && receive_done);
    CHECK(buffer_text(received->payload()) == "client-record");
    CHECK(received->take_credit().size() ==
          std::string_view("client-record").size());
    pair.executor->run();

    send_done = false;
    receive_done = false;
    received.reset();
    pair.client->async_receive(
        {}, [&receive_done, &received](Result<ReceivedRecord> result) {
            received.emplace(require(std::move(result)));
            receive_done = true;
        });
    pair.server->async_send(
        make_buffer("server-record"), {},
        [&send_done](Status status, std::size_t bytes) {
            CHECK(status.ok());
            CHECK(bytes == std::string_view("server-record").size());
            send_done = true;
        });
    pair.executor->run();
    CHECK(send_done && receive_done);
    CHECK(buffer_text(received->payload()) == "server-record");
}

void test_receive_cancellation_and_queue_bound() {
    OpenedPair pair = open_pair();
    CancellationSource cancellation;
    bool cancelled = false;
    pair.client->async_receive(
        cancellation.token(),
        [&cancelled](Result<ReceivedRecord> result) {
            CHECK(!result.ok());
            CHECK(result.status().code() == StatusCode::Cancelled);
            cancelled = true;
        });
    pair.executor->run();
    cancellation.cancel();
    pair.executor->run();
    CHECK(cancelled);

    bool rejected = false;
    auto oversized = require(Buffer::allocate(
        pair.client->max_record_size() + 1U,
        pair.client->max_record_size() + 1U));
    pair.client->async_send(
        std::move(oversized), {},
        [&rejected](Status status, std::size_t bytes) {
            CHECK(status.code() == StatusCode::ResourceExhausted);
            CHECK(bytes == 0U);
            rejected = true;
        });
    pair.executor->run();
    CHECK(rejected);
}

void test_executor_rejection_settles_each_operation_once() {
    OpenedPair pair = open_pair();
    pair.executor->reject_new_tasks();

    unsigned int receives = 0U;
    pair.client->async_receive({}, [&receives](Result<ReceivedRecord> result) {
        CHECK(!result.ok());
        CHECK(result.status().code() == StatusCode::Internal);
        ++receives;
    });
    CHECK(receives == 1U);

    unsigned int sends = 0U;
    pair.client->async_send(
        make_buffer("rejected"), {},
        [&sends](Status status, std::size_t bytes) {
            CHECK(!status.ok());
            CHECK(status.code() == StatusCode::Internal);
            CHECK(bytes == 0U);
            ++sends;
        });
    CHECK(sends == 1U);
}

void test_executor_rejection_settles_provider_creation_once() {
    TestExecutor executor;
    auto pipe = std::make_shared<TestPipe>(executor);
    auto provider = require(H2DuplexCarrierProvider::create(
        ExecutorAffinity(77U),
        executor.dispatch(),
        H2DuplexClientConfig{"cover.example", 443U, {}}, kTestAdmissionKey));

    executor.reject_new_tasks();
    unsigned int completions = 0U;
    provider->async_create(
        std::make_unique<FakeSecureChannel>(pipe, 0U), EndpointRole::Client, {},
        [&completions](Result<std::unique_ptr<Carrier>> result) {
            CHECK(!result.ok());
            CHECK(result.status().code() == StatusCode::Internal);
            ++completions;
        });
    CHECK(completions == 1U);
}

void test_partial_secure_write_fails_send() {
    OpenedPair pair = open_pair();
    pair.pipe->partial_next_write[0] = true;
    bool failed = false;
    pair.client->async_send(
        make_buffer("partial"), {},
        [&failed](Status status, std::size_t bytes) {
            CHECK(!status.ok());
            CHECK(bytes == 0U);
            failed = true;
        });
    pair.executor->run();
    CHECK(failed);
    // A transport failure settles the control lifecycle too; a later explicit
    // close or final public-handle destruction must not resurrect work.
    pair.client->close();
    pair.client->cancel();
    pair.client.reset();
    CHECK(pair.executor->empty());
    CHECK(pair.pipe->destroyed[0] == 1U);
}

void test_malformed_carrier_envelope_fails_closed() {
    std::vector<std::uint8_t> malformed{
        'B', 'A', 'D', 0, 1, 0, 0, 0, 0, 0, 0, 1, 0xaa};
    OpenedPair pair = open_pair(std::move(malformed), false);
    if (!pair.client_open_status.ok()) {
        CHECK(pair.client_open_status.code() == StatusCode::InvalidArgument);
        return;
    }
    bool failed = false;
    pair.client->async_receive({}, [&failed](Result<ReceivedRecord> result) {
        CHECK(!result.ok());
        CHECK(result.status().code() == StatusCode::InvalidArgument);
        failed = true;
    });
    pair.executor->run();
    CHECK(failed);
}

void test_oversized_carrier_length_fails_before_payload() {
    std::vector<std::uint8_t> oversized{
        'Y', 'C', 'R', 0, 1, 0, 0, 0, 0x7f, 0xff, 0xff, 0xff};
    OpenedPair pair = open_pair(std::move(oversized), false);
    if (!pair.client_open_status.ok()) {
        CHECK(pair.client_open_status.code() == StatusCode::ResourceExhausted);
        return;
    }
    bool failed = false;
    pair.client->async_receive({}, [&failed](Result<ReceivedRecord> result) {
        CHECK(!result.ok());
        CHECK(result.status().code() == StatusCode::ResourceExhausted);
        failed = true;
    });
    pair.executor->run();
    CHECK(failed);
}

void test_client_creation_allocation_failures_settle_once() {
    for (std::ptrdiff_t count = 0; count < 80; ++count) {
        TestExecutor executor;
        auto pipe = std::make_shared<TestPipe>(executor);
        pipe->endpoints[0].hold_writes = true;
        auto provider = require(H2DuplexCarrierProvider::create(
            ExecutorAffinity(77U), executor.dispatch(),
            H2DuplexClientConfig{"cover.example", 443U, {}}, kTestAdmissionKey));
        std::unique_ptr<SecureChannel> channel = std::make_unique<FakeSecureChannel>(pipe, 0U);
        CancellationSource cancellation;
        unsigned int calls = 0U;
        StatusCode code = StatusCode::Ok;
        engine::CarrierProvider::Completion completion = [&](Result<std::unique_ptr<Carrier>> result) {
            ++calls;
            if (!result.ok()) code = result.status().code();
        };
        {
            test_allocation_failure::Scope one_shot(count);
            provider->async_create(std::move(channel), EndpointRole::Client,
                                   cancellation.token(), std::move(completion));
            executor.run();
        }
        provider.reset();
        if (calls == 0U) {
            test_allocation_failure::SustainedScope all;
            cancellation.cancel();
            executor.run();
        }
        CHECK(calls == 1U);
        CHECK(code == StatusCode::Cancelled || code == StatusCode::ResourceExhausted ||
              code == StatusCode::FailedPrecondition);
        CHECK(pipe->destroyed[0] == 1U);
    }
}

void test_receive_allocation_failures_settle_once() {
    // Walk allocation sites in initiation and registration; sustained denial
    // additionally proves their error paths do not allocate to deliver status.
    for (std::ptrdiff_t count = 0; count < 8; ++count) {
        for (const bool sustained : {false, true}) {
            auto pair = open_pair();
            CancellationSource cancellation;
            unsigned int calls = 0U;
            StatusCode code = StatusCode::Ok;
            Carrier::ReceiveCompletion completion = [&](Result<ReceivedRecord> result) {
                ++calls;
                if (!result.ok()) code = result.status().code();
            };
            {
                test_allocation_failure::Scope one_shot(count);
                test_allocation_failure::SustainedScope all(sustained);
                pair.client->async_receive(cancellation.token(), std::move(completion));
                pair.executor->run();
            }
            if (calls == 0U) {
                cancellation.cancel();
                pair.executor->run();
                CHECK(code == StatusCode::Cancelled);
            } else CHECK(code == StatusCode::ResourceExhausted);
            pair.client.reset();
            pair.executor->run();
            CHECK(calls == 1U && pair.pipe->destroyed[0] == 1U);
        }
    }
}

void test_send_allocation_failures_settle_once() {
    for (std::ptrdiff_t count = 0; count < 24; ++count) {
        auto pair = open_pair();
        pair.pipe->endpoints[0].hold_writes = true;
        auto record = make_buffer("allocation sweep");
        CancellationSource cancellation;
        unsigned int calls = 0U;
        StatusCode code = StatusCode::Ok;
        Carrier::SendCompletion completion = [&](Status status, std::size_t) {
            ++calls;
            code = status.code();
        };
        {
            test_allocation_failure::Scope one_shot(count);
            pair.client->async_send(std::move(record), cancellation.token(), std::move(completion));
            pair.executor->run();
        }
        if (calls == 0U) {
            test_allocation_failure::SustainedScope all;
            cancellation.cancel();
            pair.executor->run();
        }
        CHECK(calls == 1U);
        CHECK(code == StatusCode::Cancelled || code == StatusCode::ResourceExhausted ||
              code == StatusCode::FailedPrecondition); // nghttp2 can reject a failed callback.
        pair.client.reset();
        pair.executor->run();
        CHECK(calls == 1U && pair.pipe->destroyed[0] == 1U);
    }
}

void test_close_cancel_and_last_owner_under_allocation_failure() {
    for (const bool sustained : {false, true}) {
        for (const bool cancel : {false, true}) {
            auto pair = open_pair();
            pair.pipe->endpoints[0].hold_writes = true;
            unsigned int receives = 0U, sends = 0U;
            bool correct = true;
            const auto expected = cancel ? StatusCode::Cancelled : StatusCode::Closed;
            pair.client->async_receive({}, [&](Result<ReceivedRecord> result) {
                ++receives;
                correct &= pair.executor->running() && !result.ok() && result.status().code() == expected;
            });
            pair.client->async_send(make_buffer("held send"), {}, [&](Status status, std::size_t bytes) {
                ++sends;
                correct &= pair.executor->running() && status.code() == expected && bytes == 0U;
            });
            pair.executor->run();
            CHECK(receives == 0U && sends == 0U);
            CHECK(pair.pipe->endpoints[0].pending && pair.pipe->endpoints[0].held_write);
            {
                test_allocation_failure::Scope one_shot(sustained ? -1 : 0);
                test_allocation_failure::SustainedScope all(sustained);
                if (cancel) pair.client->cancel();
                // Releasing the last public handle must retain the state until
                // its control task cancels both underlying operations and drains.
                pair.client.reset();
                pair.executor->run();
            }
            CHECK(correct && receives == 1U && sends == 1U);
            CHECK(pair.pipe->endpoints[0].closed);
            CHECK(pair.pipe->destroyed[0] == 1U);
            CHECK(!pair.pipe->endpoints[0].pending && !pair.pipe->endpoints[0].held_write);
        }
    }
}

void test_receive_token_and_credit_return_under_allocation_failure() {
    auto pair = open_pair();
    CancellationSource cancellation;
    unsigned int cancelled = 0U;
    bool correct = true;
    pair.client->async_receive(cancellation.token(), [&](Result<ReceivedRecord> result) {
        ++cancelled;
        correct &= pair.executor->running() && !result.ok() && result.status().code() == StatusCode::Cancelled;
    });
    pair.executor->run();
    {
        test_allocation_failure::SustainedScope all;
        cancellation.cancel();
        pair.executor->run();
    }
    CHECK(correct && cancelled == 1U);
    std::optional<ReceivedRecord> received;
    pair.client->async_receive({}, [&](Result<ReceivedRecord> result) {
        if (result.ok()) received.emplace(std::move(result).take_value());
    });
    pair.server->async_send(make_buffer("retained credit"), {}, [](Status, std::size_t) {});
    pair.executor->run();
    CHECK(received.has_value());
    {
        // Return credit after close and last-handle release, before control
        // delivery. Its weak owner must not leak or run H2 off the executor.
        test_allocation_failure::SustainedScope all;
        pair.client.reset();
        received.reset();
        pair.executor->run();
    }
    CHECK(pair.pipe->destroyed[0] == 1U);
}

void test_closed_handles_and_credit_release_after_final_drain() {
    auto pair = open_pair();
    std::optional<ReceivedRecord> retained;
    pair.client->async_receive({}, [&](Result<ReceivedRecord> result) {
        if (result.ok()) retained.emplace(std::move(result).take_value());
    });
    pair.server->async_send(make_buffer("credit survives shutdown"), {},
                           [](Status, std::size_t) {});
    pair.executor->run();
    CHECK(retained.has_value());
    pair.client->close();
    pair.server->close();
    pair.executor->run();
    CHECK(pair.executor->empty());
    CHECK(pair.pipe->destroyed[0] == 0U && pair.pipe->destroyed[1] == 0U);
    {
        test_allocation_failure::SustainedScope all;
        pair.client->close();
        pair.client->cancel();
        pair.server->cancel();
        pair.server->close();
        retained.reset();
        pair.client.reset();
        pair.server.reset();
    }
    CHECK(pair.executor->empty());
    CHECK(pair.pipe->destroyed[0] == 1U && pair.pipe->destroyed[1] == 1U);
}

void test_active_credit_return_allocation_failure_settles_receive() {
    auto pair = open_pair();
    pair.pipe->fragment_bytes = 64U * 1024U;
    std::vector<ReceivedRecord> retained;
    for (unsigned int i = 0; i < 3U; ++i) {
        bool sent = false;
        pair.client->async_receive({}, [&](Result<ReceivedRecord> result) {
            retained.push_back(require(std::move(result)));
        });
        auto buffer = require(Buffer::allocate(2U * 1024U * 1024U, 2U * 1024U * 1024U));
        pair.server->async_send(std::move(buffer), {}, [&](Status status, std::size_t bytes) {
            sent = status.ok() && bytes == 2U * 1024U * 1024U;
        });
        pair.executor->run();
        CHECK(sent && retained.size() == i + 1U);
    }
    unsigned int calls = 0U;
    StatusCode code = StatusCode::Ok;
    pair.client->async_receive({}, [&](Result<ReceivedRecord> result) {
        ++calls;
        if (!result.ok()) code = result.status().code();
    });
    pair.executor->run();
    {
        // Returning over half the receive window creates WINDOW_UPDATE output.
        // If that allocation fails, the queued receive must fail and release
        // the carrier, rather than silently losing its credit-return task.
        test_allocation_failure::SustainedScope all;
        retained.clear();
        pair.executor->run();
        pair.client.reset();
        pair.executor->run();
    }
    CHECK(calls == 1U);
    CHECK(code == StatusCode::ResourceExhausted || code == StatusCode::FailedPrecondition);
    CHECK(pair.pipe->destroyed[0] == 1U);
}

void test_read_failure_settles_both_callbacks_under_allocation_failure() {
    auto pair = open_pair();
    pair.pipe->endpoints[0].hold_writes = true;
    unsigned int receives = 0U, sends = 0U;
    bool correct = true;
    pair.client->async_receive({}, [&](Result<ReceivedRecord> result) {
        ++receives;
        correct &= pair.executor->running() && !result.ok() && result.status().code() == StatusCode::ResourceExhausted;
        throw 42; // One throwing consumer must not prevent its sibling settling.
    });
    pair.client->async_send(make_buffer("held send"), {}, [&](Status status, std::size_t bytes) {
        ++sends;
        correct &= pair.executor->running() && status.code() == StatusCode::ResourceExhausted && bytes == 0U;
    });
    pair.executor->run();
    auto completion = std::move(pair.pipe->endpoints[0].pending->completion);
    pair.pipe->endpoints[0].pending.reset();
    auto failure = std::make_shared<Result<Buffer>>(Status(
        StatusCode::ResourceExhausted, "retained upstream diagnostic larger than small string storage"));
    pair.executor->post([&] {
        test_allocation_failure::SustainedScope all;
        completion(std::move(*failure));
    });
    pair.executor->run();
    CHECK(correct && receives == 1U && sends == 1U);
    CHECK(pair.pipe->endpoints[0].closed);
}

}  // namespace
}  // namespace yume::providers

int main() {
    yume::test::before_allocate_on_any_thread.store(check_test_allocation);

    try {
        yume::providers::test_client_creation_allocation_failures_settle_once();
        yume::providers::test_receive_allocation_failures_settle_once();
        yume::providers::test_send_allocation_failures_settle_once();
        yume::providers::test_close_cancel_and_last_owner_under_allocation_failure();
        yume::providers::test_receive_token_and_credit_return_under_allocation_failure();
        yume::providers::test_closed_handles_and_credit_release_after_final_drain();
        yume::providers::test_active_credit_return_allocation_failure_settles_receive();
        yume::providers::test_read_failure_settles_both_callbacks_under_allocation_failure();
        yume::providers::test_admission_configuration_rejects_invalid_inputs();
        yume::providers::test_admission_failures_close_before_http_output();
        yume::providers::test_admission_uses_fresh_nonce_and_exporter_binding();
        yume::providers::test_opening_fragmentation_and_bidirectional_records();
        yume::providers::test_receive_cancellation_and_queue_bound();
        yume::providers::test_executor_rejection_settles_each_operation_once();
        yume::providers::test_executor_rejection_settles_provider_creation_once();
        yume::providers::test_partial_secure_write_fails_send();
        yume::providers::test_malformed_carrier_envelope_fails_closed();
        yume::providers::test_oversized_carrier_length_fails_before_payload();
        yume::providers::test_limits_cover_envelope_and_receive_window();
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << exception.what() << '\n';
        return 1;
    }
}
