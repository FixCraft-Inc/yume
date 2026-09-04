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

#include "providers/ytp1_h2_carrier.hpp"

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

ProviderDescriptor make_secure_descriptor() {
    return require(ProviderDescriptor::create(
        "test.tls13", ProviderKind::SecureChannel, 1U,
        engine::mandatory_capabilities(ProviderKind::SecureChannel)
            .with(engine::Capability::Tls13)));
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

    void run() {
        std::size_t turns = 0U;
        while (!tasks_.empty()) {
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
    void reject_new_tasks() noexcept { reject_ = true; }
    void accept_new_tasks() noexcept { reject_ = false; }

private:
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

    struct Endpoint {
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
    std::size_t callback_count{0U};
};

class FakeSecureChannel final : public SecureChannel {
public:
    FakeSecureChannel(std::shared_ptr<TestPipe> pipe, std::size_t side)
        : pipe_(std::move(pipe)), side_(side),
          descriptor_(make_secure_descriptor()),
          peer_(make_peer(side)) {}
    ~FakeSecureChannel() noexcept override { close(); }

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
        auto& pending = pipe_->endpoints[side_].pending;
        if (pending.has_value()) {
            auto callback = std::move(pending->completion);
            pending.reset();
            pipe_->executor.post([callback = std::move(callback)]() mutable {
                callback(Result<Buffer>(Status(
                    StatusCode::Cancelled, "test secure channel cancelled")));
            });
        }
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
        std::string_view,
        std::span<const std::byte>,
        std::size_t output_size) override {
        return Buffer::allocate(output_size, output_size);
    }

private:
    static SecureChannelPeerEvidence make_peer(std::size_t side) {
        if (side == 1U) {
            return SecureChannelPeerEvidence::anonymous_client();
        }
        return require(SecureChannelPeerEvidence::authenticated(
            EndpointRole::Server, "test-server", "tls13",
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
        auto promoted = make_ytp1_h2_admitted_server_carrier(
            std::move(channel_), std::move(h2_), ExecutorAffinity(77U),
            [this](std::function<void()> task) {
                executor_.post(std::move(task));
            });
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
            // Carrier destruction requests one final idempotent close. Drain
            // those self-capturing tasks too, or a test post handler that owns
            // its executor forms state -> executor -> task -> state at exit.
            client.reset();
            server.reset();
            executor->run();
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
                     bool expect_success = true) {
    OpenedPair pair;
    pair.executor = std::make_shared<TestExecutor>();
    pair.pipe = std::make_shared<TestPipe>(*pair.executor);
    std::unique_ptr<SecureChannel> client_channel =
        std::make_unique<FakeSecureChannel>(pair.pipe, 0U);
    std::unique_ptr<SecureChannel> server_channel =
        std::make_unique<FakeSecureChannel>(pair.pipe, 1U);
    pair.server_opening = std::make_shared<ServerOpening>(
        *pair.executor, std::move(server_channel),
        std::move(injected_binary));
    pair.server_opening->start();

    auto provider = require(Ytp1H2CarrierProvider::create(
        ExecutorAffinity(77U),
        [executor = pair.executor](std::function<void()> task) {
            executor->post(std::move(task));
        },
        Ytp1H2ClientConfig{"cover.example", "/carrier-test", {}}));
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
    pair.executor->run();
    CHECK(completed);
    pair.server = pair.server_opening->take_carrier();
    CHECK(pair.server != nullptr);
    CHECK(pair.server->descriptor().provider_id() ==
          kYtp1H2CarrierProviderId);
    if (expect_success) {
        CHECK(pair.client_open_status.ok());
        CHECK(pair.client != nullptr);
        CHECK(pair.client->descriptor().provider_id() ==
              kYtp1H2CarrierProviderId);
    }
    return pair;
}

void test_limits_cover_envelope_and_receive_window() {
    auto executor = std::make_shared<TestExecutor>();
    const auto post = [executor](std::function<void()> task) {
        executor->post(std::move(task));
    };

    Ytp1H2ClientConfig retained_too_small{
        "cover.example", "/carrier-test", {}};
    retained_too_small.limits.max_retained_receive_bytes =
        retained_too_small.limits.max_record_bytes;
    auto retained = Ytp1H2CarrierProvider::create(
        ExecutorAffinity(77U), post, std::move(retained_too_small));
    CHECK(!retained.ok());
    CHECK(retained.status().code() == StatusCode::InvalidArgument);

    Ytp1H2ClientConfig record_too_large{
        "cover.example", "/carrier-test", {}};
    record_too_large.limits.max_record_bytes =
        obfs::kAdmittedH2ReceiveWindowBytes -
        kYtp1H2CarrierEnvelopeBytes + 1U;
    auto oversized = Ytp1H2CarrierProvider::create(
        ExecutorAffinity(77U), post, std::move(record_too_large));
    CHECK(!oversized.ok());
    CHECK(oversized.status().code() == StatusCode::InvalidArgument);
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
    auto provider = require(Ytp1H2CarrierProvider::create(
        ExecutorAffinity(77U),
        [](std::function<void()>) {
            throw TestFailure("executor rejected provider creation");
        },
        Ytp1H2ClientConfig{"cover.example", "/carrier-test", {}}));

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

}  // namespace
}  // namespace yume::providers

int main() {
    try {
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
