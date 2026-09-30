/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/circuit_client.hpp"

#include <algorithm>
#include <atomic>
#include <deque>
#include <map>
#include <new>
#include <utility>

#include <boost/asio/basic_waitable_timer.hpp>
#include <boost/asio/post.hpp>

namespace yume::runtime::circuit {
namespace {

namespace c1 = yume::circuit1;
namespace cc = yume::providers::circuit;
using engine::Buffer;
using engine::CancellationRegistration;
using engine::CancellationSource;
using engine::CancellationToken;
using engine::CarrierCredit;
using engine::ReceivedRecord;
using engine::Result;
using engine::Status;
using engine::StatusCode;
using engine::StreamResponder;
using Clock = std::chrono::steady_clock;
using Timer = boost::asio::basic_waitable_timer<
    Clock, boost::asio::wait_traits<Clock>,
    providers::AsioExecutionContext::Executor>;

constexpr std::size_t kMaxWriteSize = 64U * 1024U;
constexpr std::size_t kDataPerCell = c1::MaxDataPayload(c1::Direction::Forward);

std::span<const std::uint8_t> bytes_of(const Buffer& buffer) noexcept {
    return {reinterpret_cast<const std::uint8_t*>(buffer.bytes().data()),
            buffer.size()};
}

Result<Buffer> buffer_of(std::span<const std::uint8_t> bytes) {
    return Buffer::copy_from(std::as_bytes(bytes), c1::kMaxCellBytes);
}

std::array<std::uint8_t, 4> u32(std::uint32_t value) noexcept {
    return {static_cast<std::uint8_t>(value >> 24U),
            static_cast<std::uint8_t>(value >> 16U),
            static_cast<std::uint8_t>(value >> 8U),
            static_cast<std::uint8_t>(value)};
}

}  // namespace

Status status_for(c1::StreamReason reason) noexcept {
    switch (reason) {
        case c1::StreamReason::Policy:
            return Status::diagnostic(
                StatusCode::PermissionDenied,
                "the exit's policy refused the destination");
        // A destination failure is a route failure, as a failed OPEN on the
        // direct session reports, so SOCKS5 answers host unreachable. NotFound
        // or FailedPrecondition would read as a refused service.
        case c1::StreamReason::NameNotFound:
            return Status::diagnostic(StatusCode::Internal,
                                      "the destination's name did not resolve");
        case c1::StreamReason::ConnectionRefused:
            return Status::diagnostic(StatusCode::Internal,
                                      "the destination refused the connection");
        case c1::StreamReason::Resources:
            return Status::diagnostic(StatusCode::ResourceExhausted,
                                      "the exit reached a bound");
        case c1::StreamReason::Unreachable:
            return Status::diagnostic(StatusCode::Internal,
                                      "the destination could not be reached");
        case c1::StreamReason::Timeout:
            return Status::diagnostic(StatusCode::Internal,
                                      "the destination did not answer in time");
        case c1::StreamReason::Done:
        case c1::StreamReason::Protocol:
        case c1::StreamReason::Closed:
            break;
    }
    return Status::diagnostic(StatusCode::Closed, "the exit ended the stream");
}

namespace detail {
class ClientStream;
}  // namespace detail

struct ClientCircuit::State final : std::enable_shared_from_this<State> {
    struct Layer final {
        cc::LayerCipher forward;
        cc::LayerCipher backward;
    };

    enum class Phase : std::uint8_t { Idle, Building, Ready, Closed };

    State(std::shared_ptr<providers::AsioExecutionContext> runner,
          std::shared_ptr<const cc::CircuitCrypto> circuit_crypto,
          std::shared_ptr<StreamResponder> stream,
          std::vector<providers::keys::CompositePublic> route_hops,
          std::vector<Fingerprint> route_fingerprints,
          ClientLimits client_limits)
        : context(std::move(runner)),
          crypto(std::move(circuit_crypto)),
          entry(std::move(stream)),
          route(std::move(route_hops)),
          fingerprints(std::move(route_fingerprints)),
          limits(client_limits),
          build_timer(context->executor()) {}

    std::shared_ptr<providers::AsioExecutionContext> context;
    std::shared_ptr<const cc::CircuitCrypto> crypto;
    std::shared_ptr<StreamResponder> entry;
    std::vector<providers::keys::CompositePublic> route;
    std::vector<Fingerprint> fingerprints;
    ClientLimits limits;
    std::vector<Layer> layers;
    std::optional<cc::ClientExchange> exchange;
    Clock::time_point sent_at{};
    std::vector<std::chrono::milliseconds> hop_times;
    std::optional<CircuitFailure> failure;
    std::function<void(Status)> built;
    Timer build_timer;
    Phase phase{Phase::Idle};
    CancellationSource cancel;
    bool reading{false};
    std::deque<Buffer> forward_queue;
    bool writing{false};
    std::uint32_t next_stream{1U};
    std::map<std::uint32_t, std::shared_ptr<detail::ClientStream>> streams;
    std::function<void()> closed_observer;

    void start_build(std::function<void(Status)> done) noexcept;
    void read() noexcept;
    void read_later() noexcept;
    void on_cell(Result<ReceivedRecord> result) noexcept;
    void handle(std::size_t hop, const c1::RelayMessageView& message);
    void add_layer(std::span<const std::uint8_t> answer);
    void extend();
    void become_ready() noexcept;
    void send_message(std::size_t target, c1::RelayType type,
                      std::uint32_t stream,
                      std::span<const std::uint8_t> payload);
    void queue_cell(c1::Result<std::vector<std::uint8_t>> cell);
    void write() noexcept;
    bool forward_room() const noexcept {
        return forward_queue.size() < limits.forward_queue_cells;
    }
    void resume_writers() noexcept;
    void open_stream(const ytp1::Destination& destination,
                     Opened done) noexcept;
    void fail(std::size_t hop, c1::CircuitReason reason) noexcept;
    void close(Status reason) noexcept;
    // How much a stream's window may grow now.
    std::uint32_t window_growth(std::uint32_t window) const noexcept;
};

namespace detail {

// One stream through the circuit's exit, as a byte stream. It opens as soon
// as BEGIN is on its way, and its first writes follow BEGIN within the window
// the exit grants every new stream, so a request does not wait a circuit
// round trip for CONNECTED. Reads hold the exit's window until their records
// are released. Every call runs on the circuit's context.
class ClientStream final : public StreamResponder,
                           public std::enable_shared_from_this<ClientStream> {
public:
    using State = ClientCircuit::State;

    ClientStream(std::weak_ptr<State> circuit, std::uint32_t id,
                 engine::ExecutorAffinity affinity, std::uint32_t window,
                 ClientCircuit::Opened opened)
        : circuit_(std::move(circuit)),
          id_(id),
          affinity_(affinity),
          window_(window),
          receive_allowed_(window),
          send_window_(window),
          opened_(std::move(opened)) {}

    engine::ExecutorAffinity executor_affinity() const noexcept override {
        return affinity_;
    }
    engine::ServiceKind service_kind() const noexcept override {
        return engine::ServiceKind::ByteStream;
    }
    std::size_t max_write_size() const noexcept override {
        return kMaxWriteSize;
    }
    bool terminated() const noexcept override { return terminated_.load(); }

    void async_read(CancellationToken cancellation,
                    ReadCompletion completion) override {
        if (pending_read_) {
            complete(
                std::move(completion),
                Result<ReceivedRecord>(Status(StatusCode::FailedPrecondition)));
            return;
        }
        pending_read_ = std::move(completion);
        if (cancellation.is_cancelled()) {
            finish_read(Result<ReceivedRecord>(Status(StatusCode::Cancelled)));
            return;
        }
        auto registration =
            cancellation.register_callback([weak = weak_from_this()] {
                const auto self = weak.lock();
                if (!self) return;
                const auto state = self->circuit_.lock();
                if (!state) return;
                try {
                    boost::asio::post(state->context->executor(), [weak] {
                        if (const auto stream = weak.lock()) {
                            stream->finish_read(Result<ReceivedRecord>(
                                Status(StatusCode::Cancelled)));
                        }
                    });
                } catch (...) {
                }
            });
        if (registration.ok())
            read_registration_ = std::move(registration).take_value();
        deliver();
    }

    void async_write(Buffer payload, CancellationToken,
                     WriteCompletion completion) override {
        if (terminated() || shutdown_) {
            complete_write(std::move(completion), Status(StatusCode::Closed),
                           0U);
            return;
        }
        const auto size = payload.size();
        if (size == 0U) {
            complete_write(std::move(completion), Status::success(), 0U);
            return;
        }
        writes_.push_back({std::move(payload), 0U, std::move(completion)});
        pump();
    }

    Status shutdown_write() noexcept override {
        if (terminated()) return Status(StatusCode::Closed);
        shutdown_ = true;
        pump();
        return Status::success();
    }

    void close(Status) noexcept override {
        if (terminated()) return;
        // Unless both sides finished, END closed ends both directions, even
        // after this side sent done, so the exit stops reading the
        // destination.
        const bool finished = end_sent_ && remote_done_;
        if (!finished) send_end(c1::StreamReason::Closed);
        abort(Status(StatusCode::Cancelled));
    }

    // From the circuit, once BEGIN is queued.
    void begun() noexcept {
        auto opened = std::move(opened_);
        if (opened) {
            complete_open(
                std::move(opened),
                Result<std::shared_ptr<StreamResponder>>(shared_from_this()));
        }
    }

    void connected() noexcept { connected_ = true; }

    bool is_connected() const noexcept { return connected_; }
    std::uint32_t window() const noexcept { return window_; }

    // Data from the exit, within the window this client granted.
    bool data(std::span<const std::uint8_t> payload) {
        if (!connected_ || remote_done_ || payload.size() > receive_allowed_)
            return false;
        auto buffer = buffer_of(payload);
        if (!buffer.ok()) throw buffer.status();
        receive_allowed_ -= static_cast<std::uint32_t>(payload.size());
        received_.push_back(std::move(buffer).take_value());
        deliver();
        return true;
    }

    void end(c1::StreamReason reason) noexcept {
        // Before CONNECTED the exit ends a stream only when it could not
        // reach the destination, which ends the stream's reads and writes.
        if (!connected_ || reason != c1::StreamReason::Done) {
            abort(status_for(reason));
            return;
        }
        remote_done_ = true;
        deliver();
        if (end_sent_) forget();
    }

    bool credit(std::uint32_t increment) noexcept {
        send_window_ += increment;
        if (send_window_ > c1::kMaxCreditIncrement) return false;
        pump();
        return true;
    }

    // The circuit ended, or this stream did.
    void abort(Status reason) noexcept {
        if (terminated_.exchange(true)) return;
        // Reads that come later end the same way.
        try {
            end_status_ = reason;
        } catch (...) {
            end_status_ = Status(reason.code());
        }
        auto opened = std::move(opened_);
        if (opened)
            complete_open(std::move(opened),
                          Result<std::shared_ptr<StreamResponder>>(reason));
        finish_read(Result<ReceivedRecord>(reason));
        auto writes = std::move(writes_);
        writes_.clear();
        for (auto& write : writes)
            complete_write(std::move(write.done), reason, write.offset);
        forget();
    }

    // Sends queued data while the exit's window and the circuit's queue
    // allow, then END once a shut-down stream has drained.
    void pump() noexcept {
        const auto state = circuit_.lock();
        if (!state || terminated()) return;
        try {
            while (!writes_.empty() && send_window_ > 0U &&
                   state->forward_room()) {
                auto& write = writes_.front();
                const auto chunk = std::min<std::size_t>(
                    {write.data.size() - write.offset,
                     static_cast<std::size_t>(send_window_), kDataPerCell});
                state->send_message(
                    state->route.size(), c1::RelayType::Data, id_,
                    bytes_of(write.data).subspan(write.offset, chunk));
                send_window_ -= chunk;
                write.offset += chunk;
                if (write.offset == write.data.size()) {
                    auto done = std::move(write.done);
                    const auto size = write.data.size();
                    writes_.pop_front();
                    complete_write(std::move(done), Status::success(), size);
                }
            }
            if (writes_.empty() && shutdown_ && !end_sent_) {
                send_end(c1::StreamReason::Done);
                if (remote_done_) forget();
            }
        } catch (...) {
            state->close(Status(StatusCode::Internal));
        }
    }

    bool has_writes() const noexcept { return !writes_.empty(); }

private:
    struct PendingWrite final {
        Buffer data;
        std::size_t offset{0U};
        WriteCompletion done;
    };

    void send_end(c1::StreamReason reason) noexcept {
        const auto state = circuit_.lock();
        auto& sent =
            reason == c1::StreamReason::Done ? end_sent_ : closed_sent_;
        if (!state || sent || state->phase != State::Phase::Ready) return;
        sent = true;
        try {
            state->send_message(
                state->route.size(), c1::RelayType::End, id_,
                std::array<std::uint8_t, 1>{static_cast<std::uint8_t>(reason)});
        } catch (...) {
            state->close(Status(StatusCode::Internal));
        }
    }

    // Hands a received record to a waiting read, or reports the end.
    void deliver() noexcept {
        if (!pending_read_) return;
        if (!received_.empty()) {
            auto buffer = std::move(received_.front());
            received_.pop_front();
            const auto size = buffer.size();
            CarrierCredit credit(
                size, [weak = weak_from_this()](std::size_t released) {
                    if (const auto self = weak.lock()) self->consumed(released);
                });
            finish_read(Result<ReceivedRecord>(
                ReceivedRecord(std::move(buffer), std::move(credit))));
            return;
        }
        if (remote_done_) {
            finish_read(
                Result<ReceivedRecord>(Status(StatusCode::EndOfStream)));
        } else if (terminated()) {
            try {
                finish_read(Result<ReceivedRecord>(end_status_));
            } catch (...) {
                finish_read(Result<ReceivedRecord>(end_status_.code()));
            }
        }
    }

    // The application released data: return window to the exit once half
    // of it has drained, and grow the window with the same credit, so a
    // stream on a long circuit is not held to its first window.
    void consumed(std::size_t released) noexcept {
        consumed_ += static_cast<std::uint32_t>(released);
        if (consumed_ < window_ / 2U || remote_done_ || terminated()) return;
        const auto state = circuit_.lock();
        if (!state || state->phase != State::Phase::Ready) return;
        const auto returned = consumed_;
        consumed_ = 0U;
        const auto growth = state->window_growth(window_);
        window_ += growth;
        receive_allowed_ += returned + growth;
        try {
            state->send_message(state->route.size(),
                                c1::RelayType::StreamCredit, id_,
                                u32(returned + growth));
        } catch (...) {
            state->close(Status(StatusCode::Internal));
        }
    }

    void finish_read(Result<ReceivedRecord> result) noexcept {
        auto completion = std::move(pending_read_);
        pending_read_ = nullptr;
        read_registration_.unregister();
        if (completion) complete(std::move(completion), std::move(result));
    }

    void forget() noexcept {
        if (const auto state = circuit_.lock()) state->streams.erase(id_);
    }

    // Completions run from the executor, never inside the caller.
    void complete(ReadCompletion completion,
                  Result<ReceivedRecord> result) noexcept {
        const auto state = circuit_.lock();
        try {
            if (!state) throw Status(StatusCode::Closed);
            auto shared =
                std::make_shared<Result<ReceivedRecord>>(std::move(result));
            boost::asio::post(
                state->context->executor(),
                [completion = std::move(completion), shared]() mutable {
                    try {
                        completion(std::move(*shared));
                    } catch (...) {
                    }
                });
        } catch (...) {
        }
    }

    void complete_write(WriteCompletion completion, Status status,
                        std::size_t size) noexcept {
        if (!completion) return;
        const auto state = circuit_.lock();
        try {
            if (!state) throw Status(StatusCode::Closed);
            boost::asio::post(
                state->context->executor(),
                [completion = std::move(completion), status, size] {
                    try {
                        completion(status, size);
                    } catch (...) {
                    }
                });
        } catch (...) {
        }
    }

    void complete_open(
        ClientCircuit::Opened opened,
        Result<std::shared_ptr<StreamResponder>> result) noexcept {
        const auto state = circuit_.lock();
        try {
            if (!state) throw Status(StatusCode::Closed);
            auto shared =
                std::make_shared<Result<std::shared_ptr<StreamResponder>>>(
                    std::move(result));
            boost::asio::post(state->context->executor(),
                              [opened = std::move(opened), shared]() mutable {
                                  try {
                                      opened(std::move(*shared));
                                  } catch (...) {
                                  }
                              });
        } catch (...) {
        }
    }

    std::weak_ptr<State> circuit_;
    std::uint32_t id_;
    engine::ExecutorAffinity affinity_;
    std::uint32_t window_;
    std::uint32_t receive_allowed_;
    std::uint32_t consumed_{0U};
    std::uint64_t send_window_;
    ClientCircuit::Opened opened_;
    bool connected_{false};
    bool remote_done_{false};
    bool shutdown_{false};
    bool end_sent_{false};
    bool closed_sent_{false};
    std::atomic<bool> terminated_{false};
    Status end_status_{StatusCode::Closed};
    std::deque<Buffer> received_;
    ReadCompletion pending_read_;
    CancellationRegistration read_registration_;
    std::deque<PendingWrite> writes_;
};

}  // namespace detail

void ClientCircuit::State::start_build(
    std::function<void(Status)> done) noexcept {
    built = std::move(done);
    if (phase != Phase::Idle) {
        close(Status(StatusCode::FailedPrecondition));
        return;
    }
    phase = Phase::Building;
    try {
        build_timer.expires_after(limits.build_timeout);
        build_timer.async_wait(
            [weak = weak_from_this()](const boost::system::error_code& error) {
                const auto self = weak.lock();
                if (!self || error || self->phase != Phase::Building) return;
                // The hop being extended to did not answer.
                self->fail(self->layers.size() + 1U,
                           c1::CircuitReason::Timeout);
            });
        auto started = cc::ClientExchange::start(*crypto);
        if (!started.ok()) {
            fail(0U, c1::CircuitReason::Protocol);
            return;
        }
        exchange.emplace(std::move(started).take_value());
        auto body = c1::EncodeCreate(1U, exchange->message());
        if (!body.ok()) {
            fail(0U, c1::CircuitReason::Protocol);
            return;
        }
        sent_at = Clock::now();
        queue_cell(c1::EncodeCell(c1::Direction::Forward, c1::Command::Create,
                                  c1::kCreateBucket, *body.value));
        read();
    } catch (...) {
        close(Status(StatusCode::Internal));
    }
}

void ClientCircuit::State::read_later() noexcept {
    try {
        boost::asio::post(context->executor(), [weak = weak_from_this()] {
            if (const auto self = weak.lock()) self->read();
        });
    } catch (...) {
        close(Status(StatusCode::ResourceExhausted));
    }
}

void ClientCircuit::State::read() noexcept {
    if (phase == Phase::Closed || reading) return;
    reading = true;
    try {
        entry->async_read(cancel.token(), [self = shared_from_this()](
                                              Result<ReceivedRecord> result) {
            self->on_cell(std::move(result));
        });
    } catch (...) {
        reading = false;
        close(Status(StatusCode::Internal));
    }
}

void ClientCircuit::State::on_cell(Result<ReceivedRecord> result) noexcept {
    reading = false;
    if (phase == Phase::Closed) return;
    if (!result.ok()) {
        fail(0U, c1::CircuitReason::Unreachable);
        return;
    }
    try {
        auto record = std::move(result).take_value();
        const auto cell =
            c1::DecodeCell(c1::Direction::Backward, bytes_of(record.payload()));
        if (!cell.ok()) {
            fail(0U, c1::CircuitReason::Protocol);
            return;
        }
        if (layers.empty()) {
            if (cell.value->command != c1::Command::Created) {
                fail(0U, c1::CircuitReason::Protocol);
                return;
            }
            add_layer(cell.value->body);
            read_later();
            return;
        }
        if (cell.value->command != c1::Command::Relay ||
            cell.value->layers > layers.size()) {
            fail(0U, c1::CircuitReason::Protocol);
            return;
        }
        std::vector<std::uint8_t> body(cell.value->body.begin(),
                                       cell.value->body.end());
        for (std::size_t index = 0U; index < cell.value->layers; ++index) {
            std::vector<std::uint8_t> opened(body.size() - c1::kLayerTagBytes);
            if (!layers[index]
                     .backward.open(cell.value->bucket, body, opened)
                     .ok()) {
                fail(0U, c1::CircuitReason::Protocol);
                return;
            }
            body = std::move(opened);
        }
        const auto message =
            c1::DecodeRelayMessage(c1::Direction::Backward, body);
        if (!message.ok()) {
            fail(0U, c1::CircuitReason::Protocol);
            return;
        }
        handle(cell.value->layers, *message.value);
        read_later();
    } catch (...) {
        close(Status(StatusCode::Internal));
    }
}

void ClientCircuit::State::handle(std::size_t hop,
                                  const c1::RelayMessageView& message) {
    using Type = c1::RelayType;
    if (message.type == Type::CircuitFailed) {
        fail(hop, static_cast<c1::CircuitReason>(message.payload[0]));
        return;
    }
    if (phase == Phase::Building) {
        if (hop != layers.size()) {
            fail(0U, c1::CircuitReason::Protocol);
            return;
        }
        if (message.type == Type::Extended) {
            add_layer(message.payload);
            return;
        }
        if (message.type == Type::ExtendFailed) {
            // The hop that failed to extend reported it. The next one, which
            // it could not reach, is the one to avoid.
            fail(hop + 1U, static_cast<c1::CircuitReason>(message.payload[0]));
            return;
        }
        fail(0U, c1::CircuitReason::Protocol);
        return;
    }
    if (phase != Phase::Ready || hop != route.size()) {
        fail(0U, c1::CircuitReason::Protocol);
        return;
    }
    const auto found = streams.find(message.stream);
    // A stream this client already ended may still see messages that
    // crossed its END.
    if (found == streams.end()) return;
    const auto stream = found->second;
    switch (message.type) {
        case Type::Connected:
            if (stream->is_connected()) {
                fail(0U, c1::CircuitReason::Protocol);
                return;
            }
            stream->connected();
            return;
        case Type::Data:
            if (!stream->data(message.payload))
                fail(0U, c1::CircuitReason::Protocol);
            return;
        case Type::End:
            stream->end(static_cast<c1::StreamReason>(message.payload[0]));
            return;
        case Type::StreamCredit: {
            const std::uint32_t increment =
                (static_cast<std::uint32_t>(message.payload[0]) << 24U) |
                (static_cast<std::uint32_t>(message.payload[1]) << 16U) |
                (static_cast<std::uint32_t>(message.payload[2]) << 8U) |
                static_cast<std::uint32_t>(message.payload[3]);
            if (!stream->credit(increment))
                fail(0U, c1::CircuitReason::Protocol);
            return;
        }
        default:
            fail(0U, c1::CircuitReason::Protocol);
    }
}

// Checks the answer of the hop at the next position and keeps its layer.
void ClientCircuit::State::add_layer(std::span<const std::uint8_t> answer) {
    const auto position = layers.size();
    const Fingerprint predecessor =
        position == 0U ? Fingerprint{} : fingerprints[position - 1U];
    auto keys = exchange->finish(*crypto, answer, route[position], predecessor,
                                 static_cast<std::uint8_t>(position + 1U));
    exchange.reset();
    if (!keys.ok()) {
        fail(position + 1U, c1::CircuitReason::Protocol);
        return;
    }
    hop_times.push_back(std::chrono::duration_cast<std::chrono::milliseconds>(
        Clock::now() - sent_at));
    using Mode = cc::LayerCipher::Mode;
    const auto& hop = keys.value();
    layers.push_back(Layer{
        cc::LayerCipher(*crypto, Mode::Seal, c1::Direction::Forward,
                        hop.forward_key.span(), hop.forward_iv.span()),
        cc::LayerCipher(*crypto, Mode::Open, c1::Direction::Backward,
                        hop.backward_key.span(), hop.backward_iv.span())});
    if (layers.size() == route.size()) {
        become_ready();
    } else {
        extend();
    }
}

void ClientCircuit::State::extend() {
    auto started = cc::ClientExchange::start(*crypto);
    if (!started.ok()) {
        fail(0U, c1::CircuitReason::Protocol);
        return;
    }
    exchange.emplace(std::move(started).take_value());
    const auto payload = c1::EncodeExtendPayload(fingerprints[layers.size()],
                                                 exchange->message());
    sent_at = Clock::now();
    send_message(layers.size(), c1::RelayType::Extend, 0U, payload);
}

void ClientCircuit::State::become_ready() noexcept {
    phase = Phase::Ready;
    boost::system::error_code ignored;
    build_timer.cancel(ignored);
    auto done = std::move(built);
    built = nullptr;
    if (done) {
        try {
            done(Status::success());
        } catch (...) {
        }
    }
}

// Pads a relay message and seals it with every layer from the target hop
// back to the entry, the target's innermost.
void ClientCircuit::State::send_message(std::size_t target, c1::RelayType type,
                                        std::uint32_t stream,
                                        std::span<const std::uint8_t> payload) {
    const auto bucket =
        c1::BucketForPayload(c1::Direction::Forward, payload.size());
    if (!bucket || target == 0U || target > layers.size()) {
        throw Status(StatusCode::InvalidArgument);
    }
    std::vector<std::uint8_t> body(
        c1::RelayCapacity(c1::Direction::Forward, *bucket));
    if (!c1::EncodeRelayMessage(c1::Direction::Forward, type, stream, payload,
                                body)
             .ok()) {
        throw Status(StatusCode::InvalidArgument);
    }
    for (std::size_t index = target; index-- > 0U;) {
        std::vector<std::uint8_t> sealed(body.size() + c1::kLayerTagBytes);
        if (!layers[index].forward.seal(*bucket, body, sealed).ok()) {
            throw Status(StatusCode::Internal);
        }
        body = std::move(sealed);
    }
    queue_cell(c1::EncodeCell(c1::Direction::Forward, c1::Command::Relay,
                              *bucket, body));
}

void ClientCircuit::State::queue_cell(
    c1::Result<std::vector<std::uint8_t>> cell) {
    if (!cell.ok()) throw Status(StatusCode::Internal);
    auto buffer = buffer_of(*cell.value);
    if (!buffer.ok()) throw buffer.status();
    forward_queue.push_back(std::move(buffer).take_value());
    write();
}

void ClientCircuit::State::write() noexcept {
    if (phase == Phase::Closed || writing || forward_queue.empty()) return;
    writing = true;
    try {
        entry->async_write(
            std::move(forward_queue.front()), cancel.token(),
            [self = shared_from_this()](Status status, std::size_t) {
                self->writing = false;
                if (self->phase == Phase::Closed) return;
                if (!status.ok()) {
                    self->fail(0U, c1::CircuitReason::Unreachable);
                    return;
                }
                self->forward_queue.pop_front();
                self->write();
                self->resume_writers();
            });
    } catch (...) {
        writing = false;
        close(Status(StatusCode::Internal));
    }
}

// A stream's pump can end its stream, so this walks a copy.
void ClientCircuit::State::resume_writers() noexcept {
    if (phase != Phase::Ready || streams.empty() || !forward_room()) return;
    std::vector<std::shared_ptr<detail::ClientStream>> waiting;
    try {
        for (const auto& [id, stream] : streams) {
            if (stream->has_writes()) waiting.push_back(stream);
        }
    } catch (...) {
        close(Status(StatusCode::ResourceExhausted));
        return;
    }
    for (const auto& stream : waiting) {
        if (phase != Phase::Ready) return;
        stream->pump();
    }
}

void ClientCircuit::State::open_stream(const ytp1::Destination& destination,
                                       Opened done) noexcept {
    const auto refuse = [&](Status status) {
        try {
            boost::asio::post(context->executor(), [done = std::move(done),
                                                    status]() mutable {
                try {
                    done(Result<std::shared_ptr<StreamResponder>>(status));
                } catch (...) {
                }
            });
        } catch (...) {
        }
    };
    if (phase != Phase::Ready)
        return refuse(Status(StatusCode::FailedPrecondition));
    if (streams.size() >= limits.streams_per_circuit || next_stream == 0U) {
        return refuse(Status(StatusCode::ResourceExhausted));
    }
    try {
        auto payload = c1::EncodeBeginPayload(destination);
        if (!payload.ok()) return refuse(Status(StatusCode::InvalidArgument));
        const auto id = next_stream++;
        auto stream = std::make_shared<detail::ClientStream>(
            weak_from_this(), id, context->affinity(), limits.stream_window,
            std::move(done));
        streams.emplace(id, stream);
        send_message(route.size(), c1::RelayType::Begin, id, *payload.value);
        stream->begun();
    } catch (...) {
        close(Status(StatusCode::Internal));
    }
}

std::uint32_t ClientCircuit::State::window_growth(
    std::uint32_t window) const noexcept {
    if (window >= limits.max_stream_window) return 0U;
    const std::uint32_t growth =
        std::min(window, limits.max_stream_window - window);
    std::uint64_t granted = growth;
    for (const auto& [id, stream] : streams) granted += stream->window();
    return granted <= limits.circuit_window ? growth : 0U;
}

void ClientCircuit::State::fail(std::size_t hop,
                                c1::CircuitReason reason) noexcept {
    if (phase == Phase::Closed) return;
    failure = CircuitFailure{hop, reason};
    close(Status::diagnostic(StatusCode::Closed, "the circuit failed"));
}

void ClientCircuit::State::close(Status reason) noexcept {
    if (phase == Phase::Closed) return;
    phase = Phase::Closed;
    if (!failure) failure = CircuitFailure{0U, c1::CircuitReason::Closing};
    cancel.cancel();
    boost::system::error_code ignored;
    build_timer.cancel(ignored);
    entry->close(Status(StatusCode::Cancelled));
    forward_queue.clear();
    exchange.reset();
    auto ending = std::move(streams);
    streams.clear();
    for (auto& [id, stream] : ending) stream->abort(reason);
    auto done = std::move(built);
    built = nullptr;
    if (done) {
        try {
            done(reason);
        } catch (...) {
        }
    }
    auto observer = std::move(closed_observer);
    closed_observer = nullptr;
    if (observer) {
        try {
            observer();
        } catch (...) {
        }
    }
}

Result<std::shared_ptr<ClientCircuit>> ClientCircuit::create(
    std::shared_ptr<providers::AsioExecutionContext> context,
    std::shared_ptr<const cc::CircuitCrypto> crypto,
    std::shared_ptr<StreamResponder> entry,
    std::vector<providers::keys::CompositePublic> hops, ClientLimits limits) {
    using Created = Result<std::shared_ptr<ClientCircuit>>;
    if (!context || !crypto || !entry || hops.empty() ||
        hops.size() > c1::kMaxHops) {
        return Created(Status(StatusCode::InvalidArgument));
    }
    try {
        std::vector<Fingerprint> fingerprints;
        for (const auto& hop : hops) {
            const auto fingerprint = cc::fingerprint_bytes(hop.fingerprint);
            if (!fingerprint)
                return Created(Status(StatusCode::InvalidArgument));
            fingerprints.push_back(*fingerprint);
        }
        auto state = std::make_shared<State>(
            std::move(context), std::move(crypto), std::move(entry),
            std::move(hops), std::move(fingerprints), limits);
        return Created(std::shared_ptr<ClientCircuit>(
            new ClientCircuit(std::move(state))));
    } catch (const std::bad_alloc&) {
        return Created(Status(StatusCode::ResourceExhausted));
    }
}

ClientCircuit::ClientCircuit(std::shared_ptr<State> state) noexcept
    : state_(std::move(state)) {}

ClientCircuit::~ClientCircuit() {
    close();
}

void ClientCircuit::build(std::function<void(Status)> done) noexcept {
    state_->start_build(std::move(done));
}

void ClientCircuit::open_stream(const ytp1::Destination& destination,
                                Opened done) noexcept {
    state_->open_stream(destination, std::move(done));
}

std::optional<CircuitFailure> ClientCircuit::failure() const noexcept {
    return state_->failure;
}

std::vector<std::chrono::milliseconds> ClientCircuit::hop_times() const {
    return state_->hop_times;
}

bool ClientCircuit::ready() const noexcept {
    return state_->phase == State::Phase::Ready;
}

bool ClientCircuit::closed() const noexcept {
    return state_->phase == State::Phase::Closed;
}

std::size_t ClientCircuit::streams() const noexcept {
    return state_->streams.size();
}

void ClientCircuit::on_closed(std::function<void()> observer) noexcept {
    state_->closed_observer = std::move(observer);
}

void ClientCircuit::close() noexcept {
    state_->close(Status(StatusCode::Cancelled));
}

}  // namespace yume::runtime::circuit
