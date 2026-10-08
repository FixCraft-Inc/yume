/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/circuit_node.hpp"

#include <algorithm>
#include <deque>
#include <map>
#include <new>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

#include <boost/asio/basic_waitable_timer.hpp>
#include <boost/asio/post.hpp>

#include "circuit/protocol.hpp"
#include "common/hex.hpp"

namespace yume::runtime::circuit {
namespace {

namespace c1 = yume::circuit1;
namespace cc = yume::providers::circuit;
using engine::Buffer;
using engine::ByteChannel;
using engine::CancellationSource;
using engine::ReceivedRecord;
using engine::Result;
using engine::Status;
using engine::StatusCode;
using engine::StreamResponder;
using Clock = std::chrono::steady_clock;
using Timer = boost::asio::basic_waitable_timer<
    Clock, boost::asio::wait_traits<Clock>,
    providers::AsioExecutionContext::Executor>;

constexpr auto kSweepInterval = std::chrono::seconds(5);

std::span<const std::uint8_t> bytes_of(const Buffer& buffer) noexcept {
    return {reinterpret_cast<const std::uint8_t*>(buffer.bytes().data()),
            buffer.size()};
}

Result<Buffer> buffer_of(std::span<const std::uint8_t> bytes) {
    return Buffer::copy_from(std::as_bytes(bytes), c1::kMaxCellBytes);
}

struct TokenBucket final {
    double rate{0.0};
    double burst{0.0};
    double tokens{0.0};
    Clock::time_point last{};

    TokenBucket(double per_second, double capacity) noexcept
        : rate(per_second),
          burst(capacity),
          tokens(capacity),
          last(Clock::now()) {}

    void refill(Clock::time_point now) noexcept {
        const std::chrono::duration<double> elapsed = now - last;
        tokens = std::min(burst, tokens + elapsed.count() * rate);
        last = now;
    }
    bool take(Clock::time_point now) noexcept {
        refill(now);
        if (tokens < 1.0) return false;
        tokens -= 1.0;
        return true;
    }
};

// What a failed destination open tells the client. The route provider
// reports a failed lookup and a failed connection alike as NotFound, so only
// a name can be name not found, and it reports a connect timeout as Closed.
c1::StreamReason exit_reason(const Status& status, bool named) noexcept {
    switch (status.code()) {
        case StatusCode::PermissionDenied:
            return c1::StreamReason::Policy;
        case StatusCode::NotFound:
            return named ? c1::StreamReason::NameNotFound
                         : c1::StreamReason::Unreachable;
        case StatusCode::ResourceExhausted:
            return c1::StreamReason::Resources;
        case StatusCode::Closed:
            return c1::StreamReason::Timeout;
        case StatusCode::Cancelled:
            return c1::StreamReason::Closed;
        default:
            return c1::StreamReason::Unreachable;
    }
}

// What a failed extension tells the client.
c1::CircuitReason extend_reason(const Status& status) noexcept {
    switch (status.code()) {
        case StatusCode::NotFound:
            return c1::CircuitReason::Refused;
        case StatusCode::ResourceExhausted:
            return c1::CircuitReason::Busy;
        default:
            return c1::CircuitReason::Unreachable;
    }
}

}  // namespace

namespace detail {
class Circuit;
}  // namespace detail

struct CircuitService::Node final {
    Node(NodeEnvironment environment, engine::ProviderDescriptor provider,
         Fingerprint own)
        : env(std::move(environment)),
          descriptor(std::move(provider)),
          self(own),
          handshakes(env.limits.handshakes_per_second,
                     env.limits.handshake_burst),
          sweep(env.context->executor()) {}

    struct Origin final {
        std::size_t circuits{0U};
        TokenBucket bucket;
    };

    NodeEnvironment env;
    engine::ProviderDescriptor descriptor;
    Fingerprint self;
    TokenBucket handshakes;
    std::unordered_map<std::string, Origin> origins;
    std::vector<std::weak_ptr<detail::Circuit>> circuits;
    std::uint64_t refused_client_circuits{0U};
    std::uint64_t refused_circuit_rate{0U};
    std::uint64_t refused_handshakes{0U};
    std::uint64_t refused_streams{0U};
    std::uint64_t failed{0U};
    Timer sweep;
    bool sweeping{false};
    bool closed{false};

    void arm_sweep(const std::shared_ptr<Node>& self_pointer) noexcept;
    void sweep_now() noexcept;
};

namespace detail {

// One circuit at this node: its stream from the previous hop, its keys, and
// either a stream to the next hop or, at an exit, its streams to their
// destinations. Every call and callback runs on the node's context.
class Circuit final : public std::enable_shared_from_this<Circuit> {
public:
    using Node = CircuitService::Node;

    Circuit(std::shared_ptr<Node> node,
            std::shared_ptr<StreamResponder> inbound, bool from_peer,
            Fingerprint predecessor, engine::StreamOpenContext origin)
        : node_(std::move(node)),
          inbound_(std::move(inbound)),
          from_peer_(from_peer),
          predecessor_(predecessor),
          origin_(std::move(origin)) {}

    void start() noexcept { read_inbound(); }

    bool closed() const noexcept { return closed_; }
    std::uint8_t depth() const noexcept { return depth_; }
    bool relayed() const noexcept {
        return next_ != nullptr && phase_ == Phase::Extended;
    }
    std::size_t streams() const noexcept { return streams_.size(); }
    const std::string& origin() const noexcept {
        return origin_.peer_evidence().identity();
    }
    bool from_peer() const noexcept { return from_peer_; }
    // The peer this circuit was extended to, while it is relayed.
    const std::string& next_peer() const noexcept { return next_peer_; }

    // Ends a circuit whose cell waited too long or whose extension hung.
    void sweep(Clock::time_point now) noexcept {
        const auto& limits = node_->env.limits;
        const bool stalled =
            (forward_since_ && now - *forward_since_ > limits.stall_timeout) ||
            (backward_since_ && now - *backward_since_ > limits.stall_timeout);
        if (stalled) {
            close(true);
            return;
        }
        if (extend_since_ && now - *extend_since_ > limits.extend_timeout) {
            abandon_extension(c1::CircuitReason::Timeout);
        }
    }

    void close(bool failure) noexcept {
        if (closed_) return;
        closed_ = true;
        cancel_.cancel();
        const Status reason(StatusCode::Cancelled);
        if (inbound_) inbound_->close(reason);
        if (next_) next_->close(reason);
        for (auto& [id, stream] : streams_) {
            stream->cancel.cancel();
            if (stream->channel) {
                stream->channel->cancel();
                stream->channel->close();
            }
        }
        streams_.clear();
        backward_queue_.clear();
        if (failure) ++node_->failed;
        const auto found = node_->origins.find(origin());
        if (found != node_->origins.end() && found->second.circuits > 0U) {
            --found->second.circuits;
        }
    }

private:
    enum class Phase : std::uint8_t { AwaitCreate, Open, Extending, Extended };

    struct Outgoing final {
        Buffer cell;
        std::optional<ReceivedRecord> hold;
        // After the write completes: read the next hop's next cell.
        bool resume_next{false};
    };

    struct ExitStream final {
        std::uint32_t id{0U};
        std::unique_ptr<ByteChannel> channel;
        CancellationSource cancel;
        std::deque<Buffer> to_destination;
        bool writing{false};
        bool reading{false};
        std::uint32_t receive_allowed{0U};
        std::uint32_t consumed{0U};
        std::uint64_t send_window{0U};
        bool client_done{false};
        bool destination_done{false};
        bool shut{false};
        bool named{false};
    };

    // Reads the next cell from the previous hop, from the executor rather
    // than inline, so a run of queued cells never recurses. A circuit lives
    // as long as an operation of its own is pending, so this holds it too.
    void read_inbound_later() noexcept {
        try {
            boost::asio::post(
                node_->env.context->executor(),
                [self = shared_from_this()] { self->read_inbound(); });
        } catch (...) {
            close(true);
        }
    }

    void read_inbound() noexcept {
        if (closed_ || reading_inbound_) return;
        reading_inbound_ = true;
        try {
            inbound_->async_read(
                cancel_.token(),
                [self = shared_from_this()](Result<ReceivedRecord> result) {
                    self->on_inbound(std::move(result));
                });
        } catch (...) {
            reading_inbound_ = false;
            close(true);
        }
    }

    void on_inbound(Result<ReceivedRecord> result) noexcept {
        reading_inbound_ = false;
        if (closed_) return;
        if (!result.ok()) {
            // The previous hop ended the circuit, or its session did.
            close(result.status().code() != StatusCode::EndOfStream &&
                  result.status().code() != StatusCode::Cancelled);
            return;
        }
        try {
            auto record = std::move(result).take_value();
            const auto decoded = c1::DecodeCell(c1::Direction::Forward,
                                                bytes_of(record.payload()));
            if (!decoded.ok()) {
                close(true);
                return;
            }
            if (phase_ == Phase::AwaitCreate) {
                if (decoded.value->command != c1::Command::Create) {
                    close(true);
                    return;
                }
                handle_create(decoded.value->body);
                return;
            }
            if (decoded.value->command != c1::Command::Relay) {
                close(true);
                return;
            }
            handle_relay(*decoded.value, std::move(record));
        } catch (...) {
            close(true);
        }
    }

    void handle_create(std::span<const std::uint8_t> body) {
        const auto create = c1::DecodeCreate(body);
        const bool depth_fits =
            create.ok() && (from_peer_ ? create.value->depth >= 2U
                                       : create.value->depth == 1U);
        if (!depth_fits) {
            close(true);
            return;
        }
        if (!node_->handshakes.take(Clock::now())) {
            ++node_->refused_handshakes;
            close(false);
            return;
        }
        auto answered =
            cc::answer(*node_->env.crypto, create.value->client_handshake,
                       *node_->env.identity, predecessor_, create.value->depth);
        if (!answered.ok()) {
            close(true);
            return;
        }
        auto reply = std::move(answered).take_value();
        using Mode = cc::LayerCipher::Mode;
        forward_.emplace(*node_->env.crypto, Mode::Open, c1::Direction::Forward,
                         reply.keys.forward_key.span(),
                         reply.keys.forward_iv.span());
        backward_.emplace(
            *node_->env.crypto, Mode::Seal, c1::Direction::Backward,
            reply.keys.backward_key.span(), reply.keys.backward_iv.span());
        depth_ = create.value->depth;
        auto cell =
            c1::EncodeCell(c1::Direction::Backward, c1::Command::Created,
                           c1::kCreatedBucket, reply.message);
        auto buffer = cell.ok() ? buffer_of(*cell.value)
                                : Result<Buffer>(Status(StatusCode::Internal));
        if (!buffer.ok()) {
            close(true);
            return;
        }
        phase_ = Phase::Open;
        enqueue({std::move(buffer).take_value(), std::nullopt, false});
        read_inbound_later();
    }

    void handle_relay(const c1::CellView& cell, ReceivedRecord record) {
        std::vector<std::uint8_t> plain(cell.body.size() - c1::kLayerTagBytes);
        if (!forward_->open(cell.bucket, cell.body, plain).ok()) {
            close(true);
            return;
        }
        if (cell.layers > 1U) {
            if (phase_ != Phase::Extended) {
                close(true);
                return;
            }
            forward(cell.bucket, plain, std::move(record));
            return;
        }
        const auto message =
            c1::DecodeRelayMessage(c1::Direction::Forward, plain);
        if (!message.ok()) {
            close(true);
            return;
        }
        handle_message(*message.value);
        read_inbound_later();
    }

    // Passes a cell with layers left to the next hop and reads the previous
    // hop again only once the next hop has taken it, so a slow hop slows the
    // one before it. The record's credit is held until then.
    void forward(std::size_t bucket, std::span<const std::uint8_t> body,
                 ReceivedRecord record) {
        auto cell = c1::EncodeCell(c1::Direction::Forward, c1::Command::Relay,
                                   bucket, body);
        auto buffer = cell.ok() ? buffer_of(*cell.value)
                                : Result<Buffer>(Status(StatusCode::Internal));
        if (!buffer.ok()) {
            close(true);
            return;
        }
        forward_since_ = Clock::now();
        auto held = std::make_shared<ReceivedRecord>(std::move(record));
        next_->async_write(
            std::move(buffer).take_value(), cancel_.token(),
            [self = shared_from_this(), held](Status status, std::size_t) {
                self->forward_since_.reset();
                if (self->closed_) return;
                if (!status.ok()) {
                    self->next_ended();
                    return;
                }
                self->read_inbound();
            });
    }

    void handle_message(const c1::RelayMessageView& message) {
        switch (message.type) {
            case c1::RelayType::Extend:
                return extend(message.payload);
            case c1::RelayType::Begin:
                return begin(message.stream, message.payload);
            case c1::RelayType::Data:
                return data(message.stream, message.payload);
            case c1::RelayType::End:
                return end(message.stream, message.payload);
            case c1::RelayType::StreamCredit:
                return credit(message.stream, message.payload);
            default:
                close(true);
        }
    }

    void extend(std::span<const std::uint8_t> payload) {
        const auto request = c1::DecodeExtendPayload(payload);
        if (!request.ok() || phase_ != Phase::Open || terminal_ ||
            depth_ >= c1::kMaxHops) {
            close(true);
            return;
        }
        const auto next =
            std::vector<std::uint8_t>(request.value->next_identity.begin(),
                                      request.value->next_identity.end());
        if (std::equal(next.begin(), next.end(), node_->self.begin()) ||
            (from_peer_ &&
             std::equal(next.begin(), next.end(), predecessor_.begin()))) {
            send(c1::RelayType::ExtendFailed, 0U,
                 std::array<std::uint8_t, 1>{
                     static_cast<std::uint8_t>(c1::CircuitReason::Refused)});
            return;
        }
        phase_ = Phase::Extending;
        extend_since_ = Clock::now();
        next_peer_ = encoding::hex_lower(next);
        create_body_.assign(payload.begin() + c1::kFingerprintBytes,
                            payload.end());
        node_->env.open_next(
            next_peer_, cancel_.token(),
            [self = shared_from_this()](
                Result<std::shared_ptr<StreamResponder>> opened) {
                self->on_next_open(std::move(opened));
            });
    }

    void on_next_open(
        Result<std::shared_ptr<StreamResponder>> opened) noexcept {
        if (closed_) {
            if (opened.ok())
                opened.value()->close(Status(StatusCode::Cancelled));
            return;
        }
        if (phase_ != Phase::Extending) {
            if (opened.ok())
                opened.value()->close(Status(StatusCode::Cancelled));
            return;
        }
        if (!opened.ok()) {
            abandon_extension(extend_reason(opened.status()));
            return;
        }
        try {
            next_ = std::move(opened).take_value();
            auto body = c1::EncodeCreate(
                static_cast<std::uint8_t>(depth_ + 1U),
                std::span<const std::uint8_t, c1::kClientHandshakeBytes>(
                    create_body_.data(), create_body_.size()));
            auto cell = body.ok()
                            ? c1::EncodeCell(c1::Direction::Forward,
                                             c1::Command::Create,
                                             c1::kCreateBucket, *body.value)
                            : c1::Result<std::vector<std::uint8_t>>{
                                  body.status, std::nullopt};
            auto buffer =
                cell.ok() ? buffer_of(*cell.value)
                          : Result<Buffer>(Status(StatusCode::InvalidArgument));
            if (!buffer.ok()) {
                abandon_extension(c1::CircuitReason::Protocol);
                return;
            }
            next_->async_write(
                std::move(buffer).take_value(), cancel_.token(),
                [self = shared_from_this()](Status status, std::size_t) {
                    if (self->closed_ || self->phase_ != Phase::Extending)
                        return;
                    if (!status.ok()) {
                        self->abandon_extension(c1::CircuitReason::Unreachable);
                        return;
                    }
                    self->read_created();
                });
        } catch (...) {
            abandon_extension(c1::CircuitReason::Unreachable);
        }
    }

    void read_created() noexcept {
        try {
            next_->async_read(
                cancel_.token(),
                [self = shared_from_this()](Result<ReceivedRecord> result) {
                    self->on_created(std::move(result));
                });
        } catch (...) {
            abandon_extension(c1::CircuitReason::Unreachable);
        }
    }

    void on_created(Result<ReceivedRecord> result) noexcept {
        if (closed_ || phase_ != Phase::Extending) return;
        if (!result.ok()) {
            abandon_extension(c1::CircuitReason::Unreachable);
            return;
        }
        try {
            auto record = std::move(result).take_value();
            const auto cell = c1::DecodeCell(c1::Direction::Backward,
                                             bytes_of(record.payload()));
            if (!cell.ok() || cell.value->command != c1::Command::Created) {
                abandon_extension(c1::CircuitReason::Protocol);
                return;
            }
            extend_since_.reset();
            create_body_.clear();
            phase_ = Phase::Extended;
            send(c1::RelayType::Extended, 0U, cell.value->body);
            read_next();
        } catch (...) {
            close(true);
        }
    }

    // A failed or timed-out extension leaves the circuit usable at this hop.
    void abandon_extension(c1::CircuitReason reason) noexcept {
        if (closed_ || phase_ != Phase::Extending) return;
        extend_since_.reset();
        create_body_.clear();
        if (next_) {
            next_->close(Status(StatusCode::Cancelled));
            next_.reset();
        }
        phase_ = Phase::Open;
        try {
            send(
                c1::RelayType::ExtendFailed, 0U,
                std::array<std::uint8_t, 1>{static_cast<std::uint8_t>(reason)});
        } catch (...) {
            close(true);
        }
    }

    // Reads the next hop's next backward cell once the previous one has been
    // written back, so the previous hop's pace holds the next one.
    void read_next() noexcept {
        if (closed_ || reading_next_ || !next_) return;
        reading_next_ = true;
        try {
            next_->async_read(
                cancel_.token(),
                [self = shared_from_this()](Result<ReceivedRecord> result) {
                    self->on_next(std::move(result));
                });
        } catch (...) {
            reading_next_ = false;
            close(true);
        }
    }

    void on_next(Result<ReceivedRecord> result) noexcept {
        reading_next_ = false;
        if (closed_) return;
        if (!result.ok()) {
            next_ended();
            return;
        }
        try {
            auto record = std::move(result).take_value();
            const auto cell = c1::DecodeCell(c1::Direction::Backward,
                                             bytes_of(record.payload()));
            if (!cell.ok() || cell.value->command != c1::Command::Relay ||
                cell.value->layers >= c1::kMaxHops) {
                close(true);
                return;
            }
            std::vector<std::uint8_t> body(cell.value->body.size() +
                                           c1::kLayerTagBytes);
            if (!backward_->seal(cell.value->bucket, cell.value->body, body)
                     .ok()) {
                close(true);
                return;
            }
            auto encoded =
                c1::EncodeCell(c1::Direction::Backward, c1::Command::Relay,
                               cell.value->bucket, body);
            auto buffer = encoded.ok()
                              ? buffer_of(*encoded.value)
                              : Result<Buffer>(Status(StatusCode::Internal));
            if (!buffer.ok()) {
                close(true);
                return;
            }
            enqueue({std::move(buffer).take_value(), std::move(record), true});
        } catch (...) {
            close(true);
        }
    }

    // The next hop or its link ended: tell the client, then end the circuit
    // once that message has gone back.
    void next_ended() noexcept {
        if (closed_ || closing_) return;
        closing_ = true;
        try {
            send(c1::RelayType::CircuitFailed, 0U,
                 std::array<std::uint8_t, 1>{static_cast<std::uint8_t>(
                     c1::CircuitReason::Unreachable)});
        } catch (...) {
            close(true);
        }
    }

    // Seals a relay message under this hop's backward layer and queues it.
    void send(c1::RelayType type, std::uint32_t stream,
              std::span<const std::uint8_t> payload) {
        const auto bucket =
            c1::BucketForPayload(c1::Direction::Backward, payload.size());
        if (!bucket) throw Status(StatusCode::InvalidArgument);
        std::vector<std::uint8_t> plain(
            c1::RelayCapacity(c1::Direction::Backward, *bucket));
        if (!c1::EncodeRelayMessage(c1::Direction::Backward, type, stream,
                                    payload, plain)
                 .ok()) {
            throw Status(StatusCode::InvalidArgument);
        }
        std::vector<std::uint8_t> body(plain.size() + c1::kLayerTagBytes);
        if (!backward_->seal(*bucket, plain, body).ok()) {
            throw Status(StatusCode::Internal);
        }
        auto cell = c1::EncodeCell(c1::Direction::Backward, c1::Command::Relay,
                                   *bucket, body);
        auto buffer = cell.ok() ? buffer_of(*cell.value)
                                : Result<Buffer>(Status(StatusCode::Internal));
        if (!buffer.ok()) throw buffer.status();
        enqueue({std::move(buffer).take_value(), std::nullopt, false});
    }

    // Backward cells leave in the order they were sealed, one write at a
    // time.
    void enqueue(Outgoing outgoing) {
        backward_queue_.push_back(std::move(outgoing));
        write_backward();
    }

    void write_backward() noexcept {
        if (closed_ || backward_writing_ || backward_queue_.empty()) return;
        backward_writing_ = true;
        backward_since_ = Clock::now();
        try {
            inbound_->async_write(
                std::move(backward_queue_.front().cell), cancel_.token(),
                [self = shared_from_this()](Status status, std::size_t) {
                    self->on_backward_written(status);
                });
        } catch (...) {
            backward_writing_ = false;
            close(true);
        }
    }

    void on_backward_written(const Status& status) noexcept {
        backward_writing_ = false;
        backward_since_.reset();
        if (closed_) return;
        if (!status.ok() || backward_queue_.empty()) {
            close(true);
            return;
        }
        const bool resume_next = backward_queue_.front().resume_next;
        backward_queue_.pop_front();
        if (closing_ && backward_queue_.empty()) {
            close(true);
            return;
        }
        write_backward();
        if (resume_next) read_next();
        resume_reads();
    }

    // A read can complete inline and end its stream, so this walks a copy.
    // The walk starts after the stream that last started a read: the queue
    // frees one slot per write, and an inline read takes it at once, so a
    // walk from the first stream would give that stream every slot.
    void resume_reads() noexcept {
        if (closed_ || streams_.empty()) return;
        std::vector<std::shared_ptr<ExitStream>> waiting;
        try {
            waiting.reserve(streams_.size());
            const auto next = streams_.upper_bound(read_cursor_);
            for (auto it = next; it != streams_.end(); ++it)
                waiting.push_back(it->second);
            for (auto it = streams_.begin(); it != next; ++it)
                waiting.push_back(it->second);
        } catch (...) {
            close(true);
            return;
        }
        for (const auto& stream : waiting) {
            if (closed_) return;
            if (find(stream->id) == stream) pump_read(stream);
        }
    }

    bool queue_has_room() const noexcept {
        return backward_queue_.size() < node_->env.limits.backward_queue_cells;
    }

    void begin(std::uint32_t id, std::span<const std::uint8_t> payload) {
        if (phase_ != Phase::Open) {
            close(true);
            return;
        }
        terminal_ = true;
        if (streams_.contains(id)) {
            close(true);
            return;
        }
        const auto refuse = [&](c1::StreamReason reason) {
            send(
                c1::RelayType::End, id,
                std::array<std::uint8_t, 1>{static_cast<std::uint8_t>(reason)});
        };
        // A one-hop circuit adds no privacy, and serving it would reach the
        // anonymous exit policy instead of the grants the entry holds for
        // the client's identity.
        if (!node_->env.open_exit || depth_ == 1U)
            return refuse(c1::StreamReason::Policy);
        const auto& limits = node_->env.limits;
        if (streams_.size() >= limits.streams_per_circuit ||
            (streams_.size() + 1U) * std::uint64_t{limits.stream_window} >
                limits.circuit_window) {
            ++node_->refused_streams;
            return refuse(c1::StreamReason::Resources);
        }
        auto destination = c1::DecodeBeginPayload(payload);
        if (!destination.ok()) return refuse(c1::StreamReason::Protocol);
        auto stream = std::make_shared<ExitStream>();
        stream->id = id;
        stream->named =
            destination.value->address_kind == ytp1::AddressKind::Dns;
        stream->receive_allowed = node_->env.limits.stream_window;
        stream->send_window = node_->env.limits.stream_window;
        streams_.emplace(id, stream);
        node_->env.open_exit(
            origin_, *destination.value, stream->cancel.token(),
            [self = shared_from_this(),
             stream](Result<std::unique_ptr<ByteChannel>> opened) {
                self->on_exit_open(stream, std::move(opened));
            });
    }

    void on_exit_open(const std::shared_ptr<ExitStream>& stream,
                      Result<std::unique_ptr<ByteChannel>> opened) noexcept {
        const auto found = streams_.find(stream->id);
        if (closed_ || found == streams_.end() || found->second != stream) {
            if (opened.ok()) opened.value()->close();
            return;
        }
        try {
            if (!opened.ok()) {
                streams_.erase(found);
                send(c1::RelayType::End, stream->id,
                     std::array<std::uint8_t, 1>{static_cast<std::uint8_t>(
                         exit_reason(opened.status(), stream->named))});
                return;
            }
            stream->channel = std::move(opened).take_value();
            send(c1::RelayType::Connected, stream->id, {});
            pump_write(stream);
            pump_read(stream);
        } catch (...) {
            close(true);
        }
    }

    std::shared_ptr<ExitStream> find(std::uint32_t id) const noexcept {
        const auto found = streams_.find(id);
        return found == streams_.end() ? nullptr : found->second;
    }

    void data(std::uint32_t id, std::span<const std::uint8_t> payload) {
        const auto stream = find(id);
        // A stream this hop already ended may still see data that crossed
        // its END.
        if (!stream) return;
        if (stream->client_done || payload.size() > stream->receive_allowed) {
            close(true);
            return;
        }
        auto buffer = buffer_of(payload);
        if (!buffer.ok()) throw buffer.status();
        stream->receive_allowed -= static_cast<std::uint32_t>(payload.size());
        stream->to_destination.push_back(std::move(buffer).take_value());
        pump_write(stream);
    }

    void end(std::uint32_t id, std::span<const std::uint8_t> payload) {
        const auto stream = find(id);
        if (!stream) return;
        if (static_cast<c1::StreamReason>(payload[0]) !=
            c1::StreamReason::Done) {
            drop(stream);
            return;
        }
        stream->client_done = true;
        pump_write(stream);
        settle(stream);
    }

    void credit(std::uint32_t id, std::span<const std::uint8_t> payload) {
        const auto stream = find(id);
        if (!stream) return;
        const std::uint32_t increment =
            (static_cast<std::uint32_t>(payload[0]) << 24U) |
            (static_cast<std::uint32_t>(payload[1]) << 16U) |
            (static_cast<std::uint32_t>(payload[2]) << 8U) |
            static_cast<std::uint32_t>(payload[3]);
        stream->send_window += increment;
        if (stream->send_window > c1::kMaxCreditIncrement) {
            close(true);
            return;
        }
        pump_read(stream);
    }

    // Writes the client's data to the destination in order, and returns
    // window once half of it has drained.
    void pump_write(const std::shared_ptr<ExitStream>& stream) {
        if (!stream->channel || stream->writing || closed_) return;
        if (stream->to_destination.empty()) {
            if (stream->client_done && !stream->shut) {
                stream->shut = true;
                (void)stream->channel->shutdown_write();
            }
            return;
        }
        stream->writing = true;
        auto buffer = std::move(stream->to_destination.front());
        stream->to_destination.pop_front();
        stream->channel->async_write(
            std::move(buffer), stream->cancel.token(),
            [self = shared_from_this(), stream](Status status,
                                                std::size_t written) {
                stream->writing = false;
                if (self->closed_ || self->find(stream->id) != stream) return;
                try {
                    if (!status.ok()) {
                        self->fail_stream(stream,
                                          c1::StreamReason::Unreachable);
                        return;
                    }
                    stream->consumed += static_cast<std::uint32_t>(written);
                    if (stream->consumed >=
                            self->node_->env.limits.stream_window / 2U &&
                        !stream->client_done) {
                        const auto returned = stream->consumed;
                        stream->consumed = 0U;
                        stream->receive_allowed += returned;
                        const std::array<std::uint8_t, 4> increment{
                            static_cast<std::uint8_t>(returned >> 24U),
                            static_cast<std::uint8_t>(returned >> 16U),
                            static_cast<std::uint8_t>(returned >> 8U),
                            static_cast<std::uint8_t>(returned)};
                        self->send(c1::RelayType::StreamCredit, stream->id,
                                   increment);
                    }
                    self->pump_write(stream);
                    self->settle(stream);
                } catch (...) {
                    self->close(true);
                }
            });
    }

    // Reads from the destination within the client's window and while the
    // backward queue has room.
    void pump_read(const std::shared_ptr<ExitStream>& stream) noexcept {
        if (closed_ || !stream->channel || stream->reading ||
            stream->destination_done || stream->send_window == 0U ||
            !queue_has_room()) {
            return;
        }
        stream->reading = true;
        read_cursor_ = stream->id;
        const auto most = std::min<std::uint64_t>(
            stream->send_window, c1::MaxDataPayload(c1::Direction::Backward));
        try {
            stream->channel->async_read(
                static_cast<std::size_t>(most), stream->cancel.token(),
                [self = shared_from_this(), stream](Result<Buffer> result) {
                    stream->reading = false;
                    if (self->closed_ || self->find(stream->id) != stream)
                        return;
                    try {
                        if (!result.ok()) {
                            // A TCP channel reports the destination's end as
                            // Closed, as the direct route handler reads it.
                            // This circuit closes its channel only after
                            // dropping the stream, which the check above
                            // catches.
                            if (result.status().code() ==
                                    StatusCode::EndOfStream ||
                                result.status().code() == StatusCode::Closed) {
                                stream->destination_done = true;
                                self->send(c1::RelayType::End, stream->id,
                                           std::array<std::uint8_t, 1>{
                                               static_cast<std::uint8_t>(
                                                   c1::StreamReason::Done)});
                                self->settle(stream);
                                return;
                            }
                            self->fail_stream(stream,
                                              c1::StreamReason::Unreachable);
                            return;
                        }
                        const auto data = bytes_of(result.value());
                        if (data.empty() || data.size() > stream->send_window) {
                            self->fail_stream(stream,
                                              c1::StreamReason::Protocol);
                            return;
                        }
                        stream->send_window -= data.size();
                        self->send(c1::RelayType::Data, stream->id, data);
                        self->pump_read_later(stream);
                    } catch (...) {
                        self->close(true);
                    }
                });
        } catch (...) {
            stream->reading = false;
            close(true);
        }
    }

    // A destination read may complete before async_read returns, so a
    // stream with data queued would read again at once and fill the queue
    // alone. It reads again after the streams already waiting their turn.
    void pump_read_later(const std::shared_ptr<ExitStream>& stream) {
        boost::asio::post(node_->env.context->executor(),
                          [self = shared_from_this(), stream] {
                              if (self->find(stream->id) == stream)
                                  self->pump_read(stream);
                          });
    }

    // A stream both sides finished, with nothing left to write, is gone.
    void settle(const std::shared_ptr<ExitStream>& stream) noexcept {
        if (stream->client_done && stream->destination_done &&
            stream->to_destination.empty() && !stream->writing) {
            drop(stream);
        }
    }

    void fail_stream(const std::shared_ptr<ExitStream>& stream,
                     c1::StreamReason reason) {
        drop(stream);
        send(c1::RelayType::End, stream->id,
             std::array<std::uint8_t, 1>{static_cast<std::uint8_t>(reason)});
    }

    void drop(const std::shared_ptr<ExitStream>& stream) noexcept {
        stream->cancel.cancel();
        if (stream->channel) {
            stream->channel->cancel();
            stream->channel->close();
        }
        streams_.erase(stream->id);
    }

    std::shared_ptr<Node> node_;
    std::shared_ptr<StreamResponder> inbound_;
    bool from_peer_;
    Fingerprint predecessor_;
    // How this circuit's stream was opened here, by the client at the entry
    // and by the previous hop's node everywhere else.
    engine::StreamOpenContext origin_;
    std::string next_peer_;
    Phase phase_{Phase::AwaitCreate};
    std::uint8_t depth_{0U};
    std::optional<cc::LayerCipher> forward_;
    std::optional<cc::LayerCipher> backward_;
    std::shared_ptr<StreamResponder> next_;
    std::vector<std::uint8_t> create_body_;
    CancellationSource cancel_;
    std::deque<Outgoing> backward_queue_;
    std::map<std::uint32_t, std::shared_ptr<ExitStream>> streams_;
    std::optional<Clock::time_point> forward_since_;
    std::optional<Clock::time_point> backward_since_;
    std::optional<Clock::time_point> extend_since_;
    bool reading_inbound_{false};
    // The stream that last started a destination read, where resume_reads
    // continues its round.
    std::uint32_t read_cursor_{0U};
    bool reading_next_{false};
    bool backward_writing_{false};
    bool terminal_{false};
    bool closing_{false};
    bool closed_{false};
};

}  // namespace detail

void CircuitService::Node::arm_sweep(
    const std::shared_ptr<Node>& self_pointer) noexcept {
    if (closed || sweeping) return;
    sweeping = true;
    try {
        sweep.expires_after(kSweepInterval);
        sweep.async_wait([weak = std::weak_ptr<Node>(self_pointer)](
                             const boost::system::error_code& error) {
            const auto self = weak.lock();
            if (!self) return;
            self->sweeping = false;
            if (error || self->closed) return;
            self->sweep_now();
            self->arm_sweep(self);
        });
    } catch (...) {
        sweeping = false;
    }
}

void CircuitService::Node::sweep_now() noexcept {
    const auto now = Clock::now();
    for (const auto& weak : circuits) {
        if (const auto circuit = weak.lock()) circuit->sweep(now);
    }
    std::erase_if(circuits, [](const std::weak_ptr<detail::Circuit>& weak) {
        const auto circuit = weak.lock();
        return !circuit || circuit->closed();
    });
    // An origin with no circuits and a refilled bucket holds nothing worth
    // keeping.
    std::erase_if(origins, [&](auto& entry) {
        entry.second.bucket.refill(now);
        return entry.second.circuits == 0U &&
               entry.second.bucket.tokens >= entry.second.bucket.burst;
    });
}

Result<std::shared_ptr<CircuitService>> CircuitService::create(
    NodeEnvironment environment) {
    using Created = Result<std::shared_ptr<CircuitService>>;
    if (!environment.context || !environment.crypto || !environment.identity ||
        !environment.is_peer || !environment.open_next) {
        return Created(Status(StatusCode::InvalidArgument));
    }
    const auto self =
        cc::fingerprint_bytes(environment.identity->identity.fingerprint);
    if (!self) return Created(Status(StatusCode::InvalidArgument));
    auto descriptor = engine::ProviderDescriptor::create(
        std::string(kServiceName), engine::ProviderKind::StreamHandler, 1U,
        engine::mandatory_capabilities(engine::ProviderKind::StreamHandler)
            .with(engine::Capability::PacketChannels));
    if (!descriptor.ok()) return Created(descriptor.status());
    try {
        auto node = std::make_shared<Node>(
            std::move(environment), std::move(descriptor).take_value(), *self);
        return Created(std::shared_ptr<CircuitService>(
            new CircuitService(std::move(node))));
    } catch (const std::bad_alloc&) {
        return Created(Status(StatusCode::ResourceExhausted));
    }
}

CircuitService::CircuitService(std::shared_ptr<Node> node) noexcept
    : node_(std::move(node)) {}

CircuitService::~CircuitService() {
    close();
}

const engine::ProviderDescriptor& CircuitService::descriptor() const noexcept {
    return node_->descriptor;
}

engine::Status CircuitService::authorize(const engine::StreamOpenContext&) {
    // The endpoint's authorization policy grants the service. Bounds apply
    // when the stream opens.
    return Status::success();
}

void CircuitService::async_open(engine::StreamOpenContext context,
                                std::shared_ptr<StreamResponder> stream,
                                AcceptanceCompletion completion) {
    auto& node = *node_;
    const auto settle = [&](Status status) {
        auto done = std::move(completion);
        try {
            if (done) done(std::move(status));
        } catch (...) {
        }
    };
    if (node.closed) return settle(Status(StatusCode::Closed));
    const auto& identity = context.peer_evidence().identity();
    const bool peer = node.env.is_peer(identity);
    const auto& limits = node.env.limits;
    auto [entry, added] = node.origins.try_emplace(
        identity,
        Node::Origin{0U, peer ? TokenBucket(limits.link_circuits_per_second,
                                            limits.link_circuit_burst)
                              : TokenBucket(limits.client_circuits_per_second,
                                            limits.client_circuit_burst)});
    auto& origin = entry->second;
    if (!peer && origin.circuits >= limits.circuits_per_client) {
        ++node.refused_client_circuits;
        return settle(Status(StatusCode::ResourceExhausted));
    }
    if (!origin.bucket.take(Clock::now())) {
        ++node.refused_circuit_rate;
        return settle(Status(StatusCode::ResourceExhausted));
    }
    Fingerprint predecessor{};
    if (peer) {
        const auto bytes = cc::fingerprint_bytes(identity);
        if (!bytes) return settle(Status(StatusCode::PermissionDenied));
        predecessor = *bytes;
    }
    auto circuit = std::make_shared<detail::Circuit>(
        node_, std::move(stream), peer, predecessor, std::move(context));
    node.circuits.push_back(circuit);
    ++origin.circuits;
    node.arm_sweep(node_);
    settle(Status::success());
    circuit->start();
}

void CircuitService::on_open(engine::StreamOpenContext,
                             std::shared_ptr<StreamResponder> stream) {
    // async_open replaces the synchronous path.
    if (stream) stream->close(Status(StatusCode::Internal));
}

NodeStatus CircuitService::status() const {
    const auto& node = *node_;
    NodeStatus result;
    const auto link = [&](const std::string& identity) -> NodeStatus::Link& {
        const auto found = std::find_if(
            result.links.begin(), result.links.end(),
            [&](const auto& entry) { return entry.peer_identity == identity; });
        if (found != result.links.end()) return *found;
        return result.links.emplace_back(NodeStatus::Link{identity, 0U, 0U});
    };
    for (const auto& weak : node.circuits) {
        const auto circuit = weak.lock();
        if (!circuit || circuit->closed()) continue;
        ++result.circuits;
        if (circuit->depth() == 1U) ++result.entry_circuits;
        if (circuit->from_peer()) ++link(circuit->origin()).inbound;
        if (circuit->relayed()) {
            ++result.relayed_circuits;
            ++link(circuit->next_peer()).outbound;
        }
        result.exit_streams += circuit->streams();
    }
    result.refused_client_circuits = node.refused_client_circuits;
    result.refused_circuit_rate = node.refused_circuit_rate;
    result.refused_handshakes = node.refused_handshakes;
    result.refused_streams = node.refused_streams;
    result.refused = node.refused_client_circuits + node.refused_circuit_rate +
                     node.refused_handshakes + node.refused_streams;
    result.failed = node.failed;
    return result;
}

void CircuitService::close() noexcept {
    auto& node = *node_;
    if (node.closed) return;
    node.closed = true;
    providers::cancel_timer(node.sweep);
    const auto circuits = node.circuits;
    for (const auto& weak : circuits) {
        if (const auto circuit = weak.lock()) circuit->close(false);
    }
    node.circuits.clear();
}

}  // namespace yume::runtime::circuit
