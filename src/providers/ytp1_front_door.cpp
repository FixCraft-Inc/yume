/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/ytp1_front_door.hpp"
#include "providers/ytp1_h2_admission.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <list>
#include <mutex>
#include <new>
#include <optional>
#include <set>
#include <string_view>
#include <utility>

#include <boost/asio/steady_timer.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/system/system_error.hpp>

// GCC 14's optimized sanitizer build diagnoses Boost.Optional's inactive
// scalar storage in Beast's content_length_unchecked(). Scope the workaround
// to the dependency definitions; YUME retains its full warning policy.
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ == 14
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
#include <boost/beast/http/parser.hpp>
#include <boost/beast/http/empty_body.hpp>
#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ == 14
#pragma GCC diagnostic pop
#endif

#include <openssl/crypto.h>

namespace yume::providers {
namespace {
using namespace engine;
using Tcp = boost::asio::ip::tcp;
using Error = boost::system::error_code;

Status listener_error(const Error& error) noexcept {
    namespace errc = boost::system::errc;
    const auto is = [&error](errc::errc_t value) noexcept {
        return error == errc::make_error_condition(value);
    };
    StatusCode code = StatusCode::Internal;
    std::string_view message = "native listener socket setup failed";
    if (is(errc::permission_denied) || is(errc::operation_not_permitted)) {
        code = StatusCode::PermissionDenied;
        message = "native listener socket permission denied";
    } else if (is(errc::address_in_use)) {
        code = StatusCode::AddressInUse;
        message = "native listener address is already in use";
    } else if (is(errc::too_many_files_open) || is(errc::too_many_files_open_in_system) ||
               is(errc::no_buffer_space) || is(errc::not_enough_memory)) {
        code = StatusCode::ResourceExhausted;
        message = "native listener socket resources exhausted";
    } else if (is(errc::address_not_available) || is(errc::invalid_argument)) {
        code = StatusCode::InvalidArgument;
        message = "native listener address is unavailable or invalid";
    }
    try { return Status(code, message); }
    catch (...) { return Status(code); }
}

template<class Callback, class... Args>
void deliver(Callback& callback, Args&&... args) noexcept {
    if (callback) {
        try { callback(std::forward<Args>(args)...); } catch (...) {}
    }
}

struct PromotionBudget final {
    std::atomic<std::size_t> active{0U};
};

struct ExporterWiper final {
    Buffer& buffer;
    ~ExporterWiper() noexcept {
        auto bytes = buffer.mutable_bytes();
        OPENSSL_cleanse(bytes.data(), bytes.size());
    }
};

struct PromotionReservation final {
    explicit PromotionReservation(std::shared_ptr<PromotionBudget> value) noexcept
        : budget(std::move(value)) { ++budget->active; }
    ~PromotionReservation() noexcept { --budget->active; }
    std::shared_ptr<PromotionBudget> budget;
};

// The accepted-channel registry must outlive published carriers. Otherwise
// destroying the FrontDoor would cancel their current TCP operations.
class OwnedCarrier final : public Carrier {
public:
    OwnedCarrier(std::shared_ptr<AsioTcpAcceptedChannelOwner> tcp,
                 std::shared_ptr<PromotionReservation> reservation,
                 std::unique_ptr<Carrier> carrier) noexcept
        : tcp_(std::move(tcp)), reservation_(std::move(reservation)),
          carrier_(std::move(carrier)) {}
    ~OwnedCarrier() noexcept override {
        carrier_->close();
        carrier_.reset();
    }
    const ProviderDescriptor& descriptor() const noexcept override {
        return carrier_->descriptor();
    }
    ExecutorAffinity executor_affinity() const noexcept override {
        return carrier_->executor_affinity();
    }
    std::size_t max_record_size() const noexcept override { return carrier_->max_record_size(); }
    SecureChannel& secure_channel() noexcept override { return carrier_->secure_channel(); }
    const SecureChannel& secure_channel() const noexcept override { return carrier_->secure_channel(); }
    void async_receive(CancellationToken token, ReceiveCompletion completion) override {
        carrier_->async_receive(std::move(token), std::move(completion));
    }
    void async_send(Buffer bytes, CancellationToken token, SendCompletion completion) override {
        carrier_->async_send(std::move(bytes), std::move(token), std::move(completion));
    }
    void cancel() noexcept override { carrier_->cancel(); }
    void close() noexcept override { carrier_->close(); }
private:
    std::shared_ptr<AsioTcpAcceptedChannelOwner> tcp_;
    std::shared_ptr<PromotionReservation> reservation_;
    std::unique_ptr<Carrier> carrier_;
};

// Retained by the promoted carrier, without retaining the listening owner.
struct CoverSession final : Ytp1H2CoverHandler {
    CoverSession(std::shared_ptr<const Ytp1CoverSite> value, Ytp1FrontDoorLimits bounds)
        : site(std::move(value)), limits(bounds) {}
    std::shared_ptr<const Ytp1CoverSite> site;
    Ytp1FrontDoorLimits limits;
    std::size_t requests{0U};
    std::set<std::int32_t> streams;

    void stream_closed(std::int32_t stream_id) noexcept override { streams.erase(stream_id); }

    bool respond(obfs::H2Carrier& h2, const obfs::H2Request& request) override {
        if (++requests > limits.max_requests_per_connection ||
            streams.size() >= limits.max_cover_streams) return false;
        const auto response = site->respond(request.method, request.path);
        const auto queued = h2.queued_output_bytes();
        if (queued > limits.max_output_bytes ||
            response.body.size() > limits.max_output_bytes - queued) return false;
        obfs::H2Headers headers(response.headers.begin(), response.headers.end());
        obfs::H2Bytes body(response.body.begin(), response.body.end());
        streams.insert(request.stream_id);
        return h2.RespondHttp(request.stream_id, static_cast<unsigned>(response.status_code),
                              headers, std::move(body), request.method == "HEAD") &&
               h2.queued_output_bytes() <= limits.max_output_bytes;
    }
};
}

class Ytp1FrontDoor::State final : public std::enable_shared_from_this<State> {
public:
    struct Waiter final {
        CancellationToken token;
        CancellationRegistration registration;
        AcceptCompletion completion;
        bool reserved{false};
        std::uint64_t epoch{0U};
    };
    class Connection;

    State(std::shared_ptr<AsioExecutionContext> execution, Ytp1FrontDoorConfig options,
          std::shared_ptr<Ytp1Tls13SecureChannelProvider> tls_provider,
          std::shared_ptr<const Ytp1CoverSite> site,
          std::shared_ptr<admission::ReplayCache> replay_cache,
          std::shared_ptr<AsioTcpAcceptedChannelOwner> tcp_owner,
          Ytp1H2Dispatch dispatch)
        : context(std::move(execution)), config(std::move(options)),
          tls(std::move(tls_provider)), cover(std::move(site)), replay(std::move(replay_cache)),
          tcp(std::move(tcp_owner)), post(std::move(dispatch)),
          acceptor(context->executor()), budget(std::make_shared<PromotionBudget>()),
          control(&State::on_control) {}

    ~State() noexcept { OPENSSL_cleanse(key.data(), key.size()); }

    void request_close() noexcept {
        std::lock_guard lock(control_mutex);
        if (closing.load()) return;
        closing.store(true);
        context->submit(control, shared_from_this());
    }
    void request_cancel() noexcept {
        std::lock_guard lock(control_mutex);
        if (closing.load()) return;
        // The generation is captured at initiation, so later waiters survive
        // an earlier cross-thread cancellation request.
        cancel_epoch.fetch_add(1U);
        context->submit(control, shared_from_this());
    }
    void notify_control() noexcept {
        // Serialize publication with close: a cancelled token must not retain
        // the listening state by submitting new work after the final drain.
        std::lock_guard lock(control_mutex);
        if (!closing.load()) context->submit(control, shared_from_this());
    }
    static void on_control(void* pointer) noexcept {
        static_cast<State*>(pointer)->settle_control();
    }
    void settle_control() noexcept;
    void start_accept() noexcept;
    void remove(Connection* connection) noexcept;
    void add_waiter(CancellationToken token, AcceptCompletion completion);

    std::shared_ptr<Waiter> available_waiter() {
        for (const auto& waiter : waiters) {
            if (!waiter->reserved && waiter->completion && !waiter->token.is_cancelled() &&
                waiter->epoch == cancel_epoch.load())
                return waiter;
        }
        return {};
    }
    void finish_waiter(const std::shared_ptr<Waiter>& waiter,
                       Result<AcceptedCarrier> result) noexcept {
        if (!waiter) return;
        auto completion = std::move(waiter->completion);
        waiter->registration.unregister();
        waiters.remove(waiter);
        deliver(completion, std::move(result));
    }

    std::shared_ptr<AsioExecutionContext> context;
    Ytp1FrontDoorConfig config;
    std::shared_ptr<Ytp1Tls13SecureChannelProvider> tls;
    std::shared_ptr<const Ytp1CoverSite> cover;
    std::shared_ptr<admission::ReplayCache> replay;
    std::shared_ptr<AsioTcpAcceptedChannelOwner> tcp;
    Ytp1H2Dispatch post;
    boost::asio::basic_socket_acceptor<Tcp, AsioExecutionContext::Executor> acceptor;
    Tcp::endpoint endpoint;
    std::shared_ptr<PromotionBudget> budget;
    std::array<std::byte, kYtp1H2AdmissionKeyBytes> key{};
    std::list<std::shared_ptr<Connection>> connections;
    std::list<std::shared_ptr<Waiter>> waiters;
    AsioExecutionContext::ControlTask control;
    std::mutex control_mutex;
    std::atomic<bool> closing{false};
    std::atomic<std::uint64_t> cancel_epoch{0U};
    bool accepting{false};
};

class Ytp1FrontDoor::State::Connection final
    : public std::enable_shared_from_this<Connection> {
public:
    explicit Connection(const std::shared_ptr<State>& owner)
        : owner_(owner), context_(owner->context), timer_(context_->executor()),
          cover_(std::make_shared<CoverSession>(owner->cover, owner->config.limits)) {
        http_.header_limit(32U * 1024U);
        // This static site accepts no uploads and always closes HTTP/1 after
        // its response. Answer at the header boundary, including Expect:
        // 100-continue, without waiting for an unsupported request body.
        http_.skip(true);
    }
    void start(AsioTcpSocket socket) noexcept {
        try {
            const auto owner = owner_.lock();
            if (!owner || owner->closing.load()) { stop(); return; }
            auto adopted = owner->tcp->adopt(std::move(socket));
            if (!adopted.ok()) { stop(); return; }
            timer_.expires_after(owner->config.limits.connection_timeout);
            timer_pending_ = true;
            timer_.async_wait([self = shared_from_this()](Error error) noexcept {
                self->timer_pending_ = false;
                if (!error) self->stop();
                else if (self->promoting_ && !self->terminal_) self->publish();
            });
            owner->tls->async_wrap_server_cover(std::move(adopted).take_value(), cancellation_.token(),
                [self = shared_from_this()](Result<std::unique_ptr<Ytp1TlsServerConnection>> result) noexcept {
                    try {
                        if (!result.ok()) { self->stop(); return; }
                        auto tls = std::move(result).take_value();
                        if (self->terminal_) { tls->close(); return; }
                        self->tls_ = std::move(tls);
                        if (self->tls_->negotiated_protocol() == "h2")
                            self->h2_ = std::make_unique<obfs::H2Carrier>(obfs::H2CarrierRole::Server);
                        self->pump();
                    } catch (...) { self->stop(); }
                });
        } catch (...) { stop(); }
    }

    void stop() noexcept {
        if (terminal_) return;
        terminal_ = true;
        cancellation_.cancel();
        Error ignored;
        timer_.cancel(ignored);
        if (tls_) tls_->close();
        reservation_.reset();
        if (const auto owner = owner_.lock()) {
            if (waiter_) {
                // A peer that disconnects during admission must not consume an
                // application's persistent accept operation.
                waiter_->reserved = false;
                waiter_.reset();
            }
            owner->remove(this);
        }
    }

private:
    void process_h2() {
        const auto owner = owner_.lock();
        if (!owner || owner->closing.load()) { stop(); return; }
        for (const auto& event : h2_->TakeStreamCloses()) {
            cover_->stream_closed(event.stream_id);
            if (candidate_ && candidate_->stream_id == event.stream_id) candidate_.reset();
        }
        for (auto& request : h2_->TakeRequests()) {
            // Proof verification reads SNI and exporter from this SSL object.
            // No peer field is allowed to supply channel-binding material.
            bool valid = false;
            if (!candidate_ && !admitted_ && request.method == "CONNECT" &&
                request.protocol == "websocket" && tls_->tls_version() == 0x0304U &&
                owner->budget->active.load() < owner->config.limits.max_promoted_carriers &&
                owner->available_waiter()) {
                auto exported = tls_->export_keying_material(kYtp1H2AdmissionExporterLabel, {},
                                                             kYtp1H2AdmissionExporterBytes);
                if (exported.ok()) {
                    const ExporterWiper wipe{exported.value()};
                    valid = verify_ytp1_h2_admission_path(owner->key, request.authority,
                        tls_->server_name(), exported.value().bytes(), request.path, owner->endpoint.port());
                }
            }
            if (valid) {
                candidate_ = std::move(request);
            } else {
                if (!cover_->respond(*h2_, request)) { stop(); return; }
            }
            for (const auto& event : h2_->TakeStreamCloses()) {
                cover_->stream_closed(event.stream_id);
                if (candidate_ && candidate_->stream_id == event.stream_id) candidate_.reset();
            }
        }
        // RespondHttp can synchronously finish a small response inside Flush.
        for (const auto& event : h2_->TakeStreamCloses()) cover_->stream_closed(event.stream_id);
    }

    void decide_admission() {
        if (!candidate_) return;
        const auto owner = owner_.lock();
        if (!owner || owner->closing.load()) { stop(); return; }
        if (reservation_) {
            if (!waiter_ || !waiter_->completion || waiter_->token.is_cancelled() ||
                waiter_->epoch != owner->cancel_epoch.load()) {
                reservation_.reset();
                if (waiter_) waiter_->reserved = false;
                waiter_.reset();
                if (!cover_->respond(*h2_, *candidate_)) { stop(); return; }
                candidate_.reset();
                return;
            }
        } else {
            auto waiter = owner->available_waiter();
            const auto parsed = admission::parse_path(candidate_->path);
            const auto ticks = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            // ReplayCache owns atomic duplicate-check/reservation. Failure never
            // evicts live entries. Its ticks and configured TTL are seconds.
            if (waiter && parsed && ticks >= 0 &&
                owner->budget->active.load() < owner->config.limits.max_promoted_carriers) {
                try { reservation_ = std::make_shared<PromotionReservation>(owner->budget); }
                catch (...) {} // Failed capacity allocation follows ordinary cover.
            }
            if (!reservation_ ||
                owner->replay->reserve(parsed->nonce, static_cast<std::uint64_t>(ticks)) !=
                    admission::ReplayDecision::Accepted) {
                reservation_.reset();
                if (!cover_->respond(*h2_, *candidate_)) { stop(); return; }
                candidate_.reset();
                return;
            }
            // Reserve before emitting 200, including the pending-write/transfer
            // interval, so concurrent connections cannot over-admit the budget.
            waiter_ = std::move(waiter);
            waiter_->reserved = true;
        }
        // Cover responses are synchronous snapshots. Once their output drains,
        // a peer's still-open request direction has no outstanding cover work.
        // Preserve those streams and their bounds in H2/CoverSession on transfer.
        if (h2_->queued_output_bytes() != 0U) return;
        // Irreversible per-connection state, independent of replay-cache TTL.
        admitted_ = true;
        if (!h2_->AcceptCarrier(candidate_->stream_id)) { stop(); return; }
        candidate_.reset();
    }

    void process_http(std::span<const std::byte> bytes) {
        if (http_input_.size() + bytes.size() > 128U * 1024U) { stop(); return; }
        http_input_.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        Error error;
        const auto consumed = http_.put(boost::asio::buffer(http_input_), error);
        http_input_.erase(0U, consumed);
        if (error && error != boost::beast::http::error::need_more) { stop(); return; }
        if (!http_.is_done()) return;
        const auto& request = http_.get();
        const auto response = cover_->site->respond(
            std::string_view(request.method_string().data(), request.method_string().size()),
            std::string_view(request.target().data(), request.target().size()));
        const std::string_view status_line = response.status_code == 200 ? "HTTP/1.1 200 OK\r\n" :
                                                                         "HTTP/1.1 404 Not Found\r\n";
        constexpr std::string_view close_header = "connection: close\r\n\r\n";
        std::size_t required = status_line.size() + close_header.size();
        const auto add = [&](std::size_t count) {
            if (required > cover_->limits.max_output_bytes ||
                count > cover_->limits.max_output_bytes - required) return false;
            required += count;
            return true;
        };
        for (const auto& [name, value] : response.headers) {
            if (!add(name.size() + value.size() + 4U)) { stop(); return; }
        }
        if (!add(response.body.size())) { stop(); return; }
        std::string wire;
        wire.reserve(required);
        wire.append(status_line);
        for (const auto& [name, value] : response.headers) wire += name + ": " + value + "\r\n";
        wire.append(close_header);
        wire.append(response.body);
        if (wire.size() > cover_->limits.max_output_bytes) { stop(); return; }
        output_.assign(wire.begin(), wire.end());
        http_done_ = true;
    }

    void pump() noexcept {
        if (pumping_) { repump_ = true; return; }
        pumping_ = true;
        do {
            repump_ = false;
            try { pump_once(); } catch (...) { stop(); }
        } while (repump_ && !terminal_);
        pumping_ = false;
    }

    void pump_once() {
        if (terminal_ || promoting_ || reading_ || writing_) return;
        if (h2_) {
            if (h2_->failed() || h2_->carrier_closed()) { stop(); return; }
            process_h2();
            if (terminal_) return;
            if (output_.empty()) decide_admission();
            if (terminal_) return;
            if (output_.empty()) output_ = h2_->TakeOutbound();
            if (h2_->failed() || output_.size() > cover_->limits.max_output_bytes) { stop(); return; }
        }
        if (!output_.empty()) {
            const auto count = std::min(output_.size() - output_offset_, tls_->max_write_size());
            if (count == 0U) { stop(); return; }
            auto buffer = Buffer::copy_from(std::as_bytes(std::span(output_.data() + output_offset_, count)), count);
            if (!buffer.ok()) { stop(); return; }
            writing_ = true;
            tls_->async_write(std::move(buffer).take_value(), cancellation_.token(),
                [self = shared_from_this(), count](Status status, std::size_t bytes) noexcept {
                    self->writing_ = false;
                    if (self->terminal_) return;
                    if (!status.ok() || bytes != count) { self->stop(); return; }
                    self->output_offset_ += count;
                    if (self->output_offset_ == self->output_.size()) {
                        self->output_.clear(); self->output_offset_ = 0U;
                    }
                    self->pump();
                });
            return;
        }
        if (admitted_) {
            promoting_ = true;
            Error ignored;
            timer_.cancel(ignored);
            if (!timer_pending_) publish();
            return;
        }
        if (http_done_) { stop(); return; }
        reading_ = true;
        tls_->async_read(std::min<std::size_t>(64U * 1024U, tls_->max_read_size()), cancellation_.token(),
            [self = shared_from_this()](Result<Buffer> result) noexcept {
                self->reading_ = false;
                if (self->terminal_) return;
                try {
                    if (!result.ok() || result.value().empty()) { self->stop(); return; }
                    const auto bytes = result.value().bytes();
                    if (self->h2_) self->h2_->Feed(reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size());
                    else self->process_http(bytes);
                    self->pump();
                } catch (...) { self->stop(); }
            });
    }

    void publish() noexcept {
        try {
            const auto owner = owner_.lock();
            if (!owner || owner->closing.load() || !waiter_ || !waiter_->completion ||
                waiter_->token.is_cancelled() || waiter_->epoch != owner->cancel_epoch.load()) { stop(); return; }
            auto secure = tls_->promote();
            if (!secure.ok()) { stop(); return; }
            auto made = make_ytp1_h2_admitted_server_carrier(std::move(secure).take_value(),
                std::move(h2_), context_->affinity(), owner->post, owner->config.carrier_limits,
                cover_);
            if (!made.ok()) { stop(); return; }
            auto owned = std::make_unique<OwnedCarrier>(owner->tcp, std::move(reservation_), std::move(made).take_value());
            auto descriptor = owned->descriptor();
            auto result = AcceptedCarrier::create(std::move(descriptor), std::move(owned));
            terminal_ = true;
            auto waiter = std::move(waiter_);
            owner->remove(this);
            owner->finish_waiter(waiter, std::move(result));
        } catch (...) { stop(); }
    }

    std::weak_ptr<State> owner_;
    std::shared_ptr<AsioExecutionContext> context_;
    boost::asio::steady_timer timer_;
    std::shared_ptr<CoverSession> cover_;
    CancellationSource cancellation_;
    std::unique_ptr<Ytp1TlsServerConnection> tls_;
    std::unique_ptr<obfs::H2Carrier> h2_;
    std::optional<obfs::H2Request> candidate_;
    std::shared_ptr<Waiter> waiter_;
    std::shared_ptr<PromotionReservation> reservation_;
    boost::beast::http::request_parser<boost::beast::http::empty_body> http_;
    std::string http_input_;
    obfs::H2Bytes output_;
    std::size_t output_offset_{0U};
    bool terminal_{false}, admitted_{false}, promoting_{false}, timer_pending_{false};
    bool reading_{false}, writing_{false}, http_done_{false}, pumping_{false}, repump_{false};
};

void Ytp1FrontDoor::State::start_accept() noexcept {
    if (closing.load() || accepting || connections.size() >= config.limits.max_connections) return;
    try {
        accepting = true;
        acceptor.async_accept(context->executor(),
            [self = shared_from_this()](Error error, AsioTcpSocket socket) noexcept {
                self->accepting = false;
                if (self->closing.load()) return;
                if (error) { self->request_close(); return; }
                try {
                    auto connection = std::make_shared<Connection>(self);
                    self->connections.push_back(connection);
                    connection->start(std::move(socket));
                    self->start_accept();
                } catch (...) { self->request_close(); }
            });
    } catch (...) { accepting = false; request_close(); }
}

void Ytp1FrontDoor::State::remove(Connection* connection) noexcept {
    connections.remove_if([connection](const auto& value) { return value.get() == connection; });
    start_accept();
}

void Ytp1FrontDoor::State::settle_control() noexcept {
    if (closing.load()) {
        Error ignored;
        acceptor.close(ignored);
        while (!connections.empty()) {
            const auto connection = connections.front();
            connection->stop();
        }
    }
    // Detach each waiter before user code. A callback may initiate another
    // accept or destroy the final public FrontDoor handle.
    for (auto it = waiters.begin(); it != waiters.end();) {
        const auto waiter = *it++;
        if (closing.load() || waiter->token.is_cancelled() ||
            waiter->epoch != cancel_epoch.load()) {
            finish_waiter(waiter, Result<AcceptedCarrier>(Status(
                closing.load() ? StatusCode::Closed : StatusCode::Cancelled)));
            it = waiters.begin();
        }
    }
}

void Ytp1FrontDoor::State::add_waiter(CancellationToken token, AcceptCompletion completion) {
    context->require_context();
    if (!completion) return;
    if (closing.load() || token.is_cancelled() || waiters.size() >= config.limits.max_pending_accepts) {
        deliver(completion, Result<AcceptedCarrier>(Status(closing.load() ? StatusCode::Closed :
            token.is_cancelled() ? StatusCode::Cancelled : StatusCode::ResourceExhausted)));
        return;
    }
    std::shared_ptr<Waiter> waiter;
    const auto epoch = cancel_epoch.load();
    try {
        waiter = std::make_shared<Waiter>();
        waiter->epoch = epoch;
        waiter->token = std::move(token);
        waiter->completion = std::move(completion);
        const std::weak_ptr<State> weak = weak_from_this();
        auto registration = waiter->token.register_callback([weak] {
            if (const auto self = weak.lock()) self->notify_control();
        });
        if (!registration.ok()) {
            deliver(waiter->completion, Result<AcceptedCarrier>(Status(StatusCode::ResourceExhausted)));
            return;
        }
        waiter->registration = std::move(registration).take_value();
        waiters.push_back(waiter);
    } catch (...) {
        if (waiter) {
            deliver(waiter->completion, Result<AcceptedCarrier>(Status(StatusCode::ResourceExhausted)));
        } else deliver(completion, Result<AcceptedCarrier>(Status(StatusCode::ResourceExhausted)));
    }
}

Result<std::shared_ptr<Ytp1FrontDoor>> Ytp1FrontDoor::create(
    std::shared_ptr<AsioExecutionContext> context, Ytp1FrontDoorConfig config,
    std::shared_ptr<Ytp1Tls13SecureChannelProvider> tls,
    std::shared_ptr<const Ytp1CoverSite> cover,
    std::shared_ptr<admission::ReplayCache> replay,
    std::span<const std::byte> admission_key) {
    if (!context || !tls || tls->local_role() != EndpointRole::Server ||
        !cover || !replay || admission_key.size() != kYtp1H2AdmissionKeyBytes)
        return Result<std::shared_ptr<Ytp1FrontDoor>>(Status(StatusCode::InvalidArgument));
    context->require_context();
    const auto& limits = config.limits;
    if (!limits.max_connections || limits.max_connections > 4096U ||
        !limits.max_promoted_carriers || limits.max_promoted_carriers > 4096U ||
        !limits.max_pending_accepts || limits.max_pending_accepts > 1024U ||
        !limits.max_cover_streams || limits.max_cover_streams > 64U ||
        !limits.max_requests_per_connection || limits.max_requests_per_connection > 65536U ||
        !limits.max_output_bytes || limits.max_output_bytes > 32U * 1024U * 1024U ||
        limits.connection_timeout <= std::chrono::milliseconds::zero() ||
        limits.connection_timeout > std::chrono::minutes(10))
        return Result<std::shared_ptr<Ytp1FrontDoor>>(Status(StatusCode::InvalidArgument));
    try {
        const auto carrier_status = validate_ytp1_h2_carrier_limits(config.carrier_limits);
        if (!carrier_status.ok()) return Result<std::shared_ptr<Ytp1FrontDoor>>(carrier_status);
        AsioTcpChannelLimits tcp_limits;
        tcp_limits.max_active_channels = limits.max_connections + limits.max_promoted_carriers;
        auto tcp = AsioTcpAcceptedChannelOwner::create(context, tcp_limits);
        if (!tcp.ok()) return Result<std::shared_ptr<Ytp1FrontDoor>>(tcp.status());
        Ytp1H2Dispatch post{
            [context](std::function<void()> task) {
                boost::asio::post(context->executor(), std::move(task));
            },
            [context](ControlTask& task, std::shared_ptr<void> owner) noexcept {
                context->submit(task, std::move(owner));
            }};
        auto state = std::make_shared<State>(context, std::move(config), std::move(tls),
            std::move(cover), std::move(replay), std::move(tcp).take_value(), std::move(post));
        std::copy(admission_key.begin(), admission_key.end(), state->key.begin());
        Error error;
        state->acceptor.open(state->config.listen_endpoint.protocol(), error);
        if (!error && state->config.listen_endpoint.address().is_v6())
            state->acceptor.set_option(boost::asio::ip::v6_only(true), error);
#if !defined(_WIN32)
        // A restarted endpoint must rebind while its earlier connections sit in
        // TIME_WAIT. Linux address reuse allows that but not a second active
        // listener. Windows SO_REUSEADDR can take over a bound port, so it is
        // left unset there.
        if (!error)
            state->acceptor.set_option(boost::asio::socket_base::reuse_address(true), error);
#endif
        if (!error) state->acceptor.bind(state->config.listen_endpoint, error);
        if (!error) state->acceptor.listen(boost::asio::socket_base::max_listen_connections, error);
        if (error) return Result<std::shared_ptr<Ytp1FrontDoor>>(listener_error(error));
        state->endpoint = state->acceptor.local_endpoint(error);
        if (error) return Result<std::shared_ptr<Ytp1FrontDoor>>(listener_error(error));
        auto result = std::shared_ptr<Ytp1FrontDoor>(new Ytp1FrontDoor(state));
        state->start_accept();
        if (state->closing.load()) return Result<std::shared_ptr<Ytp1FrontDoor>>(Status(StatusCode::Internal));
        return Result<std::shared_ptr<Ytp1FrontDoor>>(std::move(result));
    } catch (const boost::system::system_error& error) {
        return Result<std::shared_ptr<Ytp1FrontDoor>>(listener_error(error.code()));
    } catch (const std::bad_alloc&) {
        return Result<std::shared_ptr<Ytp1FrontDoor>>(Status(StatusCode::ResourceExhausted));
    } catch (...) {
        return Result<std::shared_ptr<Ytp1FrontDoor>>(Status(StatusCode::Internal));
    }
}

Ytp1FrontDoor::Ytp1FrontDoor(std::shared_ptr<State> state) noexcept : state_(std::move(state)) {}
Ytp1FrontDoor::~Ytp1FrontDoor() noexcept { close(); }
ExecutorAffinity Ytp1FrontDoor::executor_affinity() const noexcept { return state_->context->affinity(); }
Tcp::endpoint Ytp1FrontDoor::local_endpoint() const noexcept { return state_->endpoint; }
void Ytp1FrontDoor::async_accept(CancellationToken token, AcceptCompletion completion) {
    const auto state = state_;
    state->add_waiter(std::move(token), std::move(completion));
}
void Ytp1FrontDoor::cancel() noexcept { state_->request_cancel(); }
void Ytp1FrontDoor::close() noexcept { state_->request_close(); }

}  // namespace yume::providers
