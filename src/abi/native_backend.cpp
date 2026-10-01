/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "abi/endpoint_backend.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <exception>
#include <filesystem>
#include <mutex>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

#include <boost/asio/ip/address.hpp>

#include "common/secure_erase.hpp"
#include "config/v1/config.hpp"
#include "engine/cancellation.hpp"
#include "engine/session_engine.hpp"
#include "engine/stream_handler.hpp"
#include "engine/transport_suite.hpp"
#include "providers/asio_execution_context.hpp"
#include "providers/control_task.hpp"
#include "providers/openssl_security_provider.hpp"
#if defined(YUME_HAS_DEVICE_BRIDGE)
#include "runtime/device_bridge.hpp"
#endif
#include "runtime/message_log.hpp"
#include "runtime/native_endpoint.hpp"
#include "runtime/sealed_kit.hpp"
#include "runtime/session_keeper.hpp"

// The YTP/1 embedding backend. It adapts the asynchronous, single-runner
// native endpoint to the blocking seam used by the C ABI.
//
// Threading: every engine and provider operation starts on the endpoint's
// runner thread. Application threads hand work over through control tasks
// embedded in the objects they concern, so a hand-over never allocates and
// cannot be lost. Once stop begins, no further task is accepted and the runner
// drains everything accepted earlier before the backend joins it.
//
// Ownership: received records keep their receive credit until the application
// has copied every byte. Releasing credit publishes engine records, so records
// are destroyed on the runner, or anywhere once the endpoint has drained.
//
// A client with a device keeps its session up with the SessionKeeper yume
// uses, and its DeviceBridge runs for as long as the endpoint is started, so
// an application's connection fails at once while no session is active
// instead of waiting. A client without one makes one attempt per start.
namespace yume::embed {
namespace {

namespace v1 = config::v1;
using engine::Status;
using engine::StatusCode;
using Clock = std::chrono::steady_clock;

// The public write bound yume.h documents. A write is split into records no
// larger than the session allows and is still admitted all or none.
constexpr std::size_t kMaxWriteBytes = 256U * 1024U;
constexpr std::chrono::milliseconds kDefaultClientStart{30'000};
constexpr std::chrono::milliseconds kMaxStartDeadline{5 * 60 * 1'000};
constexpr std::chrono::milliseconds kClientStartGrace{5'000};
// Blocked calls re-check endpoint shutdown at this interval. Engine
// completions delivered during the final drain normally wake them sooner.
constexpr std::chrono::milliseconds kStopRecheck{100};
// Authenticated OPENs held for application accept across one endpoint. Each
// holds no receive credit until it is accepted.
constexpr std::size_t kMaxWaitingOpens = 256U;
constexpr std::string_view kServiceProviderId = "embed.ytp1.service";

std::atomic<std::uint64_t> g_next_affinity{UINT64_C(0x5954503145000001)};

BackendIo io_from(StatusCode code) noexcept {
    switch (code) {
    case StatusCode::Ok:
        return BackendIo::Ok;
    case StatusCode::InvalidArgument:
    case StatusCode::AlreadyExists:
        return BackendIo::Invalid;
    case StatusCode::ResourceExhausted:
        return BackendIo::ResourceExhausted;
    case StatusCode::PermissionDenied:
        return BackendIo::PermissionDenied;
    case StatusCode::AddressInUse:
        return BackendIo::AddressInUse;
    case StatusCode::NotFound:
        return BackendIo::NotFound;
    case StatusCode::ProviderMismatch:
        return BackendIo::Incompatible;
    case StatusCode::Cancelled:
    case StatusCode::Closed:
    case StatusCode::EndOfStream:
        return BackendIo::Closed;
    case StatusCode::FailedPrecondition:
    case StatusCode::Internal:
        return BackendIo::Failed;
    }
    return BackendIo::Failed;
}

// An OPEN refused after the session authenticated. The peer's unauthorized
// close arrives as FailedPrecondition while the session is still Active.
BackendIo open_io_from(StatusCode code) noexcept {
    return code == StatusCode::FailedPrecondition ? BackendIo::PermissionDenied
                                                  : io_from(code);
}

// Diagnostics are secondary to the typed outcome. Losing their text to an
// allocation failure must not replace that outcome.
void describe(std::string& error, std::string_view text) noexcept {
    try {
        error.assign(text);
    } catch (...) {
        error.clear();
    }
}

void describe(std::string& error, const Status& status,
              std::string_view fallback) noexcept {
    describe(error, status.message().empty()
                        ? fallback
                        : std::string_view(status.message()));
}

Status copy_status(const Status& status) noexcept {
    try {
        return Status(status.code(), status.message());
    } catch (...) {
        return Status(status.code());
    }
}

BackendPeerIdentity identity_from(const engine::PeerEvidence& evidence,
                                  std::string_view service) {
    static constexpr char kHex[] = "0123456789abcdef";
    BackendPeerIdentity identity;
    identity.service.assign(service);
    identity.peer_label = evidence.identity();
    identity.authenticated = true;
    identity.peer_is_server =
        evidence.peer_role() == engine::EndpointRole::Server;
    const auto fingerprint = evidence.credential_evidence();
    if (fingerprint.size() == 32U) {
        identity.fingerprint_sha256.resize(fingerprint.size() * 2U);
        for (std::size_t index = 0U; index < fingerprint.size(); ++index) {
            const auto byte = std::to_integer<unsigned>(fingerprint[index]);
            identity.fingerprint_sha256[index * 2U] = kHex[byte >> 4U];
            identity.fingerprint_sha256[index * 2U + 1U] = kHex[byte & 0x0fU];
        }
    }
    return identity;
}

BackendTraffic add(BackendTraffic total,
                   const engine::SessionTraffic& more) noexcept {
    total.payload_bytes_sent += more.payload_bytes_sent;
    total.payload_bytes_received += more.payload_bytes_received;
    total.record_bytes_sent += more.record_bytes_sent;
    total.record_bytes_received += more.record_bytes_received;
    return total;
}

// What one backend keeps across its runs: the lines it has said and the
// traffic of the sessions that ended with an earlier run.
struct BackendRecord final {
    void say(std::string_view text) noexcept { messages.add(text); }
    // "what: why", or what alone without a reason.
    void say(std::string_view what, std::string_view why) noexcept {
        if (why.empty()) {
            messages.add(what);
            return;
        }
        try {
            std::string text(what);
            text += ": ";
            text += why;
            messages.add(text);
        } catch (...) {
            messages.add(what);
        }
    }

    runtime::MessageLog messages;
    std::mutex mutex;
    BackendTraffic retired;
};

#if defined(YUME_HAS_DEVICE_BRIDGE)
using DeviceOptions = runtime::DeviceBridgeOptions;
#else
// No bridge on this platform, so no backend is ever made with a device.
struct DeviceOptions final {};
#endif

class NativeRun;

// Blocking application view of one authenticated engine stream. While the
// stream can still receive, one engine read stays pending, so a peer abort or
// session end is observed even when the application is not reading.
class NativeStream final : public std::enable_shared_from_this<NativeStream> {
public:
    NativeStream(std::shared_ptr<NativeRun> run,
                 std::shared_ptr<engine::StreamResponder> responder,
                 BackendPeerIdentity identity);
    ~NativeStream();

    NativeStream(const NativeStream&) = delete;
    NativeStream& operator=(const NativeStream&) = delete;

    // Runner only.
    void start_reading() noexcept { arm_read(); }
    void close_on_runner() noexcept;

    bool dead() const noexcept;
    const BackendPeerIdentity& identity() const noexcept { return identity_; }

    // Application threads. One reader and one writer may run concurrently.
    BackendIo read(void* out, std::size_t capacity, std::uint32_t timeout_ms,
                   std::size_t& bytes_read, std::string& error);
    BackendIo write(const void* data, std::size_t size,
                    std::uint32_t timeout_ms, std::string& error);
    BackendIo shutdown_write(std::uint32_t timeout_ms, std::string& error);
    BackendIo read_packets(void* storage, std::size_t storage_size,
                           std::span<BackendPacketSlot> slots,
                           std::uint32_t timeout_ms, std::size_t& packets_read,
                           std::size_t& required_storage, std::string& error);
    BackendIo write_packets(std::span<const BackendPacketView> packets,
                            std::uint32_t timeout_ms, std::string& error);
    void close() noexcept;

private:
    static void on_service(void* value) noexcept {
        static_cast<NativeStream*>(value)->service();
    }

    bool request_service() noexcept;
    void service() noexcept;
    void arm_read() noexcept;
    void on_read(engine::Result<engine::ReceivedRecord> result) noexcept;
    void pump_writes() noexcept;
    void on_write(Status status, std::size_t written,
                  std::size_t expected) noexcept;
    BackendIo admit_write(std::vector<engine::Buffer> chunks, std::size_t size,
                           Clock::time_point deadline, std::uint32_t timeout_ms,
                           std::string& error);
    void finish_shutdown() noexcept;
    void drop_records() noexcept;
    void fail_locked(std::string_view reason) noexcept;
    void fail_writes_locked(std::string_view reason) noexcept;
    BackendIo send_refusal_locked(std::string& error) const noexcept;
    bool stopped() const noexcept;
    template <typename Ready>
    bool wait_until(std::unique_lock<std::mutex>& lock,
                    Clock::time_point deadline, Ready ready);

    const std::shared_ptr<NativeRun> run_;
    const std::shared_ptr<engine::StreamResponder> responder_;
    const BackendPeerIdentity identity_;
    const std::size_t max_record_;
    const std::size_t max_packet_batch_;
    providers::ControlTask task_;

    mutable std::mutex mutex_;
    std::condition_variable cv_;

    // Inbound. Records before consumed_ are fully copied and wait for the
    // runner to release their credit. offset_ indexes records_[consumed_].
    std::deque<engine::ReceivedRecord> records_;
    std::size_t consumed_{0U};
    std::size_t offset_{0U};
    bool read_pending_{false};
    bool end_of_stream_{false};
    bool failed_{false};
    std::string failure_;
    bool local_closed_{false};
    bool closed_on_runner_{false};

    // Outbound. One accepted write is sent before the next is admitted.
    std::vector<engine::Buffer> chunks_;
    std::size_t next_chunk_{0U};
    std::size_t queued_bytes_{0U};
    bool write_in_flight_{false};
    bool write_failed_{false};
    std::string write_failure_;
    bool shutdown_requested_{false};
    bool shutdown_running_{false};
    bool shutdown_done_{false};
    bool shutdown_ok_{false};
    std::string shutdown_failure_;

    // Runner-only trampolines. An engine may complete inline, and re-entering
    // from that completion must continue the outer loop instead of recursing.
    bool arming_{false};
    bool arm_again_{false};
    bool pumping_{false};
    bool pump_again_{false};
};

struct WaitingOpen final {
    std::shared_ptr<NativeStream> stream;
    engine::StreamHandler::AcceptanceCompletion acceptance;
};

// One started endpoint: its execution context, the native endpoint created on
// the runner and the state shared with streams and blocked calls. The backend
// owns the runner thread and joins it after the final drain.
class NativeRun final : public std::enable_shared_from_this<NativeRun> {
public:
    NativeRun(std::shared_ptr<providers::AsioExecutionContext> execution,
              const v1::Config& endpoint_config,
              std::filesystem::path base_directory,
              std::filesystem::path resolver,
              const std::vector<BackendService>& registrations,
              providers::AsioTcpSocketProtector protector,
              std::shared_ptr<BackendRecord> log,
              std::optional<DeviceOptions> device_options);

    NativeRun(const NativeRun&) = delete;
    NativeRun& operator=(const NativeRun&) = delete;

    const std::shared_ptr<providers::AsioExecutionContext> context;
    const v1::Config config;
    const std::filesystem::path base;
    // SystemResolver helper program. Empty leaves names unresolvable.
    const std::filesystem::path resolver_program;
    const providers::AsioTcpSocketProtector socket_protector;
    const bool server;
    const std::shared_ptr<BackendRecord> record;
    // A client with a device keeps its session up and bridges the device.
    const std::optional<DeviceOptions> device;

    // A client without a device: its one session. Written on the runner
    // before start reports success and unchanged afterwards.
    std::shared_ptr<engine::SessionEngine> session;
    Clock::time_point connected_since{};
    // A client with a device: created with the endpoint, before start
    // reports success, and unchanged afterwards.
    std::shared_ptr<runtime::SessionKeeper> keeper;
#if defined(YUME_HAS_DEVICE_BRIDGE)
    std::shared_ptr<runtime::DeviceBridge> bridge;
#endif
    // The authenticated server. Without a keeper it is written before start
    // reports success and unchanged afterwards. With one it follows the
    // current session and only the runner reads it.
    BackendPeerIdentity server_peer;

    bool running() const noexcept {
        return phase_.load(std::memory_order_acquire) == Phase::Running;
    }
    bool drained() const noexcept {
        return phase_.load(std::memory_order_acquire) == Phase::Drained;
    }
    bool on_runner() const noexcept {
        return context->running_in_this_thread();
    }

    // Accepts a hand-over only while running. The phase lock serializes this
    // check with stop, so nothing is queued behind the final drain.
    bool submit(providers::ControlTask& task,
                std::shared_ptr<void> owner) noexcept;
    void run_until_drained() noexcept;
    void begin_stop() noexcept;
    void mark_drained() noexcept;
    void wait_drained() noexcept;

    // Runner only.
    Status create_endpoint(std::chrono::milliseconds client_start_timeout);
    const std::shared_ptr<runtime::NativeEndpoint>& endpoint() const noexcept {
        return endpoint_;
    }
    // The client's authenticated session, or nullptr while it has none.
    std::shared_ptr<engine::SessionEngine> active_session() const noexcept;
    // Opens the device bridge of a client that has a device.
    Status start_bridge();
    // Receives the keeper's state changes until an empty watcher replaces it.
    using StatusWatcher =
        std::function<void(const runtime::NativeClientStatus&)>;
    void watch_status(StatusWatcher watcher) noexcept {
        status_watcher_ = std::move(watcher);
    }

    // Any thread, once start has reported success.
    void fill_status(BackendStatus& status) const;
    engine::SessionTraffic traffic() const noexcept;
    // Starts a waiting keeper's next attempt now.
    void request_retry() noexcept;
    // Hands server accepts to the native endpoint. A later accept failure
    // stops this run.
    Status start_accepting() noexcept;
    const Status& accept_failure() const noexcept { return accept_failure_; }
    // Application threads.
    std::string_view stop_reason() const noexcept;
    void offer(std::size_t index, engine::StreamOpenContext open,
               std::shared_ptr<engine::StreamResponder> responder,
               engine::StreamHandler::AcceptanceCompletion acceptance);

    std::optional<std::size_t> waiting_index(
        std::string_view service,
        BackendServiceKind kind = BackendServiceKind::ByteStream) const noexcept;
    BackendIo accept(std::size_t index, std::uint32_t timeout_ms,
                     std::shared_ptr<NativeStream>& out, std::string& error);

private:
    enum class Phase : std::uint8_t {
        Running,
        Stopping,
        Drained,
    };

    static void on_close(void* value) noexcept {
        static_cast<NativeRun*>(value)->close_on_runner();
    }
    static void on_retry(void* value) noexcept {
        const auto* self = static_cast<NativeRun*>(value);
        if (self->running() && self->keeper) (void)self->keeper->retry_now();
    }

    void close_on_runner() noexcept;
    void wake_waiters() noexcept;
    void on_accept_failure(Status status) noexcept;
    void on_session_ended(const Status& reason) noexcept;
    void on_keeper_status(const runtime::NativeClientStatus& status) noexcept;
    void on_keeper_session(
        const std::shared_ptr<engine::SessionEngine>& session) noexcept;
    void on_keeper_failure(Status status) noexcept;

    std::atomic<Phase> phase_{Phase::Running};
    std::mutex phase_mutex_;
    std::condition_variable drained_cv_;
    providers::ControlTask close_task_;
    providers::ControlTask retry_task_;
    // Runner only.
    StatusWatcher status_watcher_;
    // Why a client's one session ended while the endpoint stayed started.
    mutable std::mutex ended_mutex_;
    bool ended_{false};
    BackendIo ended_io_{BackendIo::Ok};
    std::string ended_message_;
    std::atomic<std::size_t> runner_exceptions_{0U};
    std::atomic<bool> accept_failed_{false};

    // Runner only.
    std::shared_ptr<runtime::NativeEndpoint> endpoint_;
    runtime::NativeAcceptOptions accept_;
    Status accept_failure_;

    // Server OPENs waiting for an application accept, one queue per
    // registered service. The service list never changes.
    std::mutex waiting_mutex_;
    std::condition_variable waiting_cv_;
    std::vector<std::pair<BackendService, std::deque<WaitingOpen>>> waiting_;
    std::size_t waiting_count_{0U};
};

// Every configured service needs a handler. Only registered
// services on a server accept. Other entries refuse at authorization, so a
// service the application never registered cannot be opened by a peer.
class ServiceHandler final : public engine::StreamHandler {
public:
    ServiceHandler(engine::ProviderDescriptor descriptor,
                   engine::ServiceKind kind, std::weak_ptr<NativeRun> run,
                   std::optional<std::size_t> waiting_index) noexcept
        : descriptor_(std::move(descriptor)),
          kind_(kind),
          run_(std::move(run)),
          waiting_index_(waiting_index) {}

    const engine::ProviderDescriptor& descriptor() const noexcept override {
        return descriptor_;
    }
    engine::ServiceKind service_kind() const noexcept override { return kind_; }

    Status authorize(const engine::StreamOpenContext& open) override {
        if (open.destination_if()) {
            return Status(StatusCode::FailedPrecondition,
                          "application service does not accept routed destinations");
        }
        if (!waiting_index_) {
            return Status(StatusCode::FailedPrecondition,
                          "service is not accepting streams on this endpoint");
        }
        return Status::success();
    }

    void async_open(engine::StreamOpenContext context,
                    std::shared_ptr<engine::StreamResponder> stream,
                    AcceptanceCompletion completion) override {
        const auto run = run_.lock();
        if (!waiting_index_ || !run) {
            completion(Status(StatusCode::Closed));
            return;
        }
        run->offer(*waiting_index_, std::move(context), std::move(stream),
                   std::move(completion));
    }

    void on_open(engine::StreamOpenContext,
                 std::shared_ptr<engine::StreamResponder> stream) override {
        if (stream) stream->close(Status(StatusCode::FailedPrecondition));
    }

private:
    engine::ProviderDescriptor descriptor_;
    engine::ServiceKind kind_;
    std::weak_ptr<NativeRun> run_;
    std::optional<std::size_t> waiting_index_;
};

// Accepting publishes stream credit, so the runner performs it. The queued
// OPEN is taken before hand-over, and the runner settles it exactly once.
class AcceptOperation final {
public:
    explicit AcceptOperation(std::shared_ptr<NativeRun> run) noexcept
        : run_(std::move(run)) {}

    providers::ControlTask task{&AcceptOperation::on_task};
    WaitingOpen waiting;

private:
    static void on_task(void* value) noexcept {
        static_cast<AcceptOperation*>(value)->accept_on_runner();
    }
    void accept_on_runner() noexcept;

    std::shared_ptr<NativeRun> run_;
};

// A client OPEN outlives a timed-out caller. The first terminal transition
// wins under mutex_, and a late success is closed on the runner.
class OpenOperation final : public std::enable_shared_from_this<OpenOperation> {
public:
    OpenOperation(std::shared_ptr<NativeRun> run, std::string service,
                  std::optional<engine::RouteDestination> destination,
                  Clock::time_point deadline,
                  engine::ServiceKind kind = engine::ServiceKind::ByteStream)
        : run_(std::move(run)),
          service_(std::move(service)),
          destination_(std::move(destination)),
          deadline_(deadline),
          kind_(kind) {}

    providers::ControlTask open_task{&OpenOperation::on_open_task};
    providers::ControlTask cancel_task{&OpenOperation::on_cancel_task};

    BackendIo wait(std::shared_ptr<NativeStream>& out, std::string& error);

private:
    static void on_open_task(void* value) noexcept {
        static_cast<OpenOperation*>(value)->open_on_runner();
    }
    static void on_cancel_task(void* value) noexcept {
        static_cast<OpenOperation*>(value)->cancellation_.cancel();
    }
    void open_on_runner() noexcept;
    void on_opened(
        engine::Result<std::shared_ptr<engine::StreamResponder>> result) noexcept;
    void settle(BackendIo io, std::string_view reason) noexcept;

    std::shared_ptr<NativeRun> run_;
    const std::string service_;
    const std::optional<engine::RouteDestination> destination_;
    const Clock::time_point deadline_;
    const engine::ServiceKind kind_;
    engine::CancellationSource cancellation_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool done_{false};
    bool abandoned_{false};
    bool admitted_{false};
    BackendIo io_{BackendIo::Failed};
    std::shared_ptr<NativeStream> stream_;
    std::string failure_;
};

class StartOperation final
    : public std::enable_shared_from_this<StartOperation> {
public:
    StartOperation(std::shared_ptr<NativeRun> run,
                   std::chrono::milliseconds client_deadline) noexcept
        : run_(std::move(run)), client_deadline_(client_deadline) {}

    providers::ControlTask task{&StartOperation::on_task};

    bool wait(Clock::time_point limit, Status& result);

private:
    static void on_task(void* value) noexcept {
        static_cast<StartOperation*>(value)->start_on_runner();
    }
    void start_on_runner() noexcept;
    void on_session(
        engine::Result<std::shared_ptr<engine::SessionEngine>> result) noexcept;
    void on_kept(const runtime::NativeClientStatus& status) noexcept;
    void settle(Status status) noexcept;

    std::shared_ptr<NativeRun> run_;
    const std::chrono::milliseconds client_deadline_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool done_{false};
    Status status_;
};

// ---------------------------------------------------------------------------
// NativeStream

NativeStream::NativeStream(std::shared_ptr<NativeRun> run,
                           std::shared_ptr<engine::StreamResponder> responder,
                           BackendPeerIdentity identity)
    : run_(std::move(run)),
      responder_(std::move(responder)),
      identity_(std::move(identity)),
      max_record_(std::max<std::size_t>(1U, responder_->max_write_size())),
      max_packet_batch_(run_->config.limits().max_packet_batch()),
      task_(&NativeStream::on_service) {}

NativeStream::~NativeStream() {
    // The last reference leaves elsewhere with records still held only while
    // the endpoint is stopping: live streams are released by the runner task
    // that closes them. Wait for the drain instead of releasing credit here.
    if (!records_.empty() && !run_->on_runner()) run_->wait_drained();
}

bool NativeStream::dead() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return failed_ || local_closed_ || responder_->terminated();
}

bool NativeStream::stopped() const noexcept { return !run_->running(); }

template <typename Ready>
bool NativeStream::wait_until(std::unique_lock<std::mutex>& lock,
                              Clock::time_point deadline, Ready ready) {
    while (!ready()) {
        const auto now = Clock::now();
        if (now >= deadline) return false;
        cv_.wait_until(lock, std::min(deadline, now + kStopRecheck));
    }
    return true;
}

BackendIo NativeStream::read(void* out, std::size_t capacity,
                             std::uint32_t timeout_ms, std::size_t& bytes_read,
                             std::string& error) {
    bytes_read = 0U;
    const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    bool release = false;
    {
        std::unique_lock<std::mutex> lock(mutex_);
        const auto ready = [this] {
            return consumed_ < records_.size() || end_of_stream_ || failed_ ||
                   local_closed_ || stopped() || responder_->terminated();
        };
        if (!ready()) {
            if (timeout_ms == 0U) {
                describe(error, "no stream data is ready");
                return BackendIo::WouldBlock;
            }
            if (!wait_until(lock, deadline, ready)) {
                describe(error, "stream read deadline expired");
                return BackendIo::Timeout;
            }
        }
        if (local_closed_ || stopped() || responder_->terminated()) {
            describe(error, "stream or endpoint is closed");
            return BackendIo::Closed;
        }
        // A terminated stream discards undelivered records, as the engine does
        // for an aborted stream. Data is never followed by a false clean end.
        if (failed_) {
            describe(error, failure_.empty() ? std::string_view("stream closed")
                                             : std::string_view(failure_));
            return BackendIo::Closed;
        }
        auto* const destination = static_cast<std::byte*>(out);
        while (bytes_read < capacity && consumed_ < records_.size()) {
            const auto bytes = records_[consumed_].payload().bytes();
            const std::size_t count =
                std::min(capacity - bytes_read, bytes.size() - offset_);
            std::memcpy(destination + bytes_read, bytes.data() + offset_, count);
            bytes_read += count;
            offset_ += count;
            if (offset_ == bytes.size()) {
                ++consumed_;
                offset_ = 0U;
                release = true;
            }
        }
        if (bytes_read == 0U) {
            if (end_of_stream_) {
                error.clear();
                return BackendIo::Eof;
            }
            describe(error, "endpoint stopped");
            return BackendIo::Closed;
        }
    }
    if (release) (void)request_service();
    return BackendIo::Ok;
}

BackendIo NativeStream::send_refusal_locked(std::string& error) const noexcept {
    if (local_closed_ || responder_->terminated()) {
        describe(error, "stream is closed");
        return BackendIo::Closed;
    }
    if (failed_) {
        describe(error, failure_.empty() ? std::string_view("stream closed")
                                         : std::string_view(failure_));
        return BackendIo::Closed;
    }
    if (write_failed_) {
        describe(error, write_failure_.empty()
                            ? std::string_view("stream write failed")
                            : std::string_view(write_failure_));
        return BackendIo::Closed;
    }
    if (stopped()) {
        describe(error, "endpoint stopped");
        return BackendIo::Closed;
    }
    return BackendIo::Ok;
}

BackendIo NativeStream::read_packets(void* storage, std::size_t storage_size,
                                     std::span<BackendPacketSlot> slots,
                                     std::uint32_t timeout_ms,
                                     std::size_t& packets_read,
                                     std::size_t& required_storage,
                                     std::string& error) {
    packets_read = 0U;
    required_storage = 0U;
    if (slots.empty() || slots.size() > kMaxPacketBatch ||
        storage_size > kMaxPacketBatchBytes || (storage_size != 0U && !storage) ||
        responder_->service_kind() != engine::ServiceKind::PacketChannel) {
        describe(error, "packet read buffers or channel kind are invalid");
        return BackendIo::Invalid;
    }
    const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    {
        std::unique_lock<std::mutex> lock(mutex_);
        const auto ready = [this] {
            return consumed_ < records_.size() || end_of_stream_ || failed_ ||
                   local_closed_ || stopped() || responder_->terminated();
        };
        if (!ready()) {
            if (timeout_ms == 0U) {
                describe(error, "no packet is ready");
                return BackendIo::WouldBlock;
            }
            if (!wait_until(lock, deadline, ready)) {
                describe(error, "packet read deadline expired");
                return BackendIo::Timeout;
            }
        }
        if (local_closed_ || stopped() || responder_->terminated() || failed_) {
            describe(error, "packet channel or endpoint is closed");
            return BackendIo::Closed;
        }
        if (consumed_ == records_.size()) {
            error.clear();
            return end_of_stream_ ? BackendIo::Eof : BackendIo::Closed;
        }
        const auto first_size = records_[consumed_].payload().size();
        if (first_size > storage_size) {
            required_storage = first_size;
            describe(error, "storage cannot hold the first queued packet");
            return BackendIo::BufferTooSmall;
        }
        std::size_t offset = 0U;
        while (packets_read < std::min(slots.size(), max_packet_batch_) &&
               consumed_ < records_.size()) {
            const auto bytes = records_[consumed_].payload().bytes();
            if (bytes.size() > storage_size - offset) break;
            std::memcpy(static_cast<std::byte*>(storage) + offset, bytes.data(), bytes.size());
            slots[packets_read] = {offset, bytes.size()};
            ++packets_read;
            ++consumed_;
            offset += bytes.size();
        }
    }
    (void)request_service();
    error.clear();
    return BackendIo::Ok;
}

BackendIo NativeStream::write_packets(std::span<const BackendPacketView> packets,
                                      std::uint32_t timeout_ms, std::string& error) {
    if (packets.empty() || packets.size() > kMaxPacketBatch ||
        responder_->service_kind() != engine::ServiceKind::PacketChannel) {
        describe(error, "packet batch count or channel kind is invalid");
        return BackendIo::Invalid;
    }
    if (packets.size() > max_packet_batch_) {
        describe(error, "packet batch exceeds the endpoint's configured count bound");
        return BackendIo::ResourceExhausted;
    }
    std::size_t total = 0U;
    for (const auto& packet : packets) {
        if (!packet.data || packet.size == 0U ||
            packet.size > std::min(kMaxPacketBytes, max_record_)) {
            describe(error, "packet exceeds the channel's record bound or has no payload");
            return BackendIo::Invalid;
        }
        if (packet.size > kMaxPacketBatchBytes - total) {
            describe(error, "packet batch exceeds the admission bound");
            return BackendIo::ResourceExhausted;
        }
        total += packet.size;
    }
    const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    // Check admission before copying. One writer owns this direction; the
    // runner may drain an earlier batch while this caller waits.
    {
        std::unique_lock<std::mutex> lock(mutex_);
        const auto idle = [this] {
            return (queued_bytes_ == 0U && !write_in_flight_) || local_closed_ ||
                   failed_ || write_failed_ || shutdown_requested_ || stopped();
        };
        if (!idle()) {
            if (timeout_ms == 0U) {
                describe(error, "an earlier packet batch is still being sent");
                return BackendIo::WouldBlock;
            }
            if (!wait_until(lock, deadline, idle)) {
                describe(error, "packet write deadline expired");
                return BackendIo::Timeout;
            }
        }
        if (const auto refusal = send_refusal_locked(error); refusal != BackendIo::Ok) {
            return refusal;
        }
    }
    std::vector<engine::Buffer> chunks;
    chunks.reserve(packets.size());
    for (const auto& packet : packets) {
        auto chunk = engine::Buffer::copy_from(
            {static_cast<const std::byte*>(packet.data), packet.size}, packet.size);
        if (!chunk.ok()) {
            describe(error, chunk.status(), "packet allocation failed");
            return io_from(chunk.status().code());
        }
        chunks.push_back(std::move(chunk).take_value());
    }
    // Each buffer remains one packet. Admission swaps the complete vector;
    // allocation failure or a rejected batch changes no channel state.
    return admit_write(std::move(chunks), total, deadline, timeout_ms, error);
}

BackendIo NativeStream::write(const void* data, std::size_t size,
                              std::uint32_t timeout_ms, std::string& error) {
    if (size == 0U) return BackendIo::Ok;
    if (size > kMaxWriteBytes) {
        describe(error, "stream write exceeds the 256 KiB admission bound");
        return BackendIo::Invalid;
    }
    const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    // Copy before admission, so allocation failure changes no stream state.
    std::vector<engine::Buffer> chunks;
    chunks.reserve((size + max_record_ - 1U) / max_record_);
    const auto* bytes = static_cast<const std::byte*>(data);
    for (std::size_t offset = 0U; offset < size; offset += max_record_) {
        const std::size_t count = std::min(max_record_, size - offset);
        auto chunk = engine::Buffer::copy_from(
            std::span<const std::byte>(bytes + offset, count), count);
        if (!chunk.ok()) {
            describe(error, chunk.status(), "stream write allocation failed");
            return io_from(chunk.status().code());
        }
        chunks.push_back(std::move(chunk).take_value());
    }
    return admit_write(std::move(chunks), size, deadline, timeout_ms, error);
}

BackendIo NativeStream::admit_write(std::vector<engine::Buffer> chunks,
                                     std::size_t size, Clock::time_point deadline,
                                     std::uint32_t timeout_ms, std::string& error) {
    {
        std::unique_lock<std::mutex> lock(mutex_);
        const auto idle = [this] {
            return (queued_bytes_ == 0U && !write_in_flight_) ||
                   local_closed_ || failed_ || write_failed_ ||
                   shutdown_requested_ || stopped();
        };
        if (!idle()) {
            if (timeout_ms == 0U) {
                describe(error, "an earlier stream write is still being sent");
                return BackendIo::WouldBlock;
            }
            if (!wait_until(lock, deadline, idle)) {
                describe(error, "stream write deadline expired");
                return BackendIo::Timeout;
            }
        }
        if (const auto refusal = send_refusal_locked(error);
            refusal != BackendIo::Ok) {
            return refusal;
        }
        if (shutdown_requested_) {
            describe(error, "stream write side is shut down");
            return BackendIo::Closed;
        }
        chunks_.swap(chunks);
        next_chunk_ = 0U;
        queued_bytes_ = size;
    }
    if (!request_service()) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!write_in_flight_ && next_chunk_ == 0U) {
            chunks_.clear();
            queued_bytes_ = 0U;
        }
        describe(error, "endpoint stopped");
        return BackendIo::Closed;
    }
    return BackendIo::Ok;
}

BackendIo NativeStream::shutdown_write(std::uint32_t timeout_ms,
                                       std::string& error) {
    const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    bool submit = false;
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!shutdown_requested_) {
            const auto drained = [this] {
                return (queued_bytes_ == 0U && !write_in_flight_) ||
                       local_closed_ || failed_ || write_failed_ || stopped();
            };
            if (!drained()) {
                if (timeout_ms == 0U) {
                    describe(error, "accepted writes are still being sent");
                    return BackendIo::WouldBlock;
                }
                if (!wait_until(lock, deadline, drained)) {
                    describe(error,
                             "timed out draining writes before write shutdown");
                    return BackendIo::Timeout;
                }
            }
            if (const auto refusal = send_refusal_locked(error);
                refusal != BackendIo::Ok) {
                return refusal;
            }
            // The FIN follows every accepted write. No later write is admitted.
            shutdown_requested_ = true;
            submit = true;
        }
    }
    if (submit && !request_service()) {
        describe(error, "endpoint stopped");
        return BackendIo::Closed;
    }
    std::unique_lock<std::mutex> lock(mutex_);
    const auto settled = [this] {
        return shutdown_done_ || local_closed_ || stopped() ||
               responder_->terminated();
    };
    if (!settled()) {
        if (timeout_ms == 0U) {
            describe(error, "stream write shutdown is pending");
            return BackendIo::WouldBlock;
        }
        if (!wait_until(lock, deadline, settled)) {
            describe(error, "stream write shutdown deadline expired");
            return BackendIo::Timeout;
        }
    }
    if (const auto refusal = send_refusal_locked(error);
        refusal != BackendIo::Ok) return refusal;
    if (shutdown_done_ && shutdown_ok_) {
        error.clear();
        return BackendIo::Ok;
    }
    describe(error, !shutdown_failure_.empty()
                        ? std::string_view(shutdown_failure_)
                        : std::string_view("stream write shutdown failed"));
    return BackendIo::Closed;
}

void NativeStream::close() noexcept {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (local_closed_) return;
        local_closed_ = true;
    }
    cv_.notify_all();
    // A stopping endpoint ends the session instead, and the drain releases
    // whatever this stream still holds.
    (void)request_service();
}

bool NativeStream::request_service() noexcept {
    try {
        return run_->submit(task_, shared_from_this());
    } catch (...) {
        return false;
    }
}

void NativeStream::service() noexcept {
    for (;;) {
        std::optional<engine::ReceivedRecord> consumed;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (consumed_ == 0U) break;
            consumed.emplace(std::move(records_.front()));
            records_.pop_front();
            --consumed_;
        }
        // Receive credit returns here, outside the stream lock.
    }
    bool close_now = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        close_now = local_closed_ && !closed_on_runner_;
    }
    if (close_now) {
        close_on_runner();
        return;
    }
    pump_writes();
    finish_shutdown();
}

void NativeStream::close_on_runner() noexcept {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (closed_on_runner_) return;
        closed_on_runner_ = true;
        local_closed_ = true;
    }
    // Inline read and write completions observe local_closed_ and ignore
    // their results. The engine sends the terminal CLOSE.
    responder_->close(Status(StatusCode::Cancelled));
    drop_records();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        chunks_.clear();
        next_chunk_ = 0U;
        queued_bytes_ = 0U;
        if (shutdown_requested_ && !shutdown_done_) {
            shutdown_done_ = true;
            shutdown_ok_ = false;
        }
    }
    cv_.notify_all();
}

void NativeStream::drop_records() noexcept {
    for (;;) {
        std::optional<engine::ReceivedRecord> record;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (records_.empty()) {
                consumed_ = 0U;
                offset_ = 0U;
                return;
            }
            record.emplace(std::move(records_.front()));
            records_.pop_front();
            if (consumed_ != 0U) {
                --consumed_;
            } else {
                offset_ = 0U;
            }
        }
    }
}

void NativeStream::fail_locked(std::string_view reason) noexcept {
    failed_ = true;
    describe(failure_, reason.empty() ? std::string_view("stream closed")
                                      : reason);
}

void NativeStream::fail_writes_locked(std::string_view reason) noexcept {
    write_failed_ = true;
    describe(write_failure_,
             reason.empty() ? std::string_view("stream write failed") : reason);
    chunks_.clear();
    next_chunk_ = 0U;
    queued_bytes_ = 0U;
}

void NativeStream::arm_read() noexcept {
    if (arming_) {
        arm_again_ = true;
        return;
    }
    arming_ = true;
    do {
        arm_again_ = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (read_pending_ || end_of_stream_ || failed_ || local_closed_) {
                break;
            }
            read_pending_ = true;
        }
        try {
            responder_->async_read(
                {}, [self = shared_from_this()](
                        engine::Result<engine::ReceivedRecord> result) {
                    self->on_read(std::move(result));
                });
        } catch (...) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                read_pending_ = false;
                fail_locked("stream read could not be scheduled");
            }
            close_on_runner();
            cv_.notify_all();
            break;
        }
    } while (arm_again_);
    arming_ = false;
}

void NativeStream::on_read(
    engine::Result<engine::ReceivedRecord> result) noexcept {
    std::optional<engine::ReceivedRecord> record;
    Status failure;
    if (result.ok()) {
        record.emplace(std::move(result).take_value());
    } else {
        failure = copy_status(result.status());
    }
    bool rearm = false;
    bool drop = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        read_pending_ = false;
        if (local_closed_) {
            // close_on_runner owns the queued records.
        } else if (record) {
            try {
                records_.push_back(std::move(*record));
                rearm = true;
            } catch (const std::bad_alloc&) {
                fail_locked("stream receive queue allocation failed");
                drop = true;
            }
        } else if (failure.code() == StatusCode::EndOfStream) {
            end_of_stream_ = true;
        } else {
            fail_locked(failure.message());
            drop = true;
        }
    }
    // A record that was not queued releases its credit here, on the runner
    // and outside the stream lock.
    record.reset();
    if (drop) close_on_runner();
    cv_.notify_all();
    if (rearm) arm_read();
}

void NativeStream::pump_writes() noexcept {
    if (pumping_) {
        pump_again_ = true;
        return;
    }
    pumping_ = true;
    do {
        pump_again_ = false;
        std::optional<engine::Buffer> chunk;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (write_in_flight_ || local_closed_ || failed_ || write_failed_ ||
                next_chunk_ >= chunks_.size()) {
                break;
            }
            chunk.emplace(std::move(chunks_[next_chunk_]));
            ++next_chunk_;
            write_in_flight_ = true;
        }
        const std::size_t size = chunk->size();
        try {
            responder_->async_write(
                std::move(*chunk), {},
                [self = shared_from_this(), size](Status status,
                                                  std::size_t written) {
                    self->on_write(std::move(status), written, size);
                });
        } catch (...) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                write_in_flight_ = false;
                fail_writes_locked("stream write could not be scheduled");
            }
            close_on_runner();
            cv_.notify_all();
            break;
        }
    } while (pump_again_);
    pumping_ = false;
}

void NativeStream::on_write(Status status, std::size_t written,
                            std::size_t expected) noexcept {
    bool more = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        write_in_flight_ = false;
        if (!local_closed_) {
            if (status.ok() && written == expected) {
                queued_bytes_ -= std::min(queued_bytes_, expected);
                if (next_chunk_ < chunks_.size()) {
                    more = true;
                } else {
                    chunks_.clear();
                    next_chunk_ = 0U;
                }
            } else {
                fail_writes_locked(status.message());
            }
        }
    }
    cv_.notify_all();
    if (more) pump_writes();
    finish_shutdown();
}

void NativeStream::finish_shutdown() noexcept {
    bool perform = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!shutdown_requested_ || shutdown_done_ || shutdown_running_) return;
        if (local_closed_ || failed_ || write_failed_) {
            shutdown_done_ = true;
            shutdown_ok_ = false;
        } else if (!write_in_flight_ && queued_bytes_ == 0U) {
            shutdown_running_ = true;
            perform = true;
        } else {
            return;
        }
    }
    if (perform) {
        const Status status = responder_->shutdown_write();
        std::lock_guard<std::mutex> lock(mutex_);
        shutdown_running_ = false;
        shutdown_done_ = true;
        shutdown_ok_ = status.ok();
        if (!status.ok()) describe(shutdown_failure_, status.message());
    }
    cv_.notify_all();
}

// ---------------------------------------------------------------------------
// Operations

void AcceptOperation::accept_on_runner() noexcept {
    auto acceptance = std::move(waiting.acceptance);
    waiting.acceptance = nullptr;
    if (acceptance) {
        if (run_->running() && !waiting.stream->dead()) {
            try {
                acceptance(Status::success());
            } catch (...) {
            }
        } else {
            try {
                acceptance(Status(run_->running() ? StatusCode::Cancelled
                                                  : StatusCode::Closed));
            } catch (...) {
            }
        }
    }
}

void OpenOperation::open_on_runner() noexcept {
    const auto session = run_->active_session();
    if (!run_->running() || !session) {
        settle(BackendIo::NotRunning, "client session is not active");
        return;
    }
    bool admitted = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (done_ || abandoned_) return;
        if (Clock::now() >= deadline_) {
            done_ = true;
            io_ = BackendIo::Timeout;
            describe(failure_, "stream OPEN timed out before admission");
        } else {
            // This admission decision and caller abandonment are ordered by
            // the same mutex. Engine callbacks may complete inline, so release
            // it before starting OPEN; later abandonment queues cancellation.
            admitted_ = true;
            admitted = true;
        }
    }
    if (!admitted) {
        cv_.notify_all();
        return;
    }
    try {
        session->async_open(
            service_, kind_, destination_,
            cancellation_.token(),
            [self = shared_from_this()](
                engine::Result<std::shared_ptr<engine::StreamResponder>> result) {
                self->on_opened(std::move(result));
            });
    } catch (...) {
        settle(BackendIo::ResourceExhausted,
               "stream OPEN could not be scheduled");
    }
}

void OpenOperation::on_opened(
    engine::Result<std::shared_ptr<engine::StreamResponder>> result) noexcept {
    std::shared_ptr<NativeStream> stream;
    BackendIo io = BackendIo::Ok;
    Status failure;
    if (result.ok()) {
        const std::shared_ptr<engine::StreamResponder> responder = result.value();
        try {
            BackendPeerIdentity identity = run_->server_peer;
            identity.service = service_;
            stream = std::make_shared<NativeStream>(run_, responder,
                                                    std::move(identity));
            stream->start_reading();
            if (stream->dead()) {
                stream->close_on_runner();
                stream.reset();
                io = BackendIo::ResourceExhausted;
            }
        } catch (...) {
            responder->close(Status(StatusCode::ResourceExhausted));
            stream.reset();
            io = BackendIo::ResourceExhausted;
        }
    } else {
        failure = copy_status(result.status());
        io = !run_->active_session() ? BackendIo::NotRunning
                                     : open_io_from(failure.code());
    }
    bool close_late = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (abandoned_) {
            close_late = static_cast<bool>(stream);
        } else {
            done_ = true;
            io_ = io;
            stream_ = stream;
            describe(failure_, failure, "stream OPEN failed");
        }
    }
    if (close_late) stream->close_on_runner();
    cv_.notify_all();
}

void OpenOperation::settle(BackendIo io, std::string_view reason) noexcept {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (done_ || abandoned_) return;
        done_ = true;
        io_ = io;
        describe(failure_, reason);
    }
    cv_.notify_all();
}

BackendIo OpenOperation::wait(std::shared_ptr<NativeStream>& out,
                              std::string& error) {
    std::unique_lock<std::mutex> lock(mutex_);
    while (!done_) {
        const auto now = Clock::now();
        if (now >= deadline_ || !run_->running()) break;
        cv_.wait_until(lock, std::min(deadline_, now + kStopRecheck));
    }
    if (done_) {
        if (io_ == BackendIo::Ok) {
            out = std::move(stream_);
            error.clear();
            return BackendIo::Ok;
        }
        describe(error, failure_);
        return io_;
    }
    abandoned_ = true;
    const bool cancel = admitted_;
    lock.unlock();
    // The OPEN may already be on the wire. Cancellation sends an abort, or
    // drops an OPEN still held behind a rekey, and a crossed acceptance is
    // closed by on_opened.
    if (!run_->running() ||
        (cancel && !run_->submit(cancel_task, shared_from_this()))) {
        describe(error, "client endpoint is stopping");
        return BackendIo::NotRunning;
    }
    describe(error, "stream OPEN timed out");
    return BackendIo::Timeout;
}

bool StartOperation::wait(Clock::time_point limit, Status& result) {
    std::unique_lock<std::mutex> lock(mutex_);
    if (!cv_.wait_until(lock, limit, [this] { return done_; })) return false;
    result = copy_status(status_);
    return true;
}

void StartOperation::start_on_runner() noexcept {
    try {
        // A cancelled start reached the runner after its stop.
        if (!run_->running()) {
            settle(Status(StatusCode::Cancelled));
            return;
        }
        Status created = run_->create_endpoint(client_deadline_);
        if (!created.ok()) {
            settle(std::move(created));
            return;
        }
        if (run_->server) {
            Status accepting = run_->start_accepting();
            // A listener that failed while arming has already closed the endpoint.
            if (accepting.ok() && !run_->running()) {
                accepting = run_->accept_failure().ok()
                    ? Status(StatusCode::Closed)
                    : copy_status(run_->accept_failure());
            }
            settle(std::move(accepting));
            return;
        }
        if (run_->keeper) {
            Status bridged = run_->start_bridge();
            if (!bridged.ok()) {
                settle(std::move(bridged));
                return;
            }
            // Start reports the first attempt. The keeper makes the later
            // ones for as long as the endpoint stays started.
            run_->watch_status([self = shared_from_this()](
                                   const runtime::NativeClientStatus& status) {
                self->on_kept(status);
            });
            run_->keeper->start();
            return;
        }
        Status accepted = run_->endpoint()->async_start_session(
            [self = shared_from_this()](
                engine::Result<std::shared_ptr<engine::SessionEngine>> result) {
                self->on_session(std::move(result));
            });
        if (!accepted.ok()) settle(std::move(accepted));
    } catch (const std::bad_alloc&) {
        settle(Status(StatusCode::ResourceExhausted));
    } catch (...) {
        settle(Status(StatusCode::Internal));
    }
}

void StartOperation::on_session(
    engine::Result<std::shared_ptr<engine::SessionEngine>> result) noexcept {
    if (!result.ok()) {
        settle(copy_status(result.status()));
        return;
    }
    const std::shared_ptr<engine::SessionEngine> session = result.value();
    // Streams report the identity YTP authenticated, never a value derived
    // from configuration or the outer TLS channel.
    auto peer = session->authenticated_peer();
    if (!peer.ok()) {
        session->stop(Status(StatusCode::Closed));
        settle(copy_status(peer.status()));
        return;
    }
    try {
        run_->server_peer = identity_from(peer.value(), {});
    } catch (...) {
        session->stop(Status(StatusCode::Closed));
        settle(Status(StatusCode::ResourceExhausted));
        return;
    }
    run_->session = session;
    run_->connected_since = Clock::now();
    settle(Status::success());
}

void StartOperation::on_kept(
    const runtime::NativeClientStatus& status) noexcept {
    using State = runtime::NativeClientState;
    if (status.state == State::Connected) {
        run_->watch_status({});
        settle(Status::success());
    } else if (status.state == State::Waiting ||
               status.state == State::Closed) {
        run_->watch_status({});
        settle(status.last_failure.ok() ? Status(StatusCode::Internal)
                                        : copy_status(status.last_failure));
    }
}

void StartOperation::settle(Status status) noexcept {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (done_) return;
        done_ = true;
        status_ = std::move(status);
    }
    cv_.notify_all();
}

// ---------------------------------------------------------------------------
// NativeRun

NativeRun::NativeRun(std::shared_ptr<providers::AsioExecutionContext> execution,
                     const v1::Config& endpoint_config,
                     std::filesystem::path base_directory,
                     std::filesystem::path resolver,
                     const std::vector<BackendService>& registrations,
                     providers::AsioTcpSocketProtector protector,
                     std::shared_ptr<BackendRecord> log,
                     std::optional<DeviceOptions> device_options)
    : context(std::move(execution)),
      config(endpoint_config),
      base(std::move(base_directory)),
      resolver_program(std::move(resolver)),
      socket_protector(std::move(protector)),
      server(endpoint_config.role() == v1::Role::Server),
      record(std::move(log)),
      device(std::move(device_options)),
      close_task_(&NativeRun::on_close),
      retry_task_(&NativeRun::on_retry) {
    if (!server) return;
    for (const auto& registration : registrations) {
        waiting_.emplace_back(registration, std::deque<WaitingOpen>{});
    }
}

bool NativeRun::submit(providers::ControlTask& task,
                       std::shared_ptr<void> owner) noexcept {
    std::lock_guard<std::mutex> lock(phase_mutex_);
    if (!running()) return false;
    context->submit(task, std::move(owner));
    return true;
}

void NativeRun::run_until_drained() noexcept {
    for (;;) {
        try {
            context->run();
            mark_drained();
            return;
        } catch (...) {
            // An escaped delivery exception cannot identify which session
            // lost its callback. Close every owner and resume the final drain.
            runner_exceptions_.fetch_add(1U, std::memory_order_relaxed);
            begin_stop();
            context->finish();
        }
    }
}

void NativeRun::begin_stop() noexcept {
    {
        std::lock_guard<std::mutex> lock(phase_mutex_);
        if (!running()) return;
        phase_.store(Phase::Stopping, std::memory_order_release);
        // Reserved control delivery allocates nothing and cannot be refused.
        context->submit(close_task_, shared_from_this());
    }
    wake_waiters();
}

void NativeRun::mark_drained() noexcept {
    {
        std::lock_guard<std::mutex> lock(phase_mutex_);
        phase_.store(Phase::Drained, std::memory_order_release);
    }
    drained_cv_.notify_all();
    wake_waiters();
}

void NativeRun::wait_drained() noexcept {
    std::unique_lock<std::mutex> lock(phase_mutex_);
    drained_cv_.wait(lock, [this] { return drained(); });
}

void NativeRun::wake_waiters() noexcept {
    {
        std::lock_guard<std::mutex> lock(waiting_mutex_);
    }
    waiting_cv_.notify_all();
}

void NativeRun::close_on_runner() noexcept {
    status_watcher_ = {};
#if defined(YUME_HAS_DEVICE_BRIDGE)
    if (bridge) bridge->close();
#endif
    if (keeper) keeper->close();
    if (endpoint_) endpoint_->close();
    // Refuse OPENs still waiting for the application while their sessions are
    // alive, so each peer sees a definite refusal before the sessions close.
    for (;;) {
        WaitingOpen waiting;
        bool found = false;
        {
            std::lock_guard<std::mutex> lock(waiting_mutex_);
            for (auto& entry : waiting_) {
                if (!entry.second.empty()) {
                    waiting = std::move(entry.second.front());
                    entry.second.pop_front();
                    --waiting_count_;
                    found = true;
                    break;
                }
            }
        }
        if (!found) break;
        if (waiting.acceptance) {
            try {
                waiting.acceptance(Status(StatusCode::Closed));
            } catch (...) {
            }
        }
    }
    wake_waiters();
}

Status NativeRun::create_endpoint(
    std::chrono::milliseconds client_start_timeout) {
    std::vector<runtime::NativeServiceBinding> bindings;
    bindings.reserve(config.services().size());
    for (const auto& service : config.services()) {
        const bool packet = service.kind() == v1::ServiceKind::Packet;
        auto capabilities = engine::mandatory_capabilities(
            engine::ProviderKind::StreamHandler);
        if (packet) {
            capabilities = capabilities.with(engine::Capability::PacketChannels);
        }
        auto descriptor = engine::ProviderDescriptor::create(
            std::string(kServiceProviderId), engine::ProviderKind::StreamHandler,
            1U, capabilities);
        if (!descriptor.ok()) return copy_status(descriptor.status());
        const std::optional<std::size_t> queue = waiting_index(service.name(),
            packet ? BackendServiceKind::Packet : BackendServiceKind::ByteStream);
        bindings.push_back({service.name(),
                            std::make_shared<ServiceHandler>(
                                std::move(descriptor).take_value(),
                                packet ? engine::ServiceKind::PacketChannel
                                       : engine::ServiceKind::ByteStream,
                                weak_from_this(), queue)});
    }

    runtime::NativeEndpointOptions options;
    std::size_t listener_count = 0U;
    if (server) {
        listener_count =
            std::get<v1::ServerEndpoint>(config.endpoint()).listen_addresses().size();
        if (listener_count == 0U) {
            return Status(StatusCode::InvalidArgument,
                          "server endpoint has no listen address");
        }
        const auto sizing = runtime::native_server_sizing(listener_count);
        accept_ = sizing.accept;
        options.max_sessions = sizing.max_sessions;
        options.max_pending_starts = sizing.max_pending_starts;
    } else {
        options.max_sessions = 1U;
        options.max_pending_starts = 1U;
        options.start_timeout = client_start_timeout;
        options.socket_protector = socket_protector;
        const std::weak_ptr<NativeRun> weak = weak_from_this();
        if (device) {
            runtime::SessionKeeperOptions keeping;
            keeping.report = [log = record](std::string_view text) {
                log->say(text);
            };
            keeping.on_status =
                [weak](const runtime::NativeClientStatus& status) {
                    if (const auto self = weak.lock()) {
                        self->on_keeper_status(status);
                    }
                };
            keeping.on_authenticated =
                [weak](const std::shared_ptr<engine::SessionEngine>& active) {
                    if (const auto self = weak.lock()) {
                        self->on_keeper_session(active);
                    }
                };
            keeper = std::make_shared<runtime::SessionKeeper>(
                context, std::move(keeping), [weak](Status status) {
                    if (const auto self = weak.lock()) {
                        self->on_keeper_failure(std::move(status));
                    }
                });
            options.session_ended = keeper->session_ended();
        } else {
            options.session_ended =
                [weak](std::shared_ptr<engine::SessionEngine>, Status reason) {
                    if (const auto self = weak.lock()) {
                        self->on_session_ended(reason);
                    }
                };
        }
    }
    if (!resolver_program.empty()) {
        providers::SystemResolverOptions resolver_options;
        resolver_options.program = resolver_program;
        auto resolver = providers::SystemResolver::create(context, std::move(resolver_options));
        if (!resolver.ok()) return copy_status(resolver.status());
        options.resolver = std::move(resolver).take_value();
    }

    auto created = runtime::NativeEndpoint::create(
        context, config, base, std::move(bindings), std::move(options));
    if (!created.ok()) return copy_status(created.status());
    endpoint_ = std::move(created).take_value();
    if (keeper) keeper->attach(endpoint_);
    return Status::success();
}

std::shared_ptr<engine::SessionEngine> NativeRun::active_session()
    const noexcept {
    if (keeper) return keeper->active_session();
    return session && session->state() == engine::SessionState::Active
               ? session
               : nullptr;
}

Status NativeRun::start_bridge() {
#if defined(YUME_HAS_DEVICE_BRIDGE)
    if (!device) return Status::success();
    const std::weak_ptr<NativeRun> weak = weak_from_this();
    auto created = runtime::DeviceBridge::create(
        context, *device,
        [weak]() -> std::shared_ptr<engine::SessionEngine> {
            const auto self = weak.lock();
            return self ? self->active_session() : nullptr;
        },
        [weak](Status status) {
            if (const auto self = weak.lock()) {
                self->record->say("device bridge stopped", status.message());
            }
        });
    if (!created.ok()) return copy_status(created.status());
    bridge = std::move(created).take_value();
#endif
    return Status::success();
}

// A client's one session ended on its own. A stop ends it too, and that is
// not a failure.
void NativeRun::on_session_ended(const Status& reason) noexcept {
    if (!running()) return;
    {
        std::lock_guard<std::mutex> lock(ended_mutex_);
        if (ended_) return;
        ended_ = true;
        ended_io_ = reason.ok() ? BackendIo::Closed : io_from(reason.code());
        describe(ended_message_, reason, "session ended");
    }
    record->say("session ended", reason.message());
}

void NativeRun::on_keeper_status(
    const runtime::NativeClientStatus& status) noexcept {
    try {
        // The watcher may replace itself, so call a copy.
        const StatusWatcher watcher = status_watcher_;
        if (watcher) watcher(status);
    } catch (...) {
    }
}

void NativeRun::on_keeper_session(
    const std::shared_ptr<engine::SessionEngine>& active) noexcept {
    try {
        auto peer = active->authenticated_peer();
        server_peer =
            peer.ok() ? identity_from(peer.value(), {}) : BackendPeerIdentity{};
    } catch (...) {
        server_peer = BackendPeerIdentity{};
    }
}

// The keeper met a failure it cannot retry, so nothing would reconnect.
void NativeRun::on_keeper_failure(Status status) noexcept {
    if (keeper) keeper->record_failure(status);
    record->say("session keeping stopped", status.message());
    begin_stop();
}

engine::SessionTraffic NativeRun::traffic() const noexcept {
    try {
        if (keeper) return keeper->status().traffic;
    } catch (...) {
        return {};
    }
    return session ? session->traffic() : engine::SessionTraffic{};
}

void NativeRun::fill_status(BackendStatus& status) const {
    status.traffic = add(status.traffic, traffic());
#if defined(YUME_HAS_DEVICE_BRIDGE)
    if (bridge) {
        status.device_tcp_connections = bridge->tcp_connections();
        status.device_udp_destinations = bridge->udp_destinations();
    }
#endif
    if (keeper) {
        using State = runtime::NativeClientState;
        const runtime::NativeClientStatus kept = keeper->status();
        status.sessions = kept.sessions;
        status.failed_attempts = kept.failed_attempts;
        if (!kept.last_failure.ok()) {
            status.failure = io_from(kept.last_failure.code());
            describe(status.failure_message, kept.last_failure,
                     "session failed");
        }
        if (!running()) return;
        switch (kept.state) {
            case State::Connecting:
                status.session = BackendSession::Connecting;
                break;
            case State::Connected:
                status.session = BackendSession::Active;
                status.connected_ms = static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        Clock::now() - kept.connected_since)
                        .count());
                status.epoch_bytes = kept.epoch_bytes.value_or(0U);
                status.peer_fingerprint_sha256 = kept.server_identity;
                break;
            case State::Waiting:
                status.session = BackendSession::Waiting;
                status.retry_ms =
                    static_cast<std::uint64_t>(kept.retry_delay.count());
                break;
            case State::Idle:
            case State::Closed:
                break;
        }
        return;
    }
    {
        std::lock_guard<std::mutex> lock(ended_mutex_);
        if (ended_) {
            status.failure = ended_io_;
            status.failure_message = ended_message_;
        }
    }
    if (!session || !running()) return;
    if (session->state() != engine::SessionState::Active) {
        status.session = BackendSession::Ended;
        return;
    }
    status.session = BackendSession::Active;
    status.sessions = 1U;
    status.connected_ms = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() -
                                                              connected_since)
            .count());
    status.epoch_bytes = session->epoch_bytes().value_or(0U);
    status.peer_fingerprint_sha256 = server_peer.fingerprint_sha256;
}

void NativeRun::request_retry() noexcept {
    try {
        (void)submit(retry_task_, shared_from_this());
    } catch (...) {
    }
}

Status NativeRun::start_accepting() noexcept {
    try {
        const std::weak_ptr<NativeRun> weak = weak_from_this();
        return endpoint_->start_accepting(accept_, [weak](Status status) {
            if (const auto self = weak.lock()) self->on_accept_failure(std::move(status));
        });
    } catch (const std::bad_alloc&) {
        return Status(StatusCode::ResourceExhausted);
    } catch (...) {
        return Status(StatusCode::Internal);
    }
}

// The native endpoint has already begun closing its sessions. Accept calls
// report the stop until the application stops and restarts the endpoint.
void NativeRun::on_accept_failure(Status status) noexcept {
    record->say("stopped accepting", status.message());
    accept_failure_ = std::move(status);
    accept_failed_.store(true, std::memory_order_release);
    begin_stop();
}

std::string_view NativeRun::stop_reason() const noexcept {
    return accept_failed_.load(std::memory_order_acquire)
        ? "server endpoint stopped because it could no longer accept sessions"
        : "server endpoint is stopping";
}

std::optional<std::size_t> NativeRun::waiting_index(
    std::string_view service, BackendServiceKind kind) const noexcept {
    for (std::size_t index = 0U; index < waiting_.size(); ++index) {
        if (waiting_[index].first.name == service && waiting_[index].first.kind == kind) return index;
    }
    return std::nullopt;
}

void NativeRun::offer(std::size_t index, engine::StreamOpenContext open,
                      std::shared_ptr<engine::StreamResponder> responder,
                      engine::StreamHandler::AcceptanceCompletion acceptance) {
    if (!running()) {
        acceptance(Status(StatusCode::Closed));
        return;
    }
    auto stream = std::make_shared<NativeStream>(
        shared_from_this(), std::move(responder),
        identity_from(open.peer_evidence(), open.service_name()));
    // The pending read reports a peer abort or session end while this OPEN
    // waits. The peer cannot send data before acceptance grants credit.
    stream->start_reading();
    WaitingOpen waiting{stream, std::move(acceptance)};
    bool queued = false;
    if (!stream->dead()) {
        try {
            std::lock_guard<std::mutex> lock(waiting_mutex_);
            // Cancelled OPENs must not occupy every waiting slot until an
            // application next accepts. This scan is bounded by the global
            // waiting limit; waiting streams hold no inbound records/credit.
            for (auto& entry : waiting_) {
                for (auto it = entry.second.begin(); it != entry.second.end();) {
                    if (it->stream->dead()) {
                        it = entry.second.erase(it);
                        --waiting_count_;
                    } else {
                        ++it;
                    }
                }
            }
            if (running() && waiting_count_ < kMaxWaitingOpens) {
                waiting_[index].second.push_back(std::move(waiting));
                ++waiting_count_;
                queued = true;
            }
        } catch (const std::bad_alloc&) {
        }
    }
    if (!queued) {
        // The refusal aborts the stream, which settles its pending read.
        waiting.acceptance(Status(StatusCode::ResourceExhausted));
        return;
    }
    waiting_cv_.notify_all();
}

BackendIo NativeRun::accept(std::size_t index, std::uint32_t timeout_ms,
                            std::shared_ptr<NativeStream>& out,
                            std::string& error) {
    out.reset();
    const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    // Allocate before taking an OPEN, so a failure cannot strand its
    // acceptance on an application thread.
    auto operation = std::make_shared<AcceptOperation>(shared_from_this());
    {
        std::unique_lock<std::mutex> lock(waiting_mutex_);
        auto& queue = waiting_[index].second;
        const auto ready = [this, &queue] {
            while (!queue.empty() && queue.front().stream->dead()) {
                queue.pop_front();
                --waiting_count_;
            }
            return !queue.empty() || !running();
        };
        if (!ready()) {
            if (timeout_ms == 0U) {
                describe(error, "no authenticated OPEN is waiting for this service");
                return BackendIo::WouldBlock;
            }
            while (!ready()) {
                const auto now = Clock::now();
                if (now >= deadline) {
                    describe(error, "stream accept deadline expired");
                    return BackendIo::Timeout;
                }
                waiting_cv_.wait_until(lock,
                                       std::min(deadline, now + kStopRecheck));
            }
        }
        if (!running()) {
            describe(error, stop_reason());
            return BackendIo::NotRunning;
        }
        operation->waiting = std::move(queue.front());
        queue.pop_front();
        --waiting_count_;
    }
    if (!submit(operation->task, operation)) {
        // Stopping won. Ending the session settles this OPEN.
        describe(error, stop_reason());
        return BackendIo::NotRunning;
    }
    // Application acceptance takes ownership here. The runner publishes
    // peer credit in queue order; waiting for that hand-over would make a
    // zero-timeout accept block. A crossed abort leaves a closed handle.
    out = operation->waiting.stream;
    error.clear();
    return BackendIo::Ok;
}

// ---------------------------------------------------------------------------
// Backend

class NativeBackendStream final : public BackendStream {
public:
    ~NativeBackendStream() override { close(); }

    void attach(std::shared_ptr<NativeStream> stream) noexcept {
        stream_ = std::move(stream);
    }

    BackendIo read(void* out, std::size_t capacity, std::uint32_t timeout_ms,
                   std::size_t& bytes_read, std::string& error) override {
        bytes_read = 0U;
        if (!stream_) return closed(error);
        return stream_->read(out, capacity, timeout_ms, bytes_read, error);
    }

    BackendIo write(const void* data, std::size_t size,
                    std::uint32_t timeout_ms, std::string& error) override {
        if (!stream_) return closed(error);
        return stream_->write(data, size, timeout_ms, error);
    }

    BackendIo shutdown_write(std::uint32_t timeout_ms,
                             std::string& error) override {
        if (!stream_) return closed(error);
        return stream_->shutdown_write(timeout_ms, error);
    }

    // The peer has already accepted the stream. Closing a handle that was
    // never published aborts it exactly like closing a published one.
    void publish() noexcept override {}

    void close() noexcept override {
        if (stream_) stream_->close();
    }

    BackendPeerIdentity peer_identity() const override {
        return stream_ ? stream_->identity() : BackendPeerIdentity{};
    }

private:
    static BackendIo closed(std::string& error) noexcept {
        describe(error, "stream is closed");
        return BackendIo::Closed;
    }

    std::shared_ptr<NativeStream> stream_;
};

class NativeBackendPacket final : public BackendPacket {
public:
    ~NativeBackendPacket() override { close(); }
    void attach(std::shared_ptr<NativeStream> stream) noexcept {
        stream_ = std::move(stream);
    }
    BackendIo write(std::span<const BackendPacketView> packets,
                    std::uint32_t timeout_ms, std::string& error) override {
        if (!stream_) return BackendIo::Closed;
        return stream_->write_packets(packets, timeout_ms, error);
    }
    BackendIo read(void* storage, std::size_t storage_size,
                   std::span<BackendPacketSlot> slots, std::uint32_t timeout_ms,
                   std::size_t& packets_read, std::size_t& required_storage,
                   std::string& error) override {
        packets_read = 0U;
        required_storage = 0U;
        if (!stream_) return BackendIo::Closed;
        return stream_->read_packets(storage, storage_size, slots, timeout_ms,
                                      packets_read, required_storage, error);
    }
    void publish() noexcept override {}
    void close() noexcept override { if (stream_) stream_->close(); }
    BackendPeerIdentity peer_identity() const override {
        return stream_ ? stream_->identity() : BackendPeerIdentity{};
    }
private:
    std::shared_ptr<NativeStream> stream_;
};

class NativeBackend final : public EndpointBackend {
public:
    NativeBackend(const v1::Config& config, std::filesystem::path base,
                  std::filesystem::path resolver_program,
                  std::vector<BackendService> registrations,
                  SocketProtector socket_protector,
                  std::optional<DeviceOptions> device)
        : config_(config),
          base_(std::move(base)),
          resolver_program_(std::move(resolver_program)),
          registrations_(std::move(registrations)),
          socket_protector_(std::move(socket_protector)),
          device_(std::move(device)),
          record_(std::make_shared<BackendRecord>()) {}

    // A caller may drop the handle without stopping first. The runner is
    // joined before the endpoint state it drives is released.
    ~NativeBackend() override { stop(); }

    BackendIo start(std::uint32_t timeout_ms,
                    const std::shared_ptr<StartCancellation>& cancellation,
                    std::string& error) override;
    void stop() noexcept override;
    bool running() const noexcept override;
    BackendStatus status() const override;
    BackendMessage message_after(std::uint64_t after) const override;
    BackendIo retry_now() noexcept override;
    BackendIo open_stream(const std::string& service,
                          const std::optional<BackendDestination>& destination,
                          std::uint32_t timeout_ms,
                          std::unique_ptr<BackendStream>& out,
                          std::string& error) override;
    BackendIo accept_stream(const std::string& service,
                            std::uint32_t timeout_ms,
                            std::unique_ptr<BackendStream>& out,
                            std::string& error) override;
    BackendIo open_packet(const std::string& service,
                          const std::optional<BackendDestination>& destination,
                          std::uint32_t timeout_ms,
                          std::unique_ptr<BackendPacket>& out,
                          std::string& error) override;
    BackendIo accept_packet(const std::string& service,
                            std::uint32_t timeout_ms,
                            std::unique_ptr<BackendPacket>& out,
                            std::string& error) override;

private:
    std::shared_ptr<NativeRun> current() const noexcept {
        std::lock_guard<std::mutex> lock(run_mutex_);
        return run_;
    }
    static void shutdown(const std::shared_ptr<NativeRun>& run,
                         std::thread& runner) noexcept;
    BackendIo start_run(std::uint32_t timeout_ms,
                        const std::shared_ptr<StartCancellation>& cancellation,
                        std::string& error);

    const v1::Config config_;
    const std::filesystem::path base_;
    const std::filesystem::path resolver_program_;
    const std::vector<BackendService> registrations_;
    const SocketProtector socket_protector_;
    const std::optional<DeviceOptions> device_;
    const std::shared_ptr<BackendRecord> record_;
    std::mutex lifecycle_mutex_;
    mutable std::mutex run_mutex_;
    std::shared_ptr<NativeRun> run_;
    std::thread runner_;
};

void NativeBackend::shutdown(const std::shared_ptr<NativeRun>& run,
                           std::thread& runner) noexcept {
    if (!run) return;
    run->begin_stop();
    run->context->finish();
    if (runner.joinable()) {
        if (runner.get_id() == std::this_thread::get_id()) {
            // Unreachable through the ABI, which refuses lifecycle calls from
            // callbacks. There is no safe teardown from the owned runner:
            // detaching would release callback owners before final drain.
            std::terminate();
        } else {
            try {
                runner.join();
            } catch (...) {
                // A joinable thread cannot be released without establishing
                // completion. This is the same invariant as its destructor.
                std::terminate();
            }
        }
    }
}

BackendIo NativeBackend::start(
    std::uint32_t timeout_ms,
    const std::shared_ptr<StartCancellation>& cancellation,
    std::string& error) {
    const BackendIo io = start_run(timeout_ms, cancellation, error);
    if (io == BackendIo::Ok) {
        // A keeper has already said that its session authenticated.
        if (config_.role() == v1::Role::Server) {
            record_->say("accepting sessions");
        } else if (!device_) {
            record_->say("session authenticated");
        }
    } else if (cancellation && cancellation->cancelled()) {
        record_->say("start cancelled");
    } else {
        record_->say("start failed", error);
    }
    return io;
}

BackendIo NativeBackend::start_run(
    std::uint32_t timeout_ms,
    const std::shared_ptr<StartCancellation>& cancellation,
    std::string& error) {
    std::lock_guard<std::mutex> lifecycle(lifecycle_mutex_);
    if (current()) {
        describe(error, "endpoint is already running");
        return BackendIo::AlreadyRunning;
    }
    const bool server = config_.role() == v1::Role::Server;
    std::chrono::milliseconds client_deadline = kDefaultClientStart;
    if (server) {
        if (timeout_ms != 0U) {
            describe(error, "server start has no caller-bounded deadline, pass zero");
            return BackendIo::Invalid;
        }
    } else if (timeout_ms != 0U) {
        client_deadline = std::chrono::milliseconds(timeout_ms);
        if (client_deadline > kMaxStartDeadline) {
            describe(error, "client start deadline exceeds the five-minute runtime bound");
            return BackendIo::Invalid;
        }
    }
    // Declared adapters are standalone application components. Starting
    // without them would silently drop part of the requested composition.
    if (!config_.adapters().empty()) {
        describe(error, "schema-1 adapters are standalone application components "
                        "and are not composed by the embedding backend");
        return BackendIo::Unsupported;
    }
    // The control socket serves the standalone program's status, which an
    // embedder reports through the ABI instead.
    if (config_.control()) {
        describe(error,
                 "the schema-1 control socket belongs to the standalone "
                 "programs and is not composed by the embedding backend");
        return BackendIo::Unsupported;
    }
    // A cluster member keeps links to its peers. Accepting the peers without
    // dialing them would be half a membership.
    if (config_.cluster()) {
        describe(error,
                 "cluster membership runs in the standalone yumed and is "
                 "not composed by the embedding backend");
        return BackendIo::Unsupported;
    }
    // Circuits wait for the user's consent to a shorter route, and the C
    // ABI has no consent interface yet.
    if (config_.circuits()) {
        describe(error,
                 "circuits run in the standalone yume and are not composed "
                 "by the embedding backend");
        return BackendIo::Unsupported;
    }
    if (std::holds_alternative<v1::ReverseProxyCover>(config_.cover())) {
        describe(error, "native reverse-proxy cover is not implemented");
        return BackendIo::Unsupported;
    }

    auto context = providers::AsioExecutionContext::create(engine::ExecutorAffinity(
        g_next_affinity.fetch_add(1U, std::memory_order_relaxed)));
    if (!context.ok()) {
        describe(error, context.status(), "execution context creation failed");
        return io_from(context.status().code());
    }
    providers::AsioTcpSocketProtector protector;
    if (socket_protector_) {
        protector = [callback = socket_protector_](std::uintptr_t handle) {
            return callback(static_cast<std::intptr_t>(handle))
                ? Status::success()
                : Status(StatusCode::FailedPrecondition,
                         "socket protector refused the outbound connection");
        };
    }
    auto run = std::make_shared<NativeRun>(
        std::move(context).take_value(), config_, base_, resolver_program_,
        registrations_, std::move(protector), record_, device_);
    auto operation = std::make_shared<StartOperation>(run, client_deadline);
    std::thread runner;
    try {
        runner = std::thread([run] { run->run_until_drained(); });
    } catch (const std::system_error&) {
        describe(error, "endpoint runner thread could not start");
        return BackendIo::ResourceExhausted;
    }
    if (!run->submit(operation->task, operation)) {
        shutdown(run, runner);
        describe(error, "endpoint runner refused startup");
        return BackendIo::Failed;
    }
    // From here another thread can end this start. Stopping the run closes
    // its endpoint on the runner, which completes the attempt in flight.
    struct Disarm final {
        const std::shared_ptr<StartCancellation>& cancellation;
        ~Disarm() {
            if (cancellation) cancellation->disarm();
        }
    } disarm{cancellation};
    if (cancellation) {
        try {
            cancellation->arm([run] { run->begin_stop(); });
        } catch (...) {
            shutdown(run, runner);
            describe(error, "endpoint start could not be made cancellable");
            return BackendIo::ResourceExhausted;
        }
    }

    // Server creation is local work. A client start is bounded by the native
    // endpoint's own deadline, and the grace only guards against a lost result.
    const auto limit = Clock::now() +
        (server ? kMaxStartDeadline : client_deadline + kClientStartGrace);
    Status result;
    if (!operation->wait(limit, result)) {
        shutdown(run, runner);
        describe(error, "endpoint start did not settle");
        return BackendIo::Timeout;
    }
    if (!result.ok()) {
        shutdown(run, runner);
        describe(error, result, "endpoint failed to start");
        // During a client start, Cancelled comes only from the native
        // endpoint's expired start deadline.
        if (!server && result.code() == StatusCode::Cancelled) {
            return BackendIo::Timeout;
        }
        return io_from(result.code());
    }
    {
        std::lock_guard<std::mutex> lock(run_mutex_);
        run_ = std::move(run);
        runner_ = std::move(runner);
    }
    error.clear();
    return BackendIo::Ok;
}

void NativeBackend::stop() noexcept {
    try {
        std::lock_guard<std::mutex> lifecycle(lifecycle_mutex_);
        std::shared_ptr<NativeRun> run;
        std::thread runner;
        {
            std::lock_guard<std::mutex> lock(run_mutex_);
            run = run_;
            runner = std::move(runner_);
        }
        // The run stays published while it winds down, so a status read in
        // between still counts its traffic.
        shutdown(run, runner);
        if (!run) return;
        {
            std::lock_guard<std::mutex> lock(run_mutex_);
            std::lock_guard<std::mutex> record_lock(record_->mutex);
            record_->retired = add(record_->retired, run->traffic());
            run_.reset();
        }
        record_->say("stopped");
    } catch (...) {
        // Reached from the destructor and a noexcept ABI boundary.
    }
}

bool NativeBackend::running() const noexcept {
    const auto run = current();
    if (!run || !run->running()) return false;
    // A client that keeps its session up is running between sessions too.
    return run->server || run->keeper ||
           (run->session &&
            run->session->state() == engine::SessionState::Active);
}

BackendStatus NativeBackend::status() const {
    BackendStatus status;
    std::shared_ptr<NativeRun> run;
    {
        std::lock_guard<std::mutex> lock(run_mutex_);
        std::lock_guard<std::mutex> record_lock(record_->mutex);
        run = run_;
        status.traffic = record_->retired;
    }
    if (run && !run->server) run->fill_status(status);
    return status;
}

BackendMessage NativeBackend::message_after(std::uint64_t after) const {
    BackendMessage message;
    message.instance = record_->messages.instance();
    auto next = record_->messages.next_after(after);
    message.missed = next.missed;
    if (next.entry) {
        message.seq = next.entry->seq;
        message.time_unix_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                next.entry->time.time_since_epoch())
                .count();
        message.text = std::move(next.entry->text);
    }
    return message;
}

BackendIo NativeBackend::retry_now() noexcept {
    const auto run = current();
    if (!run || !run->running()) return BackendIo::NotRunning;
    if (!run->keeper) return BackendIo::Invalid;
    run->request_retry();
    return BackendIo::Ok;
}

BackendIo NativeBackend::open_stream(const std::string& service,
                                   const std::optional<BackendDestination>& destination,
                                   std::uint32_t timeout_ms,
                                   std::unique_ptr<BackendStream>& out,
                                   std::string& error) {
    const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    out.reset();
    if (config_.role() != v1::Role::Client) {
        describe(error, "a server endpoint does not open streams");
        return BackendIo::Invalid;
    }
    const bool declared = std::any_of(
        config_.services().begin(), config_.services().end(),
        [&service](const v1::Service& entry) {
            return entry.name() == service &&
                   entry.kind() == v1::ServiceKind::Stream;
        });
    if (!declared) {
        describe(error, "byte-stream service is not declared by the endpoint configuration");
        return BackendIo::NotFound;
    }
    if (timeout_ms == 0U) {
        describe(error, "stream OPEN would block, no OPEN was sent");
        return BackendIo::WouldBlock;
    }
    const auto run = current();
    if (!run || !run->running()) {
        describe(error, "client endpoint is not running");
        return BackendIo::NotRunning;
    }
    std::optional<engine::RouteDestination> route;
    if (destination) {
        engine::Result<engine::RouteDestination> parsed{Status(StatusCode::InvalidArgument)};
        if (destination->kind == BackendAddressKind::Hostname) {
            parsed = engine::RouteDestination::dns_name(
                engine::NetworkProtocol::Tcp, destination->host, destination->port);
        } else {
            boost::system::error_code code;
            const auto address = boost::asio::ip::make_address(destination->host, code);
            if (!code && destination->kind == BackendAddressKind::Ipv4 && address.is_v4()) {
                parsed = engine::RouteDestination::ipv4(
                    engine::NetworkProtocol::Tcp, address.to_v4().to_bytes(), destination->port);
            } else if (!code && destination->kind == BackendAddressKind::Ipv6 && address.is_v6() &&
                       address.to_v6().scope_id() == 0U) {
                parsed = engine::RouteDestination::ipv6(
                    engine::NetworkProtocol::Tcp, address.to_v6().to_bytes(), destination->port);
            }
        }
        if (!parsed.ok()) {
            describe(error, "stream destination is invalid");
            return BackendIo::Invalid;
        }
        route.emplace(std::move(parsed).take_value());
    }
    auto handle = std::make_unique<NativeBackendStream>();
    auto operation = std::make_shared<OpenOperation>(
        run, service, std::move(route), deadline);
    if (!run->submit(operation->open_task, operation)) {
        describe(error, "client endpoint is not running");
        return BackendIo::NotRunning;
    }
    std::shared_ptr<NativeStream> stream;
    const BackendIo io = operation->wait(stream, error);
    if (io != BackendIo::Ok) return io;
    handle->attach(std::move(stream));
    out = std::move(handle);
    return BackendIo::Ok;
}

BackendIo NativeBackend::accept_stream(const std::string& service,
                                     std::uint32_t timeout_ms,
                                     std::unique_ptr<BackendStream>& out,
                                     std::string& error) {
    out.reset();
    if (config_.role() != v1::Role::Server) {
        describe(error, "a client endpoint does not accept streams");
        return BackendIo::Invalid;
    }
    const auto run = current();
    if (!run || !run->running()) {
        describe(error, run ? run->stop_reason()
                            : std::string_view("server endpoint is not running"));
        return BackendIo::NotRunning;
    }
    const bool declared = std::any_of(config_.services().begin(), config_.services().end(),
        [&service](const v1::Service& entry) {
            return entry.name() == service && entry.kind() == v1::ServiceKind::Stream;
        });
    const auto index = run->waiting_index(service);
    if (!declared || !index) {
        describe(error, "byte-stream service is not registered on this endpoint");
        return BackendIo::NotFound;
    }
    auto handle = std::make_unique<NativeBackendStream>();
    std::shared_ptr<NativeStream> stream;
    const BackendIo io = run->accept(*index, timeout_ms, stream, error);
    if (io != BackendIo::Ok) return io;
    handle->attach(std::move(stream));
    out = std::move(handle);
    return BackendIo::Ok;
}

BackendIo NativeBackend::open_packet(const std::string& service,
                                   const std::optional<BackendDestination>& destination,
                                   std::uint32_t timeout_ms,
                                   std::unique_ptr<BackendPacket>& out,
                                   std::string& error) {
    const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    out.reset();
    if (config_.role() != v1::Role::Client) {
        describe(error, "a server endpoint does not open packets");
        return BackendIo::Invalid;
    }
    const bool declared = std::any_of(
        config_.services().begin(), config_.services().end(),
        [&service](const v1::Service& entry) {
            return entry.name() == service &&
                   entry.kind() == v1::ServiceKind::Packet;
        });
    if (!declared) {
        describe(error, "packet service is not declared by the endpoint configuration");
        return BackendIo::NotFound;
    }
    if (timeout_ms == 0U) {
        describe(error, "packet OPEN would block, no OPEN was sent");
        return BackendIo::WouldBlock;
    }
    const auto run = current();
    if (!run || !run->running()) {
        describe(error, "client endpoint is not running");
        return BackendIo::NotRunning;
    }
    std::optional<engine::RouteDestination> route;
    if (destination) {
        engine::Result<engine::RouteDestination> parsed{Status(StatusCode::InvalidArgument)};
        if (destination->kind == BackendAddressKind::Hostname) {
            parsed = engine::RouteDestination::dns_name(
                engine::NetworkProtocol::Udp, destination->host, destination->port);
        } else {
            boost::system::error_code code;
            const auto address = boost::asio::ip::make_address(destination->host, code);
            if (!code && destination->kind == BackendAddressKind::Ipv4 && address.is_v4()) {
                parsed = engine::RouteDestination::ipv4(
                    engine::NetworkProtocol::Udp, address.to_v4().to_bytes(), destination->port);
            } else if (!code && destination->kind == BackendAddressKind::Ipv6 && address.is_v6() &&
                       address.to_v6().scope_id() == 0U) {
                parsed = engine::RouteDestination::ipv6(
                    engine::NetworkProtocol::Udp, address.to_v6().to_bytes(), destination->port);
            }
        }
        if (!parsed.ok()) {
            describe(error, "packet destination is invalid");
            return BackendIo::Invalid;
        }
        route.emplace(std::move(parsed).take_value());
    }
    auto handle = std::make_unique<NativeBackendPacket>();
    auto operation = std::make_shared<OpenOperation>(
        run, service, std::move(route), deadline,
        engine::ServiceKind::PacketChannel);
    if (!run->submit(operation->open_task, operation)) {
        describe(error, "client endpoint is not running");
        return BackendIo::NotRunning;
    }
    std::shared_ptr<NativeStream> stream;
    const BackendIo io = operation->wait(stream, error);
    if (io != BackendIo::Ok) return io;
    handle->attach(std::move(stream));
    out = std::move(handle);
    return BackendIo::Ok;
}

BackendIo NativeBackend::accept_packet(const std::string& service,
                                     std::uint32_t timeout_ms,
                                     std::unique_ptr<BackendPacket>& out,
                                     std::string& error) {
    out.reset();
    if (config_.role() != v1::Role::Server) {
        describe(error, "a client endpoint does not accept packets");
        return BackendIo::Invalid;
    }
    const auto run = current();
    if (!run || !run->running()) {
        describe(error, run ? run->stop_reason()
                            : std::string_view("server endpoint is not running"));
        return BackendIo::NotRunning;
    }
    const bool declared = std::any_of(config_.services().begin(), config_.services().end(),
        [&service](const v1::Service& entry) {
            return entry.name() == service && entry.kind() == v1::ServiceKind::Packet;
        });
    const auto index = run->waiting_index(service, BackendServiceKind::Packet);
    if (!declared || !index) {
        describe(error, "packet service is not registered on this endpoint");
        return BackendIo::NotFound;
    }
    auto handle = std::make_unique<NativeBackendPacket>();
    std::shared_ptr<NativeStream> stream;
    const BackendIo io = run->accept(*index, timeout_ms, stream, error);
    if (io != BackendIo::Ok) return io;
    handle->attach(std::move(stream));
    out = std::move(handle);
    return BackendIo::Ok;
}

bool declares(const v1::Config& config, std::string_view name,
              v1::ServiceKind kind) {
    return std::any_of(config.services().begin(), config.services().end(),
                       [&](const v1::Service& entry) {
                           return entry.name() == name && entry.kind() == kind;
                       });
}

#if defined(YUME_HAS_DEVICE_BRIDGE)
// One family's addresses as text. Two empty strings leave the family out.
bool parse_pair(bool ipv6, const std::string& address, const std::string& peer,
                std::optional<runtime::DeviceAddressPair>& out) {
    out.reset();
    if (address.empty() && peer.empty()) return true;
    boost::system::error_code first;
    boost::system::error_code second;
    runtime::DeviceAddressPair pair;
    if (ipv6) {
        const auto device = boost::asio::ip::make_address_v6(address, first);
        const auto other = boost::asio::ip::make_address_v6(peer, second);
        if (first || second || device.scope_id() != 0U ||
            other.scope_id() != 0U) {
            return false;
        }
        pair.device = device.to_bytes();
        pair.peer = other.to_bytes();
    } else {
        const auto device = boost::asio::ip::make_address_v4(address, first);
        const auto other = boost::asio::ip::make_address_v4(peer, second);
        if (first || second) return false;
        const auto device_bytes = device.to_bytes();
        const auto other_bytes = other.to_bytes();
        std::copy(device_bytes.begin(), device_bytes.end(),
                  pair.device.begin());
        std::copy(other_bytes.begin(), other_bytes.end(), pair.peer.begin());
    }
    const runtime::DeviceAddress unspecified{};
    if (pair.device == pair.peer || pair.device == unspecified ||
        pair.peer == unspecified) {
        return false;
    }
    out = pair;
    return true;
}
#endif

// Checks a device against a configuration and, with a bridge on this
// platform, turns it into the bridge's options.
BackendIo resolve_device(const v1::Config& config, const BackendDevice& device,
                         std::optional<DeviceOptions>& out,
                         std::string& error) {
    out.reset();
    if (config.role() != v1::Role::Client) {
        describe(error, "only a client endpoint carries a device");
        return BackendIo::Unsupported;
    }
#if !defined(YUME_HAS_DEVICE_BRIDGE)
    (void)device;
    describe(error, "this platform has no device bridge");
    return BackendIo::Unsupported;
#else
    if (device.descriptor < 0) {
        describe(error, "the device descriptor is not open");
        return BackendIo::Invalid;
    }
    if (device.stream_service.empty() ||
        !declares(config, device.stream_service, v1::ServiceKind::Stream)) {
        describe(error,
                 "the device's stream service is not a byte-stream "
                 "service of the configuration");
        return BackendIo::NotFound;
    }
    if (!device.packet_service.empty() &&
        !declares(config, device.packet_service, v1::ServiceKind::Packet)) {
        describe(error,
                 "the device's packet service is not a packet service "
                 "of the configuration");
        return BackendIo::NotFound;
    }
    DeviceOptions options;
    options.descriptor = device.descriptor;
    options.mtu = device.mtu;
    options.stream_service = device.stream_service;
    options.packet_service = device.packet_service;
    // The bridge keeps a quarter of the session's pending OPENs free for
    // datagram destinations and the application's own opens.
    options.max_pending_opens = std::max<std::size_t>(
        1U, static_cast<std::size_t>(config.limits().max_pending_opens()) * 3U /
                4U);
    if (!parse_pair(false, device.ipv4_address, device.ipv4_peer,
                    options.ipv4) ||
        !parse_pair(true, device.ipv6_address, device.ipv6_peer,
                    options.ipv6)) {
        describe(error,
                 "a device address pair needs two different IP "
                 "literals of its family");
        return BackendIo::Invalid;
    }
    if (!options.ipv4 && !options.ipv6) {
        describe(error, "the device needs an address pair of one family");
        return BackendIo::Invalid;
    }
    if (device.mtu < (options.ipv6 ? 1280U : 576U) || device.mtu > 65'535U) {
        describe(error,
                 "the device MTU is 576 to 65535, and at least 1280 "
                 "with IPv6");
        return BackendIo::Invalid;
    }
    out = std::move(options);
    error.clear();
    return BackendIo::Ok;
#endif
}

class SealedKit final : public BackendKit {
public:
    explicit SealedKit(runtime::kit::Kit kit) noexcept : kit_(std::move(kit)) {}

    std::size_t file_count() const noexcept override {
        return kit_.files.size();
    }
    BackendKitFile file(std::size_t index) const noexcept override {
        const auto& entry = kit_.files[index];
        return BackendKitFile{entry.path, entry.bytes, entry.executable};
    }

private:
    // Its destructor wipes every file.
    runtime::kit::Kit kit_;
};

}  // namespace

BackendIo check_backend_device(const config::v1::Config& config,
                               const BackendDevice& device,
                               std::string& error) {
    try {
        std::optional<DeviceOptions> ignored;
        return resolve_device(config, device, ignored, error);
    } catch (const std::bad_alloc&) {
        describe(error, "allocation failed");
        return BackendIo::ResourceExhausted;
    } catch (...) {
        describe(error, "the device could not be checked");
        return BackendIo::Failed;
    }
}

std::unique_ptr<BackendKit> open_sealed_kit(
    std::span<const std::uint8_t> sealed, std::string_view typed_code,
    BackendKitOutcome& outcome, std::string& error) {
    namespace kit = runtime::kit;
    outcome = BackendKitOutcome::Failed;
    try {
        if (sealed.size() > kit::kMaxSealedBytes) {
            outcome = BackendKitOutcome::TooLarge;
            describe(error, "the file is larger than a sealed kit can be");
            return nullptr;
        }
        auto code = kit::normalize_code(typed_code);
        if (!code) {
            outcome = BackendKitOutcome::BadCode;
            describe(error, "the kit code is not 25 code characters");
            return nullptr;
        }
        const security::ScopedErase code_guard(*code);
        // A file of another shape is refused like a wrong code, before the
        // key derivation spends its time.
        if (!kit::sealed_size(sealed.size())) {
            outcome = BackendKitOutcome::Refused;
            describe(error,
                     "the code is wrong or the file is not a sealed kit");
            return nullptr;
        }
        auto opened = kit::open(sealed, *code);
        if (!opened.ok()) {
            switch (opened.status().code()) {
                case StatusCode::PermissionDenied:
                    outcome = BackendKitOutcome::Refused;
                    break;
                case StatusCode::InvalidArgument:
                    outcome = BackendKitOutcome::Malformed;
                    break;
                case StatusCode::ResourceExhausted:
                    outcome = BackendKitOutcome::Exhausted;
                    break;
                default:
                    outcome = BackendKitOutcome::Failed;
                    break;
            }
            describe(error, opened.status(),
                     "the sealed kit could not be opened");
            return nullptr;
        }
        auto result =
            std::make_unique<SealedKit>(std::move(opened).take_value());
        outcome = BackendKitOutcome::Ok;
        error.clear();
        return result;
    } catch (const std::bad_alloc&) {
        outcome = BackendKitOutcome::Exhausted;
        describe(error, "allocation failed");
    } catch (...) {
        describe(error, "the sealed kit could not be opened");
    }
    return nullptr;
}

std::unique_ptr<EndpointBackend> make_native_backend(
    const config::v1::Config& config, std::string_view base_dir,
    std::string_view resolver_program,
    std::vector<BackendService> registered_services,
    SocketProtector socket_protector,
    const std::optional<BackendDevice>& device, BackendIo& outcome,
    std::string& error) {
    outcome = BackendIo::Failed;
    try {
        const bool server = config.role() == v1::Role::Server;
        std::optional<DeviceOptions> device_options;
        if (device) {
            outcome = resolve_device(config, *device, device_options, error);
            if (outcome != BackendIo::Ok) return nullptr;
            outcome = BackendIo::Failed;
        }
        for (const auto& registration : registered_services) {
            const auto kind = registration.kind == BackendServiceKind::ByteStream
                ? v1::ServiceKind::Stream : v1::ServiceKind::Packet;
            const bool declared = std::any_of(
                config.services().begin(), config.services().end(),
                [&](const v1::Service& entry) {
                    return entry.name() == registration.name &&
                           entry.kind() == kind;
                });
            if (!server || !declared) {
                outcome = BackendIo::Invalid;
                describe(error, server
                    ? "registered service is not declared by the configuration"
                    : "a client endpoint does not register services");
                return nullptr;
            }
        }
        auto backend = std::make_unique<NativeBackend>(
            config, std::filesystem::path(std::string(base_dir)),
            std::filesystem::path(std::string(resolver_program)),
            std::move(registered_services), std::move(socket_protector),
            std::move(device_options));
        outcome = BackendIo::Ok;
        error.clear();
        return backend;
    } catch (const std::bad_alloc&) {
        outcome = BackendIo::ResourceExhausted;
        describe(error, "endpoint backend allocation failed");
    } catch (const std::exception& thrown) {
        describe(error, thrown.what());
    } catch (...) {
        describe(error, "endpoint backend construction failed");
    }
    return nullptr;
}

std::string_view security_provider_identity() noexcept {
    return providers::kOpenSslSecurityProviderId;
}

std::string_view crypto_backend_identity() noexcept {
    return providers::openssl_crypto_backend();
}

}  // namespace yume::embed
