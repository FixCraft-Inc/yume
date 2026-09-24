/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/asio_tcp_byte_channel_provider.hpp"

#include <atomic>
#include <chrono>
#include <deque>
#include <limits>
#include <map>
#include <mutex>
#include <new>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/cancellation_type.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>

namespace yume::providers {
namespace {

using engine::Buffer;
using engine::ByteChannel;
using engine::ByteChannelProvider;
using engine::CancellationRegistration;
using engine::CancellationToken;
using engine::Capability;
using engine::CapabilitySet;
using engine::EndpointRole;
using engine::ExecutorAffinity;
using engine::ProviderDescriptor;
using engine::ProviderKind;
using engine::Result;
using engine::Status;
using engine::StatusCode;

using Executor = AsioExecutionContext::Executor;
using ControlTask = AsioExecutionContext::ControlTask;
using Tcp = boost::asio::ip::tcp;
using Addresses = std::vector<boost::asio::ip::address>;
using Timer = boost::asio::basic_waitable_timer<std::chrono::steady_clock,
    boost::asio::wait_traits<std::chrono::steady_clock>, Executor>;

constexpr std::size_t kMaximumProviderOperations = 1U << 20U;
constexpr std::size_t kMaximumResolvedEndpoints = 256U;
constexpr std::size_t kMaximumConnectAttempts = 256U;
constexpr std::size_t kMaximumHostBytes = 253U;
constexpr auto kMaximumPhaseTimeout = std::chrono::minutes(10);

Status safe_status(StatusCode code, std::string_view message) noexcept {
    try {
        return Status(code, message);
    } catch (...) {
        return Status(code);
    }
}

Status cancelled_status() noexcept {
    return safe_status(StatusCode::Cancelled,
                       "Asio TCP operation was cancelled");
}

Status closed_status() noexcept {
    return safe_status(StatusCode::Closed, "Asio TCP channel is closed");
}

Status allocation_status(std::string_view message) noexcept {
    return safe_status(StatusCode::ResourceExhausted, message);
}

template <typename Completion, typename... Args>
void invoke_noexcept(Completion& completion, Args&&... args) noexcept {
    if (!completion) {
        return;
    }
    try {
        completion(std::forward<Args>(args)...);
    } catch (...) {
        // Application callbacks are outside the provider trust boundary.
    }
}

void complete_read(ByteChannel::ReadCompletion completion,
                   Status status) noexcept {
    Result<Buffer> result(std::move(status));
    invoke_noexcept(completion, std::move(result));
}

void complete_read(ByteChannel::ReadCompletion completion,
                   Buffer buffer) noexcept {
    Result<Buffer> result(std::move(buffer));
    invoke_noexcept(completion, std::move(result));
}

bool add_fits(std::size_t current,
              std::size_t addition,
              std::size_t maximum) noexcept {
    return addition <= maximum && current <= maximum - addition;
}

bool valid_host(std::string_view host) noexcept {
    return !host.empty() && host.size() <= kMaximumHostBytes &&
           host.find('\0') == std::string_view::npos;
}

bool valid_channel_limits(const AsioTcpChannelLimits& limits) noexcept {
    return limits.max_active_channels > 0U &&
           limits.max_active_channels <= kMaximumProviderOperations &&
           limits.max_read_bytes > 0U &&
           limits.max_read_bytes <= engine::kAbsoluteMaxBufferBytes &&
           limits.max_write_bytes > 0U &&
           limits.max_write_bytes <= engine::kAbsoluteMaxBufferBytes &&
           limits.max_queued_read_operations > 0U &&
           limits.max_queued_read_operations <= kMaximumProviderOperations &&
           limits.max_queued_write_operations > 0U &&
           limits.max_queued_write_operations <= kMaximumProviderOperations &&
           limits.max_queued_read_bytes >= limits.max_read_bytes &&
           limits.max_queued_read_bytes <= engine::kAbsoluteMaxBufferBytes &&
           limits.max_queued_write_bytes >= limits.max_write_bytes &&
           limits.max_queued_write_bytes <= engine::kAbsoluteMaxBufferBytes;
}

bool valid_limits(const AsioTcpByteChannelLimits& limits) noexcept {
    return valid_channel_limits(limits) &&
           limits.max_pending_creates > 0U &&
           limits.max_pending_creates <= kMaximumProviderOperations &&
           limits.max_resolved_endpoints > 0U &&
           limits.max_resolved_endpoints <= kMaximumResolvedEndpoints &&
           limits.max_connect_attempts > 0U &&
           limits.max_connect_attempts <= kMaximumConnectAttempts &&
           limits.resolve_timeout > std::chrono::milliseconds::zero() &&
           limits.resolve_timeout <= kMaximumPhaseTimeout &&
           limits.connect_timeout > std::chrono::milliseconds::zero() &&
           limits.connect_timeout <= kMaximumPhaseTimeout;
}

template <typename NativeHandle>
std::uintptr_t socket_handle_value(NativeHandle handle) noexcept {
    if constexpr (std::is_pointer_v<NativeHandle>) {
        return reinterpret_cast<std::uintptr_t>(handle);
    } else {
        return static_cast<std::uintptr_t>(handle);
    }
}

Status protect_socket(AsioTcpSocket& socket,
                      const AsioTcpSocketProtector& protector) noexcept {
    if (!protector) {
        return Status::success();
    }
    try {
        return protector(socket_handle_value(socket.native_handle()));
    } catch (const std::bad_alloc&) {
        return allocation_status("socket-protection callback allocation failed");
    } catch (...) {
        return safe_status(StatusCode::Internal,
                           "socket-protection callback threw");
    }
}

class CancelTarget {
public:
    virtual ~CancelTarget() = default;
    virtual void request_cancel() noexcept = 0;
};

enum class TargetKind : std::uint8_t {
    PendingCreate,
    ActiveChannel,
};

struct TargetEntry final {
    TargetKind kind{TargetKind::PendingCreate};
    std::weak_ptr<CancelTarget> target;
};

class ChannelRegistry final {
public:
    ChannelRegistry(std::shared_ptr<AsioExecutionContext> context,
                    AsioTcpChannelLimits limits) noexcept
        : context_(std::move(context)),
          limits_(limits) {}

    Result<std::pair<std::uint64_t, std::uint64_t>> reserve_create(
        std::size_t max_pending_creates) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (pending_creates_ >= max_pending_creates ||
            active_channels_ + pending_creates_ >=
                limits_.max_active_channels) {
            return Result<std::pair<std::uint64_t, std::uint64_t>>(
                safe_status(StatusCode::ResourceExhausted,
                            "Asio TCP provider capacity exhausted"));
        }
        if (next_target_id_ == std::numeric_limits<std::uint64_t>::max()) {
            return Result<std::pair<std::uint64_t, std::uint64_t>>(
                safe_status(StatusCode::ResourceExhausted,
                            "Asio TCP target identifier exhausted"));
        }
        const std::uint64_t id = next_target_id_++;
        try {
            targets_.emplace(id, TargetEntry{TargetKind::PendingCreate, {}});
        } catch (const std::bad_alloc&) {
            return Result<std::pair<std::uint64_t, std::uint64_t>>(
                allocation_status("Asio TCP reservation allocation failed"));
        }
        ++pending_creates_;
        return Result<std::pair<std::uint64_t, std::uint64_t>>(
            std::make_pair(id, cancellation_epoch_));
    }

    Result<std::pair<std::uint64_t, std::uint64_t>> reserve_active() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (active_channels_ + pending_creates_ >=
            limits_.max_active_channels) {
            return Result<std::pair<std::uint64_t, std::uint64_t>>(
                safe_status(StatusCode::ResourceExhausted,
                            "Asio TCP channel capacity exhausted"));
        }
        if (next_target_id_ == std::numeric_limits<std::uint64_t>::max()) {
            return Result<std::pair<std::uint64_t, std::uint64_t>>(
                safe_status(StatusCode::ResourceExhausted,
                            "Asio TCP target identifier exhausted"));
        }
        const std::uint64_t id = next_target_id_++;
        try {
            targets_.emplace(id, TargetEntry{TargetKind::ActiveChannel, {}});
        } catch (const std::bad_alloc&) {
            return Result<std::pair<std::uint64_t, std::uint64_t>>(
                allocation_status("Asio TCP reservation allocation failed"));
        }
        ++active_channels_;
        return Result<std::pair<std::uint64_t, std::uint64_t>>(
            std::make_pair(id, cancellation_epoch_));
    }

    bool bind_target(std::uint64_t id,
                     std::uint64_t reserved_epoch,
                     const std::shared_ptr<CancelTarget>& target) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto found = targets_.find(id);
        if (found == targets_.end()) {
            return true;
        }
        found->second.target = target;
        return reserved_epoch != cancellation_epoch_;
    }

    Status promote(std::uint64_t id,
                   std::uint64_t reserved_epoch,
                   const std::shared_ptr<CancelTarget>& target) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        if (reserved_epoch != cancellation_epoch_) return cancelled_status();
        const auto found = targets_.find(id);
        if (found == targets_.end() ||
            found->second.kind != TargetKind::PendingCreate ||
            pending_creates_ == 0U ||
            active_channels_ >= limits_.max_active_channels) {
            return safe_status(StatusCode::ResourceExhausted,
                               "TCP active-channel capacity exhausted");
        }
        found->second.kind = TargetKind::ActiveChannel;
        found->second.target = target;
        --pending_creates_;
        ++active_channels_;
        return Status::success();
    }

    void release(std::uint64_t id) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto found = targets_.find(id);
        if (found == targets_.end()) {
            return;
        }
        if (found->second.kind == TargetKind::PendingCreate) {
            if (pending_creates_ > 0U) {
                --pending_creates_;
            }
        } else if (active_channels_ > 0U) {
            --active_channels_;
        }
        targets_.erase(found);
    }

    void cancel_all() noexcept {
        std::uint64_t last_id = 0U;
        std::uint64_t final_id;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            ++cancellation_epoch_;
            final_id = next_target_id_ - 1U;
        }
        // Walk stable identifiers without allocating a snapshot. Neither the
        // cancellation request nor a target's last-reference destructor may
        // run under the registry lock: destruction releases its registration.
        for (;;) {
            std::shared_ptr<CancelTarget> target;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                const auto next = targets_.upper_bound(last_id);
                if (next == targets_.end() || next->first > final_id) {
                    return;
                }
                last_id = next->first;
                target = next->second.target.lock();
            }
            if (target) {
                target->request_cancel();
            }
        }
    }

    Executor executor() const noexcept { return context_->executor(); }
    ExecutorAffinity affinity() const noexcept { return context_->affinity(); }
    const std::shared_ptr<AsioExecutionContext>& context() const noexcept {
        return context_;
    }
    const AsioTcpChannelLimits& limits() const noexcept { return limits_; }

private:
    std::shared_ptr<AsioExecutionContext> context_;
    AsioTcpChannelLimits limits_;

    std::mutex mutex_;
    std::map<std::uint64_t, TargetEntry> targets_;
    std::uint64_t next_target_id_{1U};
    std::uint64_t cancellation_epoch_{0U};
    std::size_t pending_creates_{0U};
    std::size_t active_channels_{0U};
};

class ProviderState final : public std::enable_shared_from_this<ProviderState> {
public:
    ProviderState(std::shared_ptr<ChannelRegistry> channels,
                  std::string host,
                  std::optional<boost::asio::ip::address> numeric_host,
                  std::uint16_t port,
                  AsioTcpByteChannelLimits limits,
                  AsioTcpSocketProtector protector,
                  std::shared_ptr<SystemResolver> resolver,
                  ProviderDescriptor descriptor) noexcept
        : channels_(std::move(channels)),
          host_(std::move(host)),
          numeric_host_(std::move(numeric_host)),
          port_(port),
          limits_(limits),
          protector_(std::move(protector)),
          resolver_(std::move(resolver)),
          descriptor_(std::move(descriptor)) {}

    Result<std::pair<std::uint64_t, std::uint64_t>> reserve_create() {
        return channels_->reserve_create(limits_.max_pending_creates);
    }
    bool bind_target(std::uint64_t id,
                     std::uint64_t reserved_epoch,
                     const std::shared_ptr<CancelTarget>& target) noexcept {
        return channels_->bind_target(id, reserved_epoch, target);
    }
    Status promote(std::uint64_t id,
                   std::uint64_t reserved_epoch,
                   const std::shared_ptr<CancelTarget>& target) noexcept {
        return channels_->promote(id, reserved_epoch, target);
    }
    void release(std::uint64_t id) noexcept { channels_->release(id); }
    void cancel_all() noexcept { channels_->cancel_all(); }

    Executor executor() const noexcept { return channels_->executor(); }
    const std::shared_ptr<AsioExecutionContext>& context() const noexcept {
        return channels_->context();
    }
    ExecutorAffinity affinity() const noexcept { return channels_->affinity(); }
    const std::shared_ptr<ChannelRegistry>& channels() const noexcept {
        return channels_;
    }
    const std::string& host() const noexcept { return host_; }
    const std::optional<boost::asio::ip::address>& numeric_host() const noexcept {
        return numeric_host_;
    }
    std::uint16_t port() const noexcept { return port_; }
    const AsioTcpByteChannelLimits& limits() const noexcept { return limits_; }
    const AsioTcpSocketProtector& protector() const noexcept {
        return protector_;
    }
    const std::shared_ptr<SystemResolver>& resolver() const noexcept {
        return resolver_;
    }
    const ProviderDescriptor& descriptor() const noexcept {
        return descriptor_;
    }

private:
    std::shared_ptr<ChannelRegistry> channels_;
    std::string host_;
    std::optional<boost::asio::ip::address> numeric_host_;
    std::uint16_t port_{0U};
    AsioTcpByteChannelLimits limits_;
    AsioTcpSocketProtector protector_;
    std::shared_ptr<SystemResolver> resolver_;
    ProviderDescriptor descriptor_;
};

}  // namespace

class AsioTcpByteChannelProvider::Impl final {
public:
    explicit Impl(std::shared_ptr<ProviderState> state) noexcept
        : state_(std::move(state)) {}

    const std::shared_ptr<ProviderState>& state() const noexcept {
        return state_;
    }

private:
    std::shared_ptr<ProviderState> state_;
};

class AsioTcpAcceptedChannelOwner::Impl final {
public:
    explicit Impl(std::shared_ptr<ChannelRegistry> channels) noexcept
        : channels_(std::move(channels)) {}

    const std::shared_ptr<ChannelRegistry>& channels() const noexcept {
        return channels_;
    }

private:
    std::shared_ptr<ChannelRegistry> channels_;
};

namespace {

class TcpChannelState final : public CancelTarget,
                              public std::enable_shared_from_this<TcpChannelState> {
public:
    TcpChannelState(AsioTcpSocket socket,
                    std::shared_ptr<ChannelRegistry> channels,
                    std::uint64_t target_id)
        : socket_(std::move(socket)),
          channels_(std::move(channels)),
          target_id_(target_id),
          control_([](void* owner) noexcept {
              static_cast<TcpChannelState*>(owner)->handle_control();
          }) {}

    ~TcpChannelState() noexcept override {
        boost::system::error_code ignored;
        socket_.close(ignored);
        unregister_once();
    }

    ExecutorAffinity affinity() const noexcept { return channels_->affinity(); }
    std::size_t max_read_size() const noexcept {
        return channels_->limits().max_read_bytes;
    }
    std::size_t max_write_size() const noexcept {
        return channels_->limits().max_write_bytes;
    }

    void async_read(std::size_t max_bytes,
                    CancellationToken cancellation,
                    ByteChannel::ReadCompletion completion) {
        channels_->context()->require_context();
        const auto keep_alive = shared_from_this();
        if (!completion) {
            return;
        }
        Status error = Status::success();
        std::uint64_t id = 0U;
        {
            std::lock_guard<std::mutex> lock(submission_mutex_);
            if (close_requested_) {
                error = closed_status();
            } else if (max_bytes == 0U || max_bytes > max_read_size()) {
                error = safe_status(StatusCode::InvalidArgument,
                                    "TCP read exceeds the provider bound");
            } else if (submitted_reads_ >=
                           channels_->limits().max_queued_read_operations ||
                       !add_fits(submitted_read_bytes_, max_bytes,
                                 channels_->limits().max_queued_read_bytes)) {
                error = safe_status(StatusCode::ResourceExhausted,
                                    "TCP read queue capacity exhausted");
            } else if (next_operation_id_ ==
                       std::numeric_limits<std::uint64_t>::max()) {
                error = safe_status(StatusCode::ResourceExhausted,
                                    "TCP operation identifier exhausted");
            } else {
                id = next_operation_id_++;
                ++submitted_reads_;
                submitted_read_bytes_ += max_bytes;
            }
        }
        if (!error.ok()) {
            complete_read(std::move(completion), std::move(error));
            return;
        }
        enqueue_read(id, max_bytes, std::move(cancellation),
                     std::move(completion));
    }

    void async_write(Buffer buffer,
                     CancellationToken cancellation,
                     ByteChannel::WriteCompletion completion) {
        channels_->context()->require_context();
        const auto keep_alive = shared_from_this();
        if (!completion) {
            return;
        }
        const std::size_t bytes = buffer.size();
        Status error = Status::success();
        std::uint64_t id = 0U;
        {
            std::lock_guard<std::mutex> lock(submission_mutex_);
            if (close_requested_ || write_shutdown_requested_) {
                error = closed_status();
            } else if (bytes > max_write_size()) {
                error = safe_status(StatusCode::ResourceExhausted,
                                    "TCP write exceeds the provider bound");
            } else if (submitted_writes_ >=
                           channels_->limits().max_queued_write_operations ||
                       !add_fits(submitted_write_bytes_, bytes,
                                 channels_->limits().max_queued_write_bytes)) {
                error = safe_status(StatusCode::ResourceExhausted,
                                    "TCP write queue capacity exhausted");
            } else if (next_operation_id_ ==
                       std::numeric_limits<std::uint64_t>::max()) {
                error = safe_status(StatusCode::ResourceExhausted,
                                    "TCP operation identifier exhausted");
            } else {
                id = next_operation_id_++;
                ++submitted_writes_;
                submitted_write_bytes_ += bytes;
            }
        }
        if (!error.ok()) {
            invoke_noexcept(completion, std::move(error), 0U);
            return;
        }
        enqueue_write(id, std::move(buffer), std::move(cancellation),
                      std::move(completion));
    }

    Status shutdown_write() noexcept {
        if (!channels_->context()->running_in_this_thread()) {
            return safe_status(StatusCode::FailedPrecondition,
                               "TCP shutdown must start on its execution context");
        }
        const auto keep_alive = shared_from_this();
        {
            std::lock_guard<std::mutex> lock(submission_mutex_);
            if (close_requested_) return closed_status();
            if (write_shutdown_requested_) return Status::success();
            write_shutdown_requested_ = true;
        }
        shutdown_write_on_context();
        return Status::success();
    }

    void request_cancel() noexcept override {
        {
            std::lock_guard<std::mutex> lock(submission_mutex_);
            cancel_through_ = next_operation_id_ - 1U;
        }
        request_control();
    }

    void request_close() noexcept {
        {
            std::lock_guard<std::mutex> lock(submission_mutex_);
            if (close_requested_) return;
            close_requested_ = true;
        }
        request_control();
    }

private:
    struct PendingRead final {
        // Keep ownership in enqueue_read until storage exists. Its allocation
        // failure path must still own a completion to invoke.
        PendingRead(std::uint64_t operation_id,
                    std::size_t requested_bytes,
                    CancellationToken&& owned_cancellation,
                    ByteChannel::ReadCompletion&& owned_completion) noexcept
            : id(operation_id),
              requested(requested_bytes),
              cancellation_token(std::move(owned_cancellation)),
              completion(std::move(owned_completion)) {}

        std::uint64_t id;
        std::size_t requested;
        CancellationToken cancellation_token;
        ByteChannel::ReadCompletion completion;
        CancellationRegistration cancellation;
        boost::asio::cancellation_signal signal;
        std::optional<Buffer> buffer;
        bool active{false};
        bool cancelled{false};
    };

    struct PendingWrite final {
        // As above, move the callback only during member construction.
        PendingWrite(std::uint64_t operation_id,
                     Buffer&& owned_buffer,
                     CancellationToken&& owned_cancellation,
                     ByteChannel::WriteCompletion&& owned_completion) noexcept
            : id(operation_id),
              buffer(std::move(owned_buffer)),
              cancellation_token(std::move(owned_cancellation)),
              completion(std::move(owned_completion)) {}

        std::uint64_t id;
        Buffer buffer;
        std::size_t transferred{0U};
        CancellationToken cancellation_token;
        ByteChannel::WriteCompletion completion;
        CancellationRegistration cancellation;
        boost::asio::cancellation_signal signal;
        bool active{false};
        bool cancelled{false};
    };

    void release_read_reservation(std::size_t bytes) noexcept {
        std::lock_guard<std::mutex> lock(submission_mutex_);
        if (submitted_reads_ > 0U) {
            --submitted_reads_;
        }
        if (submitted_read_bytes_ >= bytes) {
            submitted_read_bytes_ -= bytes;
        } else {
            submitted_read_bytes_ = 0U;
        }
    }

    void release_write_reservation(std::size_t bytes) noexcept {
        std::lock_guard<std::mutex> lock(submission_mutex_);
        if (submitted_writes_ > 0U) {
            --submitted_writes_;
        }
        if (submitted_write_bytes_ >= bytes) {
            submitted_write_bytes_ -= bytes;
        } else {
            submitted_write_bytes_ = 0U;
        }
    }

    void enqueue_read(std::uint64_t id,
                      std::size_t max_bytes,
                      CancellationToken cancellation,
                      ByteChannel::ReadCompletion completion) noexcept {
        std::unique_ptr<PendingRead> operation;
        try {
            operation = std::make_unique<PendingRead>(
                id, max_bytes, std::move(cancellation),
                std::move(completion));
            reads_.push_back(std::move(operation));
            start_next_read();
        } catch (const std::bad_alloc&) {
            release_read_reservation(max_bytes);
            complete_read(
                operation ? std::move(operation->completion)
                          : std::move(completion),
                allocation_status(
                "TCP read queue allocation failed"));
        } catch (...) {
            release_read_reservation(max_bytes);
            complete_read(
                operation ? std::move(operation->completion)
                          : std::move(completion),
                safe_status(StatusCode::Internal,
                            "TCP read queueing failed"));
        }
    }

    void enqueue_write(std::uint64_t id,
                       Buffer buffer,
                       CancellationToken cancellation,
                       ByteChannel::WriteCompletion completion) noexcept {
        const std::size_t bytes = buffer.size();
        std::unique_ptr<PendingWrite> operation;
        try {
            operation = std::make_unique<PendingWrite>(
                id, std::move(buffer), std::move(cancellation),
                std::move(completion));
            writes_.push_back(std::move(operation));
            start_next_write();
        } catch (const std::bad_alloc&) {
            release_write_reservation(bytes);
            auto& selected_completion =
                operation ? operation->completion : completion;
            invoke_noexcept(selected_completion, allocation_status(
                "TCP write queue allocation failed"), 0U);
        } catch (...) {
            release_write_reservation(bytes);
            auto& selected_completion =
                operation ? operation->completion : completion;
            invoke_noexcept(selected_completion, safe_status(
                StatusCode::Internal, "TCP write queueing failed"), 0U);
        }
    }

    std::optional<StatusCode> requested_terminal(std::uint64_t id) noexcept {
        std::lock_guard<std::mutex> lock(submission_mutex_);
        if (close_requested_) return StatusCode::Closed;
        if (id <= cancel_through_) return StatusCode::Cancelled;
        return std::nullopt;
    }

    struct DrainGuard final {
        explicit DrainGuard(bool& active) noexcept : active_(active) { active_ = true; }
        ~DrainGuard() { active_ = false; }
        bool& active_;
    };

    void start_next_read() noexcept {
        if (draining_reads_) return;
        const DrainGuard draining(draining_reads_);
        while (!reads_.empty() && !reads_.front()->active) {
            PendingRead& operation = *reads_.front();
            const auto requested = requested_terminal(operation.id);
            if (closed_ || read_eof_ || requested == StatusCode::Closed) {
                settle_front_read(closed_status());
                continue;
            }
            if (operation.cancelled || requested == StatusCode::Cancelled ||
                operation.cancellation_token.is_cancelled()) {
                settle_front_read(cancelled_status());
                continue;
            }
            try {
                auto registration =
                    operation.cancellation_token.register_callback(
                        [weak = weak_from_this()]() noexcept {
                            if (auto self = weak.lock()) {
                                self->request_control();
                            }
                        });
                if (!registration.ok()) {
                    settle_front_read(safe_status(registration.status().code(),
                                                  registration.status().message()));
                    continue;
                }
                operation.cancellation =
                    std::move(registration).take_value();
                auto allocated = Buffer::allocate(
                    operation.requested, max_read_size());
                if (!allocated.ok()) {
                    settle_front_read(safe_status(allocated.status().code(),
                                                  allocated.status().message()));
                    continue;
                }
                operation.buffer.emplace(
                    std::move(allocated).take_value());
                const auto latest_request = requested_terminal(operation.id);
                if (latest_request == StatusCode::Closed) {
                    settle_front_read(closed_status());
                    continue;
                }
                if (latest_request == StatusCode::Cancelled ||
                    operation.cancellation_token.is_cancelled()) {
                    settle_front_read(cancelled_status());
                    continue;
                }
                operation.active = true;
                const auto bytes = operation.buffer->mutable_bytes();
                socket_.async_read_some(
                    boost::asio::buffer(bytes.data(), bytes.size()),
                    boost::asio::bind_cancellation_slot(
                        operation.signal.slot(),
                        [self = shared_from_this(), id = operation.id](
                            const boost::system::error_code& error,
                            std::size_t transferred) noexcept {
                            self->complete_socket_read(id, error, transferred);
                        }));
                return;
            } catch (const std::bad_alloc&) {
                settle_front_read(allocation_status(
                    "TCP read-operation allocation failed"));
            } catch (...) {
                settle_front_read(safe_status(
                    StatusCode::Internal, "TCP read setup failed"));
            }
        }
    }

    void start_next_write() noexcept {
        if (draining_writes_) return;
        const DrainGuard draining(draining_writes_);
        while (!writes_.empty() && !writes_.front()->active) {
            PendingWrite& operation = *writes_.front();
            const auto requested = requested_terminal(operation.id);
            if (closed_ || write_shutdown_ || requested == StatusCode::Closed) {
                settle_front_write(closed_status(), 0U);
                continue;
            }
            if (operation.cancelled || requested == StatusCode::Cancelled ||
                operation.cancellation_token.is_cancelled()) {
                settle_front_write(cancelled_status(), 0U);
                continue;
            }
            try {
                auto registration =
                    operation.cancellation_token.register_callback(
                        [weak = weak_from_this()]() noexcept {
                            if (auto self = weak.lock()) {
                                self->request_control();
                            }
                        });
                if (!registration.ok()) {
                    settle_front_write(safe_status(registration.status().code(),
                                                   registration.status().message()), 0U);
                    continue;
                }
                operation.cancellation =
                    std::move(registration).take_value();
                if (operation.buffer.empty()) {
                    settle_front_write(Status::success(), 0U);
                    continue;
                }
                if (start_write_some()) return;
            } catch (const std::bad_alloc&) {
                settle_front_write(allocation_status(
                    "TCP write-operation allocation failed"), 0U);
            } catch (...) {
                settle_front_write(safe_status(
                    StatusCode::Internal, "TCP write setup failed"), 0U);
            }
        }
        if (shutdown_after_writes_ && writes_.empty()) {
            shutdown_socket_write();
        }
    }

    void request_control() noexcept {
        channels_->context()->submit(control_, shared_from_this());
    }

    void handle_control() noexcept {
        bool close;
        std::uint64_t cancel_through;
        {
            std::lock_guard<std::mutex> lock(submission_mutex_);
            close = close_requested_;
            cancel_through = cancel_through_;
        }
        if (close) {
            close_on_context();
            return;
        }
        if (closed_) return;
        for (auto& operation : reads_) {
            if (operation->id <= cancel_through ||
                operation->cancellation_token.is_cancelled()) {
                operation->cancelled = true;
            }
        }
        for (auto& operation : writes_) {
            if (operation->id <= cancel_through ||
                operation->cancellation_token.is_cancelled()) {
                operation->cancelled = true;
            }
        }
        if (!reads_.empty() && reads_.front()->active) {
            if (reads_.front()->cancelled) {
                reads_.front()->signal.emit(
                    boost::asio::cancellation_type::terminal);
            }
        } else {
            start_next_read();
        }
        if (!writes_.empty() && writes_.front()->active) {
            if (writes_.front()->cancelled) {
                writes_.front()->signal.emit(
                    boost::asio::cancellation_type::terminal);
            }
        } else {
            start_next_write();
        }
    }

    // One guarded native initiation per partial transfer. Asio's composed
    // async_write would initiate later writes outside our exception boundary.
    bool start_write_some() noexcept {
        PendingWrite& operation = *writes_.front();
        const auto requested = requested_terminal(operation.id);
        if (requested == StatusCode::Closed) {
            settle_front_write(closed_status(), operation.transferred);
            return false;
        }
        if (requested == StatusCode::Cancelled || operation.cancelled ||
            operation.cancellation_token.is_cancelled()) {
            settle_front_write(cancelled_status(), operation.transferred);
            return false;
        }
        try {
            operation.active = true;
            const auto bytes = operation.buffer.bytes().subspan(operation.transferred);
            socket_.async_write_some(
                boost::asio::buffer(bytes.data(), bytes.size()),
                boost::asio::bind_cancellation_slot(
                    operation.signal.slot(),
                    [self = shared_from_this(), id = operation.id](
                        const boost::system::error_code& error,
                        std::size_t transferred) noexcept {
                        self->complete_socket_write(id, error, transferred);
                    }));
            return true;
        } catch (const std::bad_alloc&) {
            const auto transferred = operation.transferred;
            settle_front_write(allocation_status(
                "TCP write-operation allocation failed"), transferred);
        } catch (...) {
            const auto transferred = operation.transferred;
            settle_front_write(safe_status(StatusCode::Internal,
                "TCP write setup failed"), transferred);
        }
        return false;
    }

    void complete_socket_read(std::uint64_t id,
                              const boost::system::error_code& error,
                              std::size_t transferred) noexcept {
        if (reads_.empty() || reads_.front()->id != id) {
            return;
        }
        PendingRead& operation = *reads_.front();
        const auto requested = requested_terminal(id);
        if (closed_ || requested == StatusCode::Closed) {
            settle_front_read(closed_status());
            start_next_read();
            return;
        }
        const bool cancelled = operation.cancelled ||
            requested == StatusCode::Cancelled ||
            operation.cancellation_token.is_cancelled();
        if (cancelled || error == boost::asio::error::operation_aborted) {
            settle_front_read(cancelled ? cancelled_status() : closed_status());
            start_next_read();
            return;
        }
        if (error) {
            if (error == boost::asio::error::eof) {
                read_eof_ = true;
            }
            settle_front_read(closed_status());
            start_next_read();
            return;
        }
        if (!operation.buffer || transferred > operation.buffer->size()) {
            settle_front_read(safe_status(
                StatusCode::Internal,
                "TCP read completion exceeded its buffer"));
            start_next_read();
            return;
        }
        const Status resized = operation.buffer->resize(transferred);
        if (!resized.ok()) {
            settle_front_read(resized);
            start_next_read();
            return;
        }
        ByteChannel::ReadCompletion completion =
            std::move(operation.completion);
        Buffer buffer = std::move(*operation.buffer);
        const std::size_t reserved = operation.requested;
        reads_.pop_front();
        release_read_reservation(reserved);
        complete_read(std::move(completion), std::move(buffer));
        start_next_read();
    }

    void complete_socket_write(std::uint64_t id,
                               const boost::system::error_code& error,
                               std::size_t transferred) noexcept {
        if (writes_.empty() || writes_.front()->id != id) return;
        PendingWrite& operation = *writes_.front();
        if (transferred > operation.buffer.size() - operation.transferred) {
            settle_front_write(safe_status(StatusCode::Internal,
                "TCP write completion exceeded its buffer"), operation.transferred);
            start_next_write();
            return;
        }
        operation.transferred += transferred;
        const auto total = operation.transferred;
        const auto requested = requested_terminal(id);
        const bool cancelled = operation.cancelled ||
            requested == StatusCode::Cancelled ||
            operation.cancellation_token.is_cancelled();
        if (closed_ || requested == StatusCode::Closed) {
            settle_front_write(closed_status(), total);
        } else if (cancelled || error == boost::asio::error::operation_aborted) {
            settle_front_write(cancelled ? cancelled_status() : closed_status(), total);
        } else if (error || transferred == 0U) {
            settle_front_write(closed_status(), total);
        } else if (total == operation.buffer.size()) {
            settle_front_write(Status::success(), total);
        } else {
            if (start_write_some()) return;
        }
        start_next_write();
    }

    void settle_front_read(Status status) noexcept {
        if (reads_.empty()) {
            return;
        }
        std::unique_ptr<PendingRead> operation = std::move(reads_.front());
        reads_.pop_front();
        operation->cancellation.unregister();
        release_read_reservation(operation->requested);
        ByteChannel::ReadCompletion completion =
            std::move(operation->completion);
        complete_read(std::move(completion), std::move(status));
    }

    void settle_front_write(Status status,
                            std::size_t transferred) noexcept {
        if (writes_.empty()) {
            return;
        }
        std::unique_ptr<PendingWrite> operation = std::move(writes_.front());
        writes_.pop_front();
        operation->cancellation.unregister();
        const std::size_t reserved = operation->buffer.size();
        release_write_reservation(reserved);
        ByteChannel::WriteCompletion completion =
            std::move(operation->completion);
        invoke_noexcept(completion, std::move(status), transferred);
    }

    void shutdown_write_on_context() noexcept {
        if (closed_ || write_shutdown_) {
            return;
        }
        if (!writes_.empty()) {
            shutdown_after_writes_ = true;
            return;
        }
        shutdown_socket_write();
    }

    void shutdown_socket_write() noexcept {
        if (closed_ || write_shutdown_) {
            return;
        }
        boost::system::error_code ignored;
        socket_.shutdown(AsioTcpSocket::shutdown_send, ignored);
        write_shutdown_ = true;
        shutdown_after_writes_ = false;
    }

    void close_on_context() noexcept {
        if (closed_) {
            return;
        }
        closed_ = true;
        boost::system::error_code ignored;
        socket_.shutdown(AsioTcpSocket::shutdown_both, ignored);
        socket_.close(ignored);
        // Asio still owns the active operations' buffer views until their
        // completion handlers run, including after socket.close(). Each active
        // completion drains the remaining queue in issue order.
        start_next_read();
        start_next_write();
        unregister_once();
    }

    void unregister_once() noexcept {
        if (registered_) {
            registered_ = false;
            channels_->release(target_id_);
        }
    }

    AsioTcpSocket socket_;
    std::shared_ptr<ChannelRegistry> channels_;
    std::uint64_t target_id_{0U};
    std::deque<std::unique_ptr<PendingRead>> reads_;
    std::deque<std::unique_ptr<PendingWrite>> writes_;
    bool draining_reads_{false};
    bool draining_writes_{false};
    bool read_eof_{false};
    bool write_shutdown_{false};
    bool shutdown_after_writes_{false};
    bool closed_{false};
    bool registered_{true};

    std::mutex submission_mutex_;
    std::uint64_t next_operation_id_{1U};
    std::size_t submitted_reads_{0U};
    std::size_t submitted_writes_{0U};
    std::size_t submitted_read_bytes_{0U};
    std::size_t submitted_write_bytes_{0U};
    bool close_requested_{false};
    bool write_shutdown_requested_{false};
    std::uint64_t cancel_through_{0U};
    ControlTask control_;
};

class AsioTcpByteChannel final : public ByteChannel {
public:
    explicit AsioTcpByteChannel(
        std::shared_ptr<TcpChannelState> state) noexcept
        : state_(std::move(state)) {}

    ~AsioTcpByteChannel() noexcept override { state_->request_close(); }

    ExecutorAffinity executor_affinity() const noexcept override {
        return state_->affinity();
    }
    std::size_t max_read_size() const noexcept override {
        return state_->max_read_size();
    }
    std::size_t max_write_size() const noexcept override {
        return state_->max_write_size();
    }
    void async_read(std::size_t max_bytes,
                    CancellationToken cancellation,
                    ReadCompletion completion) override {
        state_->async_read(max_bytes, std::move(cancellation),
                           std::move(completion));
    }
    void async_write(Buffer buffer,
                     CancellationToken cancellation,
                     WriteCompletion completion) override {
        state_->async_write(std::move(buffer), std::move(cancellation),
                            std::move(completion));
    }
    Status shutdown_write() noexcept override {
        return state_->shutdown_write();
    }
    void cancel() noexcept override { state_->request_cancel(); }
    void close() noexcept override { state_->request_close(); }

private:
    std::shared_ptr<TcpChannelState> state_;
};

class CreateOperation final : public CancelTarget,
                              public std::enable_shared_from_this<CreateOperation> {
public:
    CreateOperation(std::shared_ptr<ProviderState> provider,
                    std::uint64_t target_id,
                    std::uint64_t reserved_epoch,
                    std::shared_ptr<ByteChannelProvider::Completion> completion)
        : provider_(std::move(provider)),
          target_id_(target_id),
          reserved_epoch_(reserved_epoch),
          completion_(std::move(completion)),
          socket_(provider_->executor()),
          resolve_timer_(provider_->executor()),
          connect_timer_(provider_->executor()),
          control_([](void* owner) noexcept {
              static_cast<CreateOperation*>(owner)->handle_control();
          }) {}

    ~CreateOperation() noexcept override {
        boost::system::error_code ignored;
        socket_.close(ignored);
        resolve_timer_.cancel(ignored);
        connect_timer_.cancel(ignored);
        if (!promoted_) {
            provider_->release(target_id_);
        }
    }

    std::uint64_t reserved_epoch() const noexcept { return reserved_epoch_; }

    void start(CancellationToken cancellation) noexcept {
        start_on_context(std::move(cancellation));
    }

    void request_cancel() noexcept override {
        cancellation_requested_.store(true, std::memory_order_release);
        provider_->context()->submit(control_, shared_from_this());
    }

private:
    void handle_control() noexcept {
        if (finished_) return;
        if (cancellation_requested_.load(std::memory_order_acquire)) {
            cancel_on_context();
        }
    }

    void start_on_context(CancellationToken cancellation) noexcept {
        try {
            if (cancellation.is_cancelled() ||
                cancellation_requested_.load(std::memory_order_acquire)) {
                finish(Result<std::unique_ptr<ByteChannel>>(
                    cancelled_status()));
                return;
            }
            auto registration = cancellation.register_callback(
                [weak = weak_from_this()]() noexcept {
                    if (auto self = weak.lock()) {
                        self->request_cancel();
                    }
                });
            if (!registration.ok()) {
                finish(Result<std::unique_ptr<ByteChannel>>(safe_status(
                    registration.status().code(), registration.status().message())));
                return;
            }
            cancellation_ = std::move(registration).take_value();
            if (cancellation_requested_.load(std::memory_order_acquire)) {
                finish(Result<std::unique_ptr<ByteChannel>>(
                    cancelled_status()));
                return;
            }
            // A numeric host needs no lookup and never starts the helper.
            if (const auto& numeric = provider_->numeric_host()) {
                endpoints_.emplace_back(*numeric, provider_->port());
                begin_connect();
                return;
            }
            resolve_timer_.expires_after(provider_->limits().resolve_timeout);
            resolve_timer_.async_wait(
                [self = shared_from_this()](
                    const boost::system::error_code& error) noexcept {
                    self->complete_resolve_timeout(error);
                });
            auto lookup = provider_->resolver()->resolve(
                provider_->host(), provider_->limits().max_resolved_endpoints,
                [self = shared_from_this()](Result<Addresses> addresses) noexcept {
                    self->complete_resolve(std::move(addresses));
                });
            if (!lookup.ok()) {
                finish(Result<std::unique_ptr<ByteChannel>>(
                    resolution_failure(lookup.status())));
                return;
            }
            lookup_ = lookup.value();
        } catch (const std::bad_alloc&) {
            finish(Result<std::unique_ptr<ByteChannel>>(allocation_status(
                "TCP create allocation failed")));
        } catch (...) {
            finish(Result<std::unique_ptr<ByteChannel>>(safe_status(
                StatusCode::Internal, "TCP create failed")));
        }
    }

    void complete_resolve_timeout(
        const boost::system::error_code& error) noexcept {
        if (error || finished_) {
            return;
        }
        cancel_lookup();
        finish(Result<std::unique_ptr<ByteChannel>>(
            cancellation_requested_.load(std::memory_order_acquire)
                ? cancelled_status()
                : safe_status(StatusCode::NotFound,
                              "TCP endpoint resolution timed out")));
    }

    void complete_connect_timeout(
        const boost::system::error_code& error) noexcept {
        if (error || finished_) {
            return;
        }
        boost::system::error_code ignored;
        socket_.cancel(ignored);
        socket_.close(ignored);
        finish(Result<std::unique_ptr<ByteChannel>>(
            cancellation_requested_.load(std::memory_order_acquire)
                ? cancelled_status()
                : safe_status(StatusCode::Closed,
                              "TCP endpoint connection timed out")));
    }

    static Status resolution_failure(const Status& status) noexcept {
        return status.code() == StatusCode::ResourceExhausted ||
                       status.code() == StatusCode::Cancelled
                   ? safe_status(status.code(), status.message())
                   : safe_status(StatusCode::NotFound,
                                 "TCP endpoint resolution failed");
    }

    void cancel_lookup() noexcept {
        if (lookup_ != 0U) provider_->resolver()->cancel(std::exchange(lookup_, 0U));
    }

    void complete_resolve(Result<Addresses> addresses) noexcept {
        lookup_ = 0U;
        try {
            if (finished_) return;
            if (cancellation_requested_.load(std::memory_order_acquire)) {
                finish(Result<std::unique_ptr<ByteChannel>>(cancelled_status()));
                return;
            }
            boost::system::error_code ignored;
            resolve_timer_.cancel(ignored);
            if (!addresses.ok()) {
                finish(Result<std::unique_ptr<ByteChannel>>(
                    resolution_failure(addresses.status())));
                return;
            }
            for (const auto& address : addresses.value()) {
                if (endpoints_.size() >=
                    provider_->limits().max_resolved_endpoints) {
                    break;
                }
                endpoints_.emplace_back(address, provider_->port());
            }
            if (endpoints_.empty()) {
                finish(Result<std::unique_ptr<ByteChannel>>(safe_status(
                    StatusCode::NotFound,
                    "TCP endpoint resolution returned no endpoints")));
                return;
            }
            begin_connect();
        } catch (const std::bad_alloc&) {
            finish(Result<std::unique_ptr<ByteChannel>>(allocation_status(
                "TCP resolved-endpoint allocation failed")));
        } catch (...) {
            finish(Result<std::unique_ptr<ByteChannel>>(safe_status(
                StatusCode::Internal,
                "TCP resolution completion failed")));
        }
    }

    void begin_connect() {
        connect_timer_.expires_after(provider_->limits().connect_timeout);
        connect_timer_.async_wait(
            [self = shared_from_this()](
                const boost::system::error_code& timer_error) noexcept {
                self->complete_connect_timeout(timer_error);
            });
        connect_next();
    }

    void connect_next() noexcept {
        try {
            if (finished_) {
                return;
            }
            if (cancellation_requested_.load(std::memory_order_acquire)) {
                finish(Result<std::unique_ptr<ByteChannel>>(
                    cancelled_status()));
                return;
            }
            boost::system::error_code ignored;
            socket_.close(ignored);
            while (endpoint_index_ < endpoints_.size() &&
                   connect_attempts_ <
                       provider_->limits().max_connect_attempts) {
                const Tcp::endpoint endpoint = endpoints_[endpoint_index_++];
                ++connect_attempts_;
                boost::system::error_code open_error;
                socket_.open(endpoint.protocol(), open_error);
                if (open_error) {
                    continue;
                }
                Status protection =
                    protect_socket(socket_, provider_->protector());
                if (!protection.ok()) {
                    finish(Result<std::unique_ptr<ByteChannel>>(
                        std::move(protection)));
                    return;
                }
                if (connect_timer_.expiry() <=
                    std::chrono::steady_clock::now()) {
                    finish(Result<std::unique_ptr<ByteChannel>>(safe_status(
                        StatusCode::Closed,
                        "TCP endpoint connection timed out")));
                    return;
                }
                socket_.async_connect(
                    endpoint, [self = shared_from_this()](
                        const boost::system::error_code& error) noexcept {
                        self->complete_connect(error);
                    });
                return;
            }
            finish(Result<std::unique_ptr<ByteChannel>>(safe_status(
                StatusCode::NotFound, "TCP endpoint connection failed")));
        } catch (const std::bad_alloc&) {
            finish(Result<std::unique_ptr<ByteChannel>>(allocation_status(
                "TCP connection allocation failed")));
        } catch (...) {
            finish(Result<std::unique_ptr<ByteChannel>>(safe_status(
                StatusCode::Internal, "TCP connection setup failed")));
        }
    }

    void complete_connect(const boost::system::error_code& error) noexcept {
        if (finished_) {
            return;
        }
        if (cancellation_requested_.load(std::memory_order_acquire)) {
            finish(Result<std::unique_ptr<ByteChannel>>(cancelled_status()));
            return;
        }
        if (error) {
            connect_next();
            return;
        }
        try {
            boost::system::error_code ignored;
            connect_timer_.cancel(ignored);
            socket_.set_option(Tcp::no_delay(true), ignored);
            auto state = std::make_shared<TcpChannelState>(
                std::move(socket_), provider_->channels(), target_id_);
            if (cancellation_requested_.load(std::memory_order_acquire)) {
                state->request_close();
                finish(Result<std::unique_ptr<ByteChannel>>(cancelled_status()));
                return;
            }
            Status promoted = provider_->promote(target_id_, reserved_epoch_, state);
            if (!promoted.ok()) {
                state->request_close();
                finish(Result<std::unique_ptr<ByteChannel>>(std::move(promoted)));
                return;
            }
            promoted_ = true;
            std::unique_ptr<ByteChannel> channel =
                std::make_unique<AsioTcpByteChannel>(std::move(state));
            if (cancellation_requested_.load(std::memory_order_acquire)) {
                channel->close();
                finish(Result<std::unique_ptr<ByteChannel>>(cancelled_status()));
                return;
            }
            finish(Result<std::unique_ptr<ByteChannel>>(std::move(channel)));
        } catch (const std::bad_alloc&) {
            finish(Result<std::unique_ptr<ByteChannel>>(allocation_status(
                "TCP channel allocation failed")));
        } catch (...) {
            finish(Result<std::unique_ptr<ByteChannel>>(safe_status(
                StatusCode::Internal,
                "TCP channel construction failed")));
        }
    }

    void cancel_on_context() noexcept {
        if (finished_) {
            return;
        }
        cancel_lookup();
        boost::system::error_code ignored;
        socket_.cancel(ignored);
        socket_.close(ignored);
        resolve_timer_.cancel(ignored);
        connect_timer_.cancel(ignored);
        finish(Result<std::unique_ptr<ByteChannel>>(cancelled_status()));
    }

    void finish(Result<std::unique_ptr<ByteChannel>> result) noexcept {
        if (finished_) {
            if (result.ok()) {
                std::unique_ptr<ByteChannel> channel =
                    std::move(result).take_value();
                channel->close();
            }
            return;
        }
        finished_ = true;
        cancellation_.unregister();
        cancel_lookup();
        boost::system::error_code ignored;
        resolve_timer_.cancel(ignored);
        connect_timer_.cancel(ignored);
        if (!promoted_) {
            socket_.close(ignored);
            provider_->release(target_id_);
        }
        if (completion_) {
            ByteChannelProvider::Completion completion =
                std::move(*completion_);
            completion_.reset();
            invoke_noexcept(completion, std::move(result));
        }
    }

    std::shared_ptr<ProviderState> provider_;
    std::uint64_t target_id_{0U};
    std::uint64_t reserved_epoch_{0U};
    std::shared_ptr<ByteChannelProvider::Completion> completion_;
    // Nonzero while a system lookup is outstanding for this create.
    std::uint64_t lookup_{0U};
    AsioTcpSocket socket_;
    Timer resolve_timer_;
    Timer connect_timer_;
    std::vector<Tcp::endpoint> endpoints_;
    std::size_t endpoint_index_{0U};
    std::size_t connect_attempts_{0U};
    CancellationRegistration cancellation_;
    std::atomic<bool> cancellation_requested_{false};
    bool finished_{false};
    bool promoted_{false};
    ControlTask control_;
};

void complete_create_failure(ByteChannelProvider::Completion completion,
                             Status status) noexcept {
    Result<std::unique_ptr<ByteChannel>> result(std::move(status));
    invoke_noexcept(completion, std::move(result));
}

}  // namespace

AsioTcpByteChannelProvider::AsioTcpByteChannelProvider(
    std::shared_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

AsioTcpByteChannelProvider::~AsioTcpByteChannelProvider() noexcept {
    cancel();
}

Result<std::shared_ptr<AsioTcpByteChannelProvider>>
AsioTcpByteChannelProvider::create(
    std::shared_ptr<AsioExecutionContext> context,
    std::string remote_host,
    std::uint16_t remote_port,
    AsioTcpByteChannelLimits limits,
    AsioTcpSocketProtector socket_protector,
    std::shared_ptr<SystemResolver> resolver) {
    if (!context || remote_port == 0U ||
        !valid_host(remote_host) || !valid_limits(limits)) {
        return Result<std::shared_ptr<AsioTcpByteChannelProvider>>(safe_status(
            StatusCode::InvalidArgument,
            "Asio TCP context, endpoint, or limits are invalid"));
    }
    boost::system::error_code numeric_error;
    std::optional<boost::asio::ip::address> numeric_host =
        boost::asio::ip::make_address(remote_host, numeric_error);
    if (numeric_error) numeric_host.reset();
    if (!numeric_host &&
        (!resolver || resolver->executor_affinity() != context->affinity())) {
        return Result<std::shared_ptr<AsioTcpByteChannelProvider>>(safe_status(
            StatusCode::InvalidArgument,
            "a TCP hostname needs a system resolver on the same context"));
    }
    try {
        auto descriptor = ProviderDescriptor::create(
            std::string(kAsioTcpByteChannelProviderId),
            ProviderKind::ByteChannel,
            kAsioTcpByteChannelProviderApiVersion,
            CapabilitySet::of({
                Capability::ReliableOrderedBytes,
                Capability::AsynchronousIo,
                Capability::Cancellation,
                Capability::ExecutorAffinity,
                Capability::BoundedWrites,
            }));
        if (!descriptor.ok()) {
            return Result<std::shared_ptr<AsioTcpByteChannelProvider>>(
                descriptor.status());
        }
        auto channels = std::make_shared<ChannelRegistry>(
            std::move(context), static_cast<const AsioTcpChannelLimits&>(limits));
        auto state = std::make_shared<ProviderState>(
            std::move(channels),
            std::move(remote_host), std::move(numeric_host), remote_port, limits,
            std::move(socket_protector), std::move(resolver),
            std::move(descriptor).take_value());
        auto impl = std::make_shared<Impl>(std::move(state));
        return Result<std::shared_ptr<AsioTcpByteChannelProvider>>(
            std::shared_ptr<AsioTcpByteChannelProvider>(
                new AsioTcpByteChannelProvider(std::move(impl))));
    } catch (const std::bad_alloc&) {
        return Result<std::shared_ptr<AsioTcpByteChannelProvider>>(
            allocation_status("Asio TCP provider allocation failed"));
    } catch (...) {
        return Result<std::shared_ptr<AsioTcpByteChannelProvider>>(safe_status(
            StatusCode::Internal, "Asio TCP provider construction failed"));
    }
}

const ProviderDescriptor&
AsioTcpByteChannelProvider::descriptor() const noexcept {
    return impl_->state()->descriptor();
}

void AsioTcpByteChannelProvider::async_create(
    EndpointRole role,
    CancellationToken cancellation,
    Completion completion) {
    const auto state = impl_->state();
    state->context()->require_context();
    if (!completion) return;
    if (role != EndpointRole::Client) {
        complete_create_failure(
            std::move(completion),
            safe_status(StatusCode::InvalidArgument,
                        "asio-tcp is a client-only ByteChannel provider"));
        return;
    }
    auto reservation = state->reserve_create();
    if (!reservation.ok()) {
        complete_create_failure(std::move(completion), safe_status(
            reservation.status().code(), reservation.status().message()));
        return;
    }
    const auto [target_id, epoch] =
        std::move(reservation).take_value();
    std::shared_ptr<Completion> completion_holder;
    try {
        completion_holder =
            std::make_shared<Completion>(std::move(completion));
        auto operation = std::make_shared<CreateOperation>(
            state, target_id, epoch, completion_holder);
        const bool cancelled_before_bind =
            state->bind_target(target_id, epoch, operation);
        if (cancelled_before_bind) {
            operation->request_cancel();
        }
        operation->start(std::move(cancellation));
    } catch (const std::bad_alloc&) {
        state->release(target_id);
        complete_create_failure(
            completion_holder ? std::move(*completion_holder)
                              : std::move(completion),
            allocation_status("TCP create-operation allocation failed"));
    } catch (...) {
        state->release(target_id);
        complete_create_failure(
            completion_holder ? std::move(*completion_holder)
                              : std::move(completion),
            safe_status(StatusCode::Internal,
                        "TCP create-operation setup failed"));
    }
}

void AsioTcpByteChannelProvider::cancel() noexcept {
    if (impl_) {
        impl_->state()->cancel_all();
    }
}

ExecutorAffinity
AsioTcpByteChannelProvider::executor_affinity() const noexcept {
    return impl_->state()->affinity();
}

const std::string& AsioTcpByteChannelProvider::remote_host() const noexcept {
    return impl_->state()->host();
}

std::uint16_t AsioTcpByteChannelProvider::remote_port() const noexcept {
    return impl_->state()->port();
}

const AsioTcpByteChannelLimits&
AsioTcpByteChannelProvider::limits() const noexcept {
    return impl_->state()->limits();
}

AsioTcpAcceptedChannelOwner::AsioTcpAcceptedChannelOwner(
    std::shared_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

AsioTcpAcceptedChannelOwner::~AsioTcpAcceptedChannelOwner() noexcept {
    cancel();
}

Result<std::shared_ptr<AsioTcpAcceptedChannelOwner>>
AsioTcpAcceptedChannelOwner::create(
    std::shared_ptr<AsioExecutionContext> context,
    AsioTcpChannelLimits limits) {
    if (!context || !valid_channel_limits(limits)) {
        return Result<std::shared_ptr<AsioTcpAcceptedChannelOwner>>(safe_status(
            StatusCode::InvalidArgument,
            "Asio accepted-channel context or limits are invalid"));
    }
    try {
        auto channels = std::make_shared<ChannelRegistry>(
            std::move(context), limits);
        auto impl = std::make_shared<Impl>(std::move(channels));
        return Result<std::shared_ptr<AsioTcpAcceptedChannelOwner>>(
            std::shared_ptr<AsioTcpAcceptedChannelOwner>(
                new AsioTcpAcceptedChannelOwner(std::move(impl))));
    } catch (const std::bad_alloc&) {
        return Result<std::shared_ptr<AsioTcpAcceptedChannelOwner>>(
            allocation_status("Asio accepted-channel owner allocation failed"));
    } catch (...) {
        return Result<std::shared_ptr<AsioTcpAcceptedChannelOwner>>(safe_status(
            StatusCode::Internal, "Asio accepted-channel owner construction failed"));
    }
}

Result<std::unique_ptr<ByteChannel>> AsioTcpAcceptedChannelOwner::adopt(
    AsioTcpSocket socket) {
    const auto channels = impl_->channels();
    if (!socket.is_open()) {
        return Result<std::unique_ptr<ByteChannel>>(safe_status(
            StatusCode::InvalidArgument,
            "accepted TCP socket is closed"));
    }
    boost::system::error_code endpoint_error;
    (void)socket.remote_endpoint(endpoint_error);
    if (endpoint_error) {
        boost::system::error_code ignored;
        socket.close(ignored);
        return Result<std::unique_ptr<ByteChannel>>(safe_status(
            StatusCode::InvalidArgument,
            "accepted TCP socket is not connected"));
    }
    if (socket.get_executor() != channels->executor()) {
        boost::system::error_code ignored;
        socket.close(ignored);
        return Result<std::unique_ptr<ByteChannel>>(safe_status(
            StatusCode::ProviderMismatch,
            "accepted TCP socket uses a different executor"));
    }
    auto reservation = channels->reserve_active();
    if (!reservation.ok()) {
        boost::system::error_code ignored;
        socket.close(ignored);
        return Result<std::unique_ptr<ByteChannel>>(safe_status(
            reservation.status().code(), reservation.status().message()));
    }
    const auto [target_id, epoch] =
        std::move(reservation).take_value();
    try {
        auto state = std::make_shared<TcpChannelState>(
            std::move(socket), channels, target_id);
        const bool cancelled_before_bind =
            channels->bind_target(target_id, epoch, state);
        std::unique_ptr<ByteChannel> channel =
            std::make_unique<AsioTcpByteChannel>(state);
        if (cancelled_before_bind) {
            state->request_cancel();
        }
        return Result<std::unique_ptr<ByteChannel>>(std::move(channel));
    } catch (const std::bad_alloc&) {
        channels->release(target_id);
        return Result<std::unique_ptr<ByteChannel>>(
            allocation_status("accepted TCP channel allocation failed"));
    } catch (...) {
        channels->release(target_id);
        return Result<std::unique_ptr<ByteChannel>>(safe_status(
            StatusCode::Internal,
            "accepted TCP channel construction failed"));
    }
}

void AsioTcpAcceptedChannelOwner::cancel() noexcept {
    if (impl_) {
        impl_->channels()->cancel_all();
    }
}

ExecutorAffinity
AsioTcpAcceptedChannelOwner::executor_affinity() const noexcept {
    return impl_->channels()->affinity();
}

const AsioTcpChannelLimits&
AsioTcpAcceptedChannelOwner::limits() const noexcept {
    return impl_->channels()->limits();
}

}  // namespace yume::providers
