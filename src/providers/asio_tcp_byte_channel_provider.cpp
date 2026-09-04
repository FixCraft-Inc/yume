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
#include <mutex>
#include <new>
#include <optional>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/cancellation_type.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/write.hpp>
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

using Executor = boost::asio::any_io_executor;
using Strand = boost::asio::strand<Executor>;
using Tcp = boost::asio::ip::tcp;

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

bool valid_limits(const AsioTcpByteChannelLimits& limits) noexcept {
    return limits.max_pending_creates > 0U &&
           limits.max_pending_creates <= kMaximumProviderOperations &&
           limits.max_active_channels > 0U &&
           limits.max_active_channels <= kMaximumProviderOperations &&
           limits.max_resolved_endpoints > 0U &&
           limits.max_resolved_endpoints <= kMaximumResolvedEndpoints &&
           limits.max_connect_attempts > 0U &&
           limits.max_connect_attempts <= kMaximumConnectAttempts &&
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
           limits.max_queued_write_bytes <= engine::kAbsoluteMaxBufferBytes &&
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

Status protect_socket(Tcp::socket& socket,
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
    std::uint64_t cancellation_epoch{0U};
};

class ProviderState final : public std::enable_shared_from_this<ProviderState> {
public:
    ProviderState(Executor executor,
                  ExecutorAffinity affinity,
                  std::string host,
                  std::uint16_t port,
                  AsioTcpByteChannelLimits limits,
                  AsioTcpSocketProtector protector,
                  ProviderDescriptor descriptor) noexcept
        : executor_(std::move(executor)),
          affinity_(affinity),
          host_(std::move(host)),
          port_(port),
          limits_(limits),
          protector_(std::move(protector)),
          descriptor_(std::move(descriptor)) {}

    Result<std::pair<std::uint64_t, std::uint64_t>> reserve_create() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (pending_creates_ >= limits_.max_pending_creates ||
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
            targets_.emplace(id, TargetEntry{
                TargetKind::PendingCreate, {}, cancellation_epoch_});
        } catch (const std::bad_alloc&) {
            return Result<std::pair<std::uint64_t, std::uint64_t>>(
                allocation_status("Asio TCP reservation allocation failed"));
        }
        ++pending_creates_;
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

    bool promote(std::uint64_t id,
                 const std::shared_ptr<CancelTarget>& target) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto found = targets_.find(id);
        if (found == targets_.end() ||
            found->second.kind != TargetKind::PendingCreate ||
            pending_creates_ == 0U ||
            active_channels_ >= limits_.max_active_channels) {
            return false;
        }
        found->second.kind = TargetKind::ActiveChannel;
        found->second.target = target;
        --pending_creates_;
        ++active_channels_;
        return true;
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
        std::lock_guard<std::mutex> lock(mutex_);
        ++cancellation_epoch_;
        for (const auto& [_, entry] : targets_) {
            if (auto target = entry.target.lock()) {
                target->request_cancel();
            }
        }
    }

    const Executor& executor() const noexcept { return executor_; }
    ExecutorAffinity affinity() const noexcept { return affinity_; }
    const std::string& host() const noexcept { return host_; }
    std::uint16_t port() const noexcept { return port_; }
    const AsioTcpByteChannelLimits& limits() const noexcept { return limits_; }
    const AsioTcpSocketProtector& protector() const noexcept {
        return protector_;
    }
    const ProviderDescriptor& descriptor() const noexcept {
        return descriptor_;
    }

private:
    Executor executor_;
    ExecutorAffinity affinity_;
    std::string host_;
    std::uint16_t port_{0U};
    AsioTcpByteChannelLimits limits_;
    AsioTcpSocketProtector protector_;
    ProviderDescriptor descriptor_;

    std::mutex mutex_;
    std::unordered_map<std::uint64_t, TargetEntry> targets_;
    std::uint64_t next_target_id_{1U};
    std::uint64_t cancellation_epoch_{0U};
    std::size_t pending_creates_{0U};
    std::size_t active_channels_{0U};
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

namespace {

class TcpChannelState final : public CancelTarget,
                              public std::enable_shared_from_this<TcpChannelState> {
public:
    TcpChannelState(Tcp::socket socket,
                    Strand strand,
                    std::shared_ptr<ProviderState> provider,
                    std::uint64_t target_id) noexcept
        : strand_(std::move(strand)),
          socket_(std::move(socket)),
          provider_(std::move(provider)),
          target_id_(target_id) {}

    ~TcpChannelState() noexcept override {
        boost::system::error_code ignored;
        socket_.close(ignored);
        unregister_once();
    }

    ExecutorAffinity affinity() const noexcept { return provider_->affinity(); }
    std::size_t max_read_size() const noexcept {
        return provider_->limits().max_read_bytes;
    }
    std::size_t max_write_size() const noexcept {
        return provider_->limits().max_write_bytes;
    }

    void async_read(std::size_t max_bytes,
                    CancellationToken cancellation,
                    ByteChannel::ReadCompletion completion) noexcept {
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
                           provider_->limits().max_queued_read_operations ||
                       !add_fits(submitted_read_bytes_, max_bytes,
                                 provider_->limits().max_queued_read_bytes)) {
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
            post_read_completion(std::move(completion), std::move(error));
            return;
        }
        std::shared_ptr<ByteChannel::ReadCompletion> completion_holder;
        try {
            completion_holder =
                std::make_shared<ByteChannel::ReadCompletion>(
                    std::move(completion));
            boost::asio::post(
                strand_,
                [self = shared_from_this(), id, max_bytes,
                 cancellation = std::move(cancellation),
                 completion_holder]() mutable noexcept {
                    self->enqueue_read(id, max_bytes,
                                       std::move(cancellation),
                                       std::move(*completion_holder));
                });
        } catch (const std::bad_alloc&) {
            release_read_reservation(max_bytes);
            post_read_completion(
                completion_holder ? std::move(*completion_holder)
                                  : std::move(completion),
                allocation_status(
                "TCP read scheduling allocation failed"));
        } catch (...) {
            release_read_reservation(max_bytes);
            post_read_completion(
                completion_holder ? std::move(*completion_holder)
                                  : std::move(completion),
                safe_status(StatusCode::Internal,
                            "TCP read scheduling failed"));
        }
    }

    void async_write(Buffer buffer,
                     CancellationToken cancellation,
                     ByteChannel::WriteCompletion completion) noexcept {
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
                           provider_->limits().max_queued_write_operations ||
                       !add_fits(submitted_write_bytes_, bytes,
                                 provider_->limits().max_queued_write_bytes)) {
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
            post_write_completion(std::move(completion), std::move(error), 0U);
            return;
        }
        std::shared_ptr<ByteChannel::WriteCompletion> completion_holder;
        try {
            completion_holder =
                std::make_shared<ByteChannel::WriteCompletion>(
                    std::move(completion));
            boost::asio::post(
                strand_,
                [self = shared_from_this(), id,
                 buffer = std::move(buffer),
                 cancellation = std::move(cancellation),
                 completion_holder]() mutable noexcept {
                    self->enqueue_write(id, std::move(buffer),
                                        std::move(cancellation),
                                        std::move(*completion_holder));
                });
        } catch (const std::bad_alloc&) {
            release_write_reservation(bytes);
            post_write_completion(
                completion_holder ? std::move(*completion_holder)
                                  : std::move(completion),
                allocation_status("TCP write scheduling allocation failed"),
                0U);
        } catch (...) {
            release_write_reservation(bytes);
            post_write_completion(
                completion_holder ? std::move(*completion_holder)
                                  : std::move(completion),
                safe_status(StatusCode::Internal,
                            "TCP write scheduling failed"),
                0U);
        }
    }

    Status shutdown_write() noexcept {
        {
            std::lock_guard<std::mutex> lock(submission_mutex_);
            if (close_requested_) {
                return closed_status();
            }
            if (write_shutdown_requested_) {
                return Status::success();
            }
            write_shutdown_requested_ = true;
        }
        try {
            boost::asio::post(strand_, [self = shared_from_this()]() noexcept {
                self->shutdown_write_on_strand();
            });
            return Status::success();
        } catch (const std::bad_alloc&) {
            std::lock_guard<std::mutex> lock(submission_mutex_);
            write_shutdown_requested_ = false;
            return allocation_status(
                "TCP write-shutdown scheduling allocation failed");
        } catch (...) {
            std::lock_guard<std::mutex> lock(submission_mutex_);
            write_shutdown_requested_ = false;
            return safe_status(StatusCode::Internal,
                               "TCP write-shutdown scheduling failed");
        }
    }

    void request_cancel() noexcept override {
        try {
            boost::asio::post(strand_, [self = shared_from_this()]() noexcept {
                self->cancel_on_strand();
            });
        } catch (...) {
        }
    }

    void request_close() noexcept {
        {
            std::lock_guard<std::mutex> lock(submission_mutex_);
            if (close_requested_) {
                return;
            }
            close_requested_ = true;
        }
        try {
            boost::asio::post(strand_, [self = shared_from_this()]() noexcept {
                self->close_on_strand();
            });
        } catch (...) {
            // The state destructor is the final socket/resource backstop if an
            // executor can no longer accept cleanup work.
        }
    }

private:
    struct PendingRead final {
        PendingRead(std::uint64_t operation_id,
                    std::size_t requested_bytes,
                    CancellationToken owned_cancellation,
                    ByteChannel::ReadCompletion owned_completion) noexcept
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
        PendingWrite(std::uint64_t operation_id,
                     Buffer owned_buffer,
                     CancellationToken owned_cancellation,
                     ByteChannel::WriteCompletion owned_completion) noexcept
            : id(operation_id),
              buffer(std::move(owned_buffer)),
              cancellation_token(std::move(owned_cancellation)),
              completion(std::move(owned_completion)) {}

        std::uint64_t id;
        Buffer buffer;
        CancellationToken cancellation_token;
        ByteChannel::WriteCompletion completion;
        CancellationRegistration cancellation;
        boost::asio::cancellation_signal signal;
        bool active{false};
        bool cancelled{false};
    };

    void post_read_completion(ByteChannel::ReadCompletion completion,
                              Status status) noexcept {
        std::shared_ptr<ByteChannel::ReadCompletion> completion_holder;
        std::shared_ptr<Status> status_holder;
        try {
            completion_holder =
                std::make_shared<ByteChannel::ReadCompletion>(
                    std::move(completion));
            status_holder = std::make_shared<Status>(std::move(status));
            boost::asio::post(
                strand_, [completion_holder, status_holder]() mutable noexcept {
                    complete_read(std::move(*completion_holder),
                                  std::move(*status_holder));
                });
        } catch (...) {
            complete_read(
                completion_holder ? std::move(*completion_holder)
                                  : std::move(completion),
                status_holder ? std::move(*status_holder)
                              : std::move(status));
        }
    }

    void post_write_completion(ByteChannel::WriteCompletion completion,
                               Status status,
                               std::size_t transferred) noexcept {
        std::shared_ptr<ByteChannel::WriteCompletion> completion_holder;
        std::shared_ptr<Status> status_holder;
        try {
            completion_holder =
                std::make_shared<ByteChannel::WriteCompletion>(
                    std::move(completion));
            status_holder = std::make_shared<Status>(std::move(status));
            boost::asio::post(
                strand_, [completion_holder, status_holder,
                          transferred]() mutable noexcept {
                    invoke_noexcept(*completion_holder,
                                    std::move(*status_holder), transferred);
                });
        } catch (...) {
            auto& selected_completion =
                completion_holder ? *completion_holder : completion;
            invoke_noexcept(
                selected_completion,
                status_holder ? std::move(*status_holder) : std::move(status),
                transferred);
        }
    }

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

    void start_next_read() noexcept {
        while (!reads_.empty() && !reads_.front()->active) {
            PendingRead& operation = *reads_.front();
            if (closed_ || read_eof_) {
                settle_front_read(closed_status());
                continue;
            }
            if (operation.cancelled ||
                operation.cancellation_token.is_cancelled()) {
                settle_front_read(cancelled_status());
                continue;
            }
            try {
                auto registration =
                    operation.cancellation_token.register_callback(
                        [weak = weak_from_this(), id = operation.id]() noexcept {
                            if (auto self = weak.lock()) {
                                self->request_cancel_read(id);
                            }
                        });
                if (!registration.ok()) {
                    settle_front_read(registration.status());
                    continue;
                }
                operation.cancellation =
                    std::move(registration).take_value();
                auto allocated = Buffer::allocate(
                    operation.requested, max_read_size());
                if (!allocated.ok()) {
                    settle_front_read(allocated.status());
                    continue;
                }
                operation.buffer.emplace(
                    std::move(allocated).take_value());
                operation.active = true;
                const auto bytes = operation.buffer->mutable_bytes();
                socket_.async_read_some(
                    boost::asio::buffer(bytes.data(), bytes.size()),
                    boost::asio::bind_executor(
                        strand_, boost::asio::bind_cancellation_slot(
                            operation.signal.slot(),
                            [self = shared_from_this(), id = operation.id](
                                const boost::system::error_code& error,
                                std::size_t transferred) noexcept {
                                self->complete_socket_read(
                                    id, error, transferred);
                            })));
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
        while (!writes_.empty() && !writes_.front()->active) {
            PendingWrite& operation = *writes_.front();
            if (closed_ || write_shutdown_) {
                settle_front_write(closed_status(), 0U);
                continue;
            }
            if (operation.cancelled ||
                operation.cancellation_token.is_cancelled()) {
                settle_front_write(cancelled_status(), 0U);
                continue;
            }
            try {
                auto registration =
                    operation.cancellation_token.register_callback(
                        [weak = weak_from_this(), id = operation.id]() noexcept {
                            if (auto self = weak.lock()) {
                                self->request_cancel_write(id);
                            }
                        });
                if (!registration.ok()) {
                    settle_front_write(registration.status(), 0U);
                    continue;
                }
                operation.cancellation =
                    std::move(registration).take_value();
                operation.active = true;
                const auto bytes = operation.buffer.bytes();
                boost::asio::async_write(
                    socket_, boost::asio::buffer(bytes.data(), bytes.size()),
                    boost::asio::bind_executor(
                        strand_, boost::asio::bind_cancellation_slot(
                            operation.signal.slot(),
                            [self = shared_from_this(), id = operation.id](
                                const boost::system::error_code& error,
                                std::size_t transferred) noexcept {
                                self->complete_socket_write(
                                    id, error, transferred);
                            })));
                return;
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

    void request_cancel_read(std::uint64_t id) noexcept {
        try {
            boost::asio::post(
                strand_, [self = shared_from_this(), id]() noexcept {
                    self->cancel_read_on_strand(id);
                });
        } catch (...) {
        }
    }

    void request_cancel_write(std::uint64_t id) noexcept {
        try {
            boost::asio::post(
                strand_, [self = shared_from_this(), id]() noexcept {
                    self->cancel_write_on_strand(id);
                });
        } catch (...) {
        }
    }

    void cancel_read_on_strand(std::uint64_t id) noexcept {
        for (auto& operation : reads_) {
            if (operation->id != id) {
                continue;
            }
            operation->cancelled = true;
            if (operation->active) {
                operation->signal.emit(
                    boost::asio::cancellation_type::terminal);
            }
            return;
        }
    }

    void cancel_write_on_strand(std::uint64_t id) noexcept {
        for (auto& operation : writes_) {
            if (operation->id != id) {
                continue;
            }
            operation->cancelled = true;
            if (operation->active) {
                operation->signal.emit(
                    boost::asio::cancellation_type::terminal);
            }
            return;
        }
    }

    void complete_socket_read(std::uint64_t id,
                              const boost::system::error_code& error,
                              std::size_t transferred) noexcept {
        if (reads_.empty() || reads_.front()->id != id) {
            return;
        }
        PendingRead& operation = *reads_.front();
        if (operation.cancelled ||
            error == boost::asio::error::operation_aborted) {
            settle_front_read(operation.cancelled ? cancelled_status()
                                                  : closed_status());
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
        if (writes_.empty() || writes_.front()->id != id) {
            return;
        }
        const PendingWrite& operation = *writes_.front();
        if (operation.cancelled ||
            error == boost::asio::error::operation_aborted) {
            settle_front_write(operation.cancelled ? cancelled_status()
                                                   : closed_status(),
                               transferred);
            start_next_write();
            return;
        }
        if (error) {
            settle_front_write(closed_status(), transferred);
            start_next_write();
            return;
        }
        if (transferred != operation.buffer.size()) {
            settle_front_write(safe_status(
                StatusCode::Internal,
                "TCP write completed only partially"), transferred);
            start_next_write();
            return;
        }
        settle_front_write(Status::success(), transferred);
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

    void shutdown_write_on_strand() noexcept {
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
        socket_.shutdown(Tcp::socket::shutdown_send, ignored);
        write_shutdown_ = true;
        shutdown_after_writes_ = false;
    }

    void cancel_on_strand() noexcept {
        if (closed_) {
            return;
        }
        for (auto& operation : reads_) {
            operation->cancelled = true;
        }
        for (auto& operation : writes_) {
            operation->cancelled = true;
        }
        if (!reads_.empty() && reads_.front()->active) {
            reads_.front()->signal.emit(
                boost::asio::cancellation_type::terminal);
        } else {
            start_next_read();
        }
        if (!writes_.empty() && writes_.front()->active) {
            writes_.front()->signal.emit(
                boost::asio::cancellation_type::terminal);
        } else {
            start_next_write();
        }
    }

    void close_on_strand() noexcept {
        if (closed_) {
            return;
        }
        closed_ = true;
        boost::system::error_code ignored;
        socket_.shutdown(Tcp::socket::shutdown_both, ignored);
        socket_.close(ignored);
        while (!reads_.empty()) {
            settle_front_read(closed_status());
        }
        while (!writes_.empty()) {
            settle_front_write(closed_status(), 0U);
        }
        unregister_once();
    }

    void unregister_once() noexcept {
        if (registered_) {
            registered_ = false;
            provider_->release(target_id_);
        }
    }

    Strand strand_;
    Tcp::socket socket_;
    std::shared_ptr<ProviderState> provider_;
    std::uint64_t target_id_{0U};
    std::deque<std::unique_ptr<PendingRead>> reads_;
    std::deque<std::unique_ptr<PendingWrite>> writes_;
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
          strand_(boost::asio::make_strand(provider_->executor())),
          resolver_(strand_),
          socket_(strand_),
          resolve_timer_(strand_),
          connect_timer_(strand_) {}

    ~CreateOperation() noexcept override {
        boost::system::error_code ignored;
        resolver_.cancel();
        socket_.close(ignored);
        resolve_timer_.cancel(ignored);
        connect_timer_.cancel(ignored);
        if (!promoted_) {
            provider_->release(target_id_);
        }
    }

    std::uint64_t reserved_epoch() const noexcept { return reserved_epoch_; }

    void start(CancellationToken cancellation) noexcept {
        try {
            boost::asio::post(
                strand_, [self = shared_from_this(),
                          cancellation = std::move(cancellation)]() mutable
                             noexcept {
                    self->start_on_strand(std::move(cancellation));
                });
        } catch (const std::bad_alloc&) {
            post_finish(Result<std::unique_ptr<ByteChannel>>(
                allocation_status("TCP create scheduling allocation failed")));
        } catch (...) {
            post_finish(Result<std::unique_ptr<ByteChannel>>(safe_status(
                StatusCode::Internal, "TCP create scheduling failed")));
        }
    }

    void request_cancel() noexcept override {
        cancellation_requested_.store(true, std::memory_order_release);
        try {
            boost::asio::post(strand_, [self = shared_from_this()]() noexcept {
                self->cancel_on_strand();
            });
        } catch (...) {
        }
    }

private:
    void post_finish(Result<std::unique_ptr<ByteChannel>> result) noexcept {
        std::shared_ptr<Result<std::unique_ptr<ByteChannel>>> result_holder;
        try {
            result_holder =
                std::make_shared<Result<std::unique_ptr<ByteChannel>>>(
                    std::move(result));
            boost::asio::post(
                strand_, [self = shared_from_this(),
                          result_holder]() mutable noexcept {
                    self->finish(std::move(*result_holder));
                });
        } catch (...) {
            finish(result_holder ? std::move(*result_holder)
                                 : std::move(result));
        }
    }

    void start_on_strand(CancellationToken cancellation) noexcept {
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
                finish(Result<std::unique_ptr<ByteChannel>>(
                    registration.status()));
                return;
            }
            cancellation_ = std::move(registration).take_value();
            if (cancellation_requested_.load(std::memory_order_acquire)) {
                finish(Result<std::unique_ptr<ByteChannel>>(
                    cancelled_status()));
                return;
            }
            resolve_timer_.expires_after(provider_->limits().resolve_timeout);
            resolve_timer_.async_wait(boost::asio::bind_executor(
                strand_, [self = shared_from_this()](
                             const boost::system::error_code& error) noexcept {
                    self->complete_resolve_timeout(error);
                }));
            resolver_.async_resolve(
                provider_->host(), std::to_string(provider_->port()),
                Tcp::resolver::numeric_service,
                boost::asio::bind_executor(
                    strand_, [self = shared_from_this()](
                                 const boost::system::error_code& error,
                                 Tcp::resolver::results_type results) noexcept {
                        self->complete_resolve(error, std::move(results));
                    }));
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
        resolver_.cancel();
        finish(Result<std::unique_ptr<ByteChannel>>(safe_status(
            StatusCode::NotFound, "TCP endpoint resolution timed out")));
    }

    void complete_connect_timeout(
        const boost::system::error_code& error) noexcept {
        if (error || finished_) {
            return;
        }
        boost::system::error_code ignored;
        socket_.cancel(ignored);
        socket_.close(ignored);
        finish(Result<std::unique_ptr<ByteChannel>>(safe_status(
            StatusCode::Closed, "TCP endpoint connection timed out")));
    }

    void complete_resolve(const boost::system::error_code& error,
                          Tcp::resolver::results_type results) noexcept {
        try {
            if (finished_) {
                return;
            }
            boost::system::error_code ignored;
            resolve_timer_.cancel(ignored);
            if (error) {
                finish(Result<std::unique_ptr<ByteChannel>>(
                    cancellation_requested_.load(std::memory_order_acquire)
                        ? cancelled_status()
                        : safe_status(StatusCode::NotFound,
                                      "TCP endpoint resolution failed")));
                return;
            }
            for (const auto& result : results) {
                if (endpoints_.size() >=
                    provider_->limits().max_resolved_endpoints) {
                    break;
                }
                endpoints_.push_back(result.endpoint());
            }
            if (endpoints_.empty()) {
                finish(Result<std::unique_ptr<ByteChannel>>(safe_status(
                    StatusCode::NotFound,
                    "TCP endpoint resolution returned no endpoints")));
                return;
            }
            connect_timer_.expires_after(provider_->limits().connect_timeout);
            connect_timer_.async_wait(boost::asio::bind_executor(
                strand_, [self = shared_from_this()](
                             const boost::system::error_code& timer_error) noexcept {
                    self->complete_connect_timeout(timer_error);
                }));
            connect_next();
        } catch (const std::bad_alloc&) {
            finish(Result<std::unique_ptr<ByteChannel>>(allocation_status(
                "TCP resolved-endpoint allocation failed")));
        } catch (...) {
            finish(Result<std::unique_ptr<ByteChannel>>(safe_status(
                StatusCode::Internal,
                "TCP resolution completion failed")));
        }
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
                    endpoint, boost::asio::bind_executor(
                        strand_, [self = shared_from_this()](
                                     const boost::system::error_code& error) noexcept {
                            self->complete_connect(error);
                        }));
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
        if (error) {
            connect_next();
            return;
        }
        try {
            boost::system::error_code ignored;
            connect_timer_.cancel(ignored);
            socket_.set_option(Tcp::no_delay(true), ignored);
            auto state = std::make_shared<TcpChannelState>(
                std::move(socket_), strand_, provider_, target_id_);
            if (!provider_->promote(target_id_, state)) {
                state->request_close();
                finish(Result<std::unique_ptr<ByteChannel>>(safe_status(
                    StatusCode::ResourceExhausted,
                    "TCP active-channel capacity exhausted")));
                return;
            }
            promoted_ = true;
            std::unique_ptr<ByteChannel> channel =
                std::make_unique<AsioTcpByteChannel>(std::move(state));
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

    void cancel_on_strand() noexcept {
        if (finished_) {
            return;
        }
        resolver_.cancel();
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
        boost::system::error_code ignored;
        resolver_.cancel();
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
    Strand strand_;
    Tcp::resolver resolver_;
    Tcp::socket socket_;
    boost::asio::steady_timer resolve_timer_;
    boost::asio::steady_timer connect_timer_;
    std::vector<Tcp::endpoint> endpoints_;
    std::size_t endpoint_index_{0U};
    std::size_t connect_attempts_{0U};
    CancellationRegistration cancellation_;
    std::atomic<bool> cancellation_requested_{false};
    bool finished_{false};
    bool promoted_{false};
};

void post_create_failure(const std::shared_ptr<ProviderState>& state,
                         ByteChannelProvider::Completion completion,
                         Status status) noexcept {
    std::shared_ptr<ByteChannelProvider::Completion> completion_holder;
    std::shared_ptr<Status> status_holder;
    try {
        completion_holder =
            std::make_shared<ByteChannelProvider::Completion>(
                std::move(completion));
        status_holder = std::make_shared<Status>(std::move(status));
        boost::asio::post(
            state->executor(),
            [completion_holder, status_holder]() mutable noexcept {
                Result<std::unique_ptr<ByteChannel>> result(
                    std::move(*status_holder));
                invoke_noexcept(*completion_holder, std::move(result));
            });
    } catch (...) {
        Result<std::unique_ptr<ByteChannel>> result(
            status_holder ? std::move(*status_holder) : std::move(status));
        auto& selected_completion =
            completion_holder ? *completion_holder : completion;
        invoke_noexcept(selected_completion, std::move(result));
    }
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
    Executor executor,
    ExecutorAffinity executor_affinity,
    std::string remote_host,
    std::uint16_t remote_port,
    AsioTcpByteChannelLimits limits,
    AsioTcpSocketProtector socket_protector) {
    if (!executor || !executor_affinity.valid() || remote_port == 0U ||
        !valid_host(remote_host) || !valid_limits(limits)) {
        return Result<std::shared_ptr<AsioTcpByteChannelProvider>>(Status(
            StatusCode::InvalidArgument,
            "Asio TCP executor, endpoint, affinity, or limits are invalid"));
    }
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
    try {
        auto state = std::make_shared<ProviderState>(
            std::move(executor), executor_affinity,
            std::move(remote_host), remote_port, limits,
            std::move(socket_protector),
            std::move(descriptor).take_value());
        auto impl = std::make_shared<Impl>(std::move(state));
        return Result<std::shared_ptr<AsioTcpByteChannelProvider>>(
            std::shared_ptr<AsioTcpByteChannelProvider>(
                new AsioTcpByteChannelProvider(std::move(impl))));
    } catch (const std::bad_alloc&) {
        return Result<std::shared_ptr<AsioTcpByteChannelProvider>>(
            allocation_status("Asio TCP provider allocation failed"));
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
    if (!completion) {
        return;
    }
    const auto& state = impl_->state();
    if (role != EndpointRole::Client) {
        post_create_failure(
            state, std::move(completion),
            safe_status(StatusCode::InvalidArgument,
                        "asio-tcp is a client-only ByteChannel provider"));
        return;
    }
    auto reservation = state->reserve_create();
    if (!reservation.ok()) {
        post_create_failure(state, std::move(completion),
                            reservation.status());
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
        operation->start(std::move(cancellation));
        if (cancelled_before_bind) {
            operation->request_cancel();
        }
    } catch (const std::bad_alloc&) {
        state->release(target_id);
        post_create_failure(
            state,
            completion_holder ? std::move(*completion_holder)
                              : std::move(completion),
            allocation_status("TCP create-operation allocation failed"));
    } catch (...) {
        state->release(target_id);
        post_create_failure(
            state,
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

}  // namespace yume::providers
