/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/asio_direct_route_provider.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <limits>
#include <mutex>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include <boost/asio/async_result.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/error_code.hpp>

namespace yume::providers {
namespace {

using engine::AuthorizedRouteRequest;
using engine::Buffer;
using engine::ByteChannel;
using engine::CancellationRegistration;
using engine::CancellationToken;
using engine::Capability;
using engine::CapabilitySet;
using engine::ExecutorAffinity;
using engine::NetworkProtocol;
using engine::PacketChannel;
using engine::ProviderDescriptor;
using engine::ProviderKind;
using engine::Result;
using engine::RouteAddressKind;
using engine::RouteConnection;
using engine::RouteDestination;
using engine::Status;
using engine::StatusCode;

using Tcp = boost::asio::ip::tcp;
using Udp = boost::asio::ip::udp;
using Executor = boost::asio::any_io_executor;
using Strand = boost::asio::strand<Executor>;

constexpr std::size_t kMaximumPendingOpens = 1U << 20U;
constexpr std::size_t kMaximumActiveConnections = 1U << 20U;
constexpr std::size_t kMaximumResolvedEndpoints = 256U;
constexpr std::size_t kMaximumUdpPayloadBytes = 65'507U;
constexpr auto kMaximumOpenPhaseTimeout = std::chrono::minutes(10);

Status safe_status(StatusCode code, std::string_view message) noexcept {
    try {
        return Status(code, message);
    } catch (...) {
        return Status(code);
    }
}

Status cancelled_status() noexcept {
    return safe_status(StatusCode::Cancelled,
                       "Asio route operation was cancelled");
}

Status closed_status() noexcept {
    return safe_status(StatusCode::Closed, "Asio route channel is closed");
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
        // Application callbacks are outside the provider's trust boundary.
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

void complete_receive(PacketChannel::ReceiveCompletion completion,
                      Status status) noexcept {
    Result<Buffer> result(std::move(status));
    invoke_noexcept(completion, std::move(result));
}

void complete_receive(PacketChannel::ReceiveCompletion completion,
                      Buffer buffer) noexcept {
    Result<Buffer> result(std::move(buffer));
    invoke_noexcept(completion, std::move(result));
}

bool valid_limits(const AsioDirectRouteLimits& limits) noexcept {
    return limits.max_pending_opens > 0U &&
           limits.max_pending_opens <= kMaximumPendingOpens &&
           limits.max_active_connections > 0U &&
           limits.max_active_connections <= kMaximumActiveConnections &&
           limits.max_resolved_endpoints > 0U &&
           limits.max_resolved_endpoints <= kMaximumResolvedEndpoints &&
           limits.max_tcp_read_bytes > 0U &&
           limits.max_tcp_read_bytes <= engine::kAbsoluteMaxBufferBytes &&
           limits.max_tcp_write_bytes > 0U &&
           limits.max_tcp_write_bytes <= engine::kAbsoluteMaxBufferBytes &&
           limits.max_udp_packet_bytes > 0U &&
           limits.max_udp_packet_bytes <= kMaximumUdpPayloadBytes &&
           limits.resolve_timeout > std::chrono::milliseconds::zero() &&
           limits.resolve_timeout <= kMaximumOpenPhaseTimeout &&
           limits.connect_timeout > std::chrono::milliseconds::zero() &&
           limits.connect_timeout <= kMaximumOpenPhaseTimeout;
}

bool valid_destination(const RouteDestination& destination) noexcept {
    if (destination.port() == 0U) {
        return false;
    }
    switch (destination.protocol()) {
    case NetworkProtocol::Tcp:
    case NetworkProtocol::Udp:
        break;
    default:
        return false;
    }
    switch (destination.address_kind()) {
    case RouteAddressKind::Ipv4:
        return destination.address_bytes().size() == 4U &&
               destination.dns_name().empty();
    case RouteAddressKind::Ipv6:
        return destination.address_bytes().size() == 16U &&
               destination.dns_name().empty();
    case RouteAddressKind::DnsName:
        return destination.address_bytes().empty() &&
               !destination.dns_name().empty() &&
               destination.dns_name().size() <=
                   engine::kMaxRouteDnsNameBytes;
    }
    return false;
}

template <typename NativeHandle>
std::uintptr_t socket_handle_value(NativeHandle handle) noexcept {
    if constexpr (std::is_pointer_v<NativeHandle>) {
        return reinterpret_cast<std::uintptr_t>(handle);
    } else {
        return static_cast<std::uintptr_t>(handle);
    }
}

template <typename Socket>
Status protect_socket(Socket& socket,
                      NetworkProtocol protocol,
                      const SocketProtector& protector) noexcept {
    if (!protector) {
        return Status::success();
    }
    try {
        return protector(NativeSocket{
            protocol, socket_handle_value(socket.native_handle())});
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
    PendingOpen,
    ActiveConnection,
};

struct TargetEntry final {
    TargetKind kind{TargetKind::PendingOpen};
    std::weak_ptr<CancelTarget> target;
    std::uint64_t cancellation_epoch{0U};
};

class ProviderState final : public std::enable_shared_from_this<ProviderState> {
public:
    ProviderState(Executor executor,
                  ExecutorAffinity affinity,
                  AsioDirectRouteLimits limits,
                  SocketProtector protector,
                  ProviderDescriptor descriptor) noexcept
        : executor_(std::move(executor)),
          affinity_(affinity),
          limits_(limits),
          protector_(std::move(protector)),
          descriptor_(std::move(descriptor)) {}

    Result<std::pair<std::uint64_t, std::uint64_t>> reserve_open() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (pending_opens_ >= limits_.max_pending_opens ||
            active_connections_ + pending_opens_ >=
                limits_.max_active_connections) {
            return Result<std::pair<std::uint64_t, std::uint64_t>>(
                safe_status(StatusCode::ResourceExhausted,
                            "direct-route provider capacity exhausted"));
        }
        if (next_target_id_ == std::numeric_limits<std::uint64_t>::max()) {
            return Result<std::pair<std::uint64_t, std::uint64_t>>(
                safe_status(StatusCode::ResourceExhausted,
                            "direct-route operation identifier exhausted"));
        }
        const std::uint64_t id = next_target_id_++;
        try {
            targets_.emplace(id, TargetEntry{
                TargetKind::PendingOpen, {}, cancellation_epoch_});
        } catch (const std::bad_alloc&) {
            return Result<std::pair<std::uint64_t, std::uint64_t>>(
                allocation_status("direct-route reservation allocation failed"));
        }
        ++pending_opens_;
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
            found->second.kind != TargetKind::PendingOpen ||
            pending_opens_ == 0U ||
            active_connections_ >= limits_.max_active_connections) {
            return false;
        }
        found->second.kind = TargetKind::ActiveConnection;
        found->second.target = target;
        --pending_opens_;
        ++active_connections_;
        return true;
    }

    void release(std::uint64_t id) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto found = targets_.find(id);
        if (found == targets_.end()) {
            return;
        }
        if (found->second.kind == TargetKind::PendingOpen) {
            if (pending_opens_ > 0U) {
                --pending_opens_;
            }
        } else if (active_connections_ > 0U) {
            --active_connections_;
        }
        targets_.erase(found);
    }

    void cancel_all() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        ++cancellation_epoch_;
        for (const auto& [_, entry] : targets_) {
            if (auto target = entry.target.lock()) {
                // Every target implementation only requests work on its own
                // executor and contains submission failures. It cannot call
                // back into ProviderState synchronously, so cancellation can
                // remain allocation-free under this dedicated state lock.
                target->request_cancel();
            }
        }
    }

    const Executor& executor() const noexcept { return executor_; }
    ExecutorAffinity affinity() const noexcept { return affinity_; }
    const AsioDirectRouteLimits& limits() const noexcept { return limits_; }
    const SocketProtector& protector() const noexcept { return protector_; }
    const ProviderDescriptor& descriptor() const noexcept {
        return descriptor_;
    }

private:
    Executor executor_;
    ExecutorAffinity affinity_;
    AsioDirectRouteLimits limits_;
    SocketProtector protector_;
    ProviderDescriptor descriptor_;

    std::mutex mutex_;
    std::unordered_map<std::uint64_t, TargetEntry> targets_;
    std::uint64_t next_target_id_{1U};
    std::uint64_t cancellation_epoch_{0U};
    std::size_t pending_opens_{0U};
    std::size_t active_connections_{0U};
};

Status socket_operation_status(const boost::system::error_code& error,
                               bool closing,
                               bool cancelled,
                               std::string_view operation) noexcept {
    if (!error) {
        return Status::success();
    }
    if (error == boost::asio::error::eof || closing) {
        return closed_status();
    }
    if (error == boost::asio::error::operation_aborted || cancelled) {
        return cancelled_status();
    }
    return safe_status(StatusCode::Closed, operation);
}

}  // namespace

class AsioDirectRouteProvider::Impl final {
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
                    std::shared_ptr<ProviderState> provider,
                    std::uint64_t target_id) noexcept
        : strand_(boost::asio::make_strand(socket.get_executor())),
          socket_(std::move(socket)),
          provider_(std::move(provider)),
          target_id_(target_id) {}

    ~TcpChannelState() noexcept override {
        boost::system::error_code ignored;
        socket_.close(ignored);
        unregister_once();
    }

    ExecutorAffinity affinity() const noexcept {
        return provider_->affinity();
    }

    std::size_t max_read_size() const noexcept {
        return provider_->limits().max_tcp_read_bytes;
    }

    std::size_t max_write_size() const noexcept {
        return provider_->limits().max_tcp_write_bytes;
    }

    void async_read(std::size_t max_bytes,
                    CancellationToken cancellation,
                    ByteChannel::ReadCompletion completion) noexcept {
        if (!completion) {
            return;
        }
        std::shared_ptr<ByteChannel::ReadCompletion> completion_holder;
        try {
            // make_shared allocates before constructing the stored callback;
            // std::function's move is noexcept. If allocation fails, the
            // caller-owned completion below therefore remains callable.
            completion_holder =
                std::make_shared<ByteChannel::ReadCompletion>(
                    std::move(completion));
        } catch (...) {
            post_read_completion(
                std::move(completion),
                allocation_status("TCP read callback allocation failed"));
            return;
        }
        Status immediate = Status::success();
        {
            std::lock_guard<std::mutex> lock(submission_mutex_);
            if (close_requested_) {
                immediate = closed_status();
            } else if (max_bytes == 0U || max_bytes > max_read_size()) {
                immediate = safe_status(
                    StatusCode::InvalidArgument,
                    "TCP read exceeds the provider bound");
            } else {
                try {
                    boost::asio::post(
                        strand_,
                        [self = shared_from_this(), max_bytes,
                         cancellation = std::move(cancellation),
                         completion_holder]() mutable noexcept {
                            self->start_read(
                                max_bytes, std::move(cancellation),
                                std::move(*completion_holder));
                        });
                    return;
                } catch (const std::bad_alloc&) {
                    immediate = allocation_status(
                        "TCP read scheduling allocation failed");
                } catch (...) {
                    immediate = safe_status(
                        StatusCode::Internal, "TCP read scheduling failed");
                }
            }
        }
        post_read_completion(
            std::move(*completion_holder), std::move(immediate));
    }

    void async_write(Buffer buffer,
                     CancellationToken cancellation,
                     ByteChannel::WriteCompletion completion) noexcept {
        if (!completion) {
            return;
        }
        std::shared_ptr<ByteChannel::WriteCompletion> completion_holder;
        try {
            completion_holder =
                std::make_shared<ByteChannel::WriteCompletion>(
                    std::move(completion));
        } catch (...) {
            post_write_completion(
                std::move(completion),
                allocation_status("TCP write callback allocation failed"),
                0U);
            return;
        }
        Status immediate = Status::success();
        {
            std::lock_guard<std::mutex> lock(submission_mutex_);
            if (close_requested_ || write_shutdown_requested_) {
                immediate = closed_status();
            } else if (buffer.size() > max_write_size()) {
                immediate = safe_status(
                    StatusCode::ResourceExhausted,
                    "TCP write exceeds the provider bound");
            } else {
                try {
                    boost::asio::post(
                        strand_,
                        [self = shared_from_this(),
                         buffer = std::move(buffer),
                         cancellation = std::move(cancellation),
                         completion_holder]() mutable noexcept {
                            self->start_write(
                                std::move(buffer), std::move(cancellation),
                                std::move(*completion_holder));
                        });
                    return;
                } catch (const std::bad_alloc&) {
                    immediate = allocation_status(
                        "TCP write scheduling allocation failed");
                } catch (...) {
                    immediate = safe_status(
                        StatusCode::Internal, "TCP write scheduling failed");
                }
            }
        }
        post_write_completion(
            std::move(*completion_holder), std::move(immediate), 0U);
    }

    Status shutdown_write() noexcept {
        std::lock_guard<std::mutex> lock(submission_mutex_);
        if (close_requested_) {
            return closed_status();
        }
        if (write_shutdown_requested_) {
            return Status::success();
        }
        try {
            boost::asio::post(
                strand_, [self = shared_from_this()]() noexcept {
                    self->shutdown_write_on_strand();
                });
            write_shutdown_requested_ = true;
            return Status::success();
        } catch (const std::bad_alloc&) {
            return allocation_status(
                "TCP write-shutdown scheduling allocation failed");
        } catch (...) {
            return safe_status(StatusCode::Internal,
                               "TCP write-shutdown scheduling failed");
        }
    }

    void request_cancel() noexcept override {
        try {
            boost::asio::post(
                strand_, [self = shared_from_this()]() noexcept {
                    self->cancel_on_strand();
                });
        } catch (...) {
            // Cancellation is best-effort only when the executor itself can no
            // longer accept work; no exception may escape cleanup.
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
            boost::asio::post(
                strand_, [self = shared_from_this()]() noexcept {
                    self->close_on_strand();
                });
        } catch (...) {
            // The state still owns the socket. Its noexcept destructor closes
            // it if the executor has already stopped accepting work.
        }
    }

private:
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
                                    std::move(*status_holder),
                                    transferred);
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

    struct PendingRead final {
        PendingRead(std::uint64_t operation_id,
                    Buffer owned_buffer,
                    ByteChannel::ReadCompletion owned_completion) noexcept
            : id(operation_id),
              buffer(std::move(owned_buffer)),
              completion(std::move(owned_completion)) {}

        std::uint64_t id;
        Buffer buffer;
        ByteChannel::ReadCompletion completion;
        CancellationRegistration cancellation;
        bool cancelled{false};
    };

    struct PendingWrite final {
        PendingWrite(std::uint64_t operation_id,
                     Buffer owned_buffer,
                     ByteChannel::WriteCompletion owned_completion) noexcept
            : id(operation_id),
              buffer(std::move(owned_buffer)),
              completion(std::move(owned_completion)) {}

        std::uint64_t id;
        Buffer buffer;
        ByteChannel::WriteCompletion completion;
        CancellationRegistration cancellation;
        bool cancelled{false};
    };

    void start_read(std::size_t max_bytes,
                    CancellationToken cancellation,
                    ByteChannel::ReadCompletion completion) noexcept {
        try {
            if (closed_ || read_eof_) {
                complete_read(std::move(completion), closed_status());
                return;
            }
            if (pending_read_) {
                complete_read(
                    std::move(completion),
                    safe_status(StatusCode::FailedPrecondition,
                                "only one TCP read may be outstanding"));
                return;
            }
            if (cancellation.is_cancelled()) {
                complete_read(std::move(completion), cancelled_status());
                return;
            }
            auto allocated = Buffer::allocate(max_bytes, max_read_size());
            if (!allocated.ok()) {
                complete_read(std::move(completion), allocated.status());
                return;
            }
            const std::uint64_t id = next_operation_id_++;
            pending_read_.emplace(
                id, std::move(allocated).take_value(),
                std::move(completion));
            auto registration = cancellation.register_callback(
                [weak = weak_from_this(), id]() noexcept {
                    if (auto self = weak.lock()) {
                        self->cancel_read(id);
                    }
                });
            if (!registration.ok()) {
                settle_read(registration.status());
                return;
            }
            pending_read_->cancellation =
                std::move(registration).take_value();
            const auto read_bytes = pending_read_->buffer.mutable_bytes();
            socket_.async_read_some(
                boost::asio::buffer(read_bytes.data(), read_bytes.size()),
                boost::asio::bind_executor(
                    strand_, [self = shared_from_this(), id](
                                 const boost::system::error_code& error,
                                 std::size_t transferred) noexcept {
                        self->complete_socket_read(id, error, transferred);
                    }));
        } catch (const std::bad_alloc&) {
            if (pending_read_) {
                settle_read(allocation_status(
                    "TCP read-operation allocation failed"));
            } else {
                complete_read(std::move(completion), allocation_status(
                    "TCP read-operation allocation failed"));
            }
        } catch (...) {
            if (pending_read_) {
                settle_read(safe_status(StatusCode::Internal,
                                        "TCP read setup failed"));
            } else {
                complete_read(std::move(completion), safe_status(
                    StatusCode::Internal, "TCP read setup failed"));
            }
        }
    }

    void start_write(Buffer buffer,
                     CancellationToken cancellation,
                     ByteChannel::WriteCompletion completion) noexcept {
        try {
            if (closed_ || write_shutdown_) {
                invoke_noexcept(completion, closed_status(), 0U);
                return;
            }
            if (pending_write_) {
                invoke_noexcept(
                    completion,
                    safe_status(StatusCode::FailedPrecondition,
                                "only one TCP write may be outstanding"),
                    0U);
                return;
            }
            if (cancellation.is_cancelled()) {
                invoke_noexcept(completion, cancelled_status(), 0U);
                return;
            }
            const std::uint64_t id = next_operation_id_++;
            pending_write_.emplace(
                id, std::move(buffer), std::move(completion));
            auto registration = cancellation.register_callback(
                [weak = weak_from_this(), id]() noexcept {
                    if (auto self = weak.lock()) {
                        self->cancel_write(id);
                    }
                });
            if (!registration.ok()) {
                settle_write(registration.status(), 0U);
                return;
            }
            pending_write_->cancellation =
                std::move(registration).take_value();
            const auto write_bytes = pending_write_->buffer.bytes();
            boost::asio::async_write(
                socket_, boost::asio::buffer(
                             write_bytes.data(), write_bytes.size()),
                boost::asio::bind_executor(
                    strand_, [self = shared_from_this(), id](
                                 const boost::system::error_code& error,
                                 std::size_t transferred) noexcept {
                        self->complete_socket_write(id, error, transferred);
                    }));
        } catch (const std::bad_alloc&) {
            if (pending_write_) {
                settle_write(allocation_status(
                                 "TCP write-operation allocation failed"),
                             0U);
            } else {
                invoke_noexcept(completion, allocation_status(
                    "TCP write-operation allocation failed"), 0U);
            }
        } catch (...) {
            if (pending_write_) {
                settle_write(safe_status(StatusCode::Internal,
                                         "TCP write setup failed"),
                             0U);
            } else {
                invoke_noexcept(completion, safe_status(
                    StatusCode::Internal, "TCP write setup failed"), 0U);
            }
        }
    }

    void cancel_read(std::uint64_t id) noexcept {
        try {
            boost::asio::post(
                strand_, [self = shared_from_this(), id]() noexcept {
                    if (!self->pending_read_ ||
                        self->pending_read_->id != id) {
                        return;
                    }
                    self->pending_read_->cancelled = true;
                    if (self->pending_write_) {
                        self->pending_write_->cancelled = true;
                    }
                    boost::system::error_code ignored;
                    self->socket_.cancel(ignored);
                });
        } catch (...) {
        }
    }

    void cancel_write(std::uint64_t id) noexcept {
        try {
            boost::asio::post(
                strand_, [self = shared_from_this(), id]() noexcept {
                    if (!self->pending_write_ ||
                        self->pending_write_->id != id) {
                        return;
                    }
                    self->pending_write_->cancelled = true;
                    if (self->pending_read_) {
                        self->pending_read_->cancelled = true;
                    }
                    boost::system::error_code ignored;
                    self->socket_.cancel(ignored);
                });
        } catch (...) {
        }
    }

    void complete_socket_read(std::uint64_t id,
                              const boost::system::error_code& error,
                              std::size_t transferred) noexcept {
        try {
            if (!pending_read_ || pending_read_->id != id) {
                return;
            }
            if (error) {
                if (error == boost::asio::error::eof) {
                    read_eof_ = true;
                }
                settle_read(socket_operation_status(
                    error, closed_, pending_read_->cancelled,
                    "TCP read failed"));
                return;
            }
            if (transferred > pending_read_->buffer.size()) {
                settle_read(safe_status(
                    StatusCode::Internal,
                    "TCP read completion exceeded its buffer"));
                return;
            }
            const Status resized = pending_read_->buffer.resize(transferred);
            if (!resized.ok()) {
                settle_read(resized);
                return;
            }
            ByteChannel::ReadCompletion completion =
                std::move(pending_read_->completion);
            Buffer buffer = std::move(pending_read_->buffer);
            pending_read_.reset();
            complete_read(std::move(completion), std::move(buffer));
        } catch (...) {
            settle_read(safe_status(StatusCode::Internal,
                                    "TCP read completion failed"));
        }
    }

    void complete_socket_write(std::uint64_t id,
                               const boost::system::error_code& error,
                               std::size_t transferred) noexcept {
        if (!pending_write_ || pending_write_->id != id) {
            return;
        }
        const bool cancelled = pending_write_->cancelled;
        const std::size_t expected = pending_write_->buffer.size();
        if (error) {
            settle_write(socket_operation_status(
                             error, closed_, cancelled, "TCP write failed"),
                         transferred);
        } else if (transferred != expected) {
            settle_write(safe_status(
                             StatusCode::Internal,
                             "TCP write completed only partially"),
                         transferred);
        } else {
            settle_write(Status::success(), transferred);
        }
        if (shutdown_after_write_ && !pending_write_) {
            shutdown_socket_write();
        }
    }

    void settle_read(Status status) noexcept {
        if (!pending_read_) {
            return;
        }
        ByteChannel::ReadCompletion completion =
            std::move(pending_read_->completion);
        pending_read_.reset();
        complete_read(std::move(completion), std::move(status));
    }

    void settle_write(Status status, std::size_t transferred) noexcept {
        if (!pending_write_) {
            return;
        }
        ByteChannel::WriteCompletion completion =
            std::move(pending_write_->completion);
        pending_write_.reset();
        invoke_noexcept(completion, std::move(status), transferred);
    }

    void shutdown_write_on_strand() noexcept {
        if (closed_ || write_shutdown_) {
            return;
        }
        if (pending_write_) {
            shutdown_after_write_ = true;
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
        shutdown_after_write_ = false;
    }

    void cancel_on_strand() noexcept {
        if (closed_) {
            return;
        }
        if (pending_read_) {
            pending_read_->cancelled = true;
        }
        if (pending_write_) {
            pending_write_->cancelled = true;
        }
        boost::system::error_code ignored;
        socket_.cancel(ignored);
    }

    void close_on_strand() noexcept {
        if (closed_) {
            return;
        }
        closed_ = true;
        boost::system::error_code ignored;
        socket_.shutdown(Tcp::socket::shutdown_both, ignored);
        socket_.close(ignored);
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
    std::uint64_t next_operation_id_{1U};
    std::optional<PendingRead> pending_read_;
    std::optional<PendingWrite> pending_write_;
    bool read_eof_{false};
    bool write_shutdown_{false};
    bool shutdown_after_write_{false};
    bool closed_{false};
    bool registered_{true};

    std::mutex submission_mutex_;
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

class UdpChannelState final : public CancelTarget,
                              public std::enable_shared_from_this<UdpChannelState> {
public:
    UdpChannelState(Udp::socket socket,
                    std::shared_ptr<ProviderState> provider,
                    std::uint64_t target_id) noexcept
        : strand_(boost::asio::make_strand(socket.get_executor())),
          socket_(std::move(socket)),
          provider_(std::move(provider)),
          target_id_(target_id) {}

    ~UdpChannelState() noexcept override {
        boost::system::error_code ignored;
        socket_.close(ignored);
        unregister_once();
    }

    ExecutorAffinity affinity() const noexcept {
        return provider_->affinity();
    }

    std::size_t max_packet_size() const noexcept {
        return provider_->limits().max_udp_packet_bytes;
    }

    std::size_t receive_capacity() const noexcept {
        // One sentinel byte makes truncation observable on platforms where a
        // datagram larger than the supplied buffer otherwise completes
        // successfully with exactly the buffer size.
        return max_packet_size() + 1U;
    }

    void async_receive(CancellationToken cancellation,
                       PacketChannel::ReceiveCompletion completion) noexcept {
        if (!completion) {
            return;
        }
        std::shared_ptr<PacketChannel::ReceiveCompletion> completion_holder;
        try {
            completion_holder =
                std::make_shared<PacketChannel::ReceiveCompletion>(
                    std::move(completion));
        } catch (...) {
            post_receive_completion(
                std::move(completion),
                allocation_status("UDP receive callback allocation failed"));
            return;
        }
        Status immediate = Status::success();
        {
            std::lock_guard<std::mutex> lock(submission_mutex_);
            if (close_requested_) {
                immediate = closed_status();
            } else {
                try {
                    boost::asio::post(
                        strand_,
                        [self = shared_from_this(),
                         cancellation = std::move(cancellation),
                         completion_holder]() mutable noexcept {
                            self->start_receive(
                                std::move(cancellation),
                                std::move(*completion_holder));
                        });
                    return;
                } catch (const std::bad_alloc&) {
                    immediate = allocation_status(
                        "UDP receive scheduling allocation failed");
                } catch (...) {
                    immediate = safe_status(
                        StatusCode::Internal,
                        "UDP receive scheduling failed");
                }
            }
        }
        post_receive_completion(
            std::move(*completion_holder), std::move(immediate));
    }

    void async_send(Buffer packet,
                    CancellationToken cancellation,
                    PacketChannel::SendCompletion completion) noexcept {
        if (!completion) {
            return;
        }
        std::shared_ptr<PacketChannel::SendCompletion> completion_holder;
        try {
            completion_holder =
                std::make_shared<PacketChannel::SendCompletion>(
                    std::move(completion));
        } catch (...) {
            post_send_completion(
                std::move(completion),
                allocation_status("UDP send callback allocation failed"),
                0U);
            return;
        }
        Status immediate = Status::success();
        {
            std::lock_guard<std::mutex> lock(submission_mutex_);
            if (close_requested_) {
                immediate = closed_status();
            } else if (packet.size() > max_packet_size()) {
                immediate = safe_status(
                    StatusCode::ResourceExhausted,
                    "UDP packet exceeds the provider bound");
            } else {
                try {
                    boost::asio::post(
                        strand_,
                        [self = shared_from_this(),
                         packet = std::move(packet),
                         cancellation = std::move(cancellation),
                         completion_holder]() mutable noexcept {
                            self->start_send(
                                std::move(packet),
                                std::move(cancellation),
                                std::move(*completion_holder));
                        });
                    return;
                } catch (const std::bad_alloc&) {
                    immediate = allocation_status(
                        "UDP send scheduling allocation failed");
                } catch (...) {
                    immediate = safe_status(
                        StatusCode::Internal, "UDP send scheduling failed");
                }
            }
        }
        post_send_completion(
            std::move(*completion_holder), std::move(immediate), 0U);
    }

    void request_cancel() noexcept override {
        try {
            boost::asio::post(
                strand_, [self = shared_from_this()]() noexcept {
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
            boost::asio::post(
                strand_, [self = shared_from_this()]() noexcept {
                    self->close_on_strand();
                });
        } catch (...) {
        }
    }

private:
    void post_receive_completion(
        PacketChannel::ReceiveCompletion completion,
        Status status) noexcept {
        std::shared_ptr<PacketChannel::ReceiveCompletion> completion_holder;
        std::shared_ptr<Status> status_holder;
        try {
            completion_holder =
                std::make_shared<PacketChannel::ReceiveCompletion>(
                    std::move(completion));
            status_holder = std::make_shared<Status>(std::move(status));
            boost::asio::post(
                strand_, [completion_holder, status_holder]() mutable noexcept {
                    complete_receive(std::move(*completion_holder),
                                     std::move(*status_holder));
                });
        } catch (...) {
            complete_receive(
                completion_holder ? std::move(*completion_holder)
                                  : std::move(completion),
                status_holder ? std::move(*status_holder)
                              : std::move(status));
        }
    }

    void post_send_completion(PacketChannel::SendCompletion completion,
                              Status status,
                              std::size_t transferred) noexcept {
        std::shared_ptr<PacketChannel::SendCompletion> completion_holder;
        std::shared_ptr<Status> status_holder;
        try {
            completion_holder =
                std::make_shared<PacketChannel::SendCompletion>(
                    std::move(completion));
            status_holder = std::make_shared<Status>(std::move(status));
            boost::asio::post(
                strand_, [completion_holder, status_holder,
                          transferred]() mutable noexcept {
                    invoke_noexcept(*completion_holder,
                                    std::move(*status_holder),
                                    transferred);
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

    struct PendingReceive final {
        PendingReceive(std::uint64_t operation_id,
                       Buffer owned_buffer,
                       PacketChannel::ReceiveCompletion owned_completion) noexcept
            : id(operation_id),
              buffer(std::move(owned_buffer)),
              completion(std::move(owned_completion)) {}

        std::uint64_t id;
        Buffer buffer;
        PacketChannel::ReceiveCompletion completion;
        CancellationRegistration cancellation;
        bool cancelled{false};
    };

    struct PendingSend final {
        PendingSend(std::uint64_t operation_id,
                    Buffer owned_buffer,
                    PacketChannel::SendCompletion owned_completion) noexcept
            : id(operation_id),
              buffer(std::move(owned_buffer)),
              completion(std::move(owned_completion)) {}

        std::uint64_t id;
        Buffer buffer;
        PacketChannel::SendCompletion completion;
        CancellationRegistration cancellation;
        bool cancelled{false};
    };

    void start_receive(CancellationToken cancellation,
                       PacketChannel::ReceiveCompletion completion) noexcept {
        try {
            if (closed_) {
                complete_receive(std::move(completion), closed_status());
                return;
            }
            if (pending_receive_) {
                complete_receive(
                    std::move(completion),
                    safe_status(StatusCode::FailedPrecondition,
                                "only one UDP receive may be outstanding"));
                return;
            }
            if (cancellation.is_cancelled()) {
                complete_receive(std::move(completion), cancelled_status());
                return;
            }
            auto allocated = Buffer::allocate(
                receive_capacity(), receive_capacity());
            if (!allocated.ok()) {
                complete_receive(std::move(completion), allocated.status());
                return;
            }
            const std::uint64_t id = next_operation_id_++;
            pending_receive_.emplace(
                id, std::move(allocated).take_value(),
                std::move(completion));
            auto registration = cancellation.register_callback(
                [weak = weak_from_this(), id]() noexcept {
                    if (auto self = weak.lock()) {
                        self->cancel_receive(id);
                    }
                });
            if (!registration.ok()) {
                settle_receive(registration.status());
                return;
            }
            pending_receive_->cancellation =
                std::move(registration).take_value();
            const auto receive_bytes =
                pending_receive_->buffer.mutable_bytes();
            socket_.async_receive(
                boost::asio::buffer(
                    receive_bytes.data(), receive_bytes.size()),
                boost::asio::bind_executor(
                    strand_, [self = shared_from_this(), id](
                                 const boost::system::error_code& error,
                                 std::size_t transferred) noexcept {
                        self->complete_socket_receive(
                            id, error, transferred);
                    }));
        } catch (const std::bad_alloc&) {
            if (pending_receive_) {
                settle_receive(allocation_status(
                    "UDP receive-operation allocation failed"));
            } else {
                complete_receive(std::move(completion), allocation_status(
                    "UDP receive-operation allocation failed"));
            }
        } catch (...) {
            if (pending_receive_) {
                settle_receive(safe_status(
                    StatusCode::Internal, "UDP receive setup failed"));
            } else {
                complete_receive(std::move(completion), safe_status(
                    StatusCode::Internal, "UDP receive setup failed"));
            }
        }
    }

    void start_send(Buffer packet,
                    CancellationToken cancellation,
                    PacketChannel::SendCompletion completion) noexcept {
        try {
            if (closed_) {
                invoke_noexcept(completion, closed_status(), 0U);
                return;
            }
            if (pending_send_) {
                invoke_noexcept(
                    completion,
                    safe_status(StatusCode::FailedPrecondition,
                                "only one UDP send may be outstanding"),
                    0U);
                return;
            }
            if (cancellation.is_cancelled()) {
                invoke_noexcept(completion, cancelled_status(), 0U);
                return;
            }
            const std::uint64_t id = next_operation_id_++;
            pending_send_.emplace(
                id, std::move(packet), std::move(completion));
            auto registration = cancellation.register_callback(
                [weak = weak_from_this(), id]() noexcept {
                    if (auto self = weak.lock()) {
                        self->cancel_send(id);
                    }
                });
            if (!registration.ok()) {
                settle_send(registration.status(), 0U);
                return;
            }
            pending_send_->cancellation =
                std::move(registration).take_value();
            const auto send_bytes = pending_send_->buffer.bytes();
            socket_.async_send(
                boost::asio::buffer(send_bytes.data(), send_bytes.size()),
                boost::asio::bind_executor(
                    strand_, [self = shared_from_this(), id](
                                 const boost::system::error_code& error,
                                 std::size_t transferred) noexcept {
                        self->complete_socket_send(id, error, transferred);
                    }));
        } catch (const std::bad_alloc&) {
            if (pending_send_) {
                settle_send(allocation_status(
                                "UDP send-operation allocation failed"),
                            0U);
            } else {
                invoke_noexcept(completion, allocation_status(
                    "UDP send-operation allocation failed"), 0U);
            }
        } catch (...) {
            if (pending_send_) {
                settle_send(safe_status(StatusCode::Internal,
                                        "UDP send setup failed"),
                            0U);
            } else {
                invoke_noexcept(completion, safe_status(
                    StatusCode::Internal, "UDP send setup failed"), 0U);
            }
        }
    }

    void cancel_receive(std::uint64_t id) noexcept {
        try {
            boost::asio::post(
                strand_, [self = shared_from_this(), id]() noexcept {
                    if (!self->pending_receive_ ||
                        self->pending_receive_->id != id) {
                        return;
                    }
                    self->pending_receive_->cancelled = true;
                    if (self->pending_send_) {
                        self->pending_send_->cancelled = true;
                    }
                    boost::system::error_code ignored;
                    self->socket_.cancel(ignored);
                });
        } catch (...) {
        }
    }

    void cancel_send(std::uint64_t id) noexcept {
        try {
            boost::asio::post(
                strand_, [self = shared_from_this(), id]() noexcept {
                    if (!self->pending_send_ ||
                        self->pending_send_->id != id) {
                        return;
                    }
                    self->pending_send_->cancelled = true;
                    if (self->pending_receive_) {
                        self->pending_receive_->cancelled = true;
                    }
                    boost::system::error_code ignored;
                    self->socket_.cancel(ignored);
                });
        } catch (...) {
        }
    }

    void complete_socket_receive(
        std::uint64_t id,
        const boost::system::error_code& error,
        std::size_t transferred) noexcept {
        try {
            if (!pending_receive_ || pending_receive_->id != id) {
                return;
            }
            if (error) {
                if (error == boost::asio::error::message_size) {
                    settle_receive(safe_status(
                        StatusCode::ResourceExhausted,
                        "UDP datagram exceeds the provider packet bound"));
                } else {
                    settle_receive(socket_operation_status(
                        error, closed_, pending_receive_->cancelled,
                        "UDP receive failed"));
                }
                return;
            }
            if (transferred > pending_receive_->buffer.size()) {
                settle_receive(safe_status(
                    StatusCode::Internal,
                    "UDP receive completion exceeded its buffer"));
                return;
            }
            if (transferred > max_packet_size()) {
                settle_receive(safe_status(
                    StatusCode::ResourceExhausted,
                    "UDP datagram exceeds the provider packet bound"));
                return;
            }
            const Status resized =
                pending_receive_->buffer.resize(transferred);
            if (!resized.ok()) {
                settle_receive(resized);
                return;
            }
            PacketChannel::ReceiveCompletion completion =
                std::move(pending_receive_->completion);
            Buffer packet = std::move(pending_receive_->buffer);
            pending_receive_.reset();
            complete_receive(std::move(completion), std::move(packet));
        } catch (...) {
            settle_receive(safe_status(
                StatusCode::Internal, "UDP receive completion failed"));
        }
    }

    void complete_socket_send(std::uint64_t id,
                              const boost::system::error_code& error,
                              std::size_t transferred) noexcept {
        if (!pending_send_ || pending_send_->id != id) {
            return;
        }
        const bool cancelled = pending_send_->cancelled;
        const std::size_t expected = pending_send_->buffer.size();
        if (error) {
            settle_send(socket_operation_status(
                            error, closed_, cancelled, "UDP send failed"),
                        transferred);
        } else if (transferred != expected) {
            settle_send(safe_status(
                            StatusCode::Internal,
                            "UDP send completed only partially"),
                        transferred);
        } else {
            settle_send(Status::success(), transferred);
        }
    }

    void settle_receive(Status status) noexcept {
        if (!pending_receive_) {
            return;
        }
        PacketChannel::ReceiveCompletion completion =
            std::move(pending_receive_->completion);
        pending_receive_.reset();
        complete_receive(std::move(completion), std::move(status));
    }

    void settle_send(Status status, std::size_t transferred) noexcept {
        if (!pending_send_) {
            return;
        }
        PacketChannel::SendCompletion completion =
            std::move(pending_send_->completion);
        pending_send_.reset();
        invoke_noexcept(completion, std::move(status), transferred);
    }

    void cancel_on_strand() noexcept {
        if (closed_) {
            return;
        }
        if (pending_receive_) {
            pending_receive_->cancelled = true;
        }
        if (pending_send_) {
            pending_send_->cancelled = true;
        }
        boost::system::error_code ignored;
        socket_.cancel(ignored);
    }

    void close_on_strand() noexcept {
        if (closed_) {
            return;
        }
        closed_ = true;
        boost::system::error_code ignored;
        socket_.close(ignored);
        unregister_once();
    }

    void unregister_once() noexcept {
        if (registered_) {
            registered_ = false;
            provider_->release(target_id_);
        }
    }

    Strand strand_;
    Udp::socket socket_;
    std::shared_ptr<ProviderState> provider_;
    std::uint64_t target_id_{0U};
    std::uint64_t next_operation_id_{1U};
    std::optional<PendingReceive> pending_receive_;
    std::optional<PendingSend> pending_send_;
    bool closed_{false};
    bool registered_{true};

    std::mutex submission_mutex_;
    bool close_requested_{false};
};

class AsioUdpPacketChannel final : public PacketChannel {
public:
    explicit AsioUdpPacketChannel(
        std::shared_ptr<UdpChannelState> state) noexcept
        : state_(std::move(state)) {}

    ~AsioUdpPacketChannel() noexcept override { state_->request_close(); }

    ExecutorAffinity executor_affinity() const noexcept override {
        return state_->affinity();
    }
    std::size_t max_packet_size() const noexcept override {
        return state_->max_packet_size();
    }
    void async_receive(CancellationToken cancellation,
                       ReceiveCompletion completion) override {
        state_->async_receive(std::move(cancellation),
                              std::move(completion));
    }
    void async_send(Buffer packet,
                    CancellationToken cancellation,
                    SendCompletion completion) override {
        state_->async_send(std::move(packet), std::move(cancellation),
                           std::move(completion));
    }
    void cancel() noexcept override { state_->request_cancel(); }
    void close() noexcept override { state_->request_close(); }

private:
    std::shared_ptr<UdpChannelState> state_;
};

class OpenCompletion final {
public:
    explicit OpenCompletion(
        engine::RouteProvider::Completion& completion) noexcept
        : completion_(std::move(completion)) {}

    void complete(Result<RouteConnection> result) noexcept {
        if (completed_.test_and_set(std::memory_order_acq_rel)) {
            return;
        }
        engine::RouteProvider::Completion completion =
            std::move(completion_);
        invoke_noexcept(completion, std::move(result));
    }

private:
    std::atomic_flag completed_ = ATOMIC_FLAG_INIT;
    engine::RouteProvider::Completion completion_;
};

void post_open_failure(
    const Executor& executor,
    const std::shared_ptr<OpenCompletion>& completion,
    Status status) noexcept {
    try {
        boost::asio::post(
            executor,
            [completion,
             status = std::move(status)]() mutable noexcept {
                completion->complete(
                    Result<RouteConnection>(std::move(status)));
            });
    } catch (...) {
        completion->complete(Result<RouteConnection>(std::move(status)));
    }
}

class OpenOperation final : public CancelTarget,
                            public std::enable_shared_from_this<OpenOperation> {
public:
    OpenOperation(std::shared_ptr<ProviderState> provider,
                  std::uint64_t target_id,
                  std::uint64_t reserved_epoch,
                  AuthorizedRouteRequest request,
                  std::shared_ptr<OpenCompletion> completion)
        : provider_(std::move(provider)),
          target_id_(target_id),
          reserved_epoch_(reserved_epoch),
          request_(std::move(request)),
          completion_(std::move(completion)),
          strand_(boost::asio::make_strand(provider_->executor())),
          tcp_resolver_(strand_),
          tcp_socket_(strand_),
          udp_resolver_(strand_),
          udp_socket_(strand_),
          resolve_timer_(strand_),
          connect_timer_(strand_) {}

    ~OpenOperation() noexcept override {
        boost::system::error_code ignored;
        tcp_resolver_.cancel();
        udp_resolver_.cancel();
        tcp_socket_.close(ignored);
        udp_socket_.close(ignored);
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
            post_finish(allocation_status(
                "direct-route open scheduling allocation failed"));
        } catch (...) {
            post_finish(safe_status(
                StatusCode::Internal,
                "direct-route open scheduling failed"));
        }
    }

    void request_cancel() noexcept override {
        cancellation_requested_.store(true, std::memory_order_release);
        try {
            boost::asio::post(
                strand_, [self = shared_from_this()]() noexcept {
                    self->cancel_on_strand();
                });
        } catch (...) {
        }
    }

private:
    void post_finish(Status status) noexcept {
        try {
            boost::asio::post(
                strand_, [self = shared_from_this(),
                          status = std::move(status)]() mutable noexcept {
                    self->finish(Result<RouteConnection>(
                        std::move(status)));
                });
        } catch (...) {
            finish(Result<RouteConnection>(std::move(status)));
        }
    }

    void start_on_strand(CancellationToken cancellation) noexcept {
        try {
            if (cancellation.is_cancelled()) {
                finish(Result<RouteConnection>(cancelled_status()));
                return;
            }
            auto registration = cancellation.register_callback(
                [weak = weak_from_this()]() noexcept {
                    if (auto self = weak.lock()) {
                        self->request_cancel();
                    }
                });
            if (!registration.ok()) {
                finish(Result<RouteConnection>(safe_status(
                    registration.status().code(),
                    registration.status().message())));
                return;
            }
            cancellation_ = std::move(registration).take_value();
            if (cancellation_requested_.load(std::memory_order_acquire)) {
                finish(Result<RouteConnection>(cancelled_status()));
                return;
            }
            if (!valid_destination(request_.destination()) ||
                request_.stream_id().is_control() ||
                !engine::valid_service_name(request_.service_name()) ||
                request_.peer_evidence().identity().empty()) {
                finish(Result<RouteConnection>(safe_status(
                    StatusCode::InvalidArgument,
                    "authorized route request is invalid")));
                return;
            }
            switch (request_.destination().protocol()) {
            case NetworkProtocol::Tcp:
                begin_tcp();
                return;
            case NetworkProtocol::Udp:
                begin_udp();
                return;
            }
            finish(Result<RouteConnection>(safe_status(
                StatusCode::InvalidArgument,
                "authorized route protocol is invalid")));
        } catch (const std::bad_alloc&) {
            finish(Result<RouteConnection>(allocation_status(
                "direct-route open allocation failed")));
        } catch (...) {
            finish(Result<RouteConnection>(safe_status(
                StatusCode::Internal, "direct-route open failed")));
        }
    }

    void begin_tcp() {
        if (request_.destination().address_kind() ==
            RouteAddressKind::DnsName) {
            arm_resolve_timeout(NetworkProtocol::Tcp);
            tcp_resolver_.async_resolve(
                std::string(request_.destination().dns_name()),
                std::to_string(request_.destination().port()),
                Tcp::resolver::numeric_service,
                boost::asio::bind_executor(
                    strand_, [self = shared_from_this()](
                                 const boost::system::error_code& error,
                                 Tcp::resolver::results_type results) noexcept {
                        self->complete_tcp_resolve(error, std::move(results));
                    }));
            return;
        }
        tcp_endpoints_.push_back(tcp_literal_endpoint());
        arm_connect_timeout(NetworkProtocol::Tcp);
        connect_next_tcp();
    }

    void begin_udp() {
        if (request_.destination().address_kind() ==
            RouteAddressKind::DnsName) {
            arm_resolve_timeout(NetworkProtocol::Udp);
            udp_resolver_.async_resolve(
                std::string(request_.destination().dns_name()),
                std::to_string(request_.destination().port()),
                Udp::resolver::numeric_service,
                boost::asio::bind_executor(
                    strand_, [self = shared_from_this()](
                                 const boost::system::error_code& error,
                                 Udp::resolver::results_type results) noexcept {
                        self->complete_udp_resolve(error, std::move(results));
                    }));
            return;
        }
        udp_endpoints_.push_back(udp_literal_endpoint());
        arm_connect_timeout(NetworkProtocol::Udp);
        connect_next_udp();
    }

    void arm_resolve_timeout(NetworkProtocol protocol) {
        resolve_timer_.expires_after(provider_->limits().resolve_timeout);
        resolve_timer_.async_wait(boost::asio::bind_executor(
            strand_, [self = shared_from_this(), protocol](
                         const boost::system::error_code& error) noexcept {
                self->complete_resolve_timeout(protocol, error);
            }));
    }

    void arm_connect_timeout(NetworkProtocol protocol) {
        connect_timer_.expires_after(provider_->limits().connect_timeout);
        connect_timer_.async_wait(boost::asio::bind_executor(
            strand_, [self = shared_from_this(), protocol](
                         const boost::system::error_code& error) noexcept {
                self->complete_connect_timeout(protocol, error);
            }));
    }

    void complete_resolve_timeout(
        NetworkProtocol protocol,
        const boost::system::error_code& error) noexcept {
        if (error || finished_) {
            return;
        }
        if (protocol == NetworkProtocol::Tcp) {
            tcp_resolver_.cancel();
        } else {
            udp_resolver_.cancel();
        }
        finish(Result<RouteConnection>(safe_status(
            StatusCode::NotFound,
            "direct-route destination resolution timed out")));
    }

    void complete_connect_timeout(
        NetworkProtocol protocol,
        const boost::system::error_code& error) noexcept {
        if (error || finished_) {
            return;
        }
        boost::system::error_code ignored;
        if (protocol == NetworkProtocol::Tcp) {
            tcp_socket_.cancel(ignored);
            tcp_socket_.close(ignored);
        } else {
            udp_socket_.cancel(ignored);
            udp_socket_.close(ignored);
        }
        finish(Result<RouteConnection>(safe_status(
            StatusCode::Closed,
            "direct-route destination connection timed out")));
    }

    Tcp::endpoint tcp_literal_endpoint() const {
        const auto bytes = request_.destination().address_bytes();
        if (request_.destination().address_kind() == RouteAddressKind::Ipv4) {
            boost::asio::ip::address_v4::bytes_type address{};
            std::copy(bytes.begin(), bytes.end(), address.begin());
            return Tcp::endpoint(
                boost::asio::ip::address_v4(address),
                request_.destination().port());
        }
        boost::asio::ip::address_v6::bytes_type address{};
        std::copy(bytes.begin(), bytes.end(), address.begin());
        return Tcp::endpoint(
            boost::asio::ip::address_v6(address),
            request_.destination().port());
    }

    Udp::endpoint udp_literal_endpoint() const {
        const auto bytes = request_.destination().address_bytes();
        if (request_.destination().address_kind() == RouteAddressKind::Ipv4) {
            boost::asio::ip::address_v4::bytes_type address{};
            std::copy(bytes.begin(), bytes.end(), address.begin());
            return Udp::endpoint(
                boost::asio::ip::address_v4(address),
                request_.destination().port());
        }
        boost::asio::ip::address_v6::bytes_type address{};
        std::copy(bytes.begin(), bytes.end(), address.begin());
        return Udp::endpoint(
            boost::asio::ip::address_v6(address),
            request_.destination().port());
    }

    void complete_tcp_resolve(
        const boost::system::error_code& error,
        Tcp::resolver::results_type results) noexcept {
        try {
            if (finished_) {
                return;
            }
            boost::system::error_code ignored;
            resolve_timer_.cancel(ignored);
            if (error) {
                finish(Result<RouteConnection>(
                    cancellation_requested_.load(std::memory_order_acquire)
                        ? cancelled_status()
                        : safe_status(StatusCode::NotFound,
                                      "TCP destination resolution failed")));
                return;
            }
            for (const auto& result : results) {
                if (tcp_endpoints_.size() >=
                    provider_->limits().max_resolved_endpoints) {
                    break;
                }
                tcp_endpoints_.push_back(result.endpoint());
            }
            if (tcp_endpoints_.empty()) {
                finish(Result<RouteConnection>(safe_status(
                    StatusCode::NotFound,
                    "TCP destination resolution returned no endpoints")));
                return;
            }
            arm_connect_timeout(NetworkProtocol::Tcp);
            connect_next_tcp();
        } catch (const std::bad_alloc&) {
            finish(Result<RouteConnection>(allocation_status(
                "TCP resolved-endpoint allocation failed")));
        } catch (...) {
            finish(Result<RouteConnection>(safe_status(
                StatusCode::Internal,
                "TCP resolution completion failed")));
        }
    }

    void complete_udp_resolve(
        const boost::system::error_code& error,
        Udp::resolver::results_type results) noexcept {
        try {
            if (finished_) {
                return;
            }
            boost::system::error_code ignored;
            resolve_timer_.cancel(ignored);
            if (error) {
                finish(Result<RouteConnection>(
                    cancellation_requested_.load(std::memory_order_acquire)
                        ? cancelled_status()
                        : safe_status(StatusCode::NotFound,
                                      "UDP destination resolution failed")));
                return;
            }
            for (const auto& result : results) {
                if (udp_endpoints_.size() >=
                    provider_->limits().max_resolved_endpoints) {
                    break;
                }
                udp_endpoints_.push_back(result.endpoint());
            }
            if (udp_endpoints_.empty()) {
                finish(Result<RouteConnection>(safe_status(
                    StatusCode::NotFound,
                    "UDP destination resolution returned no endpoints")));
                return;
            }
            arm_connect_timeout(NetworkProtocol::Udp);
            connect_next_udp();
        } catch (const std::bad_alloc&) {
            finish(Result<RouteConnection>(allocation_status(
                "UDP resolved-endpoint allocation failed")));
        } catch (...) {
            finish(Result<RouteConnection>(safe_status(
                StatusCode::Internal,
                "UDP resolution completion failed")));
        }
    }

    void connect_next_tcp() noexcept {
        try {
            if (finished_) {
                return;
            }
            if (cancellation_requested_.load(std::memory_order_acquire)) {
                finish(Result<RouteConnection>(cancelled_status()));
                return;
            }
            boost::system::error_code ignored;
            tcp_socket_.close(ignored);
            while (tcp_endpoint_index_ < tcp_endpoints_.size()) {
                const Tcp::endpoint endpoint =
                    tcp_endpoints_[tcp_endpoint_index_++];
                boost::system::error_code error;
                tcp_socket_.open(endpoint.protocol(), error);
                if (error) {
                    continue;
                }
                Status protection = protect_socket(
                    tcp_socket_, NetworkProtocol::Tcp,
                    provider_->protector());
                if (!protection.ok()) {
                    finish(Result<RouteConnection>(std::move(protection)));
                    return;
                }
                tcp_socket_.async_connect(
                    endpoint,
                    boost::asio::bind_executor(
                        strand_, [self = shared_from_this()](
                                     const boost::system::error_code& error) noexcept {
                            self->complete_tcp_connect(error);
                        }));
                return;
            }
            finish(Result<RouteConnection>(safe_status(
                StatusCode::NotFound,
                "TCP destination connection failed")));
        } catch (const std::bad_alloc&) {
            finish(Result<RouteConnection>(allocation_status(
                "TCP connection allocation failed")));
        } catch (...) {
            finish(Result<RouteConnection>(safe_status(
                StatusCode::Internal, "TCP connection setup failed")));
        }
    }

    void connect_next_udp() noexcept {
        try {
            if (finished_) {
                return;
            }
            if (cancellation_requested_.load(std::memory_order_acquire)) {
                finish(Result<RouteConnection>(cancelled_status()));
                return;
            }
            boost::system::error_code ignored;
            udp_socket_.close(ignored);
            while (udp_endpoint_index_ < udp_endpoints_.size()) {
                const Udp::endpoint endpoint =
                    udp_endpoints_[udp_endpoint_index_++];
                boost::system::error_code error;
                udp_socket_.open(endpoint.protocol(), error);
                if (error) {
                    continue;
                }
                Status protection = protect_socket(
                    udp_socket_, NetworkProtocol::Udp,
                    provider_->protector());
                if (!protection.ok()) {
                    finish(Result<RouteConnection>(std::move(protection)));
                    return;
                }
                udp_socket_.async_connect(
                    endpoint,
                    boost::asio::bind_executor(
                        strand_, [self = shared_from_this()](
                                     const boost::system::error_code& error) noexcept {
                            self->complete_udp_connect(error);
                        }));
                return;
            }
            finish(Result<RouteConnection>(safe_status(
                StatusCode::NotFound,
                "UDP destination connection failed")));
        } catch (const std::bad_alloc&) {
            finish(Result<RouteConnection>(allocation_status(
                "UDP connection allocation failed")));
        } catch (...) {
            finish(Result<RouteConnection>(safe_status(
                StatusCode::Internal, "UDP connection setup failed")));
        }
    }

    void complete_tcp_connect(
        const boost::system::error_code& error) noexcept {
        if (finished_) {
            return;
        }
        if (error) {
            connect_next_tcp();
            return;
        }
        try {
            boost::system::error_code ignored;
            connect_timer_.cancel(ignored);
            tcp_socket_.set_option(Tcp::no_delay(true), ignored);
            auto state = std::make_shared<TcpChannelState>(
                std::move(tcp_socket_), provider_, target_id_);
            if (!provider_->promote(target_id_, state)) {
                state->request_close();
                finish(Result<RouteConnection>(safe_status(
                    StatusCode::ResourceExhausted,
                    "direct-route active-connection capacity exhausted")));
                return;
            }
            promoted_ = true;
            std::unique_ptr<ByteChannel> channel =
                std::make_unique<AsioTcpByteChannel>(std::move(state));
            auto connection =
                RouteConnection::byte_stream(std::move(channel));
            finish(std::move(connection));
        } catch (const std::bad_alloc&) {
            finish(Result<RouteConnection>(allocation_status(
                "TCP route-channel allocation failed")));
        } catch (...) {
            finish(Result<RouteConnection>(safe_status(
                StatusCode::Internal,
                "TCP route-channel construction failed")));
        }
    }

    void complete_udp_connect(
        const boost::system::error_code& error) noexcept {
        if (finished_) {
            return;
        }
        if (error) {
            connect_next_udp();
            return;
        }
        try {
            boost::system::error_code ignored;
            connect_timer_.cancel(ignored);
            auto state = std::make_shared<UdpChannelState>(
                std::move(udp_socket_), provider_, target_id_);
            if (!provider_->promote(target_id_, state)) {
                state->request_close();
                finish(Result<RouteConnection>(safe_status(
                    StatusCode::ResourceExhausted,
                    "direct-route active-connection capacity exhausted")));
                return;
            }
            promoted_ = true;
            std::unique_ptr<PacketChannel> channel =
                std::make_unique<AsioUdpPacketChannel>(std::move(state));
            auto connection =
                RouteConnection::packet_channel(std::move(channel));
            finish(std::move(connection));
        } catch (const std::bad_alloc&) {
            finish(Result<RouteConnection>(allocation_status(
                "UDP route-channel allocation failed")));
        } catch (...) {
            finish(Result<RouteConnection>(safe_status(
                StatusCode::Internal,
                "UDP route-channel construction failed")));
        }
    }

    void cancel_on_strand() noexcept {
        if (finished_) {
            return;
        }
        tcp_resolver_.cancel();
        udp_resolver_.cancel();
        boost::system::error_code ignored;
        tcp_socket_.cancel(ignored);
        tcp_socket_.close(ignored);
        udp_socket_.cancel(ignored);
        udp_socket_.close(ignored);
        resolve_timer_.cancel(ignored);
        connect_timer_.cancel(ignored);
        finish(Result<RouteConnection>(cancelled_status()));
    }

    void finish(Result<RouteConnection> result) noexcept {
        if (finished_) {
            if (result.ok()) {
                RouteConnection connection =
                    std::move(result).take_value();
                if (auto* channel = connection.byte_channel_if()) {
                    channel->close();
                }
                if (auto* channel = connection.packet_channel_if()) {
                    channel->close();
                }
            }
            return;
        }
        finished_ = true;
        cancellation_.unregister();
        boost::system::error_code ignored;
        resolve_timer_.cancel(ignored);
        connect_timer_.cancel(ignored);
        tcp_resolver_.cancel();
        udp_resolver_.cancel();
        if (!promoted_) {
            tcp_socket_.close(ignored);
            udp_socket_.close(ignored);
        }
        completion_->complete(std::move(result));
    }

    std::shared_ptr<ProviderState> provider_;
    std::uint64_t target_id_{0U};
    std::uint64_t reserved_epoch_{0U};
    AuthorizedRouteRequest request_;
    std::shared_ptr<OpenCompletion> completion_;
    Strand strand_;
    Tcp::resolver tcp_resolver_;
    Tcp::socket tcp_socket_;
    Udp::resolver udp_resolver_;
    Udp::socket udp_socket_;
    boost::asio::steady_timer resolve_timer_;
    boost::asio::steady_timer connect_timer_;
    std::vector<Tcp::endpoint> tcp_endpoints_;
    std::vector<Udp::endpoint> udp_endpoints_;
    std::size_t tcp_endpoint_index_{0U};
    std::size_t udp_endpoint_index_{0U};
    CancellationRegistration cancellation_;
    std::atomic<bool> cancellation_requested_{false};
    bool finished_{false};
    bool promoted_{false};
};

}  // namespace

AsioDirectRouteProvider::AsioDirectRouteProvider(
    std::shared_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

AsioDirectRouteProvider::~AsioDirectRouteProvider() noexcept {
    cancel();
}

Result<std::shared_ptr<AsioDirectRouteProvider>>
AsioDirectRouteProvider::create(
    Executor executor,
    ExecutorAffinity executor_affinity,
    AsioDirectRouteLimits limits,
    SocketProtector socket_protector) {
    if (!executor || !executor_affinity.valid() || !valid_limits(limits)) {
        return Result<std::shared_ptr<AsioDirectRouteProvider>>(Status(
            StatusCode::InvalidArgument,
            "Asio route executor, affinity, or limits are invalid"));
    }
    auto descriptor = ProviderDescriptor::create(
        std::string(kAsioDirectRouteProviderId),
        ProviderKind::RouteProvider,
        kAsioDirectRouteProviderApiVersion,
        CapabilitySet::of({
            Capability::AsynchronousIo,
            Capability::Cancellation,
            Capability::IdentityBoundRouting,
            Capability::DirectTcp,
            Capability::DirectUdp,
        }));
    if (!descriptor.ok()) {
        return Result<std::shared_ptr<AsioDirectRouteProvider>>(
            descriptor.status());
    }
    try {
        auto state = std::make_shared<ProviderState>(
            std::move(executor), executor_affinity, limits,
            std::move(socket_protector),
            std::move(descriptor).take_value());
        auto impl = std::make_shared<Impl>(std::move(state));
        auto provider = std::shared_ptr<AsioDirectRouteProvider>(
            new AsioDirectRouteProvider(std::move(impl)));
        return Result<std::shared_ptr<AsioDirectRouteProvider>>(
            std::move(provider));
    } catch (const std::bad_alloc&) {
        return Result<std::shared_ptr<AsioDirectRouteProvider>>(Status(
            StatusCode::ResourceExhausted,
            "Asio direct-route provider allocation failed"));
    } catch (...) {
        return Result<std::shared_ptr<AsioDirectRouteProvider>>(Status(
            StatusCode::Internal,
            "Asio direct-route provider construction failed"));
    }
}

const ProviderDescriptor&
AsioDirectRouteProvider::descriptor() const noexcept {
    return impl_->state()->descriptor();
}

void AsioDirectRouteProvider::async_open(
    const AuthorizedRouteRequest& request,
    CancellationToken cancellation,
    Completion completion) {
    if (!completion) {
        return;
    }
    const auto& state = impl_->state();
    std::shared_ptr<OpenCompletion> open_completion;
    try {
        open_completion =
            std::make_shared<OpenCompletion>(completion);
    } catch (const std::bad_alloc&) {
        Result<RouteConnection> failure(allocation_status(
            "direct-route completion allocation failed"));
        invoke_noexcept(completion, std::move(failure));
        return;
    } catch (...) {
        Result<RouteConnection> failure(safe_status(
            StatusCode::Internal,
            "direct-route completion construction failed"));
        invoke_noexcept(completion, std::move(failure));
        return;
    }
    if (!valid_destination(request.destination()) ||
        request.stream_id().is_control() ||
        !engine::valid_service_name(request.service_name()) ||
        request.peer_evidence().identity().empty()) {
        post_open_failure(
            state->executor(), open_completion,
            safe_status(StatusCode::InvalidArgument,
                        "authorized route request is invalid"));
        return;
    }

    auto reservation = state->reserve_open();
    if (!reservation.ok()) {
        post_open_failure(
            state->executor(), open_completion,
            safe_status(reservation.status().code(),
                        reservation.status().message()));
        return;
    }
    const auto [target_id, reserved_epoch] =
        std::move(reservation).take_value();
    try {
        auto operation = std::make_shared<OpenOperation>(
            state, target_id, reserved_epoch, request,
            open_completion);
        const bool cancel_now = state->bind_target(
            target_id, reserved_epoch, operation);
        operation->start(std::move(cancellation));
        if (cancel_now) {
            operation->request_cancel();
        }
    } catch (const std::bad_alloc&) {
        state->release(target_id);
        post_open_failure(
            state->executor(), open_completion,
            allocation_status("direct-route open allocation failed"));
    } catch (...) {
        state->release(target_id);
        post_open_failure(
            state->executor(), open_completion,
            safe_status(StatusCode::Internal,
                        "direct-route open construction failed"));
    }
}

void AsioDirectRouteProvider::cancel() noexcept {
    if (impl_) {
        impl_->state()->cancel_all();
    }
}

ExecutorAffinity
AsioDirectRouteProvider::executor_affinity() const noexcept {
    return impl_->state()->affinity();
}

const AsioDirectRouteLimits&
AsioDirectRouteProvider::limits() const noexcept {
    return impl_->state()->limits();
}

}  // namespace yume::providers
