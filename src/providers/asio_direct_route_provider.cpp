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
#include <map>
#include <utility>
#include <vector>

#include <boost/asio/async_result.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/asio/steady_timer.hpp>
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
using Executor = AsioExecutionContext::Executor;
using TcpSocket = boost::asio::basic_stream_socket<Tcp, Executor>;
using UdpSocket = boost::asio::basic_datagram_socket<Udp, Executor>;
using TcpResolver = boost::asio::ip::basic_resolver<Tcp, Executor>;
using UdpResolver = boost::asio::ip::basic_resolver<Udp, Executor>;
using Timer = boost::asio::basic_waitable_timer<std::chrono::steady_clock,
    boost::asio::wait_traits<std::chrono::steady_clock>, Executor>;

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

void publish_cancel_id(std::atomic<std::uint64_t>& destination,
                       std::uint64_t id) noexcept {
    auto previous = destination.load(std::memory_order_acquire);
    while (previous < id && !destination.compare_exchange_weak(
        previous, id, std::memory_order_acq_rel, std::memory_order_acquire)) {}
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
    ProviderState(std::shared_ptr<AsioExecutionContext> context,
                  ResolvedRoutePolicy resolved_policy,
                  AsioDirectRouteLimits limits,
                  SocketProtector protector,
                  ProviderDescriptor descriptor) noexcept
        : context_(std::move(context)),
          resolved_policy_(std::move(resolved_policy)),
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

    Status promote(std::uint64_t id, std::uint64_t reserved_epoch,
                 const std::shared_ptr<CancelTarget>& target) noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto found = targets_.find(id);
        if (reserved_epoch != cancellation_epoch_) return cancelled_status();
        if (found == targets_.end() ||
            found->second.kind != TargetKind::PendingOpen ||
            pending_opens_ == 0U ||
            active_connections_ >= limits_.max_active_connections) {
            return safe_status(StatusCode::ResourceExhausted,
                "direct-route active-connection capacity exhausted");
        }
        found->second.kind = TargetKind::ActiveConnection;
        found->second.target = target;
        --pending_opens_;
        ++active_connections_;
        return Status::success();
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
        std::uint64_t last_id = 0U;
        std::uint64_t final_id;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            ++cancellation_epoch_;
            final_id = next_target_id_ - 1U;
        }
        // Neither a cancellation request nor a target's last-reference
        // destructor may run under this registry lock. Both release ownership.
        for (;;) {
            std::shared_ptr<CancelTarget> target;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                const auto next = targets_.upper_bound(last_id);
                if (next == targets_.end() || next->first > final_id) return;
                last_id = next->first;
                target = next->second.target.lock();
            }
            if (target) target->request_cancel();
        }
    }

    Executor executor() const noexcept { return context_->executor(); }
    ExecutorAffinity affinity() const noexcept { return context_->affinity(); }
    const std::shared_ptr<AsioExecutionContext>& context() const noexcept {
        return context_;
    }
    const AsioDirectRouteLimits& limits() const noexcept { return limits_; }
    const SocketProtector& protector() const noexcept { return protector_; }
    const ResolvedRoutePolicy& resolved_policy() const noexcept { return resolved_policy_; }
    const ProviderDescriptor& descriptor() const noexcept {
        return descriptor_;
    }

private:
    std::shared_ptr<AsioExecutionContext> context_;
    ResolvedRoutePolicy resolved_policy_;
    AsioDirectRouteLimits limits_;
    SocketProtector protector_;
    ProviderDescriptor descriptor_;

    std::mutex mutex_;
    std::map<std::uint64_t, TargetEntry> targets_;
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
    TcpChannelState(TcpSocket socket,
                    std::shared_ptr<ProviderState> provider,
                    std::uint64_t target_id)
        : socket_(std::move(socket)),
          provider_(std::move(provider)),
          target_id_(target_id),
          control_([](void* owner) noexcept {
              static_cast<TcpChannelState*>(owner)->handle_control();
          }) {}

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
                    ByteChannel::ReadCompletion completion) {
        provider_->context()->require_context();
        const auto owner = shared_from_this();
        if (!completion) return;
        if (close_requested_.load(std::memory_order_acquire)) {
            complete_read(std::move(completion), closed_status());
        } else if (max_bytes == 0U || max_bytes > max_read_size()) {
            complete_read(std::move(completion), safe_status(StatusCode::InvalidArgument,
                "TCP read exceeds the provider bound"));
        } else {
            start_read(max_bytes, std::move(cancellation), std::move(completion));
        }
    }

    void async_write(Buffer buffer,
                     CancellationToken cancellation,
                     ByteChannel::WriteCompletion completion) {
        provider_->context()->require_context();
        const auto owner = shared_from_this();
        if (!completion) return;
        if (close_requested_.load(std::memory_order_acquire) || write_shutdown_requested_) {
            invoke_noexcept(completion, closed_status(), 0U);
        } else if (buffer.size() > max_write_size()) {
            invoke_noexcept(completion, safe_status(StatusCode::ResourceExhausted,
                "TCP write exceeds the provider bound"), 0U);
        } else {
            start_write(std::move(buffer), std::move(cancellation), std::move(completion));
        }
    }

    Status shutdown_write() noexcept {
        if (!provider_->context()->running_in_this_thread())
            return Status(StatusCode::FailedPrecondition);
        const auto owner = shared_from_this();
        if (close_requested_.load(std::memory_order_acquire)) return closed_status();
        if (!write_shutdown_requested_) {
            write_shutdown_requested_ = true;
            shutdown_write_on_context();
        }
        return Status::success();
    }

    void request_cancel() noexcept override {
        std::lock_guard<std::mutex> lock(publication_mutex_);
        if (close_requested_.load(std::memory_order_acquire)) return;
        publish_cancel_id(cancel_through_,
            next_operation_id_.load(std::memory_order_acquire) - 1U);
        provider_->context()->submit(control_, shared_from_this());
    }

    void request_close() noexcept {
        std::lock_guard<std::mutex> lock(publication_mutex_);
        if (close_requested_.exchange(true, std::memory_order_acq_rel)) return;
        provider_->context()->submit(control_, shared_from_this());
    }

private:
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
        std::size_t transferred{0U};
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
                complete_read(std::move(completion), safe_status(allocated.status().code(), allocated.status().message()));
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
                settle_read(safe_status(registration.status().code(), registration.status().message()));
                return;
            }
            pending_read_->cancellation =
                std::move(registration).take_value();
            const auto read_bytes = pending_read_->buffer.mutable_bytes();
            socket_.async_read_some(
                boost::asio::buffer(read_bytes.data(), read_bytes.size()),
                [self = shared_from_this(), id](
                    const boost::system::error_code& error,
                    std::size_t transferred) noexcept {
                    self->complete_socket_read(id, error, transferred);
                });
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
                settle_write(safe_status(registration.status().code(), registration.status().message()), 0U);
                return;
            }
            pending_write_->cancellation =
                std::move(registration).take_value();
            continue_write();
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
        request_operation_cancel(id, cancelled_read_);
    }

    void cancel_write(std::uint64_t id) noexcept {
        request_operation_cancel(id, cancelled_write_);
    }

    void request_operation_cancel(std::uint64_t id,
                                  std::atomic<std::uint64_t>& requested) noexcept {
        std::lock_guard<std::mutex> lock(publication_mutex_);
        if (close_requested_.load(std::memory_order_acquire)) return;
        publish_cancel_id(requested, id);
        provider_->context()->submit(control_, shared_from_this());
    }

    void handle_control() noexcept {
        if (close_requested_.load(std::memory_order_acquire)) {
            close_on_context();
            return;
        }
        const auto through = cancel_through_.load(std::memory_order_acquire);
        if ((pending_read_ && (pending_read_->id <= through ||
             pending_read_->id == cancelled_read_.load(std::memory_order_acquire))) ||
            (pending_write_ && (pending_write_->id <= through ||
             pending_write_->id == cancelled_write_.load(std::memory_order_acquire))))
            cancel_on_context();
    }

    void complete_socket_read(std::uint64_t id,
                              const boost::system::error_code& error,
                              std::size_t transferred) noexcept {
        try {
            if (!pending_read_ || pending_read_->id != id) {
                return;
            }
            if (close_requested_.load(std::memory_order_acquire)) {
                settle_read(closed_status());
                return;
            }
            if (pending_read_->cancelled || id <= cancel_through_.load(std::memory_order_acquire) ||
                id == cancelled_read_.load(std::memory_order_acquire)) {
                settle_read(cancelled_status());
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
                settle_read(safe_status(resized.code(), resized.message()));
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

    void continue_write() noexcept {
        if (!pending_write_) return;
        auto& operation = *pending_write_;
        const auto id = operation.id;
        const auto transferred = operation.transferred;
        if (close_requested_.load(std::memory_order_acquire)) {
            settle_write(closed_status(), transferred);
            return;
        }
        if (operation.cancelled || id <= cancel_through_.load(std::memory_order_acquire) ||
            id == cancelled_write_.load(std::memory_order_acquire)) {
            settle_write(cancelled_status(), transferred);
            return;
        }
        const auto remaining = operation.buffer.bytes().subspan(transferred);
        if (remaining.empty()) {
            settle_write(Status::success(), transferred);
            return;
        }
        try {
            socket_.async_write_some(boost::asio::buffer(remaining.data(), remaining.size()),
                [self = shared_from_this(), id](const boost::system::error_code& error,
                                               std::size_t count) noexcept {
                    self->complete_socket_write(id, error, count);
                });
        } catch (const std::bad_alloc&) {
            settle_write(allocation_status("TCP write continuation allocation failed"), transferred);
        } catch (...) {
            settle_write(safe_status(StatusCode::Internal, "TCP write continuation failed"), transferred);
        }
    }

    void complete_socket_write(std::uint64_t id,
                               const boost::system::error_code& error,
                               std::size_t transferred) noexcept {
        if (!pending_write_ || pending_write_->id != id) return;
        auto& operation = *pending_write_;
        if (transferred > operation.buffer.size() - operation.transferred) {
            settle_write(safe_status(StatusCode::Internal,
                "TCP write completion exceeded its buffer"), operation.transferred);
            return;
        }
        operation.transferred += transferred;
        const auto total = operation.transferred;
        const bool cancelled = operation.cancelled ||
            id <= cancel_through_.load(std::memory_order_acquire) ||
            id == cancelled_write_.load(std::memory_order_acquire);
        if (close_requested_.load(std::memory_order_acquire)) {
            settle_write(closed_status(), total);
        } else if (cancelled) {
            settle_write(cancelled_status(), total);
        } else if (error || transferred == 0U) {
            settle_write(error ? socket_operation_status(error, closed_, false, "TCP write failed")
                               : closed_status(), total);
        } else if (total == operation.buffer.size()) {
            settle_write(Status::success(), total);
        } else {
            continue_write();
        }
        if (shutdown_after_write_ && !pending_write_) shutdown_socket_write();
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

    void shutdown_write_on_context() noexcept {
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

    void cancel_on_context() noexcept {
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

    void close_on_context() noexcept {
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

    TcpSocket socket_;
    std::shared_ptr<ProviderState> provider_;
    std::uint64_t target_id_{0U};
    std::atomic<std::uint64_t> next_operation_id_{1U};
    std::optional<PendingRead> pending_read_;
    std::optional<PendingWrite> pending_write_;
    bool read_eof_{false};
    bool write_shutdown_{false};
    bool shutdown_after_write_{false};
    bool closed_{false};
    bool registered_{true};

    // Terminal publication and control admission share this gate. A cancel
    // racing close must enqueue before close returns, never after final drain.
    std::mutex publication_mutex_;
    std::atomic<bool> close_requested_{false};
    bool write_shutdown_requested_{false};
    std::atomic<std::uint64_t> cancel_through_{0U};
    std::atomic<std::uint64_t> cancelled_read_{0U};
    std::atomic<std::uint64_t> cancelled_write_{0U};
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

class UdpChannelState final : public CancelTarget,
                              public std::enable_shared_from_this<UdpChannelState> {
public:
    UdpChannelState(UdpSocket socket,
                    std::shared_ptr<ProviderState> provider,
                    std::uint64_t target_id)
        : socket_(std::move(socket)),
          provider_(std::move(provider)),
          target_id_(target_id),
          control_([](void* owner) noexcept {
              static_cast<UdpChannelState*>(owner)->handle_control();
          }) {}

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
                       PacketChannel::ReceiveCompletion completion) {
        provider_->context()->require_context();
        const auto owner = shared_from_this();
        if (!completion) return;
        if (close_requested_.load(std::memory_order_acquire)) {
            complete_receive(std::move(completion), closed_status());
        } else {
            start_receive(std::move(cancellation), std::move(completion));
        }
    }

    void async_send(Buffer packet,
                    CancellationToken cancellation,
                    PacketChannel::SendCompletion completion) {
        provider_->context()->require_context();
        const auto owner = shared_from_this();
        if (!completion) return;
        if (close_requested_.load(std::memory_order_acquire)) {
            invoke_noexcept(completion, closed_status(), 0U);
        } else if (packet.size() > max_packet_size()) {
            invoke_noexcept(completion, safe_status(StatusCode::ResourceExhausted,
                "UDP packet exceeds the provider bound"), 0U);
        } else {
            start_send(std::move(packet), std::move(cancellation), std::move(completion));
        }
    }

    void request_cancel() noexcept override {
        std::lock_guard<std::mutex> lock(publication_mutex_);
        if (close_requested_.load(std::memory_order_acquire)) return;
        publish_cancel_id(cancel_through_,
            next_operation_id_.load(std::memory_order_acquire) - 1U);
        provider_->context()->submit(control_, shared_from_this());
    }

    void request_close() noexcept {
        std::lock_guard<std::mutex> lock(publication_mutex_);
        if (close_requested_.exchange(true, std::memory_order_acq_rel)) return;
        provider_->context()->submit(control_, shared_from_this());
    }

private:
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
                complete_receive(std::move(completion), safe_status(allocated.status().code(), allocated.status().message()));
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
                settle_receive(safe_status(registration.status().code(), registration.status().message()));
                return;
            }
            pending_receive_->cancellation =
                std::move(registration).take_value();
            const auto receive_bytes =
                pending_receive_->buffer.mutable_bytes();
            socket_.async_receive(
                boost::asio::buffer(
                    receive_bytes.data(), receive_bytes.size()),
                [self = shared_from_this(), id](
                    const boost::system::error_code& error,
                    std::size_t transferred) noexcept {
                    self->complete_socket_receive(id, error, transferred);
                });
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
                settle_send(safe_status(registration.status().code(), registration.status().message()), 0U);
                return;
            }
            pending_send_->cancellation =
                std::move(registration).take_value();
            const auto send_bytes = pending_send_->buffer.bytes();
            socket_.async_send(
                boost::asio::buffer(send_bytes.data(), send_bytes.size()),
                [self = shared_from_this(), id](
                    const boost::system::error_code& error,
                    std::size_t transferred) noexcept {
                    self->complete_socket_send(id, error, transferred);
                });
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
        request_operation_cancel(id, cancelled_receive_);
    }

    void cancel_send(std::uint64_t id) noexcept {
        request_operation_cancel(id, cancelled_send_);
    }

    void request_operation_cancel(std::uint64_t id,
                                  std::atomic<std::uint64_t>& requested) noexcept {
        std::lock_guard<std::mutex> lock(publication_mutex_);
        if (close_requested_.load(std::memory_order_acquire)) return;
        publish_cancel_id(requested, id);
        provider_->context()->submit(control_, shared_from_this());
    }

    void handle_control() noexcept {
        if (close_requested_.load(std::memory_order_acquire)) {
            close_on_context();
            return;
        }
        const auto through = cancel_through_.load(std::memory_order_acquire);
        if ((pending_receive_ && (pending_receive_->id <= through ||
             pending_receive_->id == cancelled_receive_.load(std::memory_order_acquire))) ||
            (pending_send_ && (pending_send_->id <= through ||
             pending_send_->id == cancelled_send_.load(std::memory_order_acquire))))
            cancel_on_context();
    }

    void complete_socket_receive(
        std::uint64_t id,
        const boost::system::error_code& error,
        std::size_t transferred) noexcept {
        try {
            if (!pending_receive_ || pending_receive_->id != id) {
                return;
            }
            if (close_requested_.load(std::memory_order_acquire)) {
                settle_receive(closed_status());
                return;
            }
            if (pending_receive_->cancelled || id <= cancel_through_.load(std::memory_order_acquire) ||
                id == cancelled_receive_.load(std::memory_order_acquire)) {
                settle_receive(cancelled_status());
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
                settle_receive(safe_status(resized.code(), resized.message()));
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
        if (close_requested_.load(std::memory_order_acquire)) {
            settle_send(closed_status(), transferred);
        } else if (pending_send_->cancelled || id <= cancel_through_.load(std::memory_order_acquire) ||
                   id == cancelled_send_.load(std::memory_order_acquire)) {
            settle_send(cancelled_status(), transferred);
        } else if (error) {
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

    void cancel_on_context() noexcept {
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

    void close_on_context() noexcept {
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

    UdpSocket socket_;
    std::shared_ptr<ProviderState> provider_;
    std::uint64_t target_id_{0U};
    std::atomic<std::uint64_t> next_operation_id_{1U};
    std::optional<PendingReceive> pending_receive_;
    std::optional<PendingSend> pending_send_;
    bool closed_{false};
    bool registered_{true};

    // Terminal publication and control admission share this gate. A cancel
    // racing close must enqueue before close returns, never after final drain.
    std::mutex publication_mutex_;
    std::atomic<bool> close_requested_{false};
    std::atomic<std::uint64_t> cancel_through_{0U};
    std::atomic<std::uint64_t> cancelled_receive_{0U};
    std::atomic<std::uint64_t> cancelled_send_{0U};
    ControlTask control_;
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

void complete_open_failure(
    const std::shared_ptr<OpenCompletion>& completion,
    Status status) noexcept {
    completion->complete(Result<RouteConnection>(std::move(status)));
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
          tcp_resolver_(std::in_place, provider_->executor()),
          tcp_socket_(provider_->executor()),
          udp_resolver_(std::in_place, provider_->executor()),
          udp_socket_(provider_->executor()),
          resolve_timer_(provider_->executor()),
          connect_timer_(provider_->executor()),
          control_([](void* owner) noexcept {
              static_cast<OpenOperation*>(owner)->handle_control();
          }) {}

    ~OpenOperation() noexcept override {
        boost::system::error_code ignored;
        tcp_resolver_.reset();
        udp_resolver_.reset();
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
        start_on_context(std::move(cancellation));
    }

    void request_cancel() noexcept override {
        std::lock_guard<std::mutex> lock(publication_mutex_);
        if (finished_.load(std::memory_order_acquire)) return;
        cancellation_requested_.store(true, std::memory_order_release);
        provider_->context()->submit(control_, shared_from_this());
    }

private:
    // Resolver delivery allocates before entering our callback. Destruction of
    // its last handler without invocation must settle via reserved dispatch.
    template <typename Protocol>
    class ResolveCompletion final {
    public:
        explicit ResolveCompletion(std::shared_ptr<OpenOperation> owner) noexcept
            : owner_(std::move(owner)) {
            owner_->resolve_handler_owners_.fetch_add(1U, std::memory_order_relaxed);
        }
        ResolveCompletion(const ResolveCompletion& other) noexcept : owner_(other.owner_) {
            if (owner_) owner_->resolve_handler_owners_.fetch_add(1U, std::memory_order_relaxed);
        }
        ResolveCompletion(ResolveCompletion&&) noexcept = default;
        ~ResolveCompletion() noexcept {
            if (owner_ && owner_->resolve_handler_owners_.fetch_sub(
                    1U, std::memory_order_acq_rel) == 1U &&
                !owner_->resolve_handler_invoked_.load(std::memory_order_acquire)) {
                owner_->request_resolve_failure();
            }
        }
        void operator()(const boost::system::error_code& error,
                        typename Protocol::resolver::results_type results) noexcept {
            owner_->resolve_handler_invoked_.store(true, std::memory_order_release);
            if constexpr (std::is_same_v<Protocol, Tcp>)
                owner_->complete_tcp_resolve(error, std::move(results));
            else owner_->complete_udp_resolve(error, std::move(results));
        }
    private:
        std::shared_ptr<OpenOperation> owner_;
    };

    void request_resolve_failure() noexcept {
        std::lock_guard<std::mutex> lock(publication_mutex_);
        if (finished_.load(std::memory_order_acquire)) return;
        resolve_handler_lost_.store(true, std::memory_order_release);
        provider_->context()->submit(control_, shared_from_this());
    }

    void handle_control() noexcept {
        if (finished_.load(std::memory_order_acquire)) return;
        if (cancellation_requested_.load(std::memory_order_acquire)) {
            cancel_on_context();
        } else if (resolve_handler_lost_.load(std::memory_order_acquire)) {
            finish(Result<RouteConnection>(allocation_status(
                "direct-route resolver completion allocation failed")));
        }
    }

    void start_on_context(CancellationToken cancellation) noexcept {
        try {
            if (cancellation.is_cancelled() ||
                cancellation_requested_.load(std::memory_order_acquire)) {
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
            tcp_resolver_->async_resolve(
                std::string(request_.destination().dns_name()),
                std::to_string(request_.destination().port()),
                Tcp::resolver::numeric_service,
                ResolveCompletion<Tcp>(shared_from_this()));
            return;
        }
        tcp_endpoints_.push_back(tcp_literal_endpoint());
        if (!authorize_endpoints(tcp_endpoints_)) return;
        arm_connect_timeout(NetworkProtocol::Tcp);
        connect_next_tcp();
    }

    void begin_udp() {
        if (request_.destination().address_kind() ==
            RouteAddressKind::DnsName) {
            arm_resolve_timeout(NetworkProtocol::Udp);
            udp_resolver_->async_resolve(
                std::string(request_.destination().dns_name()),
                std::to_string(request_.destination().port()),
                Udp::resolver::numeric_service,
                ResolveCompletion<Udp>(shared_from_this()));
            return;
        }
        udp_endpoints_.push_back(udp_literal_endpoint());
        if (!authorize_endpoints(udp_endpoints_)) return;
        arm_connect_timeout(NetworkProtocol::Udp);
        connect_next_udp();
    }

    Result<RouteDestination> policy_destination(
        boost::asio::ip::address address, std::uint16_t port) const {
        if (address.is_v6()) {
            const auto ipv6 = address.to_v6();
            if (ipv6.scope_id() != 0U) {
                return Result<RouteDestination>(safe_status(
                    StatusCode::FailedPrecondition,
                    "scoped IPv6 routes are unsupported"));
            }
            if (!ipv6.is_v4_mapped()) {
                return RouteDestination::ipv6(
                    request_.destination().protocol(), ipv6.to_bytes(), port);
            }
            const auto bytes = ipv6.to_bytes();
            return RouteDestination::ipv4(request_.destination().protocol(),
                {bytes[12], bytes[13], bytes[14], bytes[15]}, port);
        }
        return RouteDestination::ipv4(request_.destination().protocol(),
                                      address.to_v4().to_bytes(), port);
    }

    template <typename Endpoint>
    bool authorize_endpoints(const std::vector<Endpoint>& endpoints) noexcept {
        try {
            // Validate the complete bounded candidate set before connecting;
            // an allowed first address cannot conceal a forbidden fallback.
            for (const auto& endpoint : endpoints) {
                auto destination = policy_destination(endpoint.address(), endpoint.port());
                if (!destination.ok()) {
                    finish(Result<RouteConnection>(destination.status()));
                    return false;
                }
                Status status = provider_->resolved_policy()(request_, destination.value());
                // Policy may cancel the provider or the original OPEN. Do not
                // open a socket after a reentrant successful callback cancels.
                if (cancellation_requested_.load(std::memory_order_acquire)) {
                    finish(Result<RouteConnection>(cancelled_status()));
                    return false;
                }
                if (!status.ok()) {
                    finish(Result<RouteConnection>(std::move(status)));
                    return false;
                }
            }
            return true;
        } catch (const std::bad_alloc&) {
            finish(Result<RouteConnection>(allocation_status(
                "resolved-route policy allocation failed")));
        } catch (...) {
            finish(Result<RouteConnection>(safe_status(
                StatusCode::Internal, "resolved-route policy threw")));
        }
        return false;
    }

    void arm_resolve_timeout(NetworkProtocol protocol) {
        resolve_timer_.expires_after(provider_->limits().resolve_timeout);
        resolve_timer_.async_wait(
            [self = shared_from_this(), protocol](
                const boost::system::error_code& error) noexcept {
                self->complete_resolve_timeout(protocol, error);
            });
    }

    void arm_connect_timeout(NetworkProtocol protocol) {
        connect_timer_.expires_after(provider_->limits().connect_timeout);
        connect_timer_.async_wait(
            [self = shared_from_this(), protocol](
                const boost::system::error_code& error) noexcept {
                self->complete_connect_timeout(protocol, error);
            });
    }

    void complete_resolve_timeout(
        NetworkProtocol protocol,
        const boost::system::error_code& error) noexcept {
        if (error || finished_) {
            return;
        }
        if (protocol == NetworkProtocol::Tcp) {
            tcp_resolver_.reset();
        } else {
            udp_resolver_.reset();
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
            if (!authorize_endpoints(tcp_endpoints_)) return;
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
            if (!authorize_endpoints(udp_endpoints_)) return;
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
                    [self = shared_from_this()](
                        const boost::system::error_code& error) noexcept {
                        self->complete_tcp_connect(error);
                    });
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
                    [self = shared_from_this()](
                        const boost::system::error_code& error) noexcept {
                        self->complete_udp_connect(error);
                    });
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
        if (cancellation_requested_.load(std::memory_order_acquire)) {
            finish(Result<RouteConnection>(cancelled_status()));
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
            auto promotion = provider_->promote(target_id_, reserved_epoch_, state);
            if (!promotion.ok()) {
                state->request_close();
                finish(Result<RouteConnection>(std::move(promotion)));
                return;
            }
            promoted_ = true;
            std::unique_ptr<ByteChannel> channel =
                std::make_unique<AsioTcpByteChannel>(std::move(state));
            auto connection =
                RouteConnection::byte_stream(std::move(channel));
            if (cancellation_requested_.load(std::memory_order_acquire)) {
                if (connection.ok()) {
                    auto owned = std::move(connection).take_value();
                    if (auto* bytes = owned.byte_channel_if()) bytes->close();
                    if (auto* packets = owned.packet_channel_if()) packets->close();
                }
                finish(Result<RouteConnection>(cancelled_status()));
            } else {
                finish(std::move(connection));
            }
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
        if (cancellation_requested_.load(std::memory_order_acquire)) {
            finish(Result<RouteConnection>(cancelled_status()));
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
            auto promotion = provider_->promote(target_id_, reserved_epoch_, state);
            if (!promotion.ok()) {
                state->request_close();
                finish(Result<RouteConnection>(std::move(promotion)));
                return;
            }
            promoted_ = true;
            std::unique_ptr<PacketChannel> channel =
                std::make_unique<AsioUdpPacketChannel>(std::move(state));
            auto connection =
                RouteConnection::packet_channel(std::move(channel));
            if (cancellation_requested_.load(std::memory_order_acquire)) {
                if (connection.ok()) {
                    auto owned = std::move(connection).take_value();
                    if (auto* bytes = owned.byte_channel_if()) bytes->close();
                    if (auto* packets = owned.packet_channel_if()) packets->close();
                }
                finish(Result<RouteConnection>(cancelled_status()));
            } else {
                finish(std::move(connection));
            }
        } catch (const std::bad_alloc&) {
            finish(Result<RouteConnection>(allocation_status(
                "UDP route-channel allocation failed")));
        } catch (...) {
            finish(Result<RouteConnection>(safe_status(
                StatusCode::Internal,
                "UDP route-channel construction failed")));
        }
    }

    void cancel_on_context() noexcept {
        if (finished_) {
            return;
        }
        tcp_resolver_.reset();
        udp_resolver_.reset();
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
        {
            std::lock_guard<std::mutex> lock(publication_mutex_);
            finished_.store(true, std::memory_order_release);
        }
        cancellation_.unregister();
        boost::system::error_code ignored;
        resolve_timer_.cancel(ignored);
        connect_timer_.cancel(ignored);
        tcp_resolver_.reset();
        udp_resolver_.reset();
        if (!promoted_) {
            tcp_socket_.close(ignored);
            udp_socket_.close(ignored);
            // Resetting a resolver cancels its token, not a blocked system
            // lookup or a queued delivery. Keep its pending reservation until
            // the retained handler/operation retires, so repeated timeouts
            // cannot bypass the configured bound on outstanding DNS work.
            if (resolve_handler_owners_.load(std::memory_order_acquire) == 0U)
                provider_->release(target_id_);
        }
        completion_->complete(std::move(result));
    }

    std::shared_ptr<ProviderState> provider_;
    std::uint64_t target_id_{0U};
    std::uint64_t reserved_epoch_{0U};
    AuthorizedRouteRequest request_;
    std::shared_ptr<OpenCompletion> completion_;
    // Resolver::cancel() allocates. Destroying the terminal resolver cancels
    // without replacing its token, including under sustained allocation failure.
    std::optional<TcpResolver> tcp_resolver_;
    TcpSocket tcp_socket_;
    std::optional<UdpResolver> udp_resolver_;
    UdpSocket udp_socket_;
    Timer resolve_timer_;
    Timer connect_timer_;
    std::vector<Tcp::endpoint> tcp_endpoints_;
    std::vector<Udp::endpoint> udp_endpoints_;
    std::size_t tcp_endpoint_index_{0U};
    std::size_t udp_endpoint_index_{0U};
    CancellationRegistration cancellation_;
    std::atomic<bool> cancellation_requested_{false};
    std::mutex publication_mutex_;
    std::atomic<bool> finished_{false};
    std::atomic<unsigned> resolve_handler_owners_{0U};
    std::atomic<bool> resolve_handler_invoked_{false};
    std::atomic<bool> resolve_handler_lost_{false};
    bool promoted_{false};
    ControlTask control_;
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
    std::shared_ptr<AsioExecutionContext> context,
    ResolvedRoutePolicy resolved_policy,
    AsioDirectRouteLimits limits,
    SocketProtector socket_protector) {
    if (!context || !resolved_policy || !valid_limits(limits)) {
        return Result<std::shared_ptr<AsioDirectRouteProvider>>(Status(
            StatusCode::InvalidArgument,
            "Asio route context, resolved policy or limits are invalid"));
    }
    try {
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
        auto state = std::make_shared<ProviderState>(
            std::move(context), std::move(resolved_policy), limits,
            std::move(socket_protector),
            std::move(descriptor).take_value());
        auto impl = std::make_shared<Impl>(std::move(state));
        auto provider = std::shared_ptr<AsioDirectRouteProvider>(
            new AsioDirectRouteProvider(std::move(impl)));
        return Result<std::shared_ptr<AsioDirectRouteProvider>>(
            std::move(provider));
    } catch (const std::bad_alloc&) {
        return Result<std::shared_ptr<AsioDirectRouteProvider>>(allocation_status(
            "Asio direct-route provider allocation failed"));
    } catch (...) {
        return Result<std::shared_ptr<AsioDirectRouteProvider>>(safe_status(
            StatusCode::Internal, "Asio direct-route provider construction failed"));
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
    const auto state = impl_->state();
    state->context()->require_context();
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
        complete_open_failure(
            open_completion,
            safe_status(StatusCode::InvalidArgument,
                        "authorized route request is invalid"));
        return;
    }

    auto reservation = state->reserve_open();
    if (!reservation.ok()) {
        complete_open_failure(
            open_completion,
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
        if (cancel_now) operation->request_cancel();
        operation->start(std::move(cancellation));
    } catch (const std::bad_alloc&) {
        state->release(target_id);
        complete_open_failure(
            open_completion,
            allocation_status("direct-route open allocation failed"));
    } catch (...) {
        state->release(target_id);
        complete_open_failure(
            open_completion,
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
