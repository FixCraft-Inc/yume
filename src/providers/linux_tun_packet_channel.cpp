/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/linux_tun_packet_channel.hpp"

#include <array>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <limits>
#include <mutex>
#include <new>
#include <optional>
#include <utility>

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <boost/asio/error.hpp>
#include <boost/asio/posix/basic_stream_descriptor.hpp>

namespace yume::providers {
namespace {
using engine::Buffer;
using engine::CancellationRegistration;
using engine::CancellationToken;
using engine::Result;
using engine::Status;
using engine::StatusCode;
using Descriptor = boost::asio::posix::basic_stream_descriptor<AsioExecutionContext::Executor>;

class OwnedFd final {
public:
    explicit OwnedFd(int fd) noexcept : fd_(fd) {}
    OwnedFd(const OwnedFd&) = delete;
    OwnedFd& operator=(const OwnedFd&) = delete;
    ~OwnedFd() noexcept { if (fd_ >= 0) ::close(fd_); }
    int get() const noexcept { return fd_; }
    int release() noexcept { return std::exchange(fd_, -1); }
private:
    int fd_;
};

Status system_failure() noexcept {
    switch (errno) {
    case EACCES: case EPERM: return Status(StatusCode::PermissionDenied);
    case ENOENT: case ENODEV: case ENXIO: return Status(StatusCode::NotFound);
    case ENOMEM: case ENFILE: case EMFILE: return Status(StatusCode::ResourceExhausted);
    case EBUSY: return Status(StatusCode::AlreadyExists);
    case EBADF: case ENOTTY: case EINVAL: return Status(StatusCode::InvalidArgument);
    default: return Status(StatusCode::Internal);
    }
}

bool valid_name(std::string_view name) noexcept {
    if (name.empty() || name.size() >= IFNAMSIZ || name == "." || name == "..") return false;
    for (const unsigned char ch : name) {
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.')) return false;
    }
    return true;
}

bool valid_mtu(std::size_t mtu) noexcept { return mtu >= 576U && mtu <= 65535U; }

Status verify_tun_file(int fd) noexcept {
    struct stat info{};
    if (::fstat(fd, &info) < 0) return system_failure();
    if (!S_ISCHR(info.st_mode) || major(info.st_rdev) != 10U || minor(info.st_rdev) != 200U)
        return Status(StatusCode::InvalidArgument);
    return Status::success();
}

Status verify_device(int fd, std::size_t mtu, std::string_view expected_name,
                     std::array<char, IFNAMSIZ>& name, unsigned int& index) noexcept {
    struct ifreq device{};
    if (::ioctl(fd, TUNGETIFF, &device) < 0) return system_failure();
    const auto length = ::strnlen(device.ifr_name, IFNAMSIZ);
    const std::string_view actual_name(device.ifr_name, length);
    if (!valid_name(actual_name) || (!expected_name.empty() && actual_name != expected_name))
        return Status(StatusCode::InvalidArgument);
    const auto flags = static_cast<unsigned short>(device.ifr_flags);
    if ((flags & (IFF_TUN | IFF_NO_PI)) != (IFF_TUN | IFF_NO_PI) ||
        (flags & (IFF_TAP | IFF_VNET_HDR | IFF_MULTI_QUEUE | IFF_PERSIST)) != 0U)
        return Status(StatusCode::InvalidArgument);
    OwnedFd control(::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    if (control.get() < 0) return system_failure();
    struct ifreq request{};
    std::memcpy(request.ifr_name, device.ifr_name, length + 1U);
    request.ifr_mtu = static_cast<int>(mtu);
    if (::ioctl(control.get(), SIOCSIFMTU, &request) < 0) return system_failure();
    if (::ioctl(control.get(), SIOCGIFMTU, &request) < 0) return system_failure();
    if (request.ifr_mtu < 0 || static_cast<std::size_t>(request.ifr_mtu) != mtu)
        return Status(StatusCode::FailedPrecondition);
    if (::ioctl(control.get(), SIOCGIFINDEX, &request) < 0) return system_failure();
    if (request.ifr_ifindex <= 0) return Status(StatusCode::FailedPrecondition);
    index = static_cast<unsigned int>(request.ifr_ifindex);
    std::memcpy(name.data(), device.ifr_name, length + 1U);
    return Status::success();
}

template <typename Completion, typename... Args>
void invoke(Completion& completion, Args&&... args) noexcept {
    try { if (completion) completion(std::forward<Args>(args)...); } catch (...) {}
}

void publish_id(std::atomic<std::uint64_t>& target, std::uint64_t id) noexcept {
    auto previous = target.load(std::memory_order_acquire);
    while (previous < id && !target.compare_exchange_weak(
        previous, id, std::memory_order_acq_rel, std::memory_order_acquire)) {}
}
}  // namespace

struct LinuxTunPacketChannel::State final : std::enable_shared_from_this<State> {
    State(std::shared_ptr<AsioExecutionContext> context_value, std::size_t mtu_value,
          std::array<char, IFNAMSIZ> name_value, unsigned int index_value)
        : context(std::move(context_value)), reader(context->executor()), writer(context->executor()),
          mtu(mtu_value), name(name_value), index(index_value), control([](void* owner) noexcept {
              static_cast<State*>(owner)->handle_control();
          }) {}

    ~State() noexcept {
        boost::system::error_code ignored;
        reader.close(ignored);
        writer.close(ignored);
    }

    struct Receive final {
        std::uint64_t id;
        Buffer packet;
        ReceiveCompletion completion;
        CancellationRegistration registration;
    };
    struct Send final {
        std::uint64_t id;
        Buffer packet;
        SendCompletion completion;
        CancellationRegistration registration;
    };

    void request(bool terminal) noexcept {
        std::lock_guard<std::mutex> lock(publication);
        if (closing.load(std::memory_order_acquire)) return;
        if (terminal) closing.store(true, std::memory_order_release);
        else publish_id(cancel_through, next_id.load(std::memory_order_acquire) - 1U);
        context->submit(control, shared_from_this());
    }

    void request_operation(std::uint64_t id, bool receive) noexcept {
        std::lock_guard<std::mutex> lock(publication);
        if (closing.load(std::memory_order_acquire)) return;
        publish_id(receive ? cancel_receive : cancel_send, id);
        context->submit(control, shared_from_this());
    }

    bool cancelled(std::uint64_t id, bool receive) const noexcept {
        return id <= cancel_through.load(std::memory_order_acquire) ||
               id <= (receive ? cancel_receive : cancel_send).load(std::memory_order_acquire);
    }

    void handle_control() noexcept {
        boost::system::error_code error;
        if (closing.load(std::memory_order_acquire)) {
            reader.close(error);
            writer.close(error);
            return;
        }
        if (pending_receive && cancelled(pending_receive->id, true)) {
            reader.cancel(error);
            if (error) request(true);
        }
        if (pending_send && cancelled(pending_send->id, false)) {
            writer.cancel(error);
            if (error) request(true);
        }
    }

    void receive(CancellationToken cancellation, ReceiveCompletion completion) {
        context->require_context();
        const auto owner = shared_from_this();
        if (!completion) return;
        if (closing.load(std::memory_order_acquire)) {
            invoke(completion, Result<Buffer>(Status(StatusCode::Closed)));
            return;
        }
        if (pending_receive) {
            invoke(completion, Result<Buffer>(Status(StatusCode::FailedPrecondition)));
            return;
        }
        if (cancellation.is_cancelled()) {
            invoke(completion, Result<Buffer>(Status(StatusCode::Cancelled)));
            return;
        }
        if (next_id.load() == std::numeric_limits<std::uint64_t>::max()) {
            invoke(completion, Result<Buffer>(Status(StatusCode::ResourceExhausted)));
            return;
        }
        try {
            // One sentinel byte detects a larger packet even if the kernel
            // truncates a packet to the supplied read size without an error.
            auto allocated = Buffer::allocate(mtu + 1U, mtu + 1U);
            if (!allocated.ok()) {
                invoke(completion, Result<Buffer>(Status(allocated.status().code())));
                return;
            }
            const auto id = next_id.fetch_add(1U, std::memory_order_acq_rel);
            pending_receive.emplace(Receive{id, std::move(allocated).take_value(), std::move(completion), {}});
            auto registered = cancellation.register_callback([weak = weak_from_this(), id]() noexcept {
                if (auto self = weak.lock()) self->request_operation(id, true);
            });
            if (!registered.ok()) {
                settle_receive(Status(registered.status().code()));
                return;
            }
            pending_receive->registration = std::move(registered).take_value();
            const auto bytes = pending_receive->packet.mutable_bytes();
            reader.async_read_some(boost::asio::buffer(bytes.data(), bytes.size()),
                [self = owner, id](const boost::system::error_code& error, std::size_t size) noexcept {
                    self->received(id, error, size);
                });
        } catch (const std::bad_alloc&) {
            fail_receive(completion, StatusCode::ResourceExhausted);
        } catch (...) {
            fail_receive(completion, StatusCode::Internal);
        }
    }

    void send(Buffer packet, CancellationToken cancellation, SendCompletion completion) {
        context->require_context();
        const auto owner = shared_from_this();
        if (!completion) return;
        StatusCode refusal = StatusCode::Ok;
        if (closing.load(std::memory_order_acquire)) refusal = StatusCode::Closed;
        else if (pending_send) refusal = StatusCode::FailedPrecondition;
        else if (packet.empty()) refusal = StatusCode::InvalidArgument;
        else if (packet.size() > mtu) refusal = StatusCode::ResourceExhausted;
        else if (cancellation.is_cancelled()) refusal = StatusCode::Cancelled;
        else if (next_id.load() == std::numeric_limits<std::uint64_t>::max()) refusal = StatusCode::ResourceExhausted;
        if (refusal != StatusCode::Ok) { invoke(completion, Status(refusal), 0U); return; }
        try {
            // A caller's small packet can still retain a large buffer capacity.
            // Bound the storage accepted by this channel, including that case.
            if (packet.max_size() > mtu) {
                auto copied = Buffer::copy_from(packet.bytes(), mtu);
                if (!copied.ok()) { invoke(completion, Status(copied.status().code()), 0U); return; }
                packet = std::move(copied).take_value();
            }
            const auto id = next_id.fetch_add(1U, std::memory_order_acq_rel);
            pending_send.emplace(Send{id, std::move(packet), std::move(completion), {}});
            auto registered = cancellation.register_callback([weak = weak_from_this(), id]() noexcept {
                if (auto self = weak.lock()) self->request_operation(id, false);
            });
            if (!registered.ok()) { settle_send(Status(registered.status().code()), 0U); return; }
            pending_send->registration = std::move(registered).take_value();
            const auto bytes = pending_send->packet.bytes();
            writer.async_write_some(boost::asio::buffer(bytes.data(), bytes.size()),
                [self = owner, id](const boost::system::error_code& error, std::size_t size) noexcept {
                    self->sent(id, error, size);
                });
        } catch (const std::bad_alloc&) {
            fail_send(completion, StatusCode::ResourceExhausted);
        } catch (...) {
            fail_send(completion, StatusCode::Internal);
        }
    }

    Status operation_status(std::uint64_t id, bool receive,
                            const boost::system::error_code& error) noexcept {
        if (closing.load(std::memory_order_acquire)) return Status(StatusCode::Closed);
        if (cancelled(id, receive) || error == boost::asio::error::operation_aborted)
            return Status(StatusCode::Cancelled);
        if (error == boost::asio::error::eof) return Status(StatusCode::Closed);
        if (error == boost::asio::error::message_size) return Status(StatusCode::ResourceExhausted);
        return error ? Status(StatusCode::Internal) : Status::success();
    }

    void received(std::uint64_t id, const boost::system::error_code& error, std::size_t size) noexcept {
        if (!pending_receive || pending_receive->id != id) return;
        auto status = operation_status(id, true, error);
        if (status.ok() && size == 0U) status = Status(StatusCode::Closed);
        if (status.ok() && size > mtu) status = Status(StatusCode::ResourceExhausted);
        if (!status.ok()) { settle_receive(std::move(status)); return; }
        try {
            status = pending_receive->packet.resize(size);
            if (!status.ok()) { settle_receive(std::move(status)); return; }
            auto completion = std::move(pending_receive->completion);
            auto packet = std::move(pending_receive->packet);
            pending_receive.reset();
            invoke(completion, Result<Buffer>(std::move(packet)));
        } catch (...) { settle_receive(Status(StatusCode::Internal)); }
    }

    void sent(std::uint64_t id, const boost::system::error_code& error, std::size_t size) noexcept {
        if (!pending_send || pending_send->id != id) return;
        auto status = operation_status(id, false, error);
        if (status.ok() && size != pending_send->packet.size()) status = Status(StatusCode::Internal);
        // Retrying a short write would turn its suffix into another IP packet.
        settle_send(std::move(status), size);
    }

    void fail_receive(ReceiveCompletion& completion, StatusCode code) noexcept {
        if (pending_receive) settle_receive(Status(code));
        else invoke(completion, Result<Buffer>(Status(code)));
    }
    void fail_send(SendCompletion& completion, StatusCode code) noexcept {
        if (pending_send) settle_send(Status(code), 0U);
        else invoke(completion, Status(code), 0U);
    }
    void settle_receive(Status status) noexcept {
        auto completion = std::move(pending_receive->completion);
        pending_receive.reset();
        invoke(completion, Result<Buffer>(std::move(status)));
    }
    void settle_send(Status status, std::size_t size) noexcept {
        auto completion = std::move(pending_send->completion);
        pending_send.reset();
        invoke(completion, std::move(status), size);
    }

    std::shared_ptr<AsioExecutionContext> context;
    // Duplicated descriptors share one TUN queue but have independent reactor
    // registrations, so cancelling a receive leaves an accepted send intact.
    Descriptor reader;
    Descriptor writer;
    const std::size_t mtu;
    const std::array<char, IFNAMSIZ> name;
    const unsigned int index;
    std::optional<Receive> pending_receive;
    std::optional<Send> pending_send;
    std::atomic<std::uint64_t> next_id{1U};
    // Publish cancel/close and enqueue under one gate. No producer may enqueue
    // after terminal close returns and its final drain has finished.
    std::mutex publication;
    std::atomic<bool> closing{false};
    std::atomic<std::uint64_t> cancel_through{0U};
    std::atomic<std::uint64_t> cancel_receive{0U};
    std::atomic<std::uint64_t> cancel_send{0U};
    ControlTask control;
};

Result<std::unique_ptr<LinuxTunPacketChannel>> LinuxTunPacketChannel::create(
    std::shared_ptr<AsioExecutionContext> context, std::string_view requested_name, std::size_t mtu) {
    using Created = Result<std::unique_ptr<LinuxTunPacketChannel>>;
    if (!context || !valid_name(requested_name) || !valid_mtu(mtu))
        return Created(Status(StatusCode::InvalidArgument));
    OwnedFd owned(::open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW));
    if (owned.get() < 0) return Created(system_failure());
    auto status = verify_tun_file(owned.get());
    if (!status.ok()) return Created(std::move(status));
    struct ifreq request{};
    std::memcpy(request.ifr_name, requested_name.data(), requested_name.size());
    request.ifr_flags = static_cast<short>(IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL);
    if (::ioctl(owned.get(), TUNSETIFF, &request) < 0) return Created(system_failure());
    std::array<char, IFNAMSIZ> name{};
    unsigned int index = 0U;
    status = verify_device(owned.get(), mtu, requested_name, name, index);
    if (!status.ok()) return Created(std::move(status));
    OwnedFd write_fd(::fcntl(owned.get(), F_DUPFD_CLOEXEC, 0));
    if (write_fd.get() < 0) return Created(system_failure());
    try {
        auto state = std::make_shared<State>(std::move(context), mtu, name, index);
        boost::system::error_code error;
        state->reader.assign(owned.get(), error);
        if (error) return Created(Status(StatusCode::Internal));
        owned.release();
        state->writer.assign(write_fd.get(), error);
        if (error) return Created(Status(StatusCode::Internal));
        write_fd.release();
        return Created(std::unique_ptr<LinuxTunPacketChannel>(new LinuxTunPacketChannel(std::move(state))));
    } catch (const std::bad_alloc&) { return Created(Status(StatusCode::ResourceExhausted)); }
    catch (...) { return Created(Status(StatusCode::Internal)); }
}

LinuxTunPacketChannel::LinuxTunPacketChannel(std::shared_ptr<State> state) noexcept : state_(std::move(state)) {}
LinuxTunPacketChannel::~LinuxTunPacketChannel() noexcept { close(); }
std::string_view LinuxTunPacketChannel::interface_name() const noexcept { return state_->name.data(); }
unsigned int LinuxTunPacketChannel::interface_index() const noexcept { return state_->index; }
engine::ExecutorAffinity LinuxTunPacketChannel::executor_affinity() const noexcept { return state_->context->affinity(); }
std::size_t LinuxTunPacketChannel::max_packet_size() const noexcept { return state_->mtu; }
void LinuxTunPacketChannel::async_receive(CancellationToken cancellation, ReceiveCompletion completion) {
    state_->receive(std::move(cancellation), std::move(completion));
}
void LinuxTunPacketChannel::async_send(Buffer packet, CancellationToken cancellation, SendCompletion completion) {
    state_->send(std::move(packet), std::move(cancellation), std::move(completion));
}
void LinuxTunPacketChannel::cancel() noexcept { state_->request(false); }
void LinuxTunPacketChannel::close() noexcept { state_->request(true); }
}  // namespace yume::providers
