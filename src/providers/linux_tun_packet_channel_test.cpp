/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/linux_tun_packet_channel.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdarg>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <utility>

#include <dirent.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <boost/asio/post.hpp>

#define YUME_TEST_ALIGNED_ALLOCATIONS 1
#include "test_support/allocation_failure.hpp"

namespace {
using namespace yume::engine;
using namespace yume::providers;
#define CHECK(value) do { if (!(value)) throw std::runtime_error("check failed: " #value); } while (false)

// Only the TUN control boundary is replaced. Asio uses the real descriptor and
// reactor on a SOCK_DGRAM pair, including real backpressure and cancellation.
struct Device final {
    int original{-1};
    int opened{-1};
    int peer{-1};
    bool char_device{true};
    unsigned short flags{IFF_TUN | IFF_NO_PI};
    const char* name{"testtun0"};
    int mtu{1500};
    int index{42};
    unsigned long fail_ioctl{0};
    int fail_errno{EPERM};
    unsigned int creates{0};
    unsigned int mutations{0};
    unsigned int opens{0};
    unsigned short creation_flags{0};
    int open_flags{0};
    bool short_write{false};
};
Device* device = nullptr;

template <typename T> T require(Result<T> result) {
    if (!result.ok()) throw std::runtime_error("require failed with status " +
        std::to_string(static_cast<unsigned int>(result.status().code())));
    return std::move(result).take_value();
}

std::size_t descriptor_count() {
    DIR* directory = ::opendir("/proc/self/fd");
    CHECK(directory != nullptr);
    std::size_t count = 0;
    while (::readdir(directory)) ++count;
    ::closedir(directory);
    return count;
}

struct Fixture final {
    Fixture() {
        CHECK(device == nullptr);
        int pair[2]{};
        CHECK(::socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
        fake.original = pair[0];
        fake.peer = pair[1];
        device = &fake;
        context = require(AsioExecutionContext::create(ExecutorAffinity(0x54554eU)));
    }
    ~Fixture() noexcept {
        channel.reset();
        context->finish();
        try { context->run(); } catch (...) { std::terminate(); }
        device = nullptr;
        ::close(fake.original);
        ::close(fake.peer);
    }
    void create() { channel = require(LinuxTunPacketChannel::create(context, "testtun0", 1500U)); }
    template <typename Function> void on_context(Function function) {
        boost::asio::post(context->executor(), std::move(function));
        context->poll();
    }
    Buffer packet(std::size_t size = 84U, std::size_t capacity = 1500U) {
        auto value = require(Buffer::allocate(size, capacity));
        std::fill(value.mutable_bytes().begin(), value.mutable_bytes().end(), std::byte{0x45});
        return value;
    }
    void inject(std::size_t size) {
        std::array<std::byte, 4096> packet{};
        CHECK(size <= packet.size());
        const auto sent = ::send(fake.peer, packet.data(), size, 0);
        if (sent != static_cast<ssize_t>(size)) throw std::runtime_error(
            "packet injection failed: " + std::to_string(sent) + " errno " + std::to_string(errno));
    }
    void fill_output() {
        int size = 4096;
        CHECK(::setsockopt(fake.original, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0);
        std::array<std::byte, 1500> packet{};
        while (::send(fake.original, packet.data(), packet.size(), 0) >= 0) {}
        CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
    }
    void drain_output() {
        std::array<std::byte, 4096> bytes{};
        while (::recv(fake.peer, bytes.data(), bytes.size(), 0) >= 0) {}
        CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
    }
    Device fake;
    std::shared_ptr<AsioExecutionContext> context;
    std::unique_ptr<LinuxTunPacketChannel> channel;
};

void creation_boundary() {
    Fixture fixture;
    for (const auto name : {"", ".", "..", "tun%d", "a/b", "bad name", "0123456789abcdef"}) {
        auto result = LinuxTunPacketChannel::create(fixture.context, name, 1500U);
        CHECK(!result.ok() && result.status().code() == StatusCode::InvalidArgument);
    }
    for (const auto mtu : {0U, 575U, 65536U}) {
        CHECK(!LinuxTunPacketChannel::create(fixture.context, "testtun0", mtu).ok());
    }
    CHECK(!LinuxTunPacketChannel::create({}, "testtun0", 1500U).ok());
    CHECK(fixture.fake.opens == 0U);

    const auto baseline = descriptor_count();
    fixture.fake.char_device = false;
    CHECK(!LinuxTunPacketChannel::create(fixture.context, "testtun0", 1500U).ok());
    CHECK(fixture.fake.creates == 0U);
    CHECK(descriptor_count() == baseline);
    fixture.fake.char_device = true;

    fixture.fake.fail_ioctl = TUNSETIFF;
    fixture.fake.fail_errno = EBUSY;
    auto existing = LinuxTunPacketChannel::create(fixture.context, "testtun0", 1500U);
    CHECK(!existing.ok() && existing.status().code() == StatusCode::AlreadyExists);
    CHECK(fixture.fake.mutations == 0U);
    CHECK(descriptor_count() == baseline);
    fixture.fake.fail_ioctl = 0;

    for (const unsigned short flag : {IFF_TAP, IFF_VNET_HDR, IFF_MULTI_QUEUE, IFF_PERSIST}) {
        fixture.fake.flags = static_cast<unsigned short>(IFF_TUN | IFF_NO_PI | flag);
        CHECK(!LinuxTunPacketChannel::create(fixture.context, "testtun0", 1500U).ok());
        CHECK(descriptor_count() == baseline);
    }
    fixture.fake.flags = IFF_TUN;
    CHECK(!LinuxTunPacketChannel::create(fixture.context, "testtun0", 1500U).ok());
    fixture.fake.flags = IFF_TUN | IFF_NO_PI;
    fixture.fake.name = "wrongtun";
    CHECK(!LinuxTunPacketChannel::create(fixture.context, "testtun0", 1500U).ok());
    fixture.fake.name = "testtun0";
    fixture.fake.mtu = 1400;
    CHECK(!LinuxTunPacketChannel::create(fixture.context, "testtun0", 1500U).ok());
    fixture.fake.mtu = 1500;
    fixture.fake.index = 0;
    CHECK(!LinuxTunPacketChannel::create(fixture.context, "testtun0", 1500U).ok());
    fixture.fake.index = 42;
    for (const auto request : {TUNGETIFF, static_cast<unsigned long>(SIOCSIFMTU),
                               static_cast<unsigned long>(SIOCGIFMTU), static_cast<unsigned long>(SIOCGIFINDEX)}) {
        fixture.fake.fail_ioctl = request;
        CHECK(!LinuxTunPacketChannel::create(fixture.context, "testtun0", 1500U).ok());
        CHECK(descriptor_count() == baseline);
    }
    fixture.fake.fail_ioctl = 0;
    fixture.create();
    CHECK(fixture.channel->interface_name() == "testtun0");
    CHECK(fixture.channel->interface_index() == 42U);
    CHECK(fixture.channel->max_packet_size() == 1500U);
    CHECK(fixture.channel->executor_affinity() == fixture.context->affinity());
    CHECK(fixture.fake.creation_flags == (IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL));
    CHECK((fixture.fake.open_flags & (O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW)) ==
          (O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW));
    CHECK((::fcntl(fixture.fake.opened, F_GETFD) & FD_CLOEXEC) != 0);
    CHECK((::fcntl(fixture.fake.opened, F_GETFL) & O_NONBLOCK) != 0);
}

void packet_io_and_bounds() {
    Fixture fixture;
    fixture.create();
    bool wrong_affinity = false;
    try { fixture.channel->async_receive({}, [](Result<Buffer>) {}); }
    catch (const std::logic_error&) { wrong_affinity = true; }
    CHECK(wrong_affinity);
    std::size_t received = 0;
    std::size_t sent = 0;
    fixture.on_context([&] {
        fixture.channel->async_receive({}, [&](Result<Buffer> packet) {
            CHECK(packet.ok() && packet.value().size() == 120U);
            ++received;
        });
        fixture.channel->async_receive({}, [&](Result<Buffer> packet) {
            CHECK(!packet.ok() && packet.status().code() == StatusCode::FailedPrecondition);
            ++received;
        });
        fixture.channel->async_send(fixture.packet(84U, 65535U), {}, [&](Status status, std::size_t size) {
            CHECK(status.ok() && size == 84U);
            ++sent;
        });
    });
    fixture.inject(120U);
    fixture.context->poll();
    CHECK(received == 2U && sent == 1U);
    std::array<std::byte, 1600> bytes{};
    CHECK(::recv(fixture.fake.peer, bytes.data(), bytes.size(), 0) == 84);
    CHECK(bytes[0] == std::byte{0x45});

    fixture.on_context([&] {
        fixture.channel->async_receive({}, [&](Result<Buffer> packet) {
            CHECK(!packet.ok() && packet.status().code() == StatusCode::ResourceExhausted);
            ++received;
        });
        fixture.channel->async_send(fixture.packet(1501U, 1501U), {}, [&](Status status, std::size_t size) {
            CHECK(status.code() == StatusCode::ResourceExhausted && size == 0U);
            ++sent;
        });
        fixture.channel->async_send(fixture.packet(0U), {}, [&](Status status, std::size_t size) {
            CHECK(status.code() == StatusCode::InvalidArgument && size == 0U);
            ++sent;
        });
    });
    fixture.inject(1700U);
    fixture.context->poll();
    CHECK(received == 3U && sent == 3U);
}

void independent_cancellation_and_reentry() {
    Fixture fixture;
    fixture.create();
    fixture.fill_output();
    CancellationSource receive_cancel;
    unsigned int receives = 0;
    unsigned int sends = 0;
    fixture.on_context([&] {
        fixture.channel->async_receive(receive_cancel.token(), [&](Result<Buffer> result) {
            CHECK(!result.ok() && result.status().code() == StatusCode::Cancelled);
            ++receives;
            fixture.channel->async_receive({}, [&](Result<Buffer> next) {
                CHECK(next.ok() && next.value().size() == 100U);
                ++receives;
                throw std::runtime_error("consumer exception");
            });
        });
        fixture.channel->async_send(fixture.packet(), {}, [&](Status status, std::size_t size) {
            CHECK(status.ok() && size == 84U);
            ++sends;
        });
        fixture.channel->async_send(fixture.packet(), {}, [&](Status status, std::size_t size) {
            CHECK(status.code() == StatusCode::FailedPrecondition && size == 0U);
            ++sends;
        });
    });
    std::thread canceller([&] { receive_cancel.cancel(); });
    canceller.join();
    fixture.context->poll();
    CHECK(receives == 1U && sends == 1U);
    fixture.drain_output();
    fixture.inject(100U);
    fixture.context->poll();
    CHECK(receives == 2U && sends == 2U);
}

void cancel_and_close_during_allocation_failure() {
    Fixture fixture;
    fixture.create();
    fixture.fill_output();
    unsigned int completions = 0;
    fixture.on_context([&] {
        fixture.channel->async_receive({}, [&](Result<Buffer> result) {
            CHECK(!result.ok() && result.status().code() == StatusCode::Cancelled);
            ++completions;
        });
        fixture.channel->async_send(fixture.packet(), {}, [&](Status status, std::size_t) {
            CHECK(status.code() == StatusCode::Cancelled);
            ++completions;
        });
    });
    yume::test::fail_allocations.store(true);
    fixture.channel->cancel();
    fixture.context->poll();
    yume::test::fail_allocations.store(false);
    CHECK(completions == 2U);
    fixture.on_context([&] {
        fixture.channel->async_receive({}, [&](Result<Buffer> result) {
            CHECK(!result.ok() && result.status().code() == StatusCode::Closed);
            CHECK(fixture.context->running_in_this_thread());
            ++completions;
        });
        fixture.channel->async_send(fixture.packet(), {}, [&](Status status, std::size_t) {
            CHECK(status.code() == StatusCode::Closed);
            ++completions;
        });
    });
    const int owned = fixture.fake.opened;
    yume::test::fail_allocations.store(true);
    fixture.channel.reset();
    fixture.context->poll();
    yume::test::fail_allocations.store(false);
    CHECK(completions == 4U);
    CHECK(::fcntl(owned, F_GETFD) < 0 && errno == EBADF);
}

void short_writes_and_precancelled_operations() {
    Fixture fixture;
    fixture.create();
    CancellationSource cancellation;
    cancellation.cancel();
    unsigned int completions = 0;
    fixture.on_context([&] {
        fixture.channel->async_receive(cancellation.token(), [&](Result<Buffer> result) {
            CHECK(!result.ok() && result.status().code() == StatusCode::Cancelled);
            ++completions;
        });
        fixture.channel->async_send(fixture.packet(), cancellation.token(), [&](Status status, std::size_t size) {
            CHECK(status.code() == StatusCode::Cancelled && size == 0U);
            ++completions;
        });
        fixture.fake.short_write = true;
        fixture.channel->async_send(fixture.packet(), {}, [&](Status status, std::size_t size) {
            CHECK(status.code() == StatusCode::Internal && size == 83U);
            ++completions;
        });
    });
    CHECK(completions == 3U);
    std::array<std::byte, 1500> bytes{};
    CHECK(::recv(fixture.fake.peer, bytes.data(), bytes.size(), 0) == 83);
    CHECK(::recv(fixture.fake.peer, bytes.data(), bytes.size(), 0) < 0 && errno == EAGAIN);
}

void allocation_rollback() {
    unsigned int failed_creates = 0;
    for (std::size_t nth = 1U; nth < 32U; ++nth) {
        Fixture fixture;
        // Initialize the reactor before recording descriptors that belong to it.
        fixture.create();
        fixture.channel.reset();
        fixture.context->poll();
        const auto baseline = descriptor_count();
        yume::test::arm_allocation_failure(nth);
        auto created = LinuxTunPacketChannel::create(fixture.context, "testtun0", 1500U);
        const bool fired = yume::test::disarm_allocation_failure();
        if (fired) {
            CHECK(!created.ok() && created.status().code() == StatusCode::ResourceExhausted);
            ++failed_creates;
            CHECK(descriptor_count() == baseline);
        } else {
            fixture.channel = require(std::move(created));
            break;
        }
    }
    CHECK(failed_creates >= 2U);
    unsigned int failed_receives = 0;
    for (std::size_t nth = 1U; nth < 32U; ++nth) {
        Fixture fixture;
        fixture.create();
        CancellationSource cancellation;
        unsigned int completions = 0;
        bool fired = false;
        fixture.on_context([&] {
            PacketChannel::ReceiveCompletion completion = [&](Result<Buffer> result) {
                CHECK(!result.ok());
                CHECK(result.status().code() == StatusCode::ResourceExhausted ||
                      result.status().code() == StatusCode::Closed);
                ++completions;
            };
            yume::test::arm_allocation_failure(nth);
            fixture.channel->async_receive(cancellation.token(), std::move(completion));
            fired = yume::test::disarm_allocation_failure();
        });
        fixture.channel->close();
        fixture.context->poll();
        CHECK(completions == 1U);
        if (!fired) break;
        ++failed_receives;
    }
    CHECK(failed_receives >= 3U);
    unsigned int failed_sends = 0;
    for (std::size_t nth = 1U; nth < 32U; ++nth) {
        Fixture fixture;
        fixture.create();
        fixture.fill_output();
        CancellationSource cancellation;
        unsigned int completions = 0;
        bool fired = false;
        fixture.on_context([&] {
            auto packet = fixture.packet(84U, 65535U);
            PacketChannel::SendCompletion completion = [&](Status status, std::size_t) {
                CHECK(status.code() == StatusCode::ResourceExhausted || status.code() == StatusCode::Closed);
                ++completions;
            };
            yume::test::arm_allocation_failure(nth);
            fixture.channel->async_send(std::move(packet), cancellation.token(), std::move(completion));
            fired = yume::test::disarm_allocation_failure();
        });
        fixture.channel->close();
        fixture.context->poll();
        CHECK(completions == 1U);
        if (!fired) break;
        ++failed_sends;
    }
    CHECK(failed_sends >= 3U);
}
}  // namespace

extern "C" int __real_open(const char*, int, ...);
extern "C" int __real_fstat(int, struct stat*);
extern "C" int __real_ioctl(int, unsigned long, ...);
extern "C" int __real_socket(int, int, int);
extern "C" ssize_t __real_write(int, const void*, std::size_t);

extern "C" ssize_t __wrap_write(int fd, const void* bytes, std::size_t size) {
    // Match the owned TUN queue's socket inode, including the write duplicate.
    // Other writes (the Asio mailbox, diagnostics) keep their normal behavior.
    if (device && device->short_write && size != 0U) {
        struct stat target{}, source{};
        if (__real_fstat(fd, &target) == 0 && __real_fstat(device->original, &source) == 0 &&
            target.st_dev == source.st_dev && target.st_ino == source.st_ino) {
            device->short_write = false;
            return __real_write(fd, bytes, size - 1U);
        }
    }
    return __real_write(fd, bytes, size);
}

extern "C" int __wrap_socket(int domain, int type, int protocol) {
    if (device && domain == AF_INET && type == (SOCK_DGRAM | SOCK_CLOEXEC) && protocol == 0)
        return __real_socket(AF_UNIX, type, protocol);
    return __real_socket(domain, type, protocol);
}

extern "C" int __wrap_open(const char* path, int flags, ...) {
    if (device && std::strcmp(path, "/dev/net/tun") == 0) {
        ++device->opens;
        device->open_flags = flags;
        device->opened = ::fcntl(device->original, F_DUPFD_CLOEXEC, 0);
        return device->opened;
    }
    if ((flags & O_CREAT) != 0) {
        va_list args;
        va_start(args, flags);
        const auto mode = va_arg(args, mode_t);
        va_end(args);
        return __real_open(path, flags, mode);
    }
    return __real_open(path, flags);
}

extern "C" int __wrap_fstat(int fd, struct stat* info) {
    const int result = __real_fstat(fd, info);
    if (result == 0 && device && fd == device->opened && device->char_device) {
        info->st_mode = S_IFCHR | 0600;
        info->st_rdev = makedev(10, 200);
    }
    return result;
}

extern "C" int __wrap_ioctl(int fd, unsigned long request, ...) {
    va_list args;
    va_start(args, request);
    void* argument = va_arg(args, void*);
    va_end(args);
    if (device && (request == TUNSETIFF || request == TUNGETIFF || request == SIOCSIFMTU ||
                   request == SIOCGIFMTU || request == SIOCGIFINDEX)) {
        auto* interface = static_cast<struct ifreq*>(argument);
        if (request == TUNSETIFF) {
            ++device->creates;
            device->creation_flags = static_cast<unsigned short>(interface->ifr_flags);
        }
        if (request == device->fail_ioctl) { errno = device->fail_errno; return -1; }
        if (request == TUNGETIFF) {
            std::strncpy(interface->ifr_name, device->name, IFNAMSIZ);
            interface->ifr_flags = static_cast<short>(device->flags);
        } else if (request == SIOCGIFMTU) interface->ifr_mtu = device->mtu;
        else if (request == SIOCGIFINDEX) interface->ifr_ifindex = device->index;
        else if (request == SIOCSIFMTU) ++device->mutations;
        return 0;
    }
    return __real_ioctl(fd, request, argument);
}

int main() {
    try {
        creation_boundary();
        packet_io_and_bounds();
        independent_cancellation_and_reentry();
        cancel_and_close_during_allocation_failure();
        short_writes_and_precancelled_operations();
        allocation_rollback();
        std::cout << "Linux TUN packet channel tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        yume::test::fail_allocations.store(false);
        std::cerr << error.what() << '\n';
        return 1;
    }
}
