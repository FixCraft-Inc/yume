/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/packet/tun_adapter.hpp"

#include <chrono>
#include <mutex>
#include <thread>
#include <vector>

#include "client/packet/channel.hpp"

#if defined(__linux__)
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace yume::client::packet {

#if defined(__linux__)
namespace {

class UniqueFd {
public:
    explicit UniqueFd(int fd = -1) noexcept : fd_(fd) {}
    ~UniqueFd() { reset(); }
    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;
    int get() const noexcept { return fd_; }
    int release() noexcept { const int fd = fd_; fd_ = -1; return fd; }
    void reset(int fd = -1) noexcept {
        if (fd_ >= 0) ::close(fd_);
        fd_ = fd;
    }
private:
    int fd_{-1};
};

bool interface_exists(const std::string& name) {
    UniqueFd socket_fd(::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    if (socket_fd.get() < 0) return false;
    struct ifreq request {};
    std::snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", name.c_str());
    return ::ioctl(socket_fd.get(), SIOCGIFINDEX, &request) == 0;
}

int attach_tun(const std::string& name, std::string* error) {
    if (name.empty() || name.size() >= IFNAMSIZ) {
        if (error) *error = "packet TUN name is empty or too long";
        return -1;
    }
    if (!interface_exists(name)) {
        if (error) *error = "packet TUN does not exist: " + name;
        return -1;
    }
    UniqueFd fd(::open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC));
    if (fd.get() < 0) {
        if (error) *error = "cannot open /dev/net/tun: " + std::string(std::strerror(errno));
        return -1;
    }
    struct ifreq request {};
    request.ifr_flags = IFF_TUN | IFF_NO_PI;
    std::snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", name.c_str());
    if (::ioctl(fd.get(), TUNSETIFF, &request) < 0) {
        if (error) {
            *error = "cannot attach packet TUN " + name + ": " +
                     std::string(std::strerror(errno));
        }
        return -1;
    }
    if (name != request.ifr_name) {
        if (error) *error = "kernel attached an unexpected packet TUN";
        return -1;
    }
    return fd.release();
}

}  // namespace
#endif

int run_packet_tun_adapter(const std::string& interface_name,
                           const std::shared_ptr<PacketChannel>& channel,
                           std::atomic<bool>& stop_requested,
                           std::string* error) {
#if !defined(__linux__)
    (void)interface_name;
    (void)channel;
    (void)stop_requested;
    if (error) *error = "--packet-tun is supported only on Linux";
    return 1;
#else
    if (!channel) {
        if (error) *error = "packet channel is unavailable";
        return 1;
    }
    UniqueFd tun(attach_tun(interface_name, error));
    if (tun.get() < 0) return 1;

    std::atomic<bool> failed{false};
    std::mutex failure_mu;
    std::string failure_reason;
    auto fail = [&](std::string reason) {
        {
            std::lock_guard<std::mutex> lock(failure_mu);
            if (failure_reason.empty()) failure_reason = std::move(reason);
        }
        failed.store(true, std::memory_order_release);
    };

    const auto mtu = channel->assignment().mtu;
    std::thread reader([&] {
        Bytes packet(mtu);
        while (!stop_requested.load(std::memory_order_acquire) &&
               !failed.load(std::memory_order_acquire)) {
            struct pollfd poll_fd {tun.get(), POLLIN, 0};
            const int ready = ::poll(&poll_fd, 1, 100);
            if (ready < 0) {
                if (errno == EINTR) continue;
                fail("packet TUN poll failed: " + std::string(std::strerror(errno)));
                break;
            }
            if (ready == 0) continue;
            if ((poll_fd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                fail("packet TUN disappeared while reading");
                break;
            }
            const ssize_t bytes = ::read(tun.get(), packet.data(), packet.size());
            if (bytes < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
                fail("packet TUN read failed: " + std::string(std::strerror(errno)));
                break;
            }
            if (bytes == 0) {
                fail("packet TUN returned end-of-file");
                break;
            }
            std::vector<Bytes> one;
            one.emplace_back(packet.begin(), packet.begin() + bytes);
            std::string reason;
            const auto queued = channel->write_packets(one, &reason);
            if (queued == QueueResult::would_block) {
                fail("packet channel outbound queue saturated");
                break;
            }
            if (queued != QueueResult::ok) {
                fail(reason.empty() ? "packet channel write failed" : reason);
                break;
            }
        }
    });

    std::thread writer([&] {
        while (!stop_requested.load(std::memory_order_acquire) &&
               !failed.load(std::memory_order_acquire)) {
            std::vector<Bytes> packets;
            std::size_t required = 0;
            const auto result = channel->read_packets(
                protocol::packet_bulk::kMaxPacketsPerBatch,
                protocol::packet_bulk::kDefaultMaxBatchBytes,
                std::chrono::milliseconds(100), &packets, &required);
            if (result == QueueResult::timeout || result == QueueResult::would_block) continue;
            if (result != QueueResult::ok) {
                fail(result == QueueResult::buffer_too_small
                    ? "packet TUN receive buffer is too small: " + std::to_string(required)
                    : "packet channel stopped while reading");
                break;
            }
            for (const auto& packet : packets) {
                struct pollfd poll_fd {tun.get(), POLLOUT, 0};
                const int ready = ::poll(&poll_fd, 1, 1000);
                if (ready <= 0 || (poll_fd.revents & POLLOUT) == 0) {
                    fail("packet TUN write timed out or device disappeared");
                    break;
                }
                const ssize_t bytes = ::write(tun.get(), packet.data(), packet.size());
                if (bytes < 0) {
                    fail("packet TUN write failed: " + std::string(std::strerror(errno)));
                    break;
                }
                if (static_cast<std::size_t>(bytes) != packet.size()) {
                    fail("packet TUN produced a partial packet write");
                    break;
                }
            }
        }
    });

    while (!stop_requested.load(std::memory_order_acquire) &&
           !failed.load(std::memory_order_acquire) &&
           !channel->stats().stopped) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    channel->close(failed.load() ? "packet TUN adapter failed" : "packet TUN adapter stopping");
    if (reader.joinable()) reader.join();
    if (writer.joinable()) writer.join();
    if (failed.load()) {
        std::lock_guard<std::mutex> lock(failure_mu);
        if (error) *error = failure_reason;
        return 1;
    }
    return 0;
#endif
}

}  // namespace yume::client::packet
