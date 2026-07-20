/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * This adapter intentionally includes only the installed public C ABI. It is
 * a benchmark/diagnostic consumer, not an internal client implementation.
 */

#include <yume/yume.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#if defined(__linux__)
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <unistd.h>
#endif

namespace {

constexpr std::size_t kBatchPackets = 64;
constexpr std::size_t kBatchStorageBytes = 128U * 1024U;
constexpr std::uint32_t kIoTimeoutMs = 250;

volatile std::sig_atomic_t g_signal_stop = 0;

void on_signal(int) {
    g_signal_stop = 1;
}

std::string abi_error(const void* handle, int status) {
    std::string message = yume_strerror(status);
    if (handle) {
        if (const char* detail = yume_handle_last_error(handle);
            detail && *detail) {
            message += ": ";
            message += detail;
        }
    }
    return message;
}

struct Runtime {
    int tun_fd{-1};
    yume_packet* packet{nullptr};
    std::atomic<bool> stop{false};
    std::atomic<std::uint64_t> upstream_bytes{0};
    std::atomic<std::uint64_t> downstream_bytes{0};
    std::mutex error_mu;
    std::string error;

    void fail(std::string reason) {
        {
            std::lock_guard<std::mutex> lock(error_mu);
            if (error.empty()) {
                error = std::move(reason);
            }
        }
        stop.store(true, std::memory_order_release);
    }

    std::string failure() {
        std::lock_guard<std::mutex> lock(error_mu);
        return error;
    }
};

std::string packet_status_json(yume_packet* packet) {
    std::size_t needed = 0;
    int status = yume_packet_status_json(packet, nullptr, 0, &needed);
    if (status != YUME_STATUS_BUFFER_TOO_SMALL || needed == 0) {
        throw std::runtime_error(
            "packet status sizing failed: " + abi_error(packet, status));
    }
    std::vector<char> storage(needed);
    status = yume_packet_status_json(
        packet, storage.data(), storage.size(), &needed);
    if (status != YUME_STATUS_OK) {
        throw std::runtime_error(
            "packet status failed: " + abi_error(packet, status));
    }
    return std::string(storage.data());
}

std::uint32_t json_uint(std::string_view json, std::string_view name) {
    const std::string key = "\"" + std::string(name) + "\":";
    const auto start = json.find(key);
    if (start == std::string_view::npos) {
        throw std::runtime_error("packet status is missing " + std::string(name));
    }
    std::size_t offset = start + key.size();
    std::uint64_t value = 0;
    bool have_digit = false;
    while (offset < json.size() && json[offset] >= '0' && json[offset] <= '9') {
        have_digit = true;
        value = value * 10U + static_cast<unsigned>(json[offset] - '0');
        if (value > UINT32_MAX) {
            throw std::runtime_error(
                "packet status " + std::string(name) + " is too large");
        }
        ++offset;
    }
    if (!have_digit) {
        throw std::runtime_error(
            "packet status " + std::string(name) + " is invalid");
    }
    return static_cast<std::uint32_t>(value);
}

#if defined(__linux__)
int attach_tun(const std::string& requested_name, std::string* actual_name) {
    if (requested_name.empty() || requested_name.size() >= IFNAMSIZ) {
        throw std::runtime_error("TUN name is empty or too long");
    }
    const int fd = ::open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        throw std::runtime_error(
            "cannot open /dev/net/tun: " + std::string(std::strerror(errno)));
    }
    struct ifreq request {};
    request.ifr_flags = IFF_TUN | IFF_NO_PI;
    std::memcpy(request.ifr_name, requested_name.data(), requested_name.size());
    if (::ioctl(fd, TUNSETIFF, &request) < 0) {
        const std::string reason = std::strerror(errno);
        ::close(fd);
        throw std::runtime_error(
            "cannot attach TUN " + requested_name + ": " + reason);
    }
    if (actual_name) {
        *actual_name = request.ifr_name;
    }
    return fd;
}

int poll_fd(int fd, short events, int timeout_ms) {
    struct pollfd item {};
    item.fd = fd;
    item.events = events;
    while (true) {
        const int result = ::poll(&item, 1, timeout_ms);
        if (result > 0) {
            if ((item.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                return -1;
            }
            return (item.revents & events) != 0 ? 1 : 0;
        }
        if (result == 0) {
            return false;
        }
        if (errno != EINTR) {
            return false;
        }
    }
}

void upstream_loop(Runtime* runtime, std::size_t mtu) {
    std::vector<std::vector<std::uint8_t>> packets(
        kBatchPackets, std::vector<std::uint8_t>(mtu));
    std::vector<const void*> pointers(kBatchPackets);
    std::vector<std::size_t> lengths(kBatchPackets);

    while (!runtime->stop.load(std::memory_order_acquire)) {
        const int ready = poll_fd(
            runtime->tun_fd, POLLIN, static_cast<int>(kIoTimeoutMs));
        if (ready < 0) {
            runtime->fail("TUN disappeared while waiting for input");
            return;
        }
        if (ready == 0) {
            continue;
        }
        std::size_t count = 0;
        while (count < kBatchPackets) {
            const ssize_t size = ::read(
                runtime->tun_fd, packets[count].data(), packets[count].size());
            if (size > 0) {
                pointers[count] = packets[count].data();
                lengths[count] = static_cast<std::size_t>(size);
                ++count;
                continue;
            }
            if (size < 0 && errno == EINTR) {
                continue;
            }
            if (size < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                break;
            }
            if (size == 0) {
                runtime->fail("TUN disappeared while reading");
            } else {
                runtime->fail(
                    "TUN read failed: " + std::string(std::strerror(errno)));
            }
            return;
        }
        if (count == 0) {
            continue;
        }

        while (!runtime->stop.load(std::memory_order_acquire)) {
            const int status = yume_packet_write_batch(
                runtime->packet, pointers.data(), lengths.data(), count,
                kIoTimeoutMs);
            if (runtime->stop.load(std::memory_order_acquire)) {
                return;
            }
            if (status == YUME_STATUS_OK) {
                std::uint64_t bytes = 0;
                for (std::size_t i = 0; i < count; ++i) {
                    bytes += lengths[i];
                }
                runtime->upstream_bytes.fetch_add(
                    bytes, std::memory_order_relaxed);
                break;
            }
            if (status == YUME_STATUS_TIMEOUT ||
                status == YUME_STATUS_WOULD_BLOCK) {
                continue;
            }
            runtime->fail(
                "packet ABI write failed: " + abi_error(runtime->packet, status));
            return;
        }
    }
}

bool write_tun_packet(Runtime* runtime,
                      const std::uint8_t* data,
                      std::size_t size) {
    while (!runtime->stop.load(std::memory_order_acquire)) {
        const ssize_t written = ::write(runtime->tun_fd, data, size);
        if (written == static_cast<ssize_t>(size)) {
            return true;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (poll_fd(runtime->tun_fd, POLLOUT,
                        static_cast<int>(kIoTimeoutMs)) < 0) {
                runtime->fail("TUN disappeared while waiting for output");
                return false;
            }
            continue;
        }
        runtime->fail(
            written >= 0
                ? "TUN performed a partial packet write"
                : "TUN write failed: " + std::string(std::strerror(errno)));
        return false;
    }
    return false;
}

void downstream_loop(Runtime* runtime) {
    std::vector<std::uint8_t> storage(kBatchStorageBytes);
    std::vector<std::size_t> offsets(kBatchPackets);
    std::vector<std::size_t> lengths(kBatchPackets);

    while (!runtime->stop.load(std::memory_order_acquire)) {
        std::size_t count = 0;
        std::size_t required = 0;
        const int status = yume_packet_read_batch(
            runtime->packet,
            storage.data(), storage.size(),
            offsets.data(), lengths.data(), offsets.size(),
            &count, &required, kIoTimeoutMs);
        if (runtime->stop.load(std::memory_order_acquire)) {
            return;
        }
        if (status == YUME_STATUS_TIMEOUT || status == YUME_STATUS_WOULD_BLOCK) {
            continue;
        }
        if (status != YUME_STATUS_OK) {
            std::string reason =
                "packet ABI read failed: " + abi_error(runtime->packet, status);
            if (status == YUME_STATUS_BUFFER_TOO_SMALL) {
                reason += " (required=" + std::to_string(required) + ")";
            }
            runtime->fail(std::move(reason));
            return;
        }
        for (std::size_t i = 0; i < count; ++i) {
            if (offsets[i] > storage.size() ||
                lengths[i] > storage.size() - offsets[i]) {
                runtime->fail("packet ABI returned an invalid caller-buffer range");
                return;
            }
            if (!write_tun_packet(
                    runtime, storage.data() + offsets[i], lengths[i])) {
                return;
            }
            runtime->downstream_bytes.fetch_add(
                lengths[i], std::memory_order_relaxed);
        }
    }
}
#endif

struct Options {
    std::string config;
    std::string tun_name;
    std::uint32_t timeout_ms{30000};
};

Options parse_args(int argc, char** argv) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto take = [&](const char* name) -> std::string {
            if (++i >= argc) {
                throw std::runtime_error(std::string(name) + " requires a value");
            }
            return argv[i];
        };
        if (arg == "--config") {
            options.config = take("--config");
        } else if (arg == "--tun") {
            options.tun_name = take("--tun");
        } else if (arg == "--timeout-ms") {
            const std::string value = take("--timeout-ms");
            std::size_t consumed = 0;
            const unsigned long parsed = std::stoul(value, &consumed);
            if (consumed != value.size() || parsed == 0 || parsed > UINT32_MAX) {
                throw std::runtime_error("--timeout-ms must be 1..4294967295");
            }
            options.timeout_ms = static_cast<std::uint32_t>(parsed);
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: yume-abi-tun --config FILE --tun IFNAME"
                         " [--timeout-ms N]\n"
                         "Attaches an operator-created Linux IFF_TUN|IFF_NO_PI"
                         " interface through only libyume's public packet ABI.\n";
            std::exit(0);
        } else {
            throw std::runtime_error("unknown option: " + arg);
        }
    }
    if (options.config.empty() || options.tun_name.empty()) {
        throw std::runtime_error("--config and --tun are required");
    }
    return options;
}

}  // namespace

int main(int argc, char** argv) {
#if !defined(__linux__)
    (void)argc;
    (void)argv;
    std::cerr << "yume-abi-tun is supported only on Linux\n";
    return 1;
#else
    yume_client* client = nullptr;
    yume_packet* packet = nullptr;
    int tun_fd = -1;
    try {
        const Options options = parse_args(argc, argv);
        std::signal(SIGINT, on_signal);
        std::signal(SIGTERM, on_signal);

        client = yume_client_create();
        if (!client) {
            throw std::runtime_error("cannot allocate YUME client");
        }
        int status = yume_client_start_file(
            client, options.config.c_str(), options.timeout_ms);
        if (status != YUME_STATUS_OK) {
            throw std::runtime_error(
                "client start failed: " + abi_error(client, status));
        }
        status = yume_client_open_packet(client, options.timeout_ms, &packet);
        if (status != YUME_STATUS_OK) {
            throw std::runtime_error(
                "packet open failed: " + abi_error(client, status));
        }

        const std::string status_json = packet_status_json(packet);
        const std::uint32_t mtu = json_uint(status_json, "mtu");
        if (mtu < 576 || mtu > 65535) {
            throw std::runtime_error("server assigned an invalid packet MTU");
        }
        std::string actual_tun;
        tun_fd = attach_tun(options.tun_name, &actual_tun);

        std::cout << "packet_status=" << status_json << "\n"
                  << "adapter=public-c-abi tun=" << actual_tun
                  << " mtu=" << mtu << "\n"
                  << "YUME does not configure the interface, address, routes, DNS,"
                     " firewall, or NAT. Press Ctrl-C to stop.\n";

        Runtime runtime;
        runtime.tun_fd = tun_fd;
        runtime.packet = packet;
        std::thread upstream([&runtime, mtu] {
            try {
                upstream_loop(&runtime, mtu);
            } catch (const std::exception& ex) {
                runtime.fail(std::string("upstream adapter failed: ") + ex.what());
            }
        });
        std::thread downstream([&runtime] {
            try {
                downstream_loop(&runtime);
            } catch (const std::exception& ex) {
                runtime.fail(std::string("downstream adapter failed: ") + ex.what());
            }
        });

        auto last = std::chrono::steady_clock::now();
        std::uint64_t last_up = 0;
        std::uint64_t last_down = 0;
        while (!g_signal_stop &&
               !runtime.stop.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            const auto now = std::chrono::steady_clock::now();
            if (now - last < std::chrono::seconds(5)) {
                continue;
            }
            const auto up = runtime.upstream_bytes.load(std::memory_order_relaxed);
            const auto down = runtime.downstream_bytes.load(std::memory_order_relaxed);
            const double seconds = std::chrono::duration<double>(now - last).count();
            std::cout << "ABI-TUN up="
                      << ((up - last_up) * 8.0 / seconds / 1'000'000.0)
                      << " Mbit/s down="
                      << ((down - last_down) * 8.0 / seconds / 1'000'000.0)
                      << " Mbit/s\n";
            last = now;
            last_up = up;
            last_down = down;
        }

        runtime.stop.store(true, std::memory_order_release);
        (void)yume_packet_close(packet);
        if (upstream.joinable()) upstream.join();
        if (downstream.joinable()) downstream.join();
        const std::string failure = runtime.failure();

        ::close(tun_fd);
        tun_fd = -1;
        yume_packet_destroy(packet);
        packet = nullptr;
        (void)yume_client_stop(client);
        yume_client_destroy(client);
        client = nullptr;
        if (!failure.empty()) {
            std::cerr << failure << "\n";
            return 1;
        }
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "yume-abi-tun: " << ex.what() << "\n";
        if (tun_fd >= 0) ::close(tun_fd);
        if (packet) {
            (void)yume_packet_close(packet);
            yume_packet_destroy(packet);
        }
        if (client) {
            (void)yume_client_stop(client);
            yume_client_destroy(client);
        }
        return 1;
    }
#endif
}
