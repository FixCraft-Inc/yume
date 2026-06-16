/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "server/packet/tun_egress.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <stdexcept>
#include <unordered_map>
#include <utility>

#include "util.hpp"

#if defined(__linux__)
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <boost/asio/posix/stream_descriptor.hpp>
#endif

namespace yume::server {

namespace {

std::uint32_t read_be32(const std::uint8_t* data) {
    return (static_cast<std::uint32_t>(data[0]) << 24) |
           (static_cast<std::uint32_t>(data[1]) << 16) |
           (static_cast<std::uint32_t>(data[2]) << 8) |
           static_cast<std::uint32_t>(data[3]);
}

std::uint16_t read_be16(const std::uint8_t* data) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[0]) << 8) |
                                      static_cast<std::uint16_t>(data[1]));
}

std::string ipv4_to_string(std::uint32_t value) {
    return std::to_string((value >> 24) & 0xff) + "." +
           std::to_string((value >> 16) & 0xff) + "." +
           std::to_string((value >> 8) & 0xff) + "." +
           std::to_string(value & 0xff);
}

std::optional<std::uint32_t> parse_ipv4(const std::string& text) {
    boost::system::error_code ec;
    const auto address = boost::asio::ip::make_address(text, ec);
    if (ec || !address.is_v4()) {
        return std::nullopt;
    }
    const auto bytes = address.to_v4().to_bytes();
    return read_be32(bytes.data());
}

struct ParsedCidr {
    std::uint32_t network{0};
    std::uint32_t first_client{0};
    std::uint32_t last_client{0};
};

ParsedCidr parse_cidr(const std::string& cidr) {
    const auto slash = cidr.find('/');
    if (slash == std::string::npos) {
        throw std::runtime_error("--packet-cidr must be in address/prefix form");
    }
    const std::string address_text = cidr.substr(0, slash);
    const std::string prefix_text = cidr.substr(slash + 1);
    const auto base = parse_ipv4(address_text);
    if (!base.has_value()) {
        throw std::runtime_error("--packet-cidr has an invalid IPv4 network address: " + address_text);
    }
    int prefix = 0;
    try {
        prefix = std::stoi(prefix_text);
    } catch (const std::exception&) {
        throw std::runtime_error("--packet-cidr has an invalid prefix: " + prefix_text);
    }
    if (prefix < 24 || prefix > 30) {
        throw std::runtime_error("--packet-cidr prefix must be /24../30 for packet egress v1");
    }
    const std::uint32_t mask = prefix == 0 ? 0 : (0xffffffffu << (32 - prefix));
    const std::uint32_t network = *base & mask;
    const std::uint32_t broadcast = network | ~mask;
    if (broadcast <= network + 2) {
        throw std::runtime_error("--packet-cidr does not leave usable client addresses");
    }
    return ParsedCidr{
        network,
        network + 2,      // .1 is reserved for the operator-prepared TUN side.
        broadcast - 1,
    };
}

std::vector<std::string> packet_dns_servers(const ServerConfig& cfg) {
    if (parse_ipv4(cfg.dns_server).has_value()) {
        return {cfg.dns_server};
    }
    return {"1.1.1.1"};
}

bool parse_ipv4_packet(const crypto::Bytes& packet,
                       std::uint32_t* source_be,
                       std::uint32_t* destination_be,
                       std::size_t* packet_len) {
    if (packet.size() < 20) {
        return false;
    }
    const std::uint8_t version = static_cast<std::uint8_t>(packet[0] >> 4);
    if (version != 4) {
        return false;
    }
    const std::size_t ihl = static_cast<std::size_t>(packet[0] & 0x0f) * 4;
    if (ihl < 20 || ihl > packet.size()) {
        return false;
    }
    const std::size_t total_len = read_be16(packet.data() + 2);
    if (total_len < ihl || total_len > packet.size()) {
        return false;
    }
    if (source_be) {
        *source_be = read_be32(packet.data() + 12);
    }
    if (destination_be) {
        *destination_be = read_be32(packet.data() + 16);
    }
    if (packet_len) {
        *packet_len = total_len;
    }
    return true;
}

}  // namespace

class PacketTunEgress::Impl {
public:
    Impl(boost::asio::io_context& io, ServerConfig cfg)
        : io_(io), cfg_(std::move(cfg)) {}

    ~Impl() {
        stop();
    }

    void start() {
        if (cfg_.packet_egress.empty() || cfg_.packet_egress == "off" || cfg_.packet_egress == "none") {
            return;
        }
        if (cfg_.packet_egress != "tun") {
            throw std::runtime_error("--packet-egress supports only 'tun' in v1");
        }
        if (cfg_.packet_mtu < 576 || cfg_.packet_mtu > 65535) {
            throw std::runtime_error("--packet-mtu must be in range 576..65535");
        }
        cidr_ = parse_cidr(cfg_.packet_cidr);
        next_client_ = cidr_.first_client;
#if defined(__linux__)
        int fd = ::open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0) {
            throw std::runtime_error("packet egress TUN open failed: " + std::string(std::strerror(errno)));
        }
        struct ifreq ifr {};
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        std::snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", cfg_.packet_tun_name.c_str());
        if (::ioctl(fd, TUNSETIFF, &ifr) < 0) {
            const std::string reason = std::strerror(errno);
            ::close(fd);
            throw std::runtime_error("packet egress TUN attach failed for " + cfg_.packet_tun_name + ": " + reason);
        }
        tun_ = std::make_unique<boost::asio::posix::stream_descriptor>(io_, fd);
        active_ = true;
        util::log_info("packet egress active: tun=" + cfg_.packet_tun_name +
                       " cidr=" + cfg_.packet_cidr +
                       " mtu=" + std::to_string(cfg_.packet_mtu) +
                       " dns=" + packet_dns_servers(cfg_).front());
        start_read();
#else
        throw std::runtime_error("--packet-egress tun is supported only on Linux");
#endif
    }

    void stop() {
        active_ = false;
#if defined(__linux__)
        if (tun_) {
            boost::system::error_code ec;
            tun_->close(ec);
        }
#endif
        std::lock_guard<std::mutex> lock(mutex_);
        clients_.clear();
        owner_clients_.clear();
        write_queue_.clear();
        write_active_ = false;
    }

    bool active() const {
        return active_.load();
    }

    std::optional<PacketTunAssignment> register_client(void* owner, PacketHandler handler) {
        if (!owner || !handler || !active_) {
            return std::nullopt;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        if (owner_clients_.find(owner) != owner_clients_.end()) {
            return std::nullopt;
        }
        const auto assigned = allocate_client_locked();
        if (!assigned.has_value()) {
            util::log_warn("packet egress: no client IPv4 addresses left in " + cfg_.packet_cidr);
            return std::nullopt;
        }
        clients_[*assigned] = Client{owner, std::move(handler)};
        owner_clients_[owner] = *assigned;
        return PacketTunAssignment{
            *assigned,
            ipv4_to_string(*assigned),
            cfg_.packet_mtu,
            packet_dns_servers(cfg_),
        };
    }

    void unregister_client(void* owner, std::uint32_t ipv4_be) {
        if (!owner && ipv4_be == 0) {
            return;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        const auto owner_it = owner_clients_.find(owner);
        const std::uint32_t current_ip = owner_it == owner_clients_.end() ? ipv4_be : owner_it->second;
        if (current_ip != 0) {
            clients_.erase(current_ip);
        }
        if (owner_it != owner_clients_.end()) {
            owner_clients_.erase(owner_it);
        }
    }

    void write_packet(std::uint32_t, crypto::Bytes packet) {
        if (!active_ || packet.empty()) {
            return;
        }
        std::size_t packet_len = 0;
        if (!parse_ipv4_packet(packet, nullptr, nullptr, &packet_len)) {
            return;
        }
        if (packet_len != packet.size()) {
            packet.resize(packet_len);
        }
        bool should_start = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (write_queue_.size() >= kMaxPendingWrites) {
                if ((dropped_writes_++ & 0x3ff) == 0) {
                    util::log_warn("packet egress: TUN write queue full; dropping IPv4 packets");
                }
                return;
            }
            write_queue_.push_back(std::make_shared<crypto::Bytes>(std::move(packet)));
            should_start = !write_active_;
        }
        if (should_start) {
            start_write();
        }
    }

private:
    struct Client {
        void* owner{nullptr};
        PacketHandler handler;
    };

    std::optional<std::uint32_t> allocate_client_locked() {
        if (clients_.size() >= static_cast<std::size_t>(cidr_.last_client - cidr_.first_client + 1)) {
            return std::nullopt;
        }
        std::uint32_t candidate = next_client_;
        while (true) {
            if (candidate > cidr_.last_client) {
                candidate = cidr_.first_client;
            }
            if (clients_.find(candidate) == clients_.end()) {
                next_client_ = candidate + 1;
                return candidate;
            }
            ++candidate;
        }
    }

    void start_read() {
#if defined(__linux__)
        if (!tun_ || !active_) {
            return;
        }
        tun_->async_read_some(
            boost::asio::buffer(read_buf_),
            [this](const boost::system::error_code& ec, std::size_t bytes) {
                if (ec) {
                    if (ec != boost::asio::error::operation_aborted) {
                        util::log_warn("packet egress: TUN read failed: " + ec.message());
                    }
                    active_ = false;
                    return;
                }
                handle_tun_packet(bytes);
                start_read();
            });
#endif
    }

    void handle_tun_packet(std::size_t bytes) {
        if (bytes == 0) {
            return;
        }
        crypto::Bytes packet(read_buf_.begin(), read_buf_.begin() + static_cast<std::ptrdiff_t>(bytes));
        std::uint32_t destination = 0;
        std::size_t packet_len = 0;
        if (!parse_ipv4_packet(packet, nullptr, &destination, &packet_len)) {
            return;
        }
        if (packet_len != packet.size()) {
            packet.resize(packet_len);
        }
        PacketHandler handler;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = clients_.find(destination);
            if (it == clients_.end()) {
                return;
            }
            handler = it->second.handler;
        }
        handler(std::move(packet));
    }

    void start_write() {
#if defined(__linux__)
        std::shared_ptr<crypto::Bytes> packet;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (write_active_ || write_queue_.empty() || !tun_) {
                return;
            }
            write_active_ = true;
            packet = write_queue_.front();
        }
        boost::asio::async_write(
            *tun_,
            boost::asio::buffer(*packet),
            [this, packet](const boost::system::error_code& ec, std::size_t) {
                bool again = false;
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (!write_queue_.empty() && write_queue_.front() == packet) {
                        write_queue_.pop_front();
                    }
                    write_active_ = false;
                    again = !write_queue_.empty();
                }
                if (ec && ec != boost::asio::error::operation_aborted) {
                    util::log_warn("packet egress: TUN write failed: " + ec.message());
                }
                if (again && active_) {
                    start_write();
                }
            });
#endif
    }

    static constexpr std::size_t kMaxPendingWrites = 2048;

    boost::asio::io_context& io_;
    ServerConfig cfg_;
    ParsedCidr cidr_;
    std::uint32_t next_client_{0};
    std::atomic_bool active_{false};
    mutable std::mutex mutex_;
    std::unordered_map<std::uint32_t, Client> clients_;
    std::unordered_map<void*, std::uint32_t> owner_clients_;
    std::deque<std::shared_ptr<crypto::Bytes>> write_queue_;
    bool write_active_{false};
    std::uint64_t dropped_writes_{0};
    std::array<std::uint8_t, 65536> read_buf_{};
#if defined(__linux__)
    std::unique_ptr<boost::asio::posix::stream_descriptor> tun_;
#endif
};

PacketTunEgress::PacketTunEgress(boost::asio::io_context& io, ServerConfig cfg)
    : impl_(std::make_unique<Impl>(io, std::move(cfg))) {}

PacketTunEgress::~PacketTunEgress() = default;

void PacketTunEgress::start() {
    impl_->start();
}

void PacketTunEgress::stop() {
    impl_->stop();
}

bool PacketTunEgress::active() const {
    return impl_->active();
}

std::optional<PacketTunAssignment> PacketTunEgress::register_client(void* owner, PacketHandler handler) {
    return impl_->register_client(owner, std::move(handler));
}

void PacketTunEgress::unregister_client(void* owner, std::uint32_t ipv4_be) {
    impl_->unregister_client(owner, ipv4_be);
}

void PacketTunEgress::write_packet(std::uint32_t client_ipv4_be, crypto::Bytes packet) {
    impl_->write_packet(client_ipv4_be, std::move(packet));
}

}  // namespace yume::server
