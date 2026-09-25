/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */
#include "runtime/linux_tun_network.hpp"
#include "providers/linux_tun_packet_channel.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <systemd/sd-bus.h>

namespace yume::runtime {
namespace {
using engine::Status;
using engine::StatusCode;
using Clock = std::chrono::steady_clock;
constexpr std::uint8_t kRouteProtocol = 186U;
constexpr auto kOperationTimeout = std::chrono::seconds(3);

// Keep failure construction allocation-free: rollback must still run when an
// allocation failed during setup or a DNS message cannot be constructed.
class NetworkError final : public std::exception {
public:
    NetworkError(const char* operation, int error) noexcept : operation_(operation), error_(error) {}
    const char* what() const noexcept override { return operation_; }
    int error() const noexcept { return error_; }
private:
    const char* operation_;
    int error_;
};
Status failure(const NetworkError& error, bool rollback_failed = false) noexcept {
    const auto code = error.error() == EPERM || error.error() == EACCES ? StatusCode::PermissionDenied :
        error.error() == ENOMEM || error.error() == ENOBUFS ? StatusCode::ResourceExhausted : StatusCode::FailedPrecondition;
    std::array<char, 384> diagnostic{};
    std::snprintf(diagnostic.data(), diagnostic.size(), "%s: %s%s", error.what(), std::strerror(error.error()),
        rollback_failed ? "; TUN networking rollback also failed" : "");
    try { return Status(code, diagnostic.data()); }
    catch (...) { return Status(code); }
}
void require(int result, const char* operation) {
    if (result == std::numeric_limits<int>::min()) throw NetworkError(operation, EPROTO);
    if (result < 0) throw NetworkError(operation, -result);
}
struct Fd final {
    int value{-1};
    Fd() = default;
    explicit Fd(int fd) : value(fd) {}
    ~Fd() noexcept { if (value >= 0) ::close(value); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
};

struct Message final {
    alignas(nlmsghdr) std::array<std::byte, 512> bytes{};
    nlmsghdr& header() noexcept { return *reinterpret_cast<nlmsghdr*>(bytes.data()); }
    const nlmsghdr& header() const noexcept { return *reinterpret_cast<const nlmsghdr*>(bytes.data()); }
    template<class T> void init(std::uint16_t type, const T& body_value, std::uint16_t flags = 0U) {
        header().nlmsg_len = NLMSG_LENGTH(sizeof(T));
        header().nlmsg_type = type;
        header().nlmsg_flags = static_cast<std::uint16_t>(NLM_F_REQUEST | flags);
        std::memcpy(bytes.data() + NLMSG_HDRLEN, &body_value, sizeof(T));
    }
    void attribute(std::uint16_t type, const void* data, std::size_t size) {
        const auto offset = NLMSG_ALIGN(header().nlmsg_len);
        if (size > bytes.size() || offset + RTA_SPACE(size) > bytes.size())
            throw NetworkError("netlink request is too large", EOVERFLOW);
        rtattr attribute_header{};
        attribute_header.rta_type = type;
        attribute_header.rta_len = static_cast<std::uint16_t>(RTA_LENGTH(size));
        std::memcpy(bytes.data() + offset, &attribute_header, sizeof(attribute_header));
        if (size != 0U) std::memcpy(bytes.data() + offset + RTA_LENGTH(0), data, size);
        header().nlmsg_len = static_cast<std::uint32_t>(offset + RTA_SPACE(size));
    }
    template<class T> void attribute(std::uint16_t type, const T& value) { attribute(type, &value, sizeof(value)); }
    std::size_t begin_nested(std::uint16_t type) {
        const auto offset = static_cast<std::size_t>(NLMSG_ALIGN(header().nlmsg_len));
        attribute(static_cast<std::uint16_t>(type | NLA_F_NESTED), nullptr, 0U);
        return offset;
    }
    void end_nested(std::size_t offset) {
        rtattr nested{};
        std::memcpy(&nested, bytes.data() + offset, sizeof(nested));
        nested.rta_len = static_cast<std::uint16_t>(header().nlmsg_len - offset);
        std::memcpy(bytes.data() + offset, &nested, sizeof(nested));
    }
};

class Netlink final {
public:
    Netlink() : fd_(::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE)) {
        if (fd_.value < 0) throw NetworkError("open route netlink", errno);
        sockaddr_nl local{}; local.nl_family = AF_NETLINK;
        if (::bind(fd_.value, reinterpret_cast<sockaddr*>(&local), sizeof(local)) < 0)
            throw NetworkError("bind route netlink", errno);
    }
    void exchange(Message request) {
        if (sequence_ == std::numeric_limits<std::uint32_t>::max())
            throw NetworkError("route netlink sequence exhausted", EOVERFLOW);
        request.header().nlmsg_seq = ++sequence_;
        request.header().nlmsg_flags |= NLM_F_ACK;
        sockaddr_nl kernel{}; kernel.nl_family = AF_NETLINK;
        const auto sent = ::sendto(fd_.value, request.bytes.data(), request.header().nlmsg_len,
            MSG_NOSIGNAL, reinterpret_cast<sockaddr*>(&kernel), sizeof(kernel));
        if (sent < 0) throw NetworkError("send route netlink", errno);
        if (static_cast<std::size_t>(sent) != request.header().nlmsg_len)
            throw NetworkError("short route netlink write", EIO);
        const auto deadline = Clock::now() + kOperationTimeout;
        for (;;) {
            const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now());
            if (remaining.count() <= 0) throw NetworkError("route netlink deadline", ETIMEDOUT);
            pollfd poll_fd{fd_.value, POLLIN, 0};
            const auto ready = ::poll(&poll_fd, 1U, static_cast<int>(remaining.count()));
            if (ready < 0 && errno == EINTR) continue;
            if (ready < 0) throw NetworkError("wait route netlink", errno);
            if (ready == 0) continue;
            if ((poll_fd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
                throw NetworkError("route netlink socket failed", EIO);
            alignas(nlmsghdr) std::array<std::byte, 8192> response{};
            sockaddr_nl source{};
            iovec buffer{response.data(), response.size()};
            msghdr message{}; message.msg_name = &source; message.msg_namelen = sizeof(source);
            message.msg_iov = &buffer; message.msg_iovlen = 1U;
            const auto count = ::recvmsg(fd_.value, &message, MSG_DONTWAIT);
            if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
            if (count < 0) throw NetworkError("receive route netlink", errno);
            if (count == 0 || message.msg_flags & (MSG_TRUNC | MSG_CTRUNC) || message.msg_namelen != sizeof(source) ||
                source.nl_family != AF_NETLINK || source.nl_pid != 0U || source.nl_groups != 0U)
                throw NetworkError("invalid route netlink sender or length", EPROTO);
            std::size_t offset = 0U;
            const auto length = static_cast<std::size_t>(count);
            while (offset < length) {
                if (length - offset < sizeof(nlmsghdr)) throw NetworkError("short netlink header", EPROTO);
                nlmsghdr header{}; std::memcpy(&header, response.data() + offset, sizeof(header));
                if (header.nlmsg_len < NLMSG_HDRLEN || header.nlmsg_len > length - offset)
                    throw NetworkError("invalid netlink message length", EPROTO);
                const auto* payload = response.data() + offset + NLMSG_HDRLEN;
                if (header.nlmsg_seq == sequence_) {
                    if (header.nlmsg_type == NLMSG_ERROR) {
                        if (header.nlmsg_len < NLMSG_LENGTH(sizeof(nlmsgerr)))
                            throw NetworkError("short netlink error", EPROTO);
                        nlmsgerr error{}; std::memcpy(&error, payload, sizeof(error));
                        if (error.msg.nlmsg_seq != sequence_ || error.msg.nlmsg_type != request.header().nlmsg_type)
                            throw NetworkError("netlink acknowledgment does not match request", EPROTO);
                        if (error.error > 0 || error.error == std::numeric_limits<int>::min())
                            throw NetworkError("invalid netlink error", EPROTO);
                        if (error.error) throw NetworkError("configure TUN networking", -error.error);
                        return;
                    } else throw NetworkError("unexpected netlink response", EPROTO);
                }
                const auto aligned = NLMSG_ALIGN(header.nlmsg_len);
                if (aligned > length - offset) {
                    if (header.nlmsg_len != length - offset) throw NetworkError("invalid netlink alignment", EPROTO);
                    break;
                }
                offset += aligned;
            }
        }
    }
private:
    Fd fd_;
    std::uint32_t sequence_{0U};
};

std::uint8_t family(common::IpFamily value) noexcept { return value == common::IpFamily::V4 ? AF_INET : AF_INET6; }
std::size_t address_size(common::IpFamily value) noexcept { return value == common::IpFamily::V4 ? 4U : 16U; }
Message route(const common::IpNetwork& network, unsigned interface_index) {
    Message message;
    rtmsg body{}; body.rtm_family = family(network.family); body.rtm_dst_len = network.prefix_length;
    body.rtm_table = RT_TABLE_MAIN; body.rtm_protocol = kRouteProtocol;
    body.rtm_scope = RT_SCOPE_LINK; body.rtm_type = RTN_UNICAST;
    message.init(RTM_NEWROUTE, body, NLM_F_CREATE | NLM_F_EXCL);
    message.attribute(RTA_DST, network.address.data(), address_size(network.family));
    message.attribute(RTA_OIF, interface_index);
    return message;
}

void disable_address_generation(Netlink& netlink, unsigned index, std::uint16_t mtu) {
    // Linux removes the per-link IPv6 state below its minimum MTU. Such a TUN
    // cannot generate IPv6 addresses and rejects AF_INET6 link attributes.
    if (mtu < 1280U) return;
    Message message; ifinfomsg link{};
    link.ifi_index = static_cast<int>(index);
    message.init(RTM_NEWLINK, link);
    const auto specific = message.begin_nested(IFLA_AF_SPEC);
    const auto ipv6 = message.begin_nested(AF_INET6);
    const std::uint8_t mode = IN6_ADDR_GEN_MODE_NONE;
    message.attribute(IFLA_INET6_ADDR_GEN_MODE, mode);
    message.end_nested(ipv6);
    message.end_nested(specific);
    // Must complete before static addresses or IFF_UP. No generated link-local
    // address means no startup RS. IFA_F_NODAD on our static addresses and the
    // TUN's IFF_NOARP suppress DAD and solicited-node multicast joins.
    // IFLA_INET6_CONF is a dump attribute, not writable sysctl configuration.
    netlink.exchange(message);
}

// All installed routes belong to the new TUN. Excluding the numeric transport
// host leaves its original route untouched, including after a lost netlink ACK.
// Collapse duplicate/contained prefixes before expansion so at most one prefix
// per address family can contain the transport host.
std::vector<common::IpNetwork> routes_for(const config::v1::TunNetwork& settings,
    const std::optional<common::IpInterfaceAddress>& transport) {
    if (settings.routes.size() > config::v1::kMaxDestinationNetworks)
        throw NetworkError("too many TUN routes", E2BIG);
    for (const auto& network : settings.routes) {
        if ((network.family != common::IpFamily::V4 && network.family != common::IpFamily::V6) ||
            network.prefix_length > address_size(network.family) * 8U || !common::detail::ip_host_bits_zero(network))
            throw NetworkError("invalid TUN route prefix", EINVAL);
    }
    if (transport && transport->family != common::IpFamily::V4 && transport->family != common::IpFamily::V6)
        throw NetworkError("invalid transport address family", EINVAL);
    if (transport) {
        const auto is_transport = [&](const common::IpInterfaceAddress& candidate) {
            return candidate.family == transport->family &&
                std::equal(candidate.address.begin(), candidate.address.begin() + address_size(candidate.family), transport->address.begin());
        };
        if (std::any_of(settings.addresses.begin(), settings.addresses.end(), is_transport))
            throw NetworkError("TUN address conflicts with the transport host", EINVAL);
        if (std::any_of(settings.dns_servers.begin(), settings.dns_servers.end(), is_transport))
            throw NetworkError("TUN DNS server cannot be the excluded transport host", EINVAL);
    }
    std::vector<common::IpNetwork> routes;
    routes.reserve(settings.routes.size() + 128U);
    std::array<bool, 129> ipv4_coverage{}, ipv6_coverage{};
    for (std::size_t i = 0U; i < settings.routes.size(); ++i) {
        const auto& network = settings.routes[i];
        const auto width = address_size(network.family) * 8U;
        if (network.prefix_length == 0U && !transport)
            throw NetworkError("default TUN routing requires a numeric transport address", EINVAL);
        const auto covers = [](const auto& prefix, const auto& candidate) {
            return prefix.family == candidate.family && prefix.prefix_length <= candidate.prefix_length &&
                common::ip_network_contains(prefix, candidate.family,
                    std::span<const std::uint8_t>(candidate.address).first(address_size(candidate.family)));
        };
        bool redundant = false;
        for (std::size_t j = 0U; j < settings.routes.size(); ++j) {
            if (j == i) continue;
            if (covers(settings.routes[j], network) &&
                (settings.routes[j].prefix_length < network.prefix_length || j < i)) {
                redundant = true; break;
            }
        }
        if (redundant) continue;
        if (!transport) {
            // Sum disjoint prefix sizes as powers of two. The extra bit
            // detects complete IPv6 coverage without overflowing 128 bits or
            // rounding away a missing host in floating-point arithmetic.
            auto& coverage = network.family == common::IpFamily::V4 ? ipv4_coverage : ipv6_coverage;
            std::size_t bit = width - network.prefix_length;
            while (bit < width && coverage[bit]) { coverage[bit] = false; ++bit; }
            if (bit == width) throw NetworkError("default TUN routing requires a numeric transport address", EINVAL);
            coverage[bit] = true;
        }
        if (transport && common::ip_network_contains(network, transport->family,
                std::span<const std::uint8_t>(transport->address).first(address_size(transport->family)))) {
            auto branch = network;
            for (std::size_t bit = network.prefix_length; bit < width; ++bit) {
                const auto mask = static_cast<std::uint8_t>(0x80U >> (bit % 8U));
                branch.prefix_length = static_cast<std::uint8_t>(bit + 1U);
                const bool high = (transport->address[bit / 8U] & mask) != 0U;
                auto sibling = branch;
                if (!high) sibling.address[bit / 8U] |= mask;
                routes.push_back(sibling);
                if (high) branch.address[bit / 8U] |= mask;
            }
        } else if (network.prefix_length == 0U) {
            auto half = network; half.prefix_length = 1U;
            routes.push_back(half);
            half.address[0] = 0x80U;
            routes.push_back(half);
        } else routes.push_back(network);
    }
    return routes;
}

using Bus = std::unique_ptr<sd_bus, decltype(&sd_bus_unref)>;
using BusMessage = std::unique_ptr<sd_bus_message, decltype(&sd_bus_message_unref)>;
BusMessage dns_message(sd_bus* bus, const char* destination, unsigned index, const char* method) {
    sd_bus_message* raw = nullptr;
    require(sd_bus_message_new_method_call(bus, &raw, destination, "/org/freedesktop/resolve1",
        "org.freedesktop.resolve1.Manager", method), "create resolved request");
    BusMessage message(raw, sd_bus_message_unref);
    require(sd_bus_message_set_allow_interactive_authorization(raw, 0), "disable interactive authorization");
    require(sd_bus_message_append(raw, "i", static_cast<int>(index)), "append DNS interface");
    return message;
}
void call(sd_bus* bus, sd_bus_message* message) {
    require(sd_bus_call(bus, message, 3'000'000U, nullptr, nullptr), "configure per-link DNS");
}
void shared_namespace(pid_t pid, const char* kind, const char* operation) {
    if (pid <= 0) throw NetworkError(operation, EPROTO);
    std::array<char, 64> current_path{}, peer_path{};
    std::snprintf(current_path.data(), current_path.size(), "/proc/self/ns/%s", kind);
    std::snprintf(peer_path.data(), peer_path.size(), "/proc/%ld/ns/%s", static_cast<long>(pid), kind);
    struct stat current{}, peer{};
    if (::stat(current_path.data(), &current) || ::stat(peer_path.data(), &peer))
        throw NetworkError(operation, errno);
    if (current.st_dev != peer.st_dev || current.st_ino != peer.st_ino) throw NetworkError(operation, EXDEV);
}
std::string resolved_owner(sd_bus* bus) {
    using Credentials = std::unique_ptr<sd_bus_creds, decltype(&sd_bus_creds_unref)>;
    sd_bus_creds* daemon_raw = nullptr;
    require(sd_bus_get_owner_creds(bus, SD_BUS_CREDS_PID, &daemon_raw), "inspect system bus peer");
    const Credentials daemon(daemon_raw, sd_bus_creds_unref);
    pid_t daemon_pid = 0;
    require(sd_bus_creds_get_pid(daemon_raw, &daemon_pid), "inspect system bus PID");
    // The kernel peer PID is relative to our namespace. The bus method's
    // service PID is relative to the daemon's. Reject a shared container bus
    // before treating that numeric PID as a process in our /proc mount.
    shared_namespace(daemon_pid, "pid", "system bus uses another PID namespace");
    sd_bus_creds* raw = nullptr;
    require(sd_bus_get_name_creds(bus, "org.freedesktop.resolve1",
        SD_BUS_CREDS_PID | SD_BUS_CREDS_UNIQUE_NAME, &raw), "inspect resolved owner");
    const Credentials credentials(raw, sd_bus_creds_unref);
    pid_t pid = 0;
    const char* name = nullptr;
    require(sd_bus_creds_get_pid(raw, &pid), "inspect resolved PID");
    require(sd_bus_creds_get_unique_name(raw, &name), "inspect resolved bus name");
    if (pid <= 0 || name == nullptr || name[0] != ':') throw NetworkError("invalid resolved owner", EPROTO);
    shared_namespace(pid, "net", "resolved belongs to another network namespace");
    // Address all mutations to this connection. A service restart must not
    // silently redirect an interface index into a different network namespace.
    return name;
}
}  // namespace

struct LinuxTunNetwork::State final {
    std::unique_ptr<providers::LinuxTunPacketChannel> tun;
    std::unique_ptr<Netlink> netlink;
    Bus bus{nullptr, sd_bus_unref};
    std::string dns_owner;
    bool dns_started{false};
    bool closed{false};
    StatusCode close_code{StatusCode::Ok};
    ~State() noexcept { (void)close(); }
    Status close() noexcept {
        if (closed) return Status(close_code);
        closed = true;
        if (!tun) return Status::success();
        Status status;
        if (dns_started) {
            try {
                auto message = dns_message(bus.get(), dns_owner.c_str(), tun->interface_index(), "RevertLink");
                call(bus.get(), message.get());
                dns_started = false;
            } catch (const NetworkError& error) { status = failure(error); }
            catch (const std::bad_alloc&) { status = Status(StatusCode::ResourceExhausted); }
            catch (...) { status = Status(StatusCode::Internal); }
        }
        try {
            Message message; ifinfomsg link{};
            link.ifi_index = static_cast<int>(tun->interface_index());
            message.init(RTM_DELLINK, link);
            // Even a missing ACK can mean deletion succeeded. Never send a
            // later DNS request to this index after attempting link deletion.
            dns_started = false;
            netlink->exchange(message);
        } catch (const NetworkError& error) {
            if (error.error() != ENODEV && status.ok()) status = failure(error);
        } catch (...) { if (status.ok()) status = Status(StatusCode::Internal); }
        // Terminal fd close removes the ephemeral interface even when netlink
        // cleanup was refused or its reply was lost. Never retry by cached
        // index: after fd closure the kernel can reuse it for another device.
        dns_started = false;
        tun->close();
        close_code = status.code();
        return status;
    }
    void prepare_dns(const config::v1::TunNetwork& settings) {
        if (settings.dns_servers.empty()) return;
        sd_bus* raw = nullptr;
        require(sd_bus_open_system(&raw), "open system DNS bus"); bus.reset(raw);
        require(sd_bus_set_method_call_timeout(bus.get(), 3'000'000U), "set DNS call deadline");
        dns_owner = resolved_owner(bus.get());
    }
    void configure_dns(const config::v1::TunNetwork& settings) {
        if (settings.dns_servers.empty()) return;
        auto dns = dns_message(bus.get(), dns_owner.c_str(), tun->interface_index(), "SetLinkDNS");
        require(sd_bus_message_open_container(dns.get(), 'a', "(iay)"), "open DNS server array");
        for (const auto& server : settings.dns_servers) {
            require(sd_bus_message_open_container(dns.get(), 'r', "iay"), "open DNS server");
            require(sd_bus_message_append(dns.get(), "i", static_cast<int>(family(server.family))), "append DNS family");
            require(sd_bus_message_append_array(dns.get(), 'y', server.address.data(), address_size(server.family)), "append DNS address");
            require(sd_bus_message_close_container(dns.get()), "close DNS server");
        }
        require(sd_bus_message_close_container(dns.get()), "close DNS array");
        dns_started = true; // A timed-out call may have been applied by resolved.
        call(bus.get(), dns.get());
        auto defaults = dns_message(bus.get(), dns_owner.c_str(), tun->interface_index(), "SetLinkDefaultRoute");
        require(sd_bus_message_append(defaults.get(), "b", 0), "append DNS default route"); call(bus.get(), defaults.get());
        auto domains = dns_message(bus.get(), dns_owner.c_str(), tun->interface_index(), "SetLinkDomains");
        require(sd_bus_message_open_container(domains.get(), 'a', "(sb)"), "open DNS routing domains");
        for (const auto& domain : settings.dns_domains)
            require(sd_bus_message_append(domains.get(), "(sb)", domain.c_str(), 1), "append DNS routing domain");
        require(sd_bus_message_close_container(domains.get()), "close DNS routing domains"); call(bus.get(), domains.get());
    }
};

engine::Result<std::shared_ptr<LinuxTunNetwork>> LinuxTunNetwork::create(
    std::shared_ptr<providers::AsioExecutionContext> context,
    const config::v1::PacketAdapter& adapter,
    std::optional<common::IpInterfaceAddress> transport_address) {
    using Created = engine::Result<std::shared_ptr<LinuxTunNetwork>>;
    if (!context) return Created(Status(StatusCode::InvalidArgument));
    context->require_context();
    std::shared_ptr<LinuxTunNetwork> owner;
    State* state = nullptr;
    try {
        const auto& settings = adapter.network();
        const auto routes = routes_for(settings, transport_address);
        // Allocate the published owner's control block before any mutation.
        // A final shared_ptr allocation failure must not hide rollback errors.
        owner.reset(new LinuxTunNetwork(std::make_unique<State>()));
        state = owner->state_.get();
        state->prepare_dns(settings);
        state->netlink = std::make_unique<Netlink>();
        auto created = providers::LinuxTunPacketChannel::create(context, adapter.interface_name(), adapter.mtu());
        if (!created.ok()) return Created(created.status());
        state->tun = std::move(created).take_value();
        const auto index = state->tun->interface_index();
        disable_address_generation(*state->netlink, index, adapter.mtu());
        for (const auto& address : settings.addresses) {
            Message message; ifaddrmsg body{};
            body.ifa_family = family(address.family); body.ifa_prefixlen = address.prefix_length; body.ifa_index = index;
            message.init(RTM_NEWADDR, body, NLM_F_CREATE | NLM_F_EXCL);
            const std::uint32_t flags = IFA_F_NOPREFIXROUTE | IFA_F_NODAD;
            message.attribute(IFA_FLAGS, flags);
            message.attribute(IFA_LOCAL, address.address.data(), address_size(address.family));
            message.attribute(IFA_ADDRESS, address.address.data(), address_size(address.family));
            state->netlink->exchange(message);
        }
        Message up; ifinfomsg link{}; link.ifi_index = static_cast<int>(index); link.ifi_flags = IFF_UP; link.ifi_change = IFF_UP;
        up.init(RTM_NEWLINK, link); state->netlink->exchange(up);
        for (const auto& network : routes) state->netlink->exchange(route(network, index));
        state->configure_dns(settings);
        return Created(std::move(owner));
    } catch (const NetworkError& error) {
        const bool rollback_failed = state && !state->close().ok();
        return Created(failure(error, rollback_failed));
    } catch (const std::bad_alloc&) {
        if (state && !state->close().ok())
            return Created(failure(NetworkError("allocation failed and TUN networking rollback failed", ENOMEM)));
        return Created(Status(StatusCode::ResourceExhausted));
    }
}
LinuxTunNetwork::LinuxTunNetwork(std::unique_ptr<State> state) noexcept : state_(std::move(state)) {}
LinuxTunNetwork::~LinuxTunNetwork() noexcept = default;
engine::PacketChannel& LinuxTunNetwork::channel() noexcept { return *state_->tun; }
std::string_view LinuxTunNetwork::interface_name() const noexcept { return state_->tun->interface_name(); }
unsigned LinuxTunNetwork::interface_index() const noexcept { return state_->tun->interface_index(); }
Status LinuxTunNetwork::close() noexcept { return state_->close(); }
}  // namespace yume::runtime
