/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */
#include "runtime/linux_tun_network.hpp"

#include <array>
#include <cerrno>
#include <cstdarg>
#include <cstring>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <utility>

#include <fcntl.h>
#include <dirent.h>
#include <linux/if.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/if_tun.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <systemd/sd-bus.h>

#include <boost/asio/post.hpp>
#define YUME_TEST_ALIGNED_ALLOCATIONS 1
#include "test_support/allocation_failure.hpp"

// Only kernel control and sd-bus calls are replaced. The production network
// transaction and TUN channel run unchanged; Asio uses real socket descriptors.
// This executable never creates a kernel TUN, changes routes, or contacts DNS.
struct sd_bus { bool active{false}; };
struct sd_bus_creds { bool active{false}; };
struct sd_bus_message {
    std::array<char, 48> method{};
    bool active{false};
    bool first_argument{true};
};

namespace {
using namespace yume;
using engine::Status;
using engine::StatusCode;
using runtime::LinuxTunNetwork;
#define CHECK(value) do { if (!(value)) throw std::runtime_error("check failed: " #value); } while (false)

enum class BadReply { None, Lost, Sender, ShortHeader, ShortError, WrongRequest, PositiveError, MinimumError, Unexpected };
struct Control final {
    int tun_original{-1};
    int tun_opened{-1};
    int tun_peer{-1};
    int mtu{1500};
    int netlink{-1};
    unsigned opens{0};
    bool link{false};
    bool up{false};
    bool ipv6_static{false};
    unsigned ipv6_configurations{0};
    unsigned addresses{0};
    unsigned route_count{0};
    unsigned total_routes{0};
    std::array<common::IpNetwork, 192> routes{};
    unsigned mutations{0};
    unsigned fail_mutation{0};
    BadReply bad_reply{BadReply::None};
    BadReply pending_bad{BadReply::None};
    int rejected_error{0};
    unsigned delete_attempts{0};
    unsigned fail_deletes{0};
    bool fail_all_deletes{false};
    BadReply delete_bad{BadReply::None};
    alignas(nlmsghdr) std::array<std::byte, NLMSG_SPACE(sizeof(nlmsgerr))> reply{};
    std::size_t reply_size{0};
    sd_bus bus;
    sd_bus_creds creds;
    sd_bus_creds daemon_creds;
    std::array<sd_bus_message, 8> messages{};
    bool namespace_matches{true};
    bool pid_namespace_matches{true};
    unsigned dns_calls{0};
    unsigned dns_fail_call{0};
    unsigned reverts{0};
    bool fail_revert{false};
    bool fail_message_allocation{false};
    bool dns_applied{false};
};
Control* control = nullptr;
constexpr unsigned kIndex = 42U;

common::IpNetwork prefix(std::string_view text) {
    auto result = common::parse_canonical_ip_network(text); CHECK(result); return *result;
}
common::IpInterfaceAddress address(std::string_view text) {
    auto result = common::parse_canonical_ip_interface(text); CHECK(result); return *result;
}
std::size_t size(common::IpFamily family) { return family == common::IpFamily::V4 ? 4U : 16U; }
bool covers(const common::IpNetwork& network, const common::IpInterfaceAddress& value) {
    return common::ip_network_contains(network, value.family, std::span(value.address).first(size(value.family)));
}
config::v1::TunNetwork settings(std::initializer_list<std::string_view> routes, bool dns = false) {
    config::v1::TunNetwork result;
    result.addresses = {address("10.72.0.1/24")};
    for (const auto route : routes) result.routes.push_back(prefix(route));
    if (dns) { result.dns_servers = {address("10.71.0.2/32")}; result.dns_domains = {"."}; }
    return result;
}
unsigned descriptor_count() {
    DIR* directory = ::opendir("/proc/self/fd"); CHECK(directory != nullptr);
    unsigned count = 0U;
    while (::readdir(directory)) ++count;
    CHECK(::closedir(directory) == 0);
    return count;
}

struct Fixture final {
    Fixture() {
        CHECK(control == nullptr);
        int pair[2]{};
        CHECK(::socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, pair) == 0);
        fake.tun_original = pair[0]; fake.tun_peer = pair[1]; control = &fake;
        auto created = providers::AsioExecutionContext::create(engine::ExecutorAffinity(0x54554e4eU));
        CHECK(created.ok()); context = std::move(created).take_value();
    }
    ~Fixture() noexcept {
        yume::test::fail_allocations.store(false);
        fake.fail_all_deletes = false; fake.fail_deletes = 0; fake.fail_revert = false;
        network.reset(); context->finish();
        try { context->run(); } catch (...) { std::terminate(); }
        control = nullptr;
        ::close(fake.tun_original); ::close(fake.tun_peer);
    }
    template<class Function> void on_context(Function function) {
        boost::asio::post(context->executor(), std::move(function)); context->poll();
    }
    Status create(config::v1::TunNetwork value, std::optional<common::IpInterfaceAddress> transport = {}) {
        config::v1::PacketAdapter adapter("test-ip", "testtun0", static_cast<std::uint16_t>(fake.mtu), std::move(value));
        Status status;
        on_context([&] {
            auto created = LinuxTunNetwork::create(context, adapter, transport);
            if (created.ok()) network = std::move(created).take_value();
            else status = created.status();
        });
        return status;
    }
    Status close() { Status status; on_context([&] { status = network->close(); }); return status; }
    Control fake;
    std::shared_ptr<providers::AsioExecutionContext> context;
    std::shared_ptr<LinuxTunNetwork> network;
};

void route_coverage() {
    // Exhaustive membership over small IPv4/IPv6 prefixes catches both a leak
    // of the transport host and a dropped neighboring address.
    for (const bool ipv6 : {false, true}) {
        for (const unsigned excluded : {0U, 1U, 127U, 128U, 255U}) {
            Fixture fixture;
            auto host = ipv6 ? address("fd71::/128") : address("10.71.0.0/32");
            const auto last = ipv6 ? 15U : 3U; host.address[last] = static_cast<std::uint8_t>(excluded);
            const auto routes = ipv6 ? settings({"fd71::/120", "fd71::/121", "fd71::/120"}) :
                settings({"10.71.0.0/24", "10.71.0.0/25", "10.71.0.0/24"});
            CHECK(fixture.create(routes, host).ok());
            CHECK(fixture.fake.route_count == 8U);
            for (unsigned candidate = 0U; candidate < 256U; ++candidate) {
                auto value = host; value.address[last] = static_cast<std::uint8_t>(candidate);
                unsigned matches = 0U;
                for (unsigned i = 0U; i < fixture.fake.route_count; ++i) matches += covers(fixture.fake.routes[i], value);
                CHECK(matches == (candidate == excluded ? 0U : 1U));
            }
            CHECK(fixture.close().ok());
            CHECK(!fixture.fake.link && fixture.fake.route_count == 0U && fixture.fake.addresses == 0U);
        }
    }
    for (const bool ipv6 : {false, true}) {
        Fixture fixture;
        const auto host = ipv6 ? address("2001:db8:71::99/128") : address("203.0.113.99/32");
        CHECK(fixture.create(ipv6 ? settings({"::/0"}) : settings({"0.0.0.0/0"}), host).ok());
        const unsigned width = ipv6 ? 128U : 32U;
        CHECK(fixture.fake.route_count == width);
        // Each other host diverges from the excluded address at one bit.
        // Its sibling prefix must be present exactly once.
        for (unsigned bit = 0U; bit < width; ++bit) {
            auto neighbor = host; neighbor.address[bit / 8U] ^= static_cast<std::uint8_t>(0x80U >> (bit % 8U));
            unsigned matches = 0U;
            for (unsigned i = 0U; i < fixture.fake.route_count; ++i) {
                CHECK(!covers(fixture.fake.routes[i], host));
                matches += covers(fixture.fake.routes[i], neighbor);
            }
            CHECK(matches == 1U);
        }
        CHECK(fixture.close().ok());
    }
    {
        Fixture fixture;
        CHECK(fixture.create(settings({"203.0.113.99/32"}), address("203.0.113.99/32")).ok());
        CHECK(fixture.fake.route_count == 0U);
        CHECK(fixture.close().ok());
    }
    {
        Fixture fixture;
        CHECK(fixture.create(settings({"0.0.0.0/0", "::/0"}), address("203.0.113.99/32")).ok());
        CHECK(fixture.fake.route_count == 34U);
        CHECK(fixture.fake.ipv6_static && fixture.fake.ipv6_configurations == 1U && fixture.fake.up);
        CHECK(fixture.close().ok());
    }
    {
        Fixture fixture;
        CHECK(!fixture.create(settings({"0.0.0.0/0"})).ok());
        CHECK(fixture.fake.opens == 0U && fixture.fake.mutations == 0U);
    }
    for (const auto& routes : {settings({"0.0.0.0/1", "128.0.0.0/1"}), settings({"::/1", "8000::/1"}),
            settings({"0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2"})}) {
        Fixture fixture;
        CHECK(!fixture.create(routes).ok());
        CHECK(fixture.fake.opens == 0U && fixture.fake.mutations == 0U);
    }
    for (const auto host : {address("10.72.0.1/32"), address("10.71.0.2/32")}) {
        Fixture fixture;
        CHECK(!fixture.create(settings({"10.71.0.0/24"}, true), host).ok());
        CHECK(fixture.fake.opens == 0U && fixture.fake.mutations == 0U);
    }
}

void partial_failures() {
    for (const auto bad : {BadReply::Lost, BadReply::Sender, BadReply::ShortHeader, BadReply::ShortError,
            BadReply::WrongRequest, BadReply::PositiveError, BadReply::MinimumError, BadReply::Unexpected}) {
        for (unsigned mutation = 1U; mutation <= 5U; ++mutation) {
            Fixture fixture;
            fixture.fake.fail_mutation = mutation; fixture.fake.bad_reply = bad;
            CHECK(!fixture.create(settings({"10.0.0.0/8", "fd71::/64"})).ok());
            CHECK(!fixture.network);
            CHECK(fixture.fake.delete_attempts == 1U);
            CHECK(!fixture.fake.link && fixture.fake.route_count == 0U && fixture.fake.addresses == 0U);
        }
    }
    {
        Fixture fixture;
        fixture.fake.fail_mutation = 4U; fixture.fake.rejected_error = EEXIST;
        CHECK(!fixture.create(settings({"10.0.0.0/8"})).ok());
        CHECK(fixture.fake.total_routes == 0U && fixture.fake.delete_attempts == 1U);
    }
    {
        Fixture fixture;
        fixture.fake.fail_mutation = 3U; fixture.fake.bad_reply = BadReply::Lost;
        fixture.fake.fail_all_deletes = true;
        const auto status = fixture.create(settings({"10.0.0.0/8"}));
        CHECK(!status.ok()); CHECK(status.message().find("rollback also failed") != std::string::npos);
        CHECK(fixture.fake.delete_attempts >= 1U);
    }
    {
        Fixture fixture;
        CHECK(fixture.create(settings({"10.0.0.0/8"})).ok());
        fixture.fake.fail_deletes = 1U;
        CHECK(!fixture.close().ok()); CHECK(fixture.fake.link);
        // Model an index recycled after asynchronous raw fd closure. Even a
        // second close or destructor must leave that new device untouched.
        CHECK(!fixture.close().ok());
        fixture.network.reset(); fixture.context->poll();
        CHECK(fixture.fake.link && fixture.fake.delete_attempts == 1U);
    }
    for (const auto error : {EPERM, EOPNOTSUPP, EAFNOSUPPORT}) {
        Fixture fixture;
        fixture.fake.fail_mutation = 1U; fixture.fake.rejected_error = error;
        CHECK(!fixture.create(settings({"10.0.0.0/8"})).ok());
        CHECK(!fixture.fake.link && !fixture.fake.up && fixture.fake.ipv6_configurations == 0U);
        CHECK(fixture.fake.addresses == 0U && fixture.fake.route_count == 0U && fixture.fake.delete_attempts == 1U);
    }
    {
        Fixture fixture;
        fixture.fake.mtu = 1200;
        CHECK(fixture.create(settings({"10.0.0.0/8"})).ok());
        CHECK(fixture.fake.ipv6_configurations == 0U && fixture.fake.up);
        CHECK(fixture.close().ok());
    }
}

void dns_ownership_and_failures() {
    {
        Fixture fixture;
        fixture.fake.pid_namespace_matches = false;
        CHECK(!fixture.create(settings({"10.0.0.0/8"}, true)).ok());
        CHECK(fixture.fake.opens == 0U && fixture.fake.dns_calls == 0U);
    }
    {
        Fixture fixture;
        fixture.fake.namespace_matches = false;
        CHECK(!fixture.create(settings({"10.0.0.0/8"}, true)).ok());
        CHECK(fixture.fake.opens == 0U && fixture.fake.dns_calls == 0U);
    }
    for (unsigned failed = 1U; failed <= 3U; ++failed) {
        Fixture fixture;
        fixture.fake.dns_fail_call = failed;
        CHECK(!fixture.create(settings({"10.0.0.0/8"}, true)).ok());
        CHECK(fixture.fake.reverts == 1U);
        CHECK(!fixture.fake.dns_applied && !fixture.fake.link);
    }
    {
        Fixture fixture;
        CHECK(fixture.create(settings({"10.0.0.0/8"}, true)).ok());
        CHECK(fixture.fake.dns_applied);
        fixture.fake.fail_revert = true;
        CHECK(!fixture.close().ok());
        CHECK(!fixture.fake.link && !fixture.fake.dns_applied);
        CHECK(!fixture.close().ok());
        CHECK(fixture.fake.reverts == 1U); // Never address a removed/reused index.
    }
    {
        Fixture fixture;
        CHECK(fixture.create(settings({"10.0.0.0/8"}, true)).ok());
        fixture.fake.fail_revert = true;
        fixture.fake.delete_bad = BadReply::Lost;
        CHECK(!fixture.close().ok()); CHECK(!fixture.fake.link);
        CHECK(!fixture.close().ok());
        CHECK(fixture.fake.reverts == 1U); // Deletion may succeed without its ACK.
        CHECK(fixture.fake.delete_attempts == 1U);
    }
}

void allocation_cleanup() {
    for (const bool library_failure : {false, true}) {
        Fixture fixture;
        CHECK(fixture.create(settings({"10.0.0.0/8"}, true)).ok());
        fixture.fake.fail_message_allocation = library_failure;
        fixture.on_context([&] {
            yume::test::fail_allocations.store(true);
            const auto status = fixture.network->close();
            yume::test::fail_allocations.store(false);
            CHECK(status.ok() == !library_failure);
            if (library_failure) CHECK(status.code() == StatusCode::ResourceExhausted);
        });
        CHECK(!fixture.fake.link && !fixture.fake.dns_applied);
    }
    unsigned failures = 0U;
    for (std::size_t nth = 1U; nth <= 64U; ++nth) {
        Fixture fixture;
        // Initialize Asio's lazy reactor before taking the descriptor baseline.
        CHECK(fixture.create(settings({"10.0.0.0/8"}, true)).ok());
        CHECK(fixture.close().ok()); fixture.network.reset(); fixture.context->poll();
        const auto before = descriptor_count();
        config::v1::PacketAdapter adapter("test-ip", "testtun0", 1500U, settings({"10.0.0.0/8"}, true));
        bool fired = false;
        bool succeeded = false;
        fixture.on_context([&] {
            yume::test::arm_allocation_failure(nth);
            auto created = LinuxTunNetwork::create(fixture.context, adapter);
            fired = yume::test::disarm_allocation_failure();
            succeeded = created.ok();
            if (succeeded) fixture.network = std::move(created).take_value();
        });
        if (succeeded) CHECK(fixture.close().ok());
        fixture.network.reset(); fixture.context->poll();
        CHECK(descriptor_count() == before);
        CHECK(fixture.fake.route_count == 0U && fixture.fake.addresses == 0U && !fixture.fake.dns_applied);
        CHECK(!fixture.fake.bus.active && !fixture.fake.creds.active && !fixture.fake.daemon_creds.active);
        for (const auto& message : fixture.fake.messages) CHECK(!message.active);
        if (!fired) break;
        CHECK(!succeeded); ++failures;
    }
    CHECK(failures >= 5U && failures < 64U);
}
}  // namespace

extern "C" int __real_open(const char*, int, ...);
extern "C" int __real_fstat(int, struct stat*);
extern "C" int __real_stat(const char*, struct stat*);
extern "C" int __real_ioctl(int, unsigned long, ...);
extern "C" int __real_socket(int, int, int);
extern "C" int __real_bind(int, const sockaddr*, socklen_t);
extern "C" ssize_t __real_sendto(int, const void*, std::size_t, int, const sockaddr*, socklen_t);
extern "C" ssize_t __real_recvmsg(int, msghdr*, int);
extern "C" int __real_poll(pollfd*, nfds_t, int);

extern "C" int __wrap_socket(int domain, int type, int protocol) {
    if (control && domain == AF_NETLINK) {
        CHECK(type == (SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK) && protocol == NETLINK_ROUTE);
        control->netlink = __real_socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0); return control->netlink;
    }
    if (control && domain == AF_INET && type == (SOCK_DGRAM | SOCK_CLOEXEC))
        return __real_socket(AF_UNIX, type, 0);
    return __real_socket(domain, type, protocol);
}
extern "C" int __wrap_bind(int fd, const sockaddr* value, socklen_t length) {
    if (control && fd == control->netlink) return 0;
    return __real_bind(fd, value, length);
}
extern "C" int __wrap_open(const char* path, int flags, ...) {
    if (control && std::strcmp(path, "/dev/net/tun") == 0) {
        ++control->opens; control->tun_opened = ::fcntl(control->tun_original, F_DUPFD_CLOEXEC, 0); return control->tun_opened;
    }
    if ((flags & O_CREAT) != 0) {
        va_list args; va_start(args, flags); const auto mode = va_arg(args, mode_t); va_end(args);
        return __real_open(path, flags, mode);
    }
    return __real_open(path, flags);
}
extern "C" int __wrap_fstat(int fd, struct stat* info) {
    const int result = __real_fstat(fd, info);
    if (result == 0 && control && fd == control->tun_opened) {
        info->st_mode = S_IFCHR | 0600; info->st_rdev = makedev(10, 200);
    }
    return result;
}
extern "C" int __wrap_stat(const char* path, struct stat* info) {
    if (control && (std::strcmp(path, "/proc/self/ns/pid") == 0 || std::strcmp(path, "/proc/3434/ns/pid") == 0)) {
        *info = {}; info->st_dev = 7; info->st_ino = 12;
        if (!control->pid_namespace_matches && std::strcmp(path, "/proc/3434/ns/pid") == 0) ++info->st_ino;
        return 0;
    }
    if (control && (std::strcmp(path, "/proc/self/ns/net") == 0 || std::strcmp(path, "/proc/4242/ns/net") == 0)) {
        *info = {}; info->st_dev = 7; info->st_ino = 11;
        if (!control->namespace_matches && std::strcmp(path, "/proc/4242/ns/net") == 0) ++info->st_ino;
        return 0;
    }
    return __real_stat(path, info);
}
extern "C" int __wrap_ioctl(int fd, unsigned long request, ...) {
    va_list args; va_start(args, request); void* argument = va_arg(args, void*); va_end(args);
    if (control && (request == TUNSETIFF || request == TUNGETIFF || request == SIOCSIFMTU ||
                   request == SIOCGIFMTU || request == SIOCGIFINDEX)) {
        auto* device = static_cast<ifreq*>(argument);
        if (request == TUNSETIFF) {
            CHECK((device->ifr_flags & IFF_TUN_EXCL) != 0); control->link = true;
            control->up = false; control->ipv6_static = false;
        } else if (request == TUNGETIFF) {
            std::strcpy(device->ifr_name, "testtun0"); device->ifr_flags = IFF_TUN | IFF_NO_PI;
        } else if (request == SIOCGIFMTU) device->ifr_mtu = control->mtu;
        else if (request == SIOCGIFINDEX) device->ifr_ifindex = static_cast<int>(kIndex);
        return 0;
    }
    return __real_ioctl(fd, request, argument);
}

extern "C" ssize_t __wrap_sendto(int fd, const void* bytes, std::size_t length, int flags,
                                  const sockaddr* target, socklen_t target_length) {
    if (!control || fd != control->netlink) return __real_sendto(fd, bytes, length, flags, target, target_length);
    CHECK(length >= sizeof(nlmsghdr));
    nlmsghdr request{}; std::memcpy(&request, bytes, sizeof(request));
    CHECK(request.nlmsg_len == length && (request.nlmsg_flags & NLM_F_ACK) != 0);
    const auto* payload = static_cast<const std::byte*>(bytes) + NLMSG_HDRLEN;
    int error = 0;
    if (request.nlmsg_type == RTM_DELLINK) {
        ++control->delete_attempts;
        ifinfomsg link{}; std::memcpy(&link, payload, sizeof(link)); CHECK(link.ifi_index == static_cast<int>(kIndex));
        if (control->fail_all_deletes || control->fail_deletes > 0U) {
            if (control->fail_deletes > 0U) --control->fail_deletes;
            error = -EPERM;
        } else if (!control->link) error = -ENODEV;
        else {
            control->link = false; control->up = false; control->addresses = 0; control->route_count = 0; control->dns_applied = false;
            control->pending_bad = std::exchange(control->delete_bad, BadReply::None);
        }
    } else {
        ++control->mutations;
        CHECK(control->link);
        if (control->mutations == control->fail_mutation) {
            error = -control->rejected_error; control->pending_bad = control->bad_reply;
        }
        if (error == 0 && request.nlmsg_type == RTM_NEWADDR) {
            ifaddrmsg address{}; std::memcpy(&address, payload, sizeof(address)); CHECK(address.ifa_index == kIndex);
            CHECK((control->ipv6_static || control->mtu < 1280) && !control->up);
            bool checked_flags = false;
            for (std::size_t offset = NLMSG_LENGTH(sizeof(ifaddrmsg)); offset < length;) {
                CHECK(offset + sizeof(rtattr) <= length);
                rtattr attribute{}; std::memcpy(&attribute, static_cast<const std::byte*>(bytes) + offset, sizeof(attribute));
                CHECK(attribute.rta_len >= RTA_LENGTH(0) && offset + attribute.rta_len <= length);
                if (attribute.rta_type == IFA_FLAGS) {
                    CHECK(attribute.rta_len == RTA_LENGTH(sizeof(std::uint32_t)) && !checked_flags);
                    std::uint32_t flags{}; std::memcpy(&flags, static_cast<const std::byte*>(bytes) + offset + RTA_LENGTH(0), sizeof(flags));
                    CHECK(flags == (IFA_F_NOPREFIXROUTE | IFA_F_NODAD)); checked_flags = true;
                }
                offset += RTA_ALIGN(attribute.rta_len);
            }
            CHECK(checked_flags);
            ++control->addresses;
        } else if (error == 0 && request.nlmsg_type == RTM_NEWLINK) {
            ifinfomsg link{}; std::memcpy(&link, payload, sizeof(link));
            CHECK(link.ifi_index == static_cast<int>(kIndex));
            if (link.ifi_flags == 0U) {
                CHECK(link.ifi_change == 0U && !control->up && control->addresses == 0U);
                std::size_t offset = NLMSG_LENGTH(sizeof(ifinfomsg));
                for (const auto type : {static_cast<unsigned>(IFLA_AF_SPEC | NLA_F_NESTED),
                        static_cast<unsigned>(AF_INET6 | NLA_F_NESTED), static_cast<unsigned>(IFLA_INET6_ADDR_GEN_MODE)}) {
                    CHECK(offset + sizeof(rtattr) <= length);
                    rtattr attribute{}; std::memcpy(&attribute, static_cast<const std::byte*>(bytes) + offset, sizeof(attribute));
                    CHECK(attribute.rta_type == type && offset + RTA_ALIGN(attribute.rta_len) == length);
                    if (type == IFLA_INET6_ADDR_GEN_MODE) CHECK(attribute.rta_len == RTA_LENGTH(1U));
                    offset += RTA_LENGTH(0);
                }
                CHECK(offset < length && static_cast<const std::byte*>(bytes)[offset] == static_cast<std::byte>(IN6_ADDR_GEN_MODE_NONE));
                control->ipv6_static = true; ++control->ipv6_configurations;
            } else {
                CHECK(link.ifi_flags == IFF_UP && link.ifi_change == IFF_UP && (control->ipv6_static || control->mtu < 1280));
                control->up = true;
            }
        } else if (error == 0 && request.nlmsg_type == RTM_NEWROUTE) {
            CHECK((request.nlmsg_flags & (NLM_F_CREATE | NLM_F_EXCL)) == (NLM_F_CREATE | NLM_F_EXCL));
            rtmsg route{}; std::memcpy(&route, payload, sizeof(route));
            CHECK(route.rtm_table == RT_TABLE_MAIN && route.rtm_type == RTN_UNICAST);
            CHECK(control->route_count < control->routes.size());
            common::IpNetwork network;
            network.family = route.rtm_family == AF_INET ? common::IpFamily::V4 : common::IpFamily::V6;
            network.prefix_length = route.rtm_dst_len;
            unsigned output = 0U;
            for (std::size_t offset = NLMSG_LENGTH(sizeof(rtmsg)); offset < length;) {
                rtattr attribute{}; std::memcpy(&attribute, static_cast<const std::byte*>(bytes) + offset, sizeof(attribute));
                const auto* value = static_cast<const std::byte*>(bytes) + offset + RTA_LENGTH(0);
                CHECK(attribute.rta_len >= RTA_LENGTH(0) && offset + attribute.rta_len <= length);
                if (attribute.rta_type == RTA_OIF) {
                    CHECK(attribute.rta_len == RTA_LENGTH(sizeof(output))); std::memcpy(&output, value, sizeof(output));
                } else if (attribute.rta_type == RTA_DST) {
                    CHECK(attribute.rta_len == RTA_LENGTH(size(network.family))); std::memcpy(network.address.data(), value, size(network.family));
                } else CHECK(false); // No physical gateway, marker or route mutation.
                offset += RTA_ALIGN(attribute.rta_len);
            }
            CHECK(output == kIndex);
            CHECK(common::detail::ip_host_bits_zero(network));
            control->routes[control->route_count++] = network; ++control->total_routes;
        } else CHECK(error != 0);
    }
    nlmsghdr reply{}; reply.nlmsg_type = NLMSG_ERROR; reply.nlmsg_seq = request.nlmsg_seq;
    reply.nlmsg_len = NLMSG_LENGTH(sizeof(nlmsgerr));
    nlmsgerr ack{}; ack.error = error; ack.msg = request;
    std::memcpy(control->reply.data(), &reply, sizeof(reply));
    std::memcpy(control->reply.data() + NLMSG_HDRLEN, &ack, sizeof(ack));
    control->reply_size = reply.nlmsg_len;
    return static_cast<ssize_t>(length);
}
extern "C" int __wrap_poll(pollfd* descriptors, nfds_t count, int timeout) {
    if (control && count == 1U && descriptors[0].fd == control->netlink) {
        CHECK(timeout > 0 && timeout <= 3000); descriptors[0].revents = POLLIN; return 1;
    }
    return __real_poll(descriptors, count, timeout);
}
extern "C" ssize_t __wrap_recvmsg(int fd, msghdr* message, int flags) {
    if (!control || fd != control->netlink) return __real_recvmsg(fd, message, flags);
    const auto bad = std::exchange(control->pending_bad, BadReply::None);
    if (bad == BadReply::Lost) { errno = ENOBUFS; return -1; }
    CHECK(message->msg_namelen >= sizeof(sockaddr_nl) && message->msg_iovlen == 1U);
    auto* source = static_cast<sockaddr_nl*>(message->msg_name); *source = {}; source->nl_family = AF_NETLINK;
    if (bad == BadReply::Sender) source->nl_pid = 123U;
    message->msg_namelen = sizeof(sockaddr_nl);
    nlmsghdr header{}; nlmsgerr ack{};
    std::memcpy(&header, control->reply.data(), sizeof(header));
    std::memcpy(&ack, control->reply.data() + NLMSG_HDRLEN, sizeof(ack));
    auto length = control->reply_size;
    if (bad == BadReply::ShortHeader) length = sizeof(nlmsghdr) - 1U;
    if (bad == BadReply::ShortError) { header.nlmsg_len = NLMSG_LENGTH(sizeof(int)); length = header.nlmsg_len; }
    if (bad == BadReply::WrongRequest) ++ack.msg.nlmsg_type;
    if (bad == BadReply::PositiveError) ack.error = EPERM;
    if (bad == BadReply::MinimumError) ack.error = std::numeric_limits<int>::min();
    if (bad == BadReply::Unexpected) header.nlmsg_type = RTM_NEWROUTE;
    std::memcpy(control->reply.data(), &header, sizeof(header));
    std::memcpy(control->reply.data() + NLMSG_HDRLEN, &ack, sizeof(ack));
    CHECK(message->msg_iov[0].iov_len >= length);
    std::memcpy(message->msg_iov[0].iov_base, control->reply.data(), length);
    return static_cast<ssize_t>(length);
}

extern "C" int __wrap_sd_bus_open_system(sd_bus** result) { CHECK(control); control->bus.active = true; *result = &control->bus; return 0; }
extern "C" sd_bus* __wrap_sd_bus_unref(sd_bus* bus) { if (bus) bus->active = false; return nullptr; }
extern "C" int __wrap_sd_bus_set_method_call_timeout(sd_bus*, uint64_t timeout) { CHECK(timeout == 3'000'000U); return 0; }
extern "C" int __wrap_sd_bus_get_name_creds(sd_bus*, const char* name, uint64_t mask, sd_bus_creds** result) {
    CHECK(std::strcmp(name, "org.freedesktop.resolve1") == 0);
    CHECK(mask == (SD_BUS_CREDS_PID | SD_BUS_CREDS_UNIQUE_NAME)); control->creds.active = true; *result = &control->creds; return 0;
}
extern "C" int __wrap_sd_bus_get_owner_creds(sd_bus*, uint64_t mask, sd_bus_creds** result) {
    CHECK(mask == SD_BUS_CREDS_PID); control->daemon_creds.active = true; *result = &control->daemon_creds; return 0;
}
extern "C" sd_bus_creds* __wrap_sd_bus_creds_unref(sd_bus_creds* creds) { if (creds) creds->active = false; return nullptr; }
extern "C" int __wrap_sd_bus_creds_get_pid(sd_bus_creds* creds, pid_t* pid) {
    *pid = creds == &control->daemon_creds ? 3434 : 4242; return 0;
}
extern "C" int __wrap_sd_bus_creds_get_unique_name(sd_bus_creds*, const char** name) { *name = ":1.42"; return 0; }
extern "C" int __wrap_sd_bus_message_new_method_call(sd_bus*, sd_bus_message** result, const char* destination,
    const char* path, const char* interface, const char* method) {
    CHECK(std::strcmp(destination, ":1.42") == 0); // Never a replaceable service name.
    CHECK(std::strcmp(path, "/org/freedesktop/resolve1") == 0 && std::strcmp(interface, "org.freedesktop.resolve1.Manager") == 0);
    if (control->fail_message_allocation) return -ENOMEM;
    for (auto& message : control->messages) {
        if (!message.active) {
            message = {}; message.active = true; CHECK(std::strlen(method) < message.method.size());
            std::strcpy(message.method.data(), method); *result = &message; return 0;
        }
    }
    return -ENOMEM;
}
extern "C" sd_bus_message* __wrap_sd_bus_message_unref(sd_bus_message* message) { if (message) message->active = false; return nullptr; }
extern "C" int __wrap_sd_bus_message_set_allow_interactive_authorization(sd_bus_message*, int value) { CHECK(value == 0); return 0; }
extern "C" int __wrap_sd_bus_message_append(sd_bus_message* message, const char* types, ...) {
    if (message->first_argument) {
        CHECK(std::strcmp(types, "i") == 0);
        va_list args; va_start(args, types); const auto index = va_arg(args, int); va_end(args);
        CHECK(index == static_cast<int>(kIndex)); message->first_argument = false;
    }
    return 0;
}
extern "C" int __wrap_sd_bus_message_open_container(sd_bus_message*, char, const char*) { return 0; }
extern "C" int __wrap_sd_bus_message_close_container(sd_bus_message*) { return 0; }
extern "C" int __wrap_sd_bus_message_append_array(sd_bus_message*, char, const void*, std::size_t) { return 0; }
extern "C" int __wrap_sd_bus_call(sd_bus*, sd_bus_message* message, uint64_t timeout, sd_bus_error*, sd_bus_message**) {
    CHECK(timeout == 3'000'000U && control->link);
    if (std::strcmp(message->method.data(), "RevertLink") == 0) {
        ++control->reverts;
        if (control->fail_revert) return -ETIMEDOUT;
        control->dns_applied = false;
    } else {
        ++control->dns_calls; control->dns_applied = true;
        if (control->dns_calls == control->dns_fail_call) return -ETIMEDOUT; // Applied, but reply was lost.
    }
    return 0;
}

int main() {
    try {
        route_coverage(); partial_failures(); dns_ownership_and_failures(); allocation_cleanup();
        std::cout << "Linux TUN network transaction tests passed\n"; return 0;
    } catch (const std::exception& error) {
        yume::test::fail_allocations.store(false); std::cerr << error.what() << '\n'; return 1;
    }
}
