/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/native_egress_policy.hpp"

#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <system_error>
#include <vector>

#include "common/ip_network.hpp"

namespace {
using namespace yume::engine;
using yume::config::v1::Adapter;
using yume::config::v1::DestinationList;
using yume::config::v1::DestinationListAction;
using yume::config::v1::DestinationListFormat;
using yume::config::v1::DestinationPolicy;
using yume::config::v1::FileReference;
using yume::config::v1::DirectTcpAdapter;
using yume::config::v1::DirectUdpAdapter;
using yume::config::v1::Socks5Adapter;
using yume::runtime::NativeEgressPolicy;

#define CHECK(condition) do { if (!(condition)) { \
    std::cerr << "egress policy check failed at " << __LINE__ << ": " #condition "\n"; \
    std::abort(); \
} } while (false)

template <typename T> T take(Result<T> result) {
    CHECK(result.ok());
    return std::move(result).take_value();
}

std::vector<yume::common::IpNetwork> networks(std::initializer_list<const char*> texts) {
    std::vector<yume::common::IpNetwork> result;
    for (const char* text : texts) {
        const auto parsed = yume::common::parse_canonical_ip_network(text);
        CHECK(parsed);
        result.push_back(*parsed);
    }
    return result;
}

RouteDestination v4(NetworkProtocol protocol, std::array<std::uint8_t, 4> address) {
    return take(RouteDestination::ipv4(protocol, address, 443U));
}

RouteDestination v6(NetworkProtocol protocol, const char* text) {
    const auto parsed = yume::common::parse_canonical_ip_network(std::string(text) + "/128");
    CHECK(parsed && parsed->family == yume::common::IpFamily::V6);
    return take(RouteDestination::ipv6(protocol, parsed->address, 443U));
}

StreamOpenContext open(std::string service, ServiceKind kind,
                       std::optional<RouteDestination> destination) {
    const auto role = EndpointRole::Client;
    auto peer = take(PeerEvidence::create(role, "device", "test",
                                          std::vector<std::byte>(32U, std::byte{1})));
    return take(StreamOpenContext::create(take(StreamId::application(1U, role)),
                                          std::move(service), kind, std::move(peer),
                                          std::move(destination)));
}

std::shared_ptr<const NativeEgressPolicy> policy() {
    std::vector<Adapter> adapters;
    adapters.emplace_back(Socks5Adapter("ignored", "127.0.0.1", 1080U));
    adapters.emplace_back(DirectTcpAdapter("web", DestinationPolicy(true, {})));
    adapters.emplace_back(DirectUdpAdapter("lan", DestinationPolicy(false,
        networks({"10.0.0.0/8", "fd00::/8"}))));
    adapters.emplace_back(DirectTcpAdapter("lan", DestinationPolicy(false,
        networks({"0.0.0.0/0"}))));
    return take(NativeEgressPolicy::create(adapters, {}));
}

bool allowed(const NativeEgressPolicy& egress, const char* service, const RouteDestination& destination) {
    const auto status = egress.authorize_address(service, destination);
    CHECK(status.ok() || status.code() == StatusCode::PermissionDenied);
    return status.ok();
}

void test_creation() {
    std::vector<Adapter> adapters;
    adapters.emplace_back(DirectTcpAdapter("web", DestinationPolicy(true, {})));
    adapters.emplace_back(DirectTcpAdapter("web", DestinationPolicy(false, networks({"10.0.0.0/8"}))));
    CHECK(NativeEgressPolicy::create(adapters, {}).status().code() == StatusCode::InvalidArgument);
    adapters.pop_back();
    adapters.emplace_back(DirectUdpAdapter("web", DestinationPolicy(false, networks({"10.0.0.0/8"}))));
    CHECK(NativeEgressPolicy::create(adapters, {}).ok());
    adapters.emplace_back(DirectUdpAdapter("empty", DestinationPolicy(false, {})));
    CHECK(NativeEgressPolicy::create(adapters, {}).status().code() == StatusCode::InvalidArgument);

    // Without direct adapters nothing is permitted.
    const auto none = take(NativeEgressPolicy::create({}, {}));
    CHECK(!allowed(*none, "web", v4(NetworkProtocol::Tcp, {8U, 8U, 8U, 8U})));
}

void test_public_addresses() {
    const auto egress = policy();
    const auto tcp = NetworkProtocol::Tcp;
    CHECK(allowed(*egress, "web", v4(tcp, {8U, 8U, 8U, 8U})));
    CHECK(allowed(*egress, "web", v6(tcp, "2606:4700::1111")));
    for (const auto& address : std::vector<std::array<std::uint8_t, 4>>{
             {10U, 0U, 0U, 1U}, {127U, 0U, 0U, 1U}, {169U, 254U, 169U, 254U},
             {192U, 168U, 1U, 1U}, {100U, 64U, 0U, 1U}, {0U, 0U, 0U, 0U},
             {224U, 0U, 0U, 1U}, {255U, 255U, 255U, 255U}}) {
        CHECK(!allowed(*egress, "web", v4(tcp, address)));
    }
    for (const char* text : {"::1", "fe80::1", "fd00::1", "::ffff:7f00:1", "::ffff:a00:1",
                             "64:ff9b::a00:1", "2002:a00:1::1", "2001::1", "::"}) {
        CHECK(!allowed(*egress, "web", v6(tcp, text)));
    }
    // A service rule applies to its own protocol only.
    CHECK(!allowed(*egress, "web", v4(NetworkProtocol::Udp, {8U, 8U, 8U, 8U})));
    CHECK(!allowed(*egress, "missing", v4(tcp, {8U, 8U, 8U, 8U})));
    CHECK(!allowed(*egress, "web", take(RouteDestination::dns_name(tcp, "example.com", 443U))));
}

void test_explicit_networks() {
    const auto egress = policy();
    const auto udp = NetworkProtocol::Udp;
    CHECK(allowed(*egress, "lan", v4(udp, {10U, 1U, 2U, 3U})));
    CHECK(allowed(*egress, "lan", v6(udp, "::ffff:a01:203")));
    CHECK(allowed(*egress, "lan", v6(udp, "fd00::5")));
    CHECK(!allowed(*egress, "lan", v4(udp, {8U, 8U, 8U, 8U})));
    CHECK(!allowed(*egress, "lan", v6(udp, "fe80::1")));
    CHECK(!allowed(*egress, "lan", v6(udp, "2606:4700::1111")));

    // Even a network containing everything never permits unusable addresses.
    const auto tcp = NetworkProtocol::Tcp;
    CHECK(allowed(*egress, "lan", v4(tcp, {127U, 0U, 0U, 1U})));
    CHECK(allowed(*egress, "lan", v4(tcp, {8U, 8U, 8U, 8U})));
    CHECK(!allowed(*egress, "lan", v4(tcp, {0U, 0U, 0U, 0U})));
    CHECK(!allowed(*egress, "lan", v4(tcp, {224U, 0U, 0U, 1U})));
    CHECK(!allowed(*egress, "lan", v4(tcp, {255U, 255U, 255U, 255U})));
    CHECK(!allowed(*egress, "lan", v6(tcp, "::1")));
}

void test_request_stage() {
    const auto egress = policy();
    const auto tcp = NetworkProtocol::Tcp;
    CHECK(egress->authorize_request(open("web", ServiceKind::ByteStream,
        v4(tcp, {8U, 8U, 8U, 8U}))).ok());
    CHECK(egress->authorize_request(open("web", ServiceKind::ByteStream,
        v4(tcp, {10U, 0U, 0U, 1U}))).code() == StatusCode::PermissionDenied);
    // Names are decided per resolved address, before any socket opens.
    CHECK(egress->authorize_request(open("web", ServiceKind::ByteStream,
        take(RouteDestination::dns_name(tcp, "localhost", 443U)))).ok());
    CHECK(egress->authorize_request(open("missing", ServiceKind::ByteStream,
        take(RouteDestination::dns_name(tcp, "localhost", 443U)))).code() == StatusCode::PermissionDenied);
    CHECK(egress->authorize_request(open("web", ServiceKind::ByteStream, std::nullopt)).code() ==
          StatusCode::PermissionDenied);
}

}  // namespace

class TempDirectory final {
public:
    TempDirectory() {
        std::string pattern =
            (std::filesystem::temp_directory_path() / "yume-egress-policy-XXXXXX").string();
        if (!::mkdtemp(pattern.data())) {
            throw std::system_error(errno, std::generic_category(), "create test directory");
        }
        path_ = pattern;
    }
    ~TempDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }
    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

void write(const std::filesystem::path& path, const std::string& contents) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << contents;
    CHECK(output.good());
}

// Lists narrow a service's destinations. A more specific Allow exempts an
// address from a broader Deny, but nothing widens the adapter's own policy.
void test_egress_lists() {
    const TempDirectory root;
    write(root.path() / "deny.json", R"({"ips": ["8.8.8.0/24", "2606:4700::/32"]})");
    write(root.path() / "allow.json", R"({"ips": ["8.8.8.8", "192.168.0.0/16"]})");
    // VPN database format 1 with no providers and one address, 9.9.9.9.
    write(root.path() / "vpn.bin", std::string("VPDB\x01\0\0\0", 8) +
          std::string("\0\0\0\0\x01\0\0\0", 8) + std::string(12, '\0') +
          std::string("\x09\x09\x09\x09\0\0", 6));
    const auto deny = DestinationListAction::Deny;
    const auto json = DestinationListFormat::Json;
    const std::vector<DestinationList> lists{
        {deny, json, FileReference("deny.json")},
        {DestinationListAction::Allow, json, FileReference((root.path() / "allow.json").string())},
        {deny, DestinationListFormat::Vpdb, FileReference("vpn.bin")}};
    std::vector<Adapter> adapters;
    adapters.emplace_back(DirectTcpAdapter("web", DestinationPolicy(true, {}, lists)));
    adapters.emplace_back(DirectUdpAdapter("web", DestinationPolicy(true, {}, lists)));
    adapters.emplace_back(DirectTcpAdapter("lan", DestinationPolicy(false, networks({"10.0.0.0/8"}), lists)));
    const auto egress = take(NativeEgressPolicy::create(adapters, root.path()));
    const auto tcp = NetworkProtocol::Tcp;
    CHECK(allowed(*egress, "web", v4(tcp, {8U, 8U, 4U, 4U})));
    CHECK(!allowed(*egress, "web", v4(tcp, {8U, 8U, 8U, 9U})));
    CHECK(allowed(*egress, "web", v4(tcp, {8U, 8U, 8U, 8U})));
    CHECK(!allowed(*egress, "web", v4(tcp, {9U, 9U, 9U, 9U})));
    CHECK(!allowed(*egress, "web", v6(tcp, "::ffff:808:809")));
    CHECK(!allowed(*egress, "web", v6(tcp, "2606:4700::1111")));
    CHECK(!allowed(*egress, "web", v4(NetworkProtocol::Udp, {8U, 8U, 8U, 9U})));
    CHECK(!allowed(*egress, "lan", v4(tcp, {192U, 168U, 1U, 1U})));
    CHECK(allowed(*egress, "lan", v4(tcp, {10U, 1U, 2U, 3U})));
    CHECK(egress->authorize_address("web", v4(tcp, {8U, 8U, 8U, 9U})).message().find("egress list") !=
          std::string::npos);

    // A load failure names the configuration entry and creates nothing.
    const auto refused = [&](DestinationPolicy destinations, const std::string& fragment) {
        std::vector<Adapter> pair;
        pair.emplace_back(DirectTcpAdapter("plain", DestinationPolicy(true, {})));
        pair.emplace_back(DirectTcpAdapter("web", std::move(destinations)));
        const auto created = NativeEgressPolicy::create(pair, root.path());
        CHECK(!created.ok());
        if (created.status().message().find(fragment) == std::string::npos) {
            std::cerr << "unexpected message: " << created.status().message() << "\n";
            std::abort();
        }
    };
    const auto one = [](DestinationListFormat format, const char* file) {
        return std::vector<DestinationList>{{DestinationListAction::Deny, format, FileReference(file)}};
    };
    write(root.path() / "bad.json", R"({"ips": ["8.8.8.0/24", "nonsense"]})");
    refused(DestinationPolicy(true, {}, one(json, "bad.json")), "/adapters/1/destinations/lists/0: /ips/1:");
    refused(DestinationPolicy(true, {}, one(json, "missing.json")), "/adapters/1/destinations/lists/0:");
    refused(DestinationPolicy(true, {}, one(DestinationListFormat::Vpdb, "deny.json")),
            "/adapters/1/destinations/lists/0: not a VPN database");
    write(root.path() / "countries.json", R"({"countries": ["US"]})");
    refused(DestinationPolicy(true, {}, one(json, "countries.json")),
            "/adapters/1/destinations: a list names countries, so country_database is required");
    refused(DestinationPolicy(true, {}, one(json, "deny.json"), FileReference("GeoLite2-Country.mmdb")),
            "/adapters/1/destinations/country_database: no list names a country");
    write(root.path() / "not.mmdb", "not a database");
    refused(DestinationPolicy(true, {}, one(json, "countries.json"), FileReference("not.mmdb")),
            "/adapters/1/destinations/country_database: country database has no MaxMind DB metadata");
    std::filesystem::create_symlink(root.path() / "deny.json", root.path() / "link.json");
    refused(DestinationPolicy(true, {}, one(json, "link.json")), "/adapters/1/destinations/lists/0:");
}

int main() {
    test_creation();
    test_public_addresses();
    test_explicit_networks();
    test_request_stage();
    test_egress_lists();
    std::cout << "native egress policy checks passed\n";
}
