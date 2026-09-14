/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "common/egress_address.hpp"
#include "common/ip_network.hpp"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>

namespace {
using yume::common::EgressAddress;
using yume::common::EgressAddressClass;
using yume::common::IpFamily;
using yume::common::IpNetwork;
using yume::common::kMaxIpNetworkTextBytes;

#define CHECK(condition) do { if (!(condition)) { \
    std::cerr << "ip network check failed at " << __LINE__ << ": " #condition "\n"; \
    std::abort(); \
} } while (false)

std::string text_of(const IpNetwork& network) {
    std::array<char, kMaxIpNetworkTextBytes> buffer{};
    return std::string(buffer.data(), yume::common::format_ip_network(network, buffer));
}

IpNetwork network_of(const std::string& text) {
    const auto parsed = yume::common::parse_canonical_ip_network(text);
    if (!parsed) std::cerr << "not a canonical network: " << text << '\n';
    CHECK(parsed);
    return *parsed;
}

void test_vectors(const char* path) {
    std::ifstream input(path);
    CHECK(input);
    std::string line;
    std::size_t valid = 0U, never = 0U, invalid = 0U;
    while (std::getline(input, line)) {
        if (line.empty() || line.front() == '#') continue;
        const auto space = line.find(' ');
        CHECK(space != std::string::npos);
        const std::string kind = line.substr(0U, space);
        const std::string text = line.substr(space + 1U);
        const auto parsed = yume::common::parse_canonical_ip_network(text);
        if (kind == "invalid") {
            if (parsed) std::cerr << "accepted invalid vector " << text << '\n';
            CHECK(!parsed);
            ++invalid;
            continue;
        }
        CHECK(kind == "valid" || kind == "never");
        if (!parsed) std::cerr << "rejected canonical vector " << text << '\n';
        CHECK(parsed && text_of(*parsed) == text);
        const bool never_allowed = yume::common::ip_network_never_allowed(*parsed);
        if (never_allowed != (kind == "never")) std::cerr << "wrong usability for " << text << '\n';
        CHECK(never_allowed == (kind == "never"));
        ++(kind == "valid" ? valid : never);
    }
    CHECK(valid >= 10U && never >= 5U && invalid >= 20U);
}

void test_text_bounds() {
    for (const char* text : {"", "/", " 10.0.0.0/8", "10.0.0.0/8 ", "10.0.0.0 /8",
                             "::/", "/128", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/0128"}) {
        CHECK(!yume::common::parse_canonical_ip_network(text));
    }
    CHECK(text_of(network_of("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128")).size() ==
          kMaxIpNetworkTextBytes);
}

// Every arrangement of zero and nonzero groups formats canonically and parses
// back. The fully written form is canonical only without a run of two zeros.
void test_every_zero_group_pattern() {
    for (unsigned pattern = 0U; pattern < 256U; ++pattern) {
        IpNetwork network;
        network.family = IpFamily::V6;
        network.prefix_length = 128U;
        std::string written;
        bool zero_run = false;
        for (unsigned group = 0U; group < 8U; ++group) {
            const bool zero = (pattern >> group) & 1U;
            const unsigned value = zero ? 0U : 0xa0U + group;
            network.address[group * 2U] = static_cast<std::uint8_t>(value >> 8U);
            network.address[group * 2U + 1U] = static_cast<std::uint8_t>(value);
            if (group != 0U) written += ':';
            written += zero ? std::string("0") : std::string{'a', static_cast<char>('0' + group)};
            if (zero && group != 0U && ((pattern >> (group - 1U)) & 1U)) zero_run = true;
        }
        const auto parsed = yume::common::parse_canonical_ip_network(text_of(network));
        CHECK(parsed && *parsed == network);
        const auto full = yume::common::parse_canonical_ip_network(written + "/128");
        CHECK(static_cast<bool>(full) == !zero_run);
        if (full) CHECK(*full == network);
    }
}

void test_contains() {
    const std::array<std::uint8_t, 4> inside{10U, 1U, 2U, 3U};
    const std::array<std::uint8_t, 4> outside{11U, 1U, 2U, 3U};
    CHECK(yume::common::ip_network_contains(network_of("10.0.0.0/8"), IpFamily::V4, inside));
    CHECK(!yume::common::ip_network_contains(network_of("10.0.0.0/8"), IpFamily::V4, outside));
    CHECK(yume::common::ip_network_contains(network_of("0.0.0.0/0"), IpFamily::V4, outside));
    const std::array<std::uint8_t, 4> shared_last{100U, 127U, 255U, 255U};
    const std::array<std::uint8_t, 4> shared_after{100U, 128U, 0U, 0U};
    CHECK(yume::common::ip_network_contains(network_of("100.64.0.0/10"), IpFamily::V4, shared_last));
    CHECK(!yume::common::ip_network_contains(network_of("100.64.0.0/10"), IpFamily::V4, shared_after));
    const auto ula = network_of("fd00::1/128");
    CHECK(yume::common::ip_network_contains(network_of("fc00::/7"), IpFamily::V6, ula.address));
    CHECK(!yume::common::ip_network_contains(network_of("fe80::/10"), IpFamily::V6, ula.address));
    // Families and address sizes never match each other.
    CHECK(!yume::common::ip_network_contains(network_of("::/0"), IpFamily::V4, inside));
    CHECK(!yume::common::ip_network_contains(network_of("0.0.0.0/0"), IpFamily::V6, ula.address));
    CHECK(!yume::common::ip_network_contains(network_of("0.0.0.0/0"), IpFamily::V4,
                                             std::span<const std::uint8_t>(ula.address)));
}

EgressAddress address_of(const std::string& text) {
    const auto family = text.find(':') == std::string::npos ? IpFamily::V4 : IpFamily::V6;
    const auto network = network_of(text + (family == IpFamily::V4 ? "/32" : "/128"));
    const auto address = EgressAddress::from_bytes(
        family, std::span<const std::uint8_t>(network.address).first(family == IpFamily::V4 ? 4U : 16U));
    CHECK(address);
    return *address;
}

void test_classification() {
    const auto expect = [](const char* text, EgressAddressClass expected) {
        const auto actual = yume::common::classify_egress_address(address_of(text));
        if (actual != expected) std::cerr << "wrong class for " << text << '\n';
        CHECK(actual == expected);
    };
    for (const char* text : {"1.1.1.1", "8.8.8.8", "192.0.1.1", "198.51.99.1", "203.0.114.1",
                             "100.63.255.255", "100.128.0.0", "172.15.255.255", "172.32.0.0",
                             "169.253.255.255", "198.20.0.0", "223.255.255.255",
                             "2606:4700::1111", "2001:4860:4860::8888", "2001:200::1",
                             "3ffe::1", "::ffff:808:808"}) {
        expect(text, EgressAddressClass::Public);
    }
    for (const char* text : {"10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254",
                             "172.16.0.1", "172.31.255.255", "192.0.0.9", "192.0.2.1",
                             "192.88.99.1", "192.168.0.1", "198.18.0.1", "198.19.255.255",
                             "198.51.100.1", "203.0.113.1", "::1", "fe80::1", "fd00::1",
                             "fec0::1", "64:ff9b::a00:1", "2001::1", "2001:1ff::1",
                             "2001:db8::1", "2002:a00:1::1", "3fff::1", "100::1", "::a00:1",
                             "5f00::1", "4000::1", "::ffff:7f00:1"}) {
        expect(text, EgressAddressClass::ExplicitOnly);
    }
    for (const char* text : {"0.0.0.0", "0.1.2.3", "224.0.0.1", "239.255.255.255",
                             "240.0.0.1", "255.255.255.255", "::", "ff02::1",
                             "::ffff:0:0", "::ffff:e000:1"}) {
        expect(text, EgressAddressClass::NeverAllowed);
    }

    // A mapped address is evaluated as IPv4, so only IPv4 networks contain it.
    const auto mapped = address_of("::ffff:a01:203");
    CHECK(mapped.family() == IpFamily::V4 && mapped.bytes().size() == 4U);
    CHECK(yume::common::ip_network_contains(network_of("10.0.0.0/8"), mapped.family(), mapped.bytes()));
    CHECK(!yume::common::ip_network_contains(network_of("::/0"), mapped.family(), mapped.bytes()));
    const std::array<std::uint8_t, 3> short_address{10U, 0U, 0U};
    CHECK(!EgressAddress::from_bytes(IpFamily::V4, short_address));
    CHECK(!EgressAddress::from_bytes(IpFamily::V6, std::span<const std::uint8_t>(mapped.bytes())));
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    test_vectors(argv[1]);
    test_text_bounds();
    test_every_zero_group_pattern();
    test_contains();
    test_classification();
    std::cout << "canonical IP network and egress address checks passed\n";
}
