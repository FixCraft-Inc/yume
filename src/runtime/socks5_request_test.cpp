/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/socks5_request.hpp"

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

namespace {
using namespace yume::runtime::socks5;
using yume::engine::RouteAddressKind;
using yume::engine::Status;
using yume::engine::StatusCode;

#define CHECK(condition) do { if (!(condition)) { \
    std::cerr << "socks5 check failed at " << __LINE__ << ": " #condition "\n"; \
    std::abort(); \
} } while (false)

std::vector<std::uint8_t> name_request(std::uint8_t command, const std::string& name, std::uint16_t port) {
    std::vector<std::uint8_t> bytes{kVersion, command, 0x00, 0x03, static_cast<std::uint8_t>(name.size())};
    bytes.insert(bytes.end(), name.begin(), name.end());
    bytes.push_back(static_cast<std::uint8_t>(port >> 8U));
    bytes.push_back(static_cast<std::uint8_t>(port));
    return bytes;
}

void test_greeting() {
    Greeting greeting;
    const std::vector<std::uint8_t> offer{kVersion, 0x02, 0x02, 0x00, 0x05, 0x01};
    for (std::size_t size = 0U; size < 4U; ++size) {
        CHECK(parse_greeting(std::span(offer).first(size), greeting) == Parse::NeedMore);
        CHECK(greeting.required_bytes == (size < 2U ? 2U : 4U));
    }
    CHECK(parse_greeting(offer, greeting) == Parse::Complete);
    CHECK(greeting.consumed == 4U && greeting.no_authentication);
    const std::vector<std::uint8_t> password_only{kVersion, 0x01, 0x02};
    CHECK(parse_greeting(password_only, greeting) == Parse::Complete && !greeting.no_authentication);
    CHECK(parse_greeting(std::vector<std::uint8_t>{0x04, 0x01, 0x00}, greeting) == Parse::Invalid);
    CHECK(parse_greeting(std::vector<std::uint8_t>{kVersion, 0x00}, greeting) == Parse::Invalid);
    CHECK(method_reply(true) == (std::array<std::uint8_t, 2>{kVersion, 0x00}));
    CHECK(method_reply(false) == (std::array<std::uint8_t, 2>{kVersion, 0xff}));
}

void test_numeric_requests() {
    Request request;
    const std::vector<std::uint8_t> v4{kVersion, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0x01, 0xbb, 0xaa};
    for (std::size_t size = 0U; size < 10U; ++size) {
        CHECK(parse_request(std::span(v4).first(size), request) == Parse::NeedMore);
        CHECK(request.required_bytes == (size < 4U ? 4U : 10U));
    }
    CHECK(parse_request(v4, request) == Parse::Complete);
    CHECK(request.consumed == 10U && request.reply == Reply::Succeeded && request.destination);
    CHECK(request.destination->address_kind() == RouteAddressKind::Ipv4 && request.destination->port() == 443U);

    std::vector<std::uint8_t> v6{kVersion, 0x01, 0x00, 0x04};
    v6.resize(20U, 0x00);
    v6[19] = 0x01;
    v6.push_back(0x00);
    v6.push_back(0x50);
    for (std::size_t size = 0U; size < v6.size(); ++size) {
        CHECK(parse_request(std::span(v6).first(size), request) == Parse::NeedMore);
        CHECK(request.required_bytes == (size < 4U ? 4U : v6.size()));
    }
    CHECK(parse_request(v6, request) == Parse::Complete);
    CHECK(request.consumed == 22U && request.destination->address_kind() == RouteAddressKind::Ipv6 &&
          request.destination->port() == 80U);

    std::vector<std::uint8_t> reserved = v4;
    reserved[2] = 0x01;
    CHECK(parse_request(reserved, request) == Parse::Invalid);
    std::vector<std::uint8_t> zero_port = v4;
    zero_port[8] = zero_port[9] = 0x00;
    CHECK(parse_request(zero_port, request) == Parse::Complete && request.reply == Reply::GeneralFailure &&
          !request.destination);
    const std::vector<std::uint8_t> unknown_type{kVersion, 0x01, 0x00, 0x09, 1, 2};
    CHECK(parse_request(unknown_type, request) == Parse::Complete && request.reply == Reply::AddressNotSupported);
}

void test_name_requests() {
    Request request;
    auto bytes = name_request(0x01, "Example.COM", 443U);
    for (std::size_t size = 0U; size < bytes.size(); ++size) {
        CHECK(parse_request(std::span(bytes).first(size), request) == Parse::NeedMore);
        CHECK(request.required_bytes == (size < 4U ? 4U : size < 5U ? 5U : bytes.size()));
    }
    CHECK(parse_request(bytes, request) == Parse::Complete && request.reply == Reply::Succeeded);
    CHECK(request.consumed == bytes.size() && request.destination->address_kind() == RouteAddressKind::DnsName);
    CHECK(request.destination->dns_name() == "example.com");

    bytes = name_request(0x01, "127.0.0.1", 8080U);
    CHECK(parse_request(bytes, request) == Parse::Complete &&
          request.destination->address_kind() == RouteAddressKind::Ipv4);
    bytes = name_request(0x01, "::1", 8080U);
    CHECK(parse_request(bytes, request) == Parse::Complete &&
          request.destination->address_kind() == RouteAddressKind::Ipv6);
    for (const char* refused : {"fe80::1%eth0", "bad_name!", "space name", "caf\xc3\xa9.test"}) {
        bytes = name_request(0x01, refused, 443U);
        CHECK(parse_request(bytes, request) == Parse::Complete && request.reply == Reply::AddressNotSupported &&
              !request.destination && request.consumed == bytes.size());
    }
    const std::vector<std::uint8_t> empty_name{kVersion, 0x01, 0x00, 0x03, 0x00};
    CHECK(parse_request(empty_name, request) == Parse::Complete && request.reply == Reply::AddressNotSupported);
    bytes = name_request(0x02, "example.com", 53U);
    CHECK(parse_request(bytes, request) == Parse::Complete &&
          request.reply == Reply::CommandNotSupported && request.consumed == bytes.size());
    const std::string longest(255U, 'a');
    bytes = name_request(0x01, longest, 443U);
    CHECK(bytes.size() == kMaxRequestBytes);
    CHECK(parse_request(bytes, request) == Parse::Complete && request.reply == Reply::AddressNotSupported);
}

void test_udp_associate_requests() {
    Request request;
    // Clients usually announce 0.0.0.0:0. The address is never a destination.
    const std::vector<std::uint8_t> unknown_source{kVersion, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    for (std::size_t size = 0U; size < unknown_source.size(); ++size) {
        CHECK(parse_request(std::span(unknown_source).first(size), request) == Parse::NeedMore);
    }
    CHECK(parse_request(unknown_source, request) == Parse::Complete);
    CHECK(request.reply == Reply::Succeeded && request.command == Command::UdpAssociate);
    CHECK(request.udp_source_port == 0U && !request.destination && request.consumed == 10U);

    // A name or an invalid literal is accepted too, since only the port is used.
    auto bytes = name_request(0x03, "bad_name!", 5353U);
    CHECK(parse_request(bytes, request) == Parse::Complete && request.reply == Reply::Succeeded);
    CHECK(request.command == Command::UdpAssociate && request.udp_source_port == 5353U);

    // A refusal after an association must not leave the UDP fields behind.
    const std::vector<std::uint8_t> unknown_type{kVersion, 0x03, 0x00, 0x09, 1, 2};
    CHECK(parse_request(unknown_type, request) == Parse::Complete);
    CHECK(request.reply == Reply::AddressNotSupported && request.command == Command::Connect);
    CHECK(request.udp_source_port == 0U);
}

std::vector<std::uint8_t> datagram(std::vector<std::uint8_t> header, std::string_view payload) {
    header.insert(header.end(), payload.begin(), payload.end());
    return header;
}

void test_udp_datagrams() {
    const auto v4 = datagram({0, 0, 0, 0x01, 192, 0, 2, 7, 0x00, 0x35}, "query");
    auto parsed = parse_udp_datagram(v4);
    CHECK(parsed && parsed->payload_offset == 10U);
    CHECK(parsed->destination.protocol() == yume::engine::NetworkProtocol::Udp);
    CHECK(parsed->destination.address_kind() == RouteAddressKind::Ipv4 && parsed->destination.port() == 53U);
    CHECK(udp_header(parsed->destination) ==
          (std::vector<std::uint8_t>{0, 0, 0, 0x01, 192, 0, 2, 7, 0x00, 0x35}));

    std::vector<std::uint8_t> v6_header{0, 0, 0, 0x04};
    v6_header.resize(20U, 0x00);
    v6_header[19] = 0x01;
    v6_header.push_back(0x01);
    v6_header.push_back(0xbb);
    parsed = parse_udp_datagram(datagram(v6_header, "x"));
    CHECK(parsed && parsed->payload_offset == 22U && parsed->destination.address_kind() == RouteAddressKind::Ipv6);
    CHECK(udp_header(parsed->destination) == v6_header);

    const std::vector<std::uint8_t> name_header{0, 0, 0, 0x03, 7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 0x00, 0x35};
    parsed = parse_udp_datagram(datagram(name_header, "q"));
    CHECK(parsed && parsed->payload_offset == name_header.size());
    CHECK(parsed->destination.address_kind() == RouteAddressKind::DnsName &&
          parsed->destination.dns_name() == "example");
    // Replies name the destination as the client's lowercase request did.
    const std::vector<std::uint8_t> lowered{0, 0, 0, 0x03, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x00, 0x35};
    CHECK(udp_header(parsed->destination) == lowered);

    // The payload may be empty here. The relay decides what to do with it.
    parsed = parse_udp_datagram(std::vector<std::uint8_t>{0, 0, 0, 0x01, 127, 0, 0, 1, 0x00, 0x35});
    CHECK(parsed && parsed->payload_offset == 10U);

    // Dropped: reserved bytes, fragments, unknown or empty address types,
    // truncated headers, a zero port and scoped literals.
    for (const auto& refused : std::vector<std::vector<std::uint8_t>>{
             {0, 1, 0, 0x01, 127, 0, 0, 1, 0x00, 0x35},
             {1, 0, 0, 0x01, 127, 0, 0, 1, 0x00, 0x35},
             {0, 0, 1, 0x01, 127, 0, 0, 1, 0x00, 0x35},
             {0, 0, 0, 0x02, 127, 0, 0, 1, 0x00, 0x35},
             {0, 0, 0, 0x03, 0x00, 0x00, 0x35},
             {0, 0, 0, 0x01, 127, 0, 0, 1, 0x00},
             {0, 0, 0, 0x03, 5, 'a', 'b'},
             {0, 0, 0, 0x01, 127, 0, 0, 1, 0x00, 0x00},
             {0, 0, 0},
             datagram({0, 0, 0, 0x03, 12}, "fe80::1%eth0\x00\x35"),
         }) {
        CHECK(!parse_udp_datagram(refused));
    }

    const auto relay = yume::engine::RouteDestination::ipv4(
        yume::engine::NetworkProtocol::Udp, {127, 0, 0, 1}, 40000U);
    CHECK(relay.ok());
    CHECK(associate_reply(relay.value()) ==
          (std::vector<std::uint8_t>{kVersion, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x9c, 0x40}));
}

void test_replies() {
    CHECK(reply(Reply::NotAllowed) ==
          (std::array<std::uint8_t, 10>{kVersion, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0}));
    CHECK(reply(Reply::TtlExpired) ==
          (std::array<std::uint8_t, 10>{kVersion, 0x06, 0x00, 0x01, 0, 0, 0, 0, 0, 0}));
    CHECK(reply_for(Status::success()) == Reply::Succeeded);
    CHECK(reply_for(Status(StatusCode::FailedPrecondition)) == Reply::NotAllowed);
    CHECK(reply_for(Status(StatusCode::PermissionDenied)) == Reply::NotAllowed);
    CHECK(reply_for(Status(StatusCode::NotFound)) == Reply::NotAllowed);
    CHECK(reply_for(Status(StatusCode::Internal)) == Reply::HostUnreachable);
    CHECK(reply_for(Status(StatusCode::Cancelled)) == Reply::HostUnreachable);
    CHECK(reply_for(Status(StatusCode::Closed)) == Reply::GeneralFailure);
    CHECK(reply_for(Status(StatusCode::ResourceExhausted)) == Reply::GeneralFailure);
}

}  // namespace

int main() {
    test_greeting();
    test_numeric_requests();
    test_name_requests();
    test_udp_associate_requests();
    test_udp_datagrams();
    test_replies();
    std::cout << "SOCKS5 request checks passed\n";
}
