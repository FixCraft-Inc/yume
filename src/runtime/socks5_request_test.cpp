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
    }
    CHECK(parse_request(v4, request) == Parse::Complete);
    CHECK(request.consumed == 10U && request.reply == Reply::Succeeded && request.destination);
    CHECK(request.destination->address_kind() == RouteAddressKind::Ipv4 && request.destination->port() == 443U);

    std::vector<std::uint8_t> v6{kVersion, 0x01, 0x00, 0x04};
    v6.resize(20U, 0x00);
    v6[19] = 0x01;
    v6.push_back(0x00);
    v6.push_back(0x50);
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
    for (const std::uint8_t command : {0x02, 0x03}) {
        bytes = name_request(command, "example.com", 53U);
        CHECK(parse_request(bytes, request) == Parse::Complete &&
              request.reply == Reply::CommandNotSupported && request.consumed == bytes.size());
    }
    const std::string longest(255U, 'a');
    bytes = name_request(0x01, longest, 443U);
    CHECK(bytes.size() == kMaxRequestBytes);
    CHECK(parse_request(bytes, request) == Parse::Complete && request.reply == Reply::AddressNotSupported);
}

void test_replies() {
    CHECK(reply(Reply::NotAllowed) ==
          (std::array<std::uint8_t, 10>{kVersion, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0}));
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
    test_replies();
    std::cout << "SOCKS5 request checks passed\n";
}
