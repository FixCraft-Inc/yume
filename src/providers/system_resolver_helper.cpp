/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/system_resolver_helper.hpp"

#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <thread>

#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "providers/process_privileges.hpp"
#include "providers/system_resolver_protocol.hpp"

namespace yume::providers {
namespace {

namespace protocol = resolver_protocol;

constexpr int kDescriptor = protocol::kHelperDescriptor;

std::atomic<std::size_t> active_lookups{0U};

#if defined(YUME_SYSTEM_RESOLVER_TEST_STALL)
// Test builds only: a lookup of this name blocks forever, standing in for an
// NSS module or DNS server that never answers. Only killing the helper ends it.
constexpr std::string_view kStallHost = "resolver-stall.invalid";
#endif

void send_message(const std::uint8_t* data, std::size_t size) noexcept {
    for (;;) {
        if (::send(kDescriptor, data, size, MSG_NOSIGNAL) >= 0) return;
        if (errno == EINTR) continue;
        // The parent is gone or the socket is unusable. Nothing else here
        // needs orderly cleanup.
        std::_Exit(0);
    }
}

void send_status(std::uint32_t id, protocol::LookupStatus status) noexcept {
    protocol::Response response;
    response.id = id;
    response.status = status;
    std::array<std::uint8_t, protocol::kMaxResponseBytes> out{};
    const std::size_t size = protocol::encode_response(response, out);
    if (size != 0U) send_message(out.data(), size);
}

protocol::LookupStatus lookup_status(int error) noexcept {
    switch (error) {
    case EAI_NONAME:
#if defined(EAI_NODATA)
    case EAI_NODATA:
#endif
#if defined(EAI_ADDRFAMILY)
    case EAI_ADDRFAMILY:
#endif
        return protocol::LookupStatus::NotFound;
    case EAI_AGAIN:
        return protocol::LookupStatus::TemporaryFailure;
    default:
        return protocol::LookupStatus::Failure;
    }
}

void lookup(std::uint32_t id, std::uint8_t max_addresses, const std::string& host) noexcept {
#if defined(YUME_SYSTEM_RESOLVER_TEST_STALL)
    if (host == kStallHost) {
        for (;;) ::pause();
    }
#endif
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    // One entry per address. The caller chooses the transport protocol.
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* results = nullptr;
    const int error = ::getaddrinfo(host.c_str(), nullptr, &hints, &results);
    protocol::Response response;
    response.id = id;
    if (error != 0) {
        response.status = lookup_status(error);
    } else {
        response.status = protocol::LookupStatus::Ok;
        for (const addrinfo* entry = results;
             entry != nullptr && response.count < max_addresses; entry = entry->ai_next) {
            protocol::Address& address = response.addresses[response.count];
            if (entry->ai_family == AF_INET &&
                entry->ai_addrlen >= sizeof(sockaddr_in)) {
                sockaddr_in ipv4{};
                std::memcpy(&ipv4, entry->ai_addr, sizeof(ipv4));
                address.family = 4U;
                std::memcpy(address.bytes.data(), &ipv4.sin_addr, 4U);
            } else if (entry->ai_family == AF_INET6 &&
                       entry->ai_addrlen >= sizeof(sockaddr_in6)) {
                sockaddr_in6 ipv6{};
                std::memcpy(&ipv6, entry->ai_addr, sizeof(ipv6));
                address.family = 6U;
                std::memcpy(address.bytes.data(), &ipv6.sin6_addr, 16U);
                address.scope_id = ipv6.sin6_scope_id;
            } else {
                continue;
            }
            ++response.count;
        }
        ::freeaddrinfo(results);
        if (response.count == 0U) response.status = protocol::LookupStatus::NotFound;
    }
    std::array<std::uint8_t, protocol::kMaxResponseBytes> out{};
    const std::size_t size = protocol::encode_response(response, out);
    if (size != 0U) send_message(out.data(), size);
    active_lookups.fetch_sub(1U, std::memory_order_acq_rel);
}

bool inherited_socketpair() noexcept {
    int value = 0;
    socklen_t length = sizeof(value);
    if (::getsockopt(kDescriptor, SOL_SOCKET, SO_TYPE, &value, &length) != 0 ||
        value != SOCK_SEQPACKET) {
        return false;
    }
    length = sizeof(value);
    return ::getsockopt(kDescriptor, SOL_SOCKET, SO_DOMAIN, &value, &length) == 0 &&
           value == AF_UNIX;
}

}  // namespace

bool is_system_resolver_helper(int argc, const char* const* argv) noexcept {
    return argc == 1 && argv != nullptr && argv[0] != nullptr &&
           std::string_view(argv[0]) == protocol::kHelperArgv0;
}

int run_system_resolver_helper() noexcept {
    if (!inherited_socketpair()) {
        static constexpr char kMessage[] =
            "yume-resolver: internal helper, started only by YUME\n";
        [[maybe_unused]] const auto ignored = ::write(2, kMessage, sizeof(kMessage) - 1U);
        return 2;
    }
    // The helper runs the system's DNS and NSS parsing and needs no privilege.
    drop_process_privileges();
    const auto hello = protocol::encode_hello();
    send_message(hello.data(), hello.size());

    // One byte of headroom detects an oversize message without MSG_TRUNC.
    std::array<std::uint8_t, protocol::kMaxRequestBytes + 1U> buffer{};
    for (;;) {
        iovec vector{buffer.data(), buffer.size()};
        msghdr message{};
        message.msg_iov = &vector;
        message.msg_iovlen = 1U;
        const ssize_t received = ::recvmsg(kDescriptor, &message, 0);
        if (received == 0) std::_Exit(0);
        if (received < 0) {
            if (errno == EINTR) continue;
            std::_Exit(1);
        }
        const auto request = (message.msg_flags & MSG_TRUNC) != 0
            ? std::nullopt
            : protocol::decode_request(std::span<const std::uint8_t>(
                  buffer.data(), static_cast<std::size_t>(received)));
        // The parent never sends malformed requests. Refusing to continue
        // keeps an unexpected peer from steering further lookups.
        if (!request) std::_Exit(3);
        if (active_lookups.fetch_add(1U, std::memory_order_acq_rel) >=
            protocol::kMaxOutstanding) {
            active_lookups.fetch_sub(1U, std::memory_order_acq_rel);
            send_status(request->id, protocol::LookupStatus::Busy);
            continue;
        }
        try {
            // Detached lookups end with this disposable process. The parent
            // replaces the whole helper to reclaim a stalled one.
            std::thread(lookup, request->id, request->max_addresses,
                        std::string(request->host)).detach();
        } catch (...) {
            active_lookups.fetch_sub(1U, std::memory_order_acq_rel);
            send_status(request->id, protocol::LookupStatus::Failure);
        }
    }
}

}  // namespace yume::providers
