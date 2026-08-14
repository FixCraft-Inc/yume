/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * ----------------------------------------------------------------
 * Internal (server-private) helpers shared across the session_*.cpp
 * translation units that together implement yume::server::Session.
 *
 * These were originally a single anonymous namespace at the top of
 * session.cpp. When session.cpp was split by responsibility, the
 * shared constants / free helpers / DirectDnsAQuery had to become
 * visible to more than one TU, so they live here in
 * yume::server::detail. Each session_*.cpp does:
 *     #include "server/session/internal.hpp"
 *     using namespace detail;   // inside namespace yume::server
 * so the moved method bodies compile unchanged.
 *
 * This is an INTERNAL header: it is included only by the session_*.cpp
 * files, never by a public consumer. No behavior change vs. the
 * former anonymous namespace.
 * ---------------------------------------------------------------- */

#pragma once

#include <array>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/pem.h>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
// vcpkg's modularised Boost (x64-mingw-dynamic) does not always pull
// these through <boost/asio.hpp> like Debian's system Boost does.
#include <boost/asio/deadline_timer.hpp>
#include <boost/date_time/posix_time/posix_time_duration.hpp>
#include <nlohmann/json.hpp>

#include "core/protocol/packet_bulk.hpp"
#include "core/protocol/protocol.hpp"
#include "core/protocol/runtime_policy.hpp"
#include "core/security/inner_crypto.hpp"
#include "core/stealth/http_profile.hpp"
#include "core/stealth/obfs_h2.hpp"
#include "core/stealth/obfs_signal.hpp"
#include "core/version.hpp"
#include "server/auth/auth.hpp"
#include "server/config/config.hpp"
#include "util.hpp"

#if YUME_USE_BASEFWX
#include <basefwx/base64.hpp>
#include <basefwx/constants.hpp>
#include <basefwx/crypto.hpp>
#endif

namespace yume::server {

class Manager;  // egress_filter_allows() only needs a pointer

namespace detail {

// ---- Constants (formerly session.cpp anonymous namespace) ----------------
inline constexpr uint32_t kMaxFrameSize = 16 * 1024 * 1024;
inline constexpr uint8_t kMinFrameType = protocol::AUTH;
inline constexpr uint8_t kMaxFrameType = protocol::REKEY_ACK;
inline constexpr int64_t kIdleTimeoutMs = 90 * 1000;
inline constexpr int64_t kIdleCheckIntervalMs = 30 * 1000;
inline constexpr int64_t kFrameHeaderTimeoutMs = 90 * 1000;
inline constexpr int64_t kFramePayloadTimeoutMs = 30 * 1000;
// Decrypt-time hop-key tolerance. With hop_interval_ms=500 (default),
// 120 hops = ±60 s of clock-drift / queue-delay tolerance. Wide enough
// for an Android client whose outbound TLS pipe backs up under congested
// upload (frames can sit queued 12+ s, pushing their hop_id outside a
// narrower window and triggering a spurious "DATA decrypt failed" reset).
inline constexpr std::uint64_t kHopDecryptWindow = 120;
inline constexpr int64_t kResolverTimeoutMs = 8000;
inline constexpr int64_t kConnectTimeoutMs = 15000;
inline constexpr int64_t kReverseAcceptTimeoutMs = 30000;
inline constexpr uint32_t kMaxWriteQueueSize = 512;
inline constexpr uint32_t kWriteQueueHighWatermark = 64;
inline constexpr uint32_t kWriteQueueLowWatermark = 16;
inline constexpr uint32_t kMaxWriteBatchFrames = 64;
inline constexpr std::size_t kMaxWriteBatchBytes = 1024 * 1024;
inline constexpr int kSocketBufferBytes = 2 * 1024 * 1024;
inline constexpr const char kBenchSinkProto[] = "bench-sink-v1";
inline constexpr const char kBenchSourceProto[] = "bench-source-v1";
inline constexpr const char kBenchEchoProto[] = "bench-message-echo-v1";
inline constexpr std::uint64_t kBenchMaxBytes = 16ULL * 1024ULL * 1024ULL * 1024ULL;
inline constexpr std::uint32_t kBenchSourceWindowFrames = 64;
inline constexpr int64_t kDirectDnsTimeoutMs = 1500;

// ---- Free helpers (defined in session_net.cpp) ---------------------------
int64_t steady_now_ms();
bool auth_debug_enabled();
bool looks_like_inner_auth_exception(const std::string& message);
bool is_private_ipv4(const boost::asio::ip::address_v4& addr);
bool is_private_ipv6(const boost::asio::ip::address_v6& addr);
bool is_public_address(const boost::asio::ip::address& addr);
bool is_allowed_address(const boost::asio::ip::address& addr, bool allow_local_ip, bool control_full);
bool egress_filter_allows(Manager* manager, const boost::asio::ip::address& address, std::string* reason);
bool is_blocked_host_literal(const std::string& host, bool allow_local_ip, bool control_full);
boost::asio::ip::address canonical_endpoint_address(const boost::asio::ip::address& addr);
bool addresses_match(const boost::asio::ip::address& lhs, const boost::asio::ip::address& rhs);
std::optional<boost::asio::ip::address> session_local_address(
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream);
bool starts_with(std::string_view value, std::string_view prefix);
bool is_background_probe_close_reason(const std::string& reason);
bool is_server_fault_close_reason(const std::string& reason);
std::string summarize_header_prefix(const std::array<uint8_t, 8>& header);
bool header_starts_with_ascii(const std::array<uint8_t, 8>& header, std::string_view prefix);
bool is_http_probe_header(const std::array<uint8_t, 8>& header);
int random_int_inclusive(int min_value, int max_value);
bool is_expected_close_ec(const boost::system::error_code& ec);
bool is_expected_close_reason(const std::string& reason);
std::string describe_error_code(const boost::system::error_code& ec);
bool env_value_enabled(const char* raw);
bool server_resolve_any_family_enabled();
void append_u16(std::vector<uint8_t>* out, std::uint16_t value);
std::uint16_t read_u16(const uint8_t* data, std::size_t offset);
bool append_dns_name(std::vector<uint8_t>* out, std::string host);
bool skip_dns_name(const uint8_t* data, std::size_t len, std::size_t* offset);
bool parse_dns_a_response(const uint8_t* data,
                          std::size_t len,
                          std::uint16_t expected_id,
                          std::vector<boost::asio::ip::address_v4>* out,
                          std::string* error);
std::uint32_t read_ipv4_be(const std::vector<uint8_t>& packet, std::size_t offset);
bool validate_client_ipv4_packet(const std::vector<uint8_t>& packet,
                                 std::uint32_t expected_source_be,
                                 std::string* reason);

// ---- Templates (must stay header-visible) --------------------------------
template <typename Endpoint>
bool is_active_server_endpoint(const Endpoint& endpoint,
                               const ServerConfig& cfg,
                               const std::optional<boost::asio::ip::address>& local_addr) {
    return local_addr.has_value() &&
           endpoint.port() == static_cast<unsigned short>(cfg.listen_port) &&
           addresses_match(endpoint.address(), *local_addr);
}

template <typename Endpoint>
void prefer_ipv4_endpoints(std::vector<Endpoint>* endpoints) {
    if (!endpoints) {
        return;
    }
    std::stable_sort(endpoints->begin(), endpoints->end(),
                     [](const Endpoint& lhs, const Endpoint& rhs) {
                         return lhs.address().is_v4() && !rhs.address().is_v4();
                     });
}

// ---- Direct (no-libc-resolver) DNS A query -------------------------------
// Self-contained async helper used by the upstream-connect path. Kept fully
// in the header because more than one session_*.cpp may instantiate it once
// handle_open and friends are split out; it only depends on the free helpers
// declared above plus util::now_ms().
class DirectDnsAQuery : public std::enable_shared_from_this<DirectDnsAQuery> {
public:
    using Handler = std::function<void(bool,
                                       const std::vector<boost::asio::ip::address_v4>&,
                                       const std::string&,
                                       int64_t)>;

    DirectDnsAQuery(boost::asio::any_io_executor exec,
                    std::string dns_server,
                    std::string host,
                    Handler handler)
        : socket_(exec)
        , timer_(exec)
        , dns_server_(std::move(dns_server))
        , host_(std::move(host))
        , handler_(std::move(handler))
        , started_ms_(util::now_ms()) {}

    void start() {
        boost::system::error_code address_ec;
        const auto dns_address = boost::asio::ip::make_address(dns_server_, address_ec);
        if (address_ec || !dns_address.is_v4()) {
            finish(false, {}, "direct DNS server must be an IPv4 address", 0);
            return;
        }
        dns_endpoint_ = boost::asio::ip::udp::endpoint(dns_address.to_v4(), 53);

        boost::system::error_code literal_ec;
        const auto literal_addr = boost::asio::ip::make_address(host_, literal_ec);
        if (!literal_ec) {
            if (literal_addr.is_v4()) {
                finish(true, {literal_addr.to_v4()}, "", 0);
            } else {
                finish(false, {}, "direct DNS resolver is IPv4-only; enable YUME_RESOLVE_FAMILY=any for IPv6 literals", 0);
            }
            return;
        }

        query_id_ = static_cast<std::uint16_t>(random_int_inclusive(1, 65535));
        query_.reserve(512);
        append_u16(&query_, query_id_);
        append_u16(&query_, 0x0100);
        append_u16(&query_, 1);
        append_u16(&query_, 0);
        append_u16(&query_, 0);
        append_u16(&query_, 0);
        if (!append_dns_name(&query_, host_)) {
            finish(false, {}, "invalid DNS host name", 0);
            return;
        }
        append_u16(&query_, 1);
        append_u16(&query_, 1);

        boost::system::error_code open_ec;
        socket_.open(boost::asio::ip::udp::v4(), open_ec);
        if (open_ec) {
            finish(false, {}, "direct DNS socket open failed: " + open_ec.message(), 0);
            return;
        }

        timer_.expires_from_now(boost::posix_time::milliseconds(kDirectDnsTimeoutMs));
        auto self = shared_from_this();
        timer_.async_wait([self](const boost::system::error_code& ec) {
            if (ec) {
                return;
            }
            boost::system::error_code close_ec;
            self->socket_.close(close_ec);
            self->finish(false, {}, "direct DNS timeout", 0);
        });

        socket_.async_send_to(boost::asio::buffer(query_), dns_endpoint_,
                              [self](const boost::system::error_code& ec, std::size_t) {
                                  if (ec) {
                                      self->finish(false, {}, "direct DNS send failed: " + ec.message(), 0);
                                      return;
                                  }
                                  self->receive();
                              });
    }

private:
    void receive() {
        auto self = shared_from_this();
        socket_.async_receive_from(boost::asio::buffer(response_), sender_,
                                   [self](const boost::system::error_code& ec, std::size_t bytes) {
                                       if (ec) {
                                           self->finish(false, {}, "direct DNS receive failed: " + ec.message(), 0);
                                           return;
                                       }
                                       std::vector<boost::asio::ip::address_v4> addresses;
                                       std::string parse_error;
                                       if (!parse_dns_a_response(self->response_.data(), bytes,
                                                                 self->query_id_, &addresses, &parse_error)) {
                                           self->finish(false, {}, parse_error, 0);
                                           return;
                                       }
                                       self->finish(true, addresses, "", 0);
                                   });
    }

    void finish(bool ok,
                std::vector<boost::asio::ip::address_v4> addresses,
                std::string reason,
                int64_t elapsed_override) {
        if (finished_) {
            return;
        }
        finished_ = true;
        boost::system::error_code ignored;
        timer_.cancel(ignored);
        socket_.close(ignored);
        const int64_t elapsed = elapsed_override > 0 ? elapsed_override : (util::now_ms() - started_ms_);
        handler_(ok, addresses, reason, elapsed);
    }

    boost::asio::ip::udp::socket socket_;
    boost::asio::deadline_timer timer_;
    boost::asio::ip::udp::endpoint dns_endpoint_;
    boost::asio::ip::udp::endpoint sender_;
    std::string dns_server_;
    std::string host_;
    Handler handler_;
    int64_t started_ms_{0};
    std::uint16_t query_id_{0};
    bool finished_{false};
    std::vector<uint8_t> query_;
    std::array<uint8_t, 1500> response_{};
};

}  // namespace detail
}  // namespace yume::server
