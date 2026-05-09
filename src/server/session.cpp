/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "server/session.hpp"
#include "server/manager.hpp"

#include <openssl/pem.h>

#include <chrono>
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <ctime>
#include <iostream>
#include <random>
#include <string>
#include <string_view>

#include "core/inner_crypto.hpp"
#include "core/obfs_h2.hpp"
#include "core/obfs_signal.hpp"
#include "core/protocol.hpp"
#include "core/runtime_policy.hpp"
#include "core/version.hpp"
#include "server/auth.hpp"
#include "util.hpp"
#include <nlohmann/json.hpp>
#if YUME_USE_BASEFWX
#include <basefwx/base64.hpp>
#include <basefwx/crypto.hpp>
#include <basefwx/constants.hpp>
#endif

namespace yume::server {

namespace {
constexpr uint32_t kMaxFrameSize = 16 * 1024 * 1024;
constexpr uint8_t kMinFrameType = protocol::AUTH;
constexpr uint8_t kMaxFrameType = protocol::SOPEN;
constexpr int64_t kIdleTimeoutMs = 90 * 1000;
constexpr int64_t kIdleCheckIntervalMs = 30 * 1000;
constexpr std::uint64_t kHopDecryptWindow = 24;
constexpr int64_t kResolverTimeoutMs = 8000;
constexpr int64_t kConnectTimeoutMs = 15000;
constexpr int64_t kReverseAcceptTimeoutMs = 30000;
constexpr uint32_t kMaxWriteQueueSize = 256;
constexpr uint32_t kWriteQueueHighWatermark = 16;
constexpr uint32_t kWriteQueueLowWatermark = 4;
constexpr uint32_t kMaxWriteBatchFrames = 16;
constexpr std::size_t kMaxWriteBatchBytes = 64 * 1024;

int64_t steady_now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

int64_t epoch_now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

bool is_private_ipv4(const boost::asio::ip::address_v4& addr) {
    const auto bytes = addr.to_bytes();
    const uint8_t a = bytes[0];
    const uint8_t b = bytes[1];
    if (a == 10) return true;
    if (a == 127) return true;
    if (a == 0) return true;
    if (a == 169 && b == 254) return true;
    if (a == 172 && (b >= 16 && b <= 31)) return true;
    if (a == 192 && b == 168) return true;
    if (a == 100 && (b >= 64 && b <= 127)) return true;
    if (a == 192 && b == 0) return true;
    if (a == 198 && (b == 18 || b == 19)) return true;
    if (a == 198 && b == 51) return true;
    if (a == 203 && b == 0) return true;
    if (a >= 224) return true;
    return false;
}

bool is_private_ipv6(const boost::asio::ip::address_v6& addr) {
    if (addr.is_loopback() || addr.is_unspecified() || addr.is_multicast()) {
        return true;
    }
    const auto bytes = addr.to_bytes();
    if ((bytes[0] & 0xFE) == 0xFC) {
        return true;
    }
    if (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80) {
        return true;
    }
    if (addr.is_v4_mapped()) {
        boost::asio::ip::address_v4::bytes_type v4bytes{
            {bytes[12], bytes[13], bytes[14], bytes[15]}
        };
        return is_private_ipv4(boost::asio::ip::address_v4(v4bytes));
    }
    return false;
}

bool is_public_address(const boost::asio::ip::address& addr) {
    if (addr.is_v4()) {
        return !is_private_ipv4(addr.to_v4());
    }
    if (addr.is_v6()) {
        return !is_private_ipv6(addr.to_v6());
    }
    return false;
}

bool is_allowed_address(const boost::asio::ip::address& addr, bool allow_local_ip, bool control_full) {
    if (control_full) {
        return true;
    }
    if (is_public_address(addr)) {
        return true;
    }
    return allow_local_ip;
}

bool is_blocked_host_literal(const std::string& host, bool allow_local_ip, bool control_full) {
    if (control_full) {
        return false;
    }
    if ((host == "localhost" || host == "localhost.localdomain") && !allow_local_ip) {
        return true;
    }
    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address(host, ec);
    if (!ec) {
        return !is_allowed_address(addr, allow_local_ip, control_full);
    }
    return false;
}

boost::asio::ip::address canonical_endpoint_address(const boost::asio::ip::address& addr) {
    if (addr.is_v6()) {
        const auto v6 = addr.to_v6();
        if (v6.is_v4_mapped()) {
            const auto bytes = v6.to_bytes();
            boost::asio::ip::address_v4::bytes_type v4bytes{
                {bytes[12], bytes[13], bytes[14], bytes[15]}
            };
            return boost::asio::ip::address_v4(v4bytes);
        }
    }
    return addr;
}

bool addresses_match(const boost::asio::ip::address& lhs, const boost::asio::ip::address& rhs) {
    return canonical_endpoint_address(lhs) == canonical_endpoint_address(rhs);
}

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

std::optional<boost::asio::ip::address> session_local_address(
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream) {
    boost::system::error_code ec;
    auto local = stream.lowest_layer().local_endpoint(ec);
    if (ec) {
        return std::nullopt;
    }
    return local.address();
}

bool starts_with(std::string_view value, std::string_view prefix) {
    return value.substr(0, prefix.size()) == prefix;
}

bool is_background_probe_close_reason(const std::string& reason) {
    if (reason == "served HTTP disguise response") {
        return true;
    }
    if (reason == "ignored post-TLS HTTP probe") {
        return true;
    }
    if (starts_with(reason, "TLS handshake failed: ")) {
        return true;
    }
    if (starts_with(reason, "preface read failed: ")) {
        return true;
    }
    if (starts_with(reason, "HTTP preface read failed: ")) {
        return true;
    }
    return false;
}

bool is_server_fault_close_reason(const std::string& reason) {
    return starts_with(reason, "AUTH challenge write failed: ") ||
           starts_with(reason, "auth rejection ANON write failed: ") ||
           starts_with(reason, "ANON write failed: ") ||
           starts_with(reason, "write queue overrun");
}

std::string summarize_header_prefix(const std::array<uint8_t, 8>& header) {
    static constexpr char kHexDigits[] = "0123456789abcdef";
    std::string hex;
    hex.reserve((header.size() * 2) + (header.size() - 1));
    for (std::size_t index = 0; index < header.size(); ++index) {
        if (index > 0) {
            hex.push_back(' ');
        }
        const auto byte = header[index];
        hex.push_back(kHexDigits[(byte >> 4) & 0x0F]);
        hex.push_back(kHexDigits[byte & 0x0F]);
    }

    std::string ascii;
    ascii.reserve(header.size());
    for (const auto byte : header) {
        ascii.push_back((byte >= 32 && byte <= 126) ? static_cast<char>(byte) : '.');
    }
    return "header=" + hex + " ascii=" + ascii;
}

bool header_starts_with_ascii(const std::array<uint8_t, 8>& header, std::string_view prefix) {
    if (prefix.size() > header.size()) {
        return false;
    }
    for (std::size_t index = 0; index < prefix.size(); ++index) {
        if (header[index] != static_cast<std::uint8_t>(prefix[index])) {
            return false;
        }
    }
    return true;
}

bool is_http_probe_header(const std::array<uint8_t, 8>& header) {
    return header_starts_with_ascii(header, "GET ") ||
           header_starts_with_ascii(header, "POST ") ||
           header_starts_with_ascii(header, "HEAD ") ||
           header_starts_with_ascii(header, "PUT ") ||
           header_starts_with_ascii(header, "DELETE ") ||
           header_starts_with_ascii(header, "OPTIONS ") ||
           header_starts_with_ascii(header, "CONNECT ") ||
           header_starts_with_ascii(header, "TRACE ") ||
           header_starts_with_ascii(header, "PATCH ") ||
           header_starts_with_ascii(header, "PRI * HT");
}

int random_int_inclusive(int min_value, int max_value) {
    if (min_value >= max_value) {
        return min_value;
    }
    static thread_local std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(min_value, max_value);
    return dist(rng);
}

bool is_expected_close_ec(const boost::system::error_code& ec) {
    return ec == boost::asio::error::eof ||
           ec == boost::asio::error::operation_aborted ||
           ec == boost::asio::ssl::error::stream_truncated;
}

bool is_expected_close_reason(const std::string& reason) {
    return reason == "authentication rejected" ||
           reason == "peer closed the TLS session" ||
           starts_with(reason, "client disconnected before AUTH") ||
           reason == "served HTTP disguise response" ||
           reason == "server closed, kicked" ||
           reason == "session closed";
}

std::string describe_error_code(const boost::system::error_code& ec) {
    std::string description = ec.message();
    const std::string category = ec.category().name();
    if (!category.empty()) {
        description += " [category=" + category + " value=" + std::to_string(ec.value()) + "]";
    }
    return description;
}

bool env_value_enabled(const char* raw) {
    if (!raw || !*raw) {
        return false;
    }
    std::string value(raw);
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value == "1" || value == "true" || value == "yes" || value == "on" ||
           value == "any" || value == "all" || value == "ipv6";
}

bool server_resolve_any_family_enabled() {
    return env_value_enabled(std::getenv("YUME_RESOLVE_ANY")) ||
           env_value_enabled(std::getenv("YUME_RESOLVE_IPV6")) ||
           env_value_enabled(std::getenv("YUME_RESOLVE_FAMILY"));
}

constexpr int64_t kDirectDnsTimeoutMs = 1500;

void append_u16(std::vector<uint8_t>* out, std::uint16_t value) {
    out->push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    out->push_back(static_cast<uint8_t>(value & 0xff));
}

std::uint16_t read_u16(const uint8_t* data, std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(data[offset]) << 8) |
                                      static_cast<std::uint16_t>(data[offset + 1]));
}

bool append_dns_name(std::vector<uint8_t>* out, std::string host) {
    if (!out || host.empty()) {
        return false;
    }
    if (!host.empty() && host.back() == '.') {
        host.pop_back();
    }
    if (host.empty() || host.size() > 253) {
        return false;
    }
    std::size_t start = 0;
    while (start < host.size()) {
        const std::size_t dot = host.find('.', start);
        const std::size_t end = dot == std::string::npos ? host.size() : dot;
        const std::size_t label_len = end - start;
        if (label_len == 0 || label_len > 63) {
            return false;
        }
        out->push_back(static_cast<uint8_t>(label_len));
        out->insert(out->end(), host.begin() + static_cast<std::ptrdiff_t>(start),
                    host.begin() + static_cast<std::ptrdiff_t>(end));
        if (dot == std::string::npos) {
            break;
        }
        start = dot + 1;
    }
    out->push_back(0);
    return true;
}

bool skip_dns_name(const uint8_t* data, std::size_t len, std::size_t* offset) {
    if (!data || !offset) {
        return false;
    }
    std::size_t pos = *offset;
    for (int depth = 0; depth < 128; ++depth) {
        if (pos >= len) {
            return false;
        }
        const uint8_t label_len = data[pos++];
        if ((label_len & 0xc0) == 0xc0) {
            if (pos >= len) {
                return false;
            }
            ++pos;
            *offset = pos;
            return true;
        }
        if ((label_len & 0xc0) != 0) {
            return false;
        }
        if (label_len == 0) {
            *offset = pos;
            return true;
        }
        if (pos + label_len > len) {
            return false;
        }
        pos += label_len;
    }
    return false;
}

bool parse_dns_a_response(const uint8_t* data,
                          std::size_t len,
                          std::uint16_t expected_id,
                          std::vector<boost::asio::ip::address_v4>* out,
                          std::string* error) {
    if (!data || len < 12 || !out) {
        if (error) {
            *error = "short DNS response";
        }
        return false;
    }
    if (read_u16(data, 0) != expected_id) {
        if (error) {
            *error = "DNS response id mismatch";
        }
        return false;
    }
    const std::uint16_t flags = read_u16(data, 2);
    if ((flags & 0x8000) == 0) {
        if (error) {
            *error = "not a DNS response";
        }
        return false;
    }
    const std::uint16_t rcode = static_cast<std::uint16_t>(flags & 0x000f);
    if (rcode != 0) {
        if (error) {
            *error = "DNS rcode " + std::to_string(rcode);
        }
        return false;
    }
    const std::uint16_t qdcount = read_u16(data, 4);
    const std::uint16_t ancount = read_u16(data, 6);
    std::size_t offset = 12;
    for (std::uint16_t i = 0; i < qdcount; ++i) {
        if (!skip_dns_name(data, len, &offset) || offset + 4 > len) {
            if (error) {
                *error = "bad DNS question";
            }
            return false;
        }
        offset += 4;
    }
    for (std::uint16_t i = 0; i < ancount; ++i) {
        if (!skip_dns_name(data, len, &offset) || offset + 10 > len) {
            if (error) {
                *error = "bad DNS answer";
            }
            return false;
        }
        const std::uint16_t type = read_u16(data, offset);
        const std::uint16_t klass = read_u16(data, offset + 2);
        const std::uint16_t rdlen = read_u16(data, offset + 8);
        offset += 10;
        if (offset + rdlen > len) {
            if (error) {
                *error = "bad DNS rdata";
            }
            return false;
        }
        if (type == 1 && klass == 1 && rdlen == 4) {
            boost::asio::ip::address_v4::bytes_type bytes{
                {data[offset], data[offset + 1], data[offset + 2], data[offset + 3]}
            };
            out->push_back(boost::asio::ip::address_v4(bytes));
        }
        offset += rdlen;
    }
    if (out->empty()) {
        if (error) {
            *error = "DNS response contained no A records";
        }
        return false;
    }
    return true;
}

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

}

Session::Session(boost::asio::ip::tcp::socket socket,
                 boost::asio::ssl::context& ssl_ctx,
                 const ServerConfig& cfg,
                 std::shared_ptr<const std::vector<crypto::Bytes>> authorized_keys,
                 uint64_t session_id,
                 Manager* manager)
    : stream_(std::move(socket), ssl_ctx)
    , cfg_(cfg)
    , authorized_keys_(std::move(authorized_keys))
    , session_id_(session_id)
    , manager_(manager)
    , strand_(stream_.get_executor())
    , preface_timer_(stream_.get_executor())
    , idle_timer_(stream_.get_executor()) {
    last_activity_ms_.store(steady_now_ms(), std::memory_order_relaxed);
    session_allow_exec_policy_ = false;
    session_allow_local_ip_ = false;
    session_control_full_ = false;
}

void Session::start() {
    touch_activity();
    schedule_idle_check();
    auto self = shared_from_this();
    boost::system::error_code keep_ec;
    stream_.lowest_layer().set_option(boost::asio::socket_base::keep_alive(true), keep_ec);
    stream_.async_handshake(boost::asio::ssl::stream_base::server,
                            boost::asio::bind_executor(strand_,
                                                       [self](const boost::system::error_code& ec) {
                                                           self->on_handshake(ec);
                                                       }));
}

void Session::stop() {
    boost::asio::post(strand_, [self = shared_from_this()]() { self->close(); });
}

void Session::notify_server_shutdown(const std::string& reason) {
    boost::asio::post(strand_, [self = shared_from_this(), reason]() {
        if (self->close_state_ != CloseState::Open) {
            return;
        }
        if (self->authenticated_) {
            nlohmann::json notice{
                {"cmd", "server.closing"},
                {"reason", reason},
                {"message", reason},
            };
            std::string payload_text = notice.dump();
            crypto::Bytes payload(payload_text.begin(), payload_text.end());
            uint16_t flags = 0;
            if (self->inner_key_.has_value()) {
                payload = self->encrypt_inner_payload(protocol::CONTROL, 0, payload);
                flags |= protocol::kFlagInnerEncrypted;
            }
            auto data = std::make_shared<std::vector<uint8_t>>(protocol::encode_frame(
                protocol::CONTROL,
                0,
                flags,
                payload));
            self->queue_encoded_write_on_strand(data);
        }
        self->close_with_reason(reason);
    });
}

void Session::on_handshake(const boost::system::error_code& ec) {
    if (ec) {
        close_with_reason("TLS handshake failed: " + ec.message());
        return;
    }
    boost::system::error_code ep_ec;
    auto ep = stream_.lowest_layer().remote_endpoint(ep_ec);
    if (!ep_ec && !cfg_.anonym) {
        client_wan_ip_ = ep.address().to_string();
    }
    boost::system::error_code nodelay_ec;
    stream_.lowest_layer().set_option(boost::asio::ip::tcp::no_delay(true), nodelay_ec);

    if (cfg_.real_http || cfg_.obfuscation) {
        start_preface_read();
        return;
    }

    send_auth_challenge();
}

void Session::start_preface_read() {
    preface_accum_.clear();
    preface_received_ = false;
    preface_probe_active_ = true;
    preface_timer_.expires_after(std::chrono::milliseconds(200));
    auto self = shared_from_this();
    preface_timer_.async_wait(boost::asio::bind_executor(strand_,
                                                         [self](const boost::system::error_code& ec) {
                                                             self->on_preface_timeout(ec);
                                                         }));
    stream_.async_read_some(boost::asio::buffer(preface_buf_),
                            boost::asio::bind_executor(strand_,
                                                       [self](const boost::system::error_code& ec, std::size_t bytes) {
                                                           self->on_preface_read(ec, bytes);
                                                       }));
}

void Session::on_preface_read(const boost::system::error_code& ec, std::size_t bytes) {
    if (ec) {
        if (ec != boost::asio::error::operation_aborted) {
            close_with_reason("preface read failed: " + ec.message());
        }
        return;
    }
    if (!preface_probe_active_) {
        return;
    }
    if (bytes == 0) {
        return;
    }

    preface_timer_.cancel();
    preface_received_ = true;
    preface_accum_.insert(preface_accum_.end(), preface_buf_.begin(), preface_buf_.begin() + static_cast<std::ptrdiff_t>(bytes));

    std::string preface(reinterpret_cast<const char*>(preface_accum_.data()), preface_accum_.size());
    if (handle_http_preface(preface)) {
        preface_probe_active_ = false;
        return;
    }

    if (preface_accum_.size() < preface_buf_.size()) {
        auto self = shared_from_this();
        stream_.async_read_some(boost::asio::buffer(preface_buf_),
                                boost::asio::bind_executor(strand_,
                                                           [self](const boost::system::error_code& e, std::size_t n) {
                                                               self->on_preface_read(e, n);
                                                           }));
        return;
    }

    if (preface_accum_.size() < header_buf_.size()) {
        auto self = shared_from_this();
        stream_.async_read_some(boost::asio::buffer(preface_buf_),
                                boost::asio::bind_executor(strand_,
                                                           [self](const boost::system::error_code& e, std::size_t n) {
                                                               self->on_preface_read(e, n);
                                                           }));
        return;
    }

    uint32_t len = (static_cast<uint32_t>(preface_accum_[0]) << 24) |
                   (static_cast<uint32_t>(preface_accum_[1]) << 16) |
                   (static_cast<uint32_t>(preface_accum_[2]) << 8) |
                   (static_cast<uint32_t>(preface_accum_[3]));
    uint8_t type = preface_accum_[4];
    bool header_ok = len <= kMaxFrameSize && type >= kMinFrameType && type <= kMaxFrameType;
    if (!header_ok && cfg_.real_http) {
        send_real_http_response("/");
        return;
    }
    if (preface_accum_.size() > header_buf_.size()) {
        preface_probe_active_ = false;
        util::log_warn("session " + std::to_string(session_id_) + ": unexpected preface data");
        close_with_reason("unexpected preface data");
        return;
    }

    std::copy(preface_accum_.begin(), preface_accum_.begin() + header_buf_.size(), header_buf_.begin());
    preface_probe_active_ = false;
    header_prefetched_ = true;
    read_header();
}

void Session::on_preface_timeout(const boost::system::error_code& ec) {
    if (ec == boost::asio::error::operation_aborted) {
        return;
    }
    if (!preface_received_ && preface_probe_active_) {
        preface_probe_active_ = false;
        boost::system::error_code cancel_ec;
        stream_.lowest_layer().cancel(cancel_ec);
        send_auth_challenge();
    }
}
bool Session::handle_http_preface(const std::string& preface) {
    if (cfg_.obfuscation && preface.rfind("PRI * HT", 0) == 0) {
        start_h2_carrier_probe();
        return true;
    }

    const std::string methods[] = {"GET ", "HEAD ", "POST ", "OPTIONS ", "PUT ", "DELETE ", "TRACE ", "PATCH ", "CONNECT "};
    bool is_http = false;
    for (const auto& m : methods) {
        if (preface.rfind(m, 0) == 0) {
            is_http = true;
            break;
        }
    }
    if (!is_http && preface.rfind("PRI * HT", 0) == 0) {
        is_http = true;
    }
    if (!is_http) {
        return false;
    }

    auto self = shared_from_this();
    auto request = std::make_shared<std::string>(preface);
    boost::asio::async_read_until(stream_, boost::asio::dynamic_buffer(*request), "\r\n\r\n",
                                  boost::asio::bind_executor(strand_,
                                                             [self, request](const boost::system::error_code& e, std::size_t) {
                                                                 if (e) {
                                                                     self->close_with_reason("HTTP preface read failed: " + e.message());
                                                                     return;
                                                                 }
                                                                 std::string line;
                                                                 auto pos = request->find("\r\n");
                                                                 if (pos != std::string::npos) {
                                                                     line = request->substr(0, pos);
                                                                 }
                                                                 std::string target = "/";
                                                                 if (!line.empty()) {
                                                                     auto p1 = line.find(' ');
                                                                     if (p1 != std::string::npos) {
                                                                         auto p2 = line.find(' ', p1 + 1);
                                                                         if (p2 != std::string::npos && p2 > p1 + 1) {
                                                                             target = line.substr(p1 + 1, p2 - p1 - 1);
                                                                         }
                                                                     }
                                                                 }

                                                                 if (!self->cfg_.real_http) {
                                                                     self->close_with_reason("ignored post-TLS HTTP probe");
                                                                     return;
                                                                 }

                                                                 std::string path = "/";
                                                                 path = target;
                                                                 self->send_real_http_response(path);
                                                             }));
    return true;
}

std::string Session::load_real_index() {
    if (!cfg_.real_index_path.empty()) {
        std::ifstream in(cfg_.real_index_path, std::ios::binary);
        if (in) {
            std::string contents((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            return contents;
        }
    }
    return "<!doctype html><html><head><meta charset=\"utf-8\">"
           "<title>Redirecting...</title>"
           "<meta http-equiv=\"refresh\" content=\"0;url=https://ja.wikipedia.org/wiki/%E5%AE%87%E5%AE%99\">"
           "<script>window.location.replace(\"https://ja.wikipedia.org/wiki/%E5%AE%87%E5%AE%99\");</script>"
           "</head><body>"
           "<noscript><meta http-equiv=\"refresh\" content=\"0;url=https://ja.wikipedia.org/wiki/%E5%AE%87%E5%AE%99\"></noscript>"
           "<p>Redirecting to Wikipedia...</p>"
           "</body></html>";
}

std::string Session::build_hidden_blob() {
#if YUME_USE_BASEFWX
    if (cfg_.real_secret.empty()) {
        return "";
    }
    basefwx::crypto::Bytes salt = basefwx::crypto::RandomBytes(basefwx::constants::kUserKdfSaltSize);
    basefwx::crypto::Bytes key = basefwx::crypto::Pbkdf2HmacSha256(
        cfg_.real_secret,
        salt,
        basefwx::constants::kUserKdfIterations,
        32);
    nlohmann::json meta{
        {"ts", static_cast<long long>(std::time(nullptr))},
        {"sid", static_cast<long long>(session_id_)},
        {"note", "yume-real"}
    };
    std::string meta_str = meta.dump();
    basefwx::crypto::Bytes payload(meta_str.begin(), meta_str.end());
    basefwx::crypto::Bytes aad{'y', 'u', 'm', 'e', '-', 'r', 'e', 'a', 'l'};
    basefwx::crypto::Bytes blob = basefwx::crypto::AeadEncrypt(key, payload, aad);

    basefwx::crypto::Bytes combined;
    combined.reserve(salt.size() + blob.size());
    combined.insert(combined.end(), salt.begin(), salt.end());
    combined.insert(combined.end(), blob.begin(), blob.end());
    std::string b64 = basefwx::base64::Encode(combined);
    return b64;
#else
    return "";
#endif
}

void Session::send_real_http_response(const std::string& path) {
    std::string body;
    std::string status_line = "HTTP/1.1 200 OK\r\n";
    if (path != "/") {
        status_line = "HTTP/1.1 302 Found\r\n";
        body = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Redirect</title></head>"
               "<body>Redirecting to /</body></html>";
    } else {
        body = load_real_index();
    }

    std::string hidden = build_hidden_blob();
    if (!hidden.empty()) {
        body += "<span style=\"display:none\" aria-hidden=\"true\">" + hidden + "</span>";
        body += "<!--" + hidden + "-->";
    }

    std::string headers;
    headers += status_line;
    if (path != "/") {
        headers += "Location: /\r\n";
    }
    headers += "Server: nginx\r\n";
    headers += "Content-Type: text/html; charset=utf-8\r\n";
    headers += "Cache-Control: no-store\r\n";
    if (!hidden.empty()) {
        headers += "X-Yume-Blob: " + hidden + "\r\n";
    }
    headers += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    headers += "Connection: close\r\n\r\n";

    auto resp = std::make_shared<std::string>(headers + body);
    auto self = shared_from_this();
    boost::asio::async_write(stream_, boost::asio::buffer(*resp),
                             boost::asio::bind_executor(strand_,
                                                        [self, resp](const boost::system::error_code&, std::size_t) {
                                                            self->close_with_reason("served HTTP disguise response");
                                                        }));
}

void Session::start_h2_carrier_probe() {
    carrier_probe_active_ = true;
    carrier_decoder_ = std::make_unique<obfs::H2InboundDecoder>(true);
    if (!preface_accum_.empty()) {
        carrier_decoder_->feed(preface_accum_.data(), preface_accum_.size());
        preface_accum_.clear();
    }
    auto replies = carrier_decoder_->take_outbound_replies();
    if (!replies.empty()) {
        auto data = std::make_shared<std::vector<uint8_t>>(std::move(replies));
        queue_encoded_write_on_strand(std::move(data));
    }
    auto self = shared_from_this();
    stream_.async_read_some(
        boost::asio::buffer(carrier_scratch_),
        boost::asio::bind_executor(strand_,
                                   [self](const boost::system::error_code& ec, std::size_t bytes) {
                                       self->on_h2_probe_read(ec, bytes);
                                   }));
}

void Session::on_h2_probe_read(const boost::system::error_code& ec, std::size_t bytes) {
    if (ec) {
        close_with_reason("h2 carrier probe read failed: " + ec.message());
        return;
    }
    if (!carrier_probe_active_ || !carrier_decoder_) {
        return;
    }
    if (bytes > 0) {
        carrier_decoder_->feed(carrier_scratch_.data(), bytes);
    }
    if (carrier_decoder_->failed()) {
        close_with_reason("h2 carrier decode failed: " + carrier_decoder_->error());
        return;
    }
    auto replies = carrier_decoder_->take_outbound_replies();
    if (!replies.empty()) {
        auto data = std::make_shared<std::vector<uint8_t>>(std::move(replies));
        queue_encoded_write_on_strand(std::move(data));
    }

    if (carrier_decoder_->headers_seen()) {
        std::string path = carrier_decoder_->extracted_path();
        std::string authority = carrier_decoder_->extracted_authority();
        std::vector<crypto::Bytes> keys;
        if (!cfg_.obfs_secret.empty()) {
            keys.push_back(obfs::derive_signal_key(cfg_.obfs_secret));
        }
        std::int64_t now_s = static_cast<std::int64_t>(std::time(nullptr));
        bool token_ok = false;
        if (path.size() == obfs::kH2PathLen) {
            if (!keys.empty()) {
                token_ok = obfs::verify_path_token(keys, authority, path, now_s);
            } else {
                token_ok = (path[0] == '/' && path[1 + obfs::kH2TokenHexLen] == '/');
            }
        }

        std::vector<uint8_t> leftover;
        carrier_decoder_->drain_inbound_buffer(&leftover);
        carrier_probe_active_ = false;
        carrier_decoder_.reset();

        if (!token_ok) {
            std::string sanitized;
            sanitized.reserve(path.size());
            for (unsigned char c : path) {
                sanitized.push_back((c >= 0x20 && c < 0x7f) ? static_cast<char>(c) : '?');
            }
            util::log_warn("session " + std::to_string(session_id_) +
                          ": h2 carrier path token rejected (size=" +
                          std::to_string(path.size()) + ", path=" + sanitized + ")");
            serve_fake_h2_real_index();
            return;
        }

        send_h2_server_handshake_then_continue();
        if (!leftover.empty()) {
            preface_accum_.assign(leftover.begin(), leftover.end());
            if (preface_accum_.size() >= header_buf_.size()) {
                std::copy(preface_accum_.begin(),
                          preface_accum_.begin() + header_buf_.size(),
                          header_buf_.begin());
                preface_accum_.erase(preface_accum_.begin(),
                                     preface_accum_.begin() + header_buf_.size());
                header_prefetched_ = true;
            }
        }
        return;
    }

    if (carrier_decoder_->inbound_buffered() > 32768) {
        close_with_reason("h2 carrier handshake too large");
        return;
    }

    auto self = shared_from_this();
    stream_.async_read_some(
        boost::asio::buffer(carrier_scratch_),
        boost::asio::bind_executor(strand_,
                                   [self](const boost::system::error_code& e, std::size_t n) {
                                       self->on_h2_probe_read(e, n);
                                   }));
}

void Session::send_h2_server_handshake_then_continue() {
    crypto::Bytes hello = obfs::encode_server_handshake();
    auto data = std::make_shared<std::vector<uint8_t>>(hello.begin(), hello.end());
    queue_encoded_write_on_strand(std::move(data));
    util::log_info("session " + std::to_string(session_id_) + ": h2 carrier handshake established");
    send_auth_challenge();
}

void Session::serve_fake_h2_real_index() {
    std::string body = load_real_index();
    crypto::Bytes hello = obfs::encode_server_handshake();
    obfs::H2EncodeParams params;
    params.padding_mean = 0;
    params.padding_max = 0;
    crypto::Bytes data_frames = obfs::encode_data_frames(
        reinterpret_cast<const uint8_t*>(body.data()), body.size(), params);
    std::vector<uint8_t> combined;
    combined.reserve(hello.size() + data_frames.size());
    combined.insert(combined.end(), hello.begin(), hello.end());
    combined.insert(combined.end(), data_frames.begin(), data_frames.end());
    auto buf = std::make_shared<std::vector<uint8_t>>(std::move(combined));
    auto self = shared_from_this();
    boost::asio::async_write(stream_, boost::asio::buffer(*buf),
                             boost::asio::bind_executor(strand_,
                                                        [self, buf](const boost::system::error_code&, std::size_t) {
                                                            self->close_with_reason("served fake h2 page to non-yume probe");
                                                        }));
}

void Session::send_auth_challenge() {
    challenge_ = crypto::random_bytes(32);
    if (cfg_.inner_crypto) {
        inner::Argon2Limits limits = inner::argon2_env_limits();
        if (inner::has_argon2_limits(limits)) {
            nlohmann::json meta{
                {"challenge_meta", 1}
            };
            if (limits.time_max > 0) {
                meta["argon2_time_max"] = limits.time_max;
            }
            if (limits.memory_max > 0) {
                meta["argon2_mem_max"] = limits.memory_max;
            }
            if (limits.parallelism_max > 0) {
                meta["argon2_par_max"] = limits.parallelism_max;
            }
            std::string meta_text = meta.dump();
            challenge_.insert(challenge_.end(), meta_text.begin(), meta_text.end());
        }
    }
    protocol::Frame frame{{static_cast<uint32_t>(challenge_.size()), protocol::AUTH, 0, 0}, challenge_};
    auto self = shared_from_this();
    async_write_frame(frame, [self](const boost::system::error_code& ec, std::size_t) {
        if (ec) {
            self->close_with_reason("AUTH challenge write failed: " + ec.message());
            return;
        }
        self->read_header();
    });
}

void Session::read_header() {
    if (close_state_ != CloseState::Open) {
        return;
    }
    if (header_prefetched_) {
        header_prefetched_ = false;
        on_read_header({}, header_buf_.size());
        return;
    }
    auto self = shared_from_this();
    boost::asio::async_read(stream_, boost::asio::buffer(header_buf_),
                            boost::asio::bind_executor(strand_,
                                                       [self](const boost::system::error_code& ec,
                                                              std::size_t bytes) {
                                                           self->on_read_header(ec, bytes);
                                                       }));
}

void Session::on_read_header(const boost::system::error_code& ec, std::size_t) {
    if (ec) {
        if (close_state_ != CloseState::Open && is_expected_close_ec(ec)) {
            maybe_finish_close();
            return;
        }
        if (authenticated_ &&
            latest_lifecycle_state_ == "disconnecting" &&
            (ec == boost::asio::error::eof || ec == boost::asio::ssl::error::stream_truncated)) {
            close_with_reason("peer closed the TLS session");
            return;
        }
        if (ec == boost::asio::ssl::error::stream_truncated ||
            ec.category().name() == std::string("ssl")) {
            close_with_reason("SSL/TLS error: " + describe_error_code(ec) +
                            " [client must reconnect]");
            return;
        }
        if (authenticated_ &&
            (ec == boost::asio::error::eof || ec == boost::asio::ssl::error::stream_truncated)) {
            close_with_reason("peer closed the TLS session");
            return;
        }
        if (!authenticated_ &&
            (ec == boost::asio::error::eof ||
             ec == boost::asio::error::connection_reset ||
             ec == boost::asio::error::operation_aborted)) {
            close_with_reason("client disconnected before AUTH: " + describe_error_code(ec));
            return;
        }
        close_with_reason("read header failed: " + describe_error_code(ec));
        return;
    }

    uint32_t len = (static_cast<uint32_t>(header_buf_[0]) << 24) |
                   (static_cast<uint32_t>(header_buf_[1]) << 16) |
                   (static_cast<uint32_t>(header_buf_[2]) << 8) |
                   (static_cast<uint32_t>(header_buf_[3]));

    if (len > kMaxFrameSize) {
        if (!authenticated_ && is_http_probe_header(header_buf_)) {
            close_with_reason("ignored post-TLS HTTP probe");
            return;
        }
        const std::string detail =
            "session " + std::to_string(session_id_) + ": frame too large (" + summarize_header_prefix(header_buf_) + ")";
        if (util::is_logging_enabled()) {
            util::log_warn(detail);
        } else {
            std::cerr << "[warn] " << detail << std::endl;
        }
        close_with_reason("frame too large");
        return;
    }

    uint8_t type = header_buf_[4];
    if (type < kMinFrameType || type > kMaxFrameType) {
        if (!authenticated_ && is_http_probe_header(header_buf_)) {
            close_with_reason("ignored post-TLS HTTP probe");
            return;
        }
        const std::string detail =
            "session " + std::to_string(session_id_) + ": invalid frame type " +
            std::to_string(static_cast<int>(type)) + " (header=" + summarize_header_prefix(header_buf_) + ")";
        if (util::is_logging_enabled()) {
            util::log_warn(detail);
        } else {
            std::cerr << "[warn] " << detail << std::endl;
        }
        close_with_reason("invalid frame type");
        return;
    }

    current_header_.len = len;
    current_header_.type = type;
    current_header_.stream_id = header_buf_[5];
    current_header_.flags = static_cast<uint16_t>(header_buf_[6] << 8) |
                            static_cast<uint16_t>(header_buf_[7]);

    payload_buf_.assign(len, 0);
    if (len == 0) {
        protocol::Frame frame{current_header_, {}};
        handle_frame(frame);
        return;
    }

    auto self = shared_from_this();
    boost::asio::async_read(stream_, boost::asio::buffer(payload_buf_),
                            boost::asio::bind_executor(strand_,
                                                       [self](const boost::system::error_code& e,
                                                              std::size_t bytes) {
                                                           self->on_read_payload(e, bytes);
                                                       }));
}

void Session::on_read_payload(const boost::system::error_code& ec, std::size_t) {
    if (ec) {
        if (close_state_ != CloseState::Open && is_expected_close_ec(ec)) {
            maybe_finish_close();
            return;
        }
        std::string error_msg = "read payload failed: " + describe_error_code(ec);
        if (ec.category().name() == std::string("ssl") ||
            ec == boost::asio::ssl::error::stream_truncated) {
            error_msg = "SSL/TLS payload read error: " + error_msg +
                       " [SSL stream may be corrupted; client must reconnect]";
            util::log_error("session " + std::to_string(session_id_) + ": " + error_msg);
        }
        close_with_reason(error_msg);
        return;
    }

    protocol::Frame frame{current_header_, payload_buf_};
    handle_frame(frame);
}

void Session::handle_frame(const protocol::Frame& frame) {
    if (close_state_ != CloseState::Open) {
        return;
    }
    touch_activity();
    if (!authenticated_) {
        if (frame.header.type != protocol::AUTH) {
            util::log_warn("session " + std::to_string(session_id_) + ": expected AUTH");
            close_with_reason("expected AUTH frame before authentication");
            return;
        }

            if (!handle_auth(frame)) {
                util::log_warn("session " + std::to_string(session_id_) + ": auth failed");
                std::string reason = auth_error_.empty() ? "access denied: invalid key" : auth_error_;
                nlohmann::json anon_error = {
                    {"error", reason},
                    {"version", yume::kVersion}
                };
                if (!cfg_.anonym_certfp.empty()) {
                    anon_error["certfp"] = cfg_.anonym_certfp;
                }
                if (!cfg_.anonym_sub_cert_b64.empty()) {
                    anon_error["sub_cert"] = cfg_.anonym_sub_cert_b64;
                }
                if (!cfg_.pq_pub_b64.empty()) {
                    anon_error["pq_pub"] = cfg_.pq_pub_b64;
                }
                if (!cfg_.pq_sig.empty()) {
                    anon_error["pq_sig"] = cfg_.pq_sig;
                }
                if (!cfg_.pq_alg.empty()) {
                    anon_error["pq_alg"] = cfg_.pq_alg;
                }
                std::string payload_str = anon_error.dump();
                crypto::Bytes payload(payload_str.begin(), payload_str.end());
                protocol::Frame anon_frame{{static_cast<uint32_t>(payload.size()), protocol::ANON, 0, 0}, payload};
            async_write_frame(anon_frame, [self = shared_from_this()](const boost::system::error_code& ec, std::size_t) {
                self->close_with_reason(ec ? "auth rejection ANON write failed: " + ec.message()
                                           : "authentication rejected");
            });
            return;
        }

        authenticated_ = true;
        if (!cfg_.anonym) {
            util::log_info("session " + std::to_string(session_id_) + ": authenticated");
        }
        nlohmann::json anon = {
            {"version", yume::kVersion},
            {"mode", cfg_.anonym ? "anonym" : "normal"},
            {"hash", cfg_.anonym_hash},
            {"sig", cfg_.anonym_sig},
            {"ts", cfg_.anonym_ts},
            {"nonce", cfg_.anonym_nonce},
            {"certfp", cfg_.anonym_certfp},
            {"algo", "ed25519"},
            {"proof_policy", cfg_.anonym_proof_mode},
            {"proof_sources", cfg_.anonym_proof_sources},
            {"ca_sig", cfg_.anonym_ca_sig},
            {"ca_alg", cfg_.anonym_ca_alg},
            {"sub_sig", cfg_.anonym_sub_sig},
            {"sub_alg", cfg_.anonym_sub_alg},
            {"sub_cert", cfg_.anonym_sub_cert_b64},
            {"pq_pub", cfg_.pq_pub_b64},
            {"pq_sig", cfg_.pq_sig},
            {"pq_alg", cfg_.pq_alg}
        };
        std::string inner_mode = "off";
        if (inner_key_.has_value()) {
            inner_mode = inner_mode_.empty() ? (cfg_.inner_heavy ? "heavy" : "light") : inner_mode_;
        } else if (cfg_.inner_crypto) {
            inner_mode = cfg_.inner_heavy ? "heavy" : "light";
        }
        anon["inner_supported"] = cfg_.inner_crypto;
        anon["inner_required"] = cfg_.inner_required;
        anon["inner_dual"] = cfg_.inner_dual;
        anon["inner_active"] = inner_key_.has_value();
        anon["inner_mode"] = inner_mode;
        if (!inner_kdf_.empty()) {
            anon["inner_kdf"] = inner_kdf_;
        }
        anon["hop_enabled"] = hop_enabled_;
        anon["hop_interval_ms"] = cfg_.hop_interval_ms;
        anon["server_time_ms"] = epoch_now_ms();
        anon["cap_pq"] = inner::pq_supported();
        anon["cap_argon2"] = inner::argon2_supported();
        anon["cap_pbkdf2"] = inner::pbkdf2_supported();
        std::string payload_str = anon.dump();
        crypto::Bytes payload(payload_str.begin(), payload_str.end());
        protocol::Frame anon_frame{{static_cast<uint32_t>(payload.size()), protocol::ANON, 0, 0}, payload};
        async_write_frame(anon_frame, [self = shared_from_this()](const boost::system::error_code& ec, std::size_t) {
            if (ec) {
                self->close_with_reason("ANON write failed: " + ec.message());
                return;
            }
            self->read_header();
        });
        return;
    }

    if (inner_key_.has_value() &&
        (frame.header.type == protocol::OPEN || frame.header.type == protocol::DATA ||
         frame.header.type == protocol::EXEC || frame.header.type == protocol::CLOSE ||
         frame.header.type == protocol::RLISTEN || frame.header.type == protocol::CONTROL)) {
        if ((frame.header.flags & protocol::kFlagInnerEncrypted) == 0) {
            util::log_warn("session " + std::to_string(session_id_) + ": missing inner encryption flag");
            close_with_reason("missing inner encryption flag on authenticated frame type " +
                              std::to_string(frame.header.type));
            return;
        }
    }

    switch (frame.header.type) {
        case protocol::OPEN:
            if (!handle_control_open_request(frame) && !handle_control_open_ack(frame)) {
                handle_open(frame);
            }
            break;
        case protocol::DATA:
            if (!handle_control_data(frame)) {
                handle_data(frame);
            }
            break;
        case protocol::EXEC: {
            if (!handle_control_exec(frame)) {
                handle_exec(frame);
            }
            break;
        }
        case protocol::RLISTEN: {
            handle_rlisten(frame);
            break;
        }
        case protocol::CONTROL: {
            handle_control(frame);
            break;
        }
        case protocol::PING: {
            protocol::Frame pong{{0, protocol::PONG, 0, 0}, {}};
            async_write_frame(pong);
            break;
        }
        case protocol::PONG:
            break;
        case protocol::CLOSE:
            if (!handle_control_close(frame)) {
                handle_close(frame.header.stream_id, "client closed");
            }
            break;
        default:
            util::log_warn("session " + std::to_string(session_id_) + ": unknown frame");
            break;
    }

    if (close_state_ == CloseState::Open) {
        read_header();
    }
}

bool Session::decrypt_inner_payload(uint8_t frame_type,
                                    uint8_t stream_id,
                                    const crypto::Bytes& input,
                                    crypto::Bytes* output) {
    if (!output) {
        return false;
    }
    if (!inner_key_.has_value()) {
        *output = input;
        return true;
    }
    auto try_decrypt = [&](const crypto::Bytes& key) -> bool {
        try {
            if (!hop_enabled_ || hop_interval_ms_ == 0) {
                *output = inner::decrypt_payload(key, frame_type, stream_id, input);
                return true;
            }
            std::uint64_t hop_id = current_hop_id();
            std::uint64_t candidates[1 + (kHopDecryptWindow * 2)];
            std::size_t candidate_count = 0;
            candidates[candidate_count++] = hop_id;
            for (std::uint64_t delta = 1; delta <= kHopDecryptWindow; ++delta) {
                if (hop_id >= delta) {
                    candidates[candidate_count++] = hop_id - delta;
                }
                candidates[candidate_count++] = hop_id + delta;
            }
            for (std::size_t i = 0; i < candidate_count; ++i) {
                std::uint64_t id = candidates[i];
                crypto::Bytes hop_key = inner::derive_hop_key(key, id);
                try {
                    *output = inner::decrypt_payload(hop_key, frame_type, stream_id, input);
                    return true;
                } catch (...) {
                }
            }
            return false;
        } catch (...) {
            return false;
        }
    };

    if (try_decrypt(*inner_key_)) {
        return true;
    }
    if (!inner_key_alt_.has_value()) {
        return false;
    }
    if (try_decrypt(*inner_key_alt_)) {
        inner_key_ = inner_key_alt_;
        inner_key_alt_.reset();
        if (!inner_alt_mode_.empty()) {
            inner_mode_ = inner_alt_mode_;
        }
        inner_alt_mode_.clear();
        if (!inner_alt_kdf_.empty()) {
            inner_kdf_ = inner_alt_kdf_;
        }
        inner_alt_kdf_.clear();
        return true;
    }
    return false;
}

crypto::Bytes Session::encrypt_inner_payload(uint8_t frame_type,
                                             uint8_t stream_id,
                                             const crypto::Bytes& input) {
    if (!inner_key_.has_value()) {
        return input;
    }
    if (!hop_enabled_ || hop_interval_ms_ == 0) {
        return inner::encrypt_payload(*inner_key_, frame_type, stream_id, input);
    }
    std::uint64_t hop_id = current_hop_id();
    crypto::Bytes hop_key = inner::derive_hop_key(*inner_key_, hop_id);
    return inner::encrypt_payload(hop_key, frame_type, stream_id, input);
}

std::uint64_t Session::current_hop_id() const {
    if (!hop_enabled_ || hop_interval_ms_ == 0) {
        return 0;
    }
    return inner::hop_id_from_time_ms(epoch_now_ms(), hop_interval_ms_, hop_offset_ms_);
}

bool Session::handle_auth(const protocol::Frame& frame) {
    auth_error_.clear();
    try {
        size_t offset = 0;
        crypto::Bytes pub_pem = read_field(frame.payload, offset);
        crypto::Bytes sig = read_field(frame.payload, offset);
        std::optional<crypto::Bytes> pq_ciphertext;
        std::optional<crypto::Bytes> pq_salt;
        std::optional<std::string> inner_mode;
        std::optional<bool> inner_hop;
        std::optional<inner::KdfParams> inner_kdf;
        if (offset < frame.payload.size()) {
            pq_ciphertext = read_field(frame.payload, offset);
        }
        if (offset < frame.payload.size()) {
            pq_salt = read_field(frame.payload, offset);
        }
        if (offset < frame.payload.size()) {
            crypto::Bytes mode_bytes = read_field(frame.payload, offset);
            if (!mode_bytes.empty()) {
                inner_mode.emplace(mode_bytes.begin(), mode_bytes.end());
            }
        }
        if (offset < frame.payload.size()) {
            crypto::Bytes hop_bytes = read_field(frame.payload, offset);
            if (!hop_bytes.empty()) {
                inner_hop = (hop_bytes[0] != static_cast<uint8_t>('0'));
            } else {
                inner_hop = false;
            }
        }
        if (offset < frame.payload.size()) {
            crypto::Bytes kdf_bytes = read_field(frame.payload, offset);
            if (!kdf_bytes.empty()) {
                inner::KdfParams params;
                params.name.assign(kdf_bytes.begin(), kdf_bytes.end());
                if (offset < frame.payload.size()) {
                    crypto::Bytes param_bytes = read_field(frame.payload, offset);
                    if (param_bytes.size() == 16) {
                        auto read_u32 = [&](size_t off) -> std::uint32_t {
                            if (off + 4 > param_bytes.size()) {
                                return 0;
                            }
                            return (static_cast<std::uint32_t>(param_bytes[off]) << 24) |
                                   (static_cast<std::uint32_t>(param_bytes[off + 1]) << 16) |
                                   (static_cast<std::uint32_t>(param_bytes[off + 2]) << 8) |
                                   static_cast<std::uint32_t>(param_bytes[off + 3]);
                        };
                        params.argon2_time = read_u32(0);
                        params.argon2_memory = read_u32(4);
                        params.argon2_parallelism = read_u32(8);
                        params.pbkdf2_iters = read_u32(12);
                    }
                }
                inner_kdf = params;
            }
        }

        BIO* pub_bio = BIO_new_mem_buf(pub_pem.data(), static_cast<int>(pub_pem.size()));
        if (!pub_bio) {
            auth_error_ = "access denied: invalid key";
            return false;
        }
        EVP_PKEY* pubkey = PEM_read_bio_PUBKEY(pub_bio, nullptr, nullptr, nullptr);
        BIO_free(pub_bio);
        if (!pubkey) {
            auth_error_ = "access denied: invalid key";
            return false;
        }

        bool sig_ok = crypto::verify_key(pubkey, challenge_, sig);
        bool auth_ok = authorized_keys_ ? is_authorized(pubkey, *authorized_keys_) : false;
        std::string fingerprint = fingerprint_pubkey(pubkey);
        client_id_ = fingerprint;
        auth_fingerprint_ = fingerprint;
        client_auth_pubkey_b64_ = yume::util::base64_encode(std::string(pub_pem.begin(), pub_pem.end()));
        EVP_PKEY_free(pubkey);

        if (!sig_ok || !auth_ok) {
            if (!sig_ok) {
                auth_error_ = "access denied: bad signature";
            } else {
                auth_error_ = "access denied: invalid key";
            }
            return false;
        }

        AuthKeyPolicy auth_policy;
        if (!cfg_.auth_keys_meta.empty()) {
            try {
                AuthKeyPolicyMap auth_policies = load_auth_policies(cfg_.auth_keys_meta);
                auto it = auth_policies.find(fingerprint);
                if (it != auth_policies.end()) {
                    auth_policy = std::move(it->second);
                }
            } catch (const std::exception& ex) {
                auth_error_ = std::string("server auth policy load failed: ") + ex.what();
                return false;
            }
        }
        const bool key_exec = auth_policy.allow_exec.value_or(false);
        const bool key_local_ip = auth_policy.allow_local_ip.value_or(false);
        const bool key_control_full = auth_policy.control_full.value_or(false);
#if YUME_FEATURE_EXEC
        session_allow_exec_policy_ = key_exec && cfg_.allow_exec;
#else
        session_allow_exec_policy_ = false;
        if (key_exec || cfg_.allow_exec) {
            util::log_warn("session " + std::to_string(session_id_) +
                          ": exec requested but YUME_FEATURE_EXEC is OFF at build time");
        }
#endif
#if YUME_FEATURE_LAN_BRIDGE
        session_allow_local_ip_ = key_local_ip && cfg_.allow_local_ip;
#else
        session_allow_local_ip_ = false;
        if (key_local_ip || cfg_.allow_local_ip) {
            util::log_warn("session " + std::to_string(session_id_) +
                          ": LAN bridging requested but YUME_FEATURE_LAN_BRIDGE is OFF at build time");
        }
#endif
#if YUME_FEATURE_FULL_CONTROL
        session_control_full_ = key_control_full && cfg_.control_full;
#else
        session_control_full_ = false;
        if (key_control_full || cfg_.control_full) {
            util::log_warn("session " + std::to_string(session_id_) +
                          ": full control requested but YUME_FEATURE_FULL_CONTROL is OFF at build time");
        }
#endif
        session_allow_inbound_admin_policy_ = auth_policy.allow_inbound_admin.value_or(false);
        session_allow_outbound_admin_policy_ = auth_policy.allow_outbound_admin.value_or(false);
        session_allow_chat_policy_ = auth_policy.allow_chat.value_or(true);
        session_allow_file_policy_ = auth_policy.allow_file.value_or(true);
        session_allow_bytes_policy_ = auth_policy.allow_bytes.value_or(true);
        if (!auth_policy.empty()) {
            util::log_info("session " + std::to_string(session_id_) + ": auth policy " +
                           summarize_auth_policy(auth_policy));
        }

        if (cfg_.inner_crypto) {
            if (!pq_ciphertext.has_value() || !pq_salt.has_value()) {
                if (cfg_.inner_required) {
                    auth_error_ = "server requires inner crypto";
                    return false;
                }
                util::log_warn("session " + std::to_string(session_id_) + ": missing PQ fields; inner crypto disabled for this session");
            } else if (pq_salt->empty()) {
                if (cfg_.inner_required) {
                    auth_error_ = "server requires inner crypto";
                    return false;
                }
                util::log_warn("session " + std::to_string(session_id_) + ": missing PQ salt; inner crypto disabled for this session");
            } else {
                if (inner_mode.has_value() && !cfg_.inner_dual) {
                    bool wants_heavy = (*inner_mode == "heavy");
                    bool wants_light = (*inner_mode == "light");
                    if ((wants_heavy && !cfg_.inner_heavy) || (wants_light && cfg_.inner_heavy)) {
                        auth_error_ = "server does not support requested inner mode";
                        return false;
                    }
                }
                if (inner_kdf.has_value() && !inner_kdf->name.empty()) {
                    if (inner_kdf->name == "argon2") {
                        if (!inner::argon2_supported()) {
                            auth_error_ = "server does not support argon2";
                            return false;
                        }
                        std::string cap_reason;
                        if (inner::argon2_params_exceed_limits(
                                *inner_kdf, inner::argon2_env_limits(), &cap_reason)) {
                            auth_error_ = "client argon2 params exceed server cap: " + cap_reason;
                            return false;
                        }
                    } else if (inner_kdf->name == "pbkdf2") {
                        if (!inner::pbkdf2_supported()) {
                            auth_error_ = "server does not support pbkdf2";
                            return false;
                        }
                    } else if (inner_kdf->name == "hkdf") {
                        if (!inner_mode.has_value() || *inner_mode != "light") {
                            auth_error_ = "invalid kdf request";
                            return false;
                        }
                    } else {
                        auth_error_ = "invalid kdf request";
                        return false;
                    }
                }
                inner::Config inner_cfg;
                inner_cfg.enabled = cfg_.inner_crypto;
                inner_cfg.pq_private_key = cfg_.pq_private_key;
                inner_cfg.allow_embedded_master = cfg_.allow_embedded_master;
                auto server_inner_start = std::chrono::steady_clock::now();
                if (cfg_.inner_dual) {
                    std::optional<inner::KdfParams> heavy_kdf;
                    if (inner_kdf.has_value() && !inner_kdf->name.empty() && inner_kdf->name != "hkdf") {
                        heavy_kdf = inner_kdf;
                    }
                    auto heavy = inner::server_derive_key(inner_cfg, *pq_ciphertext, *pq_salt, true, heavy_kdf);
                    auto light = inner::server_derive_key(inner_cfg, *pq_ciphertext, *pq_salt, false, std::nullopt);
                    if ((!heavy.has_value() || heavy->key.empty()) && (!light.has_value() || light->key.empty())) {
                        util::log_warn("session " + std::to_string(session_id_) + ": PQ key derivation failed");
                        auth_error_ = "access denied: pq key derivation failed";
                        return false;
                    }
                    bool prefer_light = (inner_mode.has_value() && *inner_mode == "light");
                    bool prefer_heavy = (inner_mode.has_value() && *inner_mode == "heavy");
                    if (prefer_light && light.has_value() && !light->key.empty()) {
                        inner_key_ = light->key;
                        inner_mode_ = "light";
                        inner_kdf_ = light->kdf;
                        if (heavy.has_value() && !heavy->key.empty()) {
                            inner_key_alt_ = heavy->key;
                            inner_alt_mode_ = "heavy";
                            inner_alt_kdf_ = heavy->kdf;
                        }
                    } else if (prefer_heavy && heavy.has_value() && !heavy->key.empty()) {
                        inner_key_ = heavy->key;
                        inner_mode_ = "heavy";
                        inner_kdf_ = heavy->kdf;
                        if (light.has_value() && !light->key.empty()) {
                            inner_key_alt_ = light->key;
                            inner_alt_mode_ = "light";
                            inner_alt_kdf_ = light->kdf;
                        }
                    } else if (cfg_.inner_heavy && heavy.has_value() && !heavy->key.empty()) {
                        inner_key_ = heavy->key;
                        inner_mode_ = "heavy";
                        inner_kdf_ = heavy->kdf;
                        if (light.has_value() && !light->key.empty()) {
                            inner_key_alt_ = light->key;
                            inner_alt_mode_ = "light";
                            inner_alt_kdf_ = light->kdf;
                        }
                    } else if (light.has_value() && !light->key.empty()) {
                        inner_key_ = light->key;
                        inner_mode_ = "light";
                        inner_kdf_ = light->kdf;
                        if (heavy.has_value() && !heavy->key.empty()) {
                            inner_key_alt_ = heavy->key;
                            inner_alt_mode_ = "heavy";
                            inner_alt_kdf_ = heavy->kdf;
                        }
                    }
                } else {
                    auto derived = inner::server_derive_key(inner_cfg, *pq_ciphertext, *pq_salt, cfg_.inner_heavy, inner_kdf);
                    if (!derived.has_value() || derived->key.empty()) {
                        util::log_warn("session " + std::to_string(session_id_) + ": PQ key derivation failed");
                        auth_error_ = "access denied: pq key derivation failed";
                        return false;
                    }
                    inner_key_ = derived->key;
                    inner_mode_ = cfg_.inner_heavy ? "heavy" : "light";
                    inner_kdf_ = derived->kdf;
                }
                auto server_inner_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - server_inner_start).count();
                util::log_timing("server.auth",
                                 "inner_prepare",
                                 "session=" + std::to_string(session_id_) +
                                     " ms=" + std::to_string(server_inner_ms) +
                                     " mode=" + (inner_mode_.empty() ? std::string("none") : inner_mode_) +
                                     " kdf=" + (inner_kdf_.empty() ? std::string("unknown") : inner_kdf_) +
                                     " alt_mode=" + (inner_alt_mode_.empty() ? std::string("none") : inner_alt_mode_) +
                                     " alt_kdf=" + (inner_alt_kdf_.empty() ? std::string("none") : inner_alt_kdf_));
            }
        } else if (pq_ciphertext.has_value()) {
            auth_error_ = "server does not support inner crypto";
            return false;
        }

        bool client_hop = inner_hop.value_or(false);
        if (cfg_.inner_hop) {
            if (!client_hop) {
                auth_error_ = "server requires hopping";
                return false;
            }
        } else if (client_hop) {
            auth_error_ = "server does not support hopping";
            return false;
        }
        hop_enabled_ = (cfg_.inner_hop && client_hop && inner_key_.has_value());
        hop_interval_ms_ = cfg_.hop_interval_ms;
        hop_offset_ms_ = 0;

        if (!cfg_.anonym) {
            update_auth_meta(cfg_.auth_keys_meta, fingerprint);
        }
        return true;
    } catch (const std::exception&) {
        auth_error_ = "access denied: invalid key";
        return false;
    }
}

void Session::handle_open(const protocol::Frame& frame) {
    if (pending_reverse_.find(frame.header.stream_id) != pending_reverse_.end()) {
        bool ok = (frame.header.flags & protocol::kFlagOpenOk) != 0;
        crypto::Bytes payload = frame.payload;
        if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
            crypto::Bytes decrypted;
            if (decrypt_inner_payload(frame.header.type, frame.header.stream_id, frame.payload, &decrypted)) {
                payload = std::move(decrypted);
            } else {
                ok = false;
            }
        }
        if (!ok) {
            std::string reason(payload.begin(), payload.end());
            util::log_warn("reverse open failed: " + reason);
            handle_close(frame.header.stream_id, "reverse open failed");
        } else {
            start_remote_read(frame.header.stream_id);
        }
        pending_reverse_.erase(frame.header.stream_id);
        return;
    }
    if (streams_.find(frame.header.stream_id) != streams_.end() ||
        udp_streams_.find(frame.header.stream_id) != udp_streams_.end()) {
        send_open_reply(frame.header.stream_id, false, "stream already exists");
        return;
    }

    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        crypto::Bytes decrypted;
        if (decrypt_inner_payload(frame.header.type, frame.header.stream_id, frame.payload, &decrypted)) {
            payload = std::move(decrypted);
        } else {
            util::log_warn("session " + std::to_string(session_id_) + ": OPEN decrypt failed for stream " +
                           std::to_string(frame.header.stream_id));
            close_with_reason("OPEN decrypt failed for stream " + std::to_string(frame.header.stream_id));
            return;
        }
    }
    std::string payload_str(payload.begin(), payload.end());
    std::string host;
    int port = 0;
    std::string proto;

    try {
        auto json = nlohmann::json::parse(payload_str);
        if (json.contains("target_id") && json.contains("channel_kind") && json.contains("channel_id")) {
            const std::string target_id = json.value("target_id", "");
            const std::string from_id = json.value("from_id", client_id_);
            const std::string channel_id = json.value("channel_id", "");
            const auto channel_kind = control::channel_kind_from_string(json.value("channel_kind", "chat"));
            if (!cfg_.relay_enable) {
                send_open_reply(frame.header.stream_id, false, "relay disabled");
                return;
            }
            if (target_id.empty() || channel_id.empty() || from_id.empty()) {
                send_open_reply(frame.header.stream_id, false, "invalid relay open");
                return;
            }
            std::shared_ptr<Session> target;
            control::PendingInvite invite;
            std::string error;
            if (!manager_ || !manager_->can_open_channel(channel_id, from_id, target_id, channel_kind, &target, &invite, &error)) {
                send_open_reply(frame.header.stream_id, false, error.empty() ? "invite invalid" : error);
                return;
            }
            if (channel_kind == control::ChannelKind::admin && client_relay_mode_ != control::RelayMode::trusted) {
                send_open_reply(frame.header.stream_id, false, "admin requires trusted relay mode");
                return;
            }
            if (channel_kind == control::ChannelKind::chat && !client_allow_chat_) {
                send_open_reply(frame.header.stream_id, false, "chat disabled");
                return;
            }
            if (channel_kind == control::ChannelKind::file && !client_allow_file_) {
                send_open_reply(frame.header.stream_id, false, "file relay disabled");
                return;
            }
            if (channel_kind == control::ChannelKind::bytes && !client_allow_bytes_) {
                send_open_reply(frame.header.stream_id, false, "byte relay disabled");
                return;
            }
            if (frame.header.stream_id == 0 || target.get() == this) {
                send_open_reply(frame.header.stream_id, false, "invalid relay target");
                return;
            }
            uint8_t target_stream = target->reserve_stream_id();
            if (target_stream == 0) {
                send_open_reply(frame.header.stream_id, false, "no stream ids available");
                return;
            }
            {
                std::lock_guard<std::mutex> lock(control_mutex_);
                control_outbound_[frame.header.stream_id] = ControlLink{
                    target,
                    target_stream,
                    true,
                    false,
                    channel_kind,
                    channel_id,
                    from_id,
                    target_id};
            }
            {
                std::lock_guard<std::mutex> lock(target->control_mutex_);
                target->control_inbound_[target_stream] = ControlLink{
                    shared_from_this(),
                    frame.header.stream_id,
                    true,
                    false,
                    channel_kind,
                    channel_id,
                    from_id,
                    target_id};
            }
            if (manager_) {
                control::ActiveRelayChannel channel;
                channel.channel_id = channel_id;
                channel.channel_kind = channel_kind;
                channel.left_endpoint_id = from_id;
                channel.right_endpoint_id = target_id;
                channel.left_stream_id = frame.header.stream_id;
                channel.right_stream_id = target_stream;
                channel.pending = true;
                manager_->register_active_channel(channel);
                if (channel_kind == control::ChannelKind::admin) {
                    manager_->add_admin_relationship(from_id, target_id);
                }
            }
            target->send_control_frame(protocol::SOPEN, target_stream, payload);
            return;
        }
        host = json.value("host", "");
        port = json.value("port", 0);
        proto = json.value("proto", "");
    } catch (const std::exception&) {
        send_open_reply(frame.header.stream_id, false, "invalid OPEN payload");
        return;
    }

    if (host.empty() || port <= 0) {
        send_open_reply(frame.header.stream_id, false, "missing host/port");
        return;
    }
    if (is_blocked_host_literal(host, session_allow_local_ip_, session_control_full_)) {
        send_open_reply(frame.header.stream_id, false, "blocked destination");
        return;
    }

    if (proto.empty()) {
        proto = "tcp";
    }
    if (proto != "tcp" && proto != "udp") {
        send_open_reply(frame.header.stream_id, false, "proto not supported");
        return;
    }

    if (proto == "udp") {
        util::log_info("session " + std::to_string(session_id_) + ": OPEN udp stream " +
                       std::to_string(frame.header.stream_id) + " -> " + host + ":" + std::to_string(port));
        auto udp = std::make_shared<UdpStream>(stream_.get_executor());
        udp->host = host;
        udp->port = port;
        udp->open_started_ms = util::now_ms();
        udp->resolve_started_ms = udp->open_started_ms;
        const bool resolve_any_family = server_resolve_any_family_enabled();
        const std::string resolve_family = resolve_any_family ? "any" : "ipv4";
        util::log_timing("server.open",
                         "start",
                         "session=" + std::to_string(session_id_) +
                             " stream=" + std::to_string(frame.header.stream_id) +
                             " proto=udp family=" + resolve_family +
                             " target=" + host + ":" + std::to_string(port));

        {
            std::lock_guard<std::mutex> lock(streams_mutex_);
            udp_streams_[frame.header.stream_id] = udp;
        }

        auto self = shared_from_this();
        const auto self_local_addr = session_local_address(stream_);

        auto resolver_timer = std::make_shared<boost::asio::deadline_timer>(stream_.get_executor());
        auto resolve_timed_out = std::make_shared<bool>(false);
        resolver_timer->expires_from_now(boost::posix_time::milliseconds(kResolverTimeoutMs));

        auto resolver_handler = [self, stream_id = frame.header.stream_id, udp, self_local_addr, resolver_timer, resolve_timed_out](const boost::system::error_code& ec,
                                                                                                                                   const boost::asio::ip::udp::resolver::results_type& results) {
            resolver_timer->cancel();
            const int64_t resolve_ms = udp->resolve_started_ms > 0 ? (util::now_ms() - udp->resolve_started_ms) : 0;
            {
                std::lock_guard<std::mutex> lock(self->streams_mutex_);
                if (self->udp_streams_.find(stream_id) == self->udp_streams_.end()) {
                    return;
                }
            }

            if (ec) {
                if (ec == boost::asio::error::operation_aborted &&
                    self->close_state_ != CloseState::Open) {
                    return;
                }
                const std::string reason = *resolve_timed_out
                    ? "resolve timeout"
                    : ("resolve failed: " + ec.message());
                util::log_timing("server.open",
                                 "resolve_failed",
                                 "session=" + std::to_string(self->session_id_) +
                                     " stream=" + std::to_string(stream_id) +
                                     " proto=udp ms=" + std::to_string(resolve_ms) +
                                     " reason=" + reason);
                self->send_open_reply(stream_id, false, reason);
                std::lock_guard<std::mutex> lock(self->streams_mutex_);
                self->udp_streams_.erase(stream_id);
                return;
            }
            std::size_t result_count = 0;
            for (const auto& result : results) {
                (void)result;
                ++result_count;
            }
            util::log_timing("server.open",
                             "resolve_ok",
                             "session=" + std::to_string(self->session_id_) +
                                 " stream=" + std::to_string(stream_id) +
                                 " proto=udp ms=" + std::to_string(resolve_ms) +
                                 " results=" + std::to_string(result_count));

            std::vector<boost::asio::ip::udp::endpoint> allowed;
            bool blocked_active_server = false;
            for (const auto& entry : results) {
                if (is_active_server_endpoint(entry.endpoint(), self->cfg_, self_local_addr)) {
                    blocked_active_server = true;
                    continue;
                }
                if (is_allowed_address(entry.endpoint().address(),
                                       self->session_allow_local_ip_,
                                       self->session_control_full_)) {
                    allowed.push_back(entry.endpoint());
                }
            }

            if (allowed.empty()) {
                self->send_open_reply(stream_id,
                                     false,
                                     blocked_active_server
                                         ? "blocked destination: active server endpoint"
                                         : "blocked destination");
                std::lock_guard<std::mutex> lock(self->streams_mutex_);
                self->udp_streams_.erase(stream_id);
                return;
            }

            prefer_ipv4_endpoints(&allowed);
            udp->remote = allowed.front();
            boost::system::error_code ec2;
            udp->socket.open(udp->remote.protocol(), ec2);
            if (ec2) {
                self->send_open_reply(stream_id, false, "udp open failed: " + ec2.message());
                std::lock_guard<std::mutex> lock(self->streams_mutex_);
                self->udp_streams_.erase(stream_id);
                return;
            }

            udp->socket.connect(udp->remote, ec2);
            if (ec2) {
                self->send_open_reply(stream_id, false, "connect failed: " + ec2.message());
                std::lock_guard<std::mutex> lock(self->streams_mutex_);
                self->udp_streams_.erase(stream_id);
                return;
            }

            self->send_open_reply(stream_id, true, "");
            util::log_timing("server.open",
                             "done",
                             "session=" + std::to_string(self->session_id_) +
                                 " stream=" + std::to_string(stream_id) +
                                 " proto=udp ok=1 ms=" +
                                 std::to_string(util::now_ms() - udp->open_started_ms));
            self->start_udp_read(stream_id);
        };

        const auto resolver_flags = boost::asio::ip::resolver_base::numeric_service;
        if (!cfg_.dns_server.empty() && !resolve_any_family) {
            auto direct_dns = std::make_shared<DirectDnsAQuery>(
                strand_,
                cfg_.dns_server,
                host,
                [self, stream_id = frame.header.stream_id, udp, self_local_addr, port](
                    bool ok,
                    const std::vector<boost::asio::ip::address_v4>& addresses,
                    const std::string& reason,
                    int64_t resolve_ms) {
                    {
                        std::lock_guard<std::mutex> lock(self->streams_mutex_);
                        if (self->udp_streams_.find(stream_id) == self->udp_streams_.end()) {
                            return;
                        }
                    }
                    if (!ok) {
                        util::log_timing("server.open",
                                         "resolve_failed",
                                         "session=" + std::to_string(self->session_id_) +
                                             " stream=" + std::to_string(stream_id) +
                                             " proto=udp direct_dns=1 ms=" + std::to_string(resolve_ms) +
                                             " reason=" + reason);
                        self->send_open_reply(stream_id, false, "resolve failed: " + reason);
                        std::lock_guard<std::mutex> lock(self->streams_mutex_);
                        self->udp_streams_.erase(stream_id);
                        return;
                    }
                    util::log_timing("server.open",
                                     "resolve_ok",
                                     "session=" + std::to_string(self->session_id_) +
                                         " stream=" + std::to_string(stream_id) +
                                         " proto=udp direct_dns=1 ms=" + std::to_string(resolve_ms) +
                                         " results=" + std::to_string(addresses.size()));

                    std::vector<boost::asio::ip::udp::endpoint> allowed;
                    bool blocked_active_server = false;
                    for (const auto& address : addresses) {
                        boost::asio::ip::udp::endpoint endpoint(address, static_cast<unsigned short>(port));
                        if (is_active_server_endpoint(endpoint, self->cfg_, self_local_addr)) {
                            blocked_active_server = true;
                            continue;
                        }
                        if (is_allowed_address(endpoint.address(),
                                               self->session_allow_local_ip_,
                                               self->session_control_full_)) {
                            allowed.push_back(endpoint);
                        }
                    }

                    if (allowed.empty()) {
                        self->send_open_reply(stream_id,
                                             false,
                                             blocked_active_server
                                                 ? "blocked destination: active server endpoint"
                                                 : "blocked destination");
                        std::lock_guard<std::mutex> lock(self->streams_mutex_);
                        self->udp_streams_.erase(stream_id);
                        return;
                    }

                    udp->remote = allowed.front();
                    boost::system::error_code ec2;
                    udp->socket.open(udp->remote.protocol(), ec2);
                    if (ec2) {
                        self->send_open_reply(stream_id, false, "udp open failed: " + ec2.message());
                        std::lock_guard<std::mutex> lock(self->streams_mutex_);
                        self->udp_streams_.erase(stream_id);
                        return;
                    }

                    udp->socket.connect(udp->remote, ec2);
                    if (ec2) {
                        self->send_open_reply(stream_id, false, "connect failed: " + ec2.message());
                        std::lock_guard<std::mutex> lock(self->streams_mutex_);
                        self->udp_streams_.erase(stream_id);
                        return;
                    }

                    self->send_open_reply(stream_id, true, "");
                    util::log_timing("server.open",
                                     "done",
                                     "session=" + std::to_string(self->session_id_) +
                                         " stream=" + std::to_string(stream_id) +
                                         " proto=udp ok=1 ms=" +
                                         std::to_string(util::now_ms() - udp->open_started_ms));
                    self->start_udp_read(stream_id);
                });
            direct_dns->start();
        } else if (resolve_any_family) {
            udp->resolver.async_resolve(host, std::to_string(port), resolver_flags,
                                        boost::asio::bind_executor(strand_, resolver_handler));
            resolver_timer->async_wait(boost::asio::bind_executor(strand_,
                [udp, resolve_timed_out](const boost::system::error_code& ec) {
                    if (ec) {
                        return;
                    }
                    *resolve_timed_out = true;
                    udp->resolver.cancel();
                }));
        } else {
            udp->resolver.async_resolve(boost::asio::ip::udp::v4(), host, std::to_string(port), resolver_flags,
                                        boost::asio::bind_executor(strand_, resolver_handler));
            resolver_timer->async_wait(boost::asio::bind_executor(strand_,
                [udp, resolve_timed_out](const boost::system::error_code& ec) {
                    if (ec) {
                        return;
                    }
                    *resolve_timed_out = true;
                    udp->resolver.cancel();
                }));
        }

        return;
    }

    util::log_info("session " + std::to_string(session_id_) + ": OPEN tcp stream " +
                   std::to_string(frame.header.stream_id) + " -> " + host + ":" + std::to_string(port));
    auto remote = std::make_shared<RemoteStream>(stream_.get_executor());
    remote->host = host;
    remote->port = port;
    remote->open_started_ms = util::now_ms();
    remote->resolve_started_ms = remote->open_started_ms;
    const bool resolve_any_family = server_resolve_any_family_enabled();
    const std::string resolve_family = resolve_any_family ? "any" : "ipv4";
    util::log_timing("server.open",
                     "start",
                     "session=" + std::to_string(session_id_) +
                         " stream=" + std::to_string(frame.header.stream_id) +
                         " proto=tcp family=" + resolve_family +
                         " target=" + host + ":" + std::to_string(port));
    boost::system::error_code keep_ec;
    remote->socket.set_option(boost::asio::socket_base::keep_alive(true), keep_ec);

    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        streams_[frame.header.stream_id] = remote;
    }

    auto self = shared_from_this();
    const auto self_local_addr = session_local_address(stream_);

    auto resolver_timer = std::make_shared<boost::asio::deadline_timer>(stream_.get_executor());
    auto resolve_timed_out = std::make_shared<bool>(false);
    resolver_timer->expires_from_now(boost::posix_time::milliseconds(kResolverTimeoutMs));

    auto continue_tcp_open = [self,
                              stream_id = frame.header.stream_id,
                              remote,
                              self_local_addr](std::vector<boost::asio::ip::tcp::endpoint> resolved,
                                               std::size_t result_count,
                                               int64_t resolve_ms,
                                               bool direct_dns) {
        util::log_timing("server.open",
                         "resolve_ok",
                         "session=" + std::to_string(self->session_id_) +
                             " stream=" + std::to_string(stream_id) +
                             " proto=tcp" +
                             (direct_dns ? std::string(" direct_dns=1") : std::string{}) +
                             " ms=" + std::to_string(resolve_ms) +
                             " results=" + std::to_string(result_count));

        std::vector<boost::asio::ip::tcp::endpoint> allowed;
        bool blocked_active_server = false;
        for (const auto& endpoint : resolved) {
            if (is_active_server_endpoint(endpoint, self->cfg_, self_local_addr)) {
                blocked_active_server = true;
                continue;
            }
            if (is_allowed_address(endpoint.address(),
                                   self->session_allow_local_ip_,
                                   self->session_control_full_)) {
                allowed.push_back(endpoint);
            }
        }

        if (allowed.empty()) {
            self->send_open_reply(stream_id,
                                  false,
                                  blocked_active_server
                                      ? "blocked destination: active server endpoint"
                                      : "blocked destination");
            std::lock_guard<std::mutex> lock(self->streams_mutex_);
            self->streams_.erase(stream_id);
            return;
        }

        prefer_ipv4_endpoints(&allowed);

        auto connect_timer = std::make_shared<boost::asio::deadline_timer>(self->stream_.get_executor());
        auto connect_timed_out = std::make_shared<bool>(false);
        remote->connect_started_ms = util::now_ms();
        connect_timer->expires_from_now(boost::posix_time::milliseconds(kConnectTimeoutMs));

        boost::asio::async_connect(remote->socket, allowed,
                                   boost::asio::bind_executor(self->strand_,
                                                              [self, stream_id, remote, connect_timer, connect_timed_out](const boost::system::error_code& ec2,
                                                                                                                          const boost::asio::ip::tcp::endpoint&) {
                                                                  connect_timer->cancel();
                                                                  const int64_t connect_ms = remote->connect_started_ms > 0
                                                                      ? (util::now_ms() - remote->connect_started_ms)
                                                                      : 0;
                                                                  {
                                                                      std::lock_guard<std::mutex> lock(self->streams_mutex_);
                                                                      if (self->streams_.find(stream_id) == self->streams_.end()) {
                                                                          return;
                                                                      }
                                                                  }
                                                                  if (ec2) {
                                                                      if (ec2 == boost::asio::error::operation_aborted &&
                                                                          self->close_state_ != CloseState::Open) {
                                                                          return;
                                                                      }
                                                                      const std::string reason = *connect_timed_out
                                                                          ? "connect timeout"
                                                                          : ("connect failed: " + ec2.message());
                                                                      util::log_timing("server.open",
                                                                                       "connect_failed",
                                                                                       "session=" + std::to_string(self->session_id_) +
                                                                                           " stream=" + std::to_string(stream_id) +
                                                                                           " proto=tcp ms=" + std::to_string(connect_ms) +
                                                                                           " reason=" + reason);
                                                                      self->send_open_reply(stream_id, false, reason);
                                                                      std::lock_guard<std::mutex> lock(self->streams_mutex_);
                                                                      self->streams_.erase(stream_id);
                                                                      return;
                                                                  }
                                                                  boost::system::error_code nodelay_ec;
                                                                  remote->socket.set_option(boost::asio::ip::tcp::no_delay(true), nodelay_ec);
                                                                  remote->connected = true;
                                                                  self->send_open_reply(stream_id, true, "");
                                                                  util::log_timing("server.open",
                                                                                   "done",
                                                                                   "session=" + std::to_string(self->session_id_) +
                                                                                       " stream=" + std::to_string(stream_id) +
                                                                                       " proto=tcp ok=1 connect_ms=" +
                                                                                       std::to_string(connect_ms) +
                                                                                       " total_ms=" +
                                                                                       std::to_string(util::now_ms() - remote->open_started_ms));
                                                                  self->start_remote_read(stream_id);
                                                                  self->do_remote_write(stream_id);
                                                                  }));

        connect_timer->async_wait(boost::asio::bind_executor(self->strand_,
            [self, stream_id, remote, connect_timed_out](const boost::system::error_code& ec) {
                if (ec) {
                    return;
                }
                *connect_timed_out = true;
                boost::system::error_code ignore_ec;
                remote->socket.close(ignore_ec);
            }));
    };

    auto resolver_handler = [self, stream_id = frame.header.stream_id, remote, resolver_timer, resolve_timed_out, continue_tcp_open](const boost::system::error_code& ec,
                                                                                                                                    const boost::asio::ip::tcp::resolver::results_type& results) {
        resolver_timer->cancel();
        const int64_t resolve_ms = remote->resolve_started_ms > 0 ? (util::now_ms() - remote->resolve_started_ms) : 0;
        {
            std::lock_guard<std::mutex> lock(self->streams_mutex_);
            if (self->streams_.find(stream_id) == self->streams_.end()) {
                return;
            }
        }

        if (ec) {
            if (ec == boost::asio::error::operation_aborted &&
                self->close_state_ != CloseState::Open) {
                return;
            }
            const std::string reason = *resolve_timed_out
                ? "resolve timeout"
                : ("resolve failed: " + ec.message());
            util::log_timing("server.open",
                             "resolve_failed",
                             "session=" + std::to_string(self->session_id_) +
                                 " stream=" + std::to_string(stream_id) +
                                 " proto=tcp ms=" + std::to_string(resolve_ms) +
                                 " reason=" + reason);
            self->send_open_reply(stream_id, false, reason);
            std::lock_guard<std::mutex> lock(self->streams_mutex_);
            self->streams_.erase(stream_id);
            return;
        }
        std::size_t result_count = 0;
        std::vector<boost::asio::ip::tcp::endpoint> resolved;
        for (const auto& result : results) {
            resolved.push_back(result.endpoint());
            ++result_count;
        }
        continue_tcp_open(std::move(resolved), result_count, resolve_ms, false);
    };

    const auto resolver_flags = boost::asio::ip::resolver_base::numeric_service;
    if (!cfg_.dns_server.empty() && !resolve_any_family) {
        auto direct_dns = std::make_shared<DirectDnsAQuery>(
            strand_,
            cfg_.dns_server,
            host,
            [self, stream_id = frame.header.stream_id, remote, port, continue_tcp_open](
                bool ok,
                const std::vector<boost::asio::ip::address_v4>& addresses,
                const std::string& reason,
                int64_t resolve_ms) {
                {
                    std::lock_guard<std::mutex> lock(self->streams_mutex_);
                    if (self->streams_.find(stream_id) == self->streams_.end()) {
                        return;
                    }
                }
                if (!ok) {
                    util::log_timing("server.open",
                                     "resolve_failed",
                                     "session=" + std::to_string(self->session_id_) +
                                         " stream=" + std::to_string(stream_id) +
                                         " proto=tcp direct_dns=1 ms=" + std::to_string(resolve_ms) +
                                         " reason=" + reason);
                    self->send_open_reply(stream_id, false, "resolve failed: " + reason);
                    std::lock_guard<std::mutex> lock(self->streams_mutex_);
                    self->streams_.erase(stream_id);
                    return;
                }
                std::vector<boost::asio::ip::tcp::endpoint> resolved;
                resolved.reserve(addresses.size());
                for (const auto& address : addresses) {
                    resolved.emplace_back(address, static_cast<unsigned short>(port));
                }
                continue_tcp_open(std::move(resolved), addresses.size(), resolve_ms, true);
            });
        direct_dns->start();
    } else if (resolve_any_family) {
        remote->resolver.async_resolve(host, std::to_string(port), resolver_flags,
                                       boost::asio::bind_executor(strand_, resolver_handler));
        resolver_timer->async_wait(boost::asio::bind_executor(strand_,
            [self, stream_id = frame.header.stream_id, remote, resolve_timed_out](const boost::system::error_code& ec) {
                if (ec) {
                    return;
                }
                *resolve_timed_out = true;
                remote->resolver.cancel();
            }));
    } else {
        remote->resolver.async_resolve(boost::asio::ip::tcp::v4(), host, std::to_string(port), resolver_flags,
                                       boost::asio::bind_executor(strand_, resolver_handler));
        resolver_timer->async_wait(boost::asio::bind_executor(strand_,
            [self, stream_id = frame.header.stream_id, remote, resolve_timed_out](const boost::system::error_code& ec) {
                if (ec) {
                    return;
                }
                *resolve_timed_out = true;
                remote->resolver.cancel();
            }));
    }
}

uint8_t Session::reserve_stream_id() {
    std::lock_guard<std::mutex> lock(streams_mutex_);
    for (int i = 1; i < 255; ++i) {
        uint8_t candidate = static_cast<uint8_t>(i);
        if (streams_.find(candidate) == streams_.end() &&
            udp_streams_.find(candidate) == udp_streams_.end() &&
            pending_reverse_.find(candidate) == pending_reverse_.end() &&
            reverse_listeners_.find(candidate) == reverse_listeners_.end()) {
            return candidate;
        }
    }
    return 0;
}

void Session::handle_rlisten(const protocol::Frame& frame) {
    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        crypto::Bytes decrypted;
        if (decrypt_inner_payload(frame.header.type, frame.header.stream_id, frame.payload, &decrypted)) {
            payload = std::move(decrypted);
        } else {
            send_open_reply(frame.header.stream_id, false, "RLISTEN decrypt failed");
            return;
        }
    }
    std::string payload_str(payload.begin(), payload.end());
    int listen_port = 0;
    bool reclaim = false;
    int min_port = 0;
    int max_port = 0;
    try {
        auto json = nlohmann::json::parse(payload_str);
        listen_port = json.value("port", 0);
        reclaim = json.value("reclaim", false);
        min_port = json.value("min_port", 0);
        max_port = json.value("max_port", 0);
    } catch (...) {
        send_open_reply(frame.header.stream_id, false, "invalid RLISTEN payload");
        return;
    }
    const bool auto_select_port = (listen_port <= 0) && (min_port > 0) && (max_port > 0);
    if (!auto_select_port) {
        if (listen_port <= 0) {
            send_open_reply(frame.header.stream_id, false, "invalid listen port");
            return;
        }
        if (listen_port < cfg_.reverse_port_min || listen_port > cfg_.reverse_port_max) {
            send_open_reply(frame.header.stream_id, false,
                            "listen port must be " + std::to_string(cfg_.reverse_port_min) + "-" +
                                std::to_string(cfg_.reverse_port_max));
            return;
        }
    } else {
        if (min_port > max_port) {
            std::swap(min_port, max_port);
        }
        min_port = std::max(min_port, cfg_.reverse_port_min);
        max_port = std::min(max_port, cfg_.reverse_port_max);
        if (min_port > max_port) {
            min_port = cfg_.reverse_port_min;
            max_port = cfg_.reverse_port_max;
        }
    }
    if (reverse_listeners_.find(frame.header.stream_id) != reverse_listeners_.end()) {
        send_open_reply(frame.header.stream_id, false, "listener exists");
        return;
    }

    bool reclaimed = false;
    std::string bind_error;
    auto try_bind_listener = [&](int candidate_port,
                                 std::shared_ptr<boost::asio::ip::tcp::acceptor>* out_acceptor) -> bool {
        if (reclaim && manager_) {
            reclaimed = manager_->reclaim_reverse_listener(candidate_port);
        }
        auto candidate = std::make_shared<boost::asio::ip::tcp::acceptor>(stream_.get_executor());
        boost::system::error_code ec;
        boost::asio::ip::tcp::endpoint ep(boost::asio::ip::tcp::v4(), candidate_port);
        candidate->open(ep.protocol(), ec);
        if (ec) {
            bind_error = "listen failed: " + ec.message();
            return false;
        }
        candidate->set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
        candidate->bind(ep, ec);
        if (ec == boost::asio::error::address_in_use && reclaim && manager_ && !reclaimed) {
            if (manager_->reclaim_reverse_listener(candidate_port)) {
                ec.clear();
                candidate->bind(ep, ec);
            }
        }
        if (ec) {
            bind_error = "bind failed: " + ec.message();
            return false;
        }
        candidate->listen(boost::asio::socket_base::max_listen_connections, ec);
        if (ec) {
            bind_error = "listen failed: " + ec.message();
            return false;
        }
        *out_acceptor = std::move(candidate);
        return true;
    };

    std::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor;
    if (auto_select_port) {
        const int range_size = max_port - min_port + 1;
        const int start_port = random_int_inclusive(min_port, max_port);
        bool found_port = false;
        for (int offset = 0; offset < range_size; ++offset) {
            int candidate = min_port + ((start_port - min_port + offset) % range_size);
            if (try_bind_listener(candidate, &acceptor)) {
                listen_port = candidate;
                found_port = true;
                break;
            }
        }
        if (!found_port) {
            send_open_reply(frame.header.stream_id, false,
                            "no available listen port in range " + std::to_string(min_port) + "-" +
                                std::to_string(max_port));
            return;
        }
    } else {
        if (!try_bind_listener(listen_port, &acceptor)) {
            send_open_reply(frame.header.stream_id, false, bind_error);
            return;
        }
    }
    reverse_listeners_[frame.header.stream_id] = acceptor;
    reverse_listener_ports_[frame.header.stream_id] = listen_port;
    reverse_port_streams_[listen_port] = frame.header.stream_id;
    if (manager_) {
        manager_->register_reverse_listener(listen_port, shared_from_this());
    }
    send_open_reply(frame.header.stream_id, true, std::to_string(listen_port));

    auto self = shared_from_this();
    auto do_accept = std::make_shared<std::function<void()>>();
    *do_accept = [self, acceptor, listen_id = frame.header.stream_id, do_accept]() {
        acceptor->async_accept([self, acceptor, listen_id, do_accept](const boost::system::error_code& ec2,
                                                                      boost::asio::ip::tcp::socket socket) {
            if (!ec2) {
                uint8_t stream_id = self->reserve_stream_id();
                if (stream_id == 0) {
                    boost::system::error_code close_ec;
                    socket.close(close_ec);
                } else {
                    auto remote = std::make_shared<RemoteStream>(self->stream_.get_executor());
                    remote->socket = std::move(socket);
                    boost::system::error_code keep_ec;
                    remote->socket.set_option(boost::asio::socket_base::keep_alive(true), keep_ec);
                    self->streams_[stream_id] = remote;
                    self->pending_reverse_.insert(stream_id);

                    nlohmann::json json{{"listen_id", listen_id}};
                    std::string payload_str = json.dump();
                    std::vector<uint8_t> payload(payload_str.begin(), payload_str.end());
                    uint16_t flags = 0;
                    if (self->inner_key_.has_value()) {
                        payload = self->encrypt_inner_payload(protocol::ROPEN, stream_id, payload);
                        flags |= protocol::kFlagInnerEncrypted;
                    }
                    protocol::Frame notify{{static_cast<uint32_t>(payload.size()), protocol::ROPEN, stream_id, flags},
                                           payload};
                    self->async_write_frame(notify);
                }
            }
            (*do_accept)();
        });
    };
    (*do_accept)();
}

void Session::handle_control(const protocol::Frame& frame) {
    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        crypto::Bytes decrypted;
        if (decrypt_inner_payload(protocol::CONTROL, frame.header.stream_id, frame.payload, &decrypted)) {
            payload = std::move(decrypted);
        } else {
            util::log_warn("session " + std::to_string(session_id_) + ": CONTROL decrypt failed");
            return;
        }
    }

    nlohmann::json json;
    try {
        json = nlohmann::json::parse(std::string(payload.begin(), payload.end()));
    } catch (...) {
        util::log_warn("session " + std::to_string(session_id_) + ": invalid CONTROL payload");
        return;
    }

    const std::string cmd = json.value("cmd", "");
    if (cmd == "register") {
        client_hostname_ = cfg_.anonym ? std::string{} : json.value("hostname", "");
        client_server_in_charge_ = json.value("server_in_charge", false);
        client_allow_exec_ = json.value("allow_exec", false) && session_allow_exec_policy_;
        const std::string reported_ip = json.value("wan_ip", "");
        if (!cfg_.anonym && !reported_ip.empty()) {
            client_wan_ip_ = reported_ip;
        }
        if (manager_) {
            ControlledClientInfo info;
            info.id = client_id_;
            info.hostname = client_hostname_;
            info.wan_ip = client_wan_ip_;
            info.allow_exec = client_allow_exec_;
            info.server_in_charge = client_server_in_charge_;
            manager_->register_controlled_client(shared_from_this(), info);
        }
        return;
    }

    auto send_json = [&](const nlohmann::json& resp) {
        nlohmann::json payload_json = resp;
        if (json.contains("request_id") && !payload_json.contains("request_id")) {
            payload_json["request_id"] = json["request_id"];
        }
        std::string out = payload_json.dump();
        crypto::Bytes bytes(out.begin(), out.end());
        send_control_frame(protocol::CONTROL, frame.header.stream_id, bytes);
    };

    if (cmd == "presence.announce") {
        util::log_info("session " + std::to_string(session_id_) + ": CONTROL cmd=presence.announce");
        if (!manager_) {
            send_json({{"cmd", cmd}, {"ok", false}, {"error", "manager unavailable"}});
            return;
        }
        control::PresenceAnnouncement announce;
        announce.endpoint_kind = control::endpoint_kind_from_string(json.value("endpoint_kind", "client"));
        announce.preferred_id = json.value("preferred_id", "");
        announce.preferred_name = json.value("preferred_name", "");
        announce.hostname = cfg_.anonym ? std::string{} : json.value("hostname", client_hostname_);
        announce.client_platform = json.value("client_platform", "unknown");
        announce.client_variant = json.value("client_variant", "unknown");
        announce.client_version = json.value("client_version", "");
        announce.relay_mode = control::relay_mode_from_string(json.value("relay_mode", "untrusted"));
        announce.allow_chat = json.value("allow_chat", true) && session_allow_chat_policy_;
        announce.allow_file = json.value("allow_file", true) && session_allow_file_policy_;
        announce.allow_bytes = json.value("allow_bytes", true) && session_allow_bytes_policy_;
        announce.allow_inbound_admin = json.value("allow_inbound_admin", false) &&
                                       session_allow_inbound_admin_policy_;
        announce.allow_outbound_admin = json.value("allow_outbound_admin", false) &&
                                        session_allow_outbound_admin_policy_;
        auto result = manager_->register_endpoint(shared_from_this(), announce, client_auth_pubkey_b64_);
        client_id_ = result.endpoint.endpoint_id;
        client_display_name_ = result.endpoint.display_name;
        client_hostname_ = result.endpoint.hostname;
        client_platform_ = result.endpoint.client_platform;
        client_variant_ = result.endpoint.client_variant;
        client_version_ = result.endpoint.client_version;
        client_relay_mode_ = result.endpoint.relay_mode;
        client_allow_chat_ = result.endpoint.allow_chat;
        client_allow_file_ = result.endpoint.allow_file;
        client_allow_bytes_ = result.endpoint.allow_bytes;
        client_allow_inbound_admin_ = result.endpoint.allow_inbound_admin;
        client_allow_outbound_admin_ = result.endpoint.allow_outbound_admin;
        nlohmann::json resp;
        resp["cmd"] = cmd;
        resp["ok"] = true;
        resp["assigned_id"] = result.endpoint.endpoint_id;
        resp["assigned_name"] = result.endpoint.display_name;
        resp["preferred_id_accepted"] = result.preferred_id_accepted;
        resp["preferred_name_accepted"] = result.preferred_name_accepted;
        resp["server_id"] = result.server_id;
        resp["server_name"] = result.server_name;
        resp["endpoint"] = control::endpoint_to_json(result.endpoint, true);
        util::log_info("session " + std::to_string(session_id_) + ": CONTROL presence.announce assigned " +
                       result.endpoint.endpoint_id + " (" + result.endpoint.display_name + ")");
        send_json(resp);
        return;
    }

    if (cmd == "client.lifecycle") {
        util::log_info("session " + std::to_string(session_id_) + ": CONTROL cmd=client.lifecycle state=" +
                       json.value("state", std::string{}));
        nlohmann::json resp;
        resp["cmd"] = cmd;
        if (!manager_) {
            resp["ok"] = false;
            resp["error"] = "manager unavailable";
            send_json(resp);
            return;
        }
        const std::string state = json.value("state", "");
        const std::string message = json.value("message", "");
        if (state.empty() || message.empty()) {
            resp["ok"] = false;
            resp["error"] = "missing state/message";
            send_json(resp);
            return;
        }
        control::ClientLifecycleEvent event;
        event.state = state;
        event.message = message;
        event.detail = json.value("detail", "");
        event.client_platform = json.value("client_platform", client_platform_);
        event.client_variant = json.value("client_variant", client_variant_);
        event.client_version = json.value("client_version", client_version_);
        event.effective_protection = json.value("effective_protection", "");
        event.traffic_verified = json.value("traffic_verified", false);
        event.exit_ip = json.value("exit_ip", "");
        event.error_code = json.value("error_code", "");
        latest_lifecycle_state_ = state;
        control::ClientLifecycleEvent stored_event;
        if (!manager_->update_endpoint_lifecycle(this, event, &stored_event)) {
            resp["ok"] = false;
            resp["error"] = "presence announce required before lifecycle";
            send_json(resp);
            return;
        }
        resp["ok"] = true;
        resp["accepted_state"] = stored_event.state;
        resp["server_time_ms"] = stored_event.server_time_ms;
        send_json(resp);
        return;
    }

    if (cmd == "directory.list" || cmd == "list") {
        nlohmann::json resp;
        resp["cmd"] = cmd;
        resp["ok"] = true;
        resp["server_id"] = manager_ ? manager_->config_snapshot().server_id : "";
        resp["server_name"] = manager_ ? manager_->config_snapshot().server_name : "";
        resp["endpoints"] = nlohmann::json::array();
        if (manager_) {
            auto endpoints = manager_->list_endpoints();
            for (const auto& endpoint : endpoints) {
                resp["endpoints"].push_back(control::endpoint_to_json(endpoint, true));
            }
        } else {
            resp["ok"] = false;
            resp["error"] = "manager unavailable";
        }
        if (cmd == "list") {
            resp["clients"] = nlohmann::json::array();
            if (manager_) {
                auto list = manager_->list_controlled_clients(cfg_.anonym);
                for (const auto& info : list) {
                    nlohmann::json item;
                    item["id"] = info.id;
                    item["hostname"] = info.hostname;
                    item["wan_ip"] = info.wan_ip;
                    item["allow_exec"] = info.allow_exec;
                    item["server_in_charge"] = info.server_in_charge;
                    resp["clients"].push_back(std::move(item));
                }
            }
        }
        send_json(resp);
        return;
    }

    if (cmd == "directory.lookup") {
        nlohmann::json resp;
        resp["cmd"] = cmd;
        const std::string query = json.value("query", "");
        control::EndpointInfo endpoint;
        auto target = manager_ ? manager_->find_endpoint_session(query, &endpoint) : nullptr;
        if (!target) {
            resp["ok"] = false;
            resp["error"] = "endpoint not found";
        } else {
            resp["ok"] = true;
            resp["endpoint"] = control::endpoint_to_json(endpoint, true);
        }
        send_json(resp);
        return;
    }

    if (cmd == "invite.request") {
        nlohmann::json resp;
        resp["cmd"] = cmd;
        control::PendingInvite invite = control::invite_from_json(json);
        invite.from_endpoint_id = client_id_;
        invite.from_display_name = client_display_name_;
        invite.from_auth_pubkey_b64 = client_auth_pubkey_b64_;
        invite.created_ms = epoch_now_ms();
        std::string error;
        if (!manager_ || !manager_->route_invite(shared_from_this(), invite, &error)) {
            resp["ok"] = false;
            resp["error"] = error.empty() ? "invite routing failed" : error;
            send_json(resp);
            return;
        }
        control::EndpointInfo target_info;
        auto target = manager_->find_endpoint_session(invite.to_endpoint_id, &target_info);
        if (!target) {
            resp["ok"] = false;
            resp["error"] = "target unavailable";
            send_json(resp);
            return;
        }
        nlohmann::json notify = control::invite_to_json(invite, false);
        notify["cmd"] = "invite.request";
        std::string out = notify.dump();
        target->send_control_frame(protocol::CONTROL, 0, crypto::Bytes(out.begin(), out.end()));
        resp["ok"] = true;
        resp["queued"] = true;
        send_json(resp);
        return;
    }

    if (cmd == "invite.reply") {
        nlohmann::json resp;
        resp["cmd"] = cmd;
        control::PendingInvite reply = control::invite_from_json(json);
        reply.from_endpoint_id = client_id_;
        std::shared_ptr<Session> initiator;
        control::PendingInvite resolved_invite;
        std::string error;
        if (!manager_ || !manager_->respond_invite(shared_from_this(), reply, &initiator, &resolved_invite, &error)) {
            resp["ok"] = false;
            resp["error"] = error.empty() ? "invite response failed" : error;
            send_json(resp);
            return;
        }
        if (initiator) {
            nlohmann::json notify = control::invite_to_json(resolved_invite, true);
            notify["cmd"] = "invite.reply";
            std::string out = notify.dump();
            initiator->send_control_frame(protocol::CONTROL, 0, crypto::Bytes(out.begin(), out.end()));
        }
        resp["ok"] = true;
        send_json(resp);
        return;
    }

    if (cmd == "admin.attach") {
        nlohmann::json resp;
        resp["cmd"] = cmd;
        const std::string target_id = json.value("id", "");
        control::EndpointInfo target_info;
        auto target = manager_ ? manager_->find_endpoint_session(target_id, &target_info) : nullptr;
        if (!target) {
            resp["ok"] = false;
            resp["error"] = "endpoint not found";
            send_json(resp);
            return;
        }
        if (client_relay_mode_ != control::RelayMode::trusted) {
            resp["ok"] = false;
            resp["error"] = "admin attach requires trusted relay mode";
            send_json(resp);
            return;
        }
        if (!target_info.allow_inbound_admin || !target_info.allow_outbound_admin) {
            resp["ok"] = false;
            resp["error"] = "target does not allow inbound admin";
            send_json(resp);
            return;
        }
        resp["ok"] = true;
        resp["endpoint"] = control::endpoint_to_json(target_info, true);
        send_json(resp);
        return;
    }

    if (cmd == "attach") {
        nlohmann::json resp;
        resp["cmd"] = "attach";
        const std::string id = json.value("id", "");
        if (id.empty()) {
            resp["ok"] = false;
            resp["error"] = "missing id";
            send_json(resp);
            return;
        }
        ControlledClientInfo info;
        std::shared_ptr<Session> target;
        if (manager_) {
            target = manager_->find_controlled_session(id, &info);
        }
        if (!target) {
            resp["ok"] = false;
            resp["error"] = "client not found";
            send_json(resp);
            return;
        }
        if (!info.server_in_charge) {
            resp["ok"] = false;
            resp["error"] = "client did not grant server-in-charge";
            send_json(resp);
            return;
        }
        is_controller_ = true;
        control_target_ = target;
        control_target_id_ = id;
        resp["ok"] = true;
        resp["id"] = info.id;
        resp["hostname"] = info.hostname;
        resp["wan_ip"] = info.wan_ip;
        resp["allow_exec"] = info.allow_exec;
        resp["server_in_charge"] = info.server_in_charge;
        send_json(resp);
        return;
    }

    nlohmann::json resp;
    resp["cmd"] = cmd;
    resp["ok"] = false;
    resp["error"] = "unknown control command";
    send_json(resp);
}

bool Session::handle_control_open_request(const protocol::Frame& frame) {
    if (!is_controller_) {
        return false;
    }
    auto target = control_target_.lock();
    if (!target) {
        send_open_reply(frame.header.stream_id, false, "control target unavailable");
        return true;
    }

    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        if (!decrypt_inner_payload(protocol::OPEN, frame.header.stream_id, frame.payload, &payload)) {
            send_open_reply(frame.header.stream_id, false, "control open decrypt failed");
            return true;
        }
    }

    uint8_t target_stream = target->reserve_stream_id();
    if (target_stream == 0) {
        send_open_reply(frame.header.stream_id, false, "no stream ids available");
        return true;
    }

    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        control_outbound_[frame.header.stream_id] = ControlLink{target, target_stream, true, false};
    }
    {
        std::lock_guard<std::mutex> lock(target->control_mutex_);
        target->control_inbound_[target_stream] = ControlLink{shared_from_this(), frame.header.stream_id, true, false};
    }

    target->send_control_frame(protocol::SOPEN, target_stream, payload);
    return true;
}

bool Session::handle_control_open_ack(const protocol::Frame& frame) {
    ControlLink link;
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        auto it = control_inbound_.find(frame.header.stream_id);
        if (it == control_inbound_.end()) {
            return false;
        }
        link = it->second;
    }

    auto peer = link.peer.lock();
    if (!peer) {
        std::lock_guard<std::mutex> lock(control_mutex_);
        control_inbound_.erase(frame.header.stream_id);
        return true;
    }

    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        if (!decrypt_inner_payload(protocol::OPEN, frame.header.stream_id, frame.payload, &payload)) {
            if (auto peer = link.peer.lock()) {
                peer->send_control_close(link.peer_stream_id, "control open decrypt failed");
            }
            std::lock_guard<std::mutex> lock(control_mutex_);
            control_inbound_.erase(frame.header.stream_id);
            return true;
        }
    }
    const bool ok = (frame.header.flags & protocol::kFlagOpenOk) != 0;
    const std::string reason(payload.begin(), payload.end());

    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        auto it = control_inbound_.find(frame.header.stream_id);
        if (it != control_inbound_.end()) {
            if (!ok) {
                control_inbound_.erase(it);
            } else {
                it->second.pending = false;
            }
        }
    }
    {
        std::lock_guard<std::mutex> lock(peer->control_mutex_);
        auto it = peer->control_outbound_.find(link.peer_stream_id);
        if (it != peer->control_outbound_.end()) {
            if (!ok) {
                peer->control_outbound_.erase(it);
            } else {
                it->second.pending = false;
            }
        }
    }

    if (ok && manager_ && !link.channel_id.empty()) {
        control::ActiveRelayChannel channel;
        channel.channel_id = link.channel_id;
        channel.channel_kind = link.channel_kind;
        channel.left_endpoint_id = link.left_endpoint_id;
        channel.right_endpoint_id = link.right_endpoint_id;
        channel.left_stream_id = link.peer_stream_id;
        channel.right_stream_id = frame.header.stream_id;
        channel.pending = false;
        manager_->register_active_channel(channel);
    }

    peer->send_open_reply(link.peer_stream_id, ok, reason);
    return true;
}

bool Session::handle_control_data(const protocol::Frame& frame) {
    ControlLink link;
    bool found = false;
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        auto it = control_outbound_.find(frame.header.stream_id);
        if (it != control_outbound_.end()) {
            link = it->second;
            found = true;
        } else {
            auto it_in = control_inbound_.find(frame.header.stream_id);
            if (it_in != control_inbound_.end()) {
                link = it_in->second;
                found = true;
            }
        }
    }
    if (!found) {
        return false;
    }

    auto peer = link.peer.lock();
    if (!peer) {
        std::lock_guard<std::mutex> lock(control_mutex_);
        control_outbound_.erase(frame.header.stream_id);
        control_inbound_.erase(frame.header.stream_id);
        return true;
    }

    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        if (!decrypt_inner_payload(protocol::DATA, frame.header.stream_id, frame.payload, &payload)) {
            if (auto peer = link.peer.lock()) {
                peer->send_control_close(link.peer_stream_id, "control data decrypt failed");
            }
            std::lock_guard<std::mutex> lock(control_mutex_);
            control_outbound_.erase(frame.header.stream_id);
            control_inbound_.erase(frame.header.stream_id);
            return true;
        }
    }

    peer->send_control_frame(protocol::DATA, link.peer_stream_id, payload);
    return true;
}

bool Session::handle_control_close(const protocol::Frame& frame) {
    ControlLink link;
    bool found = false;
    bool outbound = false;
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        auto it = control_outbound_.find(frame.header.stream_id);
        if (it != control_outbound_.end()) {
            link = it->second;
            found = true;
            outbound = true;
        } else {
            auto it_in = control_inbound_.find(frame.header.stream_id);
            if (it_in != control_inbound_.end()) {
                link = it_in->second;
                found = true;
            }
        }
    }
    if (!found) {
        return false;
    }

    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        if (!decrypt_inner_payload(protocol::CLOSE, frame.header.stream_id, frame.payload, &payload)) {
            payload.clear();
        }
    }
    const std::string reason(payload.begin(), payload.end());

    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        if (outbound) {
            control_outbound_.erase(frame.header.stream_id);
        } else {
            control_inbound_.erase(frame.header.stream_id);
        }
    }
    if (manager_ && !link.channel_id.empty()) {
        if (link.channel_kind == control::ChannelKind::admin) {
            manager_->remove_admin_relationship(link.left_endpoint_id, link.right_endpoint_id);
        }
        manager_->unregister_active_channel(link.channel_id);
    }
    if (auto peer = link.peer.lock()) {
        peer->send_control_close(link.peer_stream_id, reason);
    }
    return true;
}

bool Session::handle_control_exec(const protocol::Frame& frame) {
    if (!is_controller_) {
        return false;
    }
    auto target = control_target_.lock();
    if (!target) {
        send_control_close(frame.header.stream_id, "control target unavailable");
        return true;
    }
    if (!target->client_allow_exec_) {
        const std::string msg = "EXEC not allowed by client";
        crypto::Bytes payload(msg.begin(), msg.end());
        send_control_frame(protocol::DATA, frame.header.stream_id, payload);
        send_control_close(frame.header.stream_id, "exec denied");
        return true;
    }

    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        if (!decrypt_inner_payload(protocol::EXEC, frame.header.stream_id, frame.payload, &payload)) {
            send_control_close(frame.header.stream_id, "control exec decrypt failed");
            return true;
        }
    }

    uint8_t target_stream = target->reserve_stream_id();
    if (target_stream == 0) {
        send_control_close(frame.header.stream_id, "no stream ids available");
        return true;
    }

    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        control_outbound_[frame.header.stream_id] = ControlLink{target, target_stream, false, true};
    }
    {
        std::lock_guard<std::mutex> lock(target->control_mutex_);
        target->control_inbound_[target_stream] = ControlLink{shared_from_this(), frame.header.stream_id, false, true};
    }

    target->send_control_frame(protocol::EXEC, target_stream, payload);
    return true;
}

void Session::send_control_frame(protocol::FrameType type, uint8_t stream_id, const crypto::Bytes& payload, uint16_t extra_flags) {
    crypto::Bytes out = payload;
    uint16_t flags = extra_flags;
    if (inner_key_.has_value()) {
        out = encrypt_inner_payload(type, stream_id, out);
        flags |= protocol::kFlagInnerEncrypted;
    }
    protocol::Frame frame{{static_cast<uint32_t>(out.size()), type, stream_id, flags}, out};
    async_write_frame(frame);
}

void Session::send_control_close(uint8_t stream_id, const std::string& reason) {
    crypto::Bytes payload(reason.begin(), reason.end());
    send_control_frame(protocol::CLOSE, stream_id, payload);
}

void Session::handle_data(const protocol::Frame& frame) {
    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() && (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        if (!decrypt_inner_payload(frame.header.type, frame.header.stream_id, frame.payload, &payload)) {
            util::log_warn("session " + std::to_string(session_id_) + ": DATA decrypt failed for stream " +
                           std::to_string(frame.header.stream_id));
            close_with_reason("DATA decrypt failed for stream " + std::to_string(frame.header.stream_id));
            return;
        }
    }
    auto it_udp = udp_streams_.find(frame.header.stream_id);
    if (it_udp != udp_streams_.end()) {
        enqueue_udp_write(frame.header.stream_id, payload);
        return;
    }
    enqueue_remote_write(frame.header.stream_id, payload);
}

void Session::handle_close(uint8_t stream_id, const std::string& reason) {
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);

        auto it_listener = reverse_listeners_.find(stream_id);
        if (it_listener != reverse_listeners_.end()) {
            boost::system::error_code ec;
            int listen_port = 0;
            auto it_port = reverse_listener_ports_.find(stream_id);
            if (it_port != reverse_listener_ports_.end()) {
                listen_port = it_port->second;
                reverse_listener_ports_.erase(it_port);
                reverse_port_streams_.erase(listen_port);
            }
            if (manager_ && listen_port > 0) {
                manager_->unregister_reverse_listener(listen_port, this);
            }
            it_listener->second->close(ec);
            reverse_listeners_.erase(it_listener);
            return;
        }

        auto it_udp = udp_streams_.find(stream_id);
        if (it_udp != udp_streams_.end()) {
            util::log_info("session " + std::to_string(session_id_) + ": udp stream " + std::to_string(stream_id) +
                           " closed: " + reason);
            auto udp = it_udp->second;
            if (!udp->close_summary_logged) {
                udp->close_summary_logged = true;
                const int64_t elapsed = udp->open_started_ms > 0 ? (util::now_ms() - udp->open_started_ms) : 0;
                util::log_timing("server.stream",
                                 "summary",
                                 "session=" + std::to_string(session_id_) +
                                     " stream=" + std::to_string(stream_id) +
                                     " proto=udp ms=" + std::to_string(elapsed) +
                                     " upstream=" + std::to_string(udp->upstream_bytes) +
                                     " downstream=" + std::to_string(udp->downstream_bytes) +
                                     " target=" + udp->host + ":" + std::to_string(udp->port) +
                                     " reason=" + reason);
            }
            boost::system::error_code ec;
            udp->resolver.cancel();
            udp->socket.close(ec);
            udp_streams_.erase(it_udp);
            return;
        }

        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }

        util::log_info("session " + std::to_string(session_id_) + ": stream " + std::to_string(stream_id) + " closed: " + reason);
        auto remote = it->second;
        if (!remote->close_summary_logged) {
            remote->close_summary_logged = true;
            const int64_t elapsed = remote->open_started_ms > 0 ? (util::now_ms() - remote->open_started_ms) : 0;
            util::log_timing("server.stream",
                             "summary",
                             "session=" + std::to_string(session_id_) +
                                 " stream=" + std::to_string(stream_id) +
                                 " proto=tcp ms=" + std::to_string(elapsed) +
                                 " upstream=" + std::to_string(remote->upstream_bytes) +
                                 " downstream=" + std::to_string(remote->downstream_bytes) +
                                 " target=" + remote->host + ":" + std::to_string(remote->port) +
                                 " reason=" + reason);
        }
        boost::system::error_code ec;
        remote->resolver.cancel();
        remote->socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        remote->socket.close(ec);
        streams_.erase(it);
    }
}

void Session::handle_exec(const protocol::Frame& frame) {
    const std::string msg = "EXEC disabled for safety";
    crypto::Bytes payload(msg.begin(), msg.end());
    uint16_t flags = 0;
            if (inner_key_.has_value()) {
                payload = encrypt_inner_payload(protocol::DATA, frame.header.stream_id, payload);
                flags |= protocol::kFlagInnerEncrypted;
            }
    protocol::Frame resp{{static_cast<uint32_t>(payload.size()), protocol::DATA, frame.header.stream_id, flags}, payload};
    async_write_frame(resp);
    send_control_close(frame.header.stream_id, "");
}

void Session::send_open_reply(uint8_t stream_id, bool ok, const std::string& message) {
    crypto::Bytes payload(message.begin(), message.end());
    uint16_t flags = ok ? protocol::kFlagOpenOk : 0;
    if (inner_key_.has_value()) {
        payload = encrypt_inner_payload(protocol::OPEN, stream_id, payload);
        flags |= protocol::kFlagInnerEncrypted;
    }
    protocol::Frame resp{{static_cast<uint32_t>(payload.size()), protocol::OPEN, stream_id, flags}, payload};
    async_write_frame(resp);
}

void Session::start_remote_read(uint8_t stream_id) {
    std::shared_ptr<RemoteStream> remote;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }
        remote = it->second;
        if (close_state_ != CloseState::Open) {
            remote->read_paused = true;
            return;
        }
        if (remote->read_in_flight) {
            return;
        }
        if (should_pause_inbound_reads_on_strand()) {
            remote->read_paused = true;
            return;
        }
        remote->read_paused = false;
        remote->read_in_flight = true;
    }

    auto self = shared_from_this();
    remote->socket.async_read_some(boost::asio::buffer(remote->read_buf),
                                   boost::asio::bind_executor(strand_,
                                                              [self, stream_id](const boost::system::error_code& ec, std::size_t bytes) {
                                                                  self->on_remote_read(stream_id, ec, bytes);
                                                              }));
}

void Session::on_remote_read(uint8_t stream_id, const boost::system::error_code& ec, std::size_t bytes) {
    std::shared_ptr<RemoteStream> remote;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }
        remote = it->second;
        remote->read_in_flight = false;
    }

    if (ec) {
        handle_close(stream_id, "remote closed");
        send_control_close(stream_id, "");
        return;
    }
    remote->downstream_bytes += static_cast<std::uint64_t>(bytes);
    if (remote->first_downstream_ms == 0) {
        remote->first_downstream_ms = util::now_ms();
        util::log_timing("server.stream",
                         "first_downstream",
                         "session=" + std::to_string(session_id_) +
                             " stream=" + std::to_string(stream_id) +
                             " proto=tcp ms=" +
                             std::to_string(remote->first_downstream_ms - remote->open_started_ms) +
                             " bytes=" + std::to_string(bytes));
    }

    crypto::Bytes payload(remote->read_buf.data(), remote->read_buf.data() + bytes);
    uint16_t flags = 0;
    if (inner_key_.has_value()) {
        payload = encrypt_inner_payload(protocol::DATA, stream_id, payload);
        flags |= protocol::kFlagInnerEncrypted;
    }

    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::DATA, stream_id, flags}, std::move(payload)};
    queue_frame_on_strand(frame);
    start_remote_read(stream_id);
}

void Session::start_udp_read(uint8_t stream_id) {
    std::shared_ptr<UdpStream> udp;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = udp_streams_.find(stream_id);
        if (it == udp_streams_.end()) {
            return;
        }
        udp = it->second;
        if (close_state_ != CloseState::Open) {
            udp->read_paused = true;
            return;
        }
        if (udp->read_in_flight) {
            return;
        }
        if (should_pause_inbound_reads_on_strand()) {
            udp->read_paused = true;
            return;
        }
        udp->read_paused = false;
        udp->read_in_flight = true;
    }

    auto self = shared_from_this();
    udp->socket.async_receive(boost::asio::buffer(udp->read_buf),
                              boost::asio::bind_executor(strand_,
                                                         [self, stream_id](const boost::system::error_code& ec, std::size_t bytes) {
                                                             self->on_udp_read(stream_id, ec, bytes);
                                                         }));
}

void Session::on_udp_read(uint8_t stream_id, const boost::system::error_code& ec, std::size_t bytes) {
    std::shared_ptr<UdpStream> udp;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = udp_streams_.find(stream_id);
        if (it == udp_streams_.end()) {
            return;
        }
        udp = it->second;
        udp->read_in_flight = false;
    }

    if (ec) {
        handle_close(stream_id, "udp remote closed");
        send_control_close(stream_id, "");
        return;
    }
    udp->downstream_bytes += static_cast<std::uint64_t>(bytes);
    if (udp->first_downstream_ms == 0) {
        udp->first_downstream_ms = util::now_ms();
        util::log_timing("server.stream",
                         "first_downstream",
                         "session=" + std::to_string(session_id_) +
                             " stream=" + std::to_string(stream_id) +
                             " proto=udp ms=" +
                             std::to_string(udp->first_downstream_ms - udp->open_started_ms) +
                             " bytes=" + std::to_string(bytes));
    }

    crypto::Bytes payload(udp->read_buf.data(), udp->read_buf.data() + bytes);
    uint16_t flags = 0;
    if (inner_key_.has_value()) {
        payload = encrypt_inner_payload(protocol::DATA, stream_id, payload);
        flags |= protocol::kFlagInnerEncrypted;
    }

    protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::DATA, stream_id, flags}, std::move(payload)};
    queue_frame_on_strand(frame);
    start_udp_read(stream_id);
}

void Session::enqueue_udp_write(uint8_t stream_id, const crypto::Bytes& data) {
    std::shared_ptr<UdpStream> udp;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = udp_streams_.find(stream_id);
        if (it == udp_streams_.end()) {
            return;
        }
        udp = it->second;
    }
    udp->upstream_bytes += static_cast<std::uint64_t>(data.size());
    if (udp->first_upstream_ms == 0) {
        udp->first_upstream_ms = util::now_ms();
        util::log_timing("server.stream",
                         "first_upstream",
                         "session=" + std::to_string(session_id_) +
                             " stream=" + std::to_string(stream_id) +
                             " proto=udp ms=" +
                             std::to_string(udp->first_upstream_ms - udp->open_started_ms) +
                             " bytes=" + std::to_string(data.size()));
    }
    udp->write_queue.push_back(data);
    if (!udp->write_in_flight) {
        do_udp_write(stream_id);
    }
}

void Session::do_udp_write(uint8_t stream_id) {
    std::shared_ptr<UdpStream> udp;
    crypto::Bytes data_to_write;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = udp_streams_.find(stream_id);
        if (it == udp_streams_.end()) {
            return;
        }
        udp = it->second;
        if (udp->write_queue.empty()) {
            udp->write_in_flight = false;
            return;
        }
        udp->write_in_flight = true;
        data_to_write = std::move(udp->write_queue.front());
        udp->write_queue.pop_front();
    }
    auto buffer = std::make_shared<crypto::Bytes>(std::move(data_to_write));
    auto self = shared_from_this();
    udp->socket.async_send(
        boost::asio::buffer(*buffer),
        boost::asio::bind_executor(
            strand_,
            [self, buffer, stream_id](const boost::system::error_code& ec, std::size_t) {
                if (ec) {
                    self->handle_close(stream_id, "udp send failed");
                    self->send_control_close(stream_id, "");
                    return;
                }
                self->do_udp_write(stream_id);
            }));
}

void Session::enqueue_remote_write(uint8_t stream_id, const std::vector<uint8_t>& data) {
    std::shared_ptr<RemoteStream> remote;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }
        remote = it->second;
    }
    remote->upstream_bytes += static_cast<std::uint64_t>(data.size());
    if (remote->first_upstream_ms == 0) {
        remote->first_upstream_ms = util::now_ms();
        util::log_timing("server.stream",
                         "first_upstream",
                         "session=" + std::to_string(session_id_) +
                             " stream=" + std::to_string(stream_id) +
                             " proto=tcp ms=" +
                             std::to_string(remote->first_upstream_ms - remote->open_started_ms) +
                             " bytes=" + std::to_string(data.size()));
    }
    remote->write_queue.push_back(data);
    if (!remote->write_in_flight) {
        do_remote_write(stream_id);
    }
}

void Session::do_remote_write(uint8_t stream_id) {
    std::shared_ptr<RemoteStream> remote;
    std::vector<uint8_t> data_to_write;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = streams_.find(stream_id);
        if (it == streams_.end()) {
            return;
        }
        remote = it->second;
        if (!remote->connected) {
            remote->write_in_flight = false;
            return;
        }
        if (remote->write_queue.empty()) {
            remote->write_in_flight = false;
            return;
        }
        remote->write_in_flight = true;
        data_to_write = std::move(remote->write_queue.front());
        remote->write_queue.pop_front();
    }

    auto buffer = std::make_shared<std::vector<uint8_t>>(std::move(data_to_write));
    auto self = shared_from_this();
    boost::asio::async_write(remote->socket, boost::asio::buffer(*buffer),
                             boost::asio::bind_executor(strand_,
                                                        [self, buffer, stream_id](const boost::system::error_code& ec, std::size_t) {
                                                            if (ec) {
                                                                self->handle_close(stream_id, "remote write failed");
                                                                self->send_control_close(stream_id, "");
                                                                return;
                                                            }
                                                            self->do_remote_write(stream_id);
                                                        }));
}

void Session::async_write_frame(const protocol::Frame& frame,
                                std::function<void(const boost::system::error_code&, std::size_t)> handler) {
    auto data = std::make_shared<std::vector<uint8_t>>(protocol::encode_frame(
        static_cast<protocol::FrameType>(frame.header.type),
        frame.header.stream_id,
        frame.header.flags,
        frame.payload));

    boost::asio::post(strand_, [self = shared_from_this(), data, handler = std::move(handler)]() mutable {
        self->queue_encoded_write_on_strand(data, std::move(handler));
    });
}

void Session::queue_frame_on_strand(const protocol::Frame& frame,
                                    std::function<void(const boost::system::error_code&, std::size_t)> handler) {
    auto data = std::make_shared<std::vector<uint8_t>>(protocol::encode_frame(
        static_cast<protocol::FrameType>(frame.header.type),
        frame.header.stream_id,
        frame.header.flags,
        frame.payload));
    queue_encoded_write_on_strand(std::move(data), std::move(handler));
}

void Session::queue_encoded_write_on_strand(
    std::shared_ptr<std::vector<uint8_t>> data,
    std::function<void(const boost::system::error_code&, std::size_t)> handler) {
    if (close_state_ != CloseState::Open) {
        if (handler) {
            handler(boost::asio::error::operation_aborted, 0);
        }
        return;
    }

    if (write_queue_depth_ >= kMaxWriteQueueSize) {
        util::log_warn("session " + std::to_string(session_id_) +
                      ": write queue overflow (" + std::to_string(write_queue_depth_) +
                      " pending), closing to prevent SSL corruption");
        close_with_reason("write queue overrun - too many pending frames");
        if (handler) {
            handler(boost::asio::error::operation_aborted, 0);
        }
        return;
    }

    write_queue_.push_back({std::move(data), std::move(handler)});
    write_queue_depth_++;
    if (!write_in_flight_) {
        do_write();
    }
}

bool Session::should_pause_inbound_reads_on_strand() const {
    return close_state_ != CloseState::Open || write_queue_depth_ >= kWriteQueueHighWatermark;
}

void Session::maybe_resume_inbound_reads_on_strand() {
    if (close_state_ != CloseState::Open || write_queue_depth_ > kWriteQueueLowWatermark) {
        return;
    }

    std::vector<uint8_t> tcp_to_resume;
    std::vector<uint8_t> udp_to_resume;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        uint32_t budget = 0;
        if (write_queue_depth_ < kWriteQueueHighWatermark) {
            budget = kWriteQueueHighWatermark - write_queue_depth_;
        }
        if (budget == 0) {
            return;
        }

        for (const auto& [stream_id, remote] : streams_) {
            if (budget == 0) {
                break;
            }
            if (remote->read_paused && !remote->read_in_flight) {
                remote->read_paused = false;
                tcp_to_resume.push_back(stream_id);
                --budget;
            }
        }
        for (const auto& [stream_id, udp] : udp_streams_) {
            if (budget == 0) {
                break;
            }
            if (udp->read_paused && !udp->read_in_flight) {
                udp->read_paused = false;
                udp_to_resume.push_back(stream_id);
                --budget;
            }
        }
    }

    for (uint8_t stream_id : tcp_to_resume) {
        start_remote_read(stream_id);
    }
    for (uint8_t stream_id : udp_to_resume) {
        start_udp_read(stream_id);
    }
}

void Session::do_write() {
    if (write_queue_.empty()) {
        write_in_flight_ = false;
        if (close_state_ != CloseState::Open) {
            maybe_finish_close();
        }
        return;
    }
    write_in_flight_ = true;

    std::size_t batch_count = 0;
    std::size_t total_bytes = 0;
    for (auto it = write_queue_.begin();
         it != write_queue_.end() &&
         batch_count < kMaxWriteBatchFrames &&
         total_bytes < kMaxWriteBatchBytes;
         ++it) {
        total_bytes += it->data ? it->data->size() : 0;
        ++batch_count;
    }
    if (batch_count == 0) {
        write_in_flight_ = false;
        return;
    }

    std::shared_ptr<std::vector<uint8_t>> batch_data;
    if (batch_count == 1) {
        batch_data = write_queue_.front().data;
    } else {
        batch_data = std::make_shared<std::vector<uint8_t>>();
        batch_data->reserve(total_bytes);
        std::size_t copied = 0;
        for (auto it = write_queue_.begin(); it != write_queue_.end() && copied < batch_count; ++it, ++copied) {
            if (it->data && !it->data->empty()) {
                batch_data->insert(batch_data->end(), it->data->begin(), it->data->end());
            }
        }
    }

    auto self = shared_from_this();
    boost::asio::async_write(stream_, boost::asio::buffer(*batch_data),
                             boost::asio::bind_executor(strand_,
                                                        [self, batch_data, batch_count](const boost::system::error_code& ec,
                                                               std::size_t bytes) {
                                                            std::vector<PendingWrite> completed;
                                                            completed.reserve(batch_count);
                                                            std::size_t popped = 0;
                                                            while (popped < batch_count && !self->write_queue_.empty()) {
                                                                completed.push_back(std::move(self->write_queue_.front()));
                                                                self->write_queue_.pop_front();
                                                                ++popped;
                                                            }
                                                            if (self->write_queue_depth_ >= popped) {
                                                                self->write_queue_depth_ -= static_cast<uint32_t>(popped);
                                                            } else {
                                                                self->write_queue_depth_ = 0;
                                                            }
                                                            if (!ec) {
                                                                self->maybe_resume_inbound_reads_on_strand();
                                                            }
                                                            for (auto& item : completed) {
                                                                if (item.handler) {
                                                                    const std::size_t item_bytes = (!ec && item.data) ? item.data->size() : bytes;
                                                                    item.handler(ec, item_bytes);
                                                                }
                                                            }
                                                            if (ec) {
                                                                if (self->close_state_ != CloseState::Open && is_expected_close_ec(ec)) {
                                                                    self->shutdown_transport();
                                                                    return;
                                                                }
                                                                std::string error_msg = "frame write failed: " + describe_error_code(ec);
                                                                if (ec.category().name() == std::string("ssl") ||
                                                                    ec == boost::asio::ssl::error::stream_truncated) {
                                                                    error_msg = "SSL/TLS write error: " + error_msg + " [client must reconnect]";
                                                                }
                                                                self->close_with_reason(error_msg);
                                                                return;
                                                            }
                                                            self->do_write();
                                                        }));
}

void Session::touch_activity() {
    last_activity_ms_.store(steady_now_ms(), std::memory_order_relaxed);
}

bool Session::is_stale() const {
    const int64_t last = last_activity_ms_.load(std::memory_order_relaxed);
    return last > 0 && (steady_now_ms() - last) > kIdleTimeoutMs;
}

void Session::force_close_reverse_port(int port) {
    boost::asio::post(strand_, [self = shared_from_this(), port]() {
        auto it = self->reverse_port_streams_.find(port);
        if (it == self->reverse_port_streams_.end()) {
            return;
        }
        self->handle_close(it->second, "listener reclaimed");
    });
}

void Session::schedule_idle_check() {
    idle_timer_.expires_after(std::chrono::milliseconds(kIdleCheckIntervalMs));
    auto self = shared_from_this();
    idle_timer_.async_wait(boost::asio::bind_executor(
        strand_,
        [self](const boost::system::error_code& ec) {
            if (ec) {
                return;
            }
            if (self->is_stale()) {
                util::log_warn("session " + std::to_string(self->session_id_) + ": idle timeout");
                self->close_with_reason("idle timeout");
                return;
            }
            self->schedule_idle_check();
        }));
}

void Session::close_with_reason(const std::string& reason) {
    if (!reason.empty() && close_reason_.empty()) {
        close_reason_ = reason;
    }
    if (close_state_ == CloseState::Open) {
        begin_close();
        return;
    }
    maybe_finish_close();
}

void Session::begin_close() {
    if (close_state_ != CloseState::Open) {
        maybe_finish_close();
        return;
    }
    close_state_ = CloseState::Closing;
    if (close_reason_.empty()) {
        close_reason_ = "session closed";
    }
    const bool suppress_log =
        is_expected_close_reason(close_reason_) ||
        (!authenticated_ && is_background_probe_close_reason(close_reason_));
    if (!suppress_log) {
        const std::string closing_message =
            "session " + std::to_string(session_id_) +
            (authenticated_ ? " [auth]" : " [pre-auth]") +
            " closing: " + close_reason_;
        if (util::is_logging_enabled()) {
            util::log_warn(closing_message);
        } else if (is_server_fault_close_reason(close_reason_)) {
            std::cerr << "[critical] server session issue: " << close_reason_ << std::endl;
        }
    }
    boost::system::error_code ec;
    idle_timer_.cancel();
    preface_timer_.cancel();
    if (manager_) {
        manager_->unregister_session(this);
        for (const auto& entry : reverse_listener_ports_) {
            manager_->unregister_reverse_listener(entry.second, this);
        }
        manager_->unregister_controlled_client(this);
        manager_->unregister_endpoint(this);
    }
    reverse_listener_ports_.clear();
    reverse_port_streams_.clear();

    std::vector<std::pair<std::shared_ptr<Session>, uint8_t>> control_peers;
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        for (const auto& entry : control_outbound_) {
            if (auto peer = entry.second.peer.lock()) {
                control_peers.emplace_back(peer, entry.second.peer_stream_id);
            }
        }
        for (const auto& entry : control_inbound_) {
            if (auto peer = entry.second.peer.lock()) {
                control_peers.emplace_back(peer, entry.second.peer_stream_id);
            }
        }
        control_outbound_.clear();
        control_inbound_.clear();
    }
    for (const auto& entry : control_peers) {
        entry.first->send_control_close(entry.second, "control peer closed");
    }

    for (auto& entry : streams_) {
        entry.second->socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        entry.second->socket.close(ec);
    }
    for (auto& entry : udp_streams_) {
        entry.second->socket.close(ec);
    }
    streams_.clear();
    for (auto& entry : reverse_listeners_) {
        entry.second->close(ec);
    }
    reverse_listeners_.clear();

    maybe_finish_close();
}

void Session::maybe_finish_close() {
    if (close_state_ != CloseState::Closing || transport_shutdown_in_flight_) {
        return;
    }
    if (write_in_flight_ || !write_queue_.empty()) {
        return;
    }
    shutdown_transport();
}

void Session::shutdown_transport() {
    if (transport_shutdown_in_flight_ || close_state_ == CloseState::Closed) {
        return;
    }
    transport_shutdown_in_flight_ = true;
    auto self = shared_from_this();
    stream_.async_shutdown(boost::asio::bind_executor(
        strand_,
        [self](const boost::system::error_code&) {
            boost::system::error_code ec;
            self->closed_ = true;
            self->close_state_ = CloseState::Closed;
            self->stream_.lowest_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            self->stream_.lowest_layer().close(ec);
        }));
}

void Session::close() {
    close_with_reason("");
}

}  // namespace yume::server
