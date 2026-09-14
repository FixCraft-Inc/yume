/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/stealth/tls_stealth.hpp"

#include "core/stealth/tls_client_profile.hpp"
#include "core/stealth/cover_profile.hpp"
#include "core/stealth/http_profile.hpp"
#include "core/stealth/tls_verify_fetch.hpp"
#include "util.hpp"

#include <boost/asio/read.hpp>
#include <boost/asio/write.hpp>
#include <boost/asio/connect.hpp>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <atomic>

#if !defined(_WIN32)
#include <sys/socket.h>
#include <sys/time.h>
#endif

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>

#include <nlohmann/json.hpp>

namespace yume::tls_stealth {

namespace {

tls_fingerprint::FingerprintData parse_tls_verify_response(const std::string& body) {
    const auto json = nlohmann::json::parse(body);
    tls_fingerprint::FingerprintData fingerprint;

    if (json.contains("tls") && json["tls"].is_object()) {
        const auto& tls = json["tls"];
        fingerprint.ja3_hash = tls.value("ja3_hash", "");
        fingerprint.ja4_hash = tls.value("ja4", tls.value("ja4_hash", ""));
        if (tls.contains("extensions") && tls["extensions"].is_array()) {
            for (const auto& ext : tls["extensions"]) {
                if (!ext.is_object()) {
                    continue;
                }
                const std::string name = ext.value("name", "");
                if (name.find("application_layer_protocol_negotiation") == std::string::npos) {
                    continue;
                }
                if (!ext.contains("protocols") || !ext["protocols"].is_array()) {
                    continue;
                }
                for (const auto& proto : ext["protocols"]) {
                    if (proto.is_string()) {
                        fingerprint.alpn_protocols.push_back(proto.get<std::string>());
                    }
                }
            }
        }
    }
    if (json.contains("http2") && json["http2"].is_object()) {
        fingerprint.akamai_hash = json["http2"].value("akamai_fingerprint_hash", "");
    }

    auto [profile, score] = tls_fingerprint::match_browser_profile(fingerprint);
    fingerprint.matched_profile = profile;
    fingerprint.similarity_score = score;
    fingerprint.matches_known_browser =
        (profile != tls_fingerprint::BrowserProfile::UNKNOWN) && (score >= 80.0);
    return fingerprint;
}

std::string current_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::tm tm;
#if defined(_WIN32)
    localtime_s(&tm, &time_t);
#else
    localtime_r(&time_t, &tm);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

}  // namespace

StealthContext::StealthContext(const StealthConfig& config)
    : config_(config)
    , ssl_context_(boost::asio::ssl::context::tlsv13_client)
    , current_profile_(config.target_profile) {
    ssl_context_.set_options(boost::asio::ssl::context::default_workarounds);

    if (config_.enabled) {
        apply_stealth_profile(current_profile_);
    }
}

StealthContext::~StealthContext() = default;

boost::asio::ssl::context& StealthContext::get_context() {
    return ssl_context_;
}

void StealthContext::apply_stealth_profile(tls_fingerprint::BrowserProfile profile) {
    current_profile_ = profile;
    for (const auto& warning : configure_client_profile(
             ssl_context_.native_handle(), profile,
             config_.native_chrome_client_hello)) {
        util::log_warn(warning);
    }
}

using verify_fetch::fetch_http11_json;
using verify_fetch::fetch_http2_json;
using verify_fetch::parse_verification_endpoint;
using verify_fetch::VerificationEndpoint;
using verify_fetch::VerifyFetchLimits;

// Ceiling for one diagnostic exchange. Long enough that a slow endpoint on a
// distant network still answers, short enough that a redirected one cannot
// hold the client indefinitely.
constexpr std::chrono::seconds kVerifyFetchTimeout{30};

// The fetch checks its deadline between reads, which bounds an endpoint that
// keeps sending. An endpoint that completes the handshake and then goes silent
// blocks inside one synchronous read instead, so the socket needs its own
// receive timeout. Asio exposes no portable option for it; POSIX is the only
// platform this diagnostic builds for today, and a failure here is not fatal
// because the deadline still bounds every other shape of stall.
void set_verify_socket_timeout(int fd, std::chrono::seconds timeout) {
#if defined(_WIN32)
    (void)fd;
    (void)timeout;
#else
    if (fd < 0) {
        return;
    }
    timeval tv{};
    tv.tv_sec = static_cast<decltype(tv.tv_sec)>(timeout.count());
    tv.tv_usec = 0;
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

FingerprintTestResult evaluate_tls_fingerprint(
    const std::string& test_endpoint,
    uint16_t port,
    tls_fingerprint::BrowserProfile target_profile) {
    FingerprintTestResult result;
    try {
        const VerificationEndpoint endpoint = parse_verification_endpoint(test_endpoint, port);
        boost::asio::io_context io_context;
        StealthConfig config;
        config.enabled = true;
        config.target_profile = target_profile;

        StealthContext stealth_ctx(config);
        boost::asio::ip::tcp::resolver resolver(io_context);
        auto endpoints = resolver.resolve(endpoint.host, std::to_string(endpoint.port));
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream(
            io_context, stealth_ctx.get_context());
        SSL_set_tlsext_host_name(stream.native_handle(), endpoint.host.c_str());
        boost::asio::connect(stream.lowest_layer(), endpoints);
        set_verify_socket_timeout(stream.lowest_layer().native_handle(),
                                  kVerifyFetchTimeout);
        stream.handshake(boost::asio::ssl::stream_base::client);

        const unsigned char* alpn_data = nullptr;
        unsigned int alpn_len = 0;
        SSL_get0_alpn_selected(stream.native_handle(), &alpn_data, &alpn_len);
        const std::string negotiated_alpn(
            reinterpret_cast<const char*>(alpn_data),
            static_cast<size_t>(alpn_len));

        VerifyFetchLimits limits;
        limits.deadline = std::chrono::steady_clock::now() + kVerifyFetchTimeout;
        const std::string body = negotiated_alpn == "h2"
            ? fetch_http2_json(stream, endpoint, limits)
            : fetch_http11_json(stream, endpoint, limits);

        result.detected_fingerprint = parse_tls_verify_response(body);
        result.ja3_from_server = result.detected_fingerprint.ja3_hash;
        result.ja4_from_server = result.detected_fingerprint.ja4_hash;

        auto profile_info = tls_fingerprint::get_browser_profile_info(target_profile);
        if (profile_info) {
            result.matches_target_profile =
                result.detected_fingerprint.ja3_hash == profile_info->ja3_hash
                && result.detected_fingerprint.ja4_hash == profile_info->ja4_hash;
        }
        result.success = !result.detected_fingerprint.ja3_hash.empty()
            || !result.detected_fingerprint.ja4_hash.empty();
        if (!result.success) {
            throw std::runtime_error("TLS fingerprint test endpoint returned no JA3/JA4 hashes");
        }

        boost::system::error_code ec;
        stream.lowest_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
        stream.lowest_layer().close(ec);
    } catch (const std::exception& e) {
        result.success = false;
        result.error_message = e.what();
    }
    
    return result;
}

StealthManager& StealthManager::instance() {
    static StealthManager instance;
    return instance;
}

void StealthManager::initialize(const StealthConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
    context_ = std::make_unique<StealthContext>(config);

    if (!config.log_file_path.empty()) {
        logger_ = std::make_unique<MetricsLogger>(config.log_file_path);
    }
}

StealthContext& StealthManager::get_context() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!context_) {
        StealthConfig default_config;
        default_config.enabled = true;
        context_ = std::make_unique<StealthContext>(default_config);
    }
    return *context_;
}

boost::asio::ssl::context generate_stealth_tls_config(
    tls_fingerprint::BrowserProfile profile,
    bool verbose) {
    StealthConfig config;
    config.enabled = true;
    config.target_profile = profile;

    StealthContext stealth_ctx(config);

    if (verbose) {
        std::cout << "Generated stealth TLS configuration for: "
                  << tls_fingerprint::browser_profile_name(profile) << "\n";
    }

    return std::move(stealth_ctx.get_context());
}

std::optional<SelfFingerprint> compute_self_fingerprint(
    tls_fingerprint::BrowserProfile profile) {
    // Build a stealth client context for the profile.
    StealthConfig config;
    config.enabled = true;
    config.target_profile = profile;
    StealthContext stealth_ctx(config);

    SSL* ssl = SSL_new(stealth_ctx.get_context().native_handle());
    if (!ssl) return std::nullopt;

    // BIO mem pair: SSL writes into write_bio (we own the other end).
    BIO* read_bio  = BIO_new(BIO_s_mem());
    BIO* write_bio = BIO_new(BIO_s_mem());
    if (!read_bio || !write_bio) {
        if (read_bio) BIO_free(read_bio);
        if (write_bio) BIO_free(write_bio);
        SSL_free(ssl);
        return std::nullopt;
    }
    SSL_set_bio(ssl, read_bio, write_bio);  // SSL takes ownership
    SSL_set_connect_state(ssl);
    SSL_set_tlsext_host_name(ssl, "example.com");

    // Drive the handshake once. It will fail (no server to read from)
    // but the ClientHello has already been written to write_bio.
    SSL_do_handshake(ssl);

    BUF_MEM* bptr = nullptr;
    BIO_get_mem_ptr(write_bio, &bptr);
    if (!bptr || bptr->length == 0) {
        SSL_free(ssl);
        return std::nullopt;
    }

    // Parse the ClientHello. The record-layer prefix (1 byte type +
    // 2 bytes version + 2 bytes length = 5 bytes) sits in front of
    // the handshake message; parse_client_hello expects the
    // ClientHello including the handshake-message wrapper.
    const std::uint8_t* data = reinterpret_cast<const std::uint8_t*>(bptr->data);
    std::size_t length = static_cast<std::size_t>(bptr->length);
    if (length < 6 || data[0] != 0x16) {  // TLS record content_type = handshake
        SSL_free(ssl);
        return std::nullopt;
    }
    // Skip the 5-byte record header; the next byte is the handshake
    // type (0x01 = ClientHello) which parse_client_hello expects.
    auto fp = tls_fingerprint::parse_client_hello(data + 5, length - 5);
    SSL_free(ssl);

    SelfFingerprint out;
    out.ja3_hash    = fp.ja3_hash;
    out.fingerprint = std::move(fp);
    return out;
}

StealthConnectionResult connect_with_stealth_mode(
    boost::asio::io_context& io_context,
    const std::string& server_host,
    uint16_t port,
    tls_fingerprint::BrowserProfile profile,
    const StealthConfig& config) {
    StealthConnectionResult result;
    result.metrics.server_host = server_host;
    result.metrics.server_port = port;
    result.metrics.used_profile = profile;
    result.metrics.timestamp = current_timestamp();

    auto start_time = std::chrono::steady_clock::now();

    try {
        StealthContext stealth_ctx(config);
        boost::asio::ip::tcp::resolver resolver(io_context);
        auto endpoints = resolver.resolve(server_host, std::to_string(port));
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream(
            io_context, stealth_ctx.get_context());
        SSL_set_tlsext_host_name(stream.native_handle(), server_host.c_str());
        boost::asio::connect(stream.lowest_layer(), endpoints);
        stream.handshake(boost::asio::ssl::stream_base::client);

        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time);

        result.success = true;
        result.metrics.handshake_succeeded = true;
        result.metrics.handshake_duration_ms = static_cast<uint32_t>(duration.count());

        boost::system::error_code ec;
        stream.lowest_layer().close(ec);
    } catch (const std::exception& e) {
        result.success = false;
        result.error_message = e.what();
        result.metrics.handshake_succeeded = false;
        result.metrics.error_message = e.what();
    }

    return result;
}

void StealthContext::log_connection_metrics(const ConnectionMetrics& metrics) {
    if (!config_.log_fingerprints || config_.log_file_path.empty()) {
        return;
    }
    
    // Log to file in JSON format
    nlohmann::json j;
    j["connection_id"] = metrics.connection_id;
    j["timestamp"] = metrics.timestamp;
    j["server_host"] = metrics.server_host;
    j["server_port"] = metrics.server_port;
    j["profile"] = tls_fingerprint::browser_profile_name(metrics.used_profile);
    j["ja3_hash"] = metrics.fingerprint.ja3_hash;
    j["ja4_hash"] = metrics.fingerprint.ja4_hash;
    j["handshake_succeeded"] = metrics.handshake_succeeded;
    j["handshake_duration_ms"] = metrics.handshake_duration_ms;
    if (!metrics.error_message.empty()) {
        j["error"] = metrics.error_message;
    }

    std::ofstream log_file(config_.log_file_path, std::ios::app);
    if (log_file) {
        log_file << j.dump() << "\n";
    }

}

MetricsLogger::MetricsLogger(const std::string& log_file_path)
    : log_file_path_(log_file_path) {
    
    if (!log_file_path_.empty()) {
        log_stream_ = std::make_unique<std::ofstream>(
            log_file_path_, std::ios::app);
    }
}

MetricsLogger::~MetricsLogger() {
    flush();
}

void MetricsLogger::log_metrics(const ConnectionMetrics& metrics) {
    if (!log_stream_ || !log_stream_->is_open()) {
        return;
    }
    
    nlohmann::json j;
    j["connection_id"] = metrics.connection_id;
    j["timestamp"] = metrics.timestamp;
    j["server_host"] = metrics.server_host;
    j["server_port"] = metrics.server_port;
    j["profile"] = tls_fingerprint::browser_profile_name(metrics.used_profile);
    j["ja3_hash"] = metrics.fingerprint.ja3_hash;
    j["ja4_hash"] = metrics.fingerprint.ja4_hash;
    j["handshake_succeeded"] = metrics.handshake_succeeded;
    j["handshake_duration_ms"] = metrics.handshake_duration_ms;
    
    if (!metrics.error_message.empty()) {
        j["error"] = metrics.error_message;
    }
    
    *log_stream_ << j.dump() << "\n";
}

void MetricsLogger::flush() {
    if (log_stream_) {
        log_stream_->flush();
    }
}

void StealthManager::log_connection(const ConnectionMetrics& metrics) {
    std::lock_guard<std::mutex> lock(mutex_);

    stats_.total_connections++;
    if (metrics.handshake_succeeded) {
        stats_.successful_connections++;
    } else {
        stats_.failed_connections++;
    }

    stats_.profile_usage[metrics.used_profile]++;

    double total_duration = stats_.average_handshake_duration_ms *
                            (stats_.total_connections - 1);
    total_duration += metrics.handshake_duration_ms;
    stats_.average_handshake_duration_ms = total_duration / stats_.total_connections;

    if (logger_) {
        logger_->log_metrics(metrics);
    }
}

StealthManager::Statistics StealthManager::get_statistics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

}  // namespace yume::tls_stealth
