/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include "core/stealth/tls_fingerprint.hpp"

#include <boost/asio/ssl.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <openssl/ssl.h>

#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace yume::tls_stealth {

struct StealthConfig {
    bool enabled{false};
    tls_fingerprint::BrowserProfile target_profile{tls_fingerprint::BrowserProfile::CHROME_131};
    bool rotate_profiles{false};
    uint32_t rotation_interval_connections{100};
    bool log_fingerprints{true};
    std::string log_file_path;
    bool verify_with_external_api{false};
    std::string test_endpoint{"tls.peet.ws"};
};

struct ConnectionMetrics {
    uint64_t connection_id{0};
    std::string timestamp;
    std::string server_host;
    uint16_t server_port{443};
    tls_fingerprint::BrowserProfile used_profile{tls_fingerprint::BrowserProfile::UNKNOWN};
    tls_fingerprint::FingerprintData fingerprint;
    bool handshake_succeeded{false};
    std::string error_message;
    uint32_t handshake_duration_ms{0};
};

class StealthContext {
public:
    explicit StealthContext(const StealthConfig& config);
    ~StealthContext();

    boost::asio::ssl::context& get_context();
    void apply_stealth_profile(tls_fingerprint::BrowserProfile profile);
    tls_fingerprint::BrowserProfile current_profile() const { return current_profile_; }
    void rotate_profile();
    void log_connection_metrics(const ConnectionMetrics& metrics);

private:
    void configure_cipher_suites(const std::vector<uint16_t>& suites);
    void configure_supported_groups(const std::vector<uint16_t>& groups);
    void configure_signature_algorithms(const std::vector<uint16_t>& algorithms);
    void configure_alpn(const std::vector<std::string>& protocols);

    StealthConfig config_;
    boost::asio::ssl::context ssl_context_;
    tls_fingerprint::BrowserProfile current_profile_;
    std::vector<tls_fingerprint::BrowserProfile> available_profiles_;
    size_t profile_rotation_index_{0};
    uint64_t connection_counter_{0};
};

boost::asio::ssl::context generate_stealth_tls_config(
    tls_fingerprint::BrowserProfile profile,
    bool verbose = false);

// Generates a ClientHello using the stealth context for `profile` via
// an in-memory BIO pair (no network I/O) and parses the resulting
// bytes through tls_fingerprint::parse_client_hello. Returns the
// computed JA3 hash and the raw component vector, or std::nullopt on
// any OpenSSL / parse error.
//
// Use at daemon startup to verify the JA3 the local OpenSSL build
// will actually emit matches the expected per-profile baseline —
// catches silent drift when OpenSSL is upgraded between builds.
struct SelfFingerprint {
    std::string ja3_hash;
    tls_fingerprint::FingerprintData fingerprint;
};
std::optional<SelfFingerprint> compute_self_fingerprint(
    tls_fingerprint::BrowserProfile profile);

struct StealthConnectionResult {
    bool success{false};
    std::string error_message;
    tls_fingerprint::FingerprintData fingerprint;
    ConnectionMetrics metrics;
};

StealthConnectionResult connect_with_stealth_mode(
    boost::asio::io_context& io_context,
    const std::string& server_host,
    uint16_t port,
    tls_fingerprint::BrowserProfile profile,
    const StealthConfig& config);

struct FingerprintTestResult {
    bool success{false};
    std::string error_message;
    tls_fingerprint::FingerprintData detected_fingerprint;
    std::string ja3_from_server;
    std::string ja4_from_server;
    bool matches_target_profile{false};
};

FingerprintTestResult evaluate_tls_fingerprint(
    const std::string& test_endpoint,
    uint16_t port,
    tls_fingerprint::BrowserProfile target_profile);

class MetricsLogger {
public:
    explicit MetricsLogger(const std::string& log_file_path);
    ~MetricsLogger();

    void log_metrics(const ConnectionMetrics& metrics);
    void flush();

private:
    std::string log_file_path_;
    std::unique_ptr<std::ofstream> log_stream_;
};

class StealthManager {
public:
    static StealthManager& instance();

    void initialize(const StealthConfig& config);
    StealthContext& get_context();
    void log_connection(const ConnectionMetrics& metrics);

    struct Statistics {
        uint64_t total_connections{0};
        uint64_t successful_connections{0};
        uint64_t failed_connections{0};
        std::map<tls_fingerprint::BrowserProfile, uint64_t> profile_usage;
        double average_handshake_duration_ms{0.0};
    };
    Statistics get_statistics() const;

private:
    StealthManager() = default;
    ~StealthManager() = default;
    StealthManager(const StealthManager&) = delete;
    StealthManager& operator=(const StealthManager&) = delete;

    StealthConfig config_;
    std::unique_ptr<StealthContext> context_;
    std::unique_ptr<MetricsLogger> logger_;
    mutable std::mutex mutex_;
    Statistics stats_;
};

std::string cipher_list_to_openssl_string(const std::vector<uint16_t>& cipher_suites);
std::string groups_to_openssl_string(const std::vector<uint16_t>& groups);
std::string cipher_suite_name(uint16_t code);
std::string supported_group_name(uint16_t code);

}  // namespace yume::tls_stealth
