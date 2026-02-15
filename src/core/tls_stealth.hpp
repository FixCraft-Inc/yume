#pragma once

#include "core/tls_fingerprint.hpp"

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

/**
 * Stealth mode configuration
 */
struct StealthConfig {
    bool enabled{false};
    tls_fingerprint::BrowserProfile target_profile{tls_fingerprint::BrowserProfile::CHROME_135};
    bool rotate_profiles{false};              // Rotate between profiles
    uint32_t rotation_interval_connections{100};  // Rotate every N connections
    bool log_fingerprints{true};              // Log TLS fingerprints
    std::string log_file_path;                // Path to fingerprint log
    bool verify_with_external_api{false};     // Test against tlsinfo.me or similar
    std::string test_endpoint{"tls.peet.ws"}; // Endpoint for fingerprint verification
};

/**
 * Connection fingerprint metrics
 */
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

/**
 * TLS stealth context - wraps Boost.Asio SSL context with stealth mode
 */
class StealthContext {
public:
    explicit StealthContext(const StealthConfig& config);
    ~StealthContext();

    // Get the underlying Boost.Asio SSL context
    boost::asio::ssl::context& get_context();

    // Apply stealth configuration to SSL context
    void apply_stealth_profile(tls_fingerprint::BrowserProfile profile);

    // Get current profile
    tls_fingerprint::BrowserProfile current_profile() const { return current_profile_; }

    // Rotate to next profile
    void rotate_profile();

    // Log connection metrics
    void log_connection_metrics(const ConnectionMetrics& metrics);

private:
    void configure_cipher_suites(const std::vector<uint16_t>& suites);
    void configure_supported_groups(const std::vector<uint16_t>& groups);
    void configure_signature_algorithms(const std::vector<uint16_t>& algorithms);
    void configure_alpn(const std::vector<std::string>& protocols);
    void configure_extensions(const std::vector<uint16_t>& extensions);

    StealthConfig config_;
    boost::asio::ssl::context ssl_context_;
    tls_fingerprint::BrowserProfile current_profile_;
    std::vector<tls_fingerprint::BrowserProfile> available_profiles_;
    size_t profile_rotation_index_{0};
    uint64_t connection_counter_{0};
};

/**
 * Generate stealth TLS configuration for a specific browser profile
 */
boost::asio::ssl::context generate_stealth_tls_config(
    tls_fingerprint::BrowserProfile profile,
    bool verbose = false);

/**
 * Connect with stealth mode to a remote server
 * Returns success status and connection details
 */
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

/**
 * Evaluate current TLS fingerprint by connecting to a test endpoint
 * This makes a real connection to tlsinfo.me or similar to verify fingerprint
 */
struct FingerprintTestResult {
    bool success{false};
    std::string error_message;
    tls_fingerprint::FingerprintData detected_fingerprint;
    std::string ja3_from_server;  // JA3 as seen by the server
    std::string ja4_from_server;  // JA4 as seen by the server
    bool matches_target_profile{false};
};

FingerprintTestResult evaluate_tls_fingerprint(
    const std::string& test_endpoint,
    uint16_t port,
    tls_fingerprint::BrowserProfile target_profile);

/**
 * Metrics logger - writes connection metrics to file and/or database
 */
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

/**
 * Global stealth mode manager - singleton for managing stealth contexts
 */
class StealthManager {
public:
    static StealthManager& instance();

    void initialize(const StealthConfig& config);
    StealthContext& get_context();
    void log_connection(const ConnectionMetrics& metrics);

    // Get cumulative statistics
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

/**
 * Helper: Create OpenSSL cipher suite string from list of cipher codes
 */
std::string cipher_list_to_openssl_string(const std::vector<uint16_t>& cipher_suites);

/**
 * Helper: Create OpenSSL curves string from supported groups
 */
std::string groups_to_openssl_string(const std::vector<uint16_t>& groups);

/**
 * Helper: Get cipher suite name from code
 */
std::string cipher_suite_name(uint16_t code);

/**
 * Helper: Get supported group name from code
 */
std::string supported_group_name(uint16_t code);

}  // namespace yume::tls_stealth
