/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "core/tls_stealth.hpp"

#include <boost/asio/connect.hpp>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <map>
#include <mutex>

#include <nlohmann/json.hpp>

namespace yume::tls_stealth {

namespace {

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

// Cipher suite mappings
std::map<uint16_t, std::string> cipher_name_map = {
    {0x1301, "TLS_AES_128_GCM_SHA256"},
    {0x1302, "TLS_AES_256_GCM_SHA384"},
    {0x1303, "TLS_CHACHA20_POLY1305_SHA256"},
    {0xc02c, "ECDHE-ECDSA-AES256-GCM-SHA384"},
    {0xc02b, "ECDHE-ECDSA-AES128-GCM-SHA256"},
    {0xc030, "ECDHE-RSA-AES256-GCM-SHA384"},
    {0xc02f, "ECDHE-RSA-AES128-GCM-SHA256"},
    {0xc024, "ECDHE-ECDSA-AES256-SHA384"},
    {0xc023, "ECDHE-ECDSA-AES128-SHA256"},
    {0xc028, "ECDHE-RSA-AES256-SHA384"},
    {0xc027, "ECDHE-RSA-AES128-SHA256"},
};

std::map<uint16_t, std::string> group_name_map = {
    {0x001d, "X25519"},
    {0x0017, "secp256r1"},
    {0x0018, "secp384r1"},
    {0x0019, "secp521r1"},
    {0x001e, "X448"},
};

std::string cipher_suite_name(uint16_t code) {
    auto it = cipher_name_map.find(code);
    if (it != cipher_name_map.end()) {
        return it->second;
    }
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(4) << std::setfill('0') << code;
    return oss.str();
}

std::string supported_group_name(uint16_t code) {
    auto it = group_name_map.find(code);
    if (it != group_name_map.end()) {
        return it->second;
    }
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setw(4) << std::setfill('0') << code;
    return oss.str();
}

std::string cipher_list_to_openssl_string(const std::vector<uint16_t>& cipher_suites) {
    std::ostringstream oss;
    for (size_t i = 0; i < cipher_suites.size(); ++i) {
        if (i > 0) oss << ":";
        oss << cipher_suite_name(cipher_suites[i]);
    }
    return oss.str();
}

std::string groups_to_openssl_string(const std::vector<uint16_t>& groups) {
    std::ostringstream oss;
    for (size_t i = 0; i < groups.size(); ++i) {
        if (i > 0) oss << ":";
        oss << supported_group_name(groups[i]);
    }
    return oss.str();
}

// StealthContext implementation

StealthContext::StealthContext(const StealthConfig& config)
    : config_(config)
    , ssl_context_(boost::asio::ssl::context::tls_client)
    , current_profile_(config.target_profile) {
    
    // Set up available profiles for rotation
    available_profiles_ = {
        tls_fingerprint::BrowserProfile::CHROME_135,
        tls_fingerprint::BrowserProfile::FIREFOX_126,
        tls_fingerprint::BrowserProfile::SAFARI_17,
    };
    
    // Initialize SSL context with basic settings
    ssl_context_.set_options(
        boost::asio::ssl::context::default_workarounds |
        boost::asio::ssl::context::no_sslv2 |
        boost::asio::ssl::context::no_sslv3 |
        boost::asio::ssl::context::no_tlsv1 |
        boost::asio::ssl::context::no_tlsv1_1);
    
    // Apply initial stealth profile
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
    
    auto profile_info = tls_fingerprint::get_browser_profile_info(profile);
    if (!profile_info) {
        // Fallback to Chrome 135 if profile not found
        profile_info = tls_fingerprint::get_browser_profile_info(
            tls_fingerprint::BrowserProfile::CHROME_135);
        if (!profile_info) {
            return;  // Should not happen
        }
    }
    
    // Configure cipher suites
    configure_cipher_suites(profile_info->cipher_suites);
    
    // Configure supported groups (curves)
    configure_supported_groups(profile_info->supported_groups);
    
    // Configure signature algorithms
    configure_signature_algorithms(profile_info->signature_algorithms);
    
    // Configure ALPN
    configure_alpn(profile_info->alpn_protocols);
    
    // Set TLS version constraints
    SSL_CTX* ctx = ssl_context_.native_handle();
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
}

void StealthContext::configure_cipher_suites(const std::vector<uint16_t>& suites) {
    std::string cipher_string = cipher_list_to_openssl_string(suites);
    SSL_CTX* ctx = ssl_context_.native_handle();
    
    // Set TLS 1.3 cipher suites
    std::string tls13_ciphers = "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";
    SSL_CTX_set_ciphersuites(ctx, tls13_ciphers.c_str());
    
    // Set TLS 1.2 cipher suites (for compatibility)
    SSL_CTX_set_cipher_list(ctx, cipher_string.c_str());
}

void StealthContext::configure_supported_groups(const std::vector<uint16_t>& groups) {
    std::string groups_string = groups_to_openssl_string(groups);
    SSL_CTX* ctx = ssl_context_.native_handle();
    SSL_CTX_set1_groups_list(ctx, groups_string.c_str());
}

void StealthContext::configure_signature_algorithms(const std::vector<uint16_t>& algorithms) {
    // OpenSSL signature algorithm configuration
    // This is more complex and requires direct OpenSSL API calls
    SSL_CTX* ctx = ssl_context_.native_handle();
    
    // For now, use default signature algorithms that match browsers
    // In production, you'd want to set these exactly
    const char* sigalgs = "ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:"
                          "RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:"
                          "RSA+SHA256:RSA+SHA384:RSA+SHA512";
    SSL_CTX_set1_sigalgs_list(ctx, sigalgs);
}

void StealthContext::configure_alpn(const std::vector<std::string>& protocols) {
    // Build ALPN protocol list in wire format
    std::vector<unsigned char> alpn_data;
    for (const auto& proto : protocols) {
        alpn_data.push_back(static_cast<unsigned char>(proto.size()));
        alpn_data.insert(alpn_data.end(), proto.begin(), proto.end());
    }
    
    SSL_CTX* ctx = ssl_context_.native_handle();
    SSL_CTX_set_alpn_protos(ctx, alpn_data.data(), 
                           static_cast<unsigned int>(alpn_data.size()));
}

void StealthContext::configure_extensions(const std::vector<uint16_t>& extensions) {
    // TLS extension configuration is complex and not fully exposed in OpenSSL
    // Some extensions are automatically handled by OpenSSL based on other settings
    // For deep customization, you would need to use BoringSSL or patched OpenSSL
}

void StealthContext::rotate_profile() {
    if (!config_.rotate_profiles || available_profiles_.empty()) {
        return;
    }
    
    profile_rotation_index_ = (profile_rotation_index_ + 1) % available_profiles_.size();
    apply_stealth_profile(available_profiles_[profile_rotation_index_]);
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
    
    // Check for profile rotation
    connection_counter_++;
    if (config_.rotate_profiles && 
        connection_counter_ >= config_.rotation_interval_connections) {
        connection_counter_ = 0;
        rotate_profile();
    }
}

// Standalone functions

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
    
    // Return a copy of the context
    // Note: This is a simplified version - in production you'd handle this differently
    return std::move(stealth_ctx.get_context());
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
        // Create stealth context
        StealthContext stealth_ctx(config);
        
        // Resolve endpoint
        boost::asio::ip::tcp::resolver resolver(io_context);
        auto endpoints = resolver.resolve(server_host, std::to_string(port));
        
        // Create SSL stream
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream(
            io_context, stealth_ctx.get_context());
        
        // Set SNI hostname
        SSL_set_tlsext_host_name(stream.native_handle(), server_host.c_str());
        
        // Connect
        boost::asio::connect(stream.lowest_layer(), endpoints);
        
        // Perform TLS handshake
        stream.handshake(boost::asio::ssl::stream_base::client);
        
        auto end_time = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time);
        
        result.success = true;
        result.metrics.handshake_succeeded = true;
        result.metrics.handshake_duration_ms = static_cast<uint32_t>(duration.count());
        
        // Close connection
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

FingerprintTestResult evaluate_tls_fingerprint(
    const std::string& test_endpoint,
    uint16_t port,
    tls_fingerprint::BrowserProfile target_profile) {
    
    FingerprintTestResult result;
    
    try {
        boost::asio::io_context io_context;
        
        StealthConfig config;
        config.enabled = true;
        config.target_profile = target_profile;
        
        auto conn_result = connect_with_stealth_mode(
            io_context, test_endpoint, port, target_profile, config);
        
        result.success = conn_result.success;
        result.error_message = conn_result.error_message;
        result.detected_fingerprint = conn_result.fingerprint;
        
        // In production, you'd fetch the JA3/JA4 from the test endpoint's response
        // For now, we just compare with the target profile
        auto profile_info = tls_fingerprint::get_browser_profile_info(target_profile);
        if (profile_info) {
            result.matches_target_profile = 
                (result.detected_fingerprint.ja3_hash == profile_info->ja3_hash);
        }
        
    } catch (const std::exception& e) {
        result.success = false;
        result.error_message = e.what();
    }
    
    return result;
}

// MetricsLogger implementation

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

// StealthManager implementation

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
        // Initialize with default config if not already initialized
        StealthConfig default_config;
        default_config.enabled = true;
        context_ = std::make_unique<StealthContext>(default_config);
    }
    return *context_;
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
    
    // Update average handshake duration
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
