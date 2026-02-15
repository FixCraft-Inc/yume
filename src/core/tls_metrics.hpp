#pragma once

#include "core/tls_fingerprint.hpp"
#include "core/tls_stealth.hpp"

#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace yume::tls_metrics {

/**
 * Fingerprint metric entry
 */
struct FingerprintMetric {
    uint64_t id{0};
    std::string timestamp;
    std::string connection_type;  // "client" or "test"
    std::string server_host;
    uint16_t server_port{443};
    
    // Fingerprint data
    std::string ja3_hash;
    std::string ja4_hash;
    std::string akamai_hash;
    std::vector<std::string> alpn_protocols;
    std::vector<uint16_t> cipher_suites;
    std::vector<uint16_t> extensions;
    std::vector<uint16_t> supported_groups;
    
    // Match results
    bool matches_browser{false};
    tls_fingerprint::BrowserProfile matched_profile{tls_fingerprint::BrowserProfile::UNKNOWN};
    double similarity_score{0.0};
    
    // Profile used (if stealth mode)
    tls_fingerprint::BrowserProfile stealth_profile{tls_fingerprint::BrowserProfile::UNKNOWN};
    bool stealth_enabled{false};
    
    // Connection details
    bool handshake_succeeded{false};
    uint32_t handshake_duration_ms{0};
    std::string error_message;
    
    // Additional metadata
    std::string client_version;
    std::string os_platform;
};

/**
 * Aggregated statistics
 */
struct AggregatedStats {
    uint64_t total_connections{0};
    uint64_t successful_connections{0};
    uint64_t failed_connections{0};
    
    // Profile statistics
    std::map<tls_fingerprint::BrowserProfile, uint64_t> profile_usage;
    std::map<tls_fingerprint::BrowserProfile, uint64_t> profile_matches;
    
    // Performance metrics
    double avg_handshake_duration_ms{0.0};
    uint32_t min_handshake_duration_ms{0};
    uint32_t max_handshake_duration_ms{0};
    
    // Detection statistics
    uint64_t browser_like_fingerprints{0};
    uint64_t non_browser_fingerprints{0};
    double avg_similarity_score{0.0};
    
    // Time range
    std::string first_connection_time;
    std::string last_connection_time;
};

/**
 * Metrics endpoint - exposes current fingerprint and stats
 */
class MetricsEndpoint {
public:
    MetricsEndpoint();
    
    // Record a new metric
    void record_metric(const FingerprintMetric& metric);
    
    // Get current fingerprint info (JSON format)
    std::string get_current_fingerprint_json() const;
    
    // Get aggregated statistics (JSON format)
    std::string get_statistics_json() const;
    
    // Get recent metrics (last N entries)
    std::vector<FingerprintMetric> get_recent_metrics(size_t count = 100) const;
    
    // Export all metrics to file
    bool export_to_file(const std::string& filepath) const;
    
    // Export to CSV
    bool export_to_csv(const std::string& filepath) const;
    
    // Clear all metrics
    void clear();
    
private:
    mutable std::mutex mutex_;
    std::vector<FingerprintMetric> metrics_;
    AggregatedStats stats_;
    uint64_t next_id_{1};
    
    void update_statistics(const FingerprintMetric& metric);
};

/**
 * Global metrics manager
 */
class MetricsManager {
public:
    static MetricsManager& instance();
    
    // Initialize with output directory
    void initialize(const std::string& log_dir = "./logs/fingerprints");
    
    // Record fingerprint from a connection
    void record_connection_fingerprint(
        const std::string& server_host,
        uint16_t server_port,
        const tls_fingerprint::FingerprintData& fingerprint,
        bool stealth_enabled = false,
        tls_fingerprint::BrowserProfile stealth_profile = tls_fingerprint::BrowserProfile::UNKNOWN,
        bool handshake_succeeded = true,
        uint32_t handshake_duration_ms = 0,
        const std::string& error_message = "");
    
    // Get metrics endpoint
    MetricsEndpoint& endpoint();
    
    // Flush metrics to disk
    void flush();
    
    // Generate and export report
    bool generate_report(const std::string& output_path) const;
    
private:
    MetricsManager() = default;
    ~MetricsManager();
    MetricsManager(const MetricsManager&) = delete;
    MetricsManager& operator=(const MetricsManager&) = delete;
    
    std::string log_dir_;
    std::unique_ptr<MetricsEndpoint> endpoint_;
    mutable std::mutex mutex_;
};

/**
 * Helper: Format fingerprint metric as JSON
 */
std::string metric_to_json(const FingerprintMetric& metric);

/**
 * Helper: Format statistics as JSON
 */
std::string stats_to_json(const AggregatedStats& stats);

/**
 * Helper: Create fingerprint comparison report
 */
struct ComparisonReport {
    bool fingerprints_match{false};
    std::vector<std::string> differences;
    std::vector<std::string> warnings;
    double overall_similarity{0.0};
};

ComparisonReport compare_fingerprints(
    const tls_fingerprint::FingerprintData& fp1,
    const tls_fingerprint::FingerprintData& fp2);

}  // namespace yume::tls_metrics
