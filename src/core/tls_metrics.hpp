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

struct FingerprintMetric {
    uint64_t id{0};
    std::string timestamp;
    std::string connection_type;
    std::string server_host;
    uint16_t server_port{443};

    std::string ja3_hash;
    std::string ja4_hash;
    std::string akamai_hash;
    std::vector<std::string> alpn_protocols;
    std::vector<uint16_t> cipher_suites;
    std::vector<uint16_t> extensions;
    std::vector<uint16_t> supported_groups;

    bool matches_browser{false};
    tls_fingerprint::BrowserProfile matched_profile{tls_fingerprint::BrowserProfile::UNKNOWN};
    double similarity_score{0.0};

    tls_fingerprint::BrowserProfile stealth_profile{tls_fingerprint::BrowserProfile::UNKNOWN};
    bool stealth_enabled{false};

    bool handshake_succeeded{false};
    uint32_t handshake_duration_ms{0};
    std::string error_message;

    std::string client_version;
    std::string os_platform;
};

struct AggregatedStats {
    uint64_t total_connections{0};
    uint64_t successful_connections{0};
    uint64_t failed_connections{0};

    std::map<tls_fingerprint::BrowserProfile, uint64_t> profile_usage;
    std::map<tls_fingerprint::BrowserProfile, uint64_t> profile_matches;

    double avg_handshake_duration_ms{0.0};
    uint32_t min_handshake_duration_ms{0};
    uint32_t max_handshake_duration_ms{0};

    uint64_t browser_like_fingerprints{0};
    uint64_t non_browser_fingerprints{0};
    double avg_similarity_score{0.0};

    std::string first_connection_time;
    std::string last_connection_time;
};

class MetricsEndpoint {
public:
    MetricsEndpoint();

    void record_metric(const FingerprintMetric& metric);
    std::string get_current_fingerprint_json() const;
    std::string get_statistics_json() const;
    std::vector<FingerprintMetric> get_recent_metrics(size_t count = 100) const;
    bool export_to_file(const std::string& filepath) const;
    bool export_to_csv(const std::string& filepath) const;
    void clear();

private:
    mutable std::mutex mutex_;
    std::vector<FingerprintMetric> metrics_;
    AggregatedStats stats_;
    uint64_t next_id_{1};

    void update_statistics(const FingerprintMetric& metric);
};

class MetricsManager {
public:
    static MetricsManager& instance();

    void initialize(const std::string& log_dir = "./logs/fingerprints");
    void record_connection_fingerprint(
        const std::string& server_host,
        uint16_t server_port,
        const tls_fingerprint::FingerprintData& fingerprint,
        bool stealth_enabled = false,
        tls_fingerprint::BrowserProfile stealth_profile = tls_fingerprint::BrowserProfile::UNKNOWN,
        bool handshake_succeeded = true,
        uint32_t handshake_duration_ms = 0,
        const std::string& error_message = "");

    MetricsEndpoint& endpoint();
    void flush();
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

std::string metric_to_json(const FingerprintMetric& metric);
std::string stats_to_json(const AggregatedStats& stats);

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
