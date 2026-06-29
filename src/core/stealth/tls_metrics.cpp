/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/stealth/tls_metrics.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>

#include <nlohmann/json.hpp>

namespace yume::tls_metrics {

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

std::string get_platform() {
#if defined(_WIN32)
    return "Windows";
#elif defined(__APPLE__)
    return "macOS";
#elif defined(__linux__)
    return "Linux";
#else
    return "Unknown";
#endif
}

}  // namespace

// MetricsEndpoint implementation

MetricsEndpoint::MetricsEndpoint() = default;

void MetricsEndpoint::record_metric(const FingerprintMetric& metric) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    FingerprintMetric m = metric;
    m.id = next_id_++;
    if (m.timestamp.empty()) {
        m.timestamp = current_timestamp();
    }
    
    metrics_.push_back(m);
    update_statistics(m);
}

void MetricsEndpoint::update_statistics(const FingerprintMetric& metric) {
    stats_.total_connections++;
    
    if (metric.handshake_succeeded) {
        stats_.successful_connections++;
    } else {
        stats_.failed_connections++;
    }
    
    if (metric.stealth_enabled) {
        stats_.profile_usage[metric.stealth_profile]++;
    }
    
    if (metric.matches_browser) {
        stats_.profile_matches[metric.matched_profile]++;
        stats_.browser_like_fingerprints++;
    } else {
        stats_.non_browser_fingerprints++;
    }
    
    if (metric.handshake_succeeded) {
        if (stats_.min_handshake_duration_ms == 0 || 
            metric.handshake_duration_ms < stats_.min_handshake_duration_ms) {
            stats_.min_handshake_duration_ms = metric.handshake_duration_ms;
        }
        if (metric.handshake_duration_ms > stats_.max_handshake_duration_ms) {
            stats_.max_handshake_duration_ms = metric.handshake_duration_ms;
        }
        
        double total_duration = stats_.avg_handshake_duration_ms * 
                               (stats_.successful_connections - 1);
        total_duration += metric.handshake_duration_ms;
        stats_.avg_handshake_duration_ms = total_duration / stats_.successful_connections;
    }
    
    double total_similarity = stats_.avg_similarity_score * (stats_.total_connections - 1);
    total_similarity += metric.similarity_score;
    stats_.avg_similarity_score = total_similarity / stats_.total_connections;
    
    if (stats_.first_connection_time.empty()) {
        stats_.first_connection_time = metric.timestamp;
    }
    stats_.last_connection_time = metric.timestamp;
}

std::string MetricsEndpoint::get_current_fingerprint_json() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (metrics_.empty()) {
        return "{}";
    }
    
    const auto& latest = metrics_.back();
    
    nlohmann::json j;
    j["timestamp"] = latest.timestamp;
    j["ja3_hash"] = latest.ja3_hash;
    j["ja4_hash"] = latest.ja4_hash;
    j["akamai_hash"] = latest.akamai_hash;
    j["alpn_protocols"] = latest.alpn_protocols;
    j["matches_browser"] = latest.matches_browser;
    j["matched_profile"] = tls_fingerprint::browser_profile_name(latest.matched_profile);
    j["similarity_score"] = latest.similarity_score;
    j["stealth_enabled"] = latest.stealth_enabled;
    if (latest.stealth_enabled) {
        j["stealth_profile"] = tls_fingerprint::browser_profile_name(latest.stealth_profile);
    }
    
    return j.dump(2);
}

std::string MetricsEndpoint::get_statistics_json() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_to_json(stats_);
}

std::vector<FingerprintMetric> MetricsEndpoint::get_recent_metrics(size_t count) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (metrics_.size() <= count) {
        return metrics_;
    }
    
    return std::vector<FingerprintMetric>(
        metrics_.end() - count, metrics_.end());
}

bool MetricsEndpoint::export_to_file(const std::string& filepath) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    try {
        nlohmann::json j = nlohmann::json::array();
        
        for (const auto& metric : metrics_) {
            j.push_back(nlohmann::json::parse(metric_to_json(metric)));
        }
        
        std::ofstream out(filepath);
        if (!out) {
            return false;
        }
        
        out << j.dump(2);
        return true;
    } catch (...) {
        return false;
    }
}

bool MetricsEndpoint::export_to_csv(const std::string& filepath) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    try {
        std::ofstream out(filepath);
        if (!out) {
            return false;
        }
        
        // CSV header
        out << "id,timestamp,server_host,server_port,"
            << "ja3_hash,ja4_hash,akamai_hash,"
            << "matches_browser,matched_profile,similarity_score,"
            << "stealth_enabled,stealth_profile,"
            << "handshake_succeeded,handshake_duration_ms,error_message\n";
        
        for (const auto& m : metrics_) {
            out << m.id << ","
                << m.timestamp << ","
                << m.server_host << ","
                << m.server_port << ","
                << m.ja3_hash << ","
                << m.ja4_hash << ","
                << m.akamai_hash << ","
                << (m.matches_browser ? "true" : "false") << ","
                << tls_fingerprint::browser_profile_name(m.matched_profile) << ","
                << m.similarity_score << ","
                << (m.stealth_enabled ? "true" : "false") << ","
                << tls_fingerprint::browser_profile_name(m.stealth_profile) << ","
                << (m.handshake_succeeded ? "true" : "false") << ","
                << m.handshake_duration_ms << ","
                << m.error_message << "\n";
        }
        
        return true;
    } catch (...) {
        return false;
    }
}

void MetricsEndpoint::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    metrics_.clear();
    stats_ = AggregatedStats{};
    next_id_ = 1;
}

// MetricsManager implementation

MetricsManager& MetricsManager::instance() {
    static MetricsManager instance;
    return instance;
}

MetricsManager::~MetricsManager() {
    flush();
}

void MetricsManager::initialize(const std::string& log_dir) {
    std::lock_guard<std::mutex> lock(mutex_);
    log_dir_ = log_dir;
    
    try {
        std::filesystem::create_directories(log_dir);
    } catch (...) {
    }
    
    if (!endpoint_) {
        endpoint_ = std::make_unique<MetricsEndpoint>();
    }
}

void MetricsManager::record_connection_fingerprint(
    const std::string& server_host,
    uint16_t server_port,
    const tls_fingerprint::FingerprintData& fingerprint,
    bool stealth_enabled,
    tls_fingerprint::BrowserProfile stealth_profile,
    bool handshake_succeeded,
    uint32_t handshake_duration_ms,
    const std::string& error_message) {
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!endpoint_) {
        initialize();
    }
    
    FingerprintMetric metric;
    metric.timestamp = current_timestamp();
    metric.connection_type = "client";
    metric.server_host = server_host;
    metric.server_port = server_port;
    
    metric.ja3_hash = fingerprint.ja3_hash;
    metric.ja4_hash = fingerprint.ja4_hash;
    metric.akamai_hash = fingerprint.akamai_hash;
    metric.alpn_protocols = fingerprint.alpn_protocols;
    metric.cipher_suites = fingerprint.ja3_components.cipher_suites;
    metric.extensions = fingerprint.ja3_components.extensions;
    metric.supported_groups = fingerprint.ja3_components.supported_groups;
    
    metric.matches_browser = fingerprint.matches_known_browser;
    metric.matched_profile = fingerprint.matched_profile;
    metric.similarity_score = fingerprint.similarity_score;
    
    metric.stealth_enabled = stealth_enabled;
    metric.stealth_profile = stealth_profile;
    
    metric.handshake_succeeded = handshake_succeeded;
    metric.handshake_duration_ms = handshake_duration_ms;
    metric.error_message = error_message;
    
    metric.os_platform = get_platform();
    
    endpoint_->record_metric(metric);
}

MetricsEndpoint& MetricsManager::endpoint() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!endpoint_) {
        initialize();
    }
    return *endpoint_;
}

void MetricsManager::flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!endpoint_ || log_dir_.empty()) {
        return;
    }
    
    auto timestamp = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(timestamp);
    std::tm tm;
#if defined(_WIN32)
    localtime_s(&tm, &time_t);
#else
    localtime_r(&time_t, &tm);
#endif
    
    std::ostringstream filename;
    filename << log_dir_ << "/fingerprints-"
             << std::put_time(&tm, "%Y%m%d-%H%M%S")
             << ".json";
    
    endpoint_->export_to_file(filename.str());
    
    std::string latest_path = log_dir_ + "/fingerprints-latest.json";
    endpoint_->export_to_file(latest_path);
    
    std::string csv_path = log_dir_ + "/fingerprints-latest.csv";
    endpoint_->export_to_csv(csv_path);
}

bool MetricsManager::generate_report(const std::string& output_path) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!endpoint_) {
        return false;
    }
    
    try {
        std::ofstream out(output_path);
        if (!out) {
            return false;
        }
        
        out << "# YUME TLS Fingerprint Report\n\n";
        out << "Generated: " << current_timestamp() << "\n\n";
        
        out << "## Current Fingerprint\n\n";
        out << "```json\n";
        out << endpoint_->get_current_fingerprint_json();
        out << "\n```\n\n";
        
        out << "## Statistics\n\n";
        out << "```json\n";
        out << endpoint_->get_statistics_json();
        out << "\n```\n\n";
        
        return true;
    } catch (...) {
        return false;
    }
}



std::string metric_to_json(const FingerprintMetric& metric) {
    nlohmann::json j;
    j["id"] = metric.id;
    j["timestamp"] = metric.timestamp;
    j["connection_type"] = metric.connection_type;
    j["server_host"] = metric.server_host;
    j["server_port"] = metric.server_port;
    j["ja3_hash"] = metric.ja3_hash;
    j["ja4_hash"] = metric.ja4_hash;
    j["akamai_hash"] = metric.akamai_hash;
    j["alpn_protocols"] = metric.alpn_protocols;
    j["matches_browser"] = metric.matches_browser;
    j["matched_profile"] = tls_fingerprint::browser_profile_name(metric.matched_profile);
    j["similarity_score"] = metric.similarity_score;
    j["stealth_enabled"] = metric.stealth_enabled;
    j["stealth_profile"] = tls_fingerprint::browser_profile_name(metric.stealth_profile);
    j["handshake_succeeded"] = metric.handshake_succeeded;
    j["handshake_duration_ms"] = metric.handshake_duration_ms;
    if (!metric.error_message.empty()) {
        j["error_message"] = metric.error_message;
    }
    j["os_platform"] = metric.os_platform;
    
    return j.dump();
}

std::string stats_to_json(const AggregatedStats& stats) {
    nlohmann::json j;
    j["total_connections"] = stats.total_connections;
    j["successful_connections"] = stats.successful_connections;
    j["failed_connections"] = stats.failed_connections;
    j["browser_like_fingerprints"] = stats.browser_like_fingerprints;
    j["non_browser_fingerprints"] = stats.non_browser_fingerprints;
    j["avg_similarity_score"] = stats.avg_similarity_score;
    j["avg_handshake_duration_ms"] = stats.avg_handshake_duration_ms;
    j["min_handshake_duration_ms"] = stats.min_handshake_duration_ms;
    j["max_handshake_duration_ms"] = stats.max_handshake_duration_ms;
    
    nlohmann::json profile_usage = nlohmann::json::object();
    for (const auto& [profile, count] : stats.profile_usage) {
        profile_usage[tls_fingerprint::browser_profile_name(profile)] = count;
    }
    j["profile_usage"] = profile_usage;
    
    nlohmann::json profile_matches = nlohmann::json::object();
    for (const auto& [profile, count] : stats.profile_matches) {
        profile_matches[tls_fingerprint::browser_profile_name(profile)] = count;
    }
    j["profile_matches"] = profile_matches;
    
    j["first_connection_time"] = stats.first_connection_time;
    j["last_connection_time"] = stats.last_connection_time;
    
    return j.dump(2);
}

ComparisonReport compare_fingerprints(
    const tls_fingerprint::FingerprintData& fp1,
    const tls_fingerprint::FingerprintData& fp2) {
    
    ComparisonReport report;
    
    if (fp1.ja3_hash == fp2.ja3_hash) {
        report.overall_similarity += 50.0;
    } else {
        report.differences.push_back("JA3 hashes differ");
    }
    
    if (fp1.ja4_hash == fp2.ja4_hash) {
        report.overall_similarity += 50.0;
    } else {
        report.differences.push_back("JA4 hashes differ");
    }
    
    report.fingerprints_match = (report.overall_similarity >= 100.0);
    
    if (!report.fingerprints_match) {
        report.warnings.push_back("Fingerprints do not match exactly");
    }
    
    if (fp1.alpn_protocols != fp2.alpn_protocols) {
        report.differences.push_back("ALPN protocols differ");
    }
    
    return report;
}

}  // namespace yume::tls_metrics
