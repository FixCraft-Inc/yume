/*
 * YUME TLS Fingerprint Test Utility
 * 
 * This utility demonstrates TLS fingerprinting and stealth mode capabilities.
 * It can be used to test and verify browser profile emulation.
 */

#include "core/stealth/tls_fingerprint.hpp"
#include "core/stealth/tls_stealth.hpp"
#include "core/stealth/tls_metrics.hpp"

#include <iostream>
#include <iomanip>
#include <string>

void print_fingerprint_info(const yume::tls_fingerprint::FingerprintData& fp) {
    std::cout << "\n=== TLS Fingerprint Information ===\n";
    std::cout << "JA3 Hash:    " << fp.ja3_hash << "\n";
    std::cout << "JA4 Hash:    " << fp.ja4_hash << "\n";
    std::cout << "Akamai Hash: " << fp.akamai_hash << "\n";
    
    std::cout << "\nALPN Protocols: ";
    for (size_t i = 0; i < fp.alpn_protocols.size(); ++i) {
        if (i > 0) std::cout << ", ";
        std::cout << fp.alpn_protocols[i];
    }
    std::cout << "\n";
    
    std::cout << "Matches Browser: " << (fp.matches_known_browser ? "Yes" : "No") << "\n";
    if (fp.matches_known_browser) {
        std::cout << "Matched Profile: " 
                  << yume::tls_fingerprint::browser_profile_name(fp.matched_profile) << "\n";
        std::cout << "Similarity Score: " << std::fixed << std::setprecision(2) 
                  << fp.similarity_score << "%\n";
    }
}

void print_browser_profiles() {
    std::cout << "\n=== Available Browser Profiles ===\n\n";
    
    auto profiles = yume::tls_fingerprint::get_known_browser_fingerprints();
    
    for (const auto& profile : profiles) {
        std::cout << "Profile: " << profile.name << "\n";
        std::cout << "  JA3 Hash: " << profile.ja3_hash << "\n";
        std::cout << "  JA4 Hash: " << profile.ja4_hash << "\n";
        std::cout << "  Cipher Suites: " << profile.cipher_suites.size() << "\n";
        std::cout << "  Extensions: " << profile.extensions.size() << "\n";
        std::cout << "  ALPN Protocols: ";
        for (size_t i = 0; i < profile.alpn_protocols.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << profile.alpn_protocols[i];
        }
        std::cout << "\n\n";
    }
}

void test_stealth_mode() {
    std::cout << "\n=== Testing Stealth Mode ===\n\n";
    
    // Test each browser profile
    std::vector<yume::tls_fingerprint::BrowserProfile> profiles = {
        yume::tls_fingerprint::BrowserProfile::CHROME_135,
        yume::tls_fingerprint::BrowserProfile::FIREFOX_126,
        yume::tls_fingerprint::BrowserProfile::SAFARI_17,
    };
    
    for (const auto& profile : profiles) {
        std::cout << "Testing profile: " 
                  << yume::tls_fingerprint::browser_profile_name(profile) << "\n";
        
        // Create stealth configuration
        yume::tls_stealth::StealthConfig config;
        config.enabled = true;
        config.target_profile = profile;
        
        try {
            // Generate stealth TLS config
            auto ssl_ctx = yume::tls_stealth::generate_stealth_tls_config(profile, false);
            std::cout << "  ✓ Stealth context created successfully\n";
            
            // Get profile information
            auto profile_info = yume::tls_fingerprint::get_browser_profile_info(profile);
            if (profile_info) {
                std::cout << "  - Cipher Suites: " << profile_info->cipher_suites.size() << "\n";
                std::cout << "  - Extensions: " << profile_info->extensions.size() << "\n";
                std::cout << "  - Supported Groups: " << profile_info->supported_groups.size() << "\n";
            }
        } catch (const std::exception& e) {
            std::cout << "  ✗ Error: " << e.what() << "\n";
        }
        
        std::cout << "\n";
    }
}

void test_fingerprint_evaluation() {
    std::cout << "\n=== Testing Fingerprint Evaluation ===\n\n";
    
    // Create a test fingerprint
    yume::tls_fingerprint::FingerprintData test_fp;
    
    // Simulate a non-browser fingerprint (too few cipher suites/extensions)
    test_fp.ja3_components.cipher_suites = {0x1301, 0x1302};  // Only 2 ciphers
    test_fp.ja3_components.extensions = {0, 10, 13};  // Only 3 extensions
    test_fp.alpn_protocols = {"http/1.1"};  // Missing h2
    
    std::cout << "Testing with simulated non-browser fingerprint:\n";
    std::cout << "  - Cipher Suites: " << test_fp.ja3_components.cipher_suites.size() << "\n";
    std::cout << "  - Extensions: " << test_fp.ja3_components.extensions.size() << "\n";
    std::cout << "  - ALPN: ";
    for (const auto& proto : test_fp.alpn_protocols) {
        std::cout << proto << " ";
    }
    std::cout << "\n\n";
    
    // Evaluate fingerprint
    auto eval = yume::tls_fingerprint::evaluate_fingerprint(test_fp);
    
    std::cout << "Evaluation Results:\n";
    std::cout << "  Looks like browser: " << (eval.looks_like_browser ? "Yes" : "No") << "\n";
    std::cout << "  Needs stealth mode: " << (eval.needs_stealth_mode ? "Yes" : "No") << "\n";
    std::cout << "  Recommended profile: " 
              << yume::tls_fingerprint::browser_profile_name(eval.recommended_profile) << "\n";
    
    if (!eval.warnings.empty()) {
        std::cout << "\n  Warnings:\n";
        for (const auto& warning : eval.warnings) {
            std::cout << "    - " << warning << "\n";
        }
    }
    
    if (!eval.recommendations.empty()) {
        std::cout << "\n  Recommendations:\n";
        for (const auto& rec : eval.recommendations) {
            std::cout << "    - " << rec << "\n";
        }
    }
}

void test_metrics_system() {
    std::cout << "\n=== Testing Metrics System ===\n\n";
    
    // Initialize metrics manager
    yume::tls_metrics::MetricsManager::instance().initialize("./test_logs");
    
    // Create test metrics
    yume::tls_fingerprint::FingerprintData fp;
    fp.ja3_hash = "test_ja3_hash_12345";
    fp.ja4_hash = "t13d1307_test_hash";
    fp.alpn_protocols = {"h2", "http/1.1"};
    
    // Record connection
    yume::tls_metrics::MetricsManager::instance().record_connection_fingerprint(
        "test.example.com",
        443,
        fp,
        true,  // stealth_enabled
        yume::tls_fingerprint::BrowserProfile::CHROME_135,
        true,  // handshake_succeeded
        250,   // handshake_duration_ms
        ""     // error_message
    );
    
    std::cout << "Recorded test connection metric\n";
    
    // Get current fingerprint
    auto& endpoint = yume::tls_metrics::MetricsManager::instance().endpoint();
    std::cout << "\nCurrent Fingerprint (JSON):\n";
    std::cout << endpoint.get_current_fingerprint_json() << "\n";
    
    // Get statistics
    std::cout << "\nStatistics:\n";
    std::cout << endpoint.get_statistics_json() << "\n";
    
    // Flush metrics
    yume::tls_metrics::MetricsManager::instance().flush();
    std::cout << "\nMetrics flushed to ./test_logs/\n";
}

void print_usage() {
    std::cout << "YUME TLS Fingerprint Test Utility\n\n";
    std::cout << "Usage: yume_tls_test [option]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --profiles      List all available browser profiles\n";
    std::cout << "  --stealth       Test stealth mode configuration\n";
    std::cout << "  --evaluate      Test fingerprint evaluation\n";
    std::cout << "  --metrics       Test metrics system\n";
    std::cout << "  --all           Run all tests\n";
    std::cout << "  --help          Show this help message\n";
}

int main(int argc, char** argv) {
    std::cout << "YUME TLS Fingerprint & Stealth Mode Test Utility\n";
    std::cout << "=================================================\n";
    
    if (argc < 2) {
        print_usage();
        return 0;
    }
    
    std::string option = argv[1];
    
    if (option == "--help") {
        print_usage();
    } else if (option == "--profiles") {
        print_browser_profiles();
    } else if (option == "--stealth") {
        test_stealth_mode();
    } else if (option == "--evaluate") {
        test_fingerprint_evaluation();
    } else if (option == "--metrics") {
        test_metrics_system();
    } else if (option == "--all") {
        print_browser_profiles();
        test_stealth_mode();
        test_fingerprint_evaluation();
        test_metrics_system();
    } else {
        std::cerr << "Unknown option: " << option << "\n";
        print_usage();
        return 1;
    }
    
    std::cout << "\nTest completed successfully.\n";
    return 0;
}
