/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/auth/auth.hpp"

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

class TemporaryDirectory {
public:
    TemporaryDirectory() {
        const auto suffix = std::chrono::steady_clock::now()
                                .time_since_epoch()
                                .count();
        path_ = std::filesystem::temp_directory_path() /
                ("yume-auth-policy-test-" + std::to_string(suffix));
        std::filesystem::create_directory(path_);
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

void assert_restrictive_policy(const yume::server::AuthKeyPolicyMap& policies,
                               const std::string& fingerprint) {
    const auto it = policies.find(fingerprint);
    if (it == policies.end()) {
        throw std::runtime_error("authorization policy disappeared");
    }
    if (!it->second.allow_file.has_value() || *it->second.allow_file) {
        throw std::runtime_error("restrictive file policy was not preserved");
    }
    if (it->second.weight != 1.5) {
        throw std::runtime_error("authorization weight was not preserved");
    }
}

void test_concurrent_policy_reads_and_last_seen_updates() {
    TemporaryDirectory temporary;
    const auto meta_path = temporary.path() / "authorized_keys.json";
    const std::string fingerprint(64, 'a');
    {
        std::ofstream output(meta_path);
        output << "{\n  \"" << fingerprint
               << "\": {\"weight\": 1.5, \"permissions\": "
                  "{\"allow_file\": false}}\n}\n";
    }

    std::atomic<bool> failed{false};
    std::thread writer([&]() {
        for (int i = 0; i < 250; ++i) {
            std::string error;
            if (!yume::server::update_auth_meta(
                    meta_path.string(), fingerprint,
                    "client-" + std::to_string(i), &error)) {
                failed.store(true, std::memory_order_relaxed);
            }
        }
    });
    std::thread reader([&]() {
        for (int i = 0; i < 250; ++i) {
            try {
                assert_restrictive_policy(
                    yume::server::load_auth_policies(meta_path.string()),
                    fingerprint);
            } catch (...) {
                failed.store(true, std::memory_order_relaxed);
            }
        }
    });
    writer.join();
    reader.join();

    if (failed.load(std::memory_order_relaxed)) {
        throw std::runtime_error("concurrent authorization policy read failed");
    }
    assert_restrictive_policy(
        yume::server::load_auth_policies(meta_path.string()), fingerprint);
}

}  // namespace

int main() {
    test_concurrent_policy_reads_and_last_seen_updates();
    std::cout << "auth_policy_concurrency_test: all cases passed\n";
    return 0;
}
