/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/auth/auth.hpp"

#include <chrono>
#include <cmath>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

namespace {

class TemporaryPolicyFile {
public:
    TemporaryPolicyFile() {
        path_ = std::filesystem::temp_directory_path() /
                ("yume-auth-policy-values-" +
                 std::to_string(std::chrono::steady_clock::now()
                                    .time_since_epoch()
                                    .count()) +
                 ".json");
    }

    ~TemporaryPolicyFile() {
        std::error_code ignored;
        std::filesystem::remove(path_, ignored);
    }

    void write(const std::string& json) const {
        std::ofstream output(path_);
        output << json;
    }

    std::string path() const { return path_.string(); }

private:
    std::filesystem::path path_;
};

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void require_rejected(const TemporaryPolicyFile& file,
                      const std::string& json) {
    file.write(json);
    try {
        (void)yume::server::load_auth_policies(file.path());
    } catch (const std::runtime_error&) {
        return;
    }
    throw std::runtime_error("unsafe auth policy was accepted");
}

void test_bulk_weight_and_limit() {
    TemporaryPolicyFile file;
    const std::string fingerprint(64, 'b');
    file.write("{\"" + fingerprint +
               "\":{\"key_type\":\"bulk\",\"weight\":1.5,"
               "\"max_sessions\":100}}");
    const auto policies = yume::server::load_auth_policies(file.path());
    const auto it = policies.find(fingerprint);
    require(it != policies.end(), "bulk policy missing");
    require(it->second.key_type == yume::server::AuthKeyType::Bulk,
            "bulk key type not parsed");
    require(it->second.max_sessions == 100, "bulk session cap not parsed");
    require(std::abs(it->second.effective_weight() - 1.5) < 0.000001,
            "fractional weight not preserved");
}

void test_unsafe_combinations_fail_closed() {
    TemporaryPolicyFile file;
    const std::string fingerprint(64, 'c');
    const std::string prefix = "{\"" + fingerprint + "\":{";
    require_rejected(
        file, prefix +
                  "\"key_type\":\"bulk\",\"permissions\":{\"allow_exec\":true}}}");
    require_rejected(
        file, prefix + "\"key_type\":\"individual\",\"max_sessions\":2}}");
    require_rejected(
        file, prefix +
                  "\"key_type\":\"bulk\",\"permissions\":{"
                  "\"allow_codecs\":[\"monero-rpc\"]}}}");
    require_rejected(
        file, prefix +
                  "\"key_type\":\"bulk\",\"permissions\":{"
                  "\"allow_services\":[\"example-service-v1\"]}}}");
    require_rejected(file, prefix + "\"weight\":0}}");
    require_rejected(file, prefix + "\"key_type\":\"shared\"}}");
}

}  // namespace

int main() {
    test_bulk_weight_and_limit();
    test_unsafe_combinations_fail_closed();
    return 0;
}
