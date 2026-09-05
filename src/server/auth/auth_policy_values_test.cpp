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
#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

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
        secret_path_ = path_;
        secret_path_ += ".psk";
        std::ofstream secret(secret_path_, std::ios::binary);
        secret << std::string(64, 'a');
        secret.close();
        std::filesystem::permissions(
            secret_path_,
            std::filesystem::perms::owner_read |
                std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace);
    }

    ~TemporaryPolicyFile() {
        std::error_code ignored;
        std::filesystem::remove(path_, ignored);
        std::filesystem::remove(secret_path_, ignored);
    }

    void write(const std::string& json) const {
        std::ofstream output(path_);
        output << json;
    }

    std::string path() const { return path_.string(); }
    std::string secret_path() const { return secret_path_.string(); }
    std::string secret_filename() const {
        return secret_path_.filename().string();
    }

private:
    std::filesystem::path path_;
    std::filesystem::path secret_path_;
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
    require_rejected(
        file, prefix + "\"codec_allow\":[\"monero-rpc\"]}}");
    require_rejected(
        file, prefix +
                  "\"permissions\":{\"codec_allow\":[\"monero-rpc\"]}}}");
    require_rejected(file, prefix + "\"weight\":0}}");
    require_rejected(file, prefix + "\"key_type\":\"shared\"}}");
    for (const std::string field : {"priority", "allow_monero_rpc"}) {
        require_rejected(file, prefix + "\"" + field + "\":1}}");
        require_rejected(file, prefix + "\"permissions\":{\"" + field +
                                   "\":true}}}");
    }
    require_rejected(file, prefix + "\"allow_chat\":false}}");
    require_rejected(file, prefix +
                              "\"permissions\":{\"allow_chatt\":false}}}");
    const std::string psk = "\",\"federation_psk_file\":\"" +
                            file.secret_path() + "\"}}";
    require_rejected(file, prefix +
                              "\"federation_peer_id\":\"ambiguous:peer" + psk);
    require_rejected(file, prefix +
                              "\"federation_peer_id\":\"bad peer" + psk);
    require_rejected(file, prefix + "\"federation_peer_id\":\"" +
                              std::string(65, 'p') + psk);
    require_rejected(file, prefix +
                              "\"federation_peer_id\":\"edge-west\"}}");
    require_rejected(file, prefix +
                              "\"federation_psk_file\":\"" +
                              file.secret_path() + "\"}}");
    require_rejected(file, prefix + "\"federation_psk_file\":42}}");
    require_rejected(file, prefix +
                              "\"federation_peer_id\":\"edge-west\","
                              "\"federation_psk_file\":\"missing.psk\"}}");
}

void test_federation_peer_id_grammar() {
    TemporaryPolicyFile file;
    const std::string fingerprint(64, 'd');
    file.write("{\"" + fingerprint +
               "\":{\"federation_peer_id\":\"edge-west_2.example\"," +
               "\"federation_psk_file\":\"" + file.secret_filename() +
               "\"}}");
    const auto policies = yume::server::load_auth_policies(file.path());
    require(policies.at(fingerprint).federation_peer_id ==
                "edge-west_2.example",
            "valid federation peer id was not preserved");
    require(policies.at(fingerprint).federation_psk_material != nullptr,
            "federation PSK was not loaded with the policy snapshot");
}

void test_federation_peer_id_uniqueness() {
    TemporaryPolicyFile file;
    const std::string first(64, 'e');
    const std::string second(64, 'f');
    file.write("{\"" + first +
               "\":{\"federation_peer_id\":\"edge-west\"," +
               "\"federation_psk_file\":\"" + file.secret_path() +
               "\"},\"" + second +
               "\":{\"federation_peer_id\":\"edge-west\"," +
               "\"federation_psk_file\":\"" + file.secret_path() +
               "\"}}");
    bool rejected = false;
    try {
        (void)yume::server::load_auth_policies(file.path());
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    require(rejected,
            "duplicate federation peer ids must fail one-store loading");

    yume::server::AuthKeyPolicyMap regular;
    yume::server::AuthKeyPolicyMap operators;
    regular[first].federation_peer_id = "edge-east";
    operators[second].federation_peer_id = "edge-east";
    rejected = false;
    try {
        yume::server::validate_unique_federation_peer_ids(
            regular, operators);
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    require(rejected,
            "duplicate federation peer ids must fail cross-store loading");
}

}  // namespace

int main() {
#if !defined(_WIN32)
    {
        TemporaryPolicyFile file;
        require(::mkfifo(file.path().c_str(), 0600) == 0, "cannot create policy FIFO");
        ::alarm(3);
        bool refused = false;
        try { (void)yume::server::load_auth_policies(file.path()); }
        catch (const std::runtime_error&) { refused = true; }
        require(refused, "daemon accepted policy FIFO");
        refused = false;
        try { (void)yume::server::load_authorized_keys(file.path()); }
        catch (const std::runtime_error&) { refused = true; }
        require(refused, "daemon accepted identity FIFO");
        ::alarm(0);
    }
#endif
    test_bulk_weight_and_limit();
    test_unsafe_combinations_fail_closed();
    test_federation_peer_id_grammar();
    test_federation_peer_id_uniqueness();
    return 0;
}
