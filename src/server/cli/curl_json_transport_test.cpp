/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/cli/curl_json_transport.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {

class TemporaryDirectory final {
public:
    TemporaryDirectory() {
        std::string pattern =
            (std::filesystem::temp_directory_path() /
             "yume-anonym-curl-test-XXXXXX").string();
        char* created = ::mkdtemp(pattern.data());
        if (!created) {
            throw std::runtime_error("mkdtemp failed");
        }
        path_ = created;
    }

    TemporaryDirectory(const TemporaryDirectory&) = delete;
    TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
};

class ScopedEnvironment final {
public:
    ScopedEnvironment(const char* name, const std::string& value)
        : name_(name) {
        if (const char* current = std::getenv(name)) {
            previous_ = current;
            had_previous_ = true;
        }
        if (::setenv(name, value.c_str(), 1) != 0) {
            throw std::runtime_error("setenv failed");
        }
    }

    ScopedEnvironment(const ScopedEnvironment&) = delete;
    ScopedEnvironment& operator=(const ScopedEnvironment&) = delete;

    ~ScopedEnvironment() {
        if (had_previous_) {
            (void)::setenv(name_.c_str(), previous_.c_str(), 1);
        } else {
            (void)::unsetenv(name_.c_str());
        }
    }

private:
    std::string name_;
    std::string previous_;
    bool had_previous_{false};
};

bool Require(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        return false;
    }
    return true;
}

std::string ReadLine(std::ifstream& input) {
    std::string line;
    std::getline(input, line);
    return line;
}

}  // namespace

int main() {
    using yume::server::cli::detail::HttpsEndpoint;
    using yume::server::cli::detail::parse_https_endpoint;

    const auto endpoint = parse_https_endpoint(
        "https://example.invalid:8443/proof?mode=strict");
    if (!Require(endpoint.host == "example.invalid", "HTTPS host parse") ||
        !Require(endpoint.port == "8443", "HTTPS port parse") ||
        !Require(endpoint.target == "/proof?mode=strict",
                 "HTTPS target parse") ||
        !Require(
            yume::server::cli::detail::https_authority(endpoint) ==
                "example.invalid:8443",
            "HTTPS authority render")) {
        return 1;
    }
    const auto ipv6_endpoint = parse_https_endpoint(
        "https://[2001:db8::1]/proof");
    if (!Require(ipv6_endpoint.host == "2001:db8::1",
                 "IPv6 host parse") ||
        !Require(ipv6_endpoint.port == "443", "IPv6 default port") ||
        !Require(
            yume::server::cli::detail::https_authority(ipv6_endpoint) ==
                "[2001:db8::1]",
            "IPv6 authority render") ||
        !Require(
            parse_https_endpoint("https://example.invalid?probe=1").target ==
                "/?probe=1",
            "query-only target parse")) {
        return 1;
    }

    const std::string invalid_urls[] = {
        "http://example.invalid/proof",
        "https://",
        "https://user@example.invalid/proof",
        "https://example.invalid:0/proof",
        "https://example.invalid:/proof",
        "https://example.invalid:65536/proof",
        "https://example.invalid:not-a-port/proof",
        "https://2001:db8::1/proof",
        "https://[not-ipv6]/proof",
        "https://[2001:db8::1]:/proof",
        "https://[fe80::1%25eth0]/proof",
        "https://example.invalid/proof#fragment",
        "https://example.invalid/bad target",
        "https://example.invalid/bad\nheader",
    };
    for (const auto& invalid_url : invalid_urls) {
        bool rejected = false;
        try {
            (void)parse_https_endpoint(invalid_url);
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        if (!Require(rejected, "invalid HTTPS endpoint was accepted")) {
            return 1;
        }
    }

    using yume::server::cli::detail::require_operator_proof_signature;
    if (!Require(
            require_operator_proof_signature(
                nlohmann::json{{"sig", "canonical-signature"}}) ==
                "canonical-signature",
            "operator proof signature extraction")) {
        return 1;
    }
    const nlohmann::json invalid_responses[] = {
        nlohmann::json::array(),
        nlohmann::json::object(),
        nlohmann::json{{"sig", nullptr}},
        nlohmann::json{{"sig", ""}},
        nlohmann::json{{"sig", "bad\nvalue"}},
        nlohmann::json{{"sig", std::string(129U, 'A')}},
    };
    for (const auto& invalid_response : invalid_responses) {
        bool rejected = false;
        try {
            (void)require_operator_proof_signature(invalid_response);
        } catch (const std::runtime_error&) {
            rejected = true;
        }
        if (!Require(rejected,
                     "invalid operator proof response was accepted")) {
            return 1;
        }
    }

    TemporaryDirectory temporary;
    const auto fake_curl = temporary.path() / "curl";
    const auto record_path = temporary.path() / "record";
    {
        std::ofstream script(fake_curl);
        script << R"SH(#!/bin/sh
config_file=
payload_file=
previous=
for argument in "$@"; do
    case "$argument" in
        *token-sentinel-with-spaces*)
            echo "token leaked through argv"
            exit 90
            ;;
        *proxy-secret*)
            echo "proxy credentials leaked through argv"
            exit 89
            ;;
    esac
    if [ "$previous" = "--config" ]; then
        config_file=$argument
    fi
    previous=$argument
done
if [ -z "$config_file" ]; then
    echo "private curl config missing"
    exit 91
fi
if [ -n "${HTTPS_PROXY+x}" ]; then
    echo "ambient proxy environment leaked into curl"
    exit 87
fi
if [ -e "/proc/self/fd/$YUME_TEST_CURL_LEAK_FD" ]; then
    echo "unrelated parent descriptor leaked into curl"
    exit 88
fi
payload_file=$(/usr/bin/sed -n \
    's/^data-binary = "@\(.*\)"$/\1/p' "$config_file") || exit 97
if [ -z "$payload_file" ]; then
    echo "private request files missing"
    exit 91
fi
config_mode=$(/usr/bin/stat -c %a "$config_file") || exit 92
payload_mode=$(/usr/bin/stat -c %a "$payload_file") || exit 93
parent_directory=${config_file%/*}
parent_mode=$(/usr/bin/stat -c %a "$parent_directory") || exit 96
/usr/bin/grep -Fqx -- \
    'header = "X-FC-VERITY-TOKEN: token-sentinel-with-spaces"' \
    "$config_file" || exit 94
/usr/bin/grep -Fqx -- \
    'proxy = "socks5h://proxy-user:proxy-secret@127.0.0.1:9050"' \
    "$config_file" || exit 98
/usr/bin/grep -Fqx -- '{"probe":"value"}' "$payload_file" || exit 95
printf '%s\n%s\n%s\n%s\n%s\n' \
    "$config_file" "$payload_file" "$config_mode" "$payload_mode" \
    "$parent_mode" \
    > "$YUME_TEST_CURL_RECORD"
if [ "$YUME_TEST_CURL_FAIL" = "1" ]; then
    echo "forced curl failure"
    exit 96
fi
printf '{"ok":true}\n'
)SH";
    }
    if (!Require(
            ::chmod(fake_curl.c_str(),
                    S_IRUSR | S_IWUSR | S_IXUSR) == 0,
            "chmod fake curl")) {
        return 1;
    }

    ScopedEnvironment executable_environment(
        "YUME_ANONYM_CURL_EXECUTABLE", fake_curl.string());
    ScopedEnvironment record_environment(
        "YUME_TEST_CURL_RECORD", record_path.string());
    const auto descriptor_sentinel = temporary.path() / "descriptor-sentinel";
    {
        std::ofstream sentinel(descriptor_sentinel);
        sentinel << "must not reach curl\n";
    }
    const int sentinel_source = ::open(descriptor_sentinel.c_str(), O_RDONLY);
    if (!Require(sentinel_source >= 0, "open descriptor sentinel")) {
        return 1;
    }
    const int inherited_sentinel = ::fcntl(sentinel_source, F_DUPFD, 64);
    (void)::close(sentinel_source);
    if (!Require(inherited_sentinel >= 64,
                 "create inheritable descriptor sentinel")) {
        return 1;
    }
    ScopedEnvironment leak_fd_environment(
        "YUME_TEST_CURL_LEAK_FD", std::to_string(inherited_sentinel));
    ScopedEnvironment ambient_proxy_environment(
        "HTTPS_PROXY", "http://ambient-proxy-secret.invalid:8080");

    const HttpsEndpoint request_endpoint =
        parse_https_endpoint("https://example.invalid/proof");
    const auto response = yume::server::cli::detail::post_json_https_via_curl(
        request_endpoint,
        nlohmann::json{{"probe", "value"}},
        "token-sentinel-with-spaces",
        "socks5://proxy-user:proxy-secret@127.0.0.1:9050");
    if (!Require(response.is_object(), "curl response is not an object") ||
        !Require(response.at("ok").get<bool>(),
                 "curl response did not report success")) {
        (void)::close(inherited_sentinel);
        return 1;
    }
    (void)::close(inherited_sentinel);

    std::ifstream record(record_path);
    if (!Require(static_cast<bool>(record), "fake curl record missing")) {
        return 1;
    }
    const std::filesystem::path config_path = ReadLine(record);
    const std::filesystem::path payload_path = ReadLine(record);
    const std::string config_mode = ReadLine(record);
    const std::string payload_mode = ReadLine(record);
    const std::string parent_mode = ReadLine(record);
    if (!Require(config_mode == "600", "config file is not mode 0600") ||
        !Require(payload_mode == "600", "payload file is not mode 0600") ||
        !Require(parent_mode == "700", "request directory is not mode 0700") ||
        !Require(!std::filesystem::exists(config_path),
                 "config file survived request cleanup") ||
        !Require(!std::filesystem::exists(payload_path),
                 "payload file survived request cleanup") ||
        !Require(!std::filesystem::exists(config_path.parent_path()),
                 "private directory survived request cleanup")) {
        return 1;
    }

    bool rejected_curl_failure = false;
    {
        ScopedEnvironment fail_environment("YUME_TEST_CURL_FAIL", "1");
        try {
            (void)yume::server::cli::detail::post_json_https_via_curl(
                request_endpoint,
                nlohmann::json{{"probe", "value"}},
                "token-sentinel-with-spaces",
                "socks5://proxy-user:proxy-secret@127.0.0.1:9050");
        } catch (const std::runtime_error&) {
            rejected_curl_failure = true;
        }
    }
    if (!Require(rejected_curl_failure, "curl failure was accepted")) {
        return 1;
    }
    std::ifstream failed_record(record_path);
    if (!Require(static_cast<bool>(failed_record),
                 "failed curl record missing")) {
        return 1;
    }
    const std::filesystem::path failed_config_path = ReadLine(failed_record);
    const std::filesystem::path failed_payload_path = ReadLine(failed_record);
    if (!Require(!std::filesystem::exists(failed_config_path),
                 "config file survived curl failure") ||
        !Require(!std::filesystem::exists(failed_payload_path),
                 "payload file survived curl failure") ||
        !Require(
            !std::filesystem::exists(failed_config_path.parent_path()),
            "private directory survived curl failure")) {
        return 1;
    }

    bool rejected_newline = false;
    try {
        (void)yume::server::cli::detail::post_json_https_via_curl(
            request_endpoint, nlohmann::json::object(),
            "bad\nheader", "");
    } catch (const std::invalid_argument&) {
        rejected_newline = true;
    }
    if (!Require(rejected_newline, "newline-bearing token was accepted")) {
        return 1;
    }

    if (!Require(
            ::chmod(fake_curl.c_str(),
                    S_IRWXU | S_IRWXG | S_IRWXO) == 0,
            "make fake curl unsafe")) {
        return 1;
    }
    bool rejected_unsafe_executable = false;
    try {
        (void)yume::server::cli::detail::post_json_https_via_curl(
            request_endpoint, nlohmann::json::object(),
            "token-sentinel-with-spaces", "");
    } catch (const std::runtime_error&) {
        rejected_unsafe_executable = true;
    }
    if (!Require(rejected_unsafe_executable,
                 "group/world-writable curl executable was accepted")) {
        return 1;
    }
    return 0;
}
