/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/parse/endpoints.hpp"

#include <iostream>
#include <string>

namespace {

int fail(const std::string& message) {
    std::cerr << message << '\n';
    return 1;
}

bool expect_bind(const std::string& text, const std::string& host, int port) {
    yume::client::BindEndpoint parsed;
    std::string error;
    if (!yume::client::parse_bind_endpoint(text, parsed, &error)) {
        std::cerr << "parse_bind_endpoint failed for '" << text << "': " << error << '\n';
        return false;
    }
    if (parsed.host != host || parsed.port != port) {
        std::cerr << "parse_bind_endpoint mismatch for '" << text << "'\n";
        return false;
    }
    return true;
}

bool expect_forward(const std::string& text,
                    const std::string& bind_host,
                    int listen_port,
                    const std::string& target_host,
                    int target_port) {
    yume::client::SshForwardSpec parsed;
    std::string error;
    if (!yume::client::parse_ssh_forward(text, parsed, &error)) {
        std::cerr << "parse_ssh_forward failed for '" << text << "': " << error << '\n';
        return false;
    }
    if (parsed.bind_host != bind_host ||
        parsed.listen_port != listen_port ||
        parsed.target_host != target_host ||
        parsed.target_port != target_port) {
        std::cerr << "parse_ssh_forward mismatch for '" << text << "'\n";
        return false;
    }
    return true;
}

bool expect_bind_reject(const std::string& text) {
    yume::client::BindEndpoint parsed;
    return !yume::client::parse_bind_endpoint(text, parsed);
}

bool expect_forward_reject(const std::string& text) {
    yume::client::SshForwardSpec parsed;
    return !yume::client::parse_ssh_forward(text, parsed);
}

}  // namespace

int main() {
    if (!expect_bind("1080", "", 1080)) return 1;
    if (!expect_bind("127.0.0.1:1080", "127.0.0.1", 1080)) return 1;
    if (!expect_bind("[::1]:1080", "::1", 1080)) return 1;

    if (!expect_bind_reject("localhost:1080")) return fail("hostname bind was accepted");
    if (!expect_bind_reject("::1:1080")) return fail("unbracketed IPv6 bind was accepted");
    if (!expect_bind_reject("127.0.0.1:0")) return fail("port 0 bind was accepted");

    if (!expect_forward("127.0.0.1:18089:target:18081",
                        "127.0.0.1",
                        18089,
                        "target",
                        18081)) return 1;
    if (!expect_forward("[::1]:2222:127.0.0.1:22",
                        "::1",
                        2222,
                        "127.0.0.1",
                        22)) return 1;
    if (!expect_forward("2222:127.0.0.1:22", "", 2222, "127.0.0.1", 22)) return 1;

    if (!expect_forward_reject("localhost:2222:127.0.0.1:22")) {
        return fail("hostname forward bind was accepted");
    }
    if (!expect_forward_reject("::1:2222:127.0.0.1:22")) {
        return fail("unbracketed IPv6 forward bind was accepted");
    }

    if (yume::client::format_bind_endpoint("", 1080) != "1080") {
        return fail("bare endpoint formatter changed compatibility output");
    }
    if (yume::client::format_bind_endpoint("::1", 1080) != "[::1]:1080") {
        return fail("IPv6 endpoint formatter did not bracket address");
    }
    if (yume::client::format_display_bind_endpoint("", 1080) != "0.0.0.0:1080") {
        return fail("display endpoint formatter did not show wildcard bind");
    }

    return 0;
}
