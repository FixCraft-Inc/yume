/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// Startup admission refusals that exist to keep a deployment from shipping a
// global fingerprint or an unnamed third-party observer. Both are checked
// before any live probe, so this test needs no listening backend.

#include <iostream>
#include <string>

#include "server/config/config.hpp"
#include "server/packet/tun_egress.hpp"
#include "server/runtime/security_config.hpp"

namespace {

bool expect(bool condition, const char* what) {
    if (!condition) {
        std::cerr << "FAIL: " << what << '\n';
    }
    return condition;
}

// A configuration that reaches the cover-source gate: everything the gate
// depends on is set, and nothing after it is.
yume::server::ServerConfig config_reaching_cover_gate() {
    yume::server::ServerConfig cfg;
    cfg.obfs_secret_file = "obfs.secret";
    cfg.inner_psk_file = "inner.psk";
    cfg.obfuscation = true;
    cfg.inner_crypto = true;
    cfg.obfs_pad_multiple = 0;
    cfg.obfs_jitter_ms = 0;
    cfg.real_http = true;
    cfg.real_backend = "loopback://127.0.0.1:1";
    return cfg;
}

bool test_cover_source_is_required() {
    auto cfg = config_reaching_cover_gate();
    std::string error;
    if (!expect(!yume::server::prepare_v2_security_config(cfg, false, &error),
                "a server with no cover source must refuse to start") ||
        !expect(error.find("no cover source is configured") != std::string::npos,
                "the refusal must say what is missing")) {
        return false;
    }
    if (!expect(error.find("--upstream-response-dir") != std::string::npos &&
                    error.find("--real-root") != std::string::npos &&
                    error.find("--real-index") != std::string::npos,
                "the refusal must name every way to satisfy it")) {
        return false;
    }

    // Each accepted source moves past the gate. The live backend probe that
    // follows fails here, which is a different message: reaching it proves the
    // cover gate let the configuration through.
    for (const char* source : {"dir", "file", "bytes", "root", "index"}) {
        auto accepted = config_reaching_cover_gate();
        const std::string which = source;
        if (which == "dir") accepted.upstream_response_dir = "/captures";
        if (which == "file") accepted.upstream_response_file = "/capture.http";
        if (which == "bytes") accepted.upstream_response_bytes = "HTTP/1.1 200";
        if (which == "root") accepted.real_root = "/srv/site";
        if (which == "index") accepted.real_index_path = "/srv/index.html";
        std::string accepted_error;
        yume::server::prepare_v2_security_config(accepted, false,
                                                 &accepted_error);
        if (!expect(accepted_error.find("no cover source") == std::string::npos,
                    "a configured cover source must pass the gate")) {
            std::cerr << "  source: " << which << '\n';
            return false;
        }
    }
    return true;
}

// The resolver handed to packet-mode clients observes every hostname they look
// up, so it is named by the operator or the daemon does not run packet mode.
bool test_packet_dns_has_no_default() {
    yume::server::ServerConfig cfg;
    if (!expect(!yume::server::packet_dns_configured(cfg),
                "an unset resolver is not configured")) {
        return false;
    }
    cfg.dns_server = "not-an-address";
    if (!expect(!yume::server::packet_dns_configured(cfg),
                "a non-IPv4 resolver is not configured")) {
        return false;
    }
    cfg.dns_server = "2001:db8::53";
    if (!expect(!yume::server::packet_dns_configured(cfg),
                "packet mode advertises IPv4 resolvers only")) {
        return false;
    }
    cfg.dns_server = "192.0.2.53";
    return expect(yume::server::packet_dns_configured(cfg),
                  "an IPv4 literal is configured");
}

}  // namespace

int main() {
    return test_cover_source_is_required() && test_packet_dns_has_no_default()
               ? 0
               : 1;
}
