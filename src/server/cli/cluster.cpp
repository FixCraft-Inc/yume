/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/cli/cluster.hpp"

#include <stdexcept>
#include <utility>

#include <nlohmann/json.hpp>

#include "server/federation/types.hpp"

namespace yume::server::cli {

std::string expand_cluster_join_spec(const std::string& spec) {
    if (spec.empty()) {
        throw std::runtime_error("--cluster-join argument is empty");
    }
    std::string body = spec;
    std::string pin;
    std::string psk_file;
    std::string carrier_secret_file;
    bool saw_pin = false;
    bool saw_psk = false;
    bool saw_carrier_secret = false;
    auto qpos = body.find('?');
    if (qpos != std::string::npos) {
        std::string query = body.substr(qpos + 1);
        body.resize(qpos);
        if (query.empty() || query.back() == '&') {
            throw std::runtime_error(
                "--cluster-join: query entries must be non-empty key=value pairs");
        }
        std::size_t cursor = 0;
        while (cursor < query.size()) {
            auto amp = query.find('&', cursor);
            std::string pair = query.substr(cursor, amp == std::string::npos ? std::string::npos : amp - cursor);
            cursor = amp == std::string::npos ? query.size() : amp + 1;
            auto eq = pair.find('=');
            if (pair.empty() || eq == std::string::npos || eq == 0U ||
                eq + 1U >= pair.size()) {
                throw std::runtime_error(
                    "--cluster-join: query entries must be non-empty key=value pairs");
            }
            std::string key = pair.substr(0, eq);
            std::string val = pair.substr(eq + 1);
            if (key == "pin") {
                if (saw_pin) {
                    throw std::runtime_error(
                        "--cluster-join: duplicate pin query parameter");
                }
                saw_pin = true;
                pin = std::move(val);
            } else if (key == "psk_file") {
                if (saw_psk) {
                    throw std::runtime_error(
                        "--cluster-join: duplicate psk_file query parameter");
                }
                saw_psk = true;
                psk_file = std::move(val);
            } else if (key == "carrier_secret_file") {
                if (saw_carrier_secret) {
                    throw std::runtime_error(
                        "--cluster-join: duplicate carrier_secret_file query parameter");
                }
                saw_carrier_secret = true;
                carrier_secret_file = std::move(val);
            } else {
                throw std::runtime_error(
                    "--cluster-join: unsupported query parameter: " + key);
            }
        }
    }
    std::string id;
    std::string hostport = body;
    auto at = body.find('@');
    if (at != std::string::npos) {
        id = body.substr(0, at);
        hostport = body.substr(at + 1);
    }
    std::string host;
    int port = 443;
    bool bracketed_host = false;
    if (!hostport.empty() && hostport.front() == '[') {
        bracketed_host = true;
        auto close = hostport.find(']');
        if (close == std::string::npos) {
            throw std::runtime_error("--cluster-join: unmatched '[' in " + spec);
        }
        host = hostport.substr(1, close - 1);
        if (close + 1 < hostport.size()) {
            if (hostport[close + 1] != ':') {
                throw std::runtime_error("--cluster-join: expected ':port' after ']' in " + spec);
            }
            if (!parse_federation_port(
                    std::string_view(hostport).substr(close + 2U), &port)) {
                throw std::runtime_error("--cluster-join: invalid port in " + spec);
            }
        }
    } else {
        const auto colon = hostport.find(':');
        if (colon == std::string::npos) {
            host = hostport;
        } else {
            if (colon != hostport.rfind(':')) {
                throw std::runtime_error(
                    "--cluster-join: IPv6 hosts must be bracketed");
            }
            host = hostport.substr(0, colon);
            if (!parse_federation_port(
                    std::string_view(hostport).substr(colon + 1U), &port)) {
                throw std::runtime_error("--cluster-join: invalid port in " + spec);
            }
        }
    }
    if (host.empty()) {
        throw std::runtime_error("--cluster-join: empty host in " + spec);
    }
    if (psk_file.empty() || carrier_secret_file.empty()) {
        throw std::runtime_error(
            "--cluster-join requires psk_file and carrier_secret_file query parameters");
    }
    if (!pin.empty() && !is_valid_federation_tls_pin(pin)) {
        throw std::runtime_error(
            "--cluster-join pin must be exactly 64 lowercase hexadecimal characters");
    }
    if (id.empty()) {
        if (bracketed_host || host.find(':') != std::string::npos) {
            throw std::runtime_error(
                "--cluster-join: bracketed IPv6 requires an explicit id@ prefix");
        }
        id = host;
    }
    if (!is_valid_federation_peer_id(id)) {
        throw std::runtime_error("--cluster-join: invalid federation peer id");
    }
    nlohmann::json peer;
    peer["id"] = id;
    peer["url"] = std::string("yume://") +
                  format_federation_host_port(host, port);
    if (!pin.empty()) {
        peer["tls_pin"] = pin;
    }
    peer["psk_file"] = std::move(psk_file);
    peer["carrier_secret_file"] = std::move(carrier_secret_file);
    return peer.dump();
}

}  // namespace yume::server::cli
