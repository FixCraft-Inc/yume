/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/cli/cluster.hpp"

#include <stdexcept>
#include <utility>

#include <nlohmann/json.hpp>

namespace yume::server::cli {

std::string expand_cluster_join_spec(const std::string& spec) {
    if (spec.empty()) {
        throw std::runtime_error("--cluster-join argument is empty");
    }
    std::string body = spec;
    std::string pin;
    std::string psk_file;
    std::string carrier_secret_file;
    auto qpos = body.find('?');
    if (qpos != std::string::npos) {
        std::string query = body.substr(qpos + 1);
        body.resize(qpos);
        std::size_t cursor = 0;
        while (cursor < query.size()) {
            auto amp = query.find('&', cursor);
            std::string pair = query.substr(cursor, amp == std::string::npos ? std::string::npos : amp - cursor);
            cursor = amp == std::string::npos ? query.size() : amp + 1;
            auto eq = pair.find('=');
            if (eq == std::string::npos) continue;
            std::string key = pair.substr(0, eq);
            std::string val = pair.substr(eq + 1);
            if (key == "pin") {
                pin = std::move(val);
            } else if (key == "psk_file") {
                psk_file = std::move(val);
            } else if (key == "carrier_secret_file") {
                carrier_secret_file = std::move(val);
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
    if (!hostport.empty() && hostport.front() == '[') {
        auto close = hostport.find(']');
        if (close == std::string::npos) {
            throw std::runtime_error("--cluster-join: unmatched '[' in " + spec);
        }
        host = hostport.substr(1, close - 1);
        if (close + 1 < hostport.size()) {
            if (hostport[close + 1] != ':') {
                throw std::runtime_error("--cluster-join: expected ':port' after ']' in " + spec);
            }
            try {
                port = std::stoi(hostport.substr(close + 2));
            } catch (const std::exception&) {
                throw std::runtime_error("--cluster-join: invalid port in " + spec);
            }
        }
    } else {
        auto colon = hostport.rfind(':');
        if (colon == std::string::npos) {
            host = hostport;
        } else {
            host = hostport.substr(0, colon);
            try {
                port = std::stoi(hostport.substr(colon + 1));
            } catch (const std::exception&) {
                throw std::runtime_error("--cluster-join: invalid port in " + spec);
            }
        }
    }
    if (host.empty()) {
        throw std::runtime_error("--cluster-join: empty host in " + spec);
    }
    if (port <= 0 || port > 65535) {
        throw std::runtime_error("--cluster-join: port out of range in " + spec);
    }
    if (psk_file.empty() || carrier_secret_file.empty()) {
        throw std::runtime_error(
            "--cluster-join requires psk_file and carrier_secret_file query parameters");
    }
    if (id.empty()) {
        id = host;
    }
    nlohmann::json peer;
    peer["id"] = id;
    peer["url"] = std::string("yume://") + (host.find(':') != std::string::npos
                                                ? "[" + host + "]"
                                                : host) +
                  ":" + std::to_string(port);
    if (!pin.empty()) {
        peer["tls_pin"] = pin;
    }
    peer["psk_file"] = std::move(psk_file);
    peer["carrier_secret_file"] = std::move(carrier_secret_file);
    return peer.dump();
}

}  // namespace yume::server::cli
