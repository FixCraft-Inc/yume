/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/federation/manager.hpp"

#include <algorithm>
#include <array>
#include <stdexcept>
#include <unordered_set>

#include "server/federation/link.hpp"
#include "server/runtime/manager.hpp"
#include "server/session/session.hpp"
#include "util.hpp"

namespace yume::server {

namespace {

bool ends_with(std::string const& value, std::string const& suffix) {
    return value.size() >= suffix.size() &&
           value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

}  // namespace

FederationManager::FederationManager(boost::asio::io_context& io,
                                     const ServerConfig& cfg,
                                     Manager* manager)
    : io_(io)
    , cfg_(cfg)
    , manager_(manager) {}

FederationManager::~FederationManager() {
    stop();
}

FederationPeer FederationManager::parse_peer(const std::string& raw) {
    auto json = nlohmann::json::parse(raw);
    if (!json.is_object()) {
        throw std::runtime_error("peer entry must be a JSON object");
    }
    constexpr std::array<std::string_view, 5> kPeerFields{
        "id", "url", "tls_pin", "psk_file", "carrier_secret_file"};
    for (auto field = json.begin(); field != json.end(); ++field) {
        if (std::find(kPeerFields.begin(), kPeerFields.end(), field.key()) ==
            kPeerFields.end()) {
            throw std::runtime_error(
                "peer entry contains an unsupported field: " + field.key());
        }
        if (!field->is_string()) {
            throw std::runtime_error(
                "peer field must be a string: " + field.key());
        }
    }
    for (const char* required : {"id", "url", "psk_file",
                                 "carrier_secret_file"}) {
        if (!json.contains(required)) {
            throw std::runtime_error(
                std::string("peer entry is missing required field: ") +
                required);
        }
    }
    FederationPeer peer;
    peer.raw_json = raw;
    peer.id = json.value("id", "");
    peer.tls_pin_sha256 = json.value("tls_pin", "");
    peer.psk_file = json.value("psk_file", "");
    peer.carrier_secret_file = json.value("carrier_secret_file", "");
    const std::string url = json.value("url", "");
    constexpr std::string_view scheme = "yume://";
    if (!is_valid_federation_peer_id(peer.id) ||
        url.rfind(scheme, 0) != 0) {
        throw std::runtime_error("peer requires id and yume://host:port url");
    }
    if (!peer.tls_pin_sha256.empty() &&
        !is_valid_federation_tls_pin(peer.tls_pin_sha256)) {
        throw std::runtime_error(
            "peer tls_pin must be exactly 64 lowercase hexadecimal characters");
    }
    std::string hostport = url.substr(scheme.size());
    if (hostport.find_first_of("/?#") != std::string::npos) {
        throw std::runtime_error(
            "peer url must contain only yume://host:port");
    }
    std::string_view port_text;
    if (!hostport.empty() && hostport.front() == '[') {
        const auto close = hostport.find(']');
        if (close == std::string::npos || close + 1U >= hostport.size() ||
            hostport[close + 1U] != ':') {
            throw std::runtime_error(
                "peer IPv6 url requires [host]:port");
        }
        peer.host = hostport.substr(1U, close - 1U);
        port_text = std::string_view(hostport).substr(close + 2U);
    } else {
        const auto colon = hostport.find(':');
        if (colon == std::string::npos) {
            throw std::runtime_error("peer url missing :port");
        }
        if (colon != hostport.rfind(':')) {
            throw std::runtime_error(
                "peer IPv6 url requires brackets around the host");
        }
        peer.host = hostport.substr(0U, colon);
        port_text = std::string_view(hostport).substr(colon + 1U);
    }
    if (peer.host.empty() ||
        !parse_federation_port(port_text, &peer.port)) {
        throw std::runtime_error("peer url host/port invalid");
    }
    if (peer.psk_file.empty()) {
        throw std::runtime_error("peer requires psk_file (pairwise AUTH v2 PSK)");
    }
    if (peer.carrier_secret_file.empty()) {
        throw std::runtime_error(
            "peer requires carrier_secret_file (the peer's --obfs-secret value; "
            "YUME 2.0 federation dials pass the same H2 admission as clients)");
    }
    return peer;
}

void FederationManager::start() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::unordered_set<std::string> configured_ids;
    for (const auto& raw : cfg_.federation_peers) {
        try {
            auto peer = parse_peer(raw);
            if (!configured_ids.insert(peer.id).second) {
                util::log_warn("duplicate federation peer id rejected: " +
                               peer.id);
                continue;
            }
            if (links_.find(peer.id) != links_.end()) {
                util::log_warn("federation peer already started: " + peer.id);
                continue;
            }
            if (ends_with(peer.host, ".onion") && cfg_.outbound_proxy_url.empty()) {
                util::log_warn("federation peer " + peer.id + " uses .onion; outbound_proxy is required");
                continue;
            }
            auto link = std::make_shared<FederationLink>(io_, cfg_, peer, this);
            // Publish ownership before starting worker threads. If thread
            // construction throws after one worker starts, stop() can still
            // find and join the partially started link.
            const bool inserted = links_.emplace(peer.id, link).second;
            if (!inserted) {
                util::log_warn("duplicate federation peer id rejected: " +
                               peer.id);
                continue;
            }
            link->start();
        } catch (const std::exception& ex) {
            util::log_warn("federation peer setup failed: " + std::string(ex.what()));
        }
    }
    if (links_.empty()) {
        if (cfg_.cluster_bootstrap && cfg_.federation_peers.empty()) {
            util::log_info(
                "federation bootstrap enabled; awaiting authenticated "
                "inbound peers");
        } else {
            util::log_warn(
                "federation enabled but no usable outbound peers were "
                "configured");
        }
    }
}

void FederationManager::stop() {
    std::vector<std::shared_ptr<FederationLink>> links;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& entry : links_) {
            links.push_back(entry.second);
        }
        links_.clear();
        remote_by_visible_id_.clear();
    }
    for (auto& link : links) {
        if (link) {
            link->close();
        }
    }
}

std::shared_ptr<FederationLink> FederationManager::find(const std::string& peer_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = links_.find(peer_id);
    return it == links_.end() ? nullptr : it->second;
}

std::vector<control::EndpointInfo> FederationManager::remote_endpoints(
        std::size_t limit) const {
    limit = std::min(limit, control::kMaxFederatedCachedEndpoints);
    std::vector<control::EndpointInfo> out;
    if (limit == 0U) return out;
    std::lock_guard<std::mutex> lock(mutex_);
    out.reserve(std::min(remote_by_visible_id_.size(), limit));
    for (const auto& entry : remote_by_visible_id_) {
        out.push_back(entry.second);
        if (out.size() == limit) break;
    }
    return out;
}

bool FederationManager::resolve_remote_endpoint(const std::string& visible_id,
                                                std::string* peer_id,
                                                std::string* remote_id,
                                                control::EndpointInfo* info) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = remote_by_visible_id_.find(visible_id);
    if (it == remote_by_visible_id_.end()) {
        return false;
    }
    if (peer_id) {
        *peer_id = it->second.federation_peer_id;
    }
    if (remote_id) {
        *remote_id = it->second.remote_endpoint_id;
    }
    if (info) {
        *info = it->second;
    }
    return true;
}

bool FederationManager::send_invite_request(const control::PendingInvite& invite,
                                            const std::string& peer_id,
                                            const std::string& remote_id,
                                            std::string* error) {
    auto link = find(peer_id);
    if (!link) {
        if (error) {
            *error = "federation peer unavailable";
        }
        return false;
    }
    return link->send_invite_request(invite, remote_id, error);
}

bool FederationManager::open_channel(const std::shared_ptr<Session>& origin,
                                     std::uint8_t origin_stream_id,
                                     const control::PendingInvite& invite,
                                     const nlohmann::json& open_json,
                                     std::string* error) {
    std::string peer_id;
    std::string remote_id;
    if (!resolve_remote_endpoint(invite.to_endpoint_id, &peer_id, &remote_id, nullptr)) {
        if (error) {
            *error = "remote target unavailable";
        }
        return false;
    }
    auto link = find(peer_id);
    if (!link) {
        if (error) {
            *error = "federation peer unavailable";
        }
        return false;
    }
    return link->open_channel(origin, origin_stream_id, invite, open_json, error);
}

bool FederationManager::handle_invite_reply(const std::string& peer_id,
                                            const control::PendingInvite& reply,
                                            std::shared_ptr<Session>* initiator,
                                            control::PendingInvite* invite_out,
                                            std::string* error) {
    if (!manager_) {
        if (error) {
            *error = "manager unavailable";
        }
        return false;
    }
    return manager_->respond_federated_invite(peer_id, reply, initiator, invite_out, error);
}

void FederationManager::update_directory(const std::string& peer_id,
                                         const std::string& server_id,
                                         const std::string& server_name,
                                         const std::vector<control::EndpointInfo>& endpoints) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = remote_by_visible_id_.begin(); it != remote_by_visible_id_.end();) {
        if (it->second.federation_peer_id == peer_id) {
            it = remote_by_visible_id_.erase(it);
        } else {
            ++it;
        }
    }
    for (auto endpoint : endpoints) {
        if (remote_by_visible_id_.size() >=
                control::kMaxFederatedCachedEndpoints ||
            !control::directory_endpoint_accounted_bytes(
                endpoint, control::DirectoryNamespace::FederationRaw)) {
            continue;
        }
        const auto visible_id =
            control::try_make_federated_visible_endpoint_id(
                peer_id, endpoint.endpoint_id);
        if (!visible_id) {
            continue;
        }
        endpoint.remote = true;
        endpoint.federation_peer_id = peer_id;
        endpoint.remote_endpoint_id = endpoint.endpoint_id;
        endpoint.endpoint_id = *visible_id;
        // Relationship IDs are meaningful only inside the advertising
        // server's namespace and are never consulted for federated routing or
        // authorization. Do not transpose them into this server's namespace.
        endpoint.controller_ids.clear();
        endpoint.controlled_target_ids.clear();
        if (endpoint.server_id.empty()) {
            endpoint.server_id = server_id;
        }
        if (endpoint.server_name.empty()) {
            endpoint.server_name = server_name;
        }
        endpoint.online = true;
        if (!control::directory_endpoint_accounted_bytes(
                endpoint, control::DirectoryNamespace::ClientVisible)) {
            continue;
        }
        remote_by_visible_id_[endpoint.endpoint_id] = std::move(endpoint);
    }
}

void FederationManager::clear_directory(const std::string& peer_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = remote_by_visible_id_.begin();
         it != remote_by_visible_id_.end();) {
        if (it->second.federation_peer_id == peer_id) {
            it = remote_by_visible_id_.erase(it);
        } else {
            ++it;
        }
    }
}

ConfiguredFederationPeers FederationManager::configured_peers() const {
    return configured_peers(cfg_);
}

ConfiguredFederationPeers FederationManager::configured_peers(
        const ServerConfig& cfg) {
    ConfiguredFederationPeers snapshot;
    snapshot.peers.reserve(cfg.federation_peers.size());
    std::unordered_set<std::string> configured_ids;
    for (const auto& raw : cfg.federation_peers) {
        try {
            const auto peer = parse_peer(raw);
            // start() keeps the first valid occurrence of an id. Mirror that
            // exact choice so conflicting duplicate rows cannot make status
            // describe a different dial target than the live manager used.
            if (!configured_ids.insert(peer.id).second) {
                ++snapshot.invalid_entries;
                continue;
            }
            snapshot.peers.push_back(ConfiguredFederationPeer{
                peer.id,
                peer.host,
                peer.port,
                !peer.tls_pin_sha256.empty(),
                !peer.psk_file.empty(),
                !peer.carrier_secret_file.empty(),
            });
        } catch (const std::exception&) {
            // An active manager's start() already logged why this entry was
            // rejected. Report only that one exists: the raw string holds the
            // operator's PSK and carrier-secret paths and must not reach a
            // reporting surface, including the pre-manager status path.
            ++snapshot.invalid_entries;
        }
    }
    return snapshot;
}

std::vector<FederationPeerStatus> FederationManager::statuses() const {
    std::vector<std::shared_ptr<FederationLink>> links;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        links.reserve(links_.size());
        for (const auto& entry : links_) {
            links.push_back(entry.second);
        }
    }
    std::vector<FederationPeerStatus> out;
    out.reserve(links.size());
    for (const auto& link : links) {
        if (link) {
            out.push_back(link->status());
        }
    }
    std::sort(out.begin(), out.end(), [](const auto& a, const auto& b) {
        return a.id < b.id;
    });
    return out;
}

}  // namespace yume::server
