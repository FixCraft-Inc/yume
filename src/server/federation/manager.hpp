#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <boost/asio.hpp>
#include <nlohmann/json.hpp>

#include "core/control_protocol.hpp"
#include "server/config/config.hpp"
#include "server/federation/types.hpp"

namespace yume::server {

class FederationLink;
class Manager;
class Session;

class FederationManager {
public:
    FederationManager(boost::asio::io_context& io, const ServerConfig& cfg, Manager* manager);
    ~FederationManager();

    void start();
    void stop();

    std::shared_ptr<FederationLink> find(const std::string& peer_id) const;
    std::vector<control::EndpointInfo> remote_endpoints() const;
    bool resolve_remote_endpoint(const std::string& visible_id,
                                 std::string* peer_id,
                                 std::string* remote_id,
                                 control::EndpointInfo* info = nullptr) const;

    bool send_invite_request(const control::PendingInvite& invite,
                             const std::string& peer_id,
                             const std::string& remote_id,
                             std::string* error);
    bool open_channel(const std::shared_ptr<Session>& origin,
                      std::uint8_t origin_stream_id,
                      const control::PendingInvite& invite,
                      const nlohmann::json& open_json,
                      std::string* error);
    bool handle_invite_reply(const std::string& peer_id,
                             const control::PendingInvite& reply,
                             std::shared_ptr<Session>* initiator,
                             control::PendingInvite* invite_out,
                             std::string* error);
    void update_directory(const std::string& peer_id,
                          const std::string& server_id,
                          const std::string& server_name,
                          const std::vector<control::EndpointInfo>& endpoints);
    std::vector<FederationPeerStatus> statuses() const;

private:
    static FederationPeer parse_peer(const std::string& raw);

    boost::asio::io_context& io_;
    ServerConfig cfg_;
    Manager* manager_{nullptr};
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::shared_ptr<FederationLink>> links_;
    std::unordered_map<std::string, control::EndpointInfo> remote_by_visible_id_;
};

}  // namespace yume::server
