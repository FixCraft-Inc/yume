#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <nlohmann/json.hpp>

#include "client/transport/core.hpp"
#include "core/protocol/control_protocol.hpp"
#include "server/config/config.hpp"
#include "server/federation/types.hpp"

namespace yume::server {

class FederationManager;
class Session;

class FederationLink : public std::enable_shared_from_this<FederationLink> {
public:
    FederationLink(boost::asio::io_context& server_io,
                   const ServerConfig& cfg,
                   const FederationPeer& peer,
                   FederationManager* owner);
    ~FederationLink();

    void start();
    void close();
    bool is_ready() const;
    const std::string& peer_id() const { return peer_.id; }
    std::string remote_namespace_for_local() const;
    FederationPeerStatus status() const;

    bool send_invite_request(const control::PendingInvite& invite,
                             const std::string& raw_remote_id,
                             std::string* error);
    bool open_channel(const std::shared_ptr<Session>& origin,
                      std::uint8_t origin_stream_id,
                      const control::PendingInvite& invite,
                      const nlohmann::json& open_json,
                      std::string* error);
    void close_channel(std::uint8_t remote_stream, const std::string& reason);
    void send_data(std::uint8_t remote_stream, const client::TransportCore::Bytes& payload);

private:
    struct LinkChannel {
        std::weak_ptr<Session> origin;
        std::uint8_t origin_stream{0};
        std::uint8_t remote_stream{0};
        std::string channel_id;
    };

    void run_loop();
    void set_state(std::string state, std::string error = {});
    void reset_transport();
    bool connect_and_auth(boost::asio::io_context& io,
                          boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream);
    bool configure_inner_from_server_info(const nlohmann::json& info,
                                          std::string* pq_public_path,
                                          std::string* error);
    void handle_control(const nlohmann::json& json);
    void request_directory();
    void handle_disconnect(const std::string& reason);

    boost::asio::io_context& server_io_;
    ServerConfig cfg_;
    FederationPeer peer_;
    FederationManager* owner_{nullptr};

    mutable std::mutex mutex_;
    std::atomic<bool> closing_{false};
    std::thread worker_;
    std::thread directory_worker_;
    std::string state_{"idle"};
    std::string last_error_;
    std::int64_t last_handshake_ts_{0};
    bool ready_{false};
    std::string remote_namespace_for_local_;
    std::uint32_t channels_active_{0};
    std::unordered_map<std::uint8_t, LinkChannel> channels_;
    std::unique_ptr<client::TransportCore> transport_;
    std::mutex write_mutex_;
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket>* active_stream_{nullptr};
    std::string cached_peer_pq_public_path_;
};

}  // namespace yume::server
