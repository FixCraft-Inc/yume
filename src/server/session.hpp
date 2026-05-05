#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <utility>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include "core/control_protocol.hpp"
#include "core/crypto.hpp"
#include "core/obfs_h2.hpp"
#include "core/protocol.hpp"
#include "server/config.hpp"

namespace yume::server {

class Manager;

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(boost::asio::ip::tcp::socket socket,
            boost::asio::ssl::context& ssl_ctx,
            const ServerConfig& cfg,
            std::shared_ptr<const std::vector<crypto::Bytes>> authorized_keys,
            uint64_t session_id,
            Manager* manager);

    void start();
    void stop();
    void notify_server_shutdown(const std::string& reason);
    bool is_stale() const;
    void force_close_reverse_port(int port);
    std::string endpoint_id() const { return client_id_; }
    std::string endpoint_name() const { return client_display_name_; }

private:
    void on_handshake(const boost::system::error_code& ec);
    void start_preface_read();
    void on_preface_read(const boost::system::error_code& ec, std::size_t bytes);
    void on_preface_timeout(const boost::system::error_code& ec);
    bool handle_http_preface(const std::string& preface);
    void send_real_http_response(const std::string& path);
    void send_obfs_connect_established(const std::string& authority);
    std::string load_real_index();
    std::string build_hidden_blob();
    void send_auth_challenge();

    void start_h2_carrier_probe();
    void on_h2_probe_read(const boost::system::error_code& ec, std::size_t bytes);
    void send_h2_server_handshake_then_continue();
    void serve_fake_h2_real_index();

    void read_header();
    void on_read_header(const boost::system::error_code& ec, std::size_t bytes);
    void on_read_payload(const boost::system::error_code& ec, std::size_t bytes);

    void handle_frame(const protocol::Frame& frame);
    bool handle_auth(const protocol::Frame& frame);
    void handle_open(const protocol::Frame& frame);
    void handle_data(const protocol::Frame& frame);
    void handle_close(uint8_t stream_id, const std::string& reason);
    void handle_exec(const protocol::Frame& frame);
    void handle_rlisten(const protocol::Frame& frame);
    void handle_control(const protocol::Frame& frame);
    bool handle_control_open_request(const protocol::Frame& frame);
    bool handle_control_open_ack(const protocol::Frame& frame);
    bool handle_control_data(const protocol::Frame& frame);
    bool handle_control_close(const protocol::Frame& frame);
    bool handle_control_exec(const protocol::Frame& frame);
    void send_control_frame(protocol::FrameType type, uint8_t stream_id, const crypto::Bytes& payload, uint16_t extra_flags = 0);
    void send_control_close(uint8_t stream_id, const std::string& reason);
    uint8_t reserve_stream_id();
    bool decrypt_inner_payload(uint8_t frame_type,
                               uint8_t stream_id,
                               const crypto::Bytes& input,
                               crypto::Bytes* output);
    crypto::Bytes encrypt_inner_payload(uint8_t frame_type,
                                        uint8_t stream_id,
                                        const crypto::Bytes& input);
    std::uint64_t current_hop_id() const;

    void send_open_reply(uint8_t stream_id, bool ok, const std::string& message);
    void start_remote_read(uint8_t stream_id);
    void on_remote_read(uint8_t stream_id, const boost::system::error_code& ec, std::size_t bytes);
    void enqueue_remote_write(uint8_t stream_id, const std::vector<uint8_t>& data);
    void do_remote_write(uint8_t stream_id);
    void start_udp_read(uint8_t stream_id);
    void on_udp_read(uint8_t stream_id, const boost::system::error_code& ec, std::size_t bytes);
    void enqueue_udp_write(uint8_t stream_id, const crypto::Bytes& data);
    void do_udp_write(uint8_t stream_id);

    void async_write_frame(const protocol::Frame& frame,
                           std::function<void(const boost::system::error_code&, std::size_t)> handler = {});
    void queue_frame_on_strand(const protocol::Frame& frame,
                               std::function<void(const boost::system::error_code&, std::size_t)> handler = {});
    void queue_encoded_write_on_strand(
        std::shared_ptr<std::vector<uint8_t>> data,
        std::function<void(const boost::system::error_code&, std::size_t)> handler = {});
    void do_write();
    bool should_pause_inbound_reads_on_strand() const;
    void maybe_resume_inbound_reads_on_strand();

    void close_with_reason(const std::string& reason);
    void begin_close();
    void maybe_finish_close();
    void shutdown_transport();
    void close();
    void touch_activity();
    void schedule_idle_check();

    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream_;
    ServerConfig cfg_;
    std::shared_ptr<const std::vector<crypto::Bytes>> authorized_keys_;
    uint64_t session_id_{0};
    Manager* manager_{nullptr};

    boost::asio::strand<boost::asio::any_io_executor> strand_;

    std::array<uint8_t, 8> header_buf_{};
    std::array<uint8_t, 8> preface_buf_{};
    std::vector<uint8_t> preface_accum_;
    bool preface_received_{false};
    bool preface_probe_active_{false};
    bool header_prefetched_{false};

    bool carrier_probe_active_{false};
    std::unique_ptr<obfs::H2InboundDecoder> carrier_decoder_;
    std::array<uint8_t, 4096> carrier_scratch_{};
    boost::asio::steady_timer preface_timer_;
    protocol::FrameHeader current_header_{};
    std::vector<uint8_t> payload_buf_;
    crypto::Bytes challenge_;
    bool authenticated_{false};
    std::string auth_error_;
    std::optional<crypto::Bytes> inner_key_;
    std::optional<crypto::Bytes> inner_key_alt_;
    std::string inner_mode_;
    std::string inner_alt_mode_;
    std::string inner_kdf_;
    std::string inner_alt_kdf_;
    bool hop_enabled_{false};
    std::uint32_t hop_interval_ms_{0};
    std::int64_t hop_offset_ms_{0};
    boost::asio::steady_timer idle_timer_;
    std::atomic<int64_t> last_activity_ms_{0};

    struct RemoteStream {
        boost::asio::ip::tcp::socket socket;
        boost::asio::ip::tcp::resolver resolver;
        std::array<uint8_t, 16384> read_buf{};
        std::deque<std::vector<uint8_t>> write_queue;
        bool write_in_flight{false};
        bool read_in_flight{false};
        bool read_paused{false};

        explicit RemoteStream(boost::asio::any_io_executor exec)
            : socket(exec)
            , resolver(exec) {}
    };

    struct UdpStream {
        boost::asio::ip::udp::socket socket;
        boost::asio::ip::udp::resolver resolver;
        boost::asio::ip::udp::endpoint remote;
        std::array<uint8_t, 65535> read_buf{};
        std::deque<crypto::Bytes> write_queue;
        bool write_in_flight{false};
        bool read_in_flight{false};
        bool read_paused{false};

        explicit UdpStream(boost::asio::any_io_executor exec)
            : socket(exec)
            , resolver(exec) {}
    };

    std::unordered_map<uint8_t, std::shared_ptr<RemoteStream>> streams_;
    std::unordered_map<uint8_t, std::shared_ptr<UdpStream>> udp_streams_;
    std::unordered_map<uint8_t, std::shared_ptr<boost::asio::ip::tcp::acceptor>> reverse_listeners_;
    std::unordered_map<uint8_t, int> reverse_listener_ports_;
    std::unordered_map<int, uint8_t> reverse_port_streams_;
    std::unordered_set<uint8_t> pending_reverse_;

    struct ControlLink {
        std::weak_ptr<Session> peer;
        uint8_t peer_stream_id{0};
        bool pending{false};
        bool is_exec{false};
        control::ChannelKind channel_kind{control::ChannelKind::chat};
        std::string channel_id;
        std::string left_endpoint_id;
        std::string right_endpoint_id;
    };

    std::mutex control_mutex_;
    std::mutex streams_mutex_;
    std::unordered_map<uint8_t, ControlLink> control_outbound_;
    std::unordered_map<uint8_t, ControlLink> control_inbound_;
    std::weak_ptr<Session> control_target_;
    std::string control_target_id_;
    bool is_controller_{false};
    bool client_allow_exec_{false};
    bool client_server_in_charge_{false};
    std::string client_id_;
    std::string client_display_name_;
    std::string auth_fingerprint_;
    std::string client_auth_pubkey_b64_;
    bool session_allow_exec_policy_{false};
    bool session_allow_local_ip_{false};
    bool session_control_full_{false};
    bool session_allow_inbound_admin_policy_{true};
    bool session_allow_outbound_admin_policy_{true};
    bool session_allow_chat_policy_{true};
    bool session_allow_file_policy_{true};
    bool session_allow_bytes_policy_{true};
    std::string client_platform_{"unknown"};
    std::string client_variant_{"unknown"};
    std::string client_version_;
    control::RelayMode client_relay_mode_{control::RelayMode::untrusted};
    bool client_allow_chat_{true};
    bool client_allow_file_{true};
    bool client_allow_bytes_{true};
    bool client_allow_inbound_admin_{false};
    bool client_allow_outbound_admin_{false};
    std::string latest_lifecycle_state_;
    std::string client_hostname_;
    std::string client_wan_ip_;

    struct PendingWrite {
        std::shared_ptr<std::vector<uint8_t>> data;
        std::function<void(const boost::system::error_code&, std::size_t)> handler;
    };

    std::deque<PendingWrite> write_queue_;
    bool write_in_flight_{false};
    uint32_t write_queue_depth_{0};
    
    enum class CloseState {
        Open,
        Closing,
        Closed,
    };
    CloseState close_state_{CloseState::Open};
    bool transport_shutdown_in_flight_{false};
    bool closed_{false};
    std::string close_reason_;
    std::chrono::steady_clock::time_point close_started_at_{};
    static constexpr int64_t kCloseTimeoutMs = 5000;
};

}  // namespace yume::server
