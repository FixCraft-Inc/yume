/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

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

#if YUME_USE_BASEFWX
#include <basefwx/pq.hpp>
#include <basefwx/x25519.hpp>
#endif

#include "core/protocol/control_protocol.hpp"
#include "core/app_codec/codec.hpp"
#include "core/runtime/service_stream.hpp"
#include "core/security/crypto.hpp"
#include "core/security/session_ratchet.hpp"
#include "core/stealth/obfs_h2.hpp"
#include "core/stealth/h2_carrier.hpp"
#include "core/stealth/obfs_signal.hpp"
#include "core/protocol/protocol.hpp"
#include "server/config/config.hpp"
#include "server/runtime/kdf_admission.hpp"
#include "server/session/authorization.hpp"
#include "server/session/fair_frame_budget.hpp"
#include "util.hpp"

namespace yume::server::static_site {
struct FileContents;  // full definition in static_site.hpp; forward-declared
                      // here so session.hpp need not pull in <filesystem>.
}

namespace yume::server {

class Manager;

// Wall-clock helper defined in session.cpp. Exposed here because
// session_control.cpp (split out in f6db161) also calls it; the
// anonymous-namespace version it used to share a TU with is gone.
std::int64_t epoch_now_ms();

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(boost::asio::ip::tcp::socket socket,
            boost::asio::ssl::context& ssl_ctx,
            const ServerConfig& cfg,
            std::shared_ptr<const std::vector<crypto::Bytes>> authorized_keys,
            std::shared_ptr<KdfAdmissionController> kdf_admission,
            std::shared_ptr<obfs::AdmissionReplayCache> admission_replay_cache,
            uint64_t session_id,
            Manager* manager);

    void start();
    void stop();
    void notify_server_shutdown(const std::string& reason);
    bool is_stale() const;
    void force_close_reverse_port(int port);
    std::string endpoint_id() const { return client_id_; }
    std::string endpoint_name() const { return client_display_name_; }
    uint64_t session_id() const { return session_id_; }
    const std::string& client_wan_ip() const { return client_wan_ip_; }
    const std::string& federation_peer_id() const { return federation_peer_id_; }
    bool is_federation_authenticated() const { return authenticated_ && !federation_peer_id_.empty(); }
    bool is_trusted_relay_endpoint() const {
        return client_relay_mode_ == control::RelayMode::trusted;
    }
    bool allows_outbound_admin() const { return client_allow_outbound_admin_; }
    bool allows_inbound_admin() const { return client_allow_inbound_admin_; }
    void send_control_json_to_client(const nlohmann::json& json);
    bool attach_federated_stream(uint8_t stream_id,
                                 control::ChannelKind channel_kind,
                                 const std::string& channel_id,
                                 const std::string& left_endpoint_id,
                                 const std::string& right_endpoint_id,
                                 std::function<void(const crypto::Bytes&)> on_data,
                                 std::function<void(const std::string&)> on_close);
    void complete_federated_open(uint8_t stream_id, bool ok, const std::string& message);
    void send_federated_data(uint8_t stream_id, const crypto::Bytes& payload);
    void send_federated_close(uint8_t stream_id, const std::string& reason);

    std::optional<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> release_for_host_proxy();

private:
    struct PendingWrite;

    void on_handshake(const boost::system::error_code& ec);
    void start_preface_read();
    void on_preface_read(const boost::system::error_code& ec, std::size_t bytes);
    void on_preface_timeout(const boost::system::error_code& ec);
    bool handle_http_preface(const std::string& preface);
    // HTTP/1.x masquerade responder with keep-alive. begin_http_masquerade
    // seeds the request buffer with the preface bytes; read/on_read/dispatch
    // form a bounded request loop, and finish_masq_write either reads the next
    // request (keep-alive) or closes. Keep-alive is gated by http_masq so the
    // byte stream never desyncs (bodyless GET/HEAD only, per-connection cap).
    void begin_http_masquerade(std::string initial);
    void read_http_request();
    void on_http_request_read(const boost::system::error_code& ec, std::size_t n);
    void dispatch_http_request(std::string request);
    void finish_masq_write(std::shared_ptr<std::string> resp,
                           bool keep_alive,
                           std::string close_reason);
    void send_real_http_response(const std::string& path, const std::string& method,
                                 bool keep_alive = false,
                                 const std::string& request_headers = "");
    // Emit a static file under --real-root as an nginx-shaped response. Honors
    // conditional GET (If-None-Match / If-Modified-Since -> 304) and byte Range
    // requests (-> 206, or 416 when unsatisfiable); otherwise a 200 with Server,
    // Date, Content-Type, Content-Length, Last-Modified, ETag, Accept-Ranges.
    // HEAD keeps the headers but drops the body.
    void send_static_file(const std::string& rel_path,
                          static_site::FileContents file,
                          bool head_only,
                          bool keep_alive,
                          const std::string& request_headers);
    void send_robots_txt_response(bool head_only = false, bool keep_alive = false);
    // Profile-driven 404 served on any non-yume probe (HTTP or otherwise)
    // so an active probe or TLS-terminating inspector gets a valid HTTP
    // response rather than the TLS-handshake-followed-by-immediate-close
    // fingerprint that the pre-1.0 path used to leak. Profile comes from
    // cfg_.http_profile (defaults to "yumed" for back-compat, overridden
    // by --hide-in-the-crowd <name> or --public-node which forces nginx).
    // Always closes after the write: the profile template owns its own
    // Connection header, so a 404 ends the (possibly keep-alive) connection
    // rather than lie about reuse.
    void send_disguise_404(const std::string& path);
    std::string load_real_index();
    std::string build_hidden_blob();
    void send_auth_challenge();

    void start_h2_carrier_probe();
    void on_h2_probe_read(const boost::system::error_code& ec, std::size_t bytes);
    void send_h2_server_handshake_then_continue();
    void start_h2_settings_ack_wait();
    void on_h2_settings_ack_read(const boost::system::error_code& ec,
                                 std::size_t bytes);
    void finish_h2_settings_ack_wait();
    void serve_fake_h2_real_index();
    void start_v2_h2_session();
    void read_v2_h2_cover();
    void on_v2_h2_cover_read(const boost::system::error_code& ec,
                             std::size_t bytes);
    void process_v2_h2_requests();
    void flush_v2_h2_wire_on_strand();
    void start_v2_h2_exact_read(
        std::uint8_t* target,
        std::size_t size,
        std::function<void(const boost::system::error_code&, std::size_t)> handler);
    void continue_v2_h2_exact_read();
    void on_v2_h2_exact_tls_read(const boost::system::error_code& ec,
                                 std::size_t bytes);

    void read_header();
    void on_read_header(const boost::system::error_code& ec, std::size_t bytes);
    void on_read_payload(const boost::system::error_code& ec, std::size_t bytes);
    void arm_frame_read_deadline(std::chrono::milliseconds timeout, std::string reason);
    void cancel_frame_read_deadline();

    void handle_frame(protocol::Frame frame);
    bool frame_allowed_by_authorization_tier(const protocol::Frame& frame);
    bool handle_auth(const protocol::Frame& frame);
    void handle_open(const protocol::Frame& frame);
    void handle_data(const protocol::Frame& frame);
    bool handle_packet_open(uint8_t stream_id);
    bool handle_packet_data(uint8_t stream_id, const crypto::Bytes& payload);
    void queue_packet_downstream(crypto::Bytes packet);
    void flush_packet_downstream();
    bool handle_bench_open(uint8_t stream_id, const std::string& proto, const nlohmann::json& json);
    bool handle_bench_data(uint8_t stream_id, const crypto::Bytes& payload);
    bool handle_bench_close(uint8_t stream_id, const std::string& reason);
    void pump_bench_sources();
    void maybe_finish_bench_source(uint8_t stream_id);
    bool handle_codec_open(uint8_t stream_id, const nlohmann::json& json);
    bool handle_codec_data(uint8_t stream_id, const crypto::Bytes& payload);
    bool handle_codec_close(uint8_t stream_id, const std::string& reason);
    bool handle_service_open(uint8_t stream_id, const nlohmann::json& json);
    bool handle_service_data(uint8_t stream_id, const crypto::Bytes& payload);
    bool handle_service_close(uint8_t stream_id, const std::string& reason, bool discard_buffered = false);
    bool handle_service_fin(uint8_t stream_id, const std::string& reason);
    void send_service_data(uint8_t stream_id, runtime::ServiceStream::Bytes payload);
    void send_service_close(uint8_t stream_id, std::string reason);
    void send_service_fin(uint8_t stream_id, std::string reason);
    void send_codec_error(uint8_t stream_id, int http_status, const std::string& message);
    void start_codec_backend(uint8_t stream_id, const crypto::Bytes& payload);
    void on_codec_backend_connect(uint8_t stream_id, const boost::system::error_code& ec);
    void on_codec_backend_write(uint8_t stream_id, const boost::system::error_code& ec, std::size_t bytes);
    void on_codec_backend_headers(uint8_t stream_id, const boost::system::error_code& ec, std::size_t bytes);
    void on_codec_backend_body(uint8_t stream_id, const boost::system::error_code& ec, std::size_t bytes);
    void arm_codec_timer(uint8_t stream_id, std::chrono::milliseconds timeout, std::string reason);
    void handle_close(uint8_t stream_id, const std::string& reason);
    void handle_stream_fin(uint8_t stream_id, const std::string& reason);
    std::string decode_close_reason(const protocol::Frame& frame, bool* ok);
    void handle_exec(const protocol::Frame& frame);
    void handle_rlisten(const protocol::Frame& frame);
    void handle_control(const protocol::Frame& frame);
    bool handle_control_open_request(const protocol::Frame& frame);
    bool handle_control_open_ack(const protocol::Frame& frame);
    bool handle_control_data(const protocol::Frame& frame);
    bool handle_control_close(const protocol::Frame& frame);
    bool handle_control_exec(const protocol::Frame& frame);
    void send_control_frame(protocol::FrameType type,
                            uint8_t stream_id,
                            const crypto::Bytes& payload,
                            uint16_t extra_flags = 0,
                            std::function<void(const boost::system::error_code&, std::size_t)> handler = {});
    void send_control_close(uint8_t stream_id, const std::string& reason);
    void send_control_fin(uint8_t stream_id, const std::string& reason);
    uint8_t reserve_stream_id();
    bool stream_id_in_use_locked(uint8_t stream_id) const;
    bool decrypt_inner_payload(uint8_t frame_type,
                               uint8_t stream_id,
                               const crypto::Bytes& input,
                               crypto::Bytes* output);
    crypto::Bytes encrypt_inner_payload(uint8_t frame_type,
                                        uint8_t stream_id,
                                        const crypto::Bytes& input);
    std::uint64_t current_hop_id() const;
    void clear_hop_key_cache();

    void send_open_reply(uint8_t stream_id, bool ok, const std::string& message);
    void start_remote_read(uint8_t stream_id);
    void on_remote_read(uint8_t stream_id, const boost::system::error_code& ec, std::size_t bytes);
    void enqueue_remote_write(uint8_t stream_id, const std::vector<uint8_t>& data);
    void do_remote_write(uint8_t stream_id);
    void shutdown_remote_send_if_ready(uint8_t stream_id);
    void finish_remote_stream_if_done(uint8_t stream_id);
    void start_udp_read(uint8_t stream_id);
    void on_udp_read(uint8_t stream_id, const boost::system::error_code& ec, std::size_t bytes);
    void enqueue_udp_write(uint8_t stream_id, const crypto::Bytes& data);
    void do_udp_write(uint8_t stream_id);

    void async_write_frame(const protocol::Frame& frame,
                           std::function<void(const boost::system::error_code&, std::size_t)> handler = {});
    void queue_frame_on_strand(const protocol::Frame& frame,
                               std::function<void(const boost::system::error_code&, std::size_t)> handler = {},
                               bool already_protected = false);
    void flush_ratchet_blocked_writes_on_strand();
    void arm_ratchet_timeout_on_strand();
    void queue_encoded_write_on_strand(
        std::shared_ptr<std::vector<uint8_t>> data,
        uint8_t frame_type,
        uint8_t stream_id,
        std::size_t payload_size,
        std::function<void(const boost::system::error_code&, std::size_t)> handler = {});
    void enqueue_tls_write_on_strand(
        std::shared_ptr<std::vector<uint8_t>> data,
        uint8_t frame_type,
        uint8_t stream_id,
        std::size_t payload_size,
        std::function<void(const boost::system::error_code&, std::size_t)> handler = {});
    std::optional<std::uint8_t> select_next_write_on_strand(
        std::size_t current_batch_bytes,
        const std::unordered_set<uint8_t>& batch_streams);
    void mark_write_stream_ready_on_strand(std::uint8_t stream_id);
    PendingWrite pop_write_stream_head_on_strand(std::uint8_t stream_id);
    bool write_queues_empty_on_strand() const noexcept;
    void do_write();
    std::chrono::milliseconds reserve_egress_delay(std::size_t bytes) const;
    bool should_pause_inbound_reads_on_strand() const;
    void maybe_resume_inbound_reads_on_strand();

    void close_with_reason(const std::string& reason);
    void begin_close();
    void maybe_finish_close();
    void arm_close_deadline();
    void shutdown_transport();
    void finish_transport_close();
    void close();
    void touch_activity();
    void schedule_idle_check();

    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream_;
    ServerConfig cfg_;
    std::shared_ptr<const std::vector<crypto::Bytes>> authorized_keys_;
    std::shared_ptr<KdfAdmissionController> kdf_admission_;
    std::shared_ptr<obfs::AdmissionReplayCache> admission_replay_cache_;
    uint64_t session_id_{0};
    Manager* manager_{nullptr};

    boost::asio::strand<boost::asio::any_io_executor> strand_;

    std::array<uint8_t, 8> header_buf_{};
    std::array<uint8_t, 8> preface_buf_{};
    std::vector<uint8_t> preface_accum_;
    bool preface_received_{false};
    bool preface_probe_active_{false};
    bool header_prefetched_{false};

    // HTTP/1.x masquerade keep-alive loop state. http_request_buf_ holds the
    // current request plus any over-read/pipelined bytes between iterations.
    std::string http_request_buf_;
    int http_requests_served_{0};

    bool carrier_probe_active_{false};
    bool carrier_settings_ack_wait_active_{false};
    std::unique_ptr<obfs::H2InboundDecoder> carrier_decoder_;
    std::unique_ptr<obfs::H2Carrier> v2_h2_carrier_;
    bool v2_h2_tunnel_active_{false};
    bool v2_h2_tls_read_in_flight_{false};
    crypto::Bytes v2_h2_decoded_;
    std::size_t v2_h2_decoded_offset_{0};
    std::uint8_t* v2_h2_read_target_{nullptr};
    std::size_t v2_h2_read_size_{0};
    std::size_t v2_h2_read_copied_{0};
    std::function<void(const boost::system::error_code&, std::size_t)>
        v2_h2_read_handler_;
    std::array<uint8_t, 4096> carrier_scratch_{};
    boost::asio::steady_timer preface_timer_;
    // Per-connection TLS handshake deadline (RFC 7540 has none; this
    // is yume's slow-loris guard). Armed in start() when
    // cfg_.tls_handshake_timeout_ms > 0, cancelled in on_handshake on
    // success or failure. Closing on expiry pulls the rug from the
    // pending async_handshake which then reports operation_aborted.
    boost::asio::steady_timer tls_handshake_timer_;
    protocol::FrameHeader current_header_{};
    std::vector<uint8_t> payload_buf_;
    crypto::Bytes challenge_;
    struct AuthV2Ephemeral {
#if YUME_USE_BASEFWX
        basefwx::pq::KemKeyPair mlkem;
        basefwx::x25519::KeyPair x25519;
#endif
        crypto::Bytes psk_salt;
        crypto::Bytes transcript_salt;
    };
    std::unique_ptr<AuthV2Ephemeral> auth_v2_ephemeral_;
    std::unique_ptr<ratchet::SessionRatchet> ratchet_;
    std::optional<std::chrono::steady_clock::time_point>
        outbound_rekey_wait_started_;
    std::uint64_t timing_seal_ns_{0};
    std::uint64_t timing_seal_frames_{0};
    std::uint64_t timing_open_ns_{0};
    std::uint64_t timing_open_frames_{0};
    bool authenticated_{false};
    authorization::SessionTier authorization_tier_{
        authorization::SessionTier::Unauthenticated};
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
    std::optional<std::uint64_t> encrypt_hop_id_;
    crypto::Bytes encrypt_hop_key_;
    std::optional<std::uint64_t> decrypt_hop_id_;
    crypto::Bytes decrypt_hop_key_;
    boost::asio::steady_timer idle_timer_;
    boost::asio::steady_timer frame_read_timer_;
    boost::asio::steady_timer ratchet_timer_;
    boost::asio::steady_timer transport_shutdown_timer_;
    boost::asio::steady_timer http_idle_timer_;
    std::atomic<int64_t> last_activity_ms_{0};

    struct RemoteStream {
        boost::asio::ip::tcp::socket socket;
        boost::asio::ip::tcp::resolver resolver;
        std::vector<uint8_t> read_buf;
        std::deque<std::vector<uint8_t>> write_queue;
        runtime::InboundQueueBudget inbound_budget;
        std::string host;
        int port{0};
        int64_t open_started_ms{0};
        int64_t resolve_started_ms{0};
        int64_t connect_started_ms{0};
        int64_t first_upstream_ms{0};
        int64_t first_downstream_ms{0};
        std::uint64_t upstream_bytes{0};
        std::uint64_t downstream_bytes{0};
        bool close_summary_logged{false};
        bool connected{false};
        bool write_in_flight{false};
        bool read_in_flight{false};
        bool read_paused{false};
        bool client_fin_received{false};
        bool remote_fin_sent{false};
        bool write_shutdown_pending{false};
        bool write_shutdown_sent{false};
        std::unique_ptr<boost::asio::steady_timer> open_timer;

        explicit RemoteStream(boost::asio::any_io_executor exec)
            : socket(exec)
            , resolver(exec) {
            read_buf.resize(util::relay_read_buf_size());
        }
    };

    struct UdpStream {
        boost::asio::ip::udp::socket socket;
        boost::asio::ip::udp::resolver resolver;
        boost::asio::ip::udp::endpoint remote;
        std::array<uint8_t, 65535> read_buf{};
        std::deque<crypto::Bytes> write_queue;
        runtime::InboundQueueBudget inbound_budget;
        std::string host;
        int port{0};
        int64_t open_started_ms{0};
        int64_t resolve_started_ms{0};
        int64_t first_upstream_ms{0};
        int64_t first_downstream_ms{0};
        std::uint64_t upstream_bytes{0};
        std::uint64_t downstream_bytes{0};
        bool close_summary_logged{false};
        bool write_in_flight{false};
        bool read_in_flight{false};
        bool read_paused{false};

        explicit UdpStream(boost::asio::any_io_executor exec)
            : socket(exec)
            , resolver(exec) {}
    };

    struct CodecStream {
        boost::asio::ip::tcp::socket socket;
        boost::asio::steady_timer timer;
        boost::asio::streambuf response_buf;
        std::string codec_id;
        std::vector<uint8_t> request_bytes;
        std::vector<uint8_t> response_body;
        std::string backend_host;
        int backend_port{0};
        int64_t open_started_ms{0};
        int64_t request_started_ms{0};
        std::uint64_t upstream_bytes{0};
        std::uint64_t downstream_bytes{0};
        // Accounted in Session::codec_response_bytes_ until close. Keep the
        // reservation separate from vector size so allocation failures and
        // cancellation release the exact admitted amount.
        std::size_t response_reserved_bytes{0};
        int response_status{0};
        bool response_sent{false};
        bool close_summary_logged{false};

        explicit CodecStream(boost::asio::any_io_executor exec)
            : socket(exec)
            , timer(exec)
            , response_buf(app_codec::kMaxHttpHeaderBytes + 1) {}
    };

    std::shared_ptr<CodecStream> find_codec_stream(uint8_t stream_id);

    struct PacketStream {
        uint8_t stream_id{0};
        std::uint32_t client_ipv4_be{0};
        std::string client_ipv4;
        std::uint32_t mtu{0};
        std::vector<std::string> dns_servers;
        std::deque<crypto::Bytes> downstream_packets;
        std::size_t downstream_encoded_bytes{0};
        std::uint64_t downstream_sequence{0};
        std::uint64_t next_upstream_sequence{0};
        bool upstream_sequence_exhausted{false};
        std::uint64_t upstream_batches{0};
        std::uint64_t upstream_packets{0};
        std::uint64_t downstream_batches{0};
        std::uint64_t downstream_packet_count{0};
        int64_t open_started_ms{0};
        bool close_summary_logged{false};
        std::unique_ptr<boost::asio::steady_timer> flush_timer;
    };

    std::unordered_map<uint8_t, std::shared_ptr<RemoteStream>> streams_;
    std::unordered_map<uint8_t, std::shared_ptr<UdpStream>> udp_streams_;
    std::unordered_map<uint8_t, std::shared_ptr<CodecStream>> codec_streams_;
    // Protected by streams_mutex_. Codec responses are fully buffered before
    // their typed envelope is sent, so cap the aggregate reservation rather
    // than allowing an authenticated peer to multiply the per-response limit.
    std::size_t codec_response_bytes_{0};
    std::unordered_map<uint8_t, std::shared_ptr<runtime::ServiceStream>> service_streams_;
    std::optional<PacketStream> packet_stream_;
    struct BenchStream {
        enum class Mode {
            Sink,
            Source,
        };
        Mode mode{Mode::Sink};
        std::uint64_t requested_bytes{0};
        std::uint64_t upstream_bytes{0};
        std::uint64_t downstream_bytes{0};
        std::uint32_t in_flight_frames{0};
        int64_t open_started_ms{0};
        bool close_sent{false};
    };
    std::unordered_map<uint8_t, BenchStream> bench_streams_;
    // Source frames are admitted per session, not per logical benchmark
    // stream. A reservation lives from scheduling until the final carrier/TLS
    // completion, so posted, ratchet-blocked, H2-pending, and TLS-pending work
    // all consume the same bounded budget.
    FairFrameBudget bench_source_budget_{64};
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
    struct FederatedStream {
        control::ChannelKind channel_kind{control::ChannelKind::chat};
        std::string channel_id;
        std::string left_endpoint_id;
        std::string right_endpoint_id;
        std::function<void(const crypto::Bytes&)> on_data;
        std::function<void(const std::string&)> on_close;
        bool pending{true};
    };
    std::unordered_map<uint8_t, FederatedStream> federated_streams_;
    std::weak_ptr<Session> control_target_;
    std::string control_target_id_;
    bool is_controller_{false};
    bool client_allow_exec_{false};
    bool client_server_in_charge_{false};
    std::string client_id_;
    std::string client_display_name_;
    std::string auth_fingerprint_;
    std::string bandwidth_fair_key_;
    std::uint32_t bandwidth_priority_{50};
    std::string federation_peer_id_;
    std::string client_auth_pubkey_b64_;
    std::deque<std::int64_t> federation_directory_hits_;
    bool session_allow_exec_policy_{false};
    bool session_allow_local_ip_{false};
    bool session_control_full_{false};
    std::unordered_set<std::string> session_allowed_codecs_;
    std::unordered_set<std::string> session_allowed_services_;
    bool session_allow_monero_rpc_policy_{false};
    bool session_allow_inbound_admin_policy_{false};
    bool session_allow_outbound_admin_policy_{false};
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
        uint8_t frame_type{0};
        uint8_t stream_id{0};
        std::size_t payload_size{0};
        std::function<void(const boost::system::error_code&, std::size_t)> handler;
    };

    struct RatchetBlockedWrite {
        protocol::Frame frame;
        std::function<void(const boost::system::error_code&, std::size_t)> handler;
    };

    std::array<std::deque<PendingWrite>, 256> write_queues_;
    std::array<std::deque<std::uint8_t>, 5> write_ready_streams_;
    std::array<std::int8_t, 256> write_ready_priority_{};
    std::deque<PendingWrite> v2_h2_pending_app_writes_;
    std::deque<RatchetBlockedWrite> ratchet_blocked_writes_;
    bool write_in_flight_{false};
    std::uint32_t write_queued_frames_{0};
    std::size_t write_queued_bytes_{0};
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
