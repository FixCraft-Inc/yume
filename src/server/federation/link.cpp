/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/federation/link.hpp"

#include "core/protocol/directory_policy.hpp"
#include "core/protocol/relay_policy.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <vector>

#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/write.hpp>

#include "client/cli/connect/auth.hpp"
#include "client/cli/connect/io.hpp"
#include "client/proxy/outbound_proxy.hpp"
#include "core/security/channel_binding.hpp"
#include "core/security/crypto.hpp"
#include "core/security/ratchet.hpp"
#include "core/stealth/obfs.hpp"
#include "server/federation/manager.hpp"
#include "server/session/session.hpp"
#include "util.hpp"

namespace yume::server {

namespace {

// Both endpoints are Yume servers we control, so TLS 1.3 only -- consistent
// with the obfs / tls_stealth contexts and required by channel binding
// (ExportChannelBinding refuses anything older).
constexpr std::chrono::milliseconds kConnectTimeout{15000};
constexpr std::chrono::milliseconds kHelloTimeout{10000};
constexpr std::string_view kRedactedPath{"[redacted-path]"};

void redact_all(std::string* text, std::string_view value) {
    if (text == nullptr || value.empty()) {
        return;
    }
    std::size_t offset = 0;
    while ((offset = text->find(value, offset)) != std::string::npos) {
        text->replace(offset, value.size(), kRedactedPath);
        offset += kRedactedPath.size();
    }
}

std::string public_link_error(std::string_view error,
                              const ServerConfig& cfg,
                              const FederationPeer& peer) {
    std::string redacted(error);
    // These paths may be included verbatim by OpenSSL or secret-file errors.
    // Redact the longest first so one configured path cannot expose the tail
    // of another path that happens to share a prefix.
    std::array<std::string_view, 4> configured_paths{
        cfg.federation_identity,
        cfg.federation_operator_ca,
        peer.psk_file,
        peer.carrier_secret_file,
    };
    std::sort(configured_paths.begin(), configured_paths.end(),
              [](std::string_view left, std::string_view right) {
                  return left.size() > right.size();
              });
    for (const auto path : configured_paths) {
        redact_all(&redacted, path);
    }
    return sanitize_federation_public_error(redacted);
}

std::string hex_encode(const unsigned char* data, std::size_t len) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(kHex[(data[i] >> 4) & 0xF]);
        out.push_back(kHex[data[i] & 0xF]);
    }
    return out;
}

std::string peer_cert_sha256(SSL* ssl) {
    if (!ssl) {
        return {};
    }
    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        return {};
    }
    unsigned char* der = nullptr;
    int len = i2d_X509(cert, &der);
    X509_free(cert);
    if (len <= 0 || !der) {
        if (der) {
            OPENSSL_free(der);
        }
        return {};
    }
    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};
    SHA256(der, static_cast<std::size_t>(len), hash);
    OPENSSL_free(der);
    return hex_encode(hash, SHA256_DIGEST_LENGTH);
}

}  // namespace

FederationLink::FederationLink(boost::asio::io_context& server_io,
                               const ServerConfig& cfg,
                               const FederationPeer& peer,
                               FederationManager* owner)
    : server_io_(server_io)
    , cfg_(cfg)
    , peer_(peer)
    , owner_(owner) {}

FederationLink::~FederationLink() {
    close();
}

void FederationLink::start() {
    if (worker_.joinable()) {
        return;
    }
    // Deterministic configuration problems must not become a retry loop: load
    // the pairwise secrets here, once, and refuse to start the link on error.
    try {
        psk_ = security::LoadSecretFile32(peer_.psk_file);
        carrier_secret_ = security::LoadSecretFile32(peer_.carrier_secret_file);
    } catch (const std::exception& ex) {
        set_state("failed", std::string("secret load failed: ") + ex.what());
        util::log_error("federation peer " + peer_.id + ": " + ex.what());
        return;
    }
    closing_.store(false);
    worker_ = std::thread([self = shared_from_this()] {
        self->run_loop();
    });
    directory_worker_ = std::thread([self = shared_from_this()] {
        while (!self->wait_for_close(std::chrono::seconds(5))) {
            if (self->is_ready()) {
                self->request_directory();
            }
        }
    });
}

void FederationLink::close() {
    closing_.store(true);
    attempt_alive_.store(false);
    close_wait_cv_.notify_all();
    std::shared_ptr<client::Tunnel> tunnel;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        tunnel = tunnel_;
    }
    if (tunnel) {
        // Unblocks the worker's io_context run loop through the normal close
        // path; Tunnel::stop is safe from a foreign thread (the GUI does it).
        tunnel->stop("federation link closing");
    }
    if (worker_.joinable()) {
        worker_.join();
    }
    if (directory_worker_.joinable()) {
        directory_worker_.join();
    }
    reset_transport();
}

bool FederationLink::wait_for_close(std::chrono::milliseconds duration) {
    std::unique_lock<std::mutex> lock(close_wait_mutex_);
    return close_wait_cv_.wait_for(
        lock, duration, [this] { return closing_.load(); });
}

bool FederationLink::is_ready() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return ready_;
}

std::string FederationLink::remote_namespace_for_local() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return remote_namespace_for_local_;
}

FederationPeerStatus FederationLink::status() const {
    std::lock_guard<std::mutex> lock(mutex_);
    FederationPeerStatus out;
    out.id = peer_.id;
    out.state = state_;
    out.ready = ready_;
    out.outbound_state = state_;
    out.outbound_ready = ready_;
    out.last_error = public_link_error(last_error_, cfg_, peer_);
    out.last_handshake_ms = last_handshake_ms_;
    out.channels_active = channels_active_;
    return out;
}

void FederationLink::set_state(std::string state, std::string error) {
    std::lock_guard<std::mutex> lock(mutex_);
    state_ = std::move(state);
    if (!error.empty()) {
        last_error_ = std::move(error);
    } else if (state_ == "ready") {
        last_error_.clear();
    }
}

void FederationLink::reset_transport() {
    std::shared_ptr<client::Tunnel> tunnel;
    std::vector<LinkChannel> closed_channels;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ready_ = false;
        attempt_alive_.store(false);
        tunnel = std::move(tunnel_);
        closed_channels.reserve(channels_.size());
        for (const auto& entry : channels_) {
            closed_channels.push_back(entry.second);
        }
        channels_.clear();
        channels_active_ = 0;
    }
    if (tunnel) {
        tunnel->stop("federation link closed");
    }
    for (const auto& channel : closed_channels) {
        if (auto session = channel.origin.lock()) {
            boost::asio::post(server_io_, [session,
                                           origin_stream = channel.origin_stream,
                                           open_pending = channel.open_pending] {
                if (open_pending) {
                    session->complete_federated_open(
                        origin_stream, false, "federation link closed");
                } else {
                    session->send_federated_close(
                        origin_stream, "federation link closed");
                }
            });
        }
    }
    if (owner_) {
        owner_->clear_directory(peer_.id);
    }
}

void FederationLink::run_loop() {
    int backoff_ms = 1000;
    while (!closing_.load()) {
        try {
            set_state("dialing");
            // Each attempt gets a private io_context that owns the stream,
            // the H2 carrier and the Tunnel's timers for that connection.
            // It dies before the Tunnel does: dial_v2's returned Tunnel is
            // released by reset_transport below, which runs before this scope
            // exits on every path out of the iteration.
            boost::asio::io_context io;
            auto tunnel = dial_v2(io);
            // The synchronous client dial helpers drive io.run() to completion,
            // which leaves this private context stopped. Restart it before the
            // asynchronous Tunnel posts its first read and CONTROL writes.
            io.restart();
            tunnel->set_allow_server_streams(false);
            tunnel->set_close_handler([this, &io](const std::string& reason) {
                handle_disconnect(reason);
                attempt_alive_.store(false);
                io.stop();
            });
            tunnel->set_control_handler(
                [weak = weak_from_this(),
                 source_tunnel = std::weak_ptr<client::Tunnel>(tunnel)](
                    const nlohmann::json& json) {
                if (auto self = weak.lock()) {
                    if (auto source = source_tunnel.lock()) {
                        boost::asio::post(self->server_io_, [self, source, json] {
                            self->handle_control(json, source);
                        });
                    }
                }
            });
            tunnel->start();
            {
                std::lock_guard<std::mutex> lock(mutex_);
                tunnel_ = std::move(tunnel);
                ready_ = false;
                remote_namespace_for_local_.clear();
                state_ = "hello";
                last_error_.clear();
            }
            attempt_alive_.store(true);
            util::log_info(
                "federation peer transport authenticated; awaiting hello: " +
                peer_.id);
            send_hello();
            backoff_ms = 1000;
            const auto hello_deadline =
                std::chrono::steady_clock::now() + kHelloTimeout;
            bool hello_timeout_requested = false;
            // The Tunnel runs on async completion handlers serviced by this
            // thread until the peer disconnects, the transport fails, or the
            // link closes.
            while (!closing_.load() && attempt_alive_.load()) {
                io.run_for(std::chrono::milliseconds(100));
                if (!hello_timeout_requested && !is_ready() &&
                    std::chrono::steady_clock::now() >= hello_deadline) {
                    hello_timeout_requested = true;
                    std::shared_ptr<client::Tunnel> active_tunnel;
                    {
                        std::lock_guard<std::mutex> lock(mutex_);
                        active_tunnel = tunnel_;
                    }
                    if (active_tunnel) {
                        active_tunnel->stop("federation hello timed out");
                    }
                }
            }
        } catch (const std::exception& ex) {
            if (!closing_.load()) {
                handle_disconnect(ex.what());
                reset_transport();
                if (wait_for_close(std::chrono::milliseconds(backoff_ms))) {
                    break;
                }
                backoff_ms = std::min(backoff_ms * 2, 30000);
                continue;
            }
        }
        reset_transport();
        if (!closing_.load()) {
            if (wait_for_close(std::chrono::milliseconds(backoff_ms))) {
                break;
            }
            backoff_ms = std::min(backoff_ms * 2, 30000);
        }
    }
    set_state("closed");
    reset_transport();
}

std::shared_ptr<client::Tunnel> FederationLink::dial_v2(boost::asio::io_context& io) {
#if YUME_USE_BASEFWX
    const client::StopPredicate should_stop =
        [this] { return closing_.load(); };
    // ---- TCP dial (optionally through the outbound SOCKS proxy) ----------
    boost::asio::ip::tcp::socket socket(io);
    if (!cfg_.outbound_proxy_url.empty()) {
        client::outbound_proxy::Config proxy_cfg;
        std::string parse_error;
        if (!client::outbound_proxy::parse_proxy_url(cfg_.outbound_proxy_url, proxy_cfg, &parse_error)) {
            throw std::runtime_error("outbound proxy: " + parse_error);
        }
        auto result = client::outbound_proxy::socks5_dial(socket,
                                                          io,
                                                          proxy_cfg,
                                                          peer_.host,
                                                          peer_.port,
                                                          kConnectTimeout,
                                                          {}, should_stop);
        if (result.cancelled) {
            throw std::runtime_error("federation link closing");
        }
        if (!result.ok) {
            throw std::runtime_error(result.error.empty() ? "proxy dial failed" : result.error);
        }
        if (closing_.load()) {
            boost::system::error_code ignored;
            socket.close(ignored);
            throw std::runtime_error("federation link closing");
        }
    } else {
        boost::asio::ip::tcp::resolver resolver(io);
        auto resolved = client::resolve_with_timeout(
            resolver, io, peer_.host, std::to_string(peer_.port),
            kConnectTimeout, should_stop);
        if (resolved.cancelled) {
            throw std::runtime_error("federation link closing");
        }
        if (resolved.timed_out) {
            throw std::runtime_error("federation DNS resolution timed out");
        }
        if (resolved.ec) {
            throw boost::system::system_error(resolved.ec);
        }
        auto connected = client::connect_with_timeout(
            socket, resolved.endpoints, io, kConnectTimeout, {}, should_stop);
        if (connected.cancelled) {
            throw std::runtime_error("federation link closing");
        }
        if (connected.timed_out) {
            throw std::runtime_error("federation connect timed out");
        }
        if (connected.ec) {
            throw boost::system::system_error(connected.ec);
        }
    }
    socket.set_option(boost::asio::ip::tcp::no_delay(true));

    // ---- TLS 1.3 with certificate pin ------------------------------------
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tlsv13_client);
    ctx.set_options(boost::asio::ssl::context::default_workarounds);
    SSL_CTX_set_min_proto_version(ctx.native_handle(), TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx.native_handle(), TLS1_3_VERSION);
    // The admitted carrier is RFC 8441 over HTTP/2. A raw Asio client context
    // advertises no ALPN, so use the same carrier offer as the normal client
    // path before the handshake; require_h2_carrier_alpn below then verifies
    // that the peer actually selected h2.
    obfs::configure_alpn(ctx, false, true);
    ctx.set_verify_mode(boost::asio::ssl::verify_peer);
    ctx.set_default_verify_paths();
    if (!cfg_.federation_operator_ca.empty()) {
        ctx.load_verify_file(cfg_.federation_operator_ca);
    }
    client::ClientTransportStream::OpenSslStream tls_stream(std::move(socket), ctx);
    SSL_set_tlsext_host_name(tls_stream.native_handle(), peer_.host.c_str());
    SSL_set1_host(tls_stream.native_handle(), peer_.host.c_str());
    auto handshake = client::handshake_with_timeout(
        tls_stream, io, kConnectTimeout, should_stop);
    if (handshake.cancelled) {
        throw std::runtime_error("federation link closing");
    }
    if (handshake.timed_out) {
        throw std::runtime_error("federation TLS handshake timed out");
    }
    if (handshake.ec) {
        throw std::runtime_error(
            "federation TLS handshake failed: " + handshake.ec.message());
    }
    const std::string fingerprint = peer_cert_sha256(tls_stream.native_handle());
    if (!peer_.tls_pin_sha256.empty() &&
        (fingerprint.empty() || fingerprint != peer_.tls_pin_sha256)) {
        throw std::runtime_error("TLS pin mismatch");
    }

    client::TlsConnectionMetadata metadata;
    metadata.alpn = obfs::selected_alpn(tls_stream.native_handle());
    metadata.leaf_fingerprint_sha256 = fingerprint;
    // Channel binding comes from our own live connection and never crosses
    // the wire. Transfer the one exporter buffer directly into the stream so
    // there is no second secret-bearing vector to wipe on exceptional paths.
    metadata.exporter =
        security::ExportChannelBinding(tls_stream.native_handle());
    client::ClientTransportStream stream(std::move(tls_stream));
    stream.set_metadata(std::move(metadata));

    // ---- Carrier admission ------------------------------------------------
    // A YUME 2.0 AUTH challenge is only issued behind the admitted H2
    // carrier, so a federating dial passes the same gate as any client.
    client::require_h2_carrier_alpn(stream, peer_.host, peer_.port);
    std::vector<uint8_t> prefetched;
    std::unique_ptr<obfs::H2Carrier> carrier;
    client::perform_h2_carrier_handshake(stream, io, peer_.host, peer_.port,
                                 carrier_secret_, &prefetched, &carrier, {},
                                 should_stop);

    // ---- AUTH v2 ----------------------------------------------------------
    set_state("authenticating");
    protocol::Frame challenge = client::read_auth_challenge(
        stream, io, peer_.host, peer_.port, &prefetched, carrier.get(),
        should_stop);
    const auto ratchet_policy =
        ratchet::ResolveSecurityProfile(cfg_.security_profile);
    if (!ratchet_policy.has_value()) {
        throw std::runtime_error("invalid local security profile for federation");
    }
    auto ratchet = client::send_auth_v2_response(
        stream, io, cfg_.federation_identity, challenge, psk_,
        stream.take_exporter(), *carrier,
        ratchet::ClampRekeyWindow(cfg_.rekey_window), *ratchet_policy, {},
        should_stop);

    protocol::Frame sealed_info = client::read_frame_over_h2_with_timeout(
        stream, io, *carrier, &prefetched,
        client::kServerInfoTimeout, "federation server info",
        peer_.host, peer_.port, should_stop);
    protocol::Frame anon = client::open_auth_ok_v2(*ratchet, sealed_info);
    if (anon.header.type != protocol::ANON) {
        throw std::runtime_error("federation peer did not send server info");
    }
    nlohmann::json info = nlohmann::json::parse(
        std::string(anon.payload.begin(), anon.payload.end()));
    const std::string server_error = info.value("error", "");
    if (!server_error.empty()) {
        throw std::runtime_error("federation peer refused auth: " + server_error);
    }

    // ---- Hand the established session to its Tunnel -----------------------
    auto tunnel = std::make_shared<client::Tunnel>(
        std::move(stream), std::move(carrier), std::move(prefetched),
        std::move(ratchet));
    return tunnel;
#else
    (void)io;
    throw std::runtime_error("YUME 2.0 federation requires BaseFWX");
#endif
}

void FederationLink::handle_control(
    const nlohmann::json& json,
    const std::shared_ptr<client::Tunnel>& source_tunnel) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!source_tunnel || tunnel_ != source_tunnel) {
            return;
        }
    }
    if (!json.is_object() || !json.contains("cmd") ||
        !json["cmd"].is_string()) {
        util::log_warn("federation peer sent a malformed control message");
        return;
    }
    const std::string cmd = json["cmd"].get<std::string>();
    if (cmd == "federation.hello") {
        const bool valid = json.size() == 6U &&
            json.contains("ok") && json["ok"].is_boolean() &&
            json["ok"].get<bool>() &&
            json.contains("peer_id") && json["peer_id"].is_string() &&
            json.contains("your_peer_id") &&
            json["your_peer_id"].is_string() &&
            json.contains("server_id") && json["server_id"].is_string() &&
            json.contains("server_name") &&
            json["server_name"].is_string() &&
            json["peer_id"].get_ref<const std::string&>() ==
                json["your_peer_id"].get_ref<const std::string&>() &&
            is_valid_federation_peer_id(
                json["your_peer_id"].get_ref<const std::string&>()) &&
            control::is_valid_directory_server_identity(
                json["server_id"].get_ref<const std::string&>(),
                json["server_name"].get_ref<const std::string&>(), true);
        if (!valid) {
            util::log_warn(
                "federation peer " + peer_.id +
                " returned an invalid or rejected hello");
            std::shared_ptr<client::Tunnel> tunnel;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                ready_ = false;
                state_ = "failed";
                last_error_ = "invalid federation hello";
                tunnel = tunnel_;
            }
            if (tunnel) {
                tunnel->stop("invalid federation hello");
            }
            return;
        }
        const std::string remote_namespace =
            json["your_peer_id"].get<std::string>();
        bool became_ready = false;
        bool namespace_changed = false;
        std::shared_ptr<client::Tunnel> tunnel;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            tunnel = tunnel_;
            if (!tunnel_) {
                return;
            }
            if (ready_) {
                namespace_changed =
                    remote_namespace_for_local_ != remote_namespace;
            } else if (state_ == "hello") {
                remote_namespace_for_local_ = remote_namespace;
                ready_ = true;
                last_handshake_ms_ = epoch_now_ms();
                state_ = "ready";
                last_error_.clear();
                became_ready = true;
            } else {
                namespace_changed = true;
            }
            if (namespace_changed) {
                ready_ = false;
                state_ = "failed";
                last_error_ = "federation hello changed namespace or state";
            }
        }
        if (namespace_changed) {
            util::log_warn(
                "federation peer " + peer_.id +
                " changed its accepted hello namespace or state");
            if (tunnel) {
                tunnel->stop("federation hello namespace changed");
            }
            return;
        }
        if (became_ready) {
            util::log_info("federation peer ready: " + peer_.id);
            request_directory();
        }
        return;
    }
    bool command_before_hello = false;
    std::shared_ptr<client::Tunnel> pre_hello_tunnel;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!ready_) {
            command_before_hello = true;
            state_ = "failed";
            last_error_ = "federation command received before accepted hello";
            pre_hello_tunnel = tunnel_;
        }
    }
    if (command_before_hello) {
        util::log_warn(
            "federation peer " + peer_.id +
            " sent an application command before accepted hello");
        if (pre_hello_tunnel) {
            pre_hello_tunnel->stop(
                "federation application command before hello");
        }
        return;
    }
    if (cmd == "federation.directory") {
        std::string parse_error;
        auto directory = control::try_directory_response_from_json(
            json, control::DirectoryNamespace::FederationRaw, &parse_error);
        if (!directory) {
            util::log_warn(
                "federation peer " + peer_.id +
                " sent an invalid directory response: " +
                (parse_error.empty() ? "policy violation" : parse_error));
            if (owner_) owner_->clear_directory(peer_.id);
            std::shared_ptr<client::Tunnel> tunnel;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                tunnel = tunnel_;
            }
            if (tunnel) {
                tunnel->stop("invalid federation directory response");
            }
            return;
        }
        if (owner_) {
            owner_->update_directory(peer_.id,
                                     directory->server_id,
                                     directory->server_name,
                                     directory->endpoints);
        }
        return;
    }
    if (cmd == "federation.invite.reply" || cmd == "invite.reply") {
        if (!json.contains("channel_kind") ||
            !json["channel_kind"].is_string() ||
            !control::try_relay_channel_kind(
                json["channel_kind"].get_ref<const std::string&>())) {
            util::log_warn("federation invite reply has an invalid channel kind");
            return;
        }
        std::shared_ptr<Session> initiator;
        control::PendingInvite invite;
        std::string error;
        const auto parsed_invite = control::try_relay_invite_from_json(json);
        if (owner_ && parsed_invite && owner_->handle_invite_reply(peer_.id,
                                                  *parsed_invite,
                                                  &initiator,
                                                  &invite,
                                                  &error) && initiator) {
            nlohmann::json notify = control::invite_to_json(invite, true);
            notify["cmd"] = "invite.reply";
            initiator->send_control_json_to_client(notify);
        } else if (!error.empty()) {
            util::log_warn("federation invite reply failed: " + error);
        }
    }
}

void FederationLink::send_hello() {
    std::shared_ptr<client::Tunnel> tunnel;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        tunnel = tunnel_;
    }
    if (tunnel) {
        tunnel->send_control_json({{"cmd", "federation.hello"},
                                   {"peer_id", cfg_.server_id},
                                   {"server_id", cfg_.server_id},
                                   {"server_name", cfg_.server_name}});
    }
}

void FederationLink::request_directory() {
    std::shared_ptr<client::Tunnel> tunnel;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!ready_) {
            return;
        }
        tunnel = tunnel_;
    }
    if (tunnel) {
        tunnel->send_control_json({{"cmd", "federation.directory"},
                                   {"request_id", "dir-" + std::to_string(epoch_now_ms())}});
    }
}

bool FederationLink::send_invite_request(const control::PendingInvite& invite,
                                         const std::string& raw_remote_id,
                                         std::string* error) {
    std::shared_ptr<client::Tunnel> tunnel;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!ready_ || !tunnel_) {
            if (error) {
                *error = "federation peer not ready";
            }
            return false;
        }
        tunnel = tunnel_;
    }
    nlohmann::json req = control::invite_to_json(invite, false);
    req["cmd"] = "federation.invite.request";
    req["raw_to_id"] = raw_remote_id;
    tunnel->send_control_json(req);
    return true;
}

bool FederationLink::open_channel(const std::shared_ptr<Session>& origin,
                                  std::uint8_t origin_stream_id,
                                  const control::PendingInvite& invite,
                                  const nlohmann::json& open_json,
                                  std::string* error) {
    std::shared_ptr<client::Tunnel> tunnel;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!ready_ || !tunnel_) {
            if (error) {
                *error = "federation peer not ready";
            }
            return false;
        }
        tunnel = tunnel_;
    }
    const std::uint8_t remote_stream = tunnel->reserve_stream_id();
    if (remote_stream == 0) {
        if (error) {
            *error = "no federation stream ids available";
        }
        return false;
    }
    bool attached = false;
    try {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!ready_ || tunnel_ != tunnel) {
            tunnel->release_reserved_stream(remote_stream);
            if (error) {
                *error = "federation peer disconnected during open";
            }
            return false;
        }
        const auto [channel_it, inserted] = channels_.emplace(
            remote_stream,
            LinkChannel{origin, origin_stream_id, remote_stream,
                        invite.invite_id, true});
        (void)channel_it;
        if (!inserted) {
            tunnel->release_reserved_stream(remote_stream);
            if (error) {
                *error = "federation stream id is already registered";
            }
            return false;
        }
        attached = origin->attach_federated_stream(
            origin_stream_id,
            invite.channel_kind,
            invite.invite_id,
            invite.from_endpoint_id,
            invite.to_endpoint_id,
            [weak = weak_from_this(), remote_stream,
             channel_id = invite.invite_id](
                const crypto::Bytes& payload,
                runtime::InboundCredit inbound_credit) {
                if (auto self = weak.lock()) {
                    self->send_data(remote_stream, channel_id, payload,
                                    std::move(inbound_credit));
                }
            },
            [weak = weak_from_this(), remote_stream,
             channel_id = invite.invite_id](const std::string& reason) {
                if (auto self = weak.lock()) {
                    self->close_channel(remote_stream, channel_id, reason);
                }
            });
        if (!attached) {
            channels_.erase(remote_stream);
            tunnel->release_reserved_stream(remote_stream);
            if (error) {
                *error = "stream already exists";
            }
            return false;
        }
        channels_active_ = static_cast<std::uint32_t>(channels_.size());
    } catch (const std::exception& ex) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            channels_.erase(remote_stream);
            channels_active_ = static_cast<std::uint32_t>(channels_.size());
        }
        tunnel->release_reserved_stream(remote_stream);
        if (error) {
            *error = std::string("federation stream registration failed: ") +
                     ex.what();
        }
        return false;
    }

    try {
        tunnel->register_stream(
            remote_stream,
            [weak = weak_from_this(), remote_stream,
             channel_id = invite.invite_id](
                const client::Tunnel::Bytes& payload,
                client::Tunnel::InboundCredit inbound_credit) {
                if (auto self = weak.lock()) {
                    std::weak_ptr<Session> origin_session;
                    std::uint8_t origin_stream = 0;
                    bool open_pending = false;
                    {
                        std::lock_guard<std::mutex> lock(self->mutex_);
                        const auto it = self->channels_.find(remote_stream);
                        if (it == self->channels_.end() ||
                            it->second.channel_id != channel_id) {
                            return;
                        }
                        origin_session = it->second.origin;
                        origin_stream = it->second.origin_stream;
                        open_pending = it->second.open_pending;
                    }
                    if (open_pending) {
                        self->fail_channel(
                            remote_stream, channel_id,
                            "federation DATA arrived before OPEN completion");
                        return;
                    }
                    if (auto session = origin_session.lock()) {
                        try {
                            boost::asio::post(
                                self->server_io_,
                                [session, origin_stream, payload,
                                 inbound_credit =
                                     std::move(inbound_credit)]() mutable {
                                session->send_federated_data(
                                    origin_stream, payload,
                                    std::move(inbound_credit));
                            });
                            return;
                        } catch (const std::exception&) {
                        }
                    }
                    self->fail_channel(remote_stream, channel_id,
                                       "federation relay origin unavailable");
                }
            },
            [weak = weak_from_this(), remote_stream,
             channel_id = invite.invite_id](const std::string& reason) {
                if (auto self = weak.lock()) {
                    self->handle_remote_channel_close(
                        remote_stream, channel_id, reason);
                }
            });

        tunnel->open_relay_stream(
            remote_stream,
            open_json,
            [weak = weak_from_this(), remote_stream,
             channel_id = invite.invite_id](
                bool ok, const std::string& reason) {
                if (auto self = weak.lock()) {
                    self->complete_channel_open(
                        remote_stream, channel_id, ok, reason);
                }
            });
    } catch (const std::exception& ex) {
        // Ownership of the local OPEN transferred when attach succeeded.
        // Complete it here instead of returning false and making the caller
        // emit a second negative ACK.
        complete_channel_open(
            remote_stream, invite.invite_id, false,
            std::string("federation OPEN failed: ") + ex.what());
    } catch (...) {
        complete_channel_open(remote_stream, invite.invite_id, false,
                              "federation OPEN failed");
    }
    return true;
}

void FederationLink::complete_channel_open(
    std::uint8_t remote_stream,
    const std::string& channel_id,
    bool ok,
    const std::string& reason) {
    std::weak_ptr<Session> origin_session;
    std::uint8_t origin_stream = 0;
    std::shared_ptr<client::Tunnel> tunnel;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = channels_.find(remote_stream);
        if (it == channels_.end() || it->second.channel_id != channel_id ||
            !it->second.open_pending) {
            return;
        }
        it->second.open_pending = false;
        origin_session = it->second.origin;
        origin_stream = it->second.origin_stream;
        tunnel = tunnel_;
        if (!ok) {
            channels_.erase(it);
            channels_active_ =
                static_cast<std::uint32_t>(channels_.size());
        }
    }
    if (!ok && tunnel) {
        tunnel->unregister_stream(remote_stream);
    }
    if (auto session = origin_session.lock()) {
        try {
            boost::asio::post(
                server_io_, [session, origin_stream, ok, reason] {
                    session->complete_federated_open(origin_stream, ok, reason);
                });
            return;
        } catch (const std::exception&) {
            session->complete_federated_open(origin_stream, ok, reason);
            return;
        }
    }
    if (ok) {
        fail_channel(remote_stream, channel_id,
                     "federation relay origin unavailable");
    }
}

void FederationLink::handle_remote_channel_close(
    std::uint8_t remote_stream,
    const std::string& channel_id,
    const std::string& reason) {
    LinkChannel channel;
    std::shared_ptr<client::Tunnel> tunnel;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = channels_.find(remote_stream);
        if (it == channels_.end() || it->second.channel_id != channel_id) {
            return;
        }
        channel = std::move(it->second);
        channels_.erase(it);
        channels_active_ = static_cast<std::uint32_t>(channels_.size());
        tunnel = tunnel_;
    }
    if (tunnel) {
        tunnel->unregister_stream(remote_stream);
    }
    if (auto session = channel.origin.lock()) {
        try {
            boost::asio::post(
                server_io_, [session, origin_stream = channel.origin_stream,
                             open_pending = channel.open_pending, reason] {
                    if (open_pending) {
                        session->complete_federated_open(
                            origin_stream, false, reason);
                    } else {
                        session->send_federated_close(origin_stream, reason);
                    }
                });
        } catch (const std::exception&) {
            if (channel.open_pending) {
                session->complete_federated_open(
                    channel.origin_stream, false, reason);
            } else {
                session->send_federated_close(
                    channel.origin_stream, reason);
            }
        }
    }
}

void FederationLink::fail_channel(std::uint8_t remote_stream,
                                  const std::string& channel_id,
                                  const std::string& reason) {
    LinkChannel channel;
    std::shared_ptr<client::Tunnel> tunnel;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = channels_.find(remote_stream);
        if (it == channels_.end() || it->second.channel_id != channel_id) {
            return;
        }
        channel = std::move(it->second);
        channels_.erase(it);
        channels_active_ = static_cast<std::uint32_t>(channels_.size());
        tunnel = tunnel_;
    }
    if (tunnel) {
        try {
            tunnel->send_close(remote_stream, reason);
        } catch (const std::exception&) {
        }
        tunnel->unregister_stream(remote_stream);
    }
    if (auto session = channel.origin.lock()) {
        try {
            boost::asio::post(
                server_io_, [session, origin_stream = channel.origin_stream,
                             open_pending = channel.open_pending, reason] {
                    if (open_pending) {
                        session->complete_federated_open(
                            origin_stream, false, reason);
                    } else {
                        session->send_federated_close(origin_stream, reason);
                    }
                });
        } catch (const std::exception&) {
            if (channel.open_pending) {
                session->complete_federated_open(
                    channel.origin_stream, false, reason);
            } else {
                session->send_federated_close(
                    channel.origin_stream, reason);
            }
        }
    }
}

void FederationLink::close_channel(std::uint8_t remote_stream,
                                   const std::string& channel_id,
                                   const std::string& reason) {
    std::shared_ptr<client::Tunnel> tunnel;
    bool removed = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = channels_.find(remote_stream);
        if (it == channels_.end() || it->second.channel_id != channel_id) {
            return;
        }
        tunnel = tunnel_;
        channels_.erase(it);
        removed = true;
        channels_active_ = static_cast<std::uint32_t>(channels_.size());
    }
    if (removed && tunnel) {
        try {
            tunnel->send_close(remote_stream, reason);
        } catch (const std::exception&) {
        }
        tunnel->unregister_stream(remote_stream);
    }
}

void FederationLink::send_data(
    std::uint8_t remote_stream,
    const std::string& channel_id,
    const client::Tunnel::Bytes& payload,
    client::Tunnel::InboundCredit inbound_credit) {
    std::shared_ptr<client::Tunnel> tunnel;
    bool invalid_channel = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = channels_.find(remote_stream);
        if (!ready_ || !tunnel_ || it == channels_.end() ||
            it->second.channel_id != channel_id || it->second.open_pending) {
            invalid_channel = true;
        } else {
            tunnel = tunnel_;
        }
    }
    if (invalid_channel) {
        fail_channel(remote_stream, channel_id,
                     "federation channel is not ready for DATA");
        return;
    }

    try {
        auto retained_credit =
            std::make_shared<client::Tunnel::InboundCredit>(
                std::move(inbound_credit));
        client::Tunnel::Bytes forwarded(payload);
        auto completion_credit = retained_credit;
        (void)tunnel->try_send_data(
            remote_stream, std::move(forwarded),
            [weak = weak_from_this(), remote_stream, channel_id,
             retained_credit = std::move(completion_credit)](
                bool ok, std::size_t, const std::string& write_error) {
                retained_credit->release_now();
                if (!ok) {
                    if (auto self = weak.lock()) {
                        self->fail_channel(
                            remote_stream, channel_id,
                            write_error.empty()
                                ? "federation DATA write was not admitted"
                                : write_error);
                    }
                }
            });
    } catch (const std::exception& ex) {
        fail_channel(remote_stream, channel_id,
                     std::string("federation DATA forwarding failed: ") +
                         ex.what());
    } catch (...) {
        fail_channel(remote_stream, channel_id,
                     "federation DATA forwarding failed");
    }
}

void FederationLink::handle_disconnect(const std::string& reason) {
    if (closing_.load()) {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    ready_ = false;
    state_ = "closed";
    last_error_ = reason;
}

}  // namespace yume::server
