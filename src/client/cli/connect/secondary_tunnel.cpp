/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/connect/secondary_tunnel.hpp"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/ssl.h>

#include "client/cli/connect/auth.hpp"
#include "client/cli/connect/cert.hpp"
#include "client/cli/connect/io.hpp"
#include "client/cli/connect/server_info.hpp"
#include "client/transport/tunnel.hpp"
#include "core/security/inner_crypto.hpp"
#include "core/protocol/protocol.hpp"
#include "core/stealth/obfs.hpp"
#include "core/stealth/tls_stealth.hpp"
#include "core/version.hpp"
#include "util.hpp"

namespace yume::client {
namespace {

constexpr int kSocketBufferBytes = 2 * 1024 * 1024;

}  // namespace

std::shared_ptr<Tunnel> connect_secondary_tunnel(boost::asio::io_context& io,
                                                 boost::asio::ssl::context& ctx,
                                                 const ClientConfig& cfg,
                                                 const outbound_proxy::Config& proxy_cfg,
                                                 int index,
                                                 std::optional<tls_fingerprint::BrowserProfile> profile,
                                                 std::string carrier_user_agent,
                                                 std::uint64_t* completed_tls_connections) {
    std::unique_ptr<tls_stealth::StealthContext> owned_stealth_context;
    boost::asio::ssl::context* connection_ctx = &ctx;
    if (profile.has_value()) {
        tls_stealth::StealthConfig stealth_config;
        stealth_config.enabled = true;
        stealth_config.target_profile = *profile;
        owned_stealth_context =
            std::make_unique<tls_stealth::StealthContext>(stealth_config);
        connection_ctx = &owned_stealth_context->get_context();
        if (cfg.obfuscation) {
            obfs::configure_alpn(*connection_ctx, false, true);
        }
        connection_ctx->set_verify_mode(boost::asio::ssl::verify_peer);
        connection_ctx->set_default_verify_paths();
        if (!cfg.tls_ca_cert.empty()) {
            connection_ctx->load_verify_file(cfg.tls_ca_cert);
        }
    }

    // SSL_new holds a reference to SSL_CTX, so the stream remains valid after
    // this function returns even when the per-connection StealthContext owner
    // below goes out of scope.
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream(io, *connection_ctx);
    const std::string& tls_name = effective_tls_server_name(cfg);
    if (proxy_cfg.type == outbound_proxy::Type::Socks5) {
        auto dr = outbound_proxy::socks5_dial(
            stream.next_layer(), io, proxy_cfg,
            cfg.server, cfg.port, kConnectTimeout);
        if (dr.timed_out) {
            throw std::runtime_error("proxy timed out");
        }
        if (!dr.ok) {
            throw std::runtime_error(dr.error.empty() ? "outbound proxy failed"
                                                      : "outbound proxy: " + dr.error);
        }
    } else {
        boost::asio::ip::tcp::resolver resolver(io);
        auto endpoints = resolver.resolve(boost::asio::ip::tcp::v4(), cfg.server, std::to_string(cfg.port));
        auto cr = connect_with_timeout(stream.next_layer(), endpoints, io, kConnectTimeout);
        if (cr.timed_out) {
            throw std::runtime_error("connect timeout");
        }
        if (cr.ec) {
            throw boost::system::system_error(cr.ec);
        }
    }

    boost::system::error_code keep_ec;
    stream.next_layer().set_option(boost::asio::socket_base::keep_alive(true), keep_ec);
    boost::system::error_code recvbuf_ec;
    stream.next_layer().set_option(boost::asio::socket_base::receive_buffer_size(kSocketBufferBytes), recvbuf_ec);
    boost::system::error_code sendbuf_ec;
    stream.next_layer().set_option(boost::asio::socket_base::send_buffer_size(kSocketBufferBytes), sendbuf_ec);
    boost::system::error_code nodelay_ec;
    stream.next_layer().set_option(boost::asio::ip::tcp::no_delay(true), nodelay_ec);
    SSL_set_tlsext_host_name(stream.native_handle(), tls_name.c_str());
    SSL_set1_host(stream.native_handle(), tls_name.c_str());

    auto hr = handshake_with_timeout(stream, io, kHandshakeTimeout);
    if (hr.timed_out) {
        throw std::runtime_error("TLS handshake timeout");
    }
    if (hr.ec) {
        throw std::runtime_error("TLS handshake failed: " + hr.ec.message());
    }
    if (completed_tls_connections) {
        ++*completed_tls_connections;
    }
    if (!cfg.tls_pin_sha256.empty()) {
        std::string fp = get_peer_cert_fingerprint(nullptr, stream.native_handle());
        if (fp.empty() || fp != cfg.tls_pin_sha256) {
            throw std::runtime_error("TLS pin mismatch");
        }
    }

    std::vector<uint8_t> prefetched_tls_bytes;
    std::unique_ptr<obfs::H2Carrier> h2_carrier;
    if (cfg.obfuscation) {
        require_h2_carrier_alpn(stream, tls_name, cfg.port);
        if (!cfg.obfs_secret_material) {
            throw std::runtime_error("YUME 2.0 admission secret was not loaded");
        }
        perform_h2_carrier_handshake(stream, io, tls_name, cfg.port,
                                     *cfg.obfs_secret_material, carrier_user_agent,
                                     &prefetched_tls_bytes, &h2_carrier);
    }

    protocol::Frame auth_challenge = read_auth_challenge(
        stream,
        io,
        tls_name,
        cfg.port,
        &prefetched_tls_bytes,
        h2_carrier.get());
    if (!h2_carrier || !cfg.inner_psk_material) {
        throw std::runtime_error("YUME 2.0 requires H2 carrier and inner PSK");
    }
    auto v2_ratchet = send_auth_v2_response(
        stream, io, cfg.identity, auth_challenge,
        *cfg.inner_psk_material, *h2_carrier);

    auto server_info_timeout = kServerInfoTimeout;
    protocol::Frame info = h2_carrier
        ? read_frame_over_h2_with_timeout(
              stream, io, *h2_carrier, &prefetched_tls_bytes,
              server_info_timeout, "server info", cfg.server, cfg.port)
        : read_frame_with_timeout(
              stream, io, server_info_timeout, "server info", cfg.server,
              cfg.port, true, &prefetched_tls_bytes);
    info = open_auth_ok_v2(*v2_ratchet, info);
    if (info.header.type != protocol::ANON) {
        throw std::runtime_error("unexpected server info response");
    }
    ServerInfoPayload server_info = parse_server_info_payload(info);
    if (!server_info.error.empty()) {
        throw std::runtime_error(server_info.error);
    }
    if (server_info.version != yume::kVersion) {
        throw std::runtime_error("transport core version mismatch");
    }
    if (cfg.require_anonym && server_info.mode != "anonym") {
        throw std::runtime_error("server is not in anonym mode");
    }
    auto tunnel = std::make_shared<Tunnel>(
        std::move(stream), std::move(h2_carrier),
        std::move(prefetched_tls_bytes), std::move(v2_ratchet));
    tunnel->set_obfs_shape(cfg.obfs_pad_multiple, cfg.obfs_jitter_ms);
    tunnel->set_close_handler([index](const std::string& reason) {
        util::log_warn("SOCKS secondary tunnel " + std::to_string(index) +
                       " closed: " + reason);
    });
    return tunnel;
}

}  // namespace yume::client
