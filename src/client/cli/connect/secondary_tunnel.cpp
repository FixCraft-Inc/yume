/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
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
                                                 int index) {
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream(io, ctx);
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
    if (!cfg.tls_pin_sha256.empty()) {
        std::string fp = get_peer_cert_fingerprint(nullptr, stream.native_handle());
        if (fp.empty() || fp != cfg.tls_pin_sha256) {
            throw std::runtime_error("TLS pin mismatch");
        }
    }

    std::vector<uint8_t> prefetched_tls_bytes;
    if (cfg.obfuscation) {
        require_h2_carrier_alpn(stream, tls_name, cfg.port);
        perform_h2_carrier_handshake(stream, io, tls_name, cfg.port,
                                     cfg.obfs_secret, &prefetched_tls_bytes);
    }

    protocol::Frame auth_challenge = read_auth_challenge(
        stream,
        io,
        tls_name,
        cfg.port,
        &prefetched_tls_bytes);
    inner::Argon2Limits argon2_limits =
        parse_auth_challenge_argon2_limits(auth_challenge);

    std::optional<crypto::Bytes> pq_ciphertext;
    std::optional<crypto::Bytes> pq_salt;
    std::optional<crypto::Bytes> inner_key;
    std::optional<std::string> inner_mode;
    std::optional<bool> inner_hop;
    std::optional<inner::KdfParams> inner_kdf;
    if (cfg.inner_crypto) {
        inner::Config inner_cfg;
        inner_cfg.enabled = true;
        inner_cfg.pq_public_key = cfg.pq_public_key;
        inner_cfg.allow_embedded_master = cfg.allow_embedded_master;
        inner_cfg.argon2_limits = argon2_limits;
        auto hs = inner::client_prepare(inner_cfg, cfg.inner_heavy);
        if (!hs.enabled || hs.key.empty()) {
            throw std::runtime_error("inner crypto init failed");
        }
        pq_ciphertext = hs.pq_ciphertext;
        pq_salt = hs.salt;
        inner_key = hs.key;
        inner_mode = cfg.inner_heavy ? std::optional<std::string>("heavy")
                                     : std::optional<std::string>("light");
        inner_hop = cfg.inner_hop;
        if (!hs.kdf.empty()) {
            inner::KdfParams params;
            params.name = hs.kdf;
            params.argon2_time = hs.argon2_time;
            params.argon2_memory = hs.argon2_memory;
            params.argon2_parallelism = hs.argon2_parallelism;
            params.pbkdf2_iters = hs.pbkdf2_iters;
            inner_kdf = params;
        }
    }

    send_auth_response(stream,
                       cfg.identity,
                       auth_challenge,
                       pq_ciphertext,
                       pq_salt,
                       inner_mode,
                       inner_hop,
                       inner_kdf);

    auto server_info_timeout = kServerInfoTimeout;
    if (pq_ciphertext.has_value() && cfg.inner_crypto) {
        server_info_timeout = cfg.inner_heavy ? kServerInfoTimeoutInnerHeavy
                                              : kServerInfoTimeoutInner;
    }
    protocol::Frame info = read_frame_with_timeout(
        stream,
        io,
        server_info_timeout,
        "server info",
        cfg.server,
        cfg.port,
        true);
    if (info.header.type != protocol::ANON) {
        throw std::runtime_error("unexpected server info response");
    }
    ServerInfoPayload server_info = parse_server_info_payload(info);
    if (!server_info.error.empty()) {
        throw std::runtime_error(server_info.error);
    }
    if (server_info.version != yume::kVersion) {
        throw std::runtime_error("server version mismatch");
    }
    if (cfg.require_anonym && server_info.mode != "anonym") {
        throw std::runtime_error("server is not in anonym mode");
    }
    if (server_info.have_inner_caps) {
        if (inner_key.has_value() && !server_info.server_inner_supported) {
            throw std::runtime_error("server does not support inner crypto");
        }
        if (!inner_key.has_value() && server_info.server_inner_required) {
            throw std::runtime_error("server requires inner crypto");
        }
    }

    std::uint32_t hop_interval_ms = server_info.server_hop_interval_ms;
    if (hop_interval_ms == 0) {
        hop_interval_ms = cfg.hop_interval_ms;
    }
    if (hop_interval_ms > 0) {
        hop_interval_ms = std::clamp<std::uint32_t>(hop_interval_ms, 250, 1000);
    }
    std::int64_t hop_offset_ms = 0;
    if (server_info.server_time_ms > 0) {
        hop_offset_ms = server_info.server_time_ms - util::now_ms();
    }
    const bool hop_enabled =
        inner_key.has_value() &&
        cfg.inner_hop &&
        server_info.server_hop_enabled &&
        hop_interval_ms > 0;

    auto tunnel = std::make_shared<Tunnel>(std::move(stream));
    if (inner_key.has_value()) {
        tunnel->set_inner_key(*inner_key);
    }
    tunnel->set_hop(hop_enabled, hop_interval_ms, hop_offset_ms);
    tunnel->set_obfs_shape(cfg.obfs_pad_multiple, cfg.obfs_jitter_ms);
    tunnel->set_close_handler([index](const std::string& reason) {
        util::log_warn("SOCKS secondary tunnel " + std::to_string(index) +
                       " closed: " + reason);
    });
    return tunnel;
}

}  // namespace yume::client
