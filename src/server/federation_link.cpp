/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "server/federation_link.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <optional>
#include <stdexcept>
#include <vector>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>

#include "client/outbound_proxy.hpp"
#include "core/crypto.hpp"
#include "core/inner_crypto.hpp"
#include "core/protocol_stream.hpp"
#include "server/federation_manager.hpp"
#include "server/session.hpp"
#include "util.hpp"

namespace yume::server {

namespace {

constexpr std::chrono::milliseconds kConnectTimeout{15000};
constexpr std::size_t kMaxFederationRead = 64U * 1024U;

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

crypto::Bytes public_pem(EVP_PKEY* key) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        throw std::runtime_error("failed to allocate public-key BIO");
    }
    if (PEM_write_bio_PUBKEY(bio, key) != 1) {
        BIO_free(bio);
        throw std::runtime_error("failed to encode public key");
    }
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    if (len <= 0 || !data) {
        BIO_free(bio);
        throw std::runtime_error("failed to read public key");
    }
    crypto::Bytes out(reinterpret_cast<std::uint8_t*>(data),
                      reinterpret_cast<std::uint8_t*>(data) + len);
    BIO_free(bio);
    return out;
}

void append_field(crypto::Bytes& payload, const crypto::Bytes& field) {
    if (field.size() > 0xFFFF) {
        throw std::runtime_error("auth field too large");
    }
    payload.push_back(static_cast<std::uint8_t>((field.size() >> 8) & 0xFF));
    payload.push_back(static_cast<std::uint8_t>(field.size() & 0xFF));
    payload.insert(payload.end(), field.begin(), field.end());
}

crypto::Bytes auth_payload(EVP_PKEY* pubkey,
                           const crypto::Bytes& signature,
                           const std::optional<crypto::Bytes>& pq_ciphertext,
                           const std::optional<crypto::Bytes>& pq_salt,
                           const std::optional<std::string>& inner_mode,
                           const std::optional<bool>& inner_hop,
                           const std::optional<inner::KdfParams>& inner_kdf) {
    crypto::Bytes payload;
    append_field(payload, public_pem(pubkey));
    append_field(payload, signature);
    if (pq_ciphertext) {
        append_field(payload, *pq_ciphertext);
        append_field(payload, pq_salt.value_or(crypto::Bytes{}));
        if (inner_mode) {
            append_field(payload, crypto::Bytes(inner_mode->begin(), inner_mode->end()));
        }
        if (inner_hop) {
            append_field(payload, crypto::Bytes{*inner_hop ? static_cast<std::uint8_t>('1')
                                                           : static_cast<std::uint8_t>('0')});
        }
        if (inner_kdf) {
            append_field(payload, crypto::Bytes(inner_kdf->name.begin(), inner_kdf->name.end()));
            crypto::Bytes params(16, 0);
            auto put = [&](std::size_t off, std::uint32_t v) {
                params[off] = static_cast<std::uint8_t>((v >> 24) & 0xFF);
                params[off + 1] = static_cast<std::uint8_t>((v >> 16) & 0xFF);
                params[off + 2] = static_cast<std::uint8_t>((v >> 8) & 0xFF);
                params[off + 3] = static_cast<std::uint8_t>(v & 0xFF);
            };
            put(0, inner_kdf->argon2_time);
            put(4, inner_kdf->argon2_memory);
            put(8, inner_kdf->argon2_parallelism);
            put(12, inner_kdf->pbkdf2_iters);
            append_field(payload, params);
        }
    }
    return payload;
}

inner::Argon2Limits parse_argon2_limits(const protocol::Frame& challenge) {
    inner::Argon2Limits limits;
    if (challenge.payload.size() <= 32 || challenge.payload[32] != static_cast<std::uint8_t>('{')) {
        return limits;
    }
    try {
        std::string text(challenge.payload.begin() + 32, challenge.payload.end());
        auto json = nlohmann::json::parse(text);
        auto read = [&](const char* key) -> std::uint32_t {
            if (!json.contains(key) || !json[key].is_number()) {
                return 0;
            }
            return static_cast<std::uint32_t>(
                std::min<std::uint64_t>(json[key].get<std::uint64_t>(),
                                        std::numeric_limits<std::uint32_t>::max()));
        };
        limits.time_max = read("argon2_time_max");
        limits.memory_max = read("argon2_mem_max");
        limits.parallelism_max = read("argon2_par_max");
    } catch (...) {
    }
    return limits;
}

std::string write_temp_pq_public(const std::string& peer_id, const std::string& raw) {
    auto path = std::filesystem::temp_directory_path() /
                ("yume-federation-" + peer_id + "-pq_public.key");
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw std::runtime_error("failed to create federation PQ public key file");
    }
    out.write(raw.data(), static_cast<std::streamsize>(raw.size()));
    return path.string();
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
    closing_.store(false);
    worker_ = std::thread([self = shared_from_this()] {
        self->run_loop();
    });
    directory_worker_ = std::thread([self = shared_from_this()] {
        while (!self->closing_.load()) {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            if (!self->closing_.load() && self->is_ready()) {
                self->request_directory();
            }
        }
    });
}

void FederationLink::close() {
    closing_.store(true);
    {
        std::lock_guard<std::mutex> lock(write_mutex_);
        if (active_stream_) {
            boost::system::error_code ec;
            active_stream_->lowest_layer().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
            active_stream_->lowest_layer().close(ec);
        }
    }
    if (worker_.joinable()) {
        worker_.join();
    }
    if (directory_worker_.joinable()) {
        directory_worker_.join();
    }
    reset_transport();
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
    out.last_error = last_error_;
    out.last_handshake_ts = last_handshake_ts_;
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
    std::unique_ptr<client::TransportCore> transport;
    std::vector<LinkChannel> closed_channels;
    {
        std::lock_guard<std::mutex> write_lock(write_mutex_);
        active_stream_ = nullptr;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ready_ = false;
        transport = std::move(transport_);
        closed_channels.reserve(channels_.size());
        for (const auto& entry : channels_) {
            closed_channels.push_back(entry.second);
        }
        channels_.clear();
        channels_active_ = 0;
    }
    if (transport) {
        (void)transport->shutdown();
    }
    for (const auto& channel : closed_channels) {
        if (auto session = channel.origin.lock()) {
            boost::asio::post(server_io_, [session, origin_stream = channel.origin_stream] {
                session->send_federated_close(origin_stream, "federation link closed");
            });
        }
    }
}

void FederationLink::run_loop() {
    int backoff_ms = 1000;
    while (!closing_.load()) {
        try {
            set_state("dialing");
            boost::asio::io_context io;
            // Both endpoints are Yume servers we control, so TLS 1.3 only.
            // Consistent with the obfs / tls_stealth contexts elsewhere.
            boost::asio::ssl::context ctx(boost::asio::ssl::context::tlsv13_client);
            ctx.set_options(boost::asio::ssl::context::default_workarounds);
            SSL_CTX_set_min_proto_version(ctx.native_handle(), TLS1_3_VERSION);
            SSL_CTX_set_max_proto_version(ctx.native_handle(), TLS1_3_VERSION);
            ctx.set_verify_mode(boost::asio::ssl::verify_peer);
            ctx.set_default_verify_paths();
            if (!cfg_.federation_anonym_ca.empty()) {
                ctx.load_verify_file(cfg_.federation_anonym_ca);
            }
            boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream(io, ctx);
            if (!connect_and_auth(io, stream)) {
                continue;
            }
            backoff_ms = 1000;
            std::array<std::uint8_t, kMaxFederationRead> buf{};
            while (!closing_.load()) {
                boost::system::error_code ec;
                std::size_t n = stream.read_some(boost::asio::buffer(buf), ec);
                if (ec) {
                    throw boost::system::system_error(ec);
                }
                client::TransportCore* transport = nullptr;
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    transport = transport_.get();
                }
                if (transport && n > 0) {
                    transport->feed_tls_bytes(buf.data(), n);
                }
            }
        } catch (const std::exception& ex) {
            if (!closing_.load()) {
                handle_disconnect(ex.what());
                reset_transport();
                std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms));
                backoff_ms = std::min(backoff_ms * 2, 30000);
            }
        }
    }
    set_state("closed");
    reset_transport();
}

bool FederationLink::connect_and_auth(boost::asio::io_context& io,
                                      boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream) {
    if (!cfg_.outbound_proxy_url.empty()) {
        client::outbound_proxy::Config proxy_cfg;
        std::string parse_error;
        if (!client::outbound_proxy::parse_proxy_url(cfg_.outbound_proxy_url, proxy_cfg, &parse_error)) {
            throw std::runtime_error("outbound proxy: " + parse_error);
        }
        auto result = client::outbound_proxy::socks5_dial(stream.next_layer(),
                                                          io,
                                                          proxy_cfg,
                                                          peer_.host,
                                                          peer_.port,
                                                          kConnectTimeout);
        if (!result.ok) {
            throw std::runtime_error(result.error.empty() ? "proxy dial failed" : result.error);
        }
    } else {
        boost::asio::ip::tcp::resolver resolver(io);
        auto endpoints = resolver.resolve(peer_.host, std::to_string(peer_.port));
        boost::asio::connect(stream.next_layer(), endpoints);
    }
    stream.next_layer().set_option(boost::asio::ip::tcp::no_delay(true));
    SSL_set_tlsext_host_name(stream.native_handle(), peer_.host.c_str());
    SSL_set1_host(stream.native_handle(), peer_.host.c_str());
    stream.handshake(boost::asio::ssl::stream_base::client);
    if (!peer_.tls_pin_sha256.empty() && peer_cert_sha256(stream.native_handle()) != peer_.tls_pin_sha256) {
        throw std::runtime_error("TLS pin mismatch");
    }

    set_state("authenticating");
    protocol::Frame challenge = protocol::read_frame(stream);
    if (challenge.header.type != protocol::AUTH) {
        throw std::runtime_error("peer did not send AUTH challenge");
    }

    std::optional<crypto::Bytes> pq_ciphertext;
    std::optional<crypto::Bytes> pq_salt;
    std::optional<crypto::Bytes> inner_key;
    std::optional<std::string> inner_mode;
    std::optional<bool> inner_hop;
    std::optional<inner::KdfParams> inner_kdf;
    if (!cached_peer_pq_public_path_.empty()) {
        inner::Config inner_cfg;
        inner_cfg.enabled = true;
        inner_cfg.pq_public_key = cached_peer_pq_public_path_;
        inner_cfg.allow_embedded_master = cfg_.allow_embedded_master;
        inner_cfg.argon2_limits = parse_argon2_limits(challenge);
        auto hs = inner::client_prepare(inner_cfg, cfg_.inner_heavy);
        if (!hs.enabled || hs.key.empty()) {
            throw std::runtime_error("inner crypto init failed");
        }
        pq_ciphertext = hs.pq_ciphertext;
        pq_salt = hs.salt;
        inner_key = hs.key;
        inner_mode = cfg_.inner_heavy ? std::optional<std::string>("heavy")
                                      : std::optional<std::string>("light");
        inner_hop = cfg_.inner_hop;
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

    auto kp = crypto::load_keypair(cfg_.federation_auth_key, "");
    crypto::Bytes signature = crypto::sign_message(kp.private_key.get(), challenge.payload);
    crypto::Bytes payload = auth_payload(kp.public_key.get() ? kp.public_key.get() : kp.private_key.get(),
                                         signature,
                                         pq_ciphertext,
                                         pq_salt,
                                         inner_mode,
                                         inner_hop,
                                         inner_kdf);
    protocol::Frame auth{{static_cast<std::uint32_t>(payload.size()), protocol::AUTH, 0, 0}, payload};
    protocol::send_frame(stream, auth);

    protocol::Frame anon = protocol::read_frame(stream);
    if (anon.header.type != protocol::ANON) {
        throw std::runtime_error("peer did not send server info");
    }
    nlohmann::json info = nlohmann::json::parse(std::string(anon.payload.begin(), anon.payload.end()));
    const std::string server_error = info.value("error", "");
    if (!server_error.empty()) {
        std::string pq_path;
        std::string pq_error;
        if (!inner_key && configure_inner_from_server_info(info, &pq_path, &pq_error)) {
            cached_peer_pq_public_path_ = pq_path;
            set_state("dialing", "peer requested inner crypto; retrying with PQ");
            return false;
        }
        throw std::runtime_error(server_error);
    }

    auto transport = std::make_unique<client::TransportCore>();
    transport->set_write_handler([this](std::shared_ptr<client::TransportCore::Bytes> data,
                                        client::TransportCore::WriteCompletion done) {
        boost::system::error_code ec;
        std::size_t n = 0;
        {
            std::lock_guard<std::mutex> lock(write_mutex_);
            if (!active_stream_) {
                if (done) {
                    done(false, 0, "federation stream unavailable");
                }
                return;
            }
            n = boost::asio::write(*active_stream_, boost::asio::buffer(*data), ec);
        }
        if (done) {
            done(!ec, n, ec ? ec.message() : std::string{});
        }
    });
    transport->set_close_transport_handler([this](const std::string& reason) {
        handle_disconnect(reason);
    });
    transport->set_control_handler([weak = weak_from_this()](const nlohmann::json& json) {
        if (auto self = weak.lock()) {
            boost::asio::post(self->server_io_, [self, json] {
                self->handle_control(json);
            });
        }
    });
    if (inner_key) {
        transport->set_inner_key(*inner_key);
        const bool hop_enabled = info.value("hop_enabled", false);
        const std::uint32_t hop_interval = static_cast<std::uint32_t>(info.value("hop_interval_ms", 0));
        const std::int64_t server_time = info.value("server_time_ms", 0LL);
        transport->set_hop(hop_enabled, hop_interval, server_time == 0 ? 0 : server_time - epoch_now_ms());
    }
    transport->start();
    {
        std::lock_guard<std::mutex> write_lock(write_mutex_);
        active_stream_ = &stream;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        transport_ = std::move(transport);
        ready_ = true;
        last_handshake_ts_ = epoch_now_ms();
        state_ = "ready";
        last_error_.clear();
    }
    util::log_info("federation peer ready: " + peer_.id);
    client::TransportCore* t = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        t = transport_.get();
    }
    if (t) {
        t->send_control_json({{"cmd", "federation.hello"},
                              {"peer_id", cfg_.server_id},
                              {"server_id", cfg_.server_id},
                              {"server_name", cfg_.server_name}});
    }
    request_directory();
    return true;
}

bool FederationLink::configure_inner_from_server_info(const nlohmann::json& info,
                                                      std::string* pq_public_path,
                                                      std::string* error) {
    const std::string pq_pub_b64 = info.value("pq_pub", "");
    if (pq_pub_b64.empty()) {
        if (error) {
            *error = "peer did not provide pq_pub";
        }
        return false;
    }
    std::string raw = util::base64_decode(pq_pub_b64);
    if (raw.empty()) {
        if (error) {
            *error = "peer pq_pub decode failed";
        }
        return false;
    }
    try {
        if (pq_public_path) {
            *pq_public_path = write_temp_pq_public(peer_.id, raw);
        }
        return true;
    } catch (const std::exception& ex) {
        if (error) {
            *error = ex.what();
        }
        return false;
    }
}

void FederationLink::handle_control(const nlohmann::json& json) {
    const std::string cmd = json.value("cmd", "");
    if (cmd == "federation.hello") {
        std::lock_guard<std::mutex> lock(mutex_);
        remote_namespace_for_local_ = json.value("your_peer_id", remote_namespace_for_local_);
        return;
    }
    if (cmd == "federation.directory") {
        std::vector<control::EndpointInfo> endpoints;
        if (json.contains("endpoints") && json["endpoints"].is_array()) {
            for (const auto& item : json["endpoints"]) {
                endpoints.push_back(control::endpoint_from_json(item));
            }
        }
        if (owner_) {
            owner_->update_directory(peer_.id,
                                     json.value("server_id", ""),
                                     json.value("server_name", ""),
                                     endpoints);
        }
        return;
    }
    if (cmd == "federation.invite.reply" || cmd == "invite.reply") {
        std::shared_ptr<Session> initiator;
        control::PendingInvite invite;
        std::string error;
        if (owner_ && owner_->handle_invite_reply(peer_.id,
                                                  control::invite_from_json(json),
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

void FederationLink::request_directory() {
    client::TransportCore* transport = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!ready_ || !transport_) {
            return;
        }
        transport = transport_.get();
    }
    transport->send_control_json({{"cmd", "federation.directory"},
                                  {"request_id", "dir-" + std::to_string(epoch_now_ms())}});
}

bool FederationLink::send_invite_request(const control::PendingInvite& invite,
                                         const std::string& raw_remote_id,
                                         std::string* error) {
    client::TransportCore* transport = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!ready_ || !transport_) {
            if (error) {
                *error = "federation peer not ready";
            }
            return false;
        }
        transport = transport_.get();
    }
    nlohmann::json req = control::invite_to_json(invite, false);
    req["cmd"] = "federation.invite.request";
    req["raw_to_id"] = raw_remote_id;
    transport->send_control_json(req);
    return true;
}

bool FederationLink::open_channel(const std::shared_ptr<Session>& origin,
                                  std::uint8_t origin_stream_id,
                                  const control::PendingInvite& invite,
                                  const nlohmann::json& open_json,
                                  std::string* error) {
    client::TransportCore* transport = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!ready_ || !transport_) {
            if (error) {
                *error = "federation peer not ready";
            }
            return false;
        }
        transport = transport_.get();
    }
    const std::uint8_t remote_stream = transport->reserve_stream_id();
    if (remote_stream == 0) {
        if (error) {
            *error = "no federation stream ids available";
        }
        return false;
    }
    if (!origin->attach_federated_stream(
            origin_stream_id,
            invite.channel_kind,
            invite.invite_id,
            invite.from_endpoint_id,
            invite.to_endpoint_id,
            [weak = weak_from_this(), remote_stream](const crypto::Bytes& payload) {
                if (auto self = weak.lock()) {
                    self->send_data(remote_stream, payload);
                }
            },
            [weak = weak_from_this(), remote_stream](const std::string& reason) {
                if (auto self = weak.lock()) {
                    self->close_channel(remote_stream, reason);
                }
            })) {
        transport->release_reserved_stream(remote_stream);
        if (error) {
            *error = "stream already exists";
        }
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(mutex_);
        channels_[remote_stream] = LinkChannel{origin, origin_stream_id, remote_stream, invite.invite_id};
        channels_active_ = static_cast<std::uint32_t>(channels_.size());
    }
    transport->register_stream(
        remote_stream,
        [weak = weak_from_this(), remote_stream](const client::TransportCore::Bytes& payload) {
            if (auto self = weak.lock()) {
                std::weak_ptr<Session> origin;
                std::uint8_t origin_stream = 0;
                {
                    std::lock_guard<std::mutex> lock(self->mutex_);
                    auto it = self->channels_.find(remote_stream);
                    if (it == self->channels_.end()) {
                        return;
                    }
                    origin = it->second.origin;
                    origin_stream = it->second.origin_stream;
                }
                if (auto session = origin.lock()) {
                    boost::asio::post(self->server_io_, [session, origin_stream, payload] {
                        session->send_federated_data(origin_stream, payload);
                    });
                }
            }
        },
        [weak = weak_from_this(), remote_stream](const std::string& reason) {
            if (auto self = weak.lock()) {
                std::weak_ptr<Session> origin;
                std::uint8_t origin_stream = 0;
                {
                    std::lock_guard<std::mutex> lock(self->mutex_);
                    auto it = self->channels_.find(remote_stream);
                    if (it == self->channels_.end()) {
                        return;
                    }
                    origin = it->second.origin;
                    origin_stream = it->second.origin_stream;
                    self->channels_.erase(it);
                    self->channels_active_ = static_cast<std::uint32_t>(self->channels_.size());
                }
                if (auto session = origin.lock()) {
                    boost::asio::post(self->server_io_, [session, origin_stream, reason] {
                        session->send_federated_close(origin_stream, reason);
                    });
                }
            }
        });

    nlohmann::json forwarded = open_json;
    transport->open_relay_stream(
        remote_stream,
        forwarded,
        [weak = weak_from_this(), origin, origin_stream_id, remote_stream](bool ok, const std::string& reason) {
            if (auto self = weak.lock()) {
                boost::asio::post(self->server_io_, [self, origin, origin_stream_id, remote_stream, ok, reason] {
                    origin->complete_federated_open(origin_stream_id, ok, reason);
                    if (!ok) {
                        std::lock_guard<std::mutex> lock(self->mutex_);
                        self->channels_.erase(remote_stream);
                        self->channels_active_ = static_cast<std::uint32_t>(self->channels_.size());
                    }
                });
            }
        });
    return true;
}

void FederationLink::close_channel(std::uint8_t remote_stream, const std::string& reason) {
    client::TransportCore* transport = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (transport_) {
            transport = transport_.get();
        }
        channels_.erase(remote_stream);
        channels_active_ = static_cast<std::uint32_t>(channels_.size());
    }
    if (transport) {
        transport->send_close(remote_stream, reason);
        transport->unregister_stream(remote_stream);
    }
}

void FederationLink::send_data(std::uint8_t remote_stream, const client::TransportCore::Bytes& payload) {
    client::TransportCore* transport = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!ready_ || !transport_) {
            return;
        }
        transport = transport_.get();
    }
    transport->send_data(remote_stream, payload);
}

void FederationLink::handle_disconnect(const std::string& reason) {
    if (closing_.load()) {
        return;
    }
    set_state("closed", reason);
    std::lock_guard<std::mutex> lock(write_mutex_);
    if (active_stream_) {
        boost::system::error_code ec;
        active_stream_->lowest_layer().close(ec);
    }
}

}  // namespace yume::server
