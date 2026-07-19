/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * ----------------------------------------------------------------
 * Session authentication and inner-crypto methods, extracted verbatim
 * from session.cpp:
 *   - send_auth_challenge   — server-issued AUTH challenge
 *   - handle_auth           — client AUTH-response verification (key
 *                             match, optional inner ML-KEM handshake)
 *   - decrypt/encrypt_inner_payload, current_hop_id — inner AEAD with
 *                             live hop-key derivation
 *
 * Same Session:: class, same wire output, no behavior change. Shared
 * helpers via server/session/internal.hpp.
 * ---------------------------------------------------------------- */

#include "server/session/session.hpp"
#include "core/security/secure_erase.hpp"
#include "core/security/auth_v2.hpp"
#include "core/app_codec/builtin/monero_rpc.hpp"
#include "server/runtime/manager.hpp"
#include "server/session/internal.hpp"

#include <algorithm>

#if YUME_USE_BASEFWX
#include <basefwx/crypto.hpp>
#include <basefwx/pq.hpp>
#include <basefwx/x25519.hpp>
#endif

namespace yume::server {

using namespace detail;

void Session::send_auth_challenge() {
#if YUME_USE_BASEFWX
    if (!v2_h2_tunnel_active_ || !cfg_.inner_psk_material) {
        close_with_reason("YUME 2.0 AUTH requires admitted H2 carrier and PSK");
        return;
    }
    try {
        auto ephemeral = std::make_unique<AuthV2Ephemeral>();
        ephemeral->mlkem = basefwx::pq::GenerateKeyPair(
            basefwx::pq::KemAlgorithm::MlKem1024);
        ephemeral->x25519 = basefwx::x25519::GenerateKeyPair();
        ephemeral->psk_salt = basefwx::crypto::RandomBytes(32);
        ephemeral->transcript_salt = basefwx::crypto::RandomBytes(32);
        crypto::Bytes random_challenge = basefwx::crypto::RandomBytes(32);
        challenge_ = auth_v2::BuildChallenge(
            random_challenge, ephemeral->mlkem.public_key,
            ephemeral->x25519.public_key, ephemeral->psk_salt,
            ephemeral->transcript_salt);
        auth_v2_ephemeral_ = std::move(ephemeral);
    } catch (const std::exception& ex) {
        close_with_reason("AUTH v2 challenge creation failed: " +
                          std::string(ex.what()));
        return;
    }
    protocol::Frame frame{{static_cast<uint32_t>(challenge_.size()),
                           protocol::AUTH, 0, 0}, challenge_};
    auto self = shared_from_this();
    async_write_frame(frame, [self](const boost::system::error_code& ec,
                                    std::size_t) {
        if (ec) {
            self->close_with_reason("AUTH challenge write failed: " + ec.message());
            return;
        }
        self->read_header();
    });
#else
    close_with_reason("YUME 2.0 AUTH requires BaseFWX");
#endif
}

void Session::clear_hop_key_cache() {
    security::secure_erase(encrypt_hop_key_);
    security::secure_erase(decrypt_hop_key_);
    encrypt_hop_id_.reset();
    decrypt_hop_id_.reset();
}

bool Session::decrypt_inner_payload(uint8_t frame_type,
                                    uint8_t stream_id,
                                    const crypto::Bytes& input,
                                    crypto::Bytes* output) {
    if (!output) {
        return false;
    }
    if (!inner_key_.has_value()) {
        *output = input;
        return true;
    }
    auto try_decrypt = [&](const crypto::Bytes& key) -> bool {
        try {
            if (!hop_enabled_ || hop_interval_ms_ == 0) {
                *output = inner::decrypt_payload(key, frame_type, stream_id, input);
                return true;
            }
            std::uint64_t hop_id = current_hop_id();
            auto in_window = [hop_id](std::uint64_t id) {
                return id <= hop_id
                    ? (hop_id - id) <= kHopDecryptWindow
                    : (id - hop_id) <= kHopDecryptWindow;
            };
            if (decrypt_hop_id_.has_value() && !decrypt_hop_key_.empty() && in_window(*decrypt_hop_id_)) {
                try {
                    *output = inner::decrypt_payload(decrypt_hop_key_, frame_type, stream_id, input);
                    return true;
                } catch (...) {
                }
            }
            std::uint64_t candidates[1 + (kHopDecryptWindow * 2)];
            std::size_t candidate_count = 0;
            candidates[candidate_count++] = hop_id;
            for (std::uint64_t delta = 1; delta <= kHopDecryptWindow; ++delta) {
                if (hop_id >= delta) {
                    candidates[candidate_count++] = hop_id - delta;
                }
                candidates[candidate_count++] = hop_id + delta;
            }
            for (std::size_t i = 0; i < candidate_count; ++i) {
                std::uint64_t id = candidates[i];
                if (decrypt_hop_id_.has_value() && *decrypt_hop_id_ == id) {
                    continue;
                }
                crypto::Bytes hop_key = inner::derive_hop_key(key, id);
                try {
                    *output = inner::decrypt_payload(hop_key, frame_type, stream_id, input);
                    decrypt_hop_id_ = id;
                    decrypt_hop_key_ = hop_key;
                    return true;
                } catch (...) {
                }
            }
            return false;
        } catch (...) {
            return false;
        }
    };

    if (try_decrypt(*inner_key_)) {
        return true;
    }
    if (!inner_key_alt_.has_value()) {
        return false;
    }
    clear_hop_key_cache();
    if (try_decrypt(*inner_key_alt_)) {
        inner_key_ = inner_key_alt_;
        inner_key_alt_.reset();
        if (!inner_alt_mode_.empty()) {
            inner_mode_ = inner_alt_mode_;
        }
        inner_alt_mode_.clear();
        if (!inner_alt_kdf_.empty()) {
            inner_kdf_ = inner_alt_kdf_;
        }
        inner_alt_kdf_.clear();
        return true;
    }
    return false;
}

crypto::Bytes Session::encrypt_inner_payload(uint8_t frame_type,
                                             uint8_t stream_id,
                                             const crypto::Bytes& input) {
    if (!inner_key_.has_value()) {
        return input;
    }
    if (!hop_enabled_ || hop_interval_ms_ == 0) {
        return inner::encrypt_payload(*inner_key_, frame_type, stream_id, input);
    }
    std::uint64_t hop_id = current_hop_id();
    crypto::Bytes hop_key;
    if (encrypt_hop_id_.has_value() && *encrypt_hop_id_ == hop_id && !encrypt_hop_key_.empty()) {
        hop_key = encrypt_hop_key_;
    }
    if (hop_key.empty()) {
        hop_key = inner::derive_hop_key(*inner_key_, hop_id);
        encrypt_hop_id_ = hop_id;
        encrypt_hop_key_ = hop_key;
    }
    return inner::encrypt_payload(hop_key, frame_type, stream_id, input);
}

std::uint64_t Session::current_hop_id() const {
    if (!hop_enabled_ || hop_interval_ms_ == 0) {
        return 0;
    }
    return inner::hop_id_from_time_ms(epoch_now_ms(), hop_interval_ms_, hop_offset_ms_);
}

bool Session::handle_auth(const protocol::Frame& frame) {
    auth_error_.clear();
    authorization_tier_ = authorization::SessionTier::Unauthenticated;
    try {
        if (!auth_v2_ephemeral_ || !cfg_.inner_psk_material) {
            auth_error_ = "access denied: invalid authentication state";
            return false;
        }
        const auth_v2::Response response = auth_v2::ParseResponse(frame.payload);
        const crypto::Bytes& pub_pem = response.identity;

        std::unique_ptr<BIO, decltype(&BIO_free)> pub_bio(
            BIO_new_mem_buf(pub_pem.data(), static_cast<int>(pub_pem.size())),
            BIO_free);
        if (!pub_bio) {
            auth_error_ = "access denied: invalid key";
            return false;
        }
        crypto::EVP_PKEY_ptr pubkey(
            PEM_read_bio_PUBKEY(pub_bio.get(), nullptr, nullptr, nullptr),
            EVP_PKEY_free);
        if (!pubkey) {
            auth_error_ = "access denied: invalid key";
            return false;
        }
        if (EVP_PKEY_base_id(pubkey.get()) != EVP_PKEY_ED25519) {
            auth_error_ = "access denied: unsupported key type";
            return false;
        }

        crypto::Bytes unsigned_response = auth_v2::BuildUnsignedResponse(
            response.x25519_public_key, response.mlkem_ciphertext,
            response.identity);
        crypto::Bytes signature_input = auth_v2::BuildSignatureInput(
            challenge_, unsigned_response);
        bool sig_ok = crypto::verify_key(pubkey.get(), signature_input,
                                         response.signature);
        bool auth_ok = authorized_keys_ ? is_authorized(pubkey.get(), *authorized_keys_) : false;
        std::string fingerprint = fingerprint_pubkey(pubkey.get());
        client_id_ = fingerprint;
        auth_fingerprint_ = fingerprint;
        client_auth_pubkey_b64_ = yume::util::base64_encode(std::string(pub_pem.begin(), pub_pem.end()));

        const bool preauth_ok =
            sig_ok && !auth_ok && !cfg_.preauth_services.empty();

        if (!sig_ok || (!auth_ok && !preauth_ok)) {
            if (!cfg_.anonym || auth_debug_enabled()) {
                const std::size_t loaded_keys = authorized_keys_ ? authorized_keys_->size() : 0;
                util::log_warn("session " + std::to_string(session_id_) +
                               ": auth rejected fingerprint=" + (fingerprint.empty() ? std::string("<unknown>") : fingerprint) +
                               " signature=" + (sig_ok ? "ok" : "bad") +
                               " authorized=" + (auth_ok ? "yes" : "no") +
                               " loaded_keys=" + std::to_string(loaded_keys) +
                               " auth_keys=" + (cfg_.auth_keys.empty() ? std::string("<unset>") : cfg_.auth_keys));
            }
            if (!sig_ok) {
                auth_error_ = "access denied: bad signature";
            } else {
                auth_error_ = "access denied: invalid key";
            }
            return false;
        }

        const bool preauth_session = preauth_ok;
        AuthKeyPolicy auth_policy;
        if (!preauth_session && !cfg_.auth_keys_meta.empty()) {
            try {
                AuthKeyPolicyMap auth_policies = load_auth_policies(cfg_.auth_keys_meta);
                auto it = auth_policies.find(fingerprint);
                if (it != auth_policies.end()) {
                    auth_policy = std::move(it->second);
                }
            } catch (const std::exception& ex) {
                auth_error_ = std::string("server auth policy load failed: ") + ex.what();
                return false;
            }
        }
        bandwidth_fair_key_ = fingerprint;
        bandwidth_priority_ = std::clamp(auth_policy.priority.value_or(kDefaultBandwidthPriority),
                                         kMinBandwidthPriority,
                                         kMaxBandwidthPriority);
        const bool key_exec = auth_policy.allow_exec.value_or(false);
        const bool key_local_ip = auth_policy.allow_local_ip.value_or(false);
        const bool key_control_full = auth_policy.control_full.value_or(false);
        const bool key_monero_rpc = auth_policy.allow_monero_rpc.value_or(false);
        session_allowed_codecs_.clear();
        for (const auto& codec : auth_policy.allowed_codecs) {
            const std::string id = app_codec::canonical_codec_id(codec);
            if (app_codec::contains_codec(cfg_.allowed_codecs, id)) {
                session_allowed_codecs_.insert(id);
            }
        }
        session_allowed_services_.clear();
        const auto& service_policy =
            preauth_session ? cfg_.preauth_services : auth_policy.allowed_services;
        for (const auto& service : service_policy) {
            if (std::find(cfg_.allowed_services.begin(), cfg_.allowed_services.end(),
                          service) != cfg_.allowed_services.end()) {
                session_allowed_services_.insert(service);
            }
        }
        if (key_monero_rpc && app_codec::contains_codec(cfg_.allowed_codecs, app_codec::builtin::kMoneroRpcCodecId)) {
            session_allowed_codecs_.insert(std::string(app_codec::builtin::kMoneroRpcCodecId));
        }
#if YUME_FEATURE_EXEC
        session_allow_exec_policy_ = key_exec && cfg_.allow_exec;
#else
        session_allow_exec_policy_ = false;
        if (key_exec || cfg_.allow_exec) {
            util::log_warn("session " + std::to_string(session_id_) +
                          ": exec requested but YUME_FEATURE_EXEC is OFF at build time");
        }
#endif
#if YUME_FEATURE_LAN_BRIDGE
        session_allow_local_ip_ = key_local_ip && cfg_.allow_local_ip;
#else
        session_allow_local_ip_ = false;
        if (key_local_ip || cfg_.allow_local_ip) {
            util::log_warn("session " + std::to_string(session_id_) +
                          ": LAN bridging requested but YUME_FEATURE_LAN_BRIDGE is OFF at build time");
        }
#endif
#if YUME_FEATURE_FULL_CONTROL
        session_control_full_ = key_control_full && cfg_.control_full;
#else
        session_control_full_ = false;
        if (key_control_full || cfg_.control_full) {
            util::log_warn("session " + std::to_string(session_id_) +
                          ": full control requested but YUME_FEATURE_FULL_CONTROL is OFF at build time");
        }
#endif
        session_allow_monero_rpc_policy_ =
            session_allowed_codecs_.count(std::string(app_codec::builtin::kMoneroRpcCodecId)) != 0;
        if ((key_monero_rpc ||
             app_codec::contains_codec(auth_policy.allowed_codecs, app_codec::builtin::kMoneroRpcCodecId)) &&
            !app_codec::contains_codec(cfg_.allowed_codecs, app_codec::builtin::kMoneroRpcCodecId)) {
            util::log_warn("session " + std::to_string(session_id_) +
                          ": Monero RPC codec requested by key but server has not enabled --codec-allow monero-rpc");
        }
        session_allow_inbound_admin_policy_ = auth_policy.allow_inbound_admin.value_or(false);
        session_allow_outbound_admin_policy_ = auth_policy.allow_outbound_admin.value_or(false);
        session_allow_chat_policy_ = auth_policy.allow_chat.value_or(true);
        session_allow_file_policy_ = auth_policy.allow_file.value_or(true);
        session_allow_bytes_policy_ = auth_policy.allow_bytes.value_or(true);
        federation_peer_id_ = auth_policy.federation_peer_id;
        if (preauth_session) {
            util::log_info("session " + std::to_string(session_id_) +
                           ": preauth services enabled for fingerprint=" +
                           fingerprint);
        } else if (!auth_policy.empty()) {
            util::log_info("session " + std::to_string(session_id_) + ": auth policy " +
                           summarize_auth_policy(auth_policy));
        }

#if YUME_USE_BASEFWX
        auto crypto_start = std::chrono::steady_clock::now();
        basefwx::crypto::SecureBytes kem_shared{
            basefwx::pq::KemDecrypt(
                basefwx::pq::KemAlgorithm::MlKem1024,
                auth_v2_ephemeral_->mlkem.private_key,
                response.mlkem_ciphertext)};
        basefwx::crypto::SecureBytes x_shared{
            basefwx::x25519::DeriveSharedSecret(
                auth_v2_ephemeral_->x25519.private_key,
                response.x25519_public_key)};
        basefwx::crypto::SecureBytes file_psk{
            cfg_.inner_psk_material->CopyBytes()};
        basefwx::crypto::SecureBytes psk_key{
            ratchet::DerivePskKey(file_psk.bytes(),
                                 auth_v2_ephemeral_->psk_salt)};
        crypto::Bytes initial_root = ratchet::DeriveInitialRoot(
            kem_shared.bytes(), x_shared.bytes(), psk_key.bytes(),
            auth_v2_ephemeral_->transcript_salt);
        ratchet_ = std::make_unique<ratchet::SessionRatchet>(
            ratchet::EndpointRole::Server, std::move(initial_root),
            psk_key.Release());
        auth_v2_ephemeral_.reset();
        inner_mode_ = "ratchet";
        inner_kdf_ = "hkdf";
        hop_enabled_ = false;
        hop_interval_ms_ = 0;
        hop_offset_ms_ = 0;
        clear_hop_key_cache();
        const auto crypto_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - crypto_start).count();
        util::log_timing("server.auth", "v2_hybrid",
                         "session=" + std::to_string(session_id_) +
                         " ms=" + std::to_string(crypto_ms));
#else
        auth_error_ = "access denied: BaseFWX unavailable";
        return false;
#endif

        if (!cfg_.anonym && !preauth_session) {
            update_auth_meta(cfg_.auth_keys_meta, fingerprint);
        }
        authorization_tier_ = preauth_session
            ? authorization::SessionTier::PreauthServiceOnly
            : authorization::SessionTier::Authorized;
        return true;
    } catch (const std::exception& ex) {
        const std::string detail = ex.what();
        const bool post_key_auth = !auth_fingerprint_.empty();
        if (!cfg_.anonym || auth_debug_enabled()) {
            util::log_warn("session " + std::to_string(session_id_) +
                           ": auth exception fingerprint=" +
                           (auth_fingerprint_.empty() ? std::string("<unknown>") : auth_fingerprint_) +
                           " detail=" + detail);
        }
        if (post_key_auth && looks_like_inner_auth_exception(detail)) {
            auth_error_ = "access denied: pq key derivation failed";
        } else {
            auth_error_ = "access denied: invalid key";
        }
        return false;
    }
}

}  // namespace yume::server
