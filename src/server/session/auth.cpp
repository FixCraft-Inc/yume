/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * Session authentication and inner-crypto methods:
 *   - send_auth_challenge   — server-issued AUTH challenge
 *   - handle_auth           — client AUTH-response verification (key
 *                             match, optional inner ML-KEM handshake)
 *   - decrypt/encrypt_inner_payload, current_hop_id — inner AEAD with
 *                             live hop-key derivation
 */

#include "server/session/session.hpp"
#include "core/security/secure_erase.hpp"
#include "core/security/auth_v2.hpp"
#include "core/security/channel_binding.hpp"
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

namespace {

// The TLS exporter derives from the master secret and feeds the initial root,
// so it is wiped on every path out of AUTH, including the early refusals.
class WipeBytesOnExit {
public:
    explicit WipeBytesOnExit(crypto::Bytes& bytes) noexcept : bytes_(bytes) {}
    WipeBytesOnExit(const WipeBytesOnExit&) = delete;
    WipeBytesOnExit& operator=(const WipeBytesOnExit&) = delete;
    ~WipeBytesOnExit() { security::secure_erase(bytes_); }

private:
    crypto::Bytes& bytes_;
};

}  // namespace

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
        const auto ratchet_policy =
            ratchet::ResolveSecurityProfile(cfg_.security_profile);
        if (!ratchet_policy.has_value()) {
            throw std::runtime_error("invalid server security profile");
        }
        challenge_ = auth_v2::BuildChallenge(
            random_challenge, ephemeral->mlkem.public_key,
            ephemeral->x25519.public_key, ephemeral->psk_salt,
            ephemeral->transcript_salt,
            ratchet::ClampRekeyWindow(cfg_.rekey_window),
            *ratchet_policy);
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
    operator_authenticated_ = false;
    admin_authenticated_ = false;
    auth_fingerprint_.clear();
    admin_fingerprint_.clear();
    auth_key_type_ = AuthKeyType::Individual;
    try {
        if (!auth_v2_ephemeral_ || !cfg_.inner_psk_material) {
            auth_error_ = "access denied: invalid authentication state";
            return false;
        }
        const auth_v2::Response response = auth_v2::ParseResponse(frame.payload);

        const crypto::CompositePublicKey visitor_identity =
            crypto::parse_composite_identity(response.identity);
        if (!visitor_identity.valid()) {
            auth_error_ = "access denied: invalid key";
            return false;
        }

        // Independently computed from this server's own TLS object. A client
        // signature produced on a different connection — the live-relay case —
        // cannot verify against it, and no peer field can influence it.
        crypto::Bytes channel_binding;
        WipeBytesOnExit wipe_channel_binding(channel_binding);
        try {
            channel_binding =
                security::ExportChannelBinding(stream_.native_handle());
        } catch (const std::exception& ex) {
            // A local TLS problem, not a client credential problem. Say so in
            // the log and still refuse the session.
            util::log_warn("session " + std::to_string(session_id_) +
                           ": AUTH channel binding unavailable: " +
                           std::string(ex.what()));
            auth_error_ = "access denied: channel binding unavailable";
            return false;
        }

        crypto::Bytes unsigned_response = auth_v2::BuildUnsignedResponse(
            response.x25519_public_key, response.mlkem_ciphertext,
            response.identity, response.rekey_window,
            response.ratchet_policy);
        crypto::Bytes signature_input = auth_v2::BuildSignatureInput(
            challenge_, unsigned_response, channel_binding);
        bool sig_ok = crypto::verify_composite(
            visitor_identity.classical.get(), visitor_identity.pq.get(),
            signature_input, response.signature);
        const bool regular_auth_ok =
            authorized_keys_ &&
            is_composite_authorized(visitor_identity, *authorized_keys_);
        const bool operator_auth_ok =
            operator_keys_ &&
            is_composite_authorized(visitor_identity, *operator_keys_);
        const bool auth_ok = regular_auth_ok || operator_auth_ok;
        std::string fingerprint = crypto::composite_fingerprint(visitor_identity);

        // An admin claim is a second factor for an already authorized visitor,
        // never an alternate route out of the deliberately narrower preauth
        // tier. Reject before parsing or verifying the admin credential so no
        // preauth session can retain privileged internal state.
        if (response.claims_admin() &&
            !authorization::admin_claim_eligible(sig_ok, auth_ok)) {
            auth_error_ = !sig_ok
                ? "access denied: bad signature"
                : "access denied: admin requires an authorized visitor key";
            return false;
        }

        // Second factor. Everything about admin is decided here and nowhere
        // else: a session is admin only if it presented a second, *distinct*
        // key that appears in the separate admin store and signed this exact
        // transcript under the admin domain. No policy flag on the visitor key
        // can produce this, which is the whole point of the requirement.
        if (response.claims_admin()) {
            const crypto::CompositePublicKey admin_identity =
                crypto::parse_composite_identity(response.admin_identity);
            if (!admin_identity.valid()) {
                auth_error_ = "access denied: invalid admin key";
                return false;
            }
            const std::string admin_fingerprint =
                crypto::composite_fingerprint(admin_identity);
            // Two keys means two *different* keys. Without this, presenting the
            // same key twice would satisfy a naive "two factors" check.
            if (admin_fingerprint == fingerprint) {
                auth_error_ = "access denied: admin key must differ from visitor key";
                return false;
            }
            if (!admin_keys_ ||
                !is_composite_authorized(admin_identity, *admin_keys_)) {
                auth_error_ = "access denied: admin key is not in the admin list";
                return false;
            }
            crypto::Bytes admin_input = auth_v2::BuildAdminSignatureInput(
                challenge_, unsigned_response, channel_binding,
                response.identity);
            const bool admin_sig_ok = crypto::verify_composite(
                admin_identity.classical.get(), admin_identity.pq.get(),
                admin_input, response.admin_signature);
            security::secure_erase(admin_input);
            if (!admin_sig_ok) {
                auth_error_ = "access denied: admin signature is invalid";
                return false;
            }
            admin_authenticated_ = true;
            admin_fingerprint_ = admin_fingerprint;
        }
        auth_fingerprint_ = fingerprint;
        client_auth_pubkey_b64_ = yume::util::base64_encode(
            std::string(response.identity.begin(), response.identity.end()));

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
        operator_authenticated_ = !preauth_session && operator_auth_ok;
        const auto& policy_store = operator_authenticated_
            ? operator_policies_
            : auth_policies_;
        if (!preauth_session && policy_store) {
            const auto it = policy_store->find(fingerprint);
            if (it != policy_store->end()) {
                auth_policy = it->second;
            }
        }
        auth_key_type_ = operator_authenticated_
            ? AuthKeyType::Individual
            : auth_policy.key_type;
        std::uint32_t identity_session_limit = 1;
        if (auth_key_type_ == AuthKeyType::Bulk) {
            identity_session_limit = auth_policy.max_sessions.value_or(
                std::max<std::uint32_t>(1, cfg_.bulk_key_max_sessions));
        }
        if (!preauth_session && manager_) {
            std::string admission_error;
            if (!manager_->admit_authenticated_identity(
                    session_id_, fingerprint, identity_session_limit,
                    &admission_error)) {
                auth_error_ = "access denied: key session limit reached";
                util::log_warn(
                    "session " + std::to_string(session_id_) +
                    ": authenticated identity refused fingerprint=" + fingerprint +
                    " limit=" + std::to_string(identity_session_limit));
                return false;
            }
        }
        if (auth_key_type_ == AuthKeyType::Bulk) {
            const std::string session_suffix = std::to_string(session_id_);
            client_id_ = fingerprint + "-" + session_suffix;
            bandwidth_fair_key_ = "bulk:" + fingerprint + ":" + session_suffix;
        } else {
            client_id_ = fingerprint;
            bandwidth_fair_key_ = operator_authenticated_
                ? "operator:" + fingerprint
                : "individual:" + fingerprint;
        }
        bandwidth_weight_ = auth_policy.effective_weight();
        const bool key_exec = auth_policy.allow_exec.value_or(false);
        const bool key_local_ip = auth_policy.allow_local_ip.value_or(false);
        // Full control and admin no longer come from the visitor key's policy --
        // load_auth_policies refuses those flags outright now. They come from a
        // verified second factor: a distinct key in the separate admin store
        // that signed this transcript under the admin domain. That is the only
        // route, so a misedited policy file cannot produce an admin session.
        const bool key_control_full = admin_authenticated_;
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
        session_allow_inbound_admin_policy_ = admin_authenticated_;
        session_allow_outbound_admin_policy_ =
            operator_authenticated_ && admin_authenticated_;
        const bool shared_key = auth_key_type_ == AuthKeyType::Bulk;
        session_allow_chat_policy_ = auth_policy.allow_chat.value_or(!shared_key);
        session_allow_file_policy_ = auth_policy.allow_file.value_or(!shared_key);
        session_allow_bytes_policy_ = auth_policy.allow_bytes.value_or(!shared_key);
        federation_peer_id_ = auth_policy.federation_peer_id;
        if (preauth_session) {
            util::log_info("session " + std::to_string(session_id_) +
                           ": preauth services enabled for fingerprint=" +
                           fingerprint);
        } else if (operator_authenticated_) {
            util::log_info("session " + std::to_string(session_id_) +
                           ": operator key authenticated policy=" +
                           summarize_auth_policy(auth_policy));
        } else if (!auth_policy.empty()) {
            util::log_info("session " + std::to_string(session_id_) + ": auth policy " +
                           summarize_auth_policy(auth_policy));
        }

#if YUME_USE_BASEFWX
        diagnostics::Stopwatch crypto_timer(YUME_TIMING_ENABLED());
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
            auth_v2_ephemeral_->transcript_salt, channel_binding);
        // Send no deeper than the client will accept, and accept no deeper
        // than this server advertised in its TLS-protected challenge. The
        // response signature binds both advertisements to the transcript.
        const std::uint16_t local_window =
            ratchet::ClampRekeyWindow(cfg_.rekey_window);
        const std::uint16_t send_window =
            std::min(local_window, response.rekey_window);
        const auto local_policy =
            ratchet::ResolveSecurityProfile(cfg_.security_profile);
        if (!local_policy.has_value()) {
            throw std::runtime_error("invalid server security profile");
        }
        const ratchet::RatchetPolicy send_policy =
            ratchet::NegotiateRatchetPolicy(
                *local_policy, response.ratchet_policy);
        ratchet_ = std::make_unique<ratchet::SessionRatchet>(
            ratchet::EndpointRole::Server, std::move(initial_root),
            psk_key.Release(), send_window, local_window, send_policy,
            send_policy);
        util::log_info("session " + std::to_string(session_id_) +
                       ": ratchet epoch window send=" +
                       std::to_string(send_window) + " accept=" +
                       std::to_string(local_window));
        util::log_info(
            "session " + std::to_string(session_id_) +
            ": ratchet policy negotiated bytes=" +
            std::to_string(send_policy.epoch_byte_limit) + " frames=" +
            std::to_string(send_policy.epoch_frame_limit) + " active_ms=" +
            std::to_string(send_policy.epoch_active_limit.count()) +
            " local_advertised_bytes=" +
            std::to_string(local_policy->epoch_byte_limit) + " frames=" +
            std::to_string(local_policy->epoch_frame_limit) + " active_ms=" +
            std::to_string(local_policy->epoch_active_limit.count()));
        auth_v2_ephemeral_.reset();
        inner_mode_ = "ratchet";
        inner_kdf_ = "hkdf";
        hop_enabled_ = false;
        hop_interval_ms_ = 0;
        hop_offset_ms_ = 0;
        clear_hop_key_cache();
        YUME_TIMING_LOG("server.auth", "v2_hybrid",
                         "session=" + std::to_string(session_id_) +
                         " ms=" + std::to_string(
                             crypto_timer.elapsed_ns() / 1'000'000U));
#else
        auth_error_ = "access denied: BaseFWX unavailable";
        return false;
#endif

        if (!cfg_.anonym && !preauth_session) {
            update_auth_meta(operator_authenticated_
                                 ? cfg_.operator_keys_meta
                                 : cfg_.auth_keys_meta,
                             fingerprint);
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
