/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * Session authentication and inner-crypto methods:
 *   - send_auth_challenge   — server-issued AUTH challenge
 *   - handle_auth           — client AUTH-response verification (key
 *                             match, optional inner ML-KEM handshake)
 *   - decrypt/encrypt_inner_payload — legacy inner AEAD
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

// Scope-bound wipe for transient AUTH transcript inputs. The TLS exporter
// derives from the master secret and feeds the initial root; signature inputs
// also combine it with authentication material. Every return and exception
// path must clear their retained vector capacity.
class WipeBytesOnExit {
public:
    explicit WipeBytesOnExit(crypto::Bytes& bytes) noexcept : bytes_(bytes) {}
    WipeBytesOnExit(const WipeBytesOnExit&) = delete;
    WipeBytesOnExit& operator=(const WipeBytesOnExit&) = delete;
    ~WipeBytesOnExit() noexcept { security::secure_erase(bytes_); }

private:
    crypto::Bytes& bytes_;
};

struct AuthCandidate {
    std::string fingerprint_;
    std::string admin_fingerprint_;
    bool signature_valid_{false};
    bool regular_authorized_{false};
    bool operator_authorized_{false};
    bool admin_authenticated_{false};

    bool visitor_authorized() const noexcept {
        return regular_authorized_ || operator_authorized_;
    }
};

struct AuthDecision {
    std::string fingerprint_;
    std::string admin_fingerprint_;
    std::string client_auth_pubkey_b64_;
    std::string client_id_;
    std::string bandwidth_fair_key_;
    std::string federation_peer_id_;
    AuthKeyPolicy policy_;
    AuthKeyType key_type_{AuthKeyType::Individual};
    std::unordered_set<std::string> allowed_codecs_;
    std::unordered_set<std::string> allowed_services_;
    std::unique_ptr<ratchet::SessionRatchet> ratchet_;
    double bandwidth_weight_{1.0};
    std::uint32_t identity_session_limit_{1};
    bool preauth_{false};
    bool operator_authenticated_{false};
    bool admin_authenticated_{false};
    bool allow_exec_{false};
    bool allow_local_ip_{false};
    bool control_full_{false};
    bool allow_monero_rpc_{false};
    bool allow_inbound_admin_{false};
    bool allow_outbound_admin_{false};
    bool allow_chat_{true};
    bool allow_file_{true};
    bool allow_bytes_{true};
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
            *output = inner::decrypt_payload(key, frame_type, stream_id, input);
            return true;
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
    if (try_decrypt(*inner_key_alt_)) {
        // Assigning over the optional would free the superseded key without
        // clearing it, and copying rather than moving would leave a second
        // live copy in the alternate slot until reset().
        if (inner_key_) security::secure_erase(*inner_key_);
        inner_key_ = std::move(inner_key_alt_);
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
    return inner::encrypt_payload(*inner_key_, frame_type, stream_id, input);
}

bool Session::handle_auth(const protocol::Frame& frame) {
    auth_error_.clear();
    authorization_tier_ = authorization::SessionTier::Unauthenticated;
    operator_authenticated_ = false;
    admin_authenticated_ = false;
    auth_fingerprint_.clear();
    admin_fingerprint_.clear();
    auth_key_type_ = AuthKeyType::Individual;
    AuthCandidate candidate;
    AuthDecision decision;
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
        WipeBytesOnExit wipe_signature_input(signature_input);
        candidate.signature_valid_ = crypto::verify_composite(
            visitor_identity.classical.get(), visitor_identity.pq.get(),
            signature_input, response.signature);
        candidate.regular_authorized_ =
            authorized_keys_ &&
            is_composite_authorized(visitor_identity, *authorized_keys_);
        candidate.operator_authorized_ =
            operator_keys_ &&
            is_composite_authorized(visitor_identity, *operator_keys_);
        candidate.fingerprint_ =
            crypto::composite_fingerprint(visitor_identity);

        // An admin claim is a second factor for an already authorized visitor,
        // never an alternate route out of the deliberately narrower preauth
        // tier. Reject before parsing or verifying the admin credential so no
        // preauth session can retain privileged internal state.
        if (response.claims_admin() &&
            !authorization::admin_claim_eligible(
                candidate.signature_valid_,
                candidate.visitor_authorized())) {
            auth_error_ = !candidate.signature_valid_
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
            candidate.admin_fingerprint_ =
                crypto::composite_fingerprint(admin_identity);
            // Two keys means two *different* keys. Without this, presenting the
            // same key twice would satisfy a naive "two factors" check.
            if (candidate.admin_fingerprint_ == candidate.fingerprint_) {
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
            WipeBytesOnExit wipe_admin_input(admin_input);
            const bool admin_sig_ok = crypto::verify_composite(
                admin_identity.classical.get(), admin_identity.pq.get(),
                admin_input, response.admin_signature);
            if (!admin_sig_ok) {
                auth_error_ = "access denied: admin signature is invalid";
                return false;
            }
            candidate.admin_authenticated_ = true;
        }
        decision.fingerprint_ = candidate.fingerprint_;
        decision.admin_fingerprint_ = candidate.admin_fingerprint_;
        decision.admin_authenticated_ = candidate.admin_authenticated_;
        decision.client_auth_pubkey_b64_ = yume::util::base64_encode(
            std::string(response.identity.begin(), response.identity.end()));

        const bool preauth_ok =
            candidate.signature_valid_ && !candidate.visitor_authorized() &&
            !cfg_.preauth_services.empty();

        if (!candidate.signature_valid_ ||
            (!candidate.visitor_authorized() && !preauth_ok)) {
            if (!cfg_.anonym || auth_debug_enabled()) {
                const std::size_t loaded_keys = authorized_keys_ ? authorized_keys_->size() : 0;
                util::log_warn("session " + std::to_string(session_id_) +
                               ": auth rejected fingerprint=" + (candidate.fingerprint_.empty() ? std::string("<unknown>") : candidate.fingerprint_) +
                               " signature=" + (candidate.signature_valid_ ? "ok" : "bad") +
                               " authorized=" + (candidate.visitor_authorized() ? "yes" : "no") +
                               " loaded_keys=" + std::to_string(loaded_keys) +
                               " auth_keys=" + (cfg_.auth_keys.empty() ? std::string("<unset>") : cfg_.auth_keys));
            }
            if (!candidate.signature_valid_) {
                auth_error_ = "access denied: bad signature";
            } else {
                auth_error_ = "access denied: invalid key";
            }
            return false;
        }

        decision.preauth_ = preauth_ok;
        decision.operator_authenticated_ =
            !decision.preauth_ && candidate.operator_authorized_;
        const auto& policy_store = decision.operator_authenticated_
            ? operator_policies_
            : auth_policies_;
        if (!decision.preauth_ && policy_store) {
            const auto it = policy_store->find(candidate.fingerprint_);
            if (it != policy_store->end()) {
                decision.policy_ = it->second;
            }
        }
        decision.key_type_ = decision.operator_authenticated_
            ? AuthKeyType::Individual
            : decision.policy_.key_type;
        if (decision.key_type_ == AuthKeyType::Bulk) {
            decision.identity_session_limit_ =
                decision.policy_.max_sessions.value_or(
                std::max<std::uint32_t>(1, cfg_.bulk_key_max_sessions));
        }
        if (decision.key_type_ == AuthKeyType::Bulk) {
            const std::string session_suffix = std::to_string(session_id_);
            decision.client_id_ =
                candidate.fingerprint_ + "-" + session_suffix;
            decision.bandwidth_fair_key_ =
                "bulk:" + candidate.fingerprint_ + ":" + session_suffix;
        } else {
            decision.client_id_ = candidate.fingerprint_;
            decision.bandwidth_fair_key_ = decision.operator_authenticated_
                ? "operator:" + candidate.fingerprint_
                : "individual:" + candidate.fingerprint_;
        }
        decision.bandwidth_weight_ = decision.policy_.effective_weight();
        const bool key_exec = decision.policy_.allow_exec.value_or(false);
        const bool key_local_ip =
            decision.policy_.allow_local_ip.value_or(false);
        // Full control and admin no longer come from the visitor key's policy --
        // load_auth_policies refuses those flags outright now. They come from a
        // verified second factor: a distinct key in the separate admin store
        // that signed this transcript under the admin domain. That is the only
        // route, so a misedited policy file cannot produce an admin session.
        const bool key_control_full = decision.admin_authenticated_;
        const bool key_monero_rpc =
            decision.policy_.allow_monero_rpc.value_or(false);
        for (const auto& codec : decision.policy_.allowed_codecs) {
            const std::string id = app_codec::canonical_codec_id(codec);
            if (app_codec::contains_codec(cfg_.allowed_codecs, id)) {
                decision.allowed_codecs_.insert(id);
            }
        }
        const auto& service_policy =
            decision.preauth_ ? cfg_.preauth_services
                              : decision.policy_.allowed_services;
        for (const auto& service : service_policy) {
            if (std::find(cfg_.allowed_services.begin(), cfg_.allowed_services.end(),
                          service) != cfg_.allowed_services.end()) {
                decision.allowed_services_.insert(service);
            }
        }
        if (key_monero_rpc && app_codec::contains_codec(cfg_.allowed_codecs, app_codec::builtin::kMoneroRpcCodecId)) {
            decision.allowed_codecs_.insert(
                std::string(app_codec::builtin::kMoneroRpcCodecId));
        }
#if YUME_FEATURE_EXEC
        decision.allow_exec_ = key_exec && cfg_.allow_exec;
#else
        decision.allow_exec_ = false;
        if (key_exec || cfg_.allow_exec) {
            util::log_warn("session " + std::to_string(session_id_) +
                          ": exec requested but YUME_FEATURE_EXEC is OFF at build time");
        }
#endif
#if YUME_FEATURE_LAN_BRIDGE
        decision.allow_local_ip_ = key_local_ip && cfg_.allow_local_ip;
#else
        decision.allow_local_ip_ = false;
        if (key_local_ip || cfg_.allow_local_ip) {
            util::log_warn("session " + std::to_string(session_id_) +
                          ": LAN bridging requested but YUME_FEATURE_LAN_BRIDGE is OFF at build time");
        }
#endif
#if YUME_FEATURE_FULL_CONTROL
        decision.control_full_ = key_control_full && cfg_.control_full;
#else
        decision.control_full_ = false;
        if (key_control_full || cfg_.control_full) {
            util::log_warn("session " + std::to_string(session_id_) +
                          ": full control requested but YUME_FEATURE_FULL_CONTROL is OFF at build time");
        }
#endif
        decision.allow_monero_rpc_ = decision.allowed_codecs_.count(
            std::string(app_codec::builtin::kMoneroRpcCodecId)) != 0;
        if ((key_monero_rpc ||
             app_codec::contains_codec(decision.policy_.allowed_codecs,
                                       app_codec::builtin::kMoneroRpcCodecId)) &&
            !app_codec::contains_codec(cfg_.allowed_codecs, app_codec::builtin::kMoneroRpcCodecId)) {
            util::log_warn("session " + std::to_string(session_id_) +
                          ": Monero RPC codec requested by key but server has not enabled --codec-allow monero-rpc");
        }
        decision.allow_inbound_admin_ = decision.admin_authenticated_;
        decision.allow_outbound_admin_ =
            decision.operator_authenticated_ && decision.admin_authenticated_;
        const bool shared_key = decision.key_type_ == AuthKeyType::Bulk;
        decision.allow_chat_ =
            decision.policy_.allow_chat.value_or(!shared_key);
        decision.allow_file_ =
            decision.policy_.allow_file.value_or(!shared_key);
        decision.allow_bytes_ =
            decision.policy_.allow_bytes.value_or(!shared_key);
        decision.federation_peer_id_ = decision.policy_.federation_peer_id;
        if (decision.preauth_) {
            util::log_info("session " + std::to_string(session_id_) +
                           ": preauth services enabled for fingerprint=" +
                           candidate.fingerprint_);
        } else if (decision.operator_authenticated_) {
            util::log_info("session " + std::to_string(session_id_) +
                           ": operator key authenticated policy=" +
                           summarize_auth_policy(decision.policy_));
        } else if (!decision.policy_.empty()) {
            util::log_info("session " + std::to_string(session_id_) + ": auth policy " +
                           summarize_auth_policy(decision.policy_));
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
        const auto& selected_psk = decision.policy_.federation_peer_id.empty()
            ? cfg_.inner_psk_material
            : decision.policy_.federation_psk_material;
        if (!selected_psk) {
            auth_error_ = "access denied: federation PSK unavailable";
            return false;
        }
        basefwx::crypto::SecureBytes file_psk{
            selected_psk->CopyBytes()};
        basefwx::crypto::SecureBytes psk_key{
            ratchet::DerivePskKey(file_psk.bytes(),
                                 auth_v2_ephemeral_->psk_salt)};
        basefwx::crypto::SecureBytes initial_root{
            ratchet::DeriveInitialRoot(
                kem_shared.bytes(), x_shared.bytes(), psk_key.bytes(),
                auth_v2_ephemeral_->transcript_salt, channel_binding)};
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
        decision.ratchet_ = std::make_unique<ratchet::SessionRatchet>(
            ratchet::EndpointRole::Server, std::move(initial_root),
            std::move(psk_key), send_window, local_window, send_policy,
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
        YUME_TIMING_LOG("server.auth", "v2_hybrid",
                         "session=" + std::to_string(session_id_) +
                         " ms=" + std::to_string(
                             crypto_timer.elapsed_ns() / 1'000'000U));
#else
        auth_error_ = "access denied: BaseFWX unavailable";
        return false;
#endif

        // Identity admission is the final fallible gate. Everything above was
        // assembled in local candidate/decision state, so a rejection cannot
        // leave a partially privileged Session behind.
        if (!decision.preauth_ && manager_) {
            std::string admission_error;
            if (!manager_->admit_authenticated_identity(
                    session_id_, decision.fingerprint_,
                    decision.identity_session_limit_, &admission_error)) {
                auth_error_ = "access denied: key session limit reached";
                util::log_warn(
                    "session " + std::to_string(session_id_) +
                    ": authenticated identity refused fingerprint=" +
                    decision.fingerprint_ + " limit=" +
                    std::to_string(decision.identity_session_limit_));
                return false;
            }
        }

        auth_fingerprint_ = std::move(decision.fingerprint_);
        admin_fingerprint_ = std::move(decision.admin_fingerprint_);
        client_auth_pubkey_b64_ = std::move(decision.client_auth_pubkey_b64_);
        client_id_ = std::move(decision.client_id_);
        bandwidth_fair_key_ = std::move(decision.bandwidth_fair_key_);
        federation_peer_id_ = std::move(decision.federation_peer_id_);
        auth_key_type_ = decision.key_type_;
        bandwidth_weight_ = decision.bandwidth_weight_;
        operator_authenticated_ = decision.operator_authenticated_;
        admin_authenticated_ = decision.admin_authenticated_;
        session_allowed_codecs_ = std::move(decision.allowed_codecs_);
        session_allowed_services_ = std::move(decision.allowed_services_);
        session_allow_exec_policy_ = decision.allow_exec_;
        session_allow_local_ip_ = decision.allow_local_ip_;
        session_control_full_ = decision.control_full_;
        session_allow_monero_rpc_policy_ = decision.allow_monero_rpc_;
        session_allow_inbound_admin_policy_ = decision.allow_inbound_admin_;
        session_allow_outbound_admin_policy_ = decision.allow_outbound_admin_;
        session_allow_chat_policy_ = decision.allow_chat_;
        session_allow_file_policy_ = decision.allow_file_;
        session_allow_bytes_policy_ = decision.allow_bytes_;
        ratchet_ = std::move(decision.ratchet_);
        auth_v2_ephemeral_.reset();
        inner_mode_ = "ratchet";
        inner_kdf_ = "hkdf";
        authorization_tier_ = decision.preauth_
            ? authorization::SessionTier::PreauthServiceOnly
            : authorization::SessionTier::Authorized;

        if (!cfg_.anonym && !decision.preauth_) {
            std::string metadata_error;
            if (!update_auth_meta(operator_authenticated_
                                      ? cfg_.operator_keys_meta
                                      : cfg_.auth_keys_meta,
                                  auth_fingerprint_, "", &metadata_error)) {
                util::log_warn(
                    "session " + std::to_string(session_id_) +
                    ": could not persist auth last_seen: " + metadata_error);
            }
        }
        return true;
    } catch (const std::exception& ex) {
        const std::string detail = ex.what();
        const bool post_key_auth = !candidate.fingerprint_.empty();
        if (!cfg_.anonym || auth_debug_enabled()) {
            util::log_warn("session " + std::to_string(session_id_) +
                           ": auth exception fingerprint=" +
                           (candidate.fingerprint_.empty()
                                ? std::string("<unknown>")
                                : candidate.fingerprint_) +
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
