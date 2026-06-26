/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
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
#include "server/runtime/manager.hpp"
#include "server/session/internal.hpp"

namespace yume::server {

using namespace detail;

void Session::send_auth_challenge() {
    challenge_ = crypto::random_bytes(32);
    if (cfg_.inner_crypto) {
        inner::Argon2Limits limits = inner::argon2_env_limits();
        nlohmann::json meta{
            {"challenge_meta", 1}
        };
        if (limits.time_max > 0) {
            meta["argon2_time_max"] = limits.time_max;
        }
        if (limits.memory_max > 0) {
            meta["argon2_mem_max"] = limits.memory_max;
        }
        if (limits.parallelism_max > 0) {
            meta["argon2_par_max"] = limits.parallelism_max;
        }
        std::string meta_text = meta.dump();
        challenge_.insert(challenge_.end(), meta_text.begin(), meta_text.end());
    }
    protocol::Frame frame{{static_cast<uint32_t>(challenge_.size()), protocol::AUTH, 0, 0}, challenge_};
    auto self = shared_from_this();
    auto do_write = [self, frame]() {
        self->async_write_frame(frame, [self](const boost::system::error_code& ec, std::size_t) {
            if (ec) {
                self->close_with_reason("AUTH challenge write failed: " + ec.message());
                return;
            }
            self->read_header();
        });
    };

    // Optional opt-in send-side jitter on the AUTH challenge. Read the
    // env once per call (cheap; getenv is fast and there's exactly one
    // AUTH per session). YUME_AUTH_JITTER_MS=N adds a uniform random
    // 0..N ms delay before writing AUTH, which breaks the
    // "server always emits AUTH at exactly T ms after TLS finish"
    // ML signature without costing latency for operators who don't
    // care. Default 0 = no delay.
    int jitter_max = 0;
    if (const char* raw = std::getenv("YUME_AUTH_JITTER_MS")) {
        try { jitter_max = std::max(0, std::stoi(raw)); }
        catch (const std::exception&) { jitter_max = 0; }
    }
    if (jitter_max == 0) {
        do_write();
        return;
    }
    thread_local std::mt19937 rng{std::random_device{}()};
    std::uniform_int_distribution<int> dist(0, jitter_max);
    int delay_ms = dist(rng);
    auto timer = std::make_shared<boost::asio::steady_timer>(strand_);
    timer->expires_after(std::chrono::milliseconds(delay_ms));
    timer->async_wait([timer, do_write](const boost::system::error_code& ec) {
        if (!ec) do_write();
    });
}

void Session::clear_hop_key_cache() {
    std::fill(encrypt_hop_key_.begin(), encrypt_hop_key_.end(), 0);
    std::fill(decrypt_hop_key_.begin(), decrypt_hop_key_.end(), 0);
    encrypt_hop_key_.clear();
    decrypt_hop_key_.clear();
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
    try {
        size_t offset = 0;
        crypto::Bytes pub_pem = read_field(frame.payload, offset);
        crypto::Bytes sig = read_field(frame.payload, offset);
        std::optional<crypto::Bytes> pq_ciphertext;
        std::optional<crypto::Bytes> pq_salt;
        std::optional<std::string> inner_mode;
        std::optional<bool> inner_hop;
        std::optional<inner::KdfParams> inner_kdf;
        if (offset < frame.payload.size()) {
            pq_ciphertext = read_field(frame.payload, offset);
        }
        if (offset < frame.payload.size()) {
            pq_salt = read_field(frame.payload, offset);
        }
        if (offset < frame.payload.size()) {
            crypto::Bytes mode_bytes = read_field(frame.payload, offset);
            if (!mode_bytes.empty()) {
                inner_mode.emplace(mode_bytes.begin(), mode_bytes.end());
            }
        }
        if (offset < frame.payload.size()) {
            crypto::Bytes hop_bytes = read_field(frame.payload, offset);
            if (!hop_bytes.empty()) {
                inner_hop = (hop_bytes[0] != static_cast<uint8_t>('0'));
            } else {
                inner_hop = false;
            }
        }
        if (offset < frame.payload.size()) {
            crypto::Bytes kdf_bytes = read_field(frame.payload, offset);
            if (!kdf_bytes.empty()) {
                inner::KdfParams params;
                params.name.assign(kdf_bytes.begin(), kdf_bytes.end());
                if (offset < frame.payload.size()) {
                    crypto::Bytes param_bytes = read_field(frame.payload, offset);
                    if (param_bytes.size() == 16) {
                        auto read_u32 = [&](size_t off) -> std::uint32_t {
                            if (off + 4 > param_bytes.size()) {
                                return 0;
                            }
                            return (static_cast<std::uint32_t>(param_bytes[off]) << 24) |
                                   (static_cast<std::uint32_t>(param_bytes[off + 1]) << 16) |
                                   (static_cast<std::uint32_t>(param_bytes[off + 2]) << 8) |
                                   static_cast<std::uint32_t>(param_bytes[off + 3]);
                        };
                        params.argon2_time = read_u32(0);
                        params.argon2_memory = read_u32(4);
                        params.argon2_parallelism = read_u32(8);
                        params.pbkdf2_iters = read_u32(12);
                    }
                }
                inner_kdf = params;
            }
        }

        BIO* pub_bio = BIO_new_mem_buf(pub_pem.data(), static_cast<int>(pub_pem.size()));
        if (!pub_bio) {
            auth_error_ = "access denied: invalid key";
            return false;
        }
        EVP_PKEY* pubkey = PEM_read_bio_PUBKEY(pub_bio, nullptr, nullptr, nullptr);
        BIO_free(pub_bio);
        if (!pubkey) {
            auth_error_ = "access denied: invalid key";
            return false;
        }

        bool sig_ok = crypto::verify_key(pubkey, challenge_, sig);
        bool auth_ok = authorized_keys_ ? is_authorized(pubkey, *authorized_keys_) : false;
        std::string fingerprint = fingerprint_pubkey(pubkey);
        client_id_ = fingerprint;
        auth_fingerprint_ = fingerprint;
        client_auth_pubkey_b64_ = yume::util::base64_encode(std::string(pub_pem.begin(), pub_pem.end()));
        EVP_PKEY_free(pubkey);

        if (!sig_ok || !auth_ok) {
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

        AuthKeyPolicy auth_policy;
        if (!cfg_.auth_keys_meta.empty()) {
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
        if (key_monero_rpc && app_codec::contains_codec(cfg_.allowed_codecs, app_codec::kMoneroRpcCodecId)) {
            session_allowed_codecs_.insert(std::string(app_codec::kMoneroRpcCodecId));
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
            session_allowed_codecs_.count(std::string(app_codec::kMoneroRpcCodecId)) != 0;
        if ((key_monero_rpc ||
             app_codec::contains_codec(auth_policy.allowed_codecs, app_codec::kMoneroRpcCodecId)) &&
            !app_codec::contains_codec(cfg_.allowed_codecs, app_codec::kMoneroRpcCodecId)) {
            util::log_warn("session " + std::to_string(session_id_) +
                          ": Monero RPC codec requested by key but server has not enabled --codec-allow monero-rpc");
        }
        session_allow_inbound_admin_policy_ = auth_policy.allow_inbound_admin.value_or(false);
        session_allow_outbound_admin_policy_ = auth_policy.allow_outbound_admin.value_or(false);
        session_allow_chat_policy_ = auth_policy.allow_chat.value_or(true);
        session_allow_file_policy_ = auth_policy.allow_file.value_or(true);
        session_allow_bytes_policy_ = auth_policy.allow_bytes.value_or(true);
        federation_peer_id_ = auth_policy.federation_peer_id;
        if (!auth_policy.empty()) {
            util::log_info("session " + std::to_string(session_id_) + ": auth policy " +
                           summarize_auth_policy(auth_policy));
        }

        if (cfg_.inner_crypto) {
            if (!pq_ciphertext.has_value() || !pq_salt.has_value()) {
                if (cfg_.inner_required) {
                    auth_error_ = "server requires inner crypto";
                    return false;
                }
                util::log_warn("session " + std::to_string(session_id_) + ": missing PQ fields; inner crypto disabled for this session");
            } else if (pq_salt->empty()) {
                if (cfg_.inner_required) {
                    auth_error_ = "server requires inner crypto";
                    return false;
                }
                util::log_warn("session " + std::to_string(session_id_) + ": missing PQ salt; inner crypto disabled for this session");
            } else {
                if (inner_mode.has_value() && !cfg_.inner_dual) {
                    bool wants_heavy = (*inner_mode == "heavy");
                    bool wants_light = (*inner_mode == "light");
                    if ((wants_heavy && !cfg_.inner_heavy) || (wants_light && cfg_.inner_heavy)) {
                        auth_error_ = "server does not support requested inner mode";
                        return false;
                    }
                }
                if (inner_kdf.has_value() && !inner_kdf->name.empty()) {
                    if (inner_kdf->name == "argon2") {
                        if (!inner::argon2_supported()) {
                            auth_error_ = "server does not support argon2";
                            return false;
                        }
                        std::string cap_reason;
                        if (inner::argon2_params_exceed_limits(
                                *inner_kdf, inner::argon2_env_limits(), &cap_reason)) {
                            auth_error_ = "client argon2 params exceed server cap: " + cap_reason;
                            return false;
                        }
                    } else if (inner_kdf->name == "pbkdf2") {
                        if (!inner::pbkdf2_supported()) {
                            auth_error_ = "server does not support pbkdf2";
                            return false;
                        }
                    } else if (inner_kdf->name == "hkdf") {
                        if (!inner_mode.has_value() || *inner_mode != "light") {
                            auth_error_ = "invalid kdf request";
                            return false;
                        }
                    } else {
                        auth_error_ = "invalid kdf request";
                        return false;
                    }
                }
                inner::Config inner_cfg;
                inner_cfg.enabled = cfg_.inner_crypto;
                inner_cfg.pq_private_key = cfg_.pq_private_key;
                inner_cfg.allow_embedded_master = cfg_.allow_embedded_master;
                auto server_inner_start = std::chrono::steady_clock::now();
                if (cfg_.inner_dual) {
                    std::optional<inner::KdfParams> heavy_kdf;
                    if (inner_kdf.has_value() && !inner_kdf->name.empty() && inner_kdf->name != "hkdf") {
                        heavy_kdf = inner_kdf;
                    }
                    auto heavy = inner::server_derive_key(inner_cfg, *pq_ciphertext, *pq_salt, true, heavy_kdf);
                    auto light = inner::server_derive_key(inner_cfg, *pq_ciphertext, *pq_salt, false, std::nullopt);
                    if ((!heavy.has_value() || heavy->key.empty()) && (!light.has_value() || light->key.empty())) {
                        util::log_warn("session " + std::to_string(session_id_) + ": PQ key derivation failed");
                        auth_error_ = "access denied: pq key derivation failed";
                        return false;
                    }
                    bool prefer_light = (inner_mode.has_value() && *inner_mode == "light");
                    bool prefer_heavy = (inner_mode.has_value() && *inner_mode == "heavy");
                    if (prefer_light && light.has_value() && !light->key.empty()) {
                        inner_key_ = light->key;
                        inner_mode_ = "light";
                        inner_kdf_ = light->kdf;
                        if (heavy.has_value() && !heavy->key.empty()) {
                            inner_key_alt_ = heavy->key;
                            inner_alt_mode_ = "heavy";
                            inner_alt_kdf_ = heavy->kdf;
                        }
                    } else if (prefer_heavy && heavy.has_value() && !heavy->key.empty()) {
                        inner_key_ = heavy->key;
                        inner_mode_ = "heavy";
                        inner_kdf_ = heavy->kdf;
                        if (light.has_value() && !light->key.empty()) {
                            inner_key_alt_ = light->key;
                            inner_alt_mode_ = "light";
                            inner_alt_kdf_ = light->kdf;
                        }
                    } else if (cfg_.inner_heavy && heavy.has_value() && !heavy->key.empty()) {
                        inner_key_ = heavy->key;
                        inner_mode_ = "heavy";
                        inner_kdf_ = heavy->kdf;
                        if (light.has_value() && !light->key.empty()) {
                            inner_key_alt_ = light->key;
                            inner_alt_mode_ = "light";
                            inner_alt_kdf_ = light->kdf;
                        }
                    } else if (light.has_value() && !light->key.empty()) {
                        inner_key_ = light->key;
                        inner_mode_ = "light";
                        inner_kdf_ = light->kdf;
                        if (heavy.has_value() && !heavy->key.empty()) {
                            inner_key_alt_ = heavy->key;
                            inner_alt_mode_ = "heavy";
                            inner_alt_kdf_ = heavy->kdf;
                        }
                    }
                } else {
                    auto derived = inner::server_derive_key(inner_cfg, *pq_ciphertext, *pq_salt, cfg_.inner_heavy, inner_kdf);
                    if (!derived.has_value() || derived->key.empty()) {
                        util::log_warn("session " + std::to_string(session_id_) + ": PQ key derivation failed");
                        auth_error_ = "access denied: pq key derivation failed";
                        return false;
                    }
                    inner_key_ = derived->key;
                    inner_mode_ = cfg_.inner_heavy ? "heavy" : "light";
                    inner_kdf_ = derived->kdf;
                }
                auto server_inner_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - server_inner_start).count();
                util::log_timing("server.auth",
                                 "inner_prepare",
                                 "session=" + std::to_string(session_id_) +
                                     " ms=" + std::to_string(server_inner_ms) +
                                     " mode=" + (inner_mode_.empty() ? std::string("none") : inner_mode_) +
                                     " kdf=" + (inner_kdf_.empty() ? std::string("unknown") : inner_kdf_) +
                                     " alt_mode=" + (inner_alt_mode_.empty() ? std::string("none") : inner_alt_mode_) +
                                     " alt_kdf=" + (inner_alt_kdf_.empty() ? std::string("none") : inner_alt_kdf_));
            }
        } else if (pq_ciphertext.has_value()) {
            auth_error_ = "server does not support inner crypto";
            return false;
        }

        bool client_hop = inner_hop.value_or(false);
        if (cfg_.inner_hop) {
            if (!client_hop) {
                auth_error_ = "server requires hopping";
                return false;
            }
        } else if (client_hop) {
            auth_error_ = "server does not support hopping";
            return false;
        }
        hop_enabled_ = (cfg_.inner_hop && client_hop && inner_key_.has_value());
        hop_interval_ms_ = cfg_.hop_interval_ms;
        hop_offset_ms_ = 0;
        clear_hop_key_cache();

        if (!cfg_.anonym) {
            update_auth_meta(cfg_.auth_keys_meta, fingerprint);
        }
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
