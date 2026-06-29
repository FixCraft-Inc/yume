/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/connect/pq_bootstrap.hpp"

#include <cstdlib>
#include <filesystem>
#include <string>

#include "client/cli/connect/cert.hpp"
#include "client/cli/config/files.hpp"
#include "util.hpp"

namespace yume::client {
namespace {

constexpr const char kPqMsgPrefix[] = "YUME-PQ-V1:";

std::string default_pq_public_key_path() {
    const char* home = std::getenv("HOME");
    if (home && *home) {
        return (std::filesystem::path(home) / ".yume" / "pq_public.key").string();
    }
    std::filesystem::path tmp;
    try {
        tmp = std::filesystem::temp_directory_path();
    } catch (...) {
        tmp = ".";
    }
    return (tmp / "yume" / "pq_public.key").string();
}

}  // namespace

PqBootstrapState maybe_auto_trust_pq(const PqBootstrapInput& input, PqBootstrapState state) {
    if (!input.allow_bootstrap || input.pq_pub_b64.empty()) {
        return state;
    }
    if (input.cert_fingerprint.empty()) {
        util::log_warn("pq_pub provided but certfp missing; refusing PQ auto-trust");
        return state;
    }
    if (input.pq_sig_b64.empty()) {
        util::log_warn("pq_pub provided but pq_sig missing; refusing PQ auto-trust");
        return state;
    }
    if (!input.peer_cert_fingerprint.empty() && input.peer_cert_fingerprint != input.cert_fingerprint) {
        util::log_warn("pq_pub cert fingerprint mismatch; refusing PQ auto-trust");
        return state;
    }

    if (!state.sub_ok && !input.sub_cert_b64.empty()) {
        if (input.anonym_ca_cert.empty()) {
            util::log_warn("pq_pub provided with sub_cert but no --anonym-ca-cert set");
        } else {
            const std::string sub_pem = util::base64_decode(input.sub_cert_b64);
            auto sub_cert = load_cert_from_pem(sub_pem);
            auto ca_cert = load_cert_from_file(input.anonym_ca_cert);
            if (!sub_cert || !ca_cert) {
                util::log_warn("pq_pub sub_cert parse failed; refusing PQ auto-trust");
            } else if (!is_cert_time_valid(sub_cert.get())) {
                util::log_warn("pq_pub sub_cert expired; refusing PQ auto-trust");
            } else if (!verify_cert_signed_by_ca(sub_cert.get(), ca_cert.get())) {
                util::log_warn("pq_pub sub_cert not signed by CA; refusing PQ auto-trust");
            } else {
                state.sub_pub = load_pubkey_from_cert_pem(sub_pem);
                state.sub_ok = static_cast<bool>(state.sub_pub);
            }
        }
    }
    if (!state.ca_ok && !input.anonym_ca_cert.empty()) {
        state.ca_pub = load_pubkey_from_cert(input.anonym_ca_cert);
        state.ca_ok = static_cast<bool>(state.ca_pub);
    }

    EVP_PKEY* pq_key = state.sub_ok ? state.sub_pub.get() : (state.ca_ok ? state.ca_pub.get() : nullptr);
    if (!pq_key) {
        util::log_warn("pq_pub provided but no verified CA/sub cert available; refusing PQ auto-trust");
        return state;
    }

    const std::string pq_msg = std::string(kPqMsgPrefix) + input.pq_pub_b64 + ":" + input.cert_fingerprint;
    crypto::Bytes pq_msg_bytes(pq_msg.begin(), pq_msg.end());
    const std::string pq_sig_raw = util::base64_decode(input.pq_sig_b64);
    if (pq_sig_raw.empty()) {
        util::log_warn("pq_sig invalid base64; refusing PQ auto-trust");
        return state;
    }
    crypto::Bytes pq_sig_bytes(pq_sig_raw.begin(), pq_sig_raw.end());
    if (!crypto::verify_key(pq_key, pq_msg_bytes, pq_sig_bytes)) {
        util::log_warn("pq_pub signature invalid; refusing PQ auto-trust");
        return state;
    }

    const std::string pq_raw = util::base64_decode(input.pq_pub_b64);
    if (pq_raw.empty()) {
        util::log_warn("pq_pub decode failed; refusing PQ auto-trust");
        return state;
    }

    std::string target_path = state.pq_public_key;
    if (target_path.empty()) {
        target_path = default_pq_public_key_path();
    }
    if (target_path.empty()) {
        util::log_warn("pq_pub verified but no output path available");
        return state;
    }

    bool pq_changed = true;
    std::string existing;
    std::string read_err;
    if (read_file_bytes(target_path, &existing, &read_err)) {
        pq_changed = (existing != pq_raw);
    }

    std::string err;
    if (!pq_changed || write_file_bytes(target_path, pq_raw, &err)) {
        if (state.pq_public_key.empty()) {
            state.pq_public_key = target_path;
        }
        if (pq_changed) {
            util::log_info("stored pq_public.key from server at " + target_path);
        }
        if (input.inner_crypto_requested &&
            !input.pq_not_supported &&
            !state.pq_reconnect_used &&
            (input.pq_need_key || pq_changed)) {
            state.pq_reconnect = true;
            state.pq_reconnect_used = true;
        }
    } else {
        util::log_warn("failed to store pq_public.key: " + err);
    }
    return state;
}

}  // namespace yume::client
