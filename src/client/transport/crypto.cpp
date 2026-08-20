/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * TransportCore inner-crypto: AEAD seal/open with live hop-key derivation.
 */

#include "client/transport/core.hpp"
#include "client/transport/internal.hpp"

#include <algorithm>
#include <cstdio>
#include <thread>

#include "core/security/inner_crypto.hpp"

namespace yume::client {

using namespace detail;

TransportCore::Bytes TransportCore::encrypt_inner_payload(uint8_t frame_type,
                                                          uint8_t stream_id,
                                                          const Bytes& input) {
    std::optional<Bytes> inner_key;
    bool hop_enabled = false;
    std::uint32_t hop_interval_ms = 0;
    std::int64_t hop_offset_ms = 0;
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        inner_key = inner_key_;
        hop_enabled = hop_enabled_;
        hop_interval_ms = hop_interval_ms_;
        hop_offset_ms = hop_offset_ms_;
    }
    if (!inner_key.has_value()) {
        return input;
    }
    if (!hop_enabled || hop_interval_ms == 0) {
        return inner::encrypt_payload(*inner_key, frame_type, stream_id, input);
    }
    const std::uint64_t hop_id = inner::hop_id_from_time_ms(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count(),
        hop_interval_ms,
        hop_offset_ms);
    Bytes hop_key;
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        if (encrypt_hop_id_.has_value() && *encrypt_hop_id_ == hop_id && !encrypt_hop_key_.empty()) {
            hop_key = encrypt_hop_key_;
        }
    }
    if (hop_key.empty()) {
        hop_key = inner::derive_hop_key(*inner_key, hop_id);
        std::lock_guard<std::mutex> lock(state_mu_);
        encrypt_hop_id_ = hop_id;
        encrypt_hop_key_ = hop_key;
    }
    return inner::encrypt_payload(hop_key, frame_type, stream_id, input);
}

bool TransportCore::decrypt_inner_payload(uint8_t frame_type,
                                          uint8_t stream_id,
                                          const Bytes& input,
                                          Bytes* output) {
    if (!output) {
        return false;
    }
    std::optional<Bytes> inner_key;
    bool hop_enabled = false;
    std::uint32_t hop_interval_ms = 0;
    std::int64_t hop_offset_ms = 0;
    std::optional<std::uint64_t> cached_hop_id;
    Bytes cached_hop_key;
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        inner_key = inner_key_;
        hop_enabled = hop_enabled_;
        hop_interval_ms = hop_interval_ms_;
        hop_offset_ms = hop_offset_ms_;
        cached_hop_id = decrypt_hop_id_;
        cached_hop_key = decrypt_hop_key_;
    }
    if (!inner_key.has_value()) {
        *output = input;
        return true;
    }
    try {
        if (!hop_enabled || hop_interval_ms == 0) {
            *output = inner::decrypt_payload(*inner_key, frame_type, stream_id, input);
            return true;
        }
        const std::uint64_t hop_id = inner::hop_id_from_time_ms(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count(),
            hop_interval_ms,
            hop_offset_ms);
        auto remember_success = [&](std::uint64_t id, const Bytes& key) {
            std::lock_guard<std::mutex> lock(state_mu_);
            decrypt_hop_id_ = id;
            decrypt_hop_key_ = key;
        };
        auto in_window = [hop_id](std::uint64_t id) {
            return id <= hop_id
                ? (hop_id - id) <= kHopDecryptWindow
                : (id - hop_id) <= kHopDecryptWindow;
        };
        if (cached_hop_id.has_value() && !cached_hop_key.empty() && in_window(*cached_hop_id)) {
            try {
                *output = inner::decrypt_payload(cached_hop_key, frame_type, stream_id, input);
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
            const std::uint64_t candidate = candidates[i];
            if (cached_hop_id.has_value() && *cached_hop_id == candidate) {
                continue;
            }
            Bytes hop_key = inner::derive_hop_key(*inner_key, candidate);
            try {
                *output = inner::decrypt_payload(hop_key, frame_type, stream_id, input);
                remember_success(candidate, hop_key);
                return true;
            } catch (...) {
            }
        }
    } catch (...) {
    }
    return false;
}

std::uint64_t TransportCore::current_hop_id() const {
    std::lock_guard<std::mutex> lock(state_mu_);
    if (!hop_enabled_ || hop_interval_ms_ == 0) {
        return 0;
    }
    return inner::hop_id_from_time_ms(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count(),
        hop_interval_ms_,
        hop_offset_ms_);
}

}  // namespace yume::client
