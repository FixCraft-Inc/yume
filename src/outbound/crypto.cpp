/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * TransportCore legacy inner-crypto AEAD seal/open.
 */

#include "outbound/core.hpp"
#include "outbound/internal.hpp"

#include "core/security/inner_crypto.hpp"

namespace yume::outbound {

using namespace detail;

TransportCore::Bytes TransportCore::encrypt_inner_payload(uint8_t frame_type,
                                                          uint8_t stream_id,
                                                          const Bytes& input) {
    std::optional<Bytes> inner_key;
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        inner_key = inner_key_;
    }
    if (!inner_key.has_value()) {
        return input;
    }
    return inner::encrypt_payload(*inner_key, frame_type, stream_id, input);
}

bool TransportCore::decrypt_inner_payload(uint8_t frame_type,
                                          uint8_t stream_id,
                                          const Bytes& input,
                                          Bytes* output) {
    if (!output) {
        return false;
    }
    std::optional<Bytes> inner_key;
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        inner_key = inner_key_;
    }
    if (!inner_key.has_value()) {
        *output = input;
        return true;
    }
    try {
        *output = inner::decrypt_payload(*inner_key, frame_type, stream_id, input);
        return true;
    } catch (...) {
    }
    return false;
}

}  // namespace yume::outbound
