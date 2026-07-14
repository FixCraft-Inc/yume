/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/connect/capabilities.hpp"

#include "core/version.hpp"
#include "util.hpp"

namespace yume::client {

ServerCapabilityResult evaluate_server_capabilities(const ServerCapabilityInput& input) {
    ServerCapabilityResult result;
    if (input.server_version != yume::kVersion) {
        result.error = "server is version " + input.server_version + ", you are " +
                       std::string(yume::kVersion) +
                       ", transport core versions must match";
        return result;
    }

    result.want_inner = input.inner_crypto_requested && !input.inner_disabled_for_session;
    if (input.have_inner_caps) {
        if (result.want_inner) {
            if (!input.server_inner_supported) {
                result.error = "server does not support inner crypto";
                return result;
            }
            if (!input.server_inner_dual &&
                !input.server_inner_mode.empty() &&
                input.server_inner_mode != "off") {
                if (input.inner_heavy && input.server_inner_mode == "light") {
                    result.error = "server does not support inner-heavy";
                    return result;
                }
                if (!input.inner_heavy && input.server_inner_mode == "heavy") {
                    result.error = "server does not support inner-light";
                    return result;
                }
            }
        } else if (input.server_inner_required) {
            result.error = "server does not support connecting without inner!";
            return result;
        }
    }

    if (result.want_inner && input.have_inner_caps && !input.server_cap_pq) {
        result.error = "server does not support PQ";
        return result;
    }
    if (result.want_inner && !input.inner_kdf_name.empty()) {
        if (input.inner_kdf_name == "argon2" && !input.server_cap_argon2) {
            result.error = "server does not support argon2";
            return result;
        }
        if (input.inner_kdf_name == "pbkdf2" && !input.server_cap_pbkdf2) {
            result.error = "server does not support pbkdf2";
            return result;
        }
    }
    if (result.want_inner) {
        if (input.server_hop_enabled && !input.inner_hop) {
            result.error = "server requires hopping";
            return result;
        }
        if (!input.server_hop_enabled && input.inner_hop) {
            result.error = "server does not support hopping";
            return result;
        }
    }

    result.hop_interval_ms = input.server_hop_interval_ms > 0
                                 ? input.server_hop_interval_ms
                                 : input.client_hop_interval_ms;
    if (result.hop_interval_ms > 0) {
        if (result.hop_interval_ms < 250) {
            result.hop_interval_ms = 250;
        } else if (result.hop_interval_ms > 1000) {
            result.hop_interval_ms = 1000;
        }
    }
    if (input.server_time_ms > 0) {
        result.hop_offset_ms = input.server_time_ms - util::now_ms();
    }
    result.hop_enabled = result.want_inner &&
                         input.inner_hop &&
                         input.server_hop_enabled &&
                         input.inner_key_established &&
                         result.hop_interval_ms > 0;
    return result;
}

}  // namespace yume::client
