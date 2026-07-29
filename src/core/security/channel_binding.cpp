/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/security/channel_binding.hpp"

#include <stdexcept>

#include "core/security/secure_erase.hpp"

namespace yume::security {

std::vector<std::uint8_t> ExportChannelBinding(SSL* ssl) {
    if (!ssl) {
        throw std::runtime_error(
            "YUME 2.0 AUTH channel binding requires a TLS connection");
    }
    // The 2.0 carrier pins TLS 1.3 exactly at both ends. Refusing anything
    // else keeps the binding on the RFC 8446 exporter rather than silently
    // accepting a weaker construction.
    if (SSL_version(ssl) != TLS1_3_VERSION) {
        throw std::runtime_error(
            "YUME 2.0 AUTH channel binding requires TLS 1.3");
    }
    if (SSL_is_init_finished(ssl) == 0) {
        throw std::runtime_error(
            "YUME 2.0 AUTH channel binding requires a completed TLS handshake");
    }

    std::vector<std::uint8_t> binding(kChannelBindingLen, 0);
    const int rc = SSL_export_keying_material(
        ssl,
        binding.data(),
        binding.size(),
        kAuthChannelBindingLabel.data(),
        kAuthChannelBindingLabel.size(),
        nullptr,
        0,
        /*use_context=*/0);
    if (rc != 1) {
        secure_erase(binding);
        throw std::runtime_error(
            "YUME 2.0 AUTH channel binding export failed");
    }
    return binding;
}

}  // namespace yume::security
