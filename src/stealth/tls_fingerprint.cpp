/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "stealth/tls_fingerprint.hpp"

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "stealth/cover_profile.hpp"

namespace yume::tls_fingerprint {

namespace {

// Cache the fingerprint across SSL_CTX instances. The generated cover profile
// owns the cipher, extension, group and signature lists; its generator checks
// declared differences from the captured ClientHello.
const std::vector<BrowserFingerprint>& cached_browser_fingerprints() {
    static const std::vector<BrowserFingerprint> kFingerprints = [] {
        const auto& cover = cover_profile::active();

        BrowserFingerprint fp;
        fp.profile = cover.tls_profile;
        fp.name = std::string(cover.browser_name) + " " +
                  std::string(cover.browser_version);
        // TLS 1.2 in the ClientHello record, upgraded to 1.3 by supported_versions.
        fp.tls_version = 0x0303;
        fp.cipher_suites.assign(cover.tls_cipher_suites.begin(),
                                cover.tls_cipher_suites.end());
        fp.extensions.assign(cover.tls_extensions.begin(),
                             cover.tls_extensions.end());
        fp.supported_groups.assign(cover.tls_supported_groups.begin(),
                                   cover.tls_supported_groups.end());
        fp.key_share_groups.assign(cover.tls_key_share_groups.begin(),
                                   cover.tls_key_share_groups.end());
        fp.ec_point_formats.assign(cover.tls_ec_point_formats.begin(),
                                   cover.tls_ec_point_formats.end());
        fp.signature_algorithms.assign(cover.tls_signature_algorithms.begin(),
                                       cover.tls_signature_algorithms.end());
        fp.alpn_protocols.reserve(cover.tls_alpn_protocols.size());
        for (const auto& protocol : cover.tls_alpn_protocols) {
            fp.alpn_protocols.emplace_back(protocol);
        }

        return std::vector<BrowserFingerprint>{std::move(fp)};
    }();
    return kFingerprints;
}

}  // namespace

std::optional<BrowserFingerprint> get_browser_profile_info(BrowserProfile profile) {
    const auto& fingerprints = cached_browser_fingerprints();
    for (const auto& fp : fingerprints) {
        if (fp.profile == profile) {
            return fp;
        }
    }
    return std::nullopt;
}

}  // namespace yume::tls_fingerprint
