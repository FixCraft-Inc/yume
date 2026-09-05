/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/runtime/security_config.hpp"

#include <exception>
#include <memory>
#include <string>
#include <utility>

#include "core/security/secret_file.hpp"
#include "server/config/config.hpp"
#include "server/host/host_routes.hpp"
#include "server/host/http_backend_client.hpp"

namespace yume::server {
namespace {

bool fail(std::string* error, std::string message) {
    if (error) *error = std::move(message);
    return false;
}

}  // namespace

bool prepare_v2_security_config(ServerConfig& cfg,
                                bool key_management_only,
                                std::string* error) {
    if (error) error->clear();
    if (key_management_only) return true;

    if (cfg.obfs_secret_file.empty() || cfg.inner_psk_file.empty()) {
        return fail(error,
                    "YUME 2.0 requires --obfs-secret-file and "
                    "--inner-psk-file");
    }
    if (!cfg.obfuscation || !cfg.inner_crypto) {
        return fail(error,
                    "YUME 2.0 requires the H2 carrier and mandatory inner "
                    "encryption; config obfuscation=false / "
                    "inner_crypto=false are not accepted");
    }
    if (cfg.obfs_pad_multiple != 0 || cfg.obfs_jitter_ms != 0) {
        return fail(error,
                    "YUME 2.0 Chrome profile rejects configured obfs "
                    "padding/jitter; the committed capture contains neither");
    }
    if (cfg.real_backend.empty()) {
        return fail(error,
                    "YUME 2.0 requires --real-backend "
                    "loopback://<loopback-ip-literal>:<port>");
    }
    const auto backend = host::parse_loopback_backend(cfg.real_backend);
    if (!backend.has_value()) {
        return fail(error,
                    "--real-backend must be "
                    "loopback://<loopback-ip-literal>:<port>");
    }

    // Ordinary H1/H2 GET/HEAD share the backend. Separate admission-failure
    // and malformed/partial-probe paths need configured cover material too.
    if (cfg.real_http && cfg.upstream_response_dir.empty() &&
        cfg.upstream_response_file.empty() &&
        cfg.upstream_response_bytes.empty() && cfg.real_root.empty() &&
        cfg.real_index_path.empty()) {
        return fail(
            error,
            "no cover source is configured for the HTTP/2 decoy, and there is "
            "no built-in page to fall back to: a constant built-in page would "
            "be identical on every YUME server and would identify this daemon "
            "to anyone who sends it one HTTP/2 request. Configure exactly one "
            "of: --upstream-response-dir <dir> or --upstream-response <file> "
            "to replay real captured responses from the site you are "
            "impersonating (best fit); --real-root <dir> to serve a real "
            "static site, whose <dir>/index.html is also used as the decoy "
            "page; or --real-index <file> for a single-page cover. "
            "--real-backend serves ordinary HTTP/1.1 and HTTP/2 GET/HEAD, "
            "but separate probe paths still require configured cover material");
    }

    std::string probe_error;
    if (!host::probe_loopback_http(
            backend->first, backend->second, &probe_error)) {
        return fail(error,
                    "--real-backend startup health check failed: " +
                        probe_error);
    }

    try {
        cfg.obfs_secret_material =
            std::make_shared<security::Secret32>(
                security::LoadSecretFile32(cfg.obfs_secret_file));
        cfg.inner_psk_material =
            std::make_shared<security::Secret32>(
                security::LoadSecretFile32(cfg.inner_psk_file));
    } catch (const std::exception& ex) {
        return fail(error,
                    std::string("YUME 2.0 secret-file validation failed: ") +
                        ex.what());
    }
    return true;
}

}  // namespace yume::server
