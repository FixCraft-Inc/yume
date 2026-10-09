/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "setup/kit_layout.hpp"

#include <algorithm>

#include "common/version.hpp"
#include "common/service_name.hpp"

namespace yume::setup {
namespace {

// The limits every kit starts from. A tuning preset then sets its own keys
// on both sides.
Json base_limits(const Json& tuning) {
    Json limits{
        {"max_frame_bytes", 262'144},    {"max_streams", 256},
        {"max_queued_bytes", 4'194'304}, {"max_pending_opens", 64},
        {"max_rekey_jobs", 4},           {"max_control_messages", 128},
        {"max_packet_bytes", 65'535},    {"max_packet_batch", 64},
    };
    limits.update(tuning);
    return limits;
}

Json suite() {
    return {
        {"id", std::string(kTransportSuite)},
        {"secure_channel", std::string(kSecureChannelProvider)},
        {"front_door", std::string(kFrontDoorProvider)},
        {"carrier", std::string(kCarrierProvider)},
        {"session", std::string(kSessionComponent)},
    };
}

Json file(std::string_view path) {
    return {{"file", std::string(path)}};
}

}  // namespace

const std::array<CoverPage, 5> kCoverSite{{
    CoverPage{
        "assets/site.css",
        R"cover(body { margin: 0; font: 17px/1.6 system-ui, sans-serif; color: #24323d; background: #f4f1e8; }
main { max-width: 48rem; margin: 10vh auto; padding: 2rem; }
h1 { font-size: clamp(2rem, 7vw, 4.5rem); line-height: 1; margin-bottom: 1rem; }
article { background: #fff; border-radius: 1rem; padding: 2rem; box-shadow: 0 1rem 3rem #26323d18; }
a { color: #176b68; }
button { font: inherit; color: #176b68; background: transparent; border: 1px solid currentColor; padding: .3rem .75rem; cursor: pointer; }
@media print { body, article { background: #fff; } main { margin: 0; } article { box-shadow: none; } button { display: none; } }
)cover"},
    CoverPage{"assets/site.js", R"cover('use strict';
// Printing is an optional enhancement; field notes remain readable without scripts.
for (const button of document.querySelectorAll('[data-print-note]')) {
    button.hidden = false;
    button.addEventListener('click', () => window.print());
}
)cover"},
    CoverPage{"index.html", R"cover(<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Northwind Field Notes</title>
  <link rel="stylesheet" href="/assets/site.css">
  <script src="/assets/site.js" defer></script>
</head>
<body>
  <main>
    <article>
      <p>Field note 01</p>
      <h1>Northwind</h1>
      <p>A small notebook about trails, changing weather, and the quiet work of keeping a good map.</p>
      <p><a href="/about.html">About this notebook</a></p>
      <button type="button" data-print-note hidden>Print this note</button>
    </article>
  </main>
</body>
</html>
)cover"},
    CoverPage{"about.html", R"cover(<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>About Northwind</title><link rel="stylesheet" href="/assets/site.css"></head>
<body><main><h1>About Northwind</h1><p>Independent field notes, maintained slowly and published when useful.</p><p><a href="/">Return home</a></p></main></body></html>
)cover"},
    CoverPage{"404.html", R"cover(<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Page not found — Northwind Field Notes</title>
  <link rel="stylesheet" href="/assets/site.css">
</head>
<body>
  <main>
    <h1>Page not found</h1>
    <p>This address does not lead to a field note. The page may have moved or the link may be incomplete.</p>
    <p><a href="/">Return to Northwind</a></p>
  </main>
</body>
</html>
)cover"},
}};

Json standard_services() {
    return Json::array({
        {{"name", "tcp"}, {"kind", "stream"}, {"max_concurrent_streams", 256}},
        {{"name", "udp"}, {"kind", "packet"}, {"max_concurrent_streams", 256}},
    });
}

bool declares_standard_services(const Json& config) {
    if (!config.contains("services") || !config.at("services").is_array())
        return false;
    const auto& declared = config.at("services");
    const auto services = standard_services();
    return std::all_of(
        services.begin(), services.end(), [&](const Json& service) {
            return std::any_of(
                declared.begin(), declared.end(), [&](const Json& entry) {
                    return entry.is_object() && entry.contains("name") &&
                           entry.contains("kind") &&
                           entry.at("name") == service.at("name") &&
                           entry.at("kind") == service.at("kind");
                });
        });
}

Json direct_adapter(std::string_view kind, const std::string& service) {
    return {{"kind", std::string(kind)},
            {"service", service},
            {"destinations", {{"public", true}, {"networks", Json::array()}}}};
}

Json socks5_adapter() {
    return {{"kind", "socks5"},
            {"service", "tcp"},
            {"listen_address", "127.0.0.1"},
            {"listen_port", 1080},
            {"udp_service", "udp"}};
}

Json server_config(std::int64_t port, const Json& tuning,
                   std::optional<std::int64_t> max_egress_mbps) {
    Json limits = base_limits(tuning);
    if (max_egress_mbps) limits["max_egress_mbps"] = *max_egress_mbps;
    return {
        {"schema", 1},
        {"role", "server"},
        {"endpoint", {{"listen_addresses", {"0.0.0.0", "::"}}, {"port", port}}},
        {"suite", suite()},
        {"credentials",
         {
             {"composite_key", file("credentials/server-composite.pem")},
             {"authorized_keys", file("credentials/authorized-keys.json")},
             {"admin_keys", file("credentials/admin-keys.json")},
             {"tls_certificate", file("credentials/server-tls.pem")},
             {"tls_key", file("credentials/server-tls.key.pem")},
             {"admission_key", file("credentials/admission.key")},
             {"mlkem_key", file("credentials/server-mlkem.key.pem")},
         }},
        {"cover",
         {{"profile", std::string(kEvidenceProfile)},
          {"root", file("cover-site")}}},
        {"services", standard_services()},
        {"adapters", Json::array({direct_adapter("direct_tcp", "tcp"),
                                  direct_adapter("direct_udp", "udp")})},
        {"limits", limits},
    };
}

Json client_config(const std::string& host, std::int64_t port,
                   const Json& tuning) {
    return {
        {"schema", 1},
        {"role", "client"},
        {"endpoint", {{"host", host}, {"port", port}}},
        {"suite", suite()},
        {"credentials",
         {
             {"composite_key", file("credentials/client-composite.pem")},
             {"access_psk", file("credentials/client-access.psk")},
             {"admission_key", file("credentials/admission.key")},
             {"server_trust", file("credentials/server-trust.pem")},
             {"server_identity", file("credentials/server-composite.pub.pem")},
             {"server_mlkem", file("credentials/server-mlkem.pub.pem")},
         }},
        {"cover", {{"profile", std::string(kEvidenceProfile)}}},
        {"services", standard_services()},
        {"adapters", Json::array({socks5_adapter()})},
        {"limits", base_limits(tuning)},
    };
}

Json authorized_entry(const std::string& name, const std::string& fingerprint,
                      std::optional<std::int64_t> max_sessions,
                      std::optional<double> weight, bool circuits) {
    Json capabilities = Json::array();
    for (const auto& service : standard_services()) {
        capabilities.push_back(
            {{"service", service.at("name")}, {"kind", service.at("kind")}});
    }
    if (circuits) {
        capabilities.push_back(
            {{"service", std::string(common::kCircuitServiceName)},
             {"kind", "packet"}});
    }
    Json entry{
        {"name", name},
        {"identity",
         {{"file", "authorized/" + name + "-composite.pub.pem"},
          {"sha256", fingerprint}}},
        {"access_psk", file("authorized/" + name + "-access.psk")},
        {"capabilities", capabilities},
    };
    if (max_sessions) entry["max_sessions"] = *max_sessions;
    if (weight) entry["weight"] = *weight;
    return entry;
}

Json circuits_section() {
    const std::string base(kClientCircuitsDirectory);
    return {
        {"hops", 3},
        {"operator_key", file(base + "/operator.pub.pem")},
        {"routes", file(base + "/cluster-routes.json")},
        {"routes_signature", file(base + "/cluster-routes.sig")},
        {"state", file(kClientCircuitsState)},
    };
}

Json kit_manifest(const std::string& host, std::int64_t port,
                  const std::string& client_name) {
    return {
        {"format", 1},
        {"product", kVersion},
        {"ytp", kYtpVersionNumber},
        {"config", kConfigSchema},
        {"abi", kAbiVersion},
        {"providers", suite()},
        {"profile", std::string(kEvidenceProfile)},
        {"suite", std::string(kTransportSuite)},
        {"runtime_status", "development-runtimes"},
        {"server",
         {{"host", host}, {"port", port}, {"config", "server/yumed.json"}}},
        {"client", {{"name", client_name}, {"config", "client/yume.json"}}},
    };
}

}  // namespace yume::setup
