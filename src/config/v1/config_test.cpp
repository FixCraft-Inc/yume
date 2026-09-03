/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "config/v1/config.hpp"

#include <array>
#include <cstdlib>
#include <exception>
#include <functional>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include <nlohmann/json.hpp>

namespace {

using Json = nlohmann::json;
using namespace yume::config::v1;

static_assert(!std::is_default_constructible_v<Config>);
static_assert(std::is_copy_constructible_v<Config>);
static_assert(!std::is_copy_assignable_v<Config>);
static_assert(!std::is_move_assignable_v<Config>);
static_assert(std::is_same_v<decltype(std::declval<const Config&>().endpoint()),
                             const Endpoint&>);
static_assert(std::is_same_v<decltype(std::declval<const Config&>().suite()),
                             const Suite&>);
static_assert(
    std::is_same_v<decltype(std::declval<const Config&>().credentials()),
                   const Credentials&>);
static_assert(std::is_same_v<decltype(std::declval<const Config&>().cover()),
                             const Cover&>);
static_assert(
    std::is_same_v<decltype(std::declval<const Config&>().services()),
                   const std::vector<Service>&>);
static_assert(
    std::is_same_v<decltype(std::declval<const Config&>().adapters()),
                   const std::vector<Adapter>&>);
static_assert(std::is_same_v<decltype(std::declval<const Config&>().limits()),
                             const ResourceLimits&>);
static_assert(
    std::is_same_v<decltype(std::declval<const FileReference&>().path()),
                   const std::string&>);

[[noreturn]] void TestFailure(std::string message) {
    throw std::runtime_error(std::move(message));
}

void Check(bool condition, std::string_view message) {
    if (!condition) TestFailure(std::string(message));
}

Json File(std::string path) {
    return Json{{"file", std::move(path)}};
}

Json SuiteDocument() {
    return {
        {"id", "ytp1-tls13-h2"},
        {"secure_channel", "tls13-native"},
        {"front_door", "h2-web"},
        {"carrier", "h2-duplex"},
        {"session", "ytp1-hybrid"},
    };
}

Json LimitsDocument() {
    return {
        {"max_frame_bytes", 262144},
        {"max_streams", 256},
        {"max_queued_bytes", 4194304},
        {"max_pending_opens", 64},
        {"max_rekey_jobs", 4},
        {"max_control_messages", 128},
        {"max_packet_bytes", 65535},
        {"max_packet_batch", 64},
    };
}

Json ClientDocument() {
    return {
        {"schema", 1},
        {"role", "client"},
        {"endpoint", {{"host", "origin.example.com"}, {"port", 443}}},
        {"suite", SuiteDocument()},
        {"credentials",
         {
             {"composite_key", File("credentials/client-composite.pem")},
             {"access_psk", File("credentials/client-access.psk")},
             {"admission_key", File("credentials/admission.key")},
             {"server_trust", File("credentials/server-trust.pem")},
             {"server_identity",
              File("credentials/server-composite.pub.pem")},
             {"server_mlkem", File("credentials/server-mlkem.pub")},
         }},
        {"cover", {{"profile", "chrome151-node24-v1"}}},
        {"services",
         Json::array({
             {{"name", "tcp"},
              {"kind", "stream"},
              {"max_concurrent_streams", 256}},
             {{"name", "packet"},
              {"kind", "packet"},
              {"max_concurrent_streams", 256}},
         })},
        {"adapters",
         Json::array({
             {{"kind", "socks5"},
              {"service", "tcp"},
              {"listen_address", "127.0.0.1"},
              {"listen_port", 1080}},
         })},
        {"limits", LimitsDocument()},
    };
}

Json ServerDocument() {
    return {
        {"schema", 1},
        {"role", "server"},
        {"endpoint",
         {{"listen_addresses", Json::array({"0.0.0.0", "::"})},
          {"port", 443}}},
        {"suite", SuiteDocument()},
        {"credentials",
         {
             {"composite_key", File("credentials/server-composite.pem")},
             {"authorized_keys", File("credentials/authorized-keys.json")},
             {"admin_keys", File("credentials/admin-keys.json")},
             {"tls_certificate", File("credentials/server-tls.pem")},
             {"tls_key", File("credentials/server-tls.key")},
             {"admission_key", File("credentials/admission.key")},
             {"mlkem_key", File("credentials/server-mlkem.key")},
         }},
        {"cover",
         {{"profile", "chrome151-node24-v1"},
          {"root", File("cover-site")}}},
        {"services",
         Json::array({
             {{"name", "tcp"},
              {"kind", "stream"},
              {"max_concurrent_streams", 256}},
             {{"name", "udp"},
              {"kind", "packet"},
              {"max_concurrent_streams", 256}},
             {{"name", "packet"},
              {"kind", "packet"},
              {"max_concurrent_streams", 256}},
         })},
        {"adapters",
         Json::array({
             {{"kind", "direct_tcp"}, {"service", "tcp"}},
             {{"kind", "direct_udp"}, {"service", "udp"}},
         })},
        {"limits", LimitsDocument()},
    };
}

void ExpectError(const Json& document,
                 std::string_view pointer,
                 std::string_view detail = {}) {
    try {
        (void)Parse(document);
    } catch (const ValidationError& error) {
        if (error.json_pointer() != pointer) {
            TestFailure("expected JSON pointer '" + std::string(pointer) +
                        "', got '" + error.json_pointer() + "' (" +
                        error.detail() + ")");
        }
        Check(std::string_view(error.what()).find(
                  "JSON pointer \"" + std::string(pointer) + "\"") !=
                  std::string_view::npos,
              "validation message omitted its JSON pointer");
        if (!detail.empty()) {
            if (error.detail().find(detail) == std::string::npos) {
                TestFailure("error at '" + std::string(pointer) +
                            "' did not contain '" + std::string(detail) +
                            "': " + error.detail());
            }
        }
        return;
    }
    TestFailure("invalid config was accepted at " + std::string(pointer));
}

void ExpectJsonError(std::string_view text,
                     std::string_view pointer,
                     std::string_view detail = {}) {
    try {
        (void)ParseJson(text);
    } catch (const ValidationError& error) {
        if (error.json_pointer() != pointer) {
            TestFailure("expected JSON text pointer '" +
                        std::string(pointer) + "', got '" +
                        error.json_pointer() + "'");
        }
        if (!detail.empty()) {
            if (error.detail().find(detail) == std::string::npos) {
                TestFailure("JSON text error did not contain '" +
                            std::string(detail) + "': " + error.detail());
            }
        }
        return;
    }
    TestFailure("invalid JSON text was accepted");
}

void TestValidDocumentsAndTypedValues() {
    const Config client = Parse(ClientDocument());
    Check(client.schema() == 1 && client.role() == Role::Client,
          "client identity was not retained");
    const auto& client_endpoint = std::get<ClientEndpoint>(client.endpoint());
    Check(client_endpoint.host() == "origin.example.com" &&
              client_endpoint.port() == 443,
          "client endpoint changed");
    Check(client.suite().id() == kSuiteId &&
              client.suite().secure_channel() == kSecureChannelProvider &&
              client.suite().front_door() == kFrontDoorProvider &&
              client.suite().carrier() == kCarrierProvider &&
              client.suite().session() == kSessionComponent,
          "mandatory suite changed");
    const auto& client_credentials =
        std::get<ClientCredentials>(client.credentials());
    Check(client_credentials.access_psk().path() ==
              "credentials/client-access.psk",
          "client credential reference changed");
    Check(client_credentials.server_identity().path() ==
              "credentials/server-composite.pub.pem",
          "server composite trust reference changed");
    Check(std::holds_alternative<ClientCover>(client.cover()),
          "client cover type changed");
    Check(client.services().size() == 2 &&
              client.services().front().max_concurrent_streams() == 256 &&
              client.adapters().size() == 1,
          "client capabilities changed");
    Check(client.limits().max_frame_bytes() == 262144 &&
              client.limits().max_packet_batch() == 64,
          "client limits changed");

    const Config from_text = ParseJson(ClientDocument().dump());
    Check(from_text.role() == Role::Client,
          "ParseJson did not delegate to typed validation");

    const Config server = Parse(ServerDocument());
    Check(server.role() == Role::Server,
          "server role was not retained");
    const auto& server_endpoint = std::get<ServerEndpoint>(server.endpoint());
    Check(server_endpoint.listen_addresses().size() == 2 &&
              server_endpoint.listen_addresses().at(1) == "::",
          "server listen addresses changed");
    Check(std::holds_alternative<ServerCredentials>(server.credentials()) &&
              std::holds_alternative<StaticCover>(server.cover()),
          "server typed variants changed");

    Json reverse = ServerDocument();
    reverse["cover"].erase("root");
    reverse["cover"]["reverse_proxy"] =
        {{"url", "http://[::1]:3000/"}};
    const Config reverse_config = Parse(reverse);
    Check(std::get<ReverseProxyCover>(reverse_config.cover()).url() ==
              "http://[::1]:3000/",
          "reverse proxy URL changed");

    Json embedded = ClientDocument();
    embedded["adapters"] = Json::array();
    Check(Parse(embedded).adapters().empty(),
          "adapter-free embedding config was rejected");

    Json packet = ClientDocument();
    packet["adapters"] = Json::array(
        {{{"kind", "packet"},
          {"service", "packet"},
          {"interface_name", "yume0"},
          {"mtu", 1420}}});
    Check(std::holds_alternative<PacketAdapter>(
              Parse(packet).adapters().front()),
          "packet adapter was not typed");
}

void TestTopLevelClosureAndVersion() {
    Json document = ClientDocument();
    document["~bad/key"] = true;
    ExpectError(document, "/~0bad~1key", "unknown key");

    document = ClientDocument();
    document["zzz"] = true;
    document["schema"] = "wrong";
    ExpectError(document, "/zzz", "unknown key");

    constexpr std::array<std::string_view, 9> required{{
        "schema", "role", "endpoint", "suite", "credentials", "cover",
        "services", "adapters", "limits"}};
    for (const auto key : required) {
        document = ClientDocument();
        document.erase(key);
        ExpectError(document, "/" + std::string(key), "required key");
    }

    document = ClientDocument();
    document["schema"] = 0;
    ExpectError(document, "/schema", "1..1");
    document["schema"] = 2;
    ExpectError(document, "/schema", "1..1");
    document["schema"] = 1.0;
    ExpectError(document, "/schema", "integer");
    document["schema"] = "1";
    ExpectError(document, "/schema", "integer");

    document = ClientDocument();
    document["role"] = "peer";
    ExpectError(document, "/role", "client");
    document["role"] = 1;
    ExpectError(document, "/role", "string");
    ExpectError(Json::array(), "", "object");
}

void TestAliasesAreRejected() {
    constexpr std::array<std::string_view, 14> old_top_level_keys{{
        "server",
        "port",
        "identity",
        "listen_port",
        "tls_backend",
        "tls_helper_path",
        "security_mode",
        "security_custom",
        "inner_crypto",
        "inner_psk_file",
        "obfs_secret",
        "obfs_secret_file",
        "rekey_window",
        "real_backend",
    }};
    for (const auto key : old_top_level_keys) {
        Json document = ClientDocument();
        document[key] = true;
        ExpectError(document, "/" + std::string(key), "unknown key");
    }

    Json document = ClientDocument();
    document["endpoint"]["server"] = "origin.example.com";
    ExpectError(document, "/endpoint/server", "unknown key");
    document = ClientDocument();
    document["suite"]["backend"] = "native";
    ExpectError(document, "/suite/backend", "unknown key");
    document = ClientDocument();
    document["credentials"]["identity"] = File("identity.pem");
    ExpectError(document, "/credentials/identity", "unknown key");
    document = ClientDocument();
    document["cover"]["transport_profile"] = "chrome151-node24-v1";
    ExpectError(document, "/cover/transport_profile", "unknown key");
    document = ClientDocument();
    document["services"][0]["proto"] = "tcp";
    ExpectError(document, "/services/0/proto", "unknown key");
    document = ClientDocument();
    document["adapters"][0]["bind"] = "127.0.0.1:1080";
    ExpectError(document, "/adapters/0/bind", "unknown key");
    document = ClientDocument();
    document["limits"]["max_sessions"] = 256;
    ExpectError(document, "/limits/max_sessions", "unknown key");
}

void TestEndpointValidation() {
    Json document = ClientDocument();
    document["endpoint"]["legacy_server"] = "example.com";
    ExpectError(document, "/endpoint/legacy_server", "unknown key");
    document = ClientDocument();
    document["endpoint"].erase("host");
    ExpectError(document, "/endpoint/host", "required key");
    document = ClientDocument();
    document["endpoint"]["host"] = "999.999.999.999";
    ExpectError(document, "/endpoint/host");
    document["endpoint"]["host"] = "bad host";
    ExpectError(document, "/endpoint/host");
    document["endpoint"]["host"] = "2001:db8::1";
    Check(Parse(document).role() == Role::Client,
          "valid client IPv6 host was rejected");
    document["endpoint"]["port"] = 0;
    ExpectError(document, "/endpoint/port");
    document["endpoint"]["port"] = 65536;
    ExpectError(document, "/endpoint/port");
    document["endpoint"]["port"] = "443";
    ExpectError(document, "/endpoint/port", "integer");

    document = ServerDocument();
    document["endpoint"]["host"] = "example.com";
    ExpectError(document, "/endpoint/host", "unknown key");
    document = ServerDocument();
    document["endpoint"]["listen_addresses"] = Json::array();
    ExpectError(document, "/endpoint/listen_addresses", "1..16");
    document["endpoint"]["listen_addresses"] = Json::array({"localhost"});
    ExpectError(document, "/endpoint/listen_addresses/0", "IP literal");
    document["endpoint"]["listen_addresses"] =
        Json::array({"127.0.0.1", "127.0.0.1"});
    ExpectError(document, "/endpoint/listen_addresses/1", "duplicate");
    document["endpoint"]["listen_addresses"] = Json::array({1});
    ExpectError(document, "/endpoint/listen_addresses/0", "string");
    document["endpoint"]["listen_addresses"] =
        Json::array({"2001:db8::1", "127.0.0.1"});
    Check(Parse(document).role() == Role::Server,
          "valid server IP literals were rejected");

    document = ClientDocument();
    document["endpoint"] = 1;
    ExpectError(document, "/endpoint", "object");
}

void TestMandatorySuite() {
    constexpr std::array<std::pair<std::string_view, std::string_view>, 5>
        fields{{
            {"id", "ytp1-tls13-h2"},
            {"secure_channel", "tls13-native"},
            {"front_door", "h2-web"},
            {"carrier", "h2-duplex"},
            {"session", "ytp1-hybrid"},
        }};
    for (const auto& [key, required] : fields) {
        Json document = ClientDocument();
        document["suite"].erase(key);
        ExpectError(document, "/suite/" + std::string(key), "required key");

        document = ClientDocument();
        document["suite"][key] = "fallback-provider";
        ExpectError(document, "/suite/" + std::string(key), required);

        document["suite"][key] = 1;
        ExpectError(document, "/suite/" + std::string(key), "string");
    }
    Json document = ClientDocument();
    document["suite"]["fallback"] = "legacy";
    ExpectError(document, "/suite/fallback", "unknown key");
    document = ClientDocument();
    document["suite"] = Json::array();
    ExpectError(document, "/suite", "object");
}

void TestCredentialReferences() {
    constexpr std::array<std::string_view, 6> client_keys{{
        "composite_key", "access_psk", "admission_key", "server_trust",
        "server_identity", "server_mlkem"}};
    for (const auto key : client_keys) {
        Json document = ClientDocument();
        document["credentials"].erase(key);
        ExpectError(document, "/credentials/" + std::string(key),
                    "required key");
    }
    constexpr std::array<std::string_view, 7> server_keys{{
        "composite_key", "authorized_keys", "admin_keys", "tls_certificate",
        "tls_key", "admission_key", "mlkem_key"}};
    for (const auto key : server_keys) {
        Json document = ServerDocument();
        document["credentials"].erase(key);
        ExpectError(document, "/credentials/" + std::string(key),
                    "required key");
    }

    Json document = ClientDocument();
    document["credentials"]["tls_key"] = File("private.pem");
    ExpectError(document, "/credentials/tls_key", "unknown key");
    document = ServerDocument();
    document["credentials"]["access_psk"] = File("secret.psk");
    ExpectError(document, "/credentials/access_psk", "unknown key");

    // The traffic store and the second-factor store must stay physically
    // separate; collapsing them is how an admin factor gets granted by
    // accident to an ordinary key.
    document = ServerDocument();
    document["credentials"]["admin_keys"] =
        document["credentials"]["authorized_keys"];
    ExpectError(document, "/credentials/admin_keys",
                "different file from authorized_keys");

    document = ClientDocument();
    document["credentials"]["access_psk"] =
        std::string(64, 'a');
    ExpectError(document, "/credentials/access_psk", "object");
    document["credentials"]["access_psk"] =
        {{"inline", std::string(64, 'a')}};
    ExpectError(document, "/credentials/access_psk/inline", "unknown key");
    document["credentials"]["access_psk"] =
        File(std::string(64, 'a'));
    ExpectError(document, "/credentials/access_psk/file", "inline");

    constexpr std::array<std::pair<std::string_view, std::string_view>, 7>
        unsafe_paths{{
            {"", "empty"},
            {" credentials/key", "whitespace"},
            {"credentials/key\n", "control"},
            {"~/credentials/key", "home"},
            {"secret://credential", "URI"},
            {"credentials/../key", "traversal"},
            {"-----BEGIN PRIVATE KEY-----", "inline"},
        }};
    for (const auto& [path, reason] : unsafe_paths) {
        document = ClientDocument();
        document["credentials"]["composite_key"] = File(std::string(path));
        ExpectError(document, "/credentials/composite_key/file", reason);
    }
    document = ClientDocument();
    document["credentials"]["composite_key"] =
        File(std::string(kMaxFileReferenceBytes + 1, 'p'));
    ExpectError(document, "/credentials/composite_key/file", "4096");
    document = ClientDocument();
    document["credentials"]["composite_key"] = {{"file", 1}};
    ExpectError(document, "/credentials/composite_key/file", "string");
    document = ClientDocument();
    document["credentials"] = "credentials";
    ExpectError(document, "/credentials", "object");
}

void TestCoverValidation() {
    Json document = ClientDocument();
    document["cover"]["root"] = File("cover-site");
    ExpectError(document, "/cover/root", "unknown key");
    document = ClientDocument();
    document["cover"]["profile"] = "bad profile";
    ExpectError(document, "/cover/profile", "profile identifier");
    document["cover"]["profile"] = 1;
    ExpectError(document, "/cover/profile", "string");

    document = ServerDocument();
    document["cover"].erase("root");
    ExpectError(document, "/cover", "exactly one");
    document = ServerDocument();
    document["cover"]["reverse_proxy"] =
        {{"url", "http://127.0.0.1:3000"}};
    ExpectError(document, "/cover/reverse_proxy", "cannot be combined");

    document = ServerDocument();
    document["cover"].erase("root");
    document["cover"]["reverse_proxy"] =
        {{"url", "http://192.0.2.1:3000"}};
    ExpectError(document, "/cover/reverse_proxy/url", "127.0.0.1");
    document["cover"]["reverse_proxy"] =
        {{"url", "https://127.0.0.1:3000"}};
    ExpectError(document, "/cover/reverse_proxy/url");
    document["cover"]["reverse_proxy"] =
        {{"url", "http://127.0.0.1:0"}};
    ExpectError(document, "/cover/reverse_proxy/url");
    document["cover"]["reverse_proxy"] =
        {{"url", "http://127.0.0.1:3000"}, {"fallback", true}};
    ExpectError(document, "/cover/reverse_proxy/fallback", "unknown key");
    document["cover"]["reverse_proxy"] = "http://127.0.0.1:3000";
    ExpectError(document, "/cover/reverse_proxy", "object");

    document = ServerDocument();
    document["cover"]["root"] = {{"inline", "<html>secret</html>"}};
    ExpectError(document, "/cover/root/inline", "unknown key");
    document = ServerDocument();
    document["cover"] = Json::array();
    ExpectError(document, "/cover", "object");
}

void TestServiceValidation() {
    Json document = ClientDocument();
    document["services"] = Json::array();
    ExpectError(document, "/services", "1..64");
    document["services"] = "tcp";
    ExpectError(document, "/services", "array");

    document = ClientDocument();
    document["services"][0]["fallback"] = true;
    ExpectError(document, "/services/0/fallback", "unknown key");
    document = ClientDocument();
    document["services"][0].erase("name");
    ExpectError(document, "/services/0/name", "required key");
    document = ClientDocument();
    document["services"][0]["name"] = "bad/service";
    ExpectError(document, "/services/0/name");
    document["services"][0]["name"] = "Bad.Service";
    ExpectError(document, "/services/0/name", "lowercase ASCII");
    document["services"][0]["name"] = "bad.-segment";
    ExpectError(document, "/services/0/name", "namespace segments");
    document["services"][0]["name"] = std::string(129, 'a');
    ExpectError(document, "/services/0/name", "128");
    document["services"][0]["name"] = std::string(128, 'a');
    document["adapters"][0]["service"] = std::string(128, 'a');
    Check(Parse(document).services().front().name().size() == 128,
          "the maximum canonical service name was rejected");
    document["services"][0]["name"] = 1;
    ExpectError(document, "/services/0/name", "string");
    document = ClientDocument();
    document["services"][0]["kind"] = "datagram";
    ExpectError(document, "/services/0/kind");
    document["services"][0]["kind"] = 1;
    ExpectError(document, "/services/0/kind", "string");
    document = ClientDocument();
    document["services"][0].erase("max_concurrent_streams");
    ExpectError(document, "/services/0/max_concurrent_streams", "required key");
    document = ClientDocument();
    document["services"][0]["max_concurrent_streams"] = 0;
    ExpectError(document, "/services/0/max_concurrent_streams", "1..65535");
    document["services"][0]["max_concurrent_streams"] = 65536;
    ExpectError(document, "/services/0/max_concurrent_streams", "1..65535");
    document["services"][0]["max_concurrent_streams"] = "256";
    ExpectError(document, "/services/0/max_concurrent_streams", "integer");
    document = ClientDocument();
    document["services"].push_back(document["services"][0]);
    ExpectError(document, "/services/2/name", "duplicate");
    document = ClientDocument();
    document["services"].push_back(
        {{"name", "tcp"},
         {"kind", "packet"},
         {"max_concurrent_streams", 32}});
    Check(Parse(document).services().size() == 3,
          "the same service name with a distinct kind was rejected");

    document = ClientDocument();
    document["services"] = Json::array();
    for (std::size_t index = 0; index < kMaxServices + 1; ++index) {
        document["services"].push_back(
            {{"name", "svc" + std::to_string(index)},
             {"kind", "stream"},
             {"max_concurrent_streams", 1}});
    }
    ExpectError(document, "/services", "64");
}

void TestAdapterValidation() {
    Json document = ClientDocument();
    document["adapters"] = "socks5";
    ExpectError(document, "/adapters", "array");
    document = ClientDocument();
    document["adapters"][0]["fallback"] = "legacy";
    ExpectError(document, "/adapters/0/fallback", "unknown key");
    document = ClientDocument();
    document["adapters"][0].erase("kind");
    ExpectError(document, "/adapters/0/kind", "required key");
    document = ClientDocument();
    document["adapters"][0]["kind"] = "http_proxy";
    ExpectError(document, "/adapters/0/kind");
    document["adapters"][0]["kind"] = 1;
    ExpectError(document, "/adapters/0/kind", "string");

    document = ServerDocument();
    document["adapters"] = ClientDocument()["adapters"];
    ExpectError(document, "/adapters/0/kind", "client-only");
    document = ClientDocument();
    document["adapters"] =
        Json::array({{{"kind", "direct_tcp"}, {"service", "tcp"}}});
    ExpectError(document, "/adapters/0/kind", "server-only");

    document = ClientDocument();
    document["adapters"][0]["listen_address"] = "0.0.0.0";
    ExpectError(document, "/adapters/0/listen_address", "127.0.0.1");
    document = ClientDocument();
    document["adapters"][0]["listen_port"] = 0;
    ExpectError(document, "/adapters/0/listen_port");
    document = ClientDocument();
    document["adapters"][0]["service"] = "missing";
    ExpectError(document, "/adapters/0/service", "undeclared");
    document["adapters"][0]["service"] = "packet";
    ExpectError(document, "/adapters/0/service", "stream service");

    document = ClientDocument();
    document["adapters"] = Json::array(
        {{{"kind", "packet"},
          {"service", "packet"},
          {"interface_name", "bad/interface"},
          {"mtu", 1420}}});
    ExpectError(document, "/adapters/0/interface_name");
    document["adapters"][0]["interface_name"] = "yume0";
    document["adapters"][0]["mtu"] = 575;
    ExpectError(document, "/adapters/0/mtu");
    document["adapters"][0]["mtu"] = 70000;
    ExpectError(document, "/adapters/0/mtu");
    document["adapters"][0]["mtu"] = 2000;
    document["limits"]["max_packet_bytes"] = 1500;
    ExpectError(document, "/adapters/0/mtu", "max_packet_bytes");

    document = ServerDocument();
    document["adapters"][1]["service"] = "tcp";
    ExpectError(document, "/adapters/1/service", "packet service");
    document = ServerDocument();
    document["adapters"].push_back(document["adapters"][0]);
    ExpectError(document, "/adapters/2/service", "duplicate");

    document = ServerDocument();
    document["services"].push_back(
        {{"name", "admin"},
         {"kind", "stream"},
         {"max_concurrent_streams", 8}});
    document["adapters"].push_back(
        {{"kind", "direct_tcp"}, {"service", "admin"}});
    Check(Parse(document).adapters().size() == 3,
          "distinct direct adapters of the same kind were rejected");

    document = ClientDocument();
    document["services"].push_back(
        {{"name", "admin"},
         {"kind", "stream"},
         {"max_concurrent_streams", 8}});
    document["adapters"].push_back(
        {{"kind", "socks5"},
         {"service", "admin"},
         {"listen_address", "127.0.0.1"},
         {"listen_port", 1081}});
    Check(Parse(document).adapters().size() == 2,
          "distinct SOCKS5 adapters were rejected");
    document["adapters"][1]["listen_port"] = 1080;
    ExpectError(document, "/adapters/1/listen_port", "duplicate");

    document = ClientDocument();
    document["adapters"] = Json::array({
        {{"kind", "packet"},
         {"service", "packet"},
         {"interface_name", "yume0"},
         {"mtu", 1420}},
        {{"kind", "packet"},
         {"service", "packet"},
         {"interface_name", "yume0"},
         {"mtu", 1420}},
    });
    ExpectError(document, "/adapters/1/interface_name", "duplicate");

    document = ClientDocument();
    document["adapters"] = Json::array();
    for (std::size_t index = 0; index < kMaxAdapters + 1; ++index) {
        document["adapters"].push_back(Json::object());
    }
    ExpectError(document, "/adapters", "16");
}

void TestResourceLimits() {
    struct Bound {
        const char* key;
        std::uint64_t minimum;
        std::uint64_t maximum;
    };
    constexpr std::array<Bound, 8> bounds{{
        {"max_frame_bytes", 1024, 1048576},
        {"max_streams", 1, 65535},
        {"max_queued_bytes", 65536, 67108864},
        {"max_pending_opens", 1, 1024},
        {"max_rekey_jobs", 1, 64},
        {"max_control_messages", 8, 4096},
        {"max_packet_bytes", 576, 65535},
        {"max_packet_batch", 1, 256},
    }};
    for (const auto& bound : bounds) {
        Json document = ClientDocument();
        document["limits"].erase(bound.key);
        ExpectError(document, "/limits/" + std::string(bound.key),
                    "required key");

        document = ClientDocument();
        document["limits"][bound.key] = bound.minimum - 1;
        ExpectError(document, "/limits/" + std::string(bound.key));

        document = ClientDocument();
        document["limits"][bound.key] = bound.maximum + 1;
        ExpectError(document, "/limits/" + std::string(bound.key));

        document = ClientDocument();
        document["limits"][bound.key] = "bounded";
        ExpectError(document, "/limits/" + std::string(bound.key), "integer");

        document = ClientDocument();
        document["limits"][bound.key] = 1.5;
        ExpectError(document, "/limits/" + std::string(bound.key), "integer");
    }

    Json minimum = ClientDocument();
    minimum["limits"] = {
        {"max_frame_bytes", 1024},
        {"max_streams", 1},
        {"max_queued_bytes", 65536},
        {"max_pending_opens", 1},
        {"max_rekey_jobs", 1},
        {"max_control_messages", 8},
        {"max_packet_bytes", 576},
        {"max_packet_batch", 1},
    };
    Check(Parse(minimum).limits().max_streams() == 1,
          "minimum resource bounds were rejected");

    Json maximum = ClientDocument();
    maximum["limits"] = {
        {"max_frame_bytes", 1048576},
        {"max_streams", 65535},
        {"max_queued_bytes", 67108864},
        {"max_pending_opens", 1024},
        {"max_rekey_jobs", 64},
        {"max_control_messages", 4096},
        {"max_packet_bytes", 65535},
        {"max_packet_batch", 256},
    };
    Check(Parse(maximum).limits().max_rekey_jobs() == 64,
          "maximum resource bounds were rejected");

    Json document = ClientDocument();
    document["limits"]["fallback"] = true;
    ExpectError(document, "/limits/fallback", "unknown key");
    document = ClientDocument();
    document["limits"]["max_frame_bytes"] = 1048576;
    document["limits"]["max_queued_bytes"] = 65536;
    ExpectError(document, "/limits/max_frame_bytes", "max_queued_bytes");
    document = ClientDocument();
    document["limits"]["max_streams"] = 10;
    document["limits"]["max_pending_opens"] = 11;
    ExpectError(document, "/limits/max_pending_opens", "max_streams");
    document = ClientDocument();
    document["limits"]["max_frame_bytes"] = 1024;
    document["limits"]["max_packet_bytes"] = 1025;
    ExpectError(document, "/limits/max_packet_bytes", "max_frame_bytes");
    document = ClientDocument();
    document["limits"] = Json::array();
    ExpectError(document, "/limits", "object");
}

void TestTextBoundsAndSyntax() {
    ExpectJsonError("{", "", "invalid JSON syntax");
    ExpectJsonError("", "", "invalid JSON syntax");
    ExpectJsonError(std::string(kMaxDocumentBytes + 1, ' '), "", "1 MiB");
    ExpectJsonError(R"({"schema":1,"schema":1})", "/schema", "duplicate");
    ExpectJsonError(
        R"({"endpoint":{"host":"first.example","host":"second.example"}})",
        "/endpoint/host", "duplicate");
    ExpectJsonError(R"({"a/b~c":1,"a/b~c":2})", "/a~1b~0c", "duplicate");

    std::string nested;
    for (std::size_t index = 0; index < kMaxNestingDepth + 3; ++index) {
        nested.push_back('[');
    }
    nested.push_back('0');
    for (std::size_t index = 0; index < kMaxNestingDepth + 3; ++index) {
        nested.push_back(']');
    }
    ExpectJsonError(nested, "", "nesting");

    try {
        (void)ParseJson("{");
    } catch (const ValidationError& error) {
        Check(std::string_view(error.what()).find("JSON pointer \"\"") !=
                  std::string_view::npos,
              "root syntax error omitted the empty RFC6901 pointer");
        return;
    }
    TestFailure("malformed JSON did not fail");
}

}  // namespace

int main(int argc, char** argv) {
    try {
        TestValidDocumentsAndTypedValues();
        TestTopLevelClosureAndVersion();
        TestAliasesAreRejected();
        TestEndpointValidation();
        TestMandatorySuite();
        TestCredentialReferences();
        TestCoverValidation();
        TestServiceValidation();
        TestAdapterValidation();
        TestResourceLimits();
        TestTextBoundsAndSyntax();
        if (argc == 2) {
            const std::string mode(argv[1]);
            if (mode != "--stdin-client" && mode != "--stdin-server") {
                TestFailure("usage: config-v1-test [--stdin-client|--stdin-server]");
            }
            const std::string text(std::istreambuf_iterator<char>(std::cin), {});
            const Config config = ParseJson(text);
            const Role expected = mode == "--stdin-client" ? Role::Client
                                                             : Role::Server;
            Check(config.role() == expected,
                  "checked-in example has the wrong role");
        } else if (argc != 1) {
            TestFailure("usage: config-v1-test [--stdin-client|--stdin-server]");
        }
    } catch (const std::exception& error) {
        std::cerr << "config v1 test failure: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "config v1 tests passed\n";
    return EXIT_SUCCESS;
}
