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

Json TunNetworkDocument() {
    return {{"addresses", Json::array({"10.71.0.1/32"})},
            {"routes", Json::array({"10.71.0.2/32"})},
            {"local_networks", Json::array({"10.71.0.1/32"})},
            {"peer_networks", Json::array({"10.71.0.2/32"})},
            {"dns", {{"servers", Json::array()}, {"domains", Json::array()}}}};
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

Json PublicDestinations() {
    return {{"public", true}, {"networks", Json::array()}};
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
             {{"kind", "direct_tcp"},
              {"service", "tcp"},
              {"destinations", PublicDestinations()}},
             {{"kind", "direct_udp"},
              {"service", "udp"},
              {"destinations", PublicDestinations()}},
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
          {"mtu", 1420}, {"network", TunNetworkDocument()}}});
    Check(std::holds_alternative<PacketAdapter>(
              Parse(packet).adapters().front()),
          "packet adapter was not typed");

    const Config without_udp = Parse(ClientDocument());
    Check(!std::get<Socks5Adapter>(without_udp.adapters().front())
               .udp_service(),
          "a SOCKS5 adapter without udp_service gained one");
    Json udp = ClientDocument();
    udp["adapters"][0]["udp_service"] = "packet";
    const Config udp_config = Parse(udp);
    const auto& socks = std::get<Socks5Adapter>(udp_config.adapters().front());
    Check(socks.udp_service() && *socks.udp_service() == "packet",
          "SOCKS5 udp_service was not retained");
    // UDP ASSOCIATE needs a declared packet service.
    udp["adapters"][0]["udp_service"] = "tcp";
    ExpectError(udp, "/adapters/0/udp_service");
    udp["adapters"][0]["udp_service"] = "missing";
    ExpectError(udp, "/adapters/0/udp_service");
    udp["adapters"][0]["udp_service"] = 7;
    ExpectError(udp, "/adapters/0/udp_service");
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

void TestClientConnectAddress() {
    Json document = ClientDocument();
    Check(!std::get<ClientEndpoint>(Parse(document).endpoint())
               .connect_address()
               .has_value(),
          "connect_address appeared without configuration");
    for (const char* address : {"10.77.77.1", "::1"}) {
        document["endpoint"]["connect_address"] = address;
        Check(std::get<ClientEndpoint>(Parse(document).endpoint())
                      .connect_address() == std::optional<std::string>(address),
              "connect_address was not retained");
    }
    document["endpoint"]["connect_address"] = "server.example.test";
    ExpectError(document, "/endpoint/connect_address", "IP literal");
    document["endpoint"]["connect_address"] = 10;
    ExpectError(document, "/endpoint/connect_address", "string");
    document = ServerDocument();
    document["endpoint"]["connect_address"] = "10.77.77.1";
    ExpectError(document, "/endpoint/connect_address", "unknown key");
}

// A client may reach its server through a SOCKS5 proxy at a numeric address,
// with an optional protected credentials file.
void TestClientSocks5Proxy() {
    Json document = ClientDocument();
    Check(!std::get<ClientEndpoint>(Parse(document).endpoint()).socks5_proxy(),
          "a SOCKS5 proxy appeared without configuration");
    document["endpoint"]["socks5_proxy"] = {{"address", "127.0.0.1"}, {"port", 1080}};
    const Config parsed = Parse(document);
    const auto& plain = std::get<ClientEndpoint>(parsed.endpoint()).socks5_proxy();
    Check(plain && plain->address() == "127.0.0.1" && plain->port() == 1080 &&
              !plain->credentials(),
          "a SOCKS5 proxy without credentials was not retained");
    document["endpoint"]["socks5_proxy"]["address"] = "fd00::10";
    document["endpoint"]["socks5_proxy"]["credentials"] = {{"file", "socks5-proxy"}};
    const Config with_credentials = Parse(document);
    const auto& secured = std::get<ClientEndpoint>(with_credentials.endpoint()).socks5_proxy();
    Check(secured && secured->address() == "fd00::10" && secured->credentials() &&
              secured->credentials()->path() == "socks5-proxy",
          "SOCKS5 proxy credentials were not retained");
    // The client's own connection goes to the proxy, then to connect_address,
    // then to host.
    Check(std::get<ClientEndpoint>(with_credentials.endpoint()).first_hop() == "fd00::10",
          "the first hop is not the proxy");
    Json direct = ClientDocument();
    const Config by_host = Parse(direct);
    Check(std::get<ClientEndpoint>(by_host.endpoint()).first_hop() ==
              std::get<ClientEndpoint>(by_host.endpoint()).host(),
          "the first hop is not the host");
    direct["endpoint"]["connect_address"] = "10.77.77.1";
    const Config by_address = Parse(direct);
    Check(std::get<ClientEndpoint>(by_address.endpoint()).first_hop() == "10.77.77.1",
          "the first hop is not connect_address");
    direct["endpoint"]["socks5_proxy"] = {{"address", "192.0.2.5"}, {"port", 1080}};
    const Config by_proxy = Parse(direct);
    Check(std::get<ClientEndpoint>(by_proxy.endpoint()).first_hop() == "192.0.2.5",
          "connect_address took the proxy's place as the first hop");

    const auto with_proxy = [](Json proxy) {
        Json changed = ClientDocument();
        changed["endpoint"]["socks5_proxy"] = std::move(proxy);
        return changed;
    };
    const std::string pointer = "/endpoint/socks5_proxy";
    ExpectError(with_proxy("127.0.0.1:1080"), pointer, "object");
    ExpectError(with_proxy({{"port", 1080}}), pointer + "/address", "required key");
    ExpectError(with_proxy({{"address", "127.0.0.1"}}), pointer + "/port", "required key");
    ExpectError(with_proxy({{"address", "proxy.example.test"}, {"port", 1080}}), pointer + "/address",
                "IP literal");
    ExpectError(with_proxy({{"address", "127.0.0.1"}, {"port", 0}}), pointer + "/port", "");
    ExpectError(with_proxy({{"address", "127.0.0.1"}, {"port", 1080}, {"user", "x"}}), pointer + "/user",
                "unknown key");
    ExpectError(with_proxy({{"address", "127.0.0.1"}, {"port", 1080}, {"credentials", "socks5-proxy"}}),
                pointer + "/credentials", "object");
    ExpectError(with_proxy({{"address", "127.0.0.1"}, {"port", 1080},
                            {"credentials", {{"file", "../socks5-proxy"}}}}),
                pointer + "/credentials/file", "parent traversal");
    document = ServerDocument();
    document["endpoint"]["socks5_proxy"] = {{"address", "127.0.0.1"}, {"port", 1080}};
    ExpectError(document, pointer, "unknown key");
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
    document = ClientDocument();
    document["cover"]["profile"] = "firefox-unqualified-v1";
    ExpectError(document, "/cover/profile", "not qualified by this build");
    document = ServerDocument();
    document["cover"]["profile"] = "firefox-unqualified-v1";
    ExpectError(document, "/cover/profile", "not qualified by this build");

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
        Json::array({{{"kind", "direct_tcp"},
                      {"service", "tcp"},
                      {"destinations", PublicDestinations()}}});
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
          {"mtu", 1420}, {"network", TunNetworkDocument()}}});
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
        {{"kind", "direct_tcp"},
         {"service", "admin"},
         {"destinations", PublicDestinations()}});
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
         {"mtu", 1420}, {"network", TunNetworkDocument()}},
        {{"kind", "packet"},
         {"service", "packet"},
         {"interface_name", "yume0"},
         {"mtu", 1420}, {"network", TunNetworkDocument()}},
    });
    ExpectError(document, "/adapters/1/interface_name", "duplicate");

    document = ClientDocument();
    document["adapters"] = Json::array();
    for (std::size_t index = 0; index < kMaxAdapters + 1; ++index) {
        document["adapters"].push_back(Json::object());
    }
    ExpectError(document, "/adapters", "16");
}

void TestDirectAdapterDestinations() {
    Json document = ServerDocument();
    document["adapters"][0].erase("destinations");
    ExpectError(document, "/adapters/0/destinations", "required key");
    document = ServerDocument();
    document["adapters"][0]["destinations"] = true;
    ExpectError(document, "/adapters/0/destinations", "object");
    document = ServerDocument();
    document["adapters"][0]["destinations"]["hosts"] = Json::array();
    ExpectError(document, "/adapters/0/destinations/hosts", "unknown key");
    document = ServerDocument();
    document["adapters"][0]["destinations"]["public"] = 1;
    ExpectError(document, "/adapters/0/destinations/public", "boolean");
    document = ServerDocument();
    document["adapters"][0]["destinations"]["networks"] = "10.0.0.0/8";
    ExpectError(document, "/adapters/0/destinations/networks", "array");
    document = ServerDocument();
    document["adapters"][0]["destinations"]["public"] = false;
    ExpectError(document, "/adapters/0/destinations", "at least one network");

    for (const char* text : {"10.0.0.1/8", "2001:DB8::/32", "localhost/32",
                             "::ffff:10.0.0.0/104"}) {
        document = ServerDocument();
        document["adapters"][1]["destinations"]["networks"] =
            Json::array({"192.168.0.0/16", text});
        ExpectError(document, "/adapters/1/destinations/networks/1", "canonical");
    }
    document = ServerDocument();
    document["adapters"][0]["destinations"]["networks"] = Json::array({1});
    ExpectError(document, "/adapters/0/destinations/networks/0", "string");
    for (const char* text : {"0.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32",
                             "::/128", "ff02::1/128", "::ffff:0:0/96",
                             "::ffff:a00:0/120"}) {
        document = ServerDocument();
        document["adapters"][0]["destinations"]["networks"] = Json::array({text});
        ExpectError(document, "/adapters/0/destinations/networks/0", "never");
    }
    document = ServerDocument();
    document["adapters"][0]["destinations"]["networks"] =
        Json::array({"10.0.0.0/8", "10.0.0.0/8"});
    ExpectError(document, "/adapters/0/destinations/networks/1", "duplicate");
    document = ServerDocument();
    for (std::size_t index = 0; index <= kMaxDestinationNetworks; ++index) {
        document["adapters"][0]["destinations"]["networks"].push_back(
            "10." + std::to_string(index) + ".0.0/16");
    }
    ExpectError(document, "/adapters/0/destinations/networks", "64");

    document = ServerDocument();
    document["adapters"][0]["destinations"] = {
        {"public", false},
        {"networks", Json::array({"127.0.0.1/32", "fd00::/8", "0.0.0.0/7"})}};
    const Config parsed = Parse(document);
    const auto* tcp = std::get_if<DirectTcpAdapter>(&parsed.adapters()[0]);
    Check(tcp != nullptr && !tcp->destinations().public_addresses() &&
              tcp->destinations().networks().size() == 3,
          "direct TCP destinations were not retained");
    Check(tcp->destinations().networks()[1] ==
              *yume::common::parse_canonical_ip_network("fd00::/8"),
          "IPv6 destination network changed");
    const auto* udp = std::get_if<DirectUdpAdapter>(&parsed.adapters()[1]);
    Check(udp != nullptr && udp->destinations().public_addresses() &&
              udp->destinations().networks().empty(),
          "direct UDP destinations were not retained");
}

// Egress list files and the country database are references. The runtime
// reads them, so the parser checks only their shape.
void TestDestinationLists() {
    const Json deny = {{"action", "deny"}, {"format", "vpdb"}, {"file", "lists/vpn_db.bin"}};
    const auto with_lists = [](Json lists) {
        Json document = ServerDocument();
        document["adapters"][0]["destinations"]["lists"] = std::move(lists);
        return document;
    };
    const auto with_item = [&](const std::function<void(Json&)>& change) {
        Json item = deny;
        change(item);
        return with_lists(Json::array({item}));
    };
    const std::string item = "/adapters/0/destinations/lists/0";
    ExpectError(with_lists(true), "/adapters/0/destinations/lists", "array");
    ExpectError(with_lists(Json::array({"lists/vpn_db.bin"})), item, "object");
    ExpectError(with_item([](Json& entry) { entry["action"] = "block"; }), item + "/action",
                "'allow' or 'deny'");
    ExpectError(with_item([](Json& entry) { entry["action"] = "Deny"; }), item + "/action",
                "'allow' or 'deny'");
    ExpectError(with_item([](Json& entry) { entry["format"] = "tar.xz"; }), item + "/format",
                "'json' or 'vpdb'");
    ExpectError(with_item([](Json& entry) { entry.erase("format"); }), item + "/format",
                "required key");
    ExpectError(with_item([](Json& entry) { entry["path"] = "x"; }), item + "/path", "unknown key");
    ExpectError(with_item([](Json& entry) { entry["file"] = 7; }), item + "/file", "string");
    ExpectError(with_item([](Json& entry) { entry["file"] = "../vpn_db.bin"; }), item + "/file",
                "parent traversal");
    ExpectError(with_item([](Json& entry) { entry["file"] = "https://example.net/list.json"; }),
                item + "/file", "URI");
    ExpectError(with_lists(Json::array({deny, deny})), "/adapters/0/destinations/lists/1/file",
                "duplicate list file");
    Json many = Json::array();
    for (std::size_t index = 0; index <= kMaxDestinationLists; ++index) {
        Json entry = deny;
        entry["file"] = "lists/" + std::to_string(index) + ".bin";
        many.push_back(entry);
    }
    ExpectError(with_lists(many), "/adapters/0/destinations/lists", "16");

    const Json database = {{"file", "GeoLite2-Country.mmdb"}};
    Json document = ServerDocument();
    document["adapters"][0]["destinations"]["country_database"] = database;
    ExpectError(document, "/adapters/0/destinations/country_database", "needs a list");
    document = with_lists(Json::array());
    document["adapters"][0]["destinations"]["country_database"] = database;
    ExpectError(document, "/adapters/0/destinations/country_database", "needs a list");
    document = with_lists(Json::array({deny}));
    document["adapters"][0]["destinations"]["country_database"] = {{"path", "x"}};
    ExpectError(document, "/adapters/0/destinations/country_database/path", "unknown key");
    document = with_lists(Json::array({deny}));
    document["adapters"][0]["destinations"]["country_database"] = "GeoLite2-Country.mmdb";
    ExpectError(document, "/adapters/0/destinations/country_database", "object");

    document = with_lists(Json::array(
        {deny, {{"action", "allow"}, {"format", "json"}, {"file", "/etc/yume/allow.json"}}}));
    document["adapters"][0]["destinations"]["country_database"] = database;
    const Config parsed = Parse(document);
    const auto* tcp = std::get_if<DirectTcpAdapter>(&parsed.adapters()[0]);
    Check(tcp != nullptr && tcp->destinations().lists().size() == 2,
          "egress lists were not retained");
    const auto& lists = tcp->destinations().lists();
    Check(lists[0].action() == DestinationListAction::Deny &&
              lists[0].format() == DestinationListFormat::Vpdb &&
              lists[0].file().path() == "lists/vpn_db.bin",
          "the first egress list changed");
    Check(lists[1].action() == DestinationListAction::Allow &&
              lists[1].format() == DestinationListFormat::Json &&
              lists[1].file().path() == "/etc/yume/allow.json",
          "the second egress list changed");
    Check(tcp->destinations().country_database() &&
              tcp->destinations().country_database()->path() == "GeoLite2-Country.mmdb",
          "the country database reference was not retained");
    const Config plain = Parse(ServerDocument());
    const auto* bare = std::get_if<DirectTcpAdapter>(&plain.adapters()[0]);
    Check(bare != nullptr && bare->destinations().lists().empty() &&
              !bare->destinations().country_database(),
          "a policy without lists gained some");
}

Json ForwardAdapterDocument(Json listener) {
    Json adapter = {{"kind", "forward"}, {"service", "tcp"}};
    adapter.update(listener);
    return adapter;
}

// A client forward listens on loopback TCP or an absolute UNIX path and may
// name a fixed TCP destination.
void TestForwardAdapters() {
    Json document = ClientDocument();
    document["adapters"].push_back(ForwardAdapterDocument(
        {{"listen_address", "::1"}, {"listen_port", 2222},
         {"destination", {{"host", "git.example.net"}, {"port", 22}}}}));
    document["adapters"].push_back(ForwardAdapterDocument(
        {{"listen_path", "/run/user/1000/yume/chat.sock"}}));
    const Config parsed = Parse(document);
    const auto* tcp = std::get_if<ForwardAdapter>(&parsed.adapters()[1]);
    Check(tcp != nullptr && tcp->service() == "tcp", "the TCP forward was not retained");
    const auto* loopback = std::get_if<LoopbackListener>(&tcp->listener());
    Check(loopback != nullptr && loopback->address == "::1" && loopback->port == 2222,
          "the TCP forward listener changed");
    Check(tcp->destination() && tcp->destination()->host == "git.example.net" &&
              tcp->destination()->port == 22,
          "the forward destination changed");
    const auto* local = std::get_if<ForwardAdapter>(&parsed.adapters()[2]);
    Check(local != nullptr && !local->destination(), "the UNIX forward was not retained");
    const auto* path = std::get_if<UnixListener>(&local->listener());
    Check(path != nullptr && path->path == "/run/user/1000/yume/chat.sock",
          "the UNIX forward path changed");

    const auto rejects = [](Json adapter, const std::string& suffix, std::string_view detail) {
        Json candidate = ClientDocument();
        candidate["adapters"].push_back(std::move(adapter));
        ExpectError(candidate, "/adapters/1" + suffix, detail);
    };
    rejects(ForwardAdapterDocument(Json::object()), "/listen_address", "required key");
    rejects(ForwardAdapterDocument({{"listen_address", "127.0.0.1"}}), "/listen_port",
            "required key");
    rejects(ForwardAdapterDocument({{"listen_address", "0.0.0.0"}, {"listen_port", 2222}}),
            "/listen_address", "127.0.0.1 or ::1");
    rejects(ForwardAdapterDocument({{"listen_address", "127.0.0.1"}, {"listen_port", 1080}}),
            "/listen_port", "duplicate local listen");
    rejects(ForwardAdapterDocument({{"listen_path", "/run/a.sock"}, {"listen_port", 22}}),
            "/listen_port", "absent with listen_path");
    for (const char* path : {"relative.sock", "/", "/run/", "/run//a.sock", "/run/./a.sock",
                             "/run/../a.sock", "/run/a\nb.sock"}) {
        rejects(ForwardAdapterDocument({{"listen_path", path}}), "/listen_path",
                "normalized absolute path");
    }
    rejects(ForwardAdapterDocument({{"listen_path", "/" + std::string(107U, 'a')}}),
            "/listen_path", "at most 107 bytes");
    rejects(ForwardAdapterDocument({{"listen_address", "127.0.0.1"}, {"listen_port", 2222},
                                    {"destination", {{"host", "bad host"}, {"port", 22}}}}),
            "/destination/host", "IP literal or DNS host name");
    rejects(ForwardAdapterDocument({{"listen_address", "127.0.0.1"}, {"listen_port", 2222},
                                    {"destination", {{"host", "example.net"}}}}),
            "/destination/port", "required key");
    rejects(ForwardAdapterDocument({{"listen_address", "127.0.0.1"}, {"listen_port", 2222},
                                    {"fallback", true}}),
            "/fallback", "unknown key");
    Json packet_service = ForwardAdapterDocument({{"listen_path", "/run/a.sock"}});
    packet_service["service"] = "packet";
    rejects(packet_service, "/service", "");

    Json twice = ClientDocument();
    twice["adapters"].push_back(ForwardAdapterDocument({{"listen_path", "/run/a.sock"}}));
    twice["adapters"].push_back(ForwardAdapterDocument({{"listen_path", "/run/a.sock"}}));
    ExpectError(twice, "/adapters/2/listen_path", "duplicate local listen path");

    Json server = ServerDocument();
    server["adapters"].push_back(ForwardAdapterDocument({{"listen_path", "/run/a.sock"}}));
    ExpectError(server, "/adapters/2/kind", "client-only");
}

// A server module runs one program for a stream service, with optional
// arguments, and no other adapter may serve that service.
void TestModuleAdapters() {
    Json document = ServerDocument();
    document["services"].push_back(
        {{"name", "chat"}, {"kind", "stream"}, {"max_concurrent_streams", 16}});
    document["adapters"].push_back({{"kind", "module"}, {"service", "chat"},
        {"program", "/usr/libexec/yume/yume-chat"}, {"arguments", {"--history", "7"}}});
    const Config parsed = Parse(document);
    const auto* module = std::get_if<ModuleAdapter>(&parsed.adapters().back());
    Check(module != nullptr && module->service() == "chat" &&
              module->program() == "/usr/libexec/yume/yume-chat" &&
              module->arguments() == std::vector<std::string>{"--history", "7"},
          "the module adapter was not retained");

    const auto rejects = [](const std::function<void(Json&)>& change, const std::string& pointer,
                            std::string_view detail) {
        Json candidate = ServerDocument();
        candidate["services"].push_back(
            {{"name", "chat"}, {"kind", "stream"}, {"max_concurrent_streams", 16}});
        candidate["adapters"].push_back({{"kind", "module"}, {"service", "chat"},
                                         {"program", "/usr/libexec/yume/yume-chat"}});
        change(candidate);
        ExpectError(candidate, pointer, detail);
    };
    Check(Parse([] {
              Json candidate = ServerDocument();
              candidate["services"].push_back(
                  {{"name", "chat"}, {"kind", "stream"}, {"max_concurrent_streams", 16}});
              candidate["adapters"].push_back({{"kind", "module"}, {"service", "chat"},
                                               {"program", "/usr/libexec/yume/yume-chat"}});
              return candidate;
          }()).adapters().size() == 3,
          "a module without arguments was refused");
    rejects([](Json& value) { value["adapters"][2]["program"] = "yume-chat"; },
            "/adapters/2/program", "normalized absolute path");
    rejects([](Json& value) { value["adapters"][2]["program"] = "/usr/../bin/sh"; },
            "/adapters/2/program", "normalized absolute path");
    rejects([](Json& value) { value["adapters"][2]["arguments"] = Json::array({1}); },
            "/adapters/2/arguments/0", "string");
    rejects([](Json& value) {
                value["adapters"][2]["arguments"] = Json::array();
                for (int count = 0; count < 33; ++count) value["adapters"][2]["arguments"].push_back("x");
            },
            "/adapters/2/arguments", "at most 32");
    rejects([](Json& value) { value["adapters"][2]["arguments"] = {std::string(1025U, 'a')}; },
            "/adapters/2/arguments/0", "at most 1024 bytes");
    rejects([](Json& value) { value["adapters"][2]["arguments"] = {std::string("a\0b", 3U)}; },
            "/adapters/2/arguments/0", "NUL");
    rejects([](Json& value) { value["adapters"][2]["service"] = "udp"; },
            "/adapters/2/service", "");
    rejects([](Json& value) { value["adapters"][2]["fallback"] = true; },
            "/adapters/2/fallback", "unknown key");
    rejects([](Json& value) { value["adapters"][2]["service"] = "tcp"; },
            "/adapters/2/service", "already has an adapter");
    rejects([](Json& value) {
                value["adapters"].push_back({{"kind", "direct_tcp"}, {"service", "chat"},
                                             {"destinations", PublicDestinations()}});
            },
            "/adapters/3/service", "already has an adapter");

    Json client = ClientDocument();
    client["adapters"].push_back({{"kind", "module"}, {"service", "tcp"},
                                  {"program", "/usr/libexec/yume/yume-chat"}});
    ExpectError(client, "/adapters/1/kind", "server-only");
}

// The egress rate is optional and server-only.
void TestEgressRate() {
    Check(!Parse(ServerDocument()).limits().max_egress_mbps(),
          "an absent egress rate was reported");
    for (const std::uint32_t mbps : {1U, 250U, 1'000'000U}) {
        Json document = ServerDocument();
        document["limits"]["max_egress_mbps"] = mbps;
        Check(Parse(document).limits().max_egress_mbps() == mbps,
              "a valid egress rate was not retained");
    }
    for (const Json& value : {Json(0), Json(1'000'001), Json(-1)}) {
        Json document = ServerDocument();
        document["limits"]["max_egress_mbps"] = value;
        ExpectError(document, "/limits/max_egress_mbps");
    }
    for (const Json& value : {Json(1.5), Json("100"), Json(true), Json(nullptr)}) {
        Json document = ServerDocument();
        document["limits"]["max_egress_mbps"] = value;
        ExpectError(document, "/limits/max_egress_mbps", "integer");
    }
    Json client = ClientDocument();
    client["limits"]["max_egress_mbps"] = 100;
    ExpectError(client, "/limits/max_egress_mbps", "server-only");
}

void TestResourceLimits() {
    struct Bound {
        const char* key;
        std::uint64_t minimum;
        std::uint64_t maximum;
    };
    constexpr std::array<Bound, 8> bounds{{
        {"max_frame_bytes", 1676, 1048576},
        {"max_streams", 1, 65535},
        {"max_queued_bytes", 65536, 67108864},
        {"max_pending_opens", 1, 1024},
        {"max_rekey_jobs", 2, 64},
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
        {"max_frame_bytes", 1676},
        {"max_streams", 1},
        {"max_queued_bytes", 65536},
        {"max_pending_opens", 1},
        {"max_rekey_jobs", 2},
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
    document["limits"]["max_frame_bytes"] = 1676;
    document["limits"]["max_packet_bytes"] = 1677;
    ExpectError(document, "/limits/max_packet_bytes", "max_frame_bytes");
    document = ClientDocument();
    document["limits"] = Json::array();
    ExpectError(document, "/limits", "object");
}

void test_managed_tun_network() {
    auto document = ClientDocument();
    document["adapters"] = Json::array({{{"kind", "packet"}, {"service", "packet"},
        {"interface_name", "yume0"}, {"mtu", 1420}, {"network", TunNetworkDocument()}}});
    const auto baseline = document;
    const auto valid = Parse(document);
    const auto& network = std::get<PacketAdapter>(valid.adapters().front()).network();
    Check(network.addresses.front().address[3] == 1U && network.routes.front().address[3] == 2U,
          "TUN parser lost interface host address");
    document["adapters"][0].erase("network");
    ExpectError(document, "/adapters/0/network");
    for (const char* field : {"addresses", "local_networks", "peer_networks"}) {
        document = baseline;
        document["adapters"][0]["network"][field] = Json::array();
        ExpectError(document, std::string("/adapters/0/network/") + field);
    }
    for (const char* address : {"10.71.0.3/32", "127.0.0.1/32", "224.0.0.1/32", "0.0.0.0/32", "10.071.0.1/32"}) {
        document = baseline;
        document["adapters"][0]["network"]["addresses"][0] = address;
        ExpectError(document, "/adapters/0/network/addresses/0");
    }
    document = baseline;
    document["adapters"][0]["network"]["dns"] = {{"servers", Json::array({"10.71.0.2"})}, {"domains", Json::array({"."})}};
    (void)Parse(document);
    document["adapters"][0]["network"]["routes"] = Json::array();
    ExpectError(document, "/adapters/0/network/dns/servers/0");
    document = baseline;
    document["adapters"][0]["network"]["local_networks"] = Json::array({"fd71::/64"});
    document["adapters"][0]["network"]["addresses"] = Json::array({"fd71::1/64"});
    (void)Parse(document);
    document["adapters"][0]["mtu"] = 1200;
    ExpectError(document, "/adapters/0/network");
    document = baseline;
    document["adapters"][0]["interface_name"] = "1234567890123456";
    ExpectError(document, "/adapters/0/interface_name");
}

void TestTextBoundsAndSyntax() {
    ExpectJsonError("{", "", "invalid JSON syntax");
    ExpectJsonError("", "", "invalid JSON syntax");
    for (const char* overflow : {"1e999", "-1e999", R"({"schema":1e999})",
                                 R"({"endpoint":{"port":-1e999}})"}) {
        ExpectJsonError(overflow, "", "number exceeds the supported range");
    }
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
    TestClientConnectAddress();
    TestClientSocks5Proxy();
        TestMandatorySuite();
        TestCredentialReferences();
        TestCoverValidation();
        TestServiceValidation();
        TestAdapterValidation();
    TestDirectAdapterDestinations();
    TestDestinationLists();
        TestResourceLimits();
        TestForwardAdapters();
        TestModuleAdapters();
        TestEgressRate();
        test_managed_tun_network();
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
