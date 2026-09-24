/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "config/v1/config.hpp"

#include "common/egress_address.hpp"
#include "common/service_name.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <initializer_list>
#include <limits>
#include <set>
#include <string>
#include <utility>

#include <nlohmann/json.hpp>

namespace yume::config::v1 {
namespace {

using Json = nlohmann::json;

constexpr std::size_t kMaxHostBytes = 253;
constexpr std::size_t kMaxProfileBytes = 128;
constexpr std::size_t kMaxInterfaceNameBytes = 15;

constexpr std::uint32_t kMinFrameBytes = 1676;
constexpr std::uint32_t kMaxFrameBytes = 1024U * 1024U;
constexpr std::uint32_t kMinStreams = 1;
constexpr std::uint32_t kMaxStreams = 65535;
constexpr std::uint32_t kMinQueuedBytes = 64U * 1024U;
constexpr std::uint32_t kMaxQueuedBytes = 64U * 1024U * 1024U;
constexpr std::uint32_t kMinPendingOpens = 1;
constexpr std::uint32_t kMaxPendingOpens = 1024;
constexpr std::uint32_t kMinRekeyJobs = 2;
constexpr std::uint32_t kMaxRekeyJobs = 64;
constexpr std::uint32_t kMinControlMessages = 8;
constexpr std::uint32_t kMaxControlMessages = 4096;
constexpr std::uint32_t kMinPacketBytes = 576;
constexpr std::uint32_t kMaxPacketBytes = 65535;
constexpr std::uint32_t kMinPacketBatch = 1;
constexpr std::uint32_t kMaxPacketBatch = 256;
constexpr std::uint32_t kMinEgressMbps = 1;
constexpr std::uint32_t kMaxEgressMbps = 1'000'000;

std::string FormatValidationMessage(std::string_view pointer,
                                    std::string_view detail) {
    return "configuration error at JSON pointer \"" + std::string(pointer) +
           "\": " + std::string(detail);
}

[[noreturn]] void Fail(std::string pointer, std::string detail) {
    throw ValidationError(std::move(pointer), std::move(detail));
}

std::string EscapePointerToken(std::string_view token) {
    std::string escaped;
    escaped.reserve(token.size());
    for (const char ch : token) {
        if (ch == '~') {
            escaped += "~0";
        } else if (ch == '/') {
            escaped += "~1";
        } else {
            escaped.push_back(ch);
        }
    }
    return escaped;
}

std::string JoinPointer(std::string_view base, std::string_view token) {
    std::string pointer(base);
    pointer.push_back('/');
    pointer += EscapePointerToken(token);
    return pointer;
}

std::string IndexPointer(std::string_view base, std::size_t index) {
    return JoinPointer(base, std::to_string(index));
}

bool Contains(std::initializer_list<std::string_view> values,
              std::string_view candidate) {
    return std::find(values.begin(), values.end(), candidate) != values.end();
}

void CheckClosedObject(
    const Json& value,
    std::string_view pointer,
    std::initializer_list<std::string_view> allowed,
    std::initializer_list<std::string_view> required) {
    if (!value.is_object()) {
        Fail(std::string(pointer), "must be an object");
    }
    for (auto it = value.begin(); it != value.end(); ++it) {
        if (!Contains(allowed, it.key())) {
            Fail(JoinPointer(pointer, it.key()), "unknown key");
        }
    }
    for (const std::string_view key : required) {
        if (!value.contains(key)) {
            Fail(JoinPointer(pointer, key), "required key is missing");
        }
    }
}

std::string ReadString(const Json& value,
                       std::string pointer,
                       std::size_t maximum) {
    if (!value.is_string()) {
        Fail(std::move(pointer), "must be a string");
    }
    const auto& text = value.get_ref<const std::string&>();
    if (text.size() > maximum) {
        Fail(std::move(pointer),
             "must be at most " + std::to_string(maximum) + " bytes");
    }
    return text;
}

bool ReadBoolean(const Json& value, std::string pointer) {
    if (!value.is_boolean()) {
        Fail(std::move(pointer), "must be a boolean");
    }
    return value.get<bool>();
}

std::uint32_t ReadBoundedUnsigned(const Json& value,
                                  std::string pointer,
                                  std::uint32_t minimum,
                                  std::uint32_t maximum) {
    std::uint64_t parsed = 0;
    if (value.is_number_unsigned()) {
        parsed = value.get<std::uint64_t>();
    } else if (value.is_number_integer()) {
        const auto signed_value = value.get<std::int64_t>();
        if (signed_value < 0) {
            Fail(std::move(pointer), "must be a non-negative integer");
        }
        parsed = static_cast<std::uint64_t>(signed_value);
    } else {
        Fail(std::move(pointer), "must be an integer");
    }
    if (parsed < minimum || parsed > maximum) {
        Fail(std::move(pointer),
             "must be in " + std::to_string(minimum) + ".." +
                 std::to_string(maximum));
    }
    return static_cast<std::uint32_t>(parsed);
}

bool IsAsciiAlnum(char ch) {
    const auto byte = static_cast<unsigned char>(ch);
    return (byte >= 'a' && byte <= 'z') ||
           (byte >= 'A' && byte <= 'Z') ||
           (byte >= '0' && byte <= '9');
}

bool IsSafeIdentifier(std::string_view value,
                      std::size_t maximum,
                      bool allow_dot) {
    if (value.empty() || value.size() > maximum ||
        !IsAsciiAlnum(value.front()) || !IsAsciiAlnum(value.back())) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [&](char ch) {
        return IsAsciiAlnum(ch) || ch == '-' || ch == '_' ||
               (allow_dot && ch == '.');
    });
}

bool IsIpv4(std::string_view value) {
    std::size_t start = 0;
    unsigned parts = 0;
    while (start <= value.size()) {
        const std::size_t end = value.find('.', start);
        const std::string_view part = value.substr(
            start, end == std::string_view::npos ? value.size() - start
                                                 : end - start);
        if (part.empty() || part.size() > 3 ||
            !std::all_of(part.begin(), part.end(), [](char ch) {
                return ch >= '0' && ch <= '9';
            })) {
            return false;
        }
        unsigned number = 0;
        const auto conversion =
            std::from_chars(part.data(), part.data() + part.size(), number);
        if (conversion.ec != std::errc{} ||
            conversion.ptr != part.data() + part.size() || number > 255) {
            return false;
        }
        ++parts;
        if (end == std::string_view::npos) break;
        start = end + 1;
    }
    return parts == 4;
}

bool CountIpv6Units(std::string_view part,
                    bool allow_embedded_ipv4,
                    unsigned* units) {
    if (!units) return false;
    *units = 0;
    if (part.empty()) return true;

    std::size_t start = 0;
    while (start <= part.size()) {
        const std::size_t end = part.find(':', start);
        const std::string_view group = part.substr(
            start, end == std::string_view::npos ? part.size() - start
                                                 : end - start);
        if (group.empty()) return false;
        if (group.find('.') != std::string_view::npos) {
            if (!allow_embedded_ipv4 || end != std::string_view::npos ||
                !IsIpv4(group)) {
                return false;
            }
            *units += 2;
        } else {
            if (group.size() > 4 ||
                !std::all_of(group.begin(), group.end(), [](char ch) {
                    return (ch >= '0' && ch <= '9') ||
                           (ch >= 'a' && ch <= 'f') ||
                           (ch >= 'A' && ch <= 'F');
                })) {
                return false;
            }
            ++*units;
        }
        if (end == std::string_view::npos) break;
        start = end + 1;
    }
    return true;
}

bool IsIpv6(std::string_view value) {
    if (value.empty() || value.find(':') == std::string_view::npos) {
        return false;
    }
    const std::size_t compression = value.find("::");
    if (compression == std::string_view::npos) {
        unsigned units = 0;
        return CountIpv6Units(value, true, &units) && units == 8;
    }
    if (value.find("::", compression + 2) != std::string_view::npos) {
        return false;
    }
    const std::string_view left = value.substr(0, compression);
    const std::string_view right = value.substr(compression + 2);
    unsigned left_units = 0;
    unsigned right_units = 0;
    return CountIpv6Units(left, false, &left_units) &&
           CountIpv6Units(right, true, &right_units) &&
           left_units + right_units < 8;
}

bool IsDnsName(std::string_view value) {
    if (value.empty() || value.size() > kMaxHostBytes) return false;
    const bool numeric_dots_only =
        std::all_of(value.begin(), value.end(), [](char ch) {
            return (ch >= '0' && ch <= '9') || ch == '.';
        });
    if (numeric_dots_only) return false;

    std::size_t start = 0;
    while (start <= value.size()) {
        const std::size_t end = value.find('.', start);
        const std::string_view label = value.substr(
            start, end == std::string_view::npos ? value.size() - start
                                                 : end - start);
        if (label.empty() || label.size() > 63 ||
            !IsAsciiAlnum(label.front()) || !IsAsciiAlnum(label.back()) ||
            !std::all_of(label.begin(), label.end(), [](char ch) {
                return IsAsciiAlnum(ch) || ch == '-';
            })) {
            return false;
        }
        if (end == std::string_view::npos) break;
        start = end + 1;
    }
    return true;
}

bool IsIpLiteral(std::string_view value) {
    return IsIpv4(value) || IsIpv6(value);
}

bool IsClientHost(std::string_view value) {
    return value.size() <= kMaxHostBytes &&
           (IsIpLiteral(value) || IsDnsName(value));
}

bool IsLoopbackAddress(std::string_view value) {
    return value == "127.0.0.1" || value == "::1";
}

bool LooksLikeInlineSecret(std::string_view value) {
    if (value.rfind("-----BEGIN", 0) == 0) return true;
    if (value.size() != 64) return false;
    return std::all_of(value.begin(), value.end(), [](char ch) {
        return (ch >= '0' && ch <= '9') ||
               (ch >= 'a' && ch <= 'f') ||
               (ch >= 'A' && ch <= 'F');
    });
}

bool HasParentTraversal(std::string_view value) {
    std::size_t start = 0;
    while (start <= value.size()) {
        const std::size_t end = value.find_first_of("/\\", start);
        const std::string_view component = value.substr(
            start, end == std::string_view::npos ? value.size() - start
                                                 : end - start);
        if (component == "..") return true;
        if (end == std::string_view::npos) break;
        start = end + 1;
    }
    return false;
}

void ValidateFileReference(std::string_view value,
                           const std::string& pointer) {
    if (value.empty()) {
        Fail(pointer, "file reference must not be empty");
    }
    if (value.size() > kMaxFileReferenceBytes) {
        Fail(pointer,
             "file reference must be at most " +
                 std::to_string(kMaxFileReferenceBytes) + " bytes");
    }
    if (std::any_of(value.begin(), value.end(), [](char ch) {
            const auto byte = static_cast<unsigned char>(ch);
            return byte < 0x20 || byte == 0x7f;
        })) {
        Fail(pointer, "file reference must not contain control characters");
    }
    if (std::isspace(static_cast<unsigned char>(value.front())) != 0 ||
        std::isspace(static_cast<unsigned char>(value.back())) != 0) {
        Fail(pointer, "file reference must not have surrounding whitespace");
    }
    if (value.front() == '~') {
        Fail(pointer, "file reference must not depend on home expansion");
    }
    if (value.find("://") != std::string_view::npos) {
        Fail(pointer, "file reference must be a path, not a URI");
    }
    if (value == "." || HasParentTraversal(value)) {
        Fail(pointer, "file reference must not contain parent traversal");
    }
    if (LooksLikeInlineSecret(value)) {
        Fail(pointer, "inline credential material is forbidden; use a file path");
    }
}

FileReference ParseFileReference(const Json& object,
                                 std::string_view parent_pointer,
                                 std::string_view key) {
    const std::string pointer = JoinPointer(parent_pointer, key);
    const auto& reference = object.at(key);
    CheckClosedObject(reference, pointer, {"file"}, {"file"});
    const std::string file_pointer = JoinPointer(pointer, "file");
    const auto& path = ReadString(reference.at("file"), file_pointer,
                                  kMaxFileReferenceBytes);
    ValidateFileReference(path, file_pointer);
    return FileReference(path);
}

std::uint16_t ParsePort(const Json& value, std::string pointer) {
    return static_cast<std::uint16_t>(
        ReadBoundedUnsigned(value, std::move(pointer), 1, 65535));
}

Role ParseRole(const Json& value) {
    const auto& role = ReadString(value, "/role", 16);
    if (role == "client") return Role::Client;
    if (role == "server") return Role::Server;
    Fail("/role", "must be 'client' or 'server'");
}

Endpoint ParseEndpoint(const Json& endpoint, Role role) {
    if (role == Role::Client) {
        CheckClosedObject(endpoint, "/endpoint",
                          {"host", "port", "connect_address"},
                          {"host", "port"});
        const auto& host =
            ReadString(endpoint.at("host"), "/endpoint/host", kMaxHostBytes);
        if (!IsClientHost(host)) {
            Fail("/endpoint/host", "must be an IP literal or DNS host name");
        }
        const std::uint16_t port =
            ParsePort(endpoint.at("port"), "/endpoint/port");
        std::optional<std::string> connect_address;
        if (endpoint.contains("connect_address")) {
            const auto& address = ReadString(endpoint.at("connect_address"),
                                             "/endpoint/connect_address", 64);
            if (!IsIpLiteral(address)) {
                Fail("/endpoint/connect_address", "must be an IP literal");
            }
            connect_address = address;
        }
        return ClientEndpoint(host, port, std::move(connect_address));
    }

    CheckClosedObject(endpoint, "/endpoint", {"listen_addresses", "port"},
                      {"listen_addresses", "port"});
    const auto& addresses = endpoint.at("listen_addresses");
    if (!addresses.is_array()) {
        Fail("/endpoint/listen_addresses", "must be an array");
    }
    if (addresses.empty() || addresses.size() > kMaxListenAddresses) {
        Fail("/endpoint/listen_addresses",
             "must contain 1.." + std::to_string(kMaxListenAddresses) +
                 " addresses");
    }
    std::vector<std::string> parsed;
    parsed.reserve(addresses.size());
    std::set<std::string> unique;
    for (std::size_t index = 0; index < addresses.size(); ++index) {
        const std::string pointer =
            IndexPointer("/endpoint/listen_addresses", index);
        const auto& address = ReadString(addresses.at(index), pointer, 64);
        if (!IsIpLiteral(address)) {
            Fail(pointer, "must be an IP literal");
        }
        if (!unique.insert(address).second) {
            Fail(pointer, "duplicate listen address");
        }
        parsed.push_back(address);
    }
    return ServerEndpoint(
        std::move(parsed),
        ParsePort(endpoint.at("port"), "/endpoint/port"));
}

Suite ParseSuite(const Json& suite) {
    CheckClosedObject(
        suite, "/suite",
        {"id", "secure_channel", "front_door", "carrier", "session"},
        {"id", "secure_channel", "front_door", "carrier", "session"});

    struct RequiredValue {
        const char* key;
        std::string_view value;
    };
    constexpr std::array<RequiredValue, 5> required{{
        {"id", kSuiteId},
        {"secure_channel", kSecureChannelProvider},
        {"front_door", kFrontDoorProvider},
        {"carrier", kCarrierProvider},
        {"session", kSessionComponent},
    }};
    std::array<std::string, required.size()> values;
    for (std::size_t index = 0; index < required.size(); ++index) {
        const std::string pointer = JoinPointer("/suite", required[index].key);
        const auto& parsed =
            ReadString(suite.at(required[index].key), pointer, 64);
        if (parsed != required[index].value) {
            Fail(pointer,
                 "unsupported value; required '" +
                     std::string(required[index].value) + "'");
        }
        values[index] = parsed;
    }
    return Suite(std::move(values[0]), std::move(values[1]),
                 std::move(values[2]), std::move(values[3]),
                 std::move(values[4]));
}

Credentials ParseCredentials(const Json& credentials, Role role) {
    if (role == Role::Client) {
        CheckClosedObject(
            credentials, "/credentials",
            {"composite_key", "access_psk", "admission_key", "server_trust",
             "server_identity", "server_mlkem"},
            {"composite_key", "access_psk", "admission_key", "server_trust",
             "server_identity", "server_mlkem"});
        return ClientCredentials(
            ParseFileReference(credentials, "/credentials", "composite_key"),
            ParseFileReference(credentials, "/credentials", "access_psk"),
            ParseFileReference(credentials, "/credentials", "admission_key"),
            ParseFileReference(credentials, "/credentials", "server_trust"),
            ParseFileReference(credentials, "/credentials", "server_identity"),
            ParseFileReference(credentials, "/credentials", "server_mlkem"));
    }

    CheckClosedObject(
        credentials, "/credentials",
        {"composite_key", "authorized_keys", "admin_keys", "tls_certificate",
         "tls_key", "admission_key", "mlkem_key"},
        {"composite_key", "authorized_keys", "admin_keys", "tls_certificate",
         "tls_key", "admission_key", "mlkem_key"});
    FileReference authorized_keys =
        ParseFileReference(credentials, "/credentials", "authorized_keys");
    FileReference admin_keys =
        ParseFileReference(credentials, "/credentials", "admin_keys");
    // The two key classes are one YUME invariant, not a deployment style. A
    // shared path would let one edit grant a traffic identity the second
    // factor, which is exactly what the split exists to prevent.
    if (authorized_keys.path() == admin_keys.path()) {
        Fail("/credentials/admin_keys",
             "must be a different file from authorized_keys");
    }
    return ServerCredentials(
        ParseFileReference(credentials, "/credentials", "composite_key"),
        std::move(authorized_keys),
        std::move(admin_keys),
        ParseFileReference(credentials, "/credentials", "tls_certificate"),
        ParseFileReference(credentials, "/credentials", "tls_key"),
        ParseFileReference(credentials, "/credentials", "admission_key"),
        ParseFileReference(credentials, "/credentials", "mlkem_key"));
}

std::string ParseProfile(const Json& value, const std::string& pointer) {
    const auto& profile = ReadString(value, pointer, kMaxProfileBytes);
    if (!IsSafeIdentifier(profile, kMaxProfileBytes, true)) {
        Fail(pointer,
             "must be a bounded profile identifier using letters, digits, '.', '_', or '-'");
    }
    return profile;
}

bool IsLoopbackReverseProxyUrl(std::string_view value) {
    constexpr std::string_view prefix = "http://";
    if (value.rfind(prefix, 0) != 0) return false;
    value.remove_prefix(prefix.size());
    if (!value.empty() && value.back() == '/') value.remove_suffix(1);

    std::string_view port_text;
    if (value.rfind("127.0.0.1:", 0) == 0) {
        port_text = value.substr(std::string_view("127.0.0.1:").size());
    } else if (value.rfind("[::1]:", 0) == 0) {
        port_text = value.substr(std::string_view("[::1]:").size());
    } else {
        return false;
    }
    if (port_text.empty() || port_text.size() > 5 ||
        !std::all_of(port_text.begin(), port_text.end(), [](char ch) {
            return ch >= '0' && ch <= '9';
        })) {
        return false;
    }
    unsigned port = 0;
    const auto conversion = std::from_chars(
        port_text.data(), port_text.data() + port_text.size(), port);
    return conversion.ec == std::errc{} &&
           conversion.ptr == port_text.data() + port_text.size() &&
           port >= 1 && port <= 65535;
}

Cover ParseCover(const Json& cover, Role role) {
    if (role == Role::Client) {
        CheckClosedObject(cover, "/cover", {"profile"}, {"profile"});
        return ClientCover(ParseProfile(cover.at("profile"), "/cover/profile"));
    }

    CheckClosedObject(cover, "/cover", {"profile", "root", "reverse_proxy"},
                      {"profile"});
    const bool has_root = cover.contains("root");
    const bool has_proxy = cover.contains("reverse_proxy");
    if (has_root && has_proxy) {
        Fail("/cover/reverse_proxy",
             "cannot be combined with the static cover root");
    }
    if (!has_root && !has_proxy) {
        Fail("/cover", "server cover requires exactly one of root or reverse_proxy");
    }
    std::string profile = ParseProfile(cover.at("profile"), "/cover/profile");
    if (has_root) {
        return StaticCover(
            std::move(profile), ParseFileReference(cover, "/cover", "root"));
    }

    const auto& proxy = cover.at("reverse_proxy");
    CheckClosedObject(proxy, "/cover/reverse_proxy", {"url"}, {"url"});
    const auto& url =
        ReadString(proxy.at("url"), "/cover/reverse_proxy/url", 128);
    if (!IsLoopbackReverseProxyUrl(url)) {
        Fail("/cover/reverse_proxy/url",
             "must be http://127.0.0.1:<port> or http://[::1]:<port>");
    }
    return ReverseProxyCover(std::move(profile), url);
}

ServiceKind ParseServiceKind(const Json& value, const std::string& pointer) {
    const auto& kind = ReadString(value, pointer, 16);
    if (kind == "stream") return ServiceKind::Stream;
    if (kind == "packet") return ServiceKind::Packet;
    Fail(pointer, "must be 'stream' or 'packet'");
}

std::string ParseServiceName(const Json& value, const std::string& pointer) {
    const auto& name = ReadString(
        value, pointer, common::kMaxServiceNameBytes);
    if (!common::valid_service_name(name)) {
        Fail(pointer,
             "must use 1..128 bytes of lowercase ASCII namespace segments; '-' and '_' are allowed inside segments");
    }
    return name;
}

std::vector<Service> ParseServices(const Json& services) {
    if (!services.is_array()) {
        Fail("/services", "must be an array");
    }
    if (services.empty() || services.size() > kMaxServices) {
        Fail("/services",
             "must contain 1.." + std::to_string(kMaxServices) + " services");
    }
    std::vector<Service> parsed;
    parsed.reserve(services.size());
    std::set<std::pair<std::string, ServiceKind>> unique;
    for (std::size_t index = 0; index < services.size(); ++index) {
        const std::string pointer = IndexPointer("/services", index);
        const auto& service = services.at(index);
        CheckClosedObject(service, pointer,
                          {"name", "kind", "max_concurrent_streams"},
                          {"name", "kind", "max_concurrent_streams"});
        const std::string name =
            ParseServiceName(service.at("name"), JoinPointer(pointer, "name"));
        const ServiceKind kind = ParseServiceKind(
            service.at("kind"), JoinPointer(pointer, "kind"));
        if (!unique.emplace(name, kind).second) {
            Fail(JoinPointer(pointer, "name"),
                 "duplicate service name and kind");
        }
        const std::uint32_t max_concurrent_streams = ReadBoundedUnsigned(
            service.at("max_concurrent_streams"),
            JoinPointer(pointer, "max_concurrent_streams"),
            kMinStreams, kMaxStreams);
        parsed.emplace_back(name, kind, max_concurrent_streams);
    }
    return parsed;
}

const Service& RequireService(const std::vector<Service>& services,
                              std::string_view name,
                              ServiceKind required_kind,
                              const std::string& pointer) {
    const auto found = std::find_if(
        services.begin(), services.end(), [&](const Service& service) {
            return service.name() == name &&
                   service.kind() == required_kind;
        });
    const bool name_exists = std::any_of(
        services.begin(), services.end(), [&](const Service& service) {
            return service.name() == name;
        });
    if (!name_exists) {
        Fail(pointer, "adapter references an undeclared service");
    }
    if (found == services.end()) {
        Fail(pointer, required_kind == ServiceKind::Stream
                          ? "adapter requires a stream service"
                          : "adapter requires a packet service");
    }
    return *found;
}

// Absolute, without empty, "." or ".." components or a trailing slash, and
// free of control bytes, so the path names exactly one socket file.
bool IsNormalizedAbsolutePath(std::string_view path) {
    if (path.size() < 2U || path.front() != '/' || path.back() == '/') {
        return false;
    }
    if (std::any_of(path.begin(), path.end(), [](char ch) {
            const auto byte = static_cast<unsigned char>(ch);
            return byte < 0x20U || byte == 0x7fU;
        })) {
        return false;
    }
    std::size_t start = 1U;
    for (;;) {
        const std::size_t end = path.find('/', start);
        const std::string_view component = path.substr(
            start, (end == std::string_view::npos ? path.size() : end) - start);
        if (component.empty() || component == "." || component == "..") {
            return false;
        }
        if (end == std::string_view::npos) return true;
        start = end + 1U;
    }
}

AdapterKind ParseAdapterKind(const Json& value, const std::string& pointer) {
    const auto& kind = ReadString(value, pointer, 24);
    if (kind == "socks5") return AdapterKind::Socks5;
    if (kind == "packet") return AdapterKind::Packet;
    if (kind == "direct_tcp") return AdapterKind::DirectTcp;
    if (kind == "direct_udp") return AdapterKind::DirectUdp;
    if (kind == "forward") return AdapterKind::Forward;
    Fail(pointer,
         "must be 'socks5', 'packet', 'direct_tcp', 'direct_udp', or 'forward'");
}

std::string ParseInterfaceName(const Json& value, const std::string& pointer) {
    const auto& name = ReadString(value, pointer, kMaxInterfaceNameBytes);
    if (!IsSafeIdentifier(name, kMaxInterfaceNameBytes, true)) {
        Fail(pointer,
             "must be a bounded interface name using letters, digits, '.', '_', or '-'");
    }
    return name;
}

DestinationPolicy ParseDestinations(const Json& value,
                                    const std::string& pointer) {
    CheckClosedObject(value, pointer, {"public", "networks"},
                      {"public", "networks"});
    const bool public_addresses =
        ReadBoolean(value.at("public"), JoinPointer(pointer, "public"));
    const std::string networks_pointer = JoinPointer(pointer, "networks");
    const auto& networks = value.at("networks");
    if (!networks.is_array()) {
        Fail(networks_pointer, "must be an array");
    }
    if (networks.size() > kMaxDestinationNetworks) {
        Fail(networks_pointer,
             "must contain at most " + std::to_string(kMaxDestinationNetworks) +
                 " networks");
    }
    std::vector<common::IpNetwork> parsed;
    parsed.reserve(networks.size());
    for (std::size_t index = 0; index < networks.size(); ++index) {
        const std::string item_pointer = IndexPointer(networks_pointer, index);
        const std::string text = ReadString(networks.at(index), item_pointer,
                                            common::kMaxIpNetworkTextBytes);
        const auto network = common::parse_canonical_ip_network(text);
        if (!network) {
            Fail(item_pointer,
                 "must be a canonical IPv4 or IPv6 network with zero host bits");
        }
        if (common::ip_network_never_allowed(*network)) {
            Fail(item_pointer,
                 "can never match a destination: unspecified, multicast and "
                 "reserved space is refused, and IPv4-mapped destinations use "
                 "IPv4 networks");
        }
        if (std::find(parsed.begin(), parsed.end(), *network) != parsed.end()) {
            Fail(item_pointer, "duplicate destination network");
        }
        parsed.push_back(*network);
    }
    if (!public_addresses && parsed.empty()) {
        Fail(pointer, "must permit public addresses or at least one network");
    }
    return DestinationPolicy(public_addresses, std::move(parsed));
}

std::vector<common::IpNetwork> parse_tun_prefixes(const Json& value,
                                                   const std::string& pointer,
                                                   bool required) {
    if (!value.is_array() || value.size() > 64U || (required && value.empty()))
        Fail(pointer, "must be an array of " + std::string(required ? "1" : "0") + " to 64 prefixes");
    std::vector<common::IpNetwork> result;
    result.reserve(value.size());
    for (std::size_t i = 0; i < value.size(); ++i) {
        const auto item = IndexPointer(pointer, i);
        const auto text = ReadString(value.at(i), item, common::kMaxIpNetworkTextBytes);
        const auto prefix = common::parse_canonical_ip_network(text);
        if (!prefix || common::ip_network_never_allowed(*prefix))
            Fail(item, "must be a canonical unicast IPv4 or IPv6 network with zero host bits");
        if (std::find(result.begin(), result.end(), *prefix) != result.end())
            Fail(item, "duplicate prefix");
        result.push_back(*prefix);
    }
    return result;
}

bool tun_contains(const std::vector<common::IpNetwork>& networks,
                  const common::IpInterfaceAddress& address) {
    return std::any_of(networks.begin(), networks.end(), [&](const auto& network) {
        return common::ip_network_contains(network, address.family,
            std::span<const std::uint8_t>(address.address).first(
                common::detail::ip_address_bytes(address.family)));
    });
}

TunNetwork parse_tun_network(const Json& value, const std::string& pointer, std::uint16_t mtu) {
    CheckClosedObject(value, pointer,
        {"addresses", "routes", "local_networks", "peer_networks", "dns"},
        {"addresses", "routes", "local_networks", "peer_networks", "dns"});
    TunNetwork result;
    result.routes = parse_tun_prefixes(value.at("routes"), JoinPointer(pointer, "routes"), false);
    result.local_networks = parse_tun_prefixes(value.at("local_networks"), JoinPointer(pointer, "local_networks"), true);
    result.peer_networks = parse_tun_prefixes(value.at("peer_networks"), JoinPointer(pointer, "peer_networks"), true);
    for (const auto* networks : {&result.routes, &result.local_networks, &result.peer_networks}) {
        if (mtu < 1280U && std::any_of(networks->begin(), networks->end(), [](const auto& prefix) {
                return prefix.family == common::IpFamily::V6;
            })) Fail(pointer, "IPv6 requires an MTU of at least 1280");
    }
    for (std::size_t i = 0; i < result.routes.size(); ++i) {
        for (std::size_t j = 0; j < i; ++j) {
            const auto& a = result.routes[i];
            const auto& b = result.routes[j];
            const auto& outer = a.prefix_length < b.prefix_length ? a : b;
            const auto& inner = a.prefix_length < b.prefix_length ? b : a;
            if (common::ip_network_contains(outer, inner.family,
                    std::span<const std::uint8_t>(inner.address).first(common::detail::ip_address_bytes(inner.family))))
                Fail(IndexPointer(JoinPointer(pointer, "routes"), i), "managed routes must not overlap");
        }
    }
    const auto parse_addresses = [&](const Json& list, const std::string& path, bool dns) {
        if (!list.is_array() || list.size() > 16U || (!dns && list.empty()))
            Fail(path, "must be an array of " + std::string(dns ? "0" : "1") + " to 16 addresses");
        std::vector<common::IpInterfaceAddress> parsed;
        for (std::size_t i = 0; i < list.size(); ++i) {
            const auto item = IndexPointer(path, i);
            const auto text = ReadString(list.at(i), item, common::kMaxIpNetworkTextBytes);
            if (dns && text.find('/') != std::string::npos) Fail(item, "DNS server must be an address without prefix");
            const auto address = common::parse_canonical_ip_interface(dns ?
                text + (text.find(':') == std::string::npos ? "/32" : "/128") : text);
            if (!address) Fail(item, "must be a canonical IPv4 or IPv6 address" + std::string(dns ? "" : " with prefix"));
            const auto bytes = std::span<const std::uint8_t>(address->address).first(common::detail::ip_address_bytes(address->family));
            const auto egress = common::EgressAddress::from_bytes(address->family, bytes);
            if (!egress || egress->family() != address->family ||
                common::classify_egress_address(*egress) == common::EgressAddressClass::NeverAllowed ||
                (address->family == common::IpFamily::V4 && address->address[0] == 127U) ||
                (address->family == common::IpFamily::V6 &&
                 common::ip_network_contains(*common::parse_canonical_ip_network("::1/128"), address->family, bytes)))
                Fail(item, "unspecified, loopback, multicast, mapped and reserved addresses are refused");
            if (address->family == common::IpFamily::V6 && mtu < 1280U)
                Fail(item, "IPv6 requires an MTU of at least 1280");
            if (!tun_contains(dns ? result.peer_networks : result.local_networks, *address))
                Fail(item, dns ? "DNS server must be within peer_networks" : "interface address must be within local_networks");
            if (dns && !tun_contains(result.routes, *address)) Fail(item, "DNS server needs a managed route");
            if (std::any_of(parsed.begin(), parsed.end(), [&](const auto& other) {
                    return other.family == address->family && other.address == address->address;
                })) Fail(item, "duplicate address");
            parsed.push_back(*address);
        }
        return parsed;
    };
    result.addresses = parse_addresses(value.at("addresses"), JoinPointer(pointer, "addresses"), false);
    const auto dns_pointer = JoinPointer(pointer, "dns");
    const auto& dns = value.at("dns");
    CheckClosedObject(dns, dns_pointer, {"servers", "domains"}, {"servers", "domains"});
    result.dns_servers = parse_addresses(dns.at("servers"), JoinPointer(dns_pointer, "servers"), true);
    const auto& domains = dns.at("domains");
    if (!domains.is_array() || domains.size() > 16U)
        Fail(JoinPointer(dns_pointer, "domains"), "must be an array of 0 to 16 routing domains");
    for (std::size_t i = 0; i < domains.size(); ++i) {
        const auto item = IndexPointer(JoinPointer(dns_pointer, "domains"), i);
        auto text = ReadString(domains.at(i), item, kMaxHostBytes);
        if (text != "." && (!IsDnsName(text) || text.back() == '.' ||
            std::any_of(text.begin(), text.end(), [](char ch) { return ch >= 'A' && ch <= 'Z'; })))
            Fail(item, "must be a lowercase DNS routing domain or '.'");
        if (std::find(result.dns_domains.begin(), result.dns_domains.end(), text) != result.dns_domains.end())
            Fail(item, "duplicate routing domain");
        result.dns_domains.push_back(std::move(text));
    }
    if (result.dns_servers.empty() != result.dns_domains.empty())
        Fail(dns_pointer, "DNS servers and routing domains must both be empty or both supplied");
    return result;
}

std::vector<Adapter> ParseAdapters(const Json& adapters,
                                   Role role,
                                   const std::vector<Service>& services) {
    if (!adapters.is_array()) {
        Fail("/adapters", "must be an array");
    }
    if (adapters.size() > kMaxAdapters) {
        Fail("/adapters",
             "must contain at most " + std::to_string(kMaxAdapters) +
                 " adapters");
    }
    std::vector<Adapter> parsed;
    parsed.reserve(adapters.size());
    // SOCKS5 and forward listeners share the local port space.
    std::set<std::pair<std::string, std::uint16_t>> local_listeners;
    std::set<std::string> unix_listeners;
    std::set<std::string> packet_interfaces;
    std::set<std::pair<AdapterKind, std::string>> direct_services;
    for (std::size_t index = 0; index < adapters.size(); ++index) {
        const std::string pointer = IndexPointer("/adapters", index);
        const auto& adapter = adapters.at(index);
        if (!adapter.is_object()) {
            Fail(pointer, "must be an object");
        }
        if (!adapter.contains("kind")) {
            Fail(JoinPointer(pointer, "kind"), "required key is missing");
        }
        const std::string kind_pointer = JoinPointer(pointer, "kind");
        const AdapterKind kind = ParseAdapterKind(adapter.at("kind"), kind_pointer);

        if (kind == AdapterKind::Socks5) {
            CheckClosedObject(adapter, pointer,
                              {"kind", "service", "listen_address",
                               "listen_port", "udp_service"},
                              {"kind", "service", "listen_address",
                               "listen_port"});
            if (role != Role::Client) {
                Fail(kind_pointer, "socks5 adapter is client-only");
            }
            const std::string service_pointer = JoinPointer(pointer, "service");
            const std::string service =
                ParseServiceName(adapter.at("service"), service_pointer);
            RequireService(services, service, ServiceKind::Stream,
                           service_pointer);
            const std::string listen_pointer =
                JoinPointer(pointer, "listen_address");
            const auto& listen =
                ReadString(adapter.at("listen_address"), listen_pointer, 64);
            if (!IsLoopbackAddress(listen)) {
                Fail(listen_pointer,
                     "socks5 listener must be 127.0.0.1 or ::1");
            }
            const std::string port_pointer =
                JoinPointer(pointer, "listen_port");
            const std::uint16_t port =
                ParsePort(adapter.at("listen_port"), port_pointer);
            if (!local_listeners.emplace(listen, port).second) {
                Fail(port_pointer, "duplicate local listen address and port");
            }
            std::optional<std::string> udp_service;
            if (adapter.contains("udp_service")) {
                const std::string udp_pointer =
                    JoinPointer(pointer, "udp_service");
                udp_service =
                    ParseServiceName(adapter.at("udp_service"), udp_pointer);
                RequireService(services, *udp_service, ServiceKind::Packet,
                               udp_pointer);
            }
            parsed.emplace_back(
                Socks5Adapter(service, listen, port, std::move(udp_service)));
            continue;
        }

        if (kind == AdapterKind::Forward) {
            CheckClosedObject(adapter, pointer,
                              {"kind", "service", "listen_address", "listen_port",
                               "listen_path", "destination"},
                              {"kind", "service"});
            if (role != Role::Client) {
                Fail(kind_pointer, "forward adapter is client-only");
            }
            const std::string service_pointer = JoinPointer(pointer, "service");
            const std::string service =
                ParseServiceName(adapter.at("service"), service_pointer);
            RequireService(services, service, ServiceKind::Stream,
                           service_pointer);
            const std::string address_pointer =
                JoinPointer(pointer, "listen_address");
            const std::string port_pointer = JoinPointer(pointer, "listen_port");
            const std::string path_pointer = JoinPointer(pointer, "listen_path");
            ForwardListener listener = UnixListener{};
            if (adapter.contains("listen_path")) {
                if (adapter.contains("listen_address")) {
                    Fail(address_pointer, "must be absent with listen_path");
                }
                if (adapter.contains("listen_port")) {
                    Fail(port_pointer, "must be absent with listen_path");
                }
                const auto& path = ReadString(adapter.at("listen_path"),
                                              path_pointer,
                                              kMaxUnixSocketPathBytes);
                if (!IsNormalizedAbsolutePath(path)) {
                    Fail(path_pointer, "must be a normalized absolute path");
                }
                if (!unix_listeners.insert(path).second) {
                    Fail(path_pointer, "duplicate local listen path");
                }
                listener = UnixListener{path};
            } else {
                if (!adapter.contains("listen_address")) {
                    Fail(address_pointer,
                         "required key is missing without listen_path");
                }
                if (!adapter.contains("listen_port")) {
                    Fail(port_pointer,
                         "required key is missing without listen_path");
                }
                const auto& listen =
                    ReadString(adapter.at("listen_address"), address_pointer, 64);
                if (!IsLoopbackAddress(listen)) {
                    Fail(address_pointer,
                         "forward listener must be 127.0.0.1 or ::1");
                }
                const std::uint16_t port =
                    ParsePort(adapter.at("listen_port"), port_pointer);
                if (!local_listeners.emplace(listen, port).second) {
                    Fail(port_pointer, "duplicate local listen address and port");
                }
                listener = LoopbackListener{listen, port};
            }
            std::optional<ForwardDestination> destination;
            if (adapter.contains("destination")) {
                const std::string destination_pointer =
                    JoinPointer(pointer, "destination");
                const auto& value = adapter.at("destination");
                CheckClosedObject(value, destination_pointer, {"host", "port"},
                                  {"host", "port"});
                const std::string host_pointer =
                    JoinPointer(destination_pointer, "host");
                const auto& host =
                    ReadString(value.at("host"), host_pointer, kMaxHostBytes);
                if (!IsClientHost(host)) {
                    Fail(host_pointer, "must be an IP literal or DNS host name");
                }
                destination = ForwardDestination{
                    host, ParsePort(value.at("port"),
                                    JoinPointer(destination_pointer, "port"))};
            }
            parsed.emplace_back(ForwardAdapter(service, std::move(listener),
                                               std::move(destination)));
            continue;
        }

        if (kind == AdapterKind::Packet) {
            CheckClosedObject(adapter, pointer,
                              {"kind", "service", "interface_name", "mtu", "network"},
                              {"kind", "service", "interface_name", "mtu", "network"});
            const std::string service_pointer = JoinPointer(pointer, "service");
            const std::string service =
                ParseServiceName(adapter.at("service"), service_pointer);
            RequireService(services, service, ServiceKind::Packet,
                           service_pointer);
            const std::string interface_pointer =
                JoinPointer(pointer, "interface_name");
            const std::string interface_name = ParseInterfaceName(
                adapter.at("interface_name"), interface_pointer);
            if (!packet_interfaces.insert(interface_name).second) {
                Fail(interface_pointer, "duplicate packet interface name");
            }
            const auto mtu = static_cast<std::uint16_t>(ReadBoundedUnsigned(
                adapter.at("mtu"), JoinPointer(pointer, "mtu"), 576, 65535));
            parsed.emplace_back(PacketAdapter(service, interface_name, mtu,
                parse_tun_network(adapter.at("network"), JoinPointer(pointer, "network"), mtu)));
            continue;
        }

        CheckClosedObject(adapter, pointer, {"kind", "service", "destinations"},
                          {"kind", "service", "destinations"});
        if (role != Role::Server) {
            Fail(kind_pointer, "direct adapters are server-only");
        }
        const std::string service_pointer = JoinPointer(pointer, "service");
        const std::string service =
            ParseServiceName(adapter.at("service"), service_pointer);
        if (!direct_services.emplace(kind, service).second) {
            Fail(service_pointer, "duplicate direct adapter service and kind");
        }
        const std::string destinations_pointer =
            JoinPointer(pointer, "destinations");
        if (kind == AdapterKind::DirectTcp) {
            RequireService(services, service, ServiceKind::Stream,
                           service_pointer);
            parsed.emplace_back(DirectTcpAdapter(
                service, ParseDestinations(adapter.at("destinations"),
                                           destinations_pointer)));
        } else {
            RequireService(services, service, ServiceKind::Packet,
                           service_pointer);
            parsed.emplace_back(DirectUdpAdapter(
                service, ParseDestinations(adapter.at("destinations"),
                                           destinations_pointer)));
        }
    }
    return parsed;
}

ResourceLimits ParseLimits(const Json& limits) {
    constexpr std::array<std::string_view, 8> keys{{
        "max_frame_bytes",
        "max_streams",
        "max_queued_bytes",
        "max_pending_opens",
        "max_rekey_jobs",
        "max_control_messages",
        "max_packet_bytes",
        "max_packet_batch",
    }};
    CheckClosedObject(
        limits, "/limits",
        {keys[0], keys[1], keys[2], keys[3], keys[4], keys[5], keys[6],
         keys[7], "max_egress_mbps"},
        {keys[0], keys[1], keys[2], keys[3], keys[4], keys[5], keys[6],
         keys[7]});

    const auto read = [&](std::string_view key,
                          std::uint32_t minimum,
                          std::uint32_t maximum) {
        return ReadBoundedUnsigned(limits.at(key), JoinPointer("/limits", key),
                                   minimum, maximum);
    };
    const std::uint32_t max_frame_bytes =
        read(keys[0], kMinFrameBytes, kMaxFrameBytes);
    const std::uint32_t max_streams =
        read(keys[1], kMinStreams, kMaxStreams);
    const std::uint32_t max_queued_bytes =
        read(keys[2], kMinQueuedBytes, kMaxQueuedBytes);
    const std::uint32_t max_pending_opens =
        read(keys[3], kMinPendingOpens, kMaxPendingOpens);
    const std::uint32_t max_rekey_jobs =
        read(keys[4], kMinRekeyJobs, kMaxRekeyJobs);
    const std::uint32_t max_control_messages =
        read(keys[5], kMinControlMessages, kMaxControlMessages);
    const std::uint32_t max_packet_bytes =
        read(keys[6], kMinPacketBytes, kMaxPacketBytes);
    const std::uint32_t max_packet_batch =
        read(keys[7], kMinPacketBatch, kMaxPacketBatch);

    if (max_frame_bytes > max_queued_bytes) {
        Fail("/limits/max_frame_bytes",
             "must not exceed max_queued_bytes");
    }
    if (max_pending_opens > max_streams) {
        Fail("/limits/max_pending_opens", "must not exceed max_streams");
    }
    if (max_packet_bytes > max_frame_bytes) {
        Fail("/limits/max_packet_bytes", "must not exceed max_frame_bytes");
    }
    std::optional<std::uint32_t> max_egress_mbps;
    if (limits.contains("max_egress_mbps")) {
        max_egress_mbps =
            read("max_egress_mbps", kMinEgressMbps, kMaxEgressMbps);
    }
    return ResourceLimits(max_frame_bytes, max_streams, max_queued_bytes,
                          max_pending_opens, max_rekey_jobs,
                          max_control_messages, max_packet_bytes,
                          max_packet_batch, max_egress_mbps);
}

void CheckAdapterLimitCombinations(const std::vector<Adapter>& adapters,
                                   const ResourceLimits& limits) {
    for (std::size_t index = 0; index < adapters.size(); ++index) {
        if (const auto* packet = std::get_if<PacketAdapter>(&adapters[index]);
            packet && packet->mtu() > limits.max_packet_bytes()) {
            Fail(JoinPointer(IndexPointer("/adapters", index), "mtu"),
                 "must not exceed limits.max_packet_bytes");
        }
    }
}

}  // namespace

ValidationError::ValidationError(std::string json_pointer, std::string detail)
    : std::runtime_error(FormatValidationMessage(json_pointer, detail)),
      json_pointer_(std::move(json_pointer)),
      detail_(std::move(detail)) {}

Config Parse(const nlohmann::json& document) {
    CheckClosedObject(
        document, "",
        {"schema", "role", "endpoint", "suite", "credentials", "cover",
         "services", "adapters", "limits"},
        {"schema", "role", "endpoint", "suite", "credentials", "cover",
         "services", "adapters", "limits"});

    const std::uint32_t schema =
        ReadBoundedUnsigned(document.at("schema"), "/schema", kSchema, kSchema);
    if (schema != kSchema) {
        // ReadBoundedUnsigned already enforces this. Keep the invariant local
        // if the supported schema range ever becomes wider.
        Fail("/schema", "unsupported schema");
    }
    const Role role = ParseRole(document.at("role"));
    Endpoint endpoint = ParseEndpoint(document.at("endpoint"), role);
    Suite suite = ParseSuite(document.at("suite"));
    Credentials credentials =
        ParseCredentials(document.at("credentials"), role);
    Cover cover = ParseCover(document.at("cover"), role);
    std::vector<Service> services = ParseServices(document.at("services"));
    std::vector<Adapter> adapters =
        ParseAdapters(document.at("adapters"), role, services);
    ResourceLimits limits = ParseLimits(document.at("limits"));
    CheckAdapterLimitCombinations(adapters, limits);
    if (role == Role::Client && limits.max_egress_mbps()) {
        Fail("/limits/max_egress_mbps", "is server-only");
    }

    return Config(role, std::move(endpoint), std::move(suite),
                  std::move(credentials), std::move(cover),
                  std::move(services), std::move(adapters), std::move(limits));
}

Config ParseJson(std::string_view text) {
    if (text.size() > kMaxDocumentBytes) {
        Fail("", "document exceeds the 1 MiB limit");
    }
    Json document;
    try {
        struct ParseScope {
            std::string pointer;
            bool is_object;
            std::set<std::string> keys;
            std::string pending_key;
            std::size_t next_index = 0;
        };
        std::vector<ParseScope> scopes;
        const Json::parser_callback_t structure_guard =
            [&scopes](int depth, Json::parse_event_t event, Json& parsed) {
                const auto consume_child_pointer = [&scopes]() {
                    if (scopes.empty()) return std::string{};
                    ParseScope& parent = scopes.back();
                    if (parent.is_object) {
                        std::string pointer =
                            JoinPointer(parent.pointer, parent.pending_key);
                        parent.pending_key.clear();
                        return pointer;
                    }
                    return IndexPointer(parent.pointer, parent.next_index++);
                };

                if (event == Json::parse_event_t::object_start ||
                    event == Json::parse_event_t::array_start) {
                    if (depth > static_cast<int>(kMaxNestingDepth)) {
                        Fail("", "document nesting exceeds the configured limit");
                    }
                    scopes.push_back(ParseScope{
                        consume_child_pointer(),
                        event == Json::parse_event_t::object_start,
                        {},
                        {},
                        0,
                    });
                } else if (event == Json::parse_event_t::key) {
                    ParseScope& scope = scopes.back();
                    const auto& key = parsed.get_ref<const std::string&>();
                    if (!scope.keys.insert(key).second) {
                        Fail(JoinPointer(scope.pointer, key),
                             "duplicate object key");
                    }
                    scope.pending_key = key;
                } else if (event == Json::parse_event_t::value &&
                           !scopes.empty()) {
                    ParseScope& parent = scopes.back();
                    if (parent.is_object) {
                        parent.pending_key.clear();
                    } else {
                        ++parent.next_index;
                    }
                } else if (event == Json::parse_event_t::object_end ||
                           event == Json::parse_event_t::array_end) {
                    scopes.pop_back();
                }
                return true;
            };
        document = Json::parse(text.begin(), text.end(), structure_guard,
                               true, false);
    } catch (const ValidationError&) {
        throw;
    } catch (const Json::parse_error& error) {
        Fail("", "invalid JSON syntax at byte " + std::to_string(error.byte));
    } catch (const Json::out_of_range& error) {
        // nlohmann reports a syntactically valid but unrepresentable number
        // as 406 rather than parse_error. Keep untrusted text on the typed
        // rejection path without hiding errors in the schema parser below.
        if (error.id != 406) throw;
        Fail("", "JSON number exceeds the supported range");
    }
    return Parse(document);
}

}  // namespace yume::config::v1
