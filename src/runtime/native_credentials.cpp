/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/native_credentials.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <exception>
#include <initializer_list>
#include <limits>
#include <new>
#include <set>
#include <utility>

#include <nlohmann/json.hpp>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "common/hex.hpp"
#include "common/secure_erase.hpp"
#include "common/service_name.hpp"
#include "fs/secret_file.hpp"
#include "providers/openssl_security_provider.hpp"
#include "providers/tls13_secure_channel.hpp"
#include "runtime/cluster_list.hpp"
#include "runtime/cluster_state.hpp"
#include "providers/composite_keys.hpp"
#include "providers/ytp1_crypto.hpp"
#include "runtime/egress_limiter.hpp"
#include "ytp/security.hpp"

namespace yume::runtime {
namespace {

using Json = nlohmann::json;
using engine::Result;
using engine::Status;
using engine::StatusCode;
constexpr std::size_t kMaxPemBytes = 256U * 1024U;
constexpr std::size_t kMaxStoreBytes = 1024U * 1024U;
constexpr std::size_t kMaxAdminIdentities = 4096U;

namespace keys = providers::keys;
using CredentialError = keys::KeyError;
using keys::require;
using CredentialCrypto = keys::KeyContext;
using CompositePublic = keys::CompositePublic;
using keys::parse_key;
using keys::pem_blocks;
using keys::public_der;
constexpr const char* kMlKem1024 =
    providers::ytp1_crypto::kMlKem1024Algorithm.data();

class SecretBytes final {
public:
    explicit SecretBytes(std::vector<std::uint8_t>&& bytes) noexcept
        : bytes_(std::move(bytes)) {}
    explicit SecretBytes(std::size_t size) : bytes_(size) {}
    SecretBytes(const SecretBytes&) = delete;
    SecretBytes& operator=(const SecretBytes&) = delete;
    SecretBytes(SecretBytes&& other) noexcept
        : bytes_(std::move(other.bytes_)) {}
    SecretBytes& operator=(SecretBytes&& other) noexcept {
        if (this != &other) {
            security::secure_erase(bytes_);
            bytes_ = std::move(other.bytes_);
        }
        return *this;
    }
    ~SecretBytes() { security::secure_erase(bytes_); }
    std::span<const std::byte> bytes() const noexcept {
        return std::as_bytes(std::span(bytes_));
    }
    std::string_view text() const noexcept {
        return {reinterpret_cast<const char*>(bytes_.data()), bytes_.size()};
    }
    unsigned char* data() noexcept { return bytes_.data(); }
    std::size_t size() const noexcept { return bytes_.size(); }

private:
    std::vector<std::uint8_t> bytes_;
};

struct Pkcs8Deleter final {
    void operator()(PKCS8_PRIV_KEY_INFO* value) const noexcept {
        if (!value) return;
        const unsigned char* bytes = nullptr;
        int size = 0;
        if (PKCS8_pkey_get0(nullptr, &bytes, &size, nullptr, value) == 1 &&
            size > 0) {
            OPENSSL_cleanse(const_cast<unsigned char*>(bytes),
                            static_cast<std::size_t>(size));
        }
        PKCS8_PRIV_KEY_INFO_free(value);
    }
};

bool ascii_space(char value) noexcept {
    return value == ' ' || value == '\t' || value == '\r' || value == '\n';
}

std::filesystem::path resolve_reference(const std::filesystem::path& base,
                                        std::string_view text) {
    require(
        !text.empty() && text.size() <= config::v1::kMaxFileReferenceBytes &&
            !ascii_space(text.front()) && !ascii_space(text.back()) &&
            text.front() != '~' && text.find("://") == std::string_view::npos &&
            !text.starts_with("-----BEGIN") && text != ".",
        "credential file reference is invalid");
    require(std::all_of(text.begin(), text.end(),
                        [](unsigned char value) {
                            return value >= 0x20U && value != 0x7fU;
                        }),
            "credential file reference contains a control character");
    require(!(text.size() == 64 &&
              std::all_of(text.begin(), text.end(),
                          [](unsigned char value) {
                              return (value >= '0' && value <= '9') ||
                                     (value >= 'a' && value <= 'f') ||
                                     (value >= 'A' && value <= 'F');
                          })),
            "inline credential material is forbidden");
    std::size_t begin = 0;
    do {
        const auto end = text.find_first_of("/\\", begin);
        require(text.substr(
                    begin, end == std::string_view::npos ? end : end - begin) !=
                    "..",
                "credential file reference contains parent traversal");
        if (end == std::string_view::npos) break;
        begin = end + 1;
    } while (begin <= text.size());
    std::filesystem::path path(text);
    return path.is_absolute() ? path : base / path;
}

SecretBytes read_file(const std::filesystem::path& path, std::size_t maximum) {
    try {
        SecretBytes bytes(security::read_private_file_strict(
            path, maximum, "native credential"));
        require(bytes.size() != 0, "credential file must not be empty");
        return bytes;
    } catch (const std::bad_alloc&) {
        throw;
    } catch (...) {
        // The lower-level loader can mention a local path. Runtime diagnostics
        // identify the failed operation without publishing credential inputs.
        throw CredentialError("credential file failed protected read");
    }
}

SecretBytes read_file(const std::filesystem::path& base,
                      const config::v1::FileReference& reference,
                      std::size_t maximum = kMaxPemBytes) {
    return read_file(resolve_reference(base, reference.path()), maximum);
}

SecretBytes read_psk(const std::filesystem::path& path) {
    auto bytes = read_file(path, 32);
    require(bytes.size() == 32,
            "credential secret must contain exactly 32 raw bytes");
    require(std::any_of(bytes.bytes().begin(), bytes.bytes().end(),
                        [](std::byte value) { return value != std::byte{0}; }),
            "credential secret must not be all zero");
    return bytes;
}

// The username on the first line and the password on the second, each 1 to
// 255 bytes, with at most one final newline and no carriage return or NUL.
common::Socks5Credentials read_socks5_credentials(const std::filesystem::path& base,
                                                  const config::v1::FileReference& reference) {
    const auto bytes = read_file(base, reference, 2U * common::Socks5Credentials::kMaxFieldBytes + 2U);
    std::string_view text = bytes.text();
    require(text.find('\r') == std::string_view::npos &&
                text.find('\0') == std::string_view::npos,
            "SOCKS5 proxy credentials must not contain a carriage return or NUL");
    const auto line_end = text.find('\n');
    require(line_end != std::string_view::npos,
            "SOCKS5 proxy credentials need a username line and a password line");
    std::string_view password = text.substr(line_end + 1U);
    if (!password.empty() && password.back() == '\n') password.remove_suffix(1U);
    require(password.find('\n') == std::string_view::npos,
            "SOCKS5 proxy credentials hold only a username line and a password line");
    auto credentials = common::Socks5Credentials::create(std::string(text.substr(0U, line_end)),
                                                         std::string(password));
    require(credentials.has_value(),
            "SOCKS5 proxy username and password need 1 to 255 bytes each");
    return std::move(*credentials);
}

SecretBytes private_der(EVP_PKEY* key) {
    std::unique_ptr<PKCS8_PRIV_KEY_INFO, Pkcs8Deleter> encoded(
        EVP_PKEY2PKCS8(key));
    const int size =
        encoded ? i2d_PKCS8_PRIV_KEY_INFO(encoded.get(), nullptr) : -1;
    require(size > 0 && static_cast<std::size_t>(size) <=
                            security::kMaxPrivateKeyFileBytes,
            "credential private DER encoding size is invalid");
    SecretBytes result(static_cast<std::size_t>(size));
    unsigned char* cursor = result.data();
    require(i2d_PKCS8_PRIV_KEY_INFO(encoded.get(), &cursor) == size &&
                cursor == result.data() + result.size(),
            "credential private DER encoding failed");
    return result;
}

CompositePublic read_public_identity(const CredentialCrypto& crypto,
                                     const std::filesystem::path& path) {
    auto pem = read_file(path, kMaxPemBytes);
    return keys::composite_public_from_pem(crypto, pem.text());
}

struct CompositePrivate final {
    SecretBytes classical;
    SecretBytes post_quantum;
    // The fingerprint of the matching public identity.
    std::string fingerprint;
    providers::CompositePrivateIdentityView view() const noexcept {
        return {classical.bytes(), post_quantum.bytes()};
    }
};

CompositePrivate read_private_identity(const CredentialCrypto& crypto,
                                       const std::filesystem::path& path) {
    auto pem = read_file(path, kMaxPemBytes);
    auto identity = keys::composite_private_from_pem(crypto, pem.text());
    return {private_der(identity.classical.get()),
            private_der(identity.post_quantum.get()),
            std::move(identity.identity.fingerprint)};
}

const Json& closed_object(const Json& value,
                          std::initializer_list<std::string_view> fields) {
    require(value.is_object() && value.size() == fields.size(),
            "credential store object has missing or unknown fields");
    for (auto field : fields) {
        require(value.contains(field),
                "credential store object is missing a field");
    }
    return value;
}

// Like closed_object, with fields that may be absent.
const Json& closed_object(const Json& value,
                          std::initializer_list<std::string_view> fields,
                          std::initializer_list<std::string_view> optional) {
    require(value.is_object(), "credential store object has missing or unknown fields");
    std::size_t present = 0U;
    for (auto field : fields) {
        require(value.contains(field), "credential store object is missing a field");
        ++present;
    }
    for (auto field : optional) {
        if (value.contains(field)) ++present;
    }
    require(value.size() == present,
            "credential store object has missing or unknown fields");
    return value;
}

const std::string& string_field(const Json& value, std::size_t maximum) {
    require(value.is_string(), "credential store field must be a string");
    const auto& text = value.get_ref<const std::string&>();
    require(!text.empty() && text.size() <= maximum,
            "credential store string size is invalid");
    return text;
}

Json read_store(const std::filesystem::path& path, std::size_t maximum,
                bool empty_allowed) {
    auto bytes = read_file(path, kMaxStoreBytes);
    std::vector<std::set<std::string>> object_keys;
    auto callback = [&object_keys](int depth, Json::parse_event_t event,
                                   Json& value) {
        require(depth >= 0 && depth <= 16,
                "credential store nesting is too deep");
        if (event == Json::parse_event_t::object_start)
            object_keys.emplace_back();
        if (event == Json::parse_event_t::key) {
            require(
                !object_keys.empty() &&
                    object_keys.back().insert(value.get<std::string>()).second,
                "credential store contains a duplicate object key");
        }
        if (event == Json::parse_event_t::object_end) object_keys.pop_back();
        return true;
    };
    Json document;
    try {
        document = Json::parse(bytes.text(), callback);
    } catch (const Json::exception&) {
        throw CredentialError("credential store JSON is invalid");
    }
    closed_object(document, {"schema", "keys"});
    const auto& schema = document.at("schema");
    require(schema.is_number_integer() && schema == 1,
            "credential store schema must be integer 1");
    const auto& keys = document.at("keys");
    require(keys.is_array() && keys.size() <= maximum &&
                (empty_allowed || !keys.empty()),
            "credential store key count is invalid");
    return document;
}

void validate_label(const std::string& label) {
    const auto alnum = [](unsigned char byte) {
        return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
               (byte >= '0' && byte <= '9');
    };
    require(alnum(label.front()) && alnum(label.back()) &&
                std::all_of(label.begin(), label.end(),
                            [alnum](unsigned char byte) {
                                return alnum(byte) || byte == '.' ||
                                       byte == '_' || byte == '-';
                            }),
            "credential store identity name is invalid");
}

CompositePublic store_identity(const CredentialCrypto& crypto,
                               const Json& value,
                               const std::filesystem::path& directory) {
    closed_object(value, {"file", "sha256"});
    const auto& expected = string_field(value.at("sha256"), 64);
    require(expected.size() == 64U && encoding::is_lower_hex(expected),
            "credential identity fingerprint must be lowercase SHA-256");
    auto identity = read_public_identity(
        crypto,
        resolve_reference(directory,
                          string_field(value.at("file"),
                                       config::v1::kMaxFileReferenceBytes)));
    require(
        CRYPTO_memcmp(expected.data(), identity.fingerprint.data(), 64) == 0,
        "credential identity fingerprint does not match its keys");
    return identity;
}

engine::ServiceKind service_kind(config::v1::ServiceKind kind) noexcept {
    return kind == config::v1::ServiceKind::Stream
               ? engine::ServiceKind::ByteStream
               : engine::ServiceKind::PacketChannel;
}

std::vector<NativeAuthorizationPolicy::Grant> read_capabilities(
    const config::v1::Config& config, const Json& value,
    const std::string& fingerprint) {
    require(value.is_array() && !value.empty() &&
                value.size() <= config::v1::kMaxServices,
            "credential capability count is invalid");
    std::vector<NativeAuthorizationPolicy::Grant> grants;
    for (const auto& capability : value) {
        closed_object(capability, {"service", "kind"});
        const auto& name = string_field(capability.at("service"), 128);
        const auto& kind = string_field(capability.at("kind"), 16);
        require(kind == "stream" || kind == "packet",
                "credential capability kind is invalid");
        const auto expected_kind = kind == "stream"
                                       ? config::v1::ServiceKind::Stream
                                       : config::v1::ServiceKind::Packet;
        // yume.circuit is the daemon's own packet service, offered only by a
        // cluster member. Its grant also lets the client fetch the routes
        // view from yume.routes.
        const bool circuit = name == common::kCircuitServiceName;
        require(circuit
                    ? config.cluster().has_value() &&
                          expected_kind == config::v1::ServiceKind::Packet
                    : std::any_of(config.services().begin(),
                                  config.services().end(),
                                  [&](const auto& service) {
                                      return service.name() == name &&
                                             service.kind() == expected_kind;
                                  }),
                "credential capability is not a configured service");
        const auto native_kind = service_kind(expected_kind);
        require(std::none_of(grants.begin(), grants.end(),
                             [&](const auto& grant) {
                                 return grant.service_name == name &&
                                        grant.service_kind == native_kind;
                             }),
                "credential store contains a duplicate capability");
        grants.push_back({fingerprint, name, native_kind});
        if (circuit) {
            grants.push_back({fingerprint,
                              std::string(common::kRoutesServiceName),
                              engine::ServiceKind::ByteStream});
        }
    }
    return grants;
}

struct AuthorizedIdentity final {
    CompositePublic identity;
    SecretBytes access_psk;
};

bool same_secret(std::span<const std::byte> left,
                 std::span<const std::byte> right) noexcept {
    return left.size() == right.size() &&
           CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0;
}

// Verifies the operator-signed cluster list and this node's peer store, and
// builds each outbound link's providers. A peer's inbound identity and PSK go
// to the server factory through inbound. Every secret must differ from every
// other: the link PSKs in both directions, every admission key and every
// client access PSK. A node identity is never also a client or admin.
NativeClusterCredentials load_cluster(
    const config::v1::ClusterSettings& refs, const std::filesystem::path& base,
    const CredentialCrypto& crypto, const CompositePrivate& local,
    std::span<const std::byte> own_admission,
    const std::vector<AuthorizedIdentity>& clients,
    const std::set<std::string>& reserved,
    std::vector<AuthorizedIdentity>& inbound) {
    auto operator_key = read_file(base, refs.operator_key);
    auto list_bytes = read_file(base, refs.list, cluster::kMaxListBytes);
    auto signature =
        read_file(base, refs.signature, ytp1::kCompositeSignatureSize);
    auto verified = cluster::verify_list(list_bytes.bytes(), signature.bytes(),
                                         operator_key.text(),
                                         std::chrono::system_clock::now());
    if (!verified.ok()) throw verified.status();
    const auto& list = verified.value();
    const auto* self = list.find(local.fingerprint);
    require(self != nullptr, "the cluster list does not name this node");
    NativeClusterCredentials result;
    result.cluster = list.cluster;
    result.serial = list.serial;
    result.not_after = list.not_after;
    result.self_name = self->name;
    // A list older than one this node has loaded before is refused, across
    // restarts too.
    result.state = resolve_reference(base, refs.state.path());
    auto saved = cluster::read_state(result.state);
    if (!saved.ok()) throw saved.status();
    if (const auto& previous = saved.value()) {
        require(previous->cluster == list.cluster,
                "the cluster state file names another cluster; remove it to "
                "join this one",
                StatusCode::FailedPrecondition);
        require(list.serial >= previous->serial,
                "the cluster list is older than one this node has loaded",
                StatusCode::FailedPrecondition);
        result.saved_serial = previous->serial;
    }
    // The routes view goes to clients as it was signed, so it is checked
    // against the list here, where the list is known.
    auto routes_bytes = read_file(base, refs.routes, cluster::kMaxListBytes);
    auto routes_signature =
        read_file(base, refs.routes_signature, ytp1::kCompositeSignatureSize);
    auto routes = cluster::verify_routes(
        routes_bytes.bytes(), routes_signature.bytes(), operator_key.text(),
        std::chrono::system_clock::now());
    if (!routes.ok()) throw routes.status();
    if (auto match = cluster::check_routes(list, routes.value()); !match.ok())
        throw match;
    result.exit = routes.value().find(local.fingerprint)->exit;
    require(result.exit == refs.exit_service.has_value(),
            result.exit ? "the routes view marks this node as an exit but its "
                          "cluster section has no exit"
                        : "this node's cluster section has an exit but the "
                          "routes view does not mark it as one",
            StatusCode::FailedPrecondition);
    result.routes.assign(routes_bytes.bytes().begin(),
                         routes_bytes.bytes().end());
    result.routes_signature.assign(routes_signature.bytes().begin(),
                                   routes_signature.bytes().end());

    const auto store_path = resolve_reference(base, refs.peers.path());
    auto store = read_store(store_path, cluster::kMaxNodes - 1U, true);
    std::vector<SecretBytes> secrets;
    std::vector<SecretBytes> admissions;
    std::set<std::string> peers;
    const auto distinct = [&](const SecretBytes& secret) {
        require(!same_secret(secret.bytes(), own_admission),
                "a cluster link PSK equals an admission key");
        for (const auto& other : admissions) {
            require(!same_secret(secret.bytes(), other.bytes()),
                    "a cluster link PSK equals an admission key");
        }
        for (const auto& other : secrets) {
            require(!same_secret(secret.bytes(), other.bytes()),
                    "a cluster link PSK is used twice");
        }
        for (const auto& client : clients) {
            require(!same_secret(secret.bytes(), client.access_psk.bytes()),
                    "a cluster link PSK equals a client access PSK");
        }
    };
    const auto peer_file = [&](const Json& entry, const char* key) {
        const auto& reference = closed_object(entry.at(key), {"file"});
        return read_psk(resolve_reference(
            store_path.parent_path(),
            string_field(reference.at("file"),
                         config::v1::kMaxFileReferenceBytes)));
    };
    for (const auto& entry : store.at("keys")) {
        closed_object(entry, {"identity", "outbound_psk", "inbound_psk",
                              "admission_key"});
        const auto& identity = string_field(entry.at("identity"), 64);
        const auto* node = list.find(identity);
        require(node != nullptr, "a cluster peer is not in the cluster list");
        require(identity != local.fingerprint,
                "a node cannot be its own cluster peer");
        require(peers.insert(identity).second,
                "the cluster peer store repeats a peer");
        require(!reserved.contains(identity),
                "a cluster peer is also a client or admin identity");
        auto admission = peer_file(entry, "admission_key");
        for (const auto& secret : secrets) {
            require(!same_secret(admission.bytes(), secret.bytes()),
                    "a cluster link PSK equals an admission key");
        }
        admissions.push_back(std::move(admission));
        auto outbound = peer_file(entry, "outbound_psk");
        distinct(outbound);
        secrets.push_back(std::move(outbound));
        auto incoming = peer_file(entry, "inbound_psk");
        distinct(incoming);
        secrets.push_back(std::move(incoming));
        const auto& outbound_psk = secrets[secrets.size() - 2U];

        auto factory = providers::OpenSslSecurityProviderFactory::create_client(
            {local.view(), node->identity.view(), node->mlkem_key,
             outbound_psk.bytes(), node->identity.fingerprint});
        require(factory.ok(),
                "cluster link security credential validation failed",
                factory.status().code());
        auto tls = providers::Tls13SecureChannelProvider::create_client(
            {node->host,
             std::as_bytes(std::span(node->tls_trust)),
             {},
             {},
             {}});
        require(tls.ok(), "cluster link TLS credential validation failed",
                tls.status().code());
        const auto& dial = node->address.empty() ? node->host : node->address;
        const auto text = [](std::string_view value) {
            return std::as_bytes(std::span(value));
        };
        const std::array<std::byte, 2> port{
            static_cast<std::byte>(node->port >> 8U),
            static_cast<std::byte>(node->port & 0xffU)};
        const auto material = crypto.digest(
            {text(local.fingerprint), text(node->name), text(identity),
             text(node->host), text(dial), port, node->identity.classical,
             node->identity.post_quantum, node->mlkem_key,
             text(node->tls_trust), admissions.back().bytes(),
             outbound_psk.bytes()});
        result.links.push_back(NativeLinkCredentials{
            node->name, identity, node->host, dial, node->port,
            std::move(factory).take_value(), std::move(tls).take_value(),
            NativeAdmissionKey(std::span<const std::byte, 32>(
                admissions.back().bytes().data(), 32)),
            material});
        result.inbound.emplace_back(identity, node->name);
        inbound.push_back(
            {node->identity,
             SecretBytes(std::vector<std::uint8_t>(
                 secrets.back().data(),
                 secrets.back().data() + secrets.back().size()))});
    }
    return result;
}

LoadedNativeCredentials load_server(const config::v1::Config& config,
                                    const std::filesystem::path& base,
                                    const CredentialCrypto& crypto) {
    const auto& refs =
        std::get<config::v1::ServerCredentials>(config.credentials());
    auto admission =
        read_psk(resolve_reference(base, refs.admission_key().path()));
    auto local = read_private_identity(
        crypto, resolve_reference(base, refs.composite_key().path()));
    auto kem_pem = read_file(base, refs.mlkem_key());
    auto kem_blocks = pem_blocks(kem_pem.text(), true, 1);
    auto kem_key = parse_key(crypto, kem_blocks[0], true, kMlKem1024);
    auto kem = private_der(kem_key.get());

    const auto store_path =
        resolve_reference(base, refs.authorized_keys().path());
    auto store =
        read_store(store_path, providers::kMaxAuthorizedIdentities, false);
    std::set<std::string> labels;
    std::set<std::string> identities;
    std::vector<AuthorizedIdentity> authorized;
    authorized.reserve(store.at("keys").size());
    std::vector<NativeAuthorizationPolicy::Grant> grants;
    std::vector<NativeAuthorizationPolicy::SessionLimit> session_limits;
    std::vector<NativeAuthorizationPolicy::EgressWeight> egress_weights;
    for (const auto& entry : store.at("keys")) {
        closed_object(entry, {"name", "identity", "access_psk", "capabilities"},
                      {"max_sessions", "weight"});
        const auto& label = string_field(entry.at("name"), 63);
        validate_label(label);
        require(labels.insert(label).second,
                "credential store contains a duplicate identity name");
        auto identity = store_identity(crypto, entry.at("identity"),
                                       store_path.parent_path());
        require(identities.insert(identity.fingerprint).second,
                "credential store contains a duplicate identity");
        const auto& psk_ref = closed_object(entry.at("access_psk"), {"file"});
        auto psk = read_psk(resolve_reference(
            store_path.parent_path(),
            string_field(psk_ref.at("file"),
                         config::v1::kMaxFileReferenceBytes)));
        require(CRYPTO_memcmp(psk.data(), admission.data(), 32) != 0,
                "access PSK must differ from admission key");
        require(std::none_of(authorized.begin(), authorized.end(),
                             [&](const auto& other) {
                                 return CRYPTO_memcmp(
                                            other.access_psk.bytes().data(),
                                            psk.data(), 32) == 0;
                             }),
                "access PSK must not be reused across identities");
        auto allowed = read_capabilities(config, entry.at("capabilities"),
                                         identity.fingerprint);
        grants.insert(grants.end(), std::make_move_iterator(allowed.begin()),
                      std::make_move_iterator(allowed.end()));
        if (const auto limit = entry.find("max_sessions"); limit != entry.end()) {
            require(limit->is_number_unsigned() &&
                        limit->get<std::uint64_t>() >= 1U &&
                        limit->get<std::uint64_t>() <= kMaxSessionsPerIdentity,
                    "credential max_sessions must be an integer from 1 to 1024");
            session_limits.push_back(
                {identity.fingerprint,
                 static_cast<std::size_t>(limit->get<std::uint64_t>())});
        }
        if (const auto weight = entry.find("weight"); weight != entry.end()) {
            require(weight->is_number() && std::isfinite(weight->get<double>()) &&
                        weight->get<double>() >= EgressLimiter::kMinWeight &&
                        weight->get<double>() <= EgressLimiter::kMaxWeight,
                    "credential weight must be a number from 0.1 to 100");
            egress_weights.push_back({identity.fingerprint, weight->get<double>()});
        }
        authorized.push_back({std::move(identity), std::move(psk)});
    }

    const auto admin_path = resolve_reference(base, refs.admin_keys().path());
    auto admins = read_store(admin_path, kMaxAdminIdentities, true);
    labels.clear();
    std::set<std::string> admin_identities;
    for (const auto& entry : admins.at("keys")) {
        closed_object(entry, {"name", "identity"});
        const auto& label = string_field(entry.at("name"), 63);
        validate_label(label);
        require(labels.insert(label).second,
                "admin store contains a duplicate identity name");
        auto identity = store_identity(crypto, entry.at("identity"),
                                       admin_path.parent_path());
        require(!identities.contains(identity.fingerprint),
                "admin identity must not also authorize ordinary traffic");
        require(admin_identities.insert(identity.fingerprint).second,
                "admin store contains a duplicate identity");
    }

    // Cluster peers authenticate like clients, with their own inbound PSKs,
    // hold at most kMaxPeerSessions sessions and are granted no service.
    std::optional<NativeClusterCredentials> cluster;
    std::vector<AuthorizedIdentity> peers;
    NativeAuthorizationPolicy::Peers recognized_peers;
    if (config.cluster()) {
        std::set<std::string> reserved = identities;
        reserved.insert(admin_identities.begin(), admin_identities.end());
        cluster = load_cluster(*config.cluster(), base, crypto, local,
                               admission.bytes(), authorized, reserved, peers);
        require(authorized.size() + peers.size() <=
                    providers::kMaxAuthorizedIdentities,
                "clients and cluster peers exceed the identity limit");
        recognized_peers.not_after = cluster->not_after;
        for (const auto& peer : peers) {
            session_limits.push_back(
                {peer.identity.fingerprint, kMaxPeerSessions});
            recognized_peers.identities.push_back(peer.identity.fingerprint);
        }
    }

    std::vector<providers::AuthorizedIdentityView> views;
    views.reserve(authorized.size() + peers.size());
    for (const auto* list : {&authorized, &peers}) {
        for (const auto& identity : *list) {
            views.push_back({identity.identity.view(),
                             identity.access_psk.bytes(),
                             identity.identity.fingerprint});
        }
    }
    auto factory = providers::OpenSslSecurityProviderFactory::create_server(
        {local.view(), kem.bytes(), views});
    require(factory.ok(),
            "native session security credential validation failed",
            factory.status().code());
    auto certificate = read_file(base, refs.tls_certificate());
    auto tls_key = read_file(base, refs.tls_key());
    // Prevent a password callback from reaching a terminal inside the TLS
    // provider. Setup kits use one unencrypted PKCS#8 key.
    (void)pem_blocks(tls_key.text(), true, 1);
    auto tls = providers::Tls13SecureChannelProvider::create_server(
        {certificate.bytes(), tls_key.bytes(), {}, {}});
    require(tls.ok(), "native TLS credential validation failed",
            tls.status().code());
    return {std::move(factory).take_value(),
            std::move(tls).take_value(),
            std::make_shared<const NativeAuthorizationPolicy>(
                engine::EndpointRole::Client, std::move(grants),
                std::move(session_limits), std::move(egress_weights),
                std::move(recognized_peers)),
            NativeAdmissionKey(
                std::span<const std::byte, 32>(admission.bytes().data(), 32)),
            std::nullopt,
            std::move(cluster),
            std::nullopt};
}

// The kit's copy of the view raises the floor when it verifies. An expired
// copy is only old, so it counts for nothing, but any other failure means a
// damaged kit. The state file must name the same cluster.
NativeCircuitCredentials load_circuits(const config::v1::CircuitSettings& refs,
                                       const std::filesystem::path& base,
                                       const CredentialCrypto& crypto,
                                       const std::string& entry) {
    NativeCircuitCredentials result;
    auto key = read_file(base, refs.operator_key);
    result.operator_key_pem.assign(key.text());
    result.cluster =
        keys::composite_public_from_pem(crypto, key.text()).fingerprint;
    result.entry = entry;
    auto view = read_file(base, refs.routes, cluster::kMaxListBytes);
    auto signature =
        read_file(base, refs.routes_signature, ytp1::kCompositeSignatureSize);
    auto verified =
        cluster::verify_routes(view.bytes(), signature.bytes(), key.text(),
                               std::chrono::system_clock::now());
    if (verified.ok()) {
        require(verified.value().find(entry) != nullptr,
                "the kit's routes view does not name its server",
                StatusCode::FailedPrecondition);
        result.floor = verified.value().serial;
    } else if (verified.status().code() != StatusCode::FailedPrecondition) {
        throw verified.status();
    }
    result.state = resolve_reference(base, refs.state.path());
    auto saved = cluster::read_state(result.state);
    if (!saved.ok()) throw saved.status();
    if (const auto& previous = saved.value()) {
        require(previous->cluster == result.cluster,
                "the circuits state file names another cluster; remove it to "
                "use this one",
                StatusCode::FailedPrecondition);
        result.saved = previous->serial;
        result.floor = std::max(result.floor, previous->serial);
    }
    return result;
}

LoadedNativeCredentials load_client(const config::v1::Config& config,
                                    const std::filesystem::path& base,
                                    std::string_view tls_server_name,
                                    const CredentialCrypto& crypto) {
    require(!tls_server_name.empty(), "client TLS server name is required");
    const auto& refs =
        std::get<config::v1::ClientCredentials>(config.credentials());
    auto admission =
        read_psk(resolve_reference(base, refs.admission_key().path()));
    auto psk = read_psk(resolve_reference(base, refs.access_psk().path()));
    require(CRYPTO_memcmp(psk.data(), admission.data(), 32) != 0,
            "access PSK must differ from admission key");
    auto local = read_private_identity(
        crypto, resolve_reference(base, refs.composite_key().path()));
    auto remote = read_public_identity(
        crypto, resolve_reference(base, refs.server_identity().path()));
    auto kem_pem = read_file(base, refs.server_mlkem());
    auto kem_blocks = pem_blocks(kem_pem.text(), false, 1);
    auto kem_key = parse_key(crypto, kem_blocks[0], false, kMlKem1024);
    auto kem = public_der(kem_key.get());
    auto factory = providers::OpenSslSecurityProviderFactory::create_client(
        {local.view(), remote.view(), kem, psk.bytes(), remote.fingerprint});
    require(factory.ok(),
            "native session security credential validation failed",
            factory.status().code());
    auto trust = read_file(base, refs.server_trust());
    auto tls = providers::Tls13SecureChannelProvider::create_client(
        {tls_server_name, trust.bytes(), {}, {}, {}});
    require(tls.ok(), "native TLS credential validation failed",
            tls.status().code());
    std::vector<NativeAuthorizationPolicy::Grant> grants;
    grants.reserve(config.services().size());
    for (const auto& service : config.services()) {
        grants.push_back(
            {remote.fingerprint, service.name(), service_kind(service.kind())});
    }
    std::optional<common::Socks5Credentials> socks5;
    const auto& proxy =
        std::get<config::v1::ClientEndpoint>(config.endpoint()).socks5_proxy();
    if (proxy && proxy->credentials()) {
        socks5.emplace(read_socks5_credentials(base, *proxy->credentials()));
    }
    std::optional<NativeCircuitCredentials> circuits;
    if (const auto& settings = config.circuits()) {
        circuits.emplace(
            load_circuits(*settings, base, crypto, remote.fingerprint));
    }
    return {std::move(factory).take_value(),
            std::move(tls).take_value(),
            std::make_shared<const NativeAuthorizationPolicy>(
                engine::EndpointRole::Server, std::move(grants)),
            NativeAdmissionKey(
                std::span<const std::byte, 32>(admission.bytes().data(), 32)),
            std::move(socks5),
            std::nullopt,
            std::move(circuits)};
}

}  // namespace

NativeAdmissionKey::NativeAdmissionKey(
    std::span<const std::byte, 32> bytes) noexcept {
    std::copy(bytes.begin(), bytes.end(), bytes_.begin());
}

NativeAdmissionKey::NativeAdmissionKey(NativeAdmissionKey&& other) noexcept
    : bytes_(other.bytes_) {
    OPENSSL_cleanse(other.bytes_.data(), other.bytes_.size());
}

NativeAdmissionKey& NativeAdmissionKey::operator=(
    NativeAdmissionKey&& other) noexcept {
    if (this != &other) {
        OPENSSL_cleanse(bytes_.data(), bytes_.size());
        bytes_ = other.bytes_;
        OPENSSL_cleanse(other.bytes_.data(), other.bytes_.size());
    }
    return *this;
}

NativeAdmissionKey::~NativeAdmissionKey() {
    OPENSSL_cleanse(bytes_.data(), bytes_.size());
}

NativeAuthorizationPolicy::NativeAuthorizationPolicy(
    engine::EndpointRole peer_role, std::vector<Grant> grants,
    std::vector<SessionLimit> session_limits,
    std::vector<EgressWeight> egress_weights, Peers peers) noexcept
    : peer_role_(peer_role),
      grants_(std::move(grants)),
      session_limits_(std::move(session_limits)),
      egress_weights_(std::move(egress_weights)),
      peers_(std::move(peers)) {}

bool NativeAuthorizationPolicy::recognizes(
    std::string_view peer_identity) const noexcept {
    const auto matches = [&](const auto& identity) {
        return identity == peer_identity;
    };
    if (std::any_of(grants_.begin(), grants_.end(), [&](const auto& grant) {
            return matches(grant.peer_identity);
        }))
        return true;
    return is_peer(peer_identity);
}

std::size_t NativeAuthorizationPolicy::max_sessions(
    std::string_view peer_identity) const noexcept {
    for (const auto& limit : session_limits_) {
        if (limit.peer_identity == peer_identity) return limit.max_sessions;
    }
    return 0U;
}

double NativeAuthorizationPolicy::egress_weight(
    std::string_view peer_identity) const noexcept {
    for (const auto& weight : egress_weights_) {
        if (weight.peer_identity == peer_identity) return weight.weight;
    }
    return EgressLimiter::kDefaultWeight;
}

Status NativeAuthorizationPolicy::authorize(
    const engine::StreamOpenContext& context) const noexcept {
    if (context.peer_evidence().peer_role() != peer_role_)
        return Status(StatusCode::FailedPrecondition);
    const auto& identity = context.peer_evidence().identity();
    if (std::any_of(grants_.begin(), grants_.end(), [&](const auto& grant) {
            return grant.peer_identity == identity &&
                   grant.service_name == context.service_name() &&
                   grant.service_kind == context.service_kind();
        })) {
        return Status::success();
    }
    // A cluster peer extends circuits over its link and opens nothing else.
    if (context.service_name() == common::kCircuitServiceName &&
        context.service_kind() == engine::ServiceKind::PacketChannel &&
        is_peer(identity)) {
        return Status::success();
    }
    return Status(StatusCode::FailedPrecondition);
}

bool NativeAuthorizationPolicy::is_peer(
    std::string_view peer_identity) const noexcept {
    return std::any_of(peers_.identities.begin(), peers_.identities.end(),
                       [&](const auto& identity) {
                           return identity == peer_identity;
                       }) &&
           std::chrono::system_clock::now() < peers_.not_after;
}

Result<LoadedNativeCredentials> load_native_credentials(
    const config::v1::Config& config,
    const std::filesystem::path& config_base_directory,
    std::string_view tls_server_name) noexcept {
    try {
        CredentialCrypto crypto;
        return Result<LoadedNativeCredentials>(
            config.role() == config::v1::Role::Server
                ? load_server(config, config_base_directory, crypto)
                : load_client(config, config_base_directory, tls_server_name,
                              crypto));
    } catch (const std::bad_alloc&) {
        return Result<LoadedNativeCredentials>(
            Status(StatusCode::ResourceExhausted));
    } catch (const CredentialError& error) {
        try {
            return Result<LoadedNativeCredentials>(
                Status(error.code(), error.what()));
        } catch (...) {
            return Result<LoadedNativeCredentials>(
                Status(StatusCode::ResourceExhausted));
        }
    } catch (const Status& status) {
        return Result<LoadedNativeCredentials>(status);
    } catch (...) {
        return Result<LoadedNativeCredentials>(Status(StatusCode::Internal));
    }
}

Result<keys::CompositePrivate> load_signing_identity(
    const config::v1::Config& config,
    const std::filesystem::path& config_base_directory,
    const keys::KeyContext& keys) noexcept {
    using Loaded = Result<keys::CompositePrivate>;
    try {
        const auto* refs =
            std::get_if<config::v1::ServerCredentials>(&config.credentials());
        if (!refs) return Loaded(Status(StatusCode::InvalidArgument));
        auto pem = read_file(config_base_directory, refs->composite_key());
        return Loaded(keys::composite_private_from_pem(keys, pem.text()));
    } catch (const std::bad_alloc&) {
        return Loaded(Status(StatusCode::ResourceExhausted));
    } catch (const CredentialError& error) {
        return Loaded(Status::diagnostic(error.code(), error.what()));
    } catch (...) {
        return Loaded(Status::diagnostic(StatusCode::InvalidArgument,
                                         "server composite key is malformed"));
    }
}

}  // namespace yume::runtime
