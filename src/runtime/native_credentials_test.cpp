/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/native_credentials.hpp"

#include <algorithm>
#include <array>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/x509.h>

#include "providers/ytp1_security_provider.hpp"
#include "test_support/tls_identity.hpp"
#include "ytp/protocol.hpp"
#include "ytp/security.hpp"

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

using Json = nlohmann::json;
using namespace yume::engine;
using namespace yume::runtime;
using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;

void check(bool condition, std::string_view description) {
    if (!condition) throw std::runtime_error(std::string(description));
}

template <typename T>
T take(Result<T> result) {
    check(result.ok(), result.status().message().empty()
                           ? "unexpected failed result"
                           : result.status().message());
    return std::move(result).take_value();
}

PkeyPtr generate_key(const char* algorithm) {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
        EVP_PKEY_CTX_new_from_name(nullptr, algorithm, "provider=default"),
        EVP_PKEY_CTX_free);
    check(context && EVP_PKEY_keygen_init(context.get()) == 1,
          "test key generation initialization failed");
    EVP_PKEY* key = nullptr;
    const int generated = EVP_PKEY_generate(context.get(), &key);
    PkeyPtr owned(key, EVP_PKEY_free);
    check(generated == 1 && owned, "test key generation failed");
    return owned;
}

std::string pem(EVP_PKEY* key, bool private_key) {
    BioPtr output(BIO_new(BIO_s_mem()), BIO_free);
    check(
        output && (private_key
                       ? PEM_write_bio_PrivateKey(output.get(), key, nullptr,
                                                  nullptr, 0, nullptr, nullptr)
                       : PEM_write_bio_PUBKEY(output.get(), key)) == 1,
        "test PEM encoding failed");
    char* data = nullptr;
    const auto size = BIO_get_mem_data(output.get(), &data);
    check(size > 0 && data, "test PEM bytes missing");
    return {data, static_cast<std::size_t>(size)};
}

std::vector<unsigned char> public_der(EVP_PKEY* key) {
    const int size = i2d_PUBKEY(key, nullptr);
    check(size > 0, "test DER size failed");
    std::vector<unsigned char> result(static_cast<std::size_t>(size));
    auto* data = result.data();
    check(i2d_PUBKEY(key, &data) == size, "test DER encoding failed");
    return result;
}

// Independent fixture writer uses the same byte grammar as yume_setup_ytp1.py.
std::string fingerprint(EVP_PKEY* classical, EVP_PKEY* pq) {
    std::vector<unsigned char> bytes;
    constexpr std::string_view kDomain = "yume/ytp/1/composite-identity/v1";
    bytes.insert(bytes.end(), kDomain.begin(), kDomain.end());
    for (auto* key : {classical, pq}) {
        const auto der = public_der(key);
        const auto size = static_cast<std::uint32_t>(der.size());
        for (unsigned int shift : {24U, 16U, 8U, 0U}) {
            bytes.push_back(static_cast<unsigned char>(size >> shift));
        }
        bytes.insert(bytes.end(), der.begin(), der.end());
    }
    std::array<unsigned char, 32> digest{};
    std::size_t digest_size = digest.size();
    check(EVP_Q_digest(nullptr, "SHA256", "provider=default", bytes.data(),
                       bytes.size(), digest.data(), &digest_size) == 1 &&
              digest_size == digest.size(),
          "test identity fingerprint failed");
    constexpr char kHex[] = "0123456789abcdef";
    std::string result;
    for (auto byte : digest) {
        result.push_back(kHex[byte >> 4U]);
        result.push_back(kHex[byte & 15U]);
    }
    return result;
}

struct Identity final {
    PkeyPtr classical = generate_key("ED25519");
    PkeyPtr pq = generate_key("ML-DSA-87");
    std::string private_pem = pem(classical.get(), true) + pem(pq.get(), true);
    std::string public_pem = pem(classical.get(), false) + pem(pq.get(), false);
    std::string id = fingerprint(classical.get(), pq.get());
};

class Directory final {
public:
    Directory() {
#if !defined(_WIN32)
        std::array<char, 44> candidate{};
        constexpr std::string_view kTemplate =
            "/tmp/yume-native-credentials.XXXXXX";
        std::copy(kTemplate.begin(), kTemplate.end(), candidate.begin());
        const char* created = ::mkdtemp(candidate.data());
        check(created != nullptr, "test private directory creation failed");
        path_ = created;
#else
        throw std::runtime_error("protected credential tests require POSIX");
#endif
    }
    ~Directory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }
    const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
};

Json reference(std::string path) {
    return {{"file", std::move(path)}};
}

struct Fixture final {
    Directory directory;
    Identity server;
    Identity client;
    Identity admin;
    PkeyPtr kem = generate_key("ML-KEM-1024");
    Json authorized;
    Json admins;
    Json server_config;
    Json client_config;

    void write(const std::string& name, std::string_view contents) const {
        const auto path = directory.path() / name;
        std::ofstream stream(path, std::ios::binary | std::ios::trunc);
        stream.write(contents.data(),
                     static_cast<std::streamsize>(contents.size()));
        stream.close();
        check(static_cast<bool>(stream), "test credential write failed");
        std::filesystem::permissions(path,
                                     std::filesystem::perms::owner_read |
                                         std::filesystem::perms::owner_write);
    }

    Fixture() {
        std::filesystem::create_directory(directory.path() / "credentials");
        std::filesystem::create_directory(directory.path() / "credentials" /
                                          "authorized");
        write("credentials/server.pem", server.private_pem);
        write("credentials/server.pub.pem", server.public_pem);
        write("credentials/client.pem", client.private_pem);
        write("credentials/authorized/client.pub.pem", client.public_pem);
        write("credentials/authorized/admin.pub.pem", admin.public_pem);
        write("credentials/kem.pem", pem(kem.get(), true));
        write("credentials/kem.pub.pem", pem(kem.get(), false));
        write("credentials/admission.key", std::string(32, '\x2a'));
        write("credentials/authorized/access.psk", std::string(32, '\x7a'));
        yume::test::write_tls_identity(
            directory.path() / "credentials/tls.pem",
            directory.path() / "credentials/tls.key");
        for (const auto* name :
             {"credentials/tls.pem", "credentials/tls.key"}) {
            std::filesystem::permissions(
                directory.path() / name,
                std::filesystem::perms::owner_read |
                    std::filesystem::perms::owner_write);
        }
        authorized = {
            {"schema", 1},
            {"keys",
             Json::array(
                 {{{"name", "client"},
                   {"identity",
                    {{"file", "authorized/client.pub.pem"},
                     {"sha256", client.id}}},
                   {"access_psk", reference("authorized/access.psk")},
                   {"capabilities", Json::array({{{"service", "echo"},
                                                  {"kind", "stream"}}})}}})}};
        admins = {{"schema", 1}, {"keys", Json::array()}};
        restore_stores();
        server_config = {
            {"schema", 1},
            {"role", "server"},
            {"endpoint", {{"listen_addresses", {"127.0.0.1"}}, {"port", 443}}},
            {"suite",
             {{"id", "ytp1-tls13-h2"},
              {"secure_channel", "tls13-native"},
              {"front_door", "h2-web"},
              {"carrier", "h2-duplex"},
              {"session", "ytp1-hybrid"}}},
            {"credentials",
             {{"composite_key", reference("credentials/server.pem")},
              {"authorized_keys", reference("credentials/authorized.json")},
              {"admin_keys", reference("credentials/admins.json")},
              {"tls_certificate", reference("credentials/tls.pem")},
              {"tls_key", reference("credentials/tls.key")},
              {"admission_key", reference("credentials/admission.key")},
              {"mlkem_key", reference("credentials/kem.pem")}}},
            {"cover",
             {{"profile", "chrome151-node24-v1"},
              {"root", reference("cover")}}},
            {"services", Json::array({{{"name", "echo"},
                                       {"kind", "stream"},
                                       {"max_concurrent_streams", 8}},
                                      {{"name", "refused"},
                                       {"kind", "stream"},
                                       {"max_concurrent_streams", 8}}})},
            {"adapters", Json::array()},
            {"limits",
             {{"max_frame_bytes", 262144},
              {"max_streams", 256},
              {"max_queued_bytes", 4194304},
              {"max_pending_opens", 64},
              {"max_rekey_jobs", 4},
              {"max_control_messages", 128},
              {"max_packet_bytes", 65535},
              {"max_packet_batch", 64}}}};
        client_config = server_config;
        client_config["role"] = "client";
        client_config["endpoint"] = {{"host", "127.0.0.1"}, {"port", 443}};
        client_config["cover"] = {{"profile", "chrome151-node24-v1"}};
        client_config["credentials"] = {
            {"composite_key", reference("credentials/client.pem")},
            {"access_psk", reference("credentials/authorized/access.psk")},
            {"admission_key", reference("credentials/admission.key")},
            {"server_trust", reference("credentials/tls.pem")},
            {"server_identity", reference("credentials/server.pub.pem")},
            {"server_mlkem", reference("credentials/kem.pub.pem")}};
    }

    void restore_stores() const {
        write("credentials/authorized.json", authorized.dump());
        write("credentials/admins.json", admins.dump());
    }

    Result<LoadedNativeCredentials> load_server() const {
        return load_native_credentials(yume::config::v1::Parse(server_config),
                                       directory.path());
    }

    void rejected_store(Json candidate, bool admin_store = false) const {
        write(admin_store ? "credentials/admins.json"
                          : "credentials/authorized.json",
              candidate.dump());
        const auto result = load_server();
        restore_stores();
        check(!result.ok() &&
                  result.status().code() == StatusCode::InvalidArgument,
              "invalid credential store was accepted");
    }
};

StreamOpenContext open_context(std::string peer, EndpointRole role,
                               std::string service, ServiceKind kind) {
    return take(StreamOpenContext::create(
        take(StreamId::application(role == EndpointRole::Client ? 1 : 2, role)),
        std::move(service), kind,
        take(PeerEvidence::create(role, std::move(peer), "ytp1-hybrid",
                                  {std::byte{1}}))));
}

void test_load_and_authenticate(Fixture& fixture) {
    auto server = take(fixture.load_server());
    const auto client_config = yume::config::v1::Parse(fixture.client_config);
    check(
        !load_native_credentials(client_config, fixture.directory.path()).ok(),
        "client accepted an absent authenticated TLS name");
    auto client = take(load_native_credentials(
        client_config, fixture.directory.path(), "yume-lock-test"));
    check(server.admission_key.bytes()[0] == std::byte{0x2a} &&
              std::equal(server.admission_key.bytes().begin(),
                         server.admission_key.bytes().end(),
                         client.admission_key.bytes().begin()),
          "admission bytes changed");
    auto server_provider =
        take(server.security_factory->create(EndpointRole::Server));
    auto client_provider =
        take(client.security_factory->create(EndpointRole::Client));
    check(!server.security_factory->create(EndpointRole::Client).ok(),
          "loaded factory changed endpoint role");
    yume::ytp1::CapabilityManifest capabilities;
    capabilities.entries.push_back(
        {"echo", yume::ytp1::ServiceKind::ByteStream, 8});
    const auto encoded = yume::ytp1::EncodeCapabilityManifest(capabilities);
    check(encoded.ok(), "fixture capability encoding failed");
    const auto manifest = std::as_bytes(std::span(*encoded.value));
    const auto parameters = yume::ytp1::RequiredSecurityParameters();
    std::array<std::byte, 32> exporter{};
    exporter.fill(std::byte{0x19});
    const auto client_peer = take(SecureChannelPeerEvidence::authenticated(
        EndpointRole::Server, "yume-lock-test", "TLS1.3", {std::byte{1}}));
    const auto server_peer = SecureChannelPeerEvidence::anonymous_client();
    check(client_provider
              ->initialize({EndpointRole::Client, yume::ytp1::kSuiteId,
                            std::as_bytes(std::span(parameters)), exporter,
                            client_peer, manifest})
              .ok(),
          "loaded client initialization failed");
    check(server_provider
              ->initialize({EndpointRole::Server, yume::ytp1::kSuiteId,
                            std::as_bytes(std::span(parameters)), exporter,
                            server_peer, manifest})
              .ok(),
          "loaded server initialization failed");
    (void)take(client_provider->start_authentication());
    auto challenge = take(server_provider->start_authentication());
    auto response = take(client_provider->process_authentication(
        AuthenticationMessageKind::Challenge,
        challenge.outbound_message->bytes()));
    auto accepted = take(server_provider->process_authentication(
        AuthenticationMessageKind::Response,
        response.outbound_message->bytes()));
    auto established = take(client_provider->process_authentication(
        AuthenticationMessageKind::Accepted,
        accepted.outbound_message->bytes()));
    check(accepted.established && established.established &&
              accepted.authenticated_peer->identity() == fixture.client.id &&
              established.authenticated_peer->identity() == fixture.server.id,
          "loaded credentials did not establish verified composite identities");
    check(server.authorization
              ->authorize(open_context(fixture.client.id, EndpointRole::Client,
                                       "echo", ServiceKind::ByteStream))
              .ok(),
          "authorized service refused");
    check(!server.authorization
               ->authorize(open_context(fixture.client.id, EndpointRole::Client,
                                        "refused", ServiceKind::ByteStream))
               .ok(),
          "identity gained a capability absent from its store");
    check(!server.authorization
               ->authorize(open_context(fixture.client.id, EndpointRole::Client,
                                        "echo", ServiceKind::PacketChannel))
               .ok(),
          "capability authorized the wrong service kind");
    check(!server.authorization
               ->authorize(open_context(fixture.client.id, EndpointRole::Server,
                                        "echo", ServiceKind::ByteStream))
               .ok(),
          "capability authorized the wrong peer role");
    check(!server.authorization
               ->authorize(open_context("client", EndpointRole::Client, "echo",
                                        ServiceKind::ByteStream))
               .ok(),
          "store name replaced verified composite identity");
    check(client.authorization
              ->authorize(open_context(fixture.server.id, EndpointRole::Server,
                                       "echo", ServiceKind::ByteStream))
              .ok(),
          "client policy refused its trusted server");

    // A loaded factory and its policy own a snapshot; rewriting the source
    // store cannot grant or revoke authority underneath an existing session.
    fixture.write("credentials/authorized.json", "{}");
    check(server.authorization
              ->authorize(open_context(fixture.client.id, EndpointRole::Client,
                                       "echo", ServiceKind::ByteStream))
              .ok(),
          "authorization snapshot retained file ownership");
    fixture.restore_stores();
}

void test_invalid_stores(Fixture& fixture) {
    for (const auto& mutation : std::vector<std::function<void(Json&)>>{
             [](Json& value) { value["schema"] = 1.0; },
             [](Json& value) { value["extra"] = true; },
             [](Json& value) { value["keys"] = Json::array(); },
             [](Json& value) { value["keys"][0]["admin"] = true; },
             [](Json& value) { value["keys"][0]["name"] = "-client"; },
             [](Json& value) {
                 value["keys"][0]["identity"]["sha256"] = std::string(64, '0');
             },
             [](Json& value) {
                 value["keys"][0]["identity"]["file"] = "../client.pub.pem";
             },
             [](Json& value) {
                 value["keys"][0]["access_psk"]["file"] = "admission.key";
             },
             [](Json& value) {
                 value["keys"][0]["capabilities"][0]["service"] = "missing";
             },
             [](Json& value) {
                 value["keys"][0]["capabilities"][0]["kind"] = "packet";
             },
             [](Json& value) {
                 value["keys"][0]["capabilities"].push_back(
                     value["keys"][0]["capabilities"][0]);
             },
             [](Json& value) { value["keys"].push_back(value["keys"][0]); },
             [](Json& value) {
                 auto duplicate = value["keys"][0];
                 duplicate["name"] = "another-name";
                 value["keys"].push_back(std::move(duplicate));
             },
             [&](Json& value) {
                 auto duplicate = value["keys"][0];
                 duplicate["name"] = "another-name";
                 duplicate["identity"] = {{"file", "authorized/admin.pub.pem"},
                                          {"sha256", fixture.admin.id}};
                 value["keys"].push_back(std::move(duplicate));
             }}) {
        auto candidate = fixture.authorized;
        mutation(candidate);
        fixture.rejected_store(std::move(candidate));
    }
    fixture.write("credentials/authorized.json",
                  "{\"schema\":1,\"schema\":1,\"keys\":[]}");
    check(!fixture.load_server().ok(), "duplicate JSON keys accepted");
    fixture.write("credentials/authorized.json",
                  std::string(18, '[') + "0" + std::string(18, ']'));
    check(!fixture.load_server().ok(), "excessive JSON depth accepted");
    fixture.restore_stores();

    Json admin_entry = {
        {"name", "admin"},
        {"identity",
         {{"file", "authorized/admin.pub.pem"}, {"sha256", fixture.admin.id}}}};
    auto candidate = fixture.admins;
    candidate["keys"].push_back(admin_entry);
    fixture.write("credentials/admins.json", candidate.dump());
    check(fixture.load_server().ok(),
          "valid separate administrator identity refused");
    admin_entry["name"] = "other-admin";
    candidate["keys"].push_back(admin_entry);
    fixture.rejected_store(candidate, true);
    candidate["keys"] = Json::array({{{"name", "admin"},
                                      {"identity",
                                       {{"file", "authorized/client.pub.pem"},
                                        {"sha256", fixture.client.id}}}}});
    fixture.rejected_store(candidate, true);
    candidate["keys"] = Json::array({admin_entry});
    candidate["keys"][0]["capabilities"] = Json::array();
    fixture.rejected_store(candidate, true);
}

void test_file_boundaries(Fixture& fixture) {
    for (const auto& bytes : {std::string(31, 'x'), std::string(33, 'x'),
                              std::string(64, 'a'), std::string(32, '\0')}) {
        fixture.write("credentials/authorized/access.psk", bytes);
        check(!fixture.load_server().ok(), "invalid raw PSK size accepted");
    }
    fixture.write("credentials/authorized/access.psk", std::string(32, '\x7a'));
    fixture.write("credentials/server.pem",
                  pem(fixture.server.pq.get(), true) +
                      pem(fixture.server.classical.get(), true));
    check(!fixture.load_server().ok(), "reversed composite key order accepted");
    fixture.write("credentials/server.pem",
                  fixture.server.private_pem + "trailing");
    check(!fixture.load_server().ok(), "trailing credential bytes accepted");
    fixture.write(
        "credentials/server.pem",
        fixture.server.private_pem + pem(fixture.server.classical.get(), true));
    check(!fixture.load_server().ok(), "extra composite key accepted");
    fixture.write("credentials/server.pem", fixture.server.private_pem);
    auto private_with_headers = fixture.server.private_pem;
    private_with_headers.insert(private_with_headers.find('\n') + 1,
                                "Proc-Type: 4,ENCRYPTED\n");
    fixture.write("credentials/server.pem", private_with_headers);
    check(!fixture.load_server().ok(), "PEM encryption header accepted");
    fixture.write("credentials/server.pem", fixture.server.private_pem);
    const auto path = fixture.directory.path() / "credentials/admission.key";
    std::filesystem::permissions(path, std::filesystem::perms::group_read,
                                 std::filesystem::perm_options::add);
    check(!fixture.load_server().ok(), "group-readable credential accepted");
    std::filesystem::permissions(path, std::filesystem::perms::owner_read |
                                           std::filesystem::perms::owner_write);
#if !defined(_WIN32)
    const auto alias = fixture.directory.path() / "credentials/alias.key";
    std::filesystem::create_symlink("admission.key", alias);
    auto config = fixture.server_config;
    config["credentials"]["admission_key"] = reference("credentials/alias.key");
    check(!load_native_credentials(yume::config::v1::Parse(config),
                                   fixture.directory.path())
               .ok(),
          "symlink credential accepted");
    const auto fifo = fixture.directory.path() / "credentials/fifo.key";
    check(::mkfifo(fifo.c_str(), 0600) == 0, "test FIFO creation failed");
    config["credentials"]["admission_key"] = reference("credentials/fifo.key");
    check(!load_native_credentials(yume::config::v1::Parse(config),
                                   fixture.directory.path())
               .ok(),
          "FIFO credential accepted");
#endif
    check(fixture.load_server().ok(),
          "valid credentials did not recover after rejected inputs");
}

void test_admission_ownership() {
    static_assert(!std::is_copy_constructible_v<NativeAdmissionKey>);
    static_assert(std::is_nothrow_move_constructible_v<NativeAdmissionKey>);
    std::array<std::byte, 32> material{};
    material.fill(std::byte{0x59});
    NativeAdmissionKey first(material);
    NativeAdmissionKey second(std::move(first));
    const auto cleared = [](auto bytes) {
        return std::all_of(bytes.begin(), bytes.end(), [](std::byte value) {
            return value == std::byte{0};
        });
    };
    check(cleared(first.bytes()) && second.bytes()[0] == std::byte{0x59},
          "admission move failed to clear its source");
    first = std::move(second);
    check(cleared(second.bytes()) && first.bytes()[0] == std::byte{0x59},
          "admission move assignment failed to clear its source");
    alignas(NativeAdmissionKey)
        std::array<std::byte, sizeof(NativeAdmissionKey)>
            storage{};
    auto* key = std::construct_at(
        reinterpret_cast<NativeAdmissionKey*>(storage.data()), material);
    std::destroy_at(key);
    check(cleared(storage), "admission destruction retained secret bytes");
}

}  // namespace

int main() {
    try {
        test_admission_ownership();
        Fixture fixture;
        test_load_and_authenticate(fixture);
        test_invalid_stores(fixture);
        test_file_boundaries(fixture);
        std::cout << "native credential tests passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "native credential test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
