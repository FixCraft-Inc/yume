/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/openssl_security_provider.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "ytp/protocol.hpp"
#include "ytp/security.hpp"
#include "providers/ytp1_crypto.hpp"
#include "test_support/allocation_failure.hpp"

namespace {

using yume::engine::AuthenticationMessageKind;
using yume::engine::AuthenticationOutput;
using yume::engine::EndpointRole;
using yume::engine::RecordKeyToken;
using yume::engine::Result;
using yume::engine::SecureChannelPeerEvidence;
using yume::engine::SessionAuthenticationContext;
using yume::engine::SessionSecurityProvider;
using yume::engine::StatusCode;
using yume::providers::CompositePrivateIdentityView;
using yume::providers::CompositePublicIdentityView;
using yume::providers::ClientCredentialsView;
using yume::providers::AuthorizedIdentityView;
using yume::providers::OpenSslSecurityProviderFactory;
using yume::providers::ServerCredentialsView;

struct PkeyDeleter final {
    void operator()(EVP_PKEY* value) const noexcept { EVP_PKEY_free(value); }
};

struct ProviderDeleter final {
    void operator()(OSSL_PROVIDER* value) const noexcept {
        if (value != nullptr) {
            (void)OSSL_PROVIDER_unload(value);
        }
    }
};

struct Pkcs8Deleter final {
    void operator()(PKCS8_PRIV_KEY_INFO* value) const noexcept {
        PKCS8_PRIV_KEY_INFO_free(value);
    }
};

using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDeleter>;
using ProviderPtr = std::unique_ptr<OSSL_PROVIDER, ProviderDeleter>;
using Pkcs8Ptr = std::unique_ptr<PKCS8_PRIV_KEY_INFO, Pkcs8Deleter>;

void check(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

template <typename T>
T require(Result<T> result, std::string_view context) {
    if (!result.ok()) {
        throw std::runtime_error(
            std::string(context) + ": " + result.status().message());
    }
    return std::move(result).take_value();
}

std::span<const std::byte> as_bytes(
    std::span<const std::uint8_t> input) noexcept {
    return {reinterpret_cast<const std::byte*>(input.data()), input.size()};
}

std::span<const std::uint8_t> as_u8(
    std::span<const std::byte> input) noexcept {
    return {reinterpret_cast<const std::uint8_t*>(input.data()), input.size()};
}

std::vector<std::byte> byte_copy(
    std::span<const std::uint8_t> input) {
    std::vector<std::byte> output(input.size());
    if (!input.empty()) {
        std::memcpy(output.data(), input.data(), input.size());
    }
    return output;
}

std::vector<std::byte> byte_copy(
    std::span<const std::byte> input) {
    return {input.begin(), input.end()};
}

PkeyPtr generate_key(std::string_view algorithm) {
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context(
        EVP_PKEY_CTX_new_from_name(nullptr, algorithm.data(), nullptr),
        EVP_PKEY_CTX_free);
    check(context != nullptr && EVP_PKEY_keygen_init(context.get()) == 1,
          "test key generation initialization failed");
    EVP_PKEY* raw = nullptr;
    check(EVP_PKEY_generate(context.get(), &raw) == 1 && raw != nullptr,
          "test key generation failed");
    return PkeyPtr(raw);
}

std::vector<std::uint8_t> public_der(EVP_PKEY* key) {
    const int size = i2d_PUBKEY(key, nullptr);
    check(size > 0, "public DER size query failed");
    std::vector<std::uint8_t> output(static_cast<std::size_t>(size));
    unsigned char* cursor = output.data();
    check(i2d_PUBKEY(key, &cursor) == size &&
              cursor == output.data() + output.size(),
          "public DER encoding failed");
    return output;
}

std::vector<std::uint8_t> private_der(EVP_PKEY* key) {
    Pkcs8Ptr pkcs8(EVP_PKEY2PKCS8(key));
    check(pkcs8 != nullptr, "PKCS#8 conversion failed");
    const int size = i2d_PKCS8_PRIV_KEY_INFO(pkcs8.get(), nullptr);
    check(size > 0, "private DER size query failed");
    std::vector<std::uint8_t> output(static_cast<std::size_t>(size));
    unsigned char* cursor = output.data();
    check(i2d_PKCS8_PRIV_KEY_INFO(pkcs8.get(), &cursor) == size &&
              cursor == output.data() + output.size(),
          "private DER encoding failed");
    return output;
}

std::vector<std::uint8_t> overlong_ber_outer_length(
    std::span<const std::uint8_t> canonical) {
    check(canonical.size() >= 2U && canonical[0] == 0x30U &&
              canonical[1] < 0x80U &&
              canonical.size() == static_cast<std::size_t>(canonical[1]) + 2U,
          "alternate PKCS#8 fixture is not a short-form DER sequence");
    std::vector<std::uint8_t> alternate;
    alternate.reserve(canonical.size() + 1U);
    alternate.push_back(canonical[0]);
    alternate.push_back(0x81U);
    alternate.push_back(canonical[1]);
    alternate.insert(alternate.end(), canonical.begin() + 2U,
                     canonical.end());
    return alternate;
}

struct CompositeDer final {
    std::vector<std::uint8_t> ed_private;
    std::vector<std::uint8_t> ed_public;
    std::vector<std::uint8_t> ml_private;
    std::vector<std::uint8_t> ml_public;
};

CompositeDer generate_composite() {
    PkeyPtr ed = generate_key("ED25519");
    PkeyPtr ml = generate_key("ML-DSA-87");
    return {
        private_der(ed.get()), public_der(ed.get()),
        private_der(ml.get()), public_der(ml.get()),
    };
}

struct Fixture final {
    CompositeDer client = generate_composite();
    CompositeDer server = generate_composite();
    CompositeDer other_server = generate_composite();
    PkeyPtr server_kem = generate_key("ML-KEM-1024");
    std::vector<std::uint8_t> server_kem_private =
        private_der(server_kem.get());
    std::vector<std::uint8_t> server_kem_public =
        public_der(server_kem.get());
    std::array<std::uint8_t, yume::ytp1::kPskSize> psk{};
    std::vector<std::byte> capabilities;
    SecureChannelPeerEvidence client_tls_peer =
        require(SecureChannelPeerEvidence::authenticated(
                    EndpointRole::Server, "tls-server", "TLS1.3",
                    {std::byte{0x01}}),
                "TLS server evidence");
    SecureChannelPeerEvidence server_tls_peer =
        SecureChannelPeerEvidence::anonymous_client();

    Fixture() {
        for (std::size_t index = 0; index < psk.size(); ++index) {
            psk[index] = static_cast<std::uint8_t>(index + 1U);
        }
        yume::ytp1::CapabilityManifest manifest;
        manifest.entries.push_back(
            {"echo", yume::ytp1::ServiceKind::ByteStream, 8U});
        const auto encoded = yume::ytp1::EncodeCapabilityManifest(manifest);
        check(encoded.ok(), "capability fixture encoding failed");
        capabilities = byte_copy(*encoded.value);
    }
};

CompositePrivateIdentityView private_view(const CompositeDer& identity) {
    return {as_bytes(identity.ed_private), as_bytes(identity.ml_private)};
}

CompositePublicIdentityView public_view(const CompositeDer& identity) {
    return {as_bytes(identity.ed_public), as_bytes(identity.ml_public)};
}

struct PairOptions final {
    const CompositeDer* trusted_server{nullptr};
    const CompositeDer* authorized_client{nullptr};
    std::array<std::uint8_t, yume::ytp1::kPskSize> client_psk{};
    std::array<std::uint8_t, yume::ytp1::kPskSize> server_psk{};
    std::array<std::uint8_t, yume::ytp1::kExporterSize> client_exporter{};
    std::array<std::uint8_t, yume::ytp1::kExporterSize> server_exporter{};
};

PairOptions default_options(const Fixture& fixture) {
    PairOptions options;
    options.trusted_server = &fixture.server;
    options.authorized_client = &fixture.client;
    options.client_psk = fixture.psk;
    options.server_psk = fixture.psk;
    for (std::size_t index = 0; index < options.client_exporter.size();
         ++index) {
        options.client_exporter[index] =
            static_cast<std::uint8_t>(0xa0U + index);
    }
    options.server_exporter = options.client_exporter;
    return options;
}

struct ProviderPair final {
    std::unique_ptr<SessionSecurityProvider> client;
    std::unique_ptr<SessionSecurityProvider> server;
};

ProviderPair make_pair(const Fixture& fixture, const PairOptions& options) {
    const ClientCredentialsView client_credentials{
        private_view(fixture.client), public_view(*options.trusted_server),
        as_bytes(fixture.server_kem_public), as_bytes(options.client_psk),
        "server-peer",
    };
    const AuthorizedIdentityView authorized{
        public_view(*options.authorized_client), as_bytes(options.server_psk),
        "client-peer",
    };
    const std::array<AuthorizedIdentityView, 1> authorized_identities{authorized};
    const ServerCredentialsView server_credentials{
        private_view(fixture.server), as_bytes(fixture.server_kem_private),
        authorized_identities,
    };
    auto client_factory = require(
        OpenSslSecurityProviderFactory::create_client(
            client_credentials),
        "client factory");
    auto server_factory = require(
        OpenSslSecurityProviderFactory::create_server(
            server_credentials),
        "server factory");
    check(!client_factory->create(EndpointRole::Server).ok(),
          "client factory accepted the server role");
    check(!server_factory->create(EndpointRole::Client).ok(),
          "server factory accepted the client role");
    ProviderPair pair{
        require(client_factory->create(EndpointRole::Client),
                "client provider"),
        require(server_factory->create(EndpointRole::Server),
                "server provider"),
    };
    const SessionAuthenticationContext client_context{
        EndpointRole::Client, yume::ytp1::kSuiteId,
        as_bytes(yume::ytp1::RequiredSecurityParameters()),
        as_bytes(options.client_exporter), fixture.client_tls_peer,
        fixture.capabilities,
    };
    const SessionAuthenticationContext server_context{
        EndpointRole::Server, yume::ytp1::kSuiteId,
        as_bytes(yume::ytp1::RequiredSecurityParameters()),
        as_bytes(options.server_exporter), fixture.server_tls_peer,
        fixture.capabilities,
    };
    check(pair.client->initialize(client_context).ok(),
          "client provider initialization failed");
    check(pair.server->initialize(server_context).ok(),
          "server provider initialization failed");
    return pair;
}

struct HandshakeFlight final {
    std::vector<std::byte> challenge;
    std::vector<std::byte> response;
    std::vector<std::byte> accepted;
    AuthenticationOutput server_output;
    AuthenticationOutput client_output;
};

std::vector<std::byte> outgoing(AuthenticationOutput& output,
                                AuthenticationMessageKind kind) {
    check(output.outbound_kind == kind && output.outbound_message.has_value(),
          "AUTH output flight is missing");
    return byte_copy(output.outbound_message->bytes());
}

std::vector<std::byte> begin_handshake(ProviderPair& pair) {
    AuthenticationOutput client_start = require(
        pair.client->start_authentication(), "client AUTH start");
    check(!client_start.outbound_kind.has_value() &&
              !client_start.outbound_message.has_value() &&
              !client_start.established,
          "client sent before the challenge");
    AuthenticationOutput server_start = require(
        pair.server->start_authentication(), "server AUTH start");
    return outgoing(server_start, AuthenticationMessageKind::Challenge);
}

HandshakeFlight complete_handshake(ProviderPair& pair) {
    HandshakeFlight flight;
    flight.challenge = begin_handshake(pair);
    AuthenticationOutput response = require(
        pair.client->process_authentication(
            AuthenticationMessageKind::Challenge, flight.challenge),
        "client challenge processing");
    flight.response = outgoing(response, AuthenticationMessageKind::Response);
    flight.server_output = require(
        pair.server->process_authentication(
            AuthenticationMessageKind::Response, flight.response),
        "server response processing");
    flight.accepted = outgoing(
        flight.server_output, AuthenticationMessageKind::Accepted);
    flight.client_output = require(
        pair.client->process_authentication(
            AuthenticationMessageKind::Accepted, flight.accepted),
        "client accepted processing");
    check(flight.server_output.established &&
              flight.client_output.established &&
              flight.server_output.authenticated_peer.has_value() &&
              flight.client_output.authenticated_peer.has_value(),
          "paired handshake did not establish both providers");
    return flight;
}

std::vector<std::byte> mutate_auth_field(
    std::span<const std::byte> message,
    yume::ytp1::AuthFieldId id,
    std::size_t value_offset) {
    auto decoded = yume::ytp1::DecodeAuthRecord(as_u8(message));
    check(decoded.ok(), "AUTH mutation input did not decode");
    const auto numeric = static_cast<std::uint16_t>(id);
    const auto iterator = std::find_if(
        decoded.value->fields.begin(), decoded.value->fields.end(),
        [numeric](const yume::ytp1::AuthField& field) {
            return field.id == numeric;
        });
    check(iterator != decoded.value->fields.end() &&
              value_offset < iterator->value.size(),
          "AUTH mutation field is missing");
    iterator->value[value_offset] ^= 0x01U;
    auto encoded = yume::ytp1::EncodeAuthRecord(*decoded.value);
    check(encoded.ok(), "mutated AUTH record did not encode");
    return byte_copy(*encoded.value);
}

std::uint16_t read_u16(std::span<const std::uint8_t> input,
                       std::size_t offset) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(input[offset]) << 8U) |
        static_cast<std::uint16_t>(input[offset + 1U]));
}

std::uint32_t read_u32(std::span<const std::uint8_t> input,
                       std::size_t offset) {
    return (static_cast<std::uint32_t>(input[offset]) << 24U) |
           (static_cast<std::uint32_t>(input[offset + 1U]) << 16U) |
           (static_cast<std::uint32_t>(input[offset + 2U]) << 8U) |
           static_cast<std::uint32_t>(input[offset + 3U]);
}

void write_u32(std::span<std::uint8_t> output,
               std::size_t offset,
               std::uint32_t value) {
    output[offset] = static_cast<std::uint8_t>(value >> 24U);
    output[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
    output[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
    output[offset + 3U] = static_cast<std::uint8_t>(value);
}

std::vector<std::byte> strip_ed25519_signature(
    std::span<const std::byte> message) {
    std::vector<std::uint8_t> encoded(
        as_u8(message).begin(), as_u8(message).end());
    const std::size_t field_count = read_u16(encoded, 2U);
    std::size_t offset = 8U;
    for (std::size_t index = 0; index < field_count; ++index) {
        const std::uint16_t id = read_u16(encoded, offset);
        const std::size_t length = read_u32(encoded, offset + 4U);
        if (id == static_cast<std::uint16_t>(
                      yume::ytp1::AuthFieldId::CompositeSignature)) {
            check(length == yume::ytp1::kCompositeSignatureSize,
                  "signature strip input has wrong size");
            const std::size_t value = offset + 8U;
            encoded.erase(
                encoded.begin() + static_cast<std::ptrdiff_t>(value),
                encoded.begin() + static_cast<std::ptrdiff_t>(
                    value + yume::ytp1::kEd25519SignatureSize));
            write_u32(encoded, offset + 4U,
                      static_cast<std::uint32_t>(
                          length - yume::ytp1::kEd25519SignatureSize));
            write_u32(encoded, 4U,
                      read_u32(encoded, 4U) -
                          static_cast<std::uint32_t>(
                              yume::ytp1::kEd25519SignatureSize));
            return byte_copy(encoded);
        }
        offset += 8U + length;
    }
    throw std::runtime_error("signature field not found");
}

std::vector<std::byte> raw_mutate_auth_field(
    std::span<const std::byte> message,
    yume::ytp1::AuthFieldId field_id,
    std::size_t value_offset) {
    std::vector<std::uint8_t> encoded(
        as_u8(message).begin(), as_u8(message).end());
    const std::size_t field_count = read_u16(encoded, 2U);
    std::size_t offset = 8U;
    for (std::size_t index = 0; index < field_count; ++index) {
        const std::uint16_t id = read_u16(encoded, offset);
        const std::size_t length = read_u32(encoded, offset + 4U);
        if (id == static_cast<std::uint16_t>(field_id)) {
            check(value_offset < length, "raw AUTH mutation is out of range");
            encoded[offset + 8U + value_offset] ^= 0x01U;
            return byte_copy(encoded);
        }
        offset += 8U + length;
    }
    throw std::runtime_error("raw AUTH mutation field not found");
}

void check_record_round_trip(SessionSecurityProvider& sender,
                             SessionSecurityProvider& receiver,
                             RecordKeyToken token,
                             std::string_view text) {
    const auto plaintext = as_bytes(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(text.data()), text.size()));
    // The record follows the requested headroom, which stays zero.
    constexpr std::size_t kHeadroom = 16U;
    auto sealed_with_headroom =
        require(sender.seal_record(token, plaintext, kHeadroom), "record seal");
    check(
        sealed_with_headroom.size() > kHeadroom &&
            std::all_of(sealed_with_headroom.bytes().begin(),
                        sealed_with_headroom.bytes().begin() + kHeadroom,
                        [](std::byte value) { return value == std::byte{0}; }),
        "sealed record headroom is not zero");
    auto sealed = require(yume::engine::Buffer::copy_from(
                              sealed_with_headroom.bytes().subspan(kHeadroom),
                              yume::engine::kAbsoluteMaxBufferBytes),
                          "sealed record copy");
    auto opened = require(receiver.open_record(token, sealed.bytes()),
                          "record open");
    check(opened.size() == text.size() &&
              std::memcmp(opened.bytes().data(), text.data(), text.size()) == 0,
          "record plaintext mismatch");
}

void test_full_handshake_and_records(const Fixture& fixture) {
    auto pair = make_pair(fixture, default_options(fixture));
    const HandshakeFlight flight = complete_handshake(pair);
    check(flight.server_output.authenticated_peer->identity() ==
              "client-peer" &&
              flight.client_output.authenticated_peer->identity() ==
                  "server-peer",
          "configured peer labels were not preserved");
    check(flight.server_output.authenticated_peer->credential_evidence().size()
              == 32U &&
              flight.client_output.authenticated_peer->credential_evidence()
                  .size() == 32U,
          "peer evidence exposed more than a credential fingerprint");
    check(flight.server_output.authenticated_peer_capability_manifest ==
              fixture.capabilities &&
              flight.client_output.authenticated_peer_capability_manifest ==
                  fixture.capabilities,
          "authenticated capabilities did not round-trip");
    check_record_round_trip(*pair.client, *pair.server, {0U, 0U},
                            "client-to-server");
    check_record_round_trip(*pair.server, *pair.client, {0U, 0U},
                            "server-to-client");
}

void test_record_fail_closed(const Fixture& fixture) {
    {
        auto pair = make_pair(fixture, default_options(fixture));
        (void)complete_handshake(pair);
        const std::array<std::byte, 1> payload{std::byte{0x41}};
        auto sealed = require(pair.client->seal_record({0U, 0U}, payload, 0U),
                              "negative record seal");
        check(!pair.client->seal_record({0U, 0U}, payload, 0U).ok(),
              "one-use outbound token was reusable");
        check(!pair.client->seal_record({0U, 1U}, payload, 0U).ok(),
              "failed provider retained secret record state");
        (void)sealed;
    }
    {
        auto pair = make_pair(fixture, default_options(fixture));
        (void)complete_handshake(pair);
        const std::array<std::byte, 1> payload{std::byte{0x42}};
        auto sealed = require(pair.client->seal_record({0U, 0U}, payload, 0U),
                              "wrong-epoch seal");
        check(!pair.server->open_record({1U, 0U}, sealed.bytes()).ok(),
              "wrong inbound epoch was accepted");
        check(!pair.server->open_record({0U, 0U}, sealed.bytes()).ok(),
              "receiver recovered after token failure");
    }
    {
        auto pair = make_pair(fixture, default_options(fixture));
        (void)complete_handshake(pair);
        const std::array<std::byte, 1> payload{std::byte{0x43}};
        auto sealed = require(pair.client->seal_record({0U, 0U}, payload, 0U),
                              "mutation seal");
        sealed.mutable_bytes()[0] ^= std::byte{0x01};
        check(!pair.server->open_record({0U, 0U}, sealed.bytes()).ok(),
              "mutated record ciphertext was accepted");
    }
    {
        auto pair = make_pair(fixture, default_options(fixture));
        (void)complete_handshake(pair);
        const std::array<std::byte, 1> payload{std::byte{0x44}};
        check(!pair.client->seal_record({0U, 1U}, payload, 0U).ok(),
              "out-of-order global sequence was accepted");
    }
}

void test_bidirectional_rekey(const Fixture& fixture) {
    auto pair = make_pair(fixture, default_options(fixture));
    (void)complete_handshake(pair);
    auto client_init = require(pair.client->begin_outbound_rekey(1U),
                               "client rekey begin");
    auto server_init = require(pair.server->begin_outbound_rekey(1U),
                               "server rekey begin");

    // Both INIT flights consume the next old-epoch record key before either
    // endpoint commits its new inbound root. The authenticated ACK payloads
    // are intentionally passed directly: the engine carries only ACK outside
    // the record AEAD so crossed directional rekeys cannot strand an ACK
    // behind a root the receiver has already retired.
    auto sealed_client_init =
        require(pair.client->seal_record({0U, 0U}, client_init.bytes(), 0U),
                "client rekey INIT seal");
    auto sealed_server_init =
        require(pair.server->seal_record({0U, 0U}, server_init.bytes(), 0U),
                "server rekey INIT seal");
    auto opened_client_init = require(pair.server->open_record(
        {0U, 0U}, sealed_client_init.bytes()), "client rekey INIT open");
    auto opened_server_init = require(pair.client->open_record(
        {0U, 0U}, sealed_server_init.bytes()), "server rekey INIT open");
    auto server_ack = require(pair.server->accept_inbound_rekey(
                                  1U, opened_client_init.bytes()),
                              "server rekey accept");
    auto client_ack = require(pair.client->accept_inbound_rekey(
                                  1U, opened_server_init.bytes()),
                              "client rekey accept");
    check(pair.client->finish_outbound_rekey(1U, server_ack.bytes()).ok(),
          "client rekey finish failed");
    check(pair.server->finish_outbound_rekey(1U, client_ack.bytes()).ok(),
          "server rekey finish failed");
    check_record_round_trip(*pair.client, *pair.server, {1U, 1U},
                            "rekeyed-client");
    check_record_round_trip(*pair.server, *pair.client, {1U, 1U},
                            "rekeyed-server");

    // The same rule also works when the two directional ratchets complete
    // sequentially. Sequence numbers remain global per direction across the
    // epoch transition and therefore advance from INIT token 0 to data token
    // 1 rather than restarting at zero.
    auto sequential = make_pair(fixture, default_options(fixture));
    (void)complete_handshake(sequential);
    auto sequential_client_init = require(
        sequential.client->begin_outbound_rekey(1U),
        "sequential client rekey begin");
    auto sequential_client_wire =
        require(sequential.client->seal_record(
                    {0U, 0U}, sequential_client_init.bytes(), 0U),
                "sequential client rekey INIT seal");
    auto sequential_client_plaintext = require(
        sequential.server->open_record(
            {0U, 0U}, sequential_client_wire.bytes()),
        "sequential client rekey INIT open");
    auto sequential_server_ack = require(
        sequential.server->accept_inbound_rekey(
            1U, sequential_client_plaintext.bytes()),
        "sequential server rekey accept");
    check(sequential.client->finish_outbound_rekey(
              1U, sequential_server_ack.bytes()).ok(),
          "sequential client rekey finish failed");
    check_record_round_trip(*sequential.client, *sequential.server,
                            {1U, 1U}, "sequential-client");

    auto sequential_server_init = require(
        sequential.server->begin_outbound_rekey(1U),
        "sequential server rekey begin");
    auto sequential_server_wire =
        require(sequential.server->seal_record(
                    {0U, 0U}, sequential_server_init.bytes(), 0U),
                "sequential server rekey INIT seal");
    auto sequential_server_plaintext = require(
        sequential.client->open_record(
            {0U, 0U}, sequential_server_wire.bytes()),
        "sequential server rekey INIT open");
    auto sequential_client_ack = require(
        sequential.client->accept_inbound_rekey(
            1U, sequential_server_plaintext.bytes()),
        "sequential client rekey accept");
    check(sequential.server->finish_outbound_rekey(
              1U, sequential_client_ack.bytes()).ok(),
          "sequential server rekey finish failed");
    check_record_round_trip(*sequential.server, *sequential.client,
                            {1U, 1U}, "sequential-server");

    auto negative = make_pair(fixture, default_options(fixture));
    (void)complete_handshake(negative);
    check(!negative.client->begin_outbound_rekey(2U).ok(),
          "skipped rekey epoch was accepted");
    auto initiation = require(negative.client->begin_outbound_rekey(1U),
                              "negative rekey begin");
    initiation.mutable_bytes().back() ^= std::byte{0x01};
    check(!negative.server->accept_inbound_rekey(
               1U, initiation.bytes()).ok(),
          "mutated old-root rekey authentication was accepted");

    auto ack_negative = make_pair(fixture, default_options(fixture));
    (void)complete_handshake(ack_negative);
    auto ack_init = require(
        ack_negative.client->begin_outbound_rekey(1U),
        "ack-negative rekey begin");
    auto acknowledgement = require(
        ack_negative.server->accept_inbound_rekey(1U, ack_init.bytes()),
        "ack-negative rekey accept");
    acknowledgement.mutable_bytes().back() ^= std::byte{0x01};
    check(!ack_negative.client->finish_outbound_rekey(
               1U, acknowledgement.bytes()).ok(),
          "mutated new-root rekey acknowledgement was accepted");
}

// After accepting INIT the receiver still opens records the sender seals in
// the old epoch until it processes ACK. The first record of the new epoch
// retires the old root, so an old-epoch record after it is refused, and no
// further INIT is accepted while the old epoch is still open.
void test_old_epoch_open_until_the_first_new_record(const Fixture& fixture) {
    auto pair = make_pair(fixture, default_options(fixture));
    (void)complete_handshake(pair);
    auto init = require(pair.client->begin_outbound_rekey(1U),
                        "make-before-break rekey begin");
    auto init_wire =
        require(pair.client->seal_record({0U, 0U}, init.bytes(), 0U),
                "make-before-break INIT seal");
    auto opened_init =
        require(pair.server->open_record({0U, 0U}, init_wire.bytes()),
                "make-before-break INIT open");
    auto ack =
        require(pair.server->accept_inbound_rekey(1U, opened_init.bytes()),
                "make-before-break rekey accept");
    check(!pair.server->accept_inbound_rekey(2U, opened_init.bytes()).ok(),
          "a second INIT was accepted while the old epoch was open");
    check_record_round_trip(*pair.client, *pair.server, {0U, 1U},
                            "old-epoch-after-init");
    check(pair.client->finish_outbound_rekey(1U, ack.bytes()).ok(),
          "make-before-break rekey finish failed");
    const std::string_view text = "first-new-epoch";
    const auto plaintext = as_bytes(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(text.data()), text.size()));
    auto first_new = require(pair.client->seal_record({1U, 2U}, plaintext, 0U),
                             "new-epoch seal");
    (void)require(pair.server->open_record({1U, 2U}, first_new.bytes()),
                  "new-epoch open");
    check(!pair.server->open_record({0U, 3U}, first_new.bytes()).ok(),
          "an old-epoch record was opened after the new epoch began");
}

void test_authentication_failures(const Fixture& fixture) {
    {
        PairOptions options = default_options(fixture);
        options.server_exporter[0] ^= 0x01U;
        auto pair = make_pair(fixture, options);
        const auto challenge = begin_handshake(pair);
        check(!pair.client->process_authentication(
                   AuthenticationMessageKind::Challenge, challenge).ok(),
              "exporter mismatch was accepted");
    }
    {
        PairOptions options = default_options(fixture);
        options.server_psk[0] ^= 0x01U;
        auto pair = make_pair(fixture, options);
        const auto challenge = begin_handshake(pair);
        auto response = require(pair.client->process_authentication(
                                    AuthenticationMessageKind::Challenge,
                                    challenge),
                                "mismatched-PSK client response");
        const auto encoded = outgoing(
            response, AuthenticationMessageKind::Response);
        check(!pair.server->process_authentication(
                   AuthenticationMessageKind::Response, encoded).ok(),
              "PSK mismatch was accepted");
    }
    {
        PairOptions options = default_options(fixture);
        options.trusted_server = &fixture.other_server;
        auto pair = make_pair(fixture, options);
        const auto challenge = begin_handshake(pair);
        check(!pair.client->process_authentication(
                   AuthenticationMessageKind::Challenge, challenge).ok(),
              "server identity mismatch was accepted");
    }
    {
        PairOptions options = default_options(fixture);
        options.authorized_client = &fixture.server;
        auto pair = make_pair(fixture, options);
        const auto challenge = begin_handshake(pair);
        auto response = require(pair.client->process_authentication(
                                    AuthenticationMessageKind::Challenge,
                                    challenge),
                                "unauthorized client response");
        const auto encoded = outgoing(
            response, AuthenticationMessageKind::Response);
        check(!pair.server->process_authentication(
                   AuthenticationMessageKind::Response, encoded).ok(),
              "unauthorized client identity was accepted");
    }
    {
        auto pair = make_pair(fixture, default_options(fixture));
        const auto challenge = begin_handshake(pair);
        check(!pair.client->process_authentication(
                   AuthenticationMessageKind::Response, challenge).ok(),
              "AUTH role/message confusion was accepted");
    }
}

void test_component_mutation_and_stripping(const Fixture& fixture) {
    for (const std::size_t signature_offset :
         {std::size_t{0U}, yume::ytp1::kEd25519SignatureSize}) {
        auto pair = make_pair(fixture, default_options(fixture));
        const auto challenge = begin_handshake(pair);
        const auto mutated = mutate_auth_field(
            challenge, yume::ytp1::AuthFieldId::CompositeSignature,
            signature_offset);
        check(!pair.client->process_authentication(
                   AuthenticationMessageKind::Challenge, mutated).ok(),
              "mutated composite-signature component was accepted");
    }
    {
        auto pair = make_pair(fixture, default_options(fixture));
        const auto challenge = begin_handshake(pair);
        const auto stripped = strip_ed25519_signature(challenge);
        check(!pair.client->process_authentication(
                   AuthenticationMessageKind::Challenge, stripped).ok(),
              "stripped signature component was accepted");
    }
    for (const auto field : {yume::ytp1::AuthFieldId::PskAuthenticator,
                             yume::ytp1::AuthFieldId::KeyConfirmation}) {
        auto pair = make_pair(fixture, default_options(fixture));
        const auto challenge = begin_handshake(pair);
        auto response = require(pair.client->process_authentication(
                                    AuthenticationMessageKind::Challenge,
                                    challenge),
                                "proof-mutation response");
        const auto encoded = outgoing(
            response, AuthenticationMessageKind::Response);
        const auto mutated = mutate_auth_field(encoded, field, 0U);
        check(!pair.server->process_authentication(
                   AuthenticationMessageKind::Response, mutated).ok(),
              "mutated response proof was accepted");
    }
    for (const auto field : {yume::ytp1::AuthFieldId::MlKemCiphertext,
                             yume::ytp1::AuthFieldId::X25519PublicKey}) {
        auto pair = make_pair(fixture, default_options(fixture));
        const auto challenge = begin_handshake(pair);
        auto response = require(pair.client->process_authentication(
                                    AuthenticationMessageKind::Challenge,
                                    challenge),
                                "hybrid-mutation response");
        const auto encoded = outgoing(
            response, AuthenticationMessageKind::Response);
        const auto mutated = mutate_auth_field(encoded, field, 0U);
        check(!pair.server->process_authentication(
                   AuthenticationMessageKind::Response, mutated).ok(),
              "mutated hybrid contribution was accepted");
    }
    {
        auto pair = make_pair(fixture, default_options(fixture));
        const auto challenge = begin_handshake(pair);
        auto response = require(pair.client->process_authentication(
                                    AuthenticationMessageKind::Challenge,
                                    challenge),
                                "accepted-mutation response");
        const auto encoded_response = outgoing(
            response, AuthenticationMessageKind::Response);
        auto accepted = require(pair.server->process_authentication(
                                    AuthenticationMessageKind::Response,
                                    encoded_response),
                                "accepted-mutation server response");
        const auto encoded_accepted = outgoing(
            accepted, AuthenticationMessageKind::Accepted);
        const auto mutated = mutate_auth_field(
            encoded_accepted, yume::ytp1::AuthFieldId::CompositeSignature,
            yume::ytp1::kEd25519SignatureSize);
        check(!pair.client->process_authentication(
                   AuthenticationMessageKind::Accepted, mutated).ok(),
              "mutated accepted ML-DSA signature was accepted");
    }
    {
        auto pair = make_pair(fixture, default_options(fixture));
        const auto challenge = begin_handshake(pair);
        const auto malformed = raw_mutate_auth_field(
            challenge, yume::ytp1::AuthFieldId::CapabilityManifest, 0U);
        check(!pair.client->process_authentication(
                   AuthenticationMessageKind::Challenge, malformed).ok(),
              "invalid capability manifest was accepted");
    }
}

void test_factory_bounds_and_cancellation(const Fixture& fixture) {
    auto options = default_options(fixture);
    ClientCredentialsView client_credentials{
        private_view(fixture.client), public_view(fixture.server),
        as_bytes(fixture.server_kem_public), as_bytes(options.client_psk),
        "server-peer",
    };
    check(OpenSslSecurityProviderFactory::create_client(
              client_credentials).ok(),
          "canonical PKCS#8 private credentials were rejected");
    const auto alternate_private = overlong_ber_outer_length(
        fixture.client.ed_private);
    CompositePrivateIdentityView noncanonical_private =
        private_view(fixture.client);
    noncanonical_private.ed25519_private_key_der =
        as_bytes(alternate_private);
    client_credentials.local_identity = noncanonical_private;
    check(!OpenSslSecurityProviderFactory::create_client(
               client_credentials).ok(),
          "noncanonical BER private-key encoding was accepted");
    client_credentials.local_identity = private_view(fixture.client);
    std::array<std::uint8_t, yume::ytp1::kPskSize> zero_psk{};
    client_credentials.access_psk = as_bytes(zero_psk);
    check(!OpenSslSecurityProviderFactory::create_client(
               client_credentials).ok(),
          "zero client PSK was accepted");
    client_credentials.access_psk = as_bytes(options.client_psk).first(31U);
    check(!OpenSslSecurityProviderFactory::create_client(
               client_credentials).ok(),
          "short client PSK was accepted");
    client_credentials.access_psk = as_bytes(options.client_psk);
    client_credentials.server_peer_identity = {};
    check(!OpenSslSecurityProviderFactory::create_client(
               client_credentials).ok(),
          "empty peer label was accepted");
    const std::string oversized_label(
        yume::engine::kMaxPeerIdentityBytes + 1U, 'x');
    client_credentials.server_peer_identity = oversized_label;
    check(!OpenSslSecurityProviderFactory::create_client(
               client_credentials).ok(),
          "oversized peer label was accepted");
    client_credentials.server_peer_identity = "server-peer";
    client_credentials.server_ml_kem_1024_public_key_der =
        as_bytes(fixture.server.ed_public);
    check(!OpenSslSecurityProviderFactory::create_client(
               client_credentials).ok(),
          "wrong server KEM algorithm was accepted");
    client_credentials.server_ml_kem_1024_public_key_der =
        as_bytes(fixture.server_kem_public);
    auto trailing_public = fixture.server.ed_public;
    trailing_public.push_back(0U);
    CompositePublicIdentityView noncanonical = public_view(fixture.server);
    noncanonical.ed25519_public_key_der = as_bytes(trailing_public);
    client_credentials.trusted_server_identity = noncanonical;
    check(!OpenSslSecurityProviderFactory::create_client(
               client_credentials).ok(),
          "noncanonical public DER was accepted");

    const AuthorizedIdentityView authorized{
        public_view(fixture.client), as_bytes(options.server_psk),
        "client-peer",
    };
    const std::array<AuthorizedIdentityView, 2> duplicates{
        authorized, authorized};
    ServerCredentialsView server_credentials{
        private_view(fixture.server), as_bytes(fixture.server_kem_private),
        duplicates,
    };
    check(!OpenSslSecurityProviderFactory::create_server(
               server_credentials).ok(),
          "duplicate authorized identity was accepted");
    server_credentials.ml_kem_1024_private_key_der =
        as_bytes(fixture.server.ed_private);
    check(!OpenSslSecurityProviderFactory::create_server(
               server_credentials).ok(),
          "wrong server KEM private algorithm was accepted");
    server_credentials.ml_kem_1024_private_key_der =
        as_bytes(fixture.server_kem_private);
    server_credentials.authorized_identities = {};
    check(!OpenSslSecurityProviderFactory::create_server(
               server_credentials).ok(),
          "empty authorized-identity set was accepted");
    std::vector<AuthorizedIdentityView> too_many(
        yume::providers::kMaxAuthorizedIdentities + 1U, authorized);
    server_credentials.authorized_identities = too_many;
    check(!OpenSslSecurityProviderFactory::create_server(
               server_credentials).ok(),
          "oversized authorized-identity set was accepted");

    auto pair = make_pair(fixture, default_options(fixture));
    pair.client->cancel();
    pair.client->cancel();
    check(pair.client->start_authentication().status().code() ==
              StatusCode::Cancelled,
          "cancelled provider accepted AUTH start");
    const std::array<std::byte, 1> byte{std::byte{0x01}};
    check(pair.client->seal_record({0U, 0U}, byte, 0U).status().code() ==
              StatusCode::Cancelled,
          "cancelled provider retained record state");

    auto established = make_pair(fixture, default_options(fixture));
    (void)complete_handshake(established);
    established.server->cancel();
    check(established.server->open_record({0U, 0U}, byte).status().code() ==
              StatusCode::Cancelled,
          "established cancellation retained inbound key state");
}

void test_crypto_backend_identity() {
    const std::string loaded =
        std::string("openssl-") + OpenSSL_version(OPENSSL_FULL_VERSION_STRING);
    const std::string_view reported =
        yume::providers::openssl_crypto_backend();
    check(reported.size() < 32U,
          "crypto backend identity does not fit a manifest field");
    check(reported.starts_with("openssl-3."),
          "crypto backend identity does not name an OpenSSL 3 release");
    check(std::string_view(loaded).starts_with(reported),
          "crypto backend identity does not name the loaded OpenSSL");
    check(reported.data() ==
              yume::providers::openssl_crypto_backend().data(),
          "crypto backend identity is not one stable value");
}

class CryptoVectors final {
public:
    CryptoVectors() {
        std::ifstream input(YUME_YTP1_CRYPTO_VECTORS_FILE);
        check(input.is_open(), "cannot open cryptographic vectors");
        std::string line;
        while (std::getline(input, line)) {
            if (line.empty() || line.front() == '#') {
                continue;
            }
            const auto separator = line.find('=');
            check(separator != std::string::npos && separator != 0U,
                  "invalid cryptographic vector entry");
            const std::string name = line.substr(0U, separator);
            const std::string_view encoded(line.data() + separator + 1U,
                                            line.size() - separator - 1U);
            check(encoded.size() % 2U == 0U && encoded.size() <= 65536U,
                  "invalid cryptographic vector size");
            std::vector<std::uint8_t> bytes;
            bytes.reserve(encoded.size() / 2U);
            for (std::size_t offset = 0U; offset < encoded.size(); offset += 2U) {
                const auto nibble = [](char value) -> std::uint8_t {
                    if (value >= '0' && value <= '9') {
                        return static_cast<std::uint8_t>(value - '0');
                    }
                    check(value >= 'a' && value <= 'f',
                          "invalid cryptographic vector hex");
                    return static_cast<std::uint8_t>(value - 'a' + 10);
                };
                bytes.push_back(static_cast<std::uint8_t>(
                    (nibble(encoded[offset]) << 4U) | nibble(encoded[offset + 1U])));
            }
            check(values_.emplace(name, std::move(bytes)).second,
                  "duplicate cryptographic vector entry");
        }
        check(input.eof(), "cryptographic vector read failed");
    }

    const std::vector<std::uint8_t>& get(std::string_view name) const {
        const auto found = values_.find(name);
        check(found != values_.end(), "missing cryptographic vector entry");
        return found->second;
    }

    void matches(std::string_view name,
                 std::span<const std::uint8_t> actual) const {
        const auto& expected = get(name);
        check(std::equal(actual.begin(), actual.end(), expected.begin(),
                         expected.end()),
              std::string("cryptographic known-answer mismatch: ") +
                  std::string(name));
    }

private:
    std::map<std::string, std::vector<std::uint8_t>, std::less<>> values_;
};

void test_cryptographic_known_answers() {
    namespace crypto = yume::providers::ytp1_crypto;
    const CryptoVectors vectors;
    const crypto::CryptoContext context;
    const auto value = [&vectors](std::string_view name)
        -> const std::vector<std::uint8_t>& { return vectors.get(name); };
    const auto digest_matches = [&](std::string_view name,
                                    std::span<const std::uint8_t> bytes) {
        vectors.matches(name, crypto::sha256(context, {bytes}));
    };
    const auto challenge_context = crypto::challenge_context(
        value("exporter"), value("server_identity"), value("ml_public"),
        value("server_x_public"), value("server_capabilities"),
        value("challenge_nonce"));
    const auto challenge_digest = crypto::sha256(context, {challenge_context});
    vectors.matches("challenge_context_sha256", challenge_digest);

    yume::ytp1::AuthRecord challenge;
    challenge.type = yume::ytp1::AuthMessageType::Challenge;
    challenge.sender_role = yume::ytp1::EndpointRole::Server;
    const auto add = [&](yume::ytp1::AuthFieldId id,
                         std::span<const std::uint8_t> bytes) {
        challenge.fields.push_back(
            {static_cast<std::uint16_t>(id), true, {bytes.begin(), bytes.end()}});
    };
    add(yume::ytp1::AuthFieldId::TranscriptHash, challenge_digest);
    add(yume::ytp1::AuthFieldId::Identity, value("server_identity"));
    add(yume::ytp1::AuthFieldId::CompositeSignature,
        value("challenge_signature_octets"));
    add(yume::ytp1::AuthFieldId::MlKemPublicKey, value("ml_public"));
    add(yume::ytp1::AuthFieldId::X25519PublicKey, value("server_x_public"));
    add(yume::ytp1::AuthFieldId::CapabilityManifest, value("server_capabilities"));
    add(yume::ytp1::AuthFieldId::Nonce, value("challenge_nonce"));
    const auto encoded_challenge = yume::ytp1::EncodeAuthRecord(challenge);
    check(encoded_challenge.ok(), "synthetic challenge encoding failed");
    const auto& challenge_wire = *encoded_challenge.value;
    digest_matches("challenge_wire_sha256", challenge_wire);
    const auto response = crypto::response_context(
        challenge_wire, value("client_identity"), value("ml_ciphertext"),
        value("client_x_public"), value("client_capabilities"));
    digest_matches("response_context_sha256", response);
    const std::array<std::span<const std::uint8_t>, 2> messages{
        challenge_wire, response};
    const auto transcript = crypto::transcript_hash(
        context, value("exporter"), messages);
    vectors.matches("transcript", transcript);

    const yume::ytp1::KeyScheduleInput input{
        yume::ytp1::EndpointRole::Client, yume::ytp1::EndpointRole::Server,
        transcript, value("exporter"), value("client_identity"),
        value("server_identity"), value("client_capabilities"),
        value("server_capabilities"), value("access_contribution"),
        value("client_x_public"), value("server_x_public"),
        value("x_shared_contribution"), value("ml_public"),
        value("ml_ciphertext"), value("ml_shared_contribution"),
    };
    const auto schedule_size = yume::ytp1::KeyScheduleInputEncodedSize(input);
    check(schedule_size.ok(), "known-answer schedule size failed");
    crypto::SecretBytes schedule(*schedule_size.value);
    std::size_t written = 0U;
    check(yume::ytp1::EncodeKeyScheduleInput(input, schedule.mutable_span(),
                                           written).ok() &&
              written == schedule.size(),
          "known-answer schedule encoding failed");
    digest_matches("schedule_sha256", schedule.span());
    auto roots = crypto::derive_initial_roots(
        context, transcript, input.exporter, input.client_identity,
        input.server_identity, input.client_capability_manifest,
        input.server_capability_manifest, input.access_psk,
        input.client_x25519_public_key, input.server_x25519_public_key,
        input.x25519_shared_secret, input.mlkem_public_key,
        input.mlkem_ciphertext, input.mlkem_shared_secret);
    vectors.matches("master_root", roots.master.span());
    vectors.matches("c2s_root", roots.client_to_server.span());
    vectors.matches("s2c_root", roots.server_to_client.span());
    const auto psk = crypto::hmac_sha256(
        context, input.access_psk, crypto::psk_authenticator_input(
            crypto::ConfirmationPurpose::Response, transcript));
    vectors.matches("response_psk_authenticator", psk);
    const auto response_confirmation = crypto::hmac_sha256(
        context, roots.master.span(), crypto::key_confirmation_input(
            crypto::ConfirmationPurpose::Response, transcript));
    const auto accepted_confirmation = crypto::hmac_sha256(
        context, roots.master.span(), crypto::key_confirmation_input(
            crypto::ConfirmationPurpose::Accepted, transcript));
    vectors.matches("response_confirmation", response_confirmation);
    vectors.matches("accepted_confirmation", accepted_confirmation);
    const std::array<std::span<const std::uint8_t>, 2> proof_fields{
        psk, response_confirmation};
    const auto proofs = crypto::canonical_tagged_input(
        yume::ytp1::kAuthSignatureDomain, proof_fields);
    digest_matches("challenge_signature_input_sha256", crypto::signature_input(
        EndpointRole::Server, yume::ytp1::AuthMessageType::Challenge,
        input.exporter, challenge_digest));
    digest_matches("response_signature_input_sha256", crypto::signature_input(
        EndpointRole::Client, yume::ytp1::AuthMessageType::Response,
        input.exporter, transcript, proofs));
    digest_matches("accepted_signature_input_sha256", crypto::signature_input(
        EndpointRole::Server, yume::ytp1::AuthMessageType::Accepted,
        input.exporter, transcript, accepted_confirmation));

    const auto record = [&](const std::string& name, EndpointRole direction,
                            std::span<const std::uint8_t> root,
                            RecordKeyToken token,
                            std::span<const std::uint8_t> plaintext) {
        const auto aad = crypto::record_aad(direction, token);
        vectors.matches(name + "_aad", aad);
        crypto::RecordEpochRoot epoch_root(
            context, crypto::SecretBytes::copy_from(root), transcript);
        auto material = crypto::derive_record_material(
            context, epoch_root, direction, token, transcript);
        vectors.matches(name + "_material", material.span());
        const auto key = material.span().first(crypto::kAes256KeyBytes);
        const auto nonce = material.span().subspan(crypto::kAes256KeyBytes);
        std::vector<std::uint8_t> sealed(plaintext.size() +
                                         crypto::kAesGcmTagBytes);
        crypto::seal_aes_gcm(context, key, nonce, aad, plaintext, sealed);
        vectors.matches(name + "_ciphertext", sealed);
        const auto opened = crypto::open_aes_gcm(
            context, key, nonce, aad, value(name + "_ciphertext"));
        check(std::equal(opened.begin(), opened.end(), plaintext.begin(),
                         plaintext.end()), "known-answer record open failed");
    };
    for (const auto direction : {EndpointRole::Client, EndpointRole::Server}) {
        const std::string name = direction == EndpointRole::Client ? "c2s" : "s2c";
        const auto old_root = direction == EndpointRole::Client
            ? roots.client_to_server.span() : roots.server_to_client.span();
        record(name + "_first", direction, old_root, {0U, 0U}, value("plaintext"));
        record(name + "_wide", direction, old_root,
               {0x01020304U, 0x0102030405060708ULL}, value("plaintext"));
        record(name + "_empty", direction, old_root, {0U, 1U}, {});
        const auto init_input = crypto::rekey_init_auth_input(
            direction, 1U, transcript, value("rekey_ml_public"),
            value("rekey_initiator_x_public"), value("rekey_nonce"));
        digest_matches(name + "_rekey_init_input_sha256", init_input);
        const auto init_auth = crypto::hmac_sha256(context, old_root, init_input);
        vectors.matches(name + "_rekey_init_authenticator", init_auth);
        const auto& init_context = value(name + "_rekey_init_context");
        const auto ack_input = crypto::rekey_ack_auth_input(
            direction, 1U, transcript, init_context, value("rekey_ml_ciphertext"),
            value("rekey_responder_x_public"));
        digest_matches(name + "_rekey_ack_input_sha256", ack_input);
        auto new_root = crypto::derive_rekey_root(
            context, old_root, direction, 1U, transcript, init_context,
            value("rekey_ml_ciphertext"), value("rekey_responder_x_public"),
            value("rekey_x_shared_contribution"),
            value("rekey_ml_shared_contribution"));
        vectors.matches(name + "_rekey_root", new_root.span());
        const auto ack_auth = crypto::hmac_sha256(context, new_root.span(), ack_input);
        vectors.matches(name + "_rekey_ack_authenticator", ack_auth);
        std::vector<std::uint8_t> init = init_context;
        init.insert(init.end(), init_auth.begin(), init_auth.end());
        check(init.size() == yume::ytp1::kRekeyInitMessageBytes,
              "known-answer INIT length mismatch");
        digest_matches(name + "_rekey_init_sha256", init);
        std::vector<std::uint8_t> ack{
            1U, 2U, static_cast<std::uint8_t>(crypto::to_ytp_role(direction)), 0U};
        crypto::append_u32(ack, 1U);
        for (const auto part : {std::span<const std::uint8_t>(value("rekey_ml_ciphertext")),
                                std::span<const std::uint8_t>(value("rekey_responder_x_public")),
                                std::span<const std::uint8_t>(ack_auth)}) {
            ack.insert(ack.end(), part.begin(), part.end());
        }
        check(ack.size() == yume::ytp1::kRekeyAckMessageBytes,
              "known-answer ACK length mismatch");
        digest_matches(name + "_rekey_ack_sha256", ack);
        record(name + "_rekey_first", direction, new_root.span(),
               {1U, 2U}, value("plaintext"));
    }
}

// The probe reads only live 32-byte allocations or storage just before
// delete. Matching HMAC(binding, root) to another allocation identifies the
// provider's root/extract pairs without exposing production secret handles.
class EpochStorageProbe final {
public:
    EpochStorageProbe() {
        check(active_ == nullptr, "nested epoch storage probe");
        active_ = this;
        yume::test::after_allocate = &allocated;
        yume::test::before_deallocate = &released;
    }
    ~EpochStorageProbe() {
        yume::test::after_allocate = nullptr;
        yume::test::before_deallocate = nullptr;
        active_ = nullptr;
    }
    EpochStorageProbe(const EpochStorageProbe&) = delete;
    EpochStorageProbe& operator=(const EpochStorageProbe&) = delete;

    void watch(std::span<const std::uint8_t> bytes) {
        check(bytes.size() == 32U, "epoch probe size differs");
        for (auto& entry : entries_) {
            if (entry.storage == bytes.data()) {
                select(entry);
                return;
            }
        }
        check(false, "epoch storage was not observed at allocation");
    }

    void watch_roots(const yume::providers::ytp1_crypto::CryptoContext& crypto,
                     std::span<const std::uint8_t> binding) {
        for (auto& root : entries_) {
            if (root.storage == nullptr || zero(root.storage)) continue;
            auto extract = yume::providers::ytp1_crypto::hmac_sha256(
                crypto, binding, {root.storage, 32U});
            for (auto& candidate : entries_) {
                if (candidate.storage != nullptr &&
                    candidate.storage != root.storage &&
                    std::equal(extract.begin(), extract.end(),
                               candidate.storage)) {
                    select(root);
                    select(candidate);
                }
            }
            OPENSSL_cleanse(extract.data(), extract.size());
        }
        check(!overflow_, "epoch allocation probe overflowed");
    }

    void watch_new_secrets(bool watch) noexcept { watch_new_ = watch; }

    std::size_t selected() const noexcept { return selected_; }
    std::size_t cleared() const {
        check(!overflow_ && !dirty_release_,
              "epoch secret released without wiping");
        std::size_t count = released_;
        for (const auto& entry : entries_) {
            if (entry.storage != nullptr && entry.watched &&
                zero(entry.storage))
                ++count;
        }
        return count;
    }

private:
    struct Entry final {
        std::uint8_t* storage{nullptr};
        bool watched{false};
    };
    static bool zero(const std::uint8_t* storage) noexcept {
        for (std::size_t index = 0U; index < 32U; ++index) {
            if (storage[index] != 0U) return false;
        }
        return true;
    }
    void select(Entry& entry) noexcept {
        if (!entry.watched) {
            entry.watched = true;
            ++selected_;
        }
    }
    static void allocated(void* storage, std::size_t size) {
        if (size != 32U) return;
        for (auto& entry : active_->entries_) {
            if (entry.storage == nullptr) {
                entry = {static_cast<std::uint8_t*>(storage), false};
                if (active_->watch_new_) active_->select(entry);
                return;
            }
        }
        active_->overflow_ = true;
    }
    static void released(void* storage) noexcept {
        for (auto& entry : active_->entries_) {
            if (entry.storage == storage) {
                if (entry.watched) {
                    ++active_->released_;
                    active_->dirty_release_ |= !zero(entry.storage);
                }
                entry = {};
                return;
            }
        }
    }
    inline static thread_local EpochStorageProbe* active_{nullptr};
    std::array<Entry, 256U> entries_{};
    std::size_t selected_{0U};
    std::size_t released_{0U};
    bool dirty_release_{false};
    bool overflow_{false};
    bool watch_new_{false};
};

std::array<std::uint8_t, 32U> handshake_binding(const HandshakeFlight& flight) {
    auto decoded = yume::ytp1::DecodeAuthRecord(as_u8(flight.response));
    check(decoded.ok(), "cache fixture AUTH response did not decode");
    for (const auto& field : decoded.value->fields) {
        if (field.id == static_cast<std::uint16_t>(
                            yume::ytp1::AuthFieldId::TranscriptHash)) {
            check(field.value.size() == 32U,
                  "cache fixture binding size differs");
            std::array<std::uint8_t, 32U> binding{};
            std::copy(field.value.begin(), field.value.end(), binding.begin());
            return binding;
        }
    }
    throw std::runtime_error("cache fixture has no session binding");
}

void test_epoch_cache_lifetime() {
    namespace crypto = yume::providers::ytp1_crypto;
    static_assert(!std::is_copy_constructible_v<crypto::RecordEpochRoot>);
    static_assert(!std::is_copy_assignable_v<crypto::RecordEpochRoot>);
    static_assert(
        std::is_nothrow_move_constructible_v<crypto::RecordEpochRoot>);
    static_assert(std::is_nothrow_move_assignable_v<crypto::RecordEpochRoot>);
    const crypto::CryptoContext context;
    std::array<std::uint8_t, 32U> binding{}, a{}, b{};
    binding.fill(0x12U);
    a.fill(0x34U);
    b.fill(0x56U);
    EpochStorageProbe probe;
    {
        crypto::RecordEpochRoot first(
            context, crypto::SecretBytes::copy_from(a), binding);
        crypto::RecordEpochRoot second(
            context, crypto::SecretBytes::copy_from(b), binding);
        probe.watch_roots(context, binding);
        check(probe.selected() == 4U && probe.cleared() == 0U,
              "epoch cache pair was not observed");
        const auto first_storage = first.span().data();
        crypto::RecordEpochRoot moved(std::move(first));
        check(first.span().empty() && moved.span().data() == first_storage,
              "epoch cache move did not transfer ownership");
        const auto expected = crypto::derive_record_material(
            context, second, EndpointRole::Client, {7U, 11U}, binding);
        moved = std::move(second);
        check(second.span().empty() && probe.cleared() == 2U,
              "epoch cache replacement did not wipe the old pair");
        auto* alias = &moved;
        moved = std::move(*alias);
        const auto material = crypto::derive_record_material(
            context, moved, EndpointRole::Client, {7U, 11U}, binding);
        check(std::equal(material.span().begin(), material.span().end(),
                         expected.span().begin()),
              "epoch cache move changed record material");
        moved.wipe();
        check(moved.span().empty() && probe.cleared() == 4U,
              "epoch cache retirement did not wipe both secrets");
        bool refused = false;
        try {
            (void)crypto::derive_record_material(
                context, moved, EndpointRole::Client, {}, binding);
        } catch (const std::invalid_argument&) {
            refused = true;
        }
        check(refused, "retired epoch cache still derived a record key");
    }
    check(probe.cleared() == 4U, "epoch cache destruction missed a secret");
}

void test_epoch_cache_constructor_failure() {
    namespace crypto = yume::providers::ytp1_crypto;
    const crypto::CryptoContext context;
    std::array<std::uint8_t, 32U> binding{}, bytes{};
    binding.fill(0x67U);
    bytes.fill(0x89U);
    for (const bool allocation_failure : {false, true}) {
        EpochStorageProbe probe;
        auto root = crypto::SecretBytes::copy_from(bytes);
        probe.watch(root.span());
        bool refused = false;
        if (allocation_failure) yume::test::arm_allocation_failure(1U);
        try {
            crypto::RecordEpochRoot candidate(
                context, std::move(root),
                allocation_failure
                    ? std::span<const std::uint8_t>(binding)
                    : std::span<const std::uint8_t>(binding).first(31U));
        } catch (const std::bad_alloc&) {
            refused = allocation_failure;
        } catch (const std::invalid_argument&) {
            refused = !allocation_failure;
        }
        const bool fired =
            allocation_failure && yume::test::disarm_allocation_failure();
        check(refused && (!allocation_failure || fired),
              "epoch cache constructor fault was not reached");
        check(root.span().empty() && probe.cleared() == 1U,
              "epoch cache constructor failure retained its root");
    }
}

void test_epoch_cache_provider_retirement(const Fixture& fixture) {
    namespace crypto = yume::providers::ytp1_crypto;
    const crypto::CryptoContext context;
    auto pair = make_pair(fixture, default_options(fixture));
    EpochStorageProbe probe;
    const auto binding = handshake_binding(complete_handshake(pair));
    probe.watch_roots(context, binding);
    check(probe.selected() == 8U && probe.cleared() == 0U,
          "established provider did not retain four root/extract pairs");
    auto init =
        require(pair.client->begin_outbound_rekey(1U), "cache retirement INIT");
    auto wire = require(pair.client->seal_record({0U, 0U}, init.bytes(), 0U),
                        "cache retirement INIT seal");
    auto opened = require(pair.server->open_record({0U, 0U}, wire.bytes()),
                          "cache retirement INIT open");
    auto ack = require(pair.server->accept_inbound_rekey(1U, opened.bytes()),
                       "cache retirement ACK");
    probe.watch_roots(context, binding);
    check(probe.selected() == 10U && probe.cleared() == 0U,
          "inbound rekey retired an old pair before the new epoch");
    check_record_round_trip(*pair.client, *pair.server, {0U, 1U},
                            "old cache retained");
    check(probe.cleared() == 0U,
          "old-epoch DATA prematurely retired its cache");
    check(pair.client->finish_outbound_rekey(1U, ack.bytes()).ok(),
          "cache retirement finish failed");
    probe.watch_roots(context, binding);
    check(probe.selected() == 12U && probe.cleared() == 2U,
          "outbound rekey did not retire exactly its old pair");
    check_record_round_trip(*pair.client, *pair.server, {1U, 2U},
                            "new cache authenticated");
    check(
        probe.cleared() == 4U,
        "first authenticated new-epoch record did not wipe the previous cache");
    pair.client->cancel();
    pair.server->cancel();
    check(probe.cleared() == 12U,
          "provider cancellation retained an epoch secret");
    pair.client.reset();
    pair.server.reset();
    check(probe.cleared() == 12U,
          "provider destruction released an unwiped epoch secret");

    auto failed = make_pair(fixture, default_options(fixture));
    const auto failed_binding = handshake_binding(complete_handshake(failed));
    probe.watch_roots(context, failed_binding);
    check(probe.selected() == 20U,
          "failed-record fixture has no cached epochs");
    const std::array<std::byte, 1U> plaintext{std::byte{0x5a}};
    auto damaged = require(failed.client->seal_record({}, plaintext, 0U),
                           "cache tag failure seal");
    damaged.mutable_bytes().back() ^= std::byte{1};
    check(!failed.server->open_record({}, damaged.bytes()).ok(),
          "cache tag failure was accepted");
    check(probe.cleared() == 16U,
          "failed authentication retained inbound or outbound cache");
    failed.client->cancel();
    failed.server->cancel();
    failed.client.reset();
    failed.server.reset();
    check(probe.cleared() == 20U,
          "failed provider teardown missed an epoch secret");
}

// A fresh fixture for each position sweeps every ordinary C++ allocation
// in both AUTH commits, record expansion and both rekey commits. Arguments
// exist before arming. OpenSSL's own malloc family is outside these hooks.
void test_epoch_cache_allocation_failures(const Fixture& fixture) {
    namespace crypto = yume::providers::ytp1_crypto;
    const crypto::CryptoContext context;
    enum class Operation { ServerAuth, ClientAuth, Seal, Open, Accept, Finish };
    const std::array operations{Operation::ServerAuth, Operation::ClientAuth,
                                Operation::Seal,       Operation::Open,
                                Operation::Accept,     Operation::Finish};
    const std::array<std::byte, 3U> plaintext{std::byte{1}, std::byte{2},
                                              std::byte{3}};
    for (const auto operation : operations) {
        bool completed_sweep = false;
        std::size_t failures = 0U;
        for (std::size_t position = 1U; position <= 1024U; ++position) {
            auto pair = make_pair(fixture, default_options(fixture));
            EpochStorageProbe probe;
            HandshakeFlight flight;
            if (operation == Operation::ServerAuth ||
                operation == Operation::ClientAuth) {
                flight.challenge = begin_handshake(pair);
                auto response = require(
                    pair.client->process_authentication(
                        AuthenticationMessageKind::Challenge, flight.challenge),
                    "fault fixture response");
                flight.response =
                    outgoing(response, AuthenticationMessageKind::Response);
                if (operation == Operation::ClientAuth) {
                    flight.server_output =
                        require(pair.server->process_authentication(
                                    AuthenticationMessageKind::Response,
                                    flight.response),
                                "fault fixture acceptance");
                    flight.accepted =
                        outgoing(flight.server_output,
                                 AuthenticationMessageKind::Accepted);
                }
            } else {
                flight = complete_handshake(pair);
            }
            const auto binding = handshake_binding(flight);
            probe.watch_roots(context, binding);
            const std::size_t expected = operation == Operation::ServerAuth ? 0U
                                         : operation == Operation::ClientAuth
                                             ? 6U
                                             : 8U;
            check(probe.selected() == expected,
                  "allocation fixture cache premises differ");

            auto argument = require(yume::engine::Buffer::allocate(0U, 4096U),
                                    "empty fault argument");
            if (operation == Operation::Open) {
                argument = require(pair.client->seal_record({}, plaintext, 0U),
                                   "fault fixture ciphertext");
            } else if (operation == Operation::Accept ||
                       operation == Operation::Finish) {
                auto init = require(pair.client->begin_outbound_rekey(1U),
                                    "fault fixture INIT");
                auto wire =
                    require(pair.client->seal_record({}, init.bytes(), 0U),
                            "fault fixture INIT seal");
                argument = require(pair.server->open_record({}, wire.bytes()),
                                   "fault fixture INIT open");
                if (operation == Operation::Finish) {
                    argument = require(
                        pair.server->accept_inbound_rekey(1U, argument.bytes()),
                        "fault fixture ACK");
                    probe.watch_roots(context, binding);
                    check(probe.selected() == 10U && probe.cleared() == 0U,
                          "finish fault fixture did not retain the old inbound "
                          "epoch");
                }
            }
            // Form spans and select the operation before fault injection.
            const auto bytes = argument.bytes();
            yume::test::arm_allocation_failure(position);
            bool ok = false;
            switch (operation) {
                case Operation::ServerAuth:
                    ok = pair.server
                             ->process_authentication(
                                 AuthenticationMessageKind::Response,
                                 flight.response)
                             .ok();
                    break;
                case Operation::ClientAuth:
                    ok = pair.client
                             ->process_authentication(
                                 AuthenticationMessageKind::Accepted,
                                 flight.accepted)
                             .ok();
                    break;
                case Operation::Seal:
                    ok = pair.client->seal_record({}, plaintext, 0U).ok();
                    break;
                case Operation::Open:
                    ok = pair.server->open_record({}, bytes).ok();
                    break;
                case Operation::Accept:
                    ok = pair.server->accept_inbound_rekey(1U, bytes).ok();
                    break;
                case Operation::Finish:
                    ok = pair.client->finish_outbound_rekey(1U, bytes).ok();
                    break;
            }
            const bool fired = yume::test::disarm_allocation_failure();
            check(ok != fired,
                  "allocation fault was swallowed or fault-free operation "
                  "failed");
            probe.watch_roots(context, binding);
            if (fired && operation != Operation::ServerAuth) {
                // Only the peer's live roots may remain after a refusal.
                // Client AUTH leaves four server secrets. Finishing an
                // outbound rekey leaves six at the server until new DATA.
                const std::size_t peer_secrets =
                    operation == Operation::Finish ? 6U : 4U;
                check(probe.cleared() + peer_secrets == probe.selected(),
                      "allocation refusal retained the failed provider's "
                      "epoch cache");
            }
            pair.client->cancel();
            pair.server->cancel();
            check(probe.cleared() == probe.selected(),
                  "allocation failure or teardown retained an epoch cache");
            pair.client.reset();
            pair.server.reset();
            check(probe.cleared() == probe.selected(),
                  "allocation failure released an unwiped epoch cache");
            if (!fired) {
                completed_sweep = true;
                break;
            }
            ++failures;
        }
        check(completed_sweep && failures > 0U,
              "allocation sweep did not reach every position");
        std::cout << "Epoch cache allocation sweep "
                  << static_cast<int>(operation) << ": " << failures
                  << " faults checked\n";
    }
}

thread_local std::size_t openssl_allocation_countdown = 0U;
thread_local bool openssl_allocation_fired = false;

bool fail_openssl_allocation() noexcept {
    if (openssl_allocation_countdown == 0U) return false;
    if (--openssl_allocation_countdown != 0U) return false;
    openssl_allocation_fired = true;
    return true;
}

void* test_openssl_malloc(std::size_t size, const char*, int) {
    return fail_openssl_allocation() ? nullptr : std::malloc(size);
}

void* test_openssl_realloc(void* storage, std::size_t size, const char*, int) {
    return fail_openssl_allocation() ? nullptr : std::realloc(storage, size);
}

void test_openssl_free(void* storage, const char*, int) {
    std::free(storage);
}

void test_epoch_cache_openssl_allocation_failures() {
    namespace crypto = yume::providers::ytp1_crypto;
    const crypto::CryptoContext context;
    std::array<std::uint8_t, 32U> binding{}, bytes{};
    binding.fill(0x9aU);
    bytes.fill(0xbcU);
    crypto::RecordEpochRoot reference(
        context, crypto::SecretBytes::copy_from(bytes), binding);
    const auto expected = crypto::derive_record_material(
        context, reference, EndpointRole::Server, {3U, 19U}, binding);
    bool complete = false;
    std::size_t refusals = 0U;
    std::size_t faults = 0U;
    for (std::size_t position = 1U; position <= 1024U; ++position) {
        EpochStorageProbe probe;
        auto root = crypto::SecretBytes::copy_from(bytes);
        probe.watch(root.span());
        // Only the constructor runs while all new 32-byte C++ allocations
        // are watched: its one extract output, including a partial output
        // from a failing EVP_KDF_derive, must be wiped before release.
        probe.watch_new_secrets(true);
        ERR_clear_error();
        openssl_allocation_countdown = position;
        openssl_allocation_fired = false;
        std::optional<crypto::RecordEpochRoot> candidate;
        bool refused = false;
        try {
            candidate.emplace(context, std::move(root), binding);
        } catch (const std::exception&) {
            refused = true;
        }
        const bool fired = openssl_allocation_fired;
        openssl_allocation_countdown = 0U;
        probe.watch_new_secrets(false);
        ERR_clear_error();
        check(!refused || fired,
              "fault-free OpenSSL cache construction failed");
        if (candidate) {
            const auto material = crypto::derive_record_material(
                context, *candidate, EndpointRole::Server, {3U, 19U}, binding);
            check(std::equal(material.span().begin(), material.span().end(),
                             expected.span().begin()),
                  "OpenSSL allocation fault changed cached record material");
        }
        candidate.reset();
        check(root.span().empty() && probe.cleared() == probe.selected(),
              "OpenSSL allocation failure retained root or partial extract");
        if (!fired) {
            complete = true;
            break;
        }
        ++faults;
        if (refused) ++refusals;
    }
    check(complete && refusals > 0U,
          "OpenSSL constructor allocation sweep was incomplete");
    std::cout << "Epoch cache OpenSSL allocation sweep: " << faults
              << " faults checked, " << refusals << " refusals\n";
}

}  // namespace

int main(int argc, char** argv) {
    try {
        check(
            CRYPTO_set_mem_functions(test_openssl_malloc, test_openssl_realloc,
                                     test_openssl_free) == 1,
            "OpenSSL allocation hooks were installed too late");
        ProviderPtr provider(OSSL_PROVIDER_load(nullptr, "default"));
        check(provider != nullptr, "OpenSSL default provider is unavailable");
        const Fixture fixture;
        const std::string_view selection = argc == 2 ? argv[1] : "";
        check(argc <= 2, "too many test arguments");
        if (!selection.empty()) {
            if (selection == "--epoch-cache-lifetime")
                test_epoch_cache_lifetime();
            else if (selection == "--epoch-cache-constructor")
                test_epoch_cache_constructor_failure();
            else if (selection == "--epoch-cache-retirement")
                test_epoch_cache_provider_retirement(fixture);
            else if (selection == "--epoch-cache-allocation")
                test_epoch_cache_allocation_failures(fixture);
            else if (selection == "--epoch-cache-openssl-allocation")
                test_epoch_cache_openssl_allocation_failures();
            else if (selection == "--epoch-cache-vectors")
                test_cryptographic_known_answers();
            else
                throw std::runtime_error("unknown test selection");
            std::cout << "Selected epoch cache test passed\n";
            return 0;
        }
        test_epoch_cache_lifetime();
        test_epoch_cache_constructor_failure();
        test_epoch_cache_provider_retirement(fixture);
        test_epoch_cache_allocation_failures(fixture);
        test_epoch_cache_openssl_allocation_failures();
        test_full_handshake_and_records(fixture);
        test_record_fail_closed(fixture);
        test_bidirectional_rekey(fixture);
        test_old_epoch_open_until_the_first_new_record(fixture);
        test_authentication_failures(fixture);
        test_component_mutation_and_stripping(fixture);
        test_factory_bounds_and_cancellation(fixture);
        test_crypto_backend_identity();
        test_cryptographic_known_answers();
        std::cout << "YTP/1 OpenSSL security-provider tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "YTP/1 OpenSSL security-provider test failed: "
                  << error.what() << '\n';
        return 1;
    }
}
