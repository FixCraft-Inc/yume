/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/ytp1_security_provider.hpp"

#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/x509.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "ytp/protocol.hpp"
#include "ytp/security.hpp"

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
using yume::providers::Ytp1ClientCredentialsView;
using yume::providers::Ytp1AuthorizedIdentityView;
using yume::providers::Ytp1OpenSslSecurityProviderFactory;
using yume::providers::Ytp1ServerCredentialsView;

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
    const Ytp1ClientCredentialsView client_credentials{
        private_view(fixture.client), public_view(*options.trusted_server),
        as_bytes(fixture.server_kem_public), as_bytes(options.client_psk),
        "server-peer",
    };
    const Ytp1AuthorizedIdentityView authorized{
        public_view(*options.authorized_client), as_bytes(options.server_psk),
        "client-peer",
    };
    const std::array<Ytp1AuthorizedIdentityView, 1> authorized_identities{authorized};
    const Ytp1ServerCredentialsView server_credentials{
        private_view(fixture.server), as_bytes(fixture.server_kem_private),
        authorized_identities,
    };
    auto client_factory = require(
        Ytp1OpenSslSecurityProviderFactory::create_client(
            client_credentials),
        "client factory");
    auto server_factory = require(
        Ytp1OpenSslSecurityProviderFactory::create_server(
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
    auto sealed = require(sender.seal_record(token, plaintext),
                          "record seal");
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
        auto sealed = require(pair.client->seal_record({0U, 0U}, payload),
                              "negative record seal");
        check(!pair.client->seal_record({0U, 0U}, payload).ok(),
              "one-use outbound token was reusable");
        check(!pair.client->seal_record({0U, 1U}, payload).ok(),
              "failed provider retained secret record state");
        (void)sealed;
    }
    {
        auto pair = make_pair(fixture, default_options(fixture));
        (void)complete_handshake(pair);
        const std::array<std::byte, 1> payload{std::byte{0x42}};
        auto sealed = require(pair.client->seal_record({0U, 0U}, payload),
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
        auto sealed = require(pair.client->seal_record({0U, 0U}, payload),
                              "mutation seal");
        sealed.mutable_bytes()[0] ^= std::byte{0x01};
        check(!pair.server->open_record({0U, 0U}, sealed.bytes()).ok(),
              "mutated record ciphertext was accepted");
    }
    {
        auto pair = make_pair(fixture, default_options(fixture));
        (void)complete_handshake(pair);
        const std::array<std::byte, 1> payload{std::byte{0x44}};
        check(!pair.client->seal_record({0U, 1U}, payload).ok(),
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
    auto sealed_client_init = require(pair.client->seal_record(
        {0U, 0U}, client_init.bytes()), "client rekey INIT seal");
    auto sealed_server_init = require(pair.server->seal_record(
        {0U, 0U}, server_init.bytes()), "server rekey INIT seal");
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
    auto sequential_client_wire = require(sequential.client->seal_record(
        {0U, 0U}, sequential_client_init.bytes()),
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
    auto sequential_server_wire = require(sequential.server->seal_record(
        {0U, 0U}, sequential_server_init.bytes()),
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
    Ytp1ClientCredentialsView client_credentials{
        private_view(fixture.client), public_view(fixture.server),
        as_bytes(fixture.server_kem_public), as_bytes(options.client_psk),
        "server-peer",
    };
    check(Ytp1OpenSslSecurityProviderFactory::create_client(
              client_credentials).ok(),
          "canonical PKCS#8 private credentials were rejected");
    const auto alternate_private = overlong_ber_outer_length(
        fixture.client.ed_private);
    CompositePrivateIdentityView noncanonical_private =
        private_view(fixture.client);
    noncanonical_private.ed25519_private_key_der =
        as_bytes(alternate_private);
    client_credentials.local_identity = noncanonical_private;
    check(!Ytp1OpenSslSecurityProviderFactory::create_client(
               client_credentials).ok(),
          "noncanonical BER private-key encoding was accepted");
    client_credentials.local_identity = private_view(fixture.client);
    std::array<std::uint8_t, yume::ytp1::kPskSize> zero_psk{};
    client_credentials.access_psk = as_bytes(zero_psk);
    check(!Ytp1OpenSslSecurityProviderFactory::create_client(
               client_credentials).ok(),
          "zero client PSK was accepted");
    client_credentials.access_psk = as_bytes(options.client_psk).first(31U);
    check(!Ytp1OpenSslSecurityProviderFactory::create_client(
               client_credentials).ok(),
          "short client PSK was accepted");
    client_credentials.access_psk = as_bytes(options.client_psk);
    client_credentials.server_peer_identity = {};
    check(!Ytp1OpenSslSecurityProviderFactory::create_client(
               client_credentials).ok(),
          "empty peer label was accepted");
    const std::string oversized_label(
        yume::engine::kMaxPeerIdentityBytes + 1U, 'x');
    client_credentials.server_peer_identity = oversized_label;
    check(!Ytp1OpenSslSecurityProviderFactory::create_client(
               client_credentials).ok(),
          "oversized peer label was accepted");
    client_credentials.server_peer_identity = "server-peer";
    client_credentials.server_ml_kem_1024_public_key_der =
        as_bytes(fixture.server.ed_public);
    check(!Ytp1OpenSslSecurityProviderFactory::create_client(
               client_credentials).ok(),
          "wrong server KEM algorithm was accepted");
    client_credentials.server_ml_kem_1024_public_key_der =
        as_bytes(fixture.server_kem_public);
    auto trailing_public = fixture.server.ed_public;
    trailing_public.push_back(0U);
    CompositePublicIdentityView noncanonical = public_view(fixture.server);
    noncanonical.ed25519_public_key_der = as_bytes(trailing_public);
    client_credentials.trusted_server_identity = noncanonical;
    check(!Ytp1OpenSslSecurityProviderFactory::create_client(
               client_credentials).ok(),
          "noncanonical public DER was accepted");

    const Ytp1AuthorizedIdentityView authorized{
        public_view(fixture.client), as_bytes(options.server_psk),
        "client-peer",
    };
    const std::array<Ytp1AuthorizedIdentityView, 2> duplicates{
        authorized, authorized};
    Ytp1ServerCredentialsView server_credentials{
        private_view(fixture.server), as_bytes(fixture.server_kem_private),
        duplicates,
    };
    check(!Ytp1OpenSslSecurityProviderFactory::create_server(
               server_credentials).ok(),
          "duplicate authorized identity was accepted");
    server_credentials.ml_kem_1024_private_key_der =
        as_bytes(fixture.server.ed_private);
    check(!Ytp1OpenSslSecurityProviderFactory::create_server(
               server_credentials).ok(),
          "wrong server KEM private algorithm was accepted");
    server_credentials.ml_kem_1024_private_key_der =
        as_bytes(fixture.server_kem_private);
    server_credentials.authorized_identities = {};
    check(!Ytp1OpenSslSecurityProviderFactory::create_server(
               server_credentials).ok(),
          "empty authorized-identity set was accepted");
    std::vector<Ytp1AuthorizedIdentityView> too_many(
        yume::providers::kMaxYtp1AuthorizedIdentities + 1U, authorized);
    server_credentials.authorized_identities = too_many;
    check(!Ytp1OpenSslSecurityProviderFactory::create_server(
               server_credentials).ok(),
          "oversized authorized-identity set was accepted");

    auto pair = make_pair(fixture, default_options(fixture));
    pair.client->cancel();
    pair.client->cancel();
    check(pair.client->start_authentication().status().code() ==
              StatusCode::Cancelled,
          "cancelled provider accepted AUTH start");
    const std::array<std::byte, 1> byte{std::byte{0x01}};
    check(pair.client->seal_record({0U, 0U}, byte).status().code() ==
              StatusCode::Cancelled,
          "cancelled provider retained record state");

    auto established = make_pair(fixture, default_options(fixture));
    (void)complete_handshake(established);
    established.server->cancel();
    check(established.server->open_record({0U, 0U}, byte).status().code() ==
              StatusCode::Cancelled,
          "established cancellation retained inbound key state");
}

}  // namespace

int main() {
    try {
        ProviderPtr provider(OSSL_PROVIDER_load(nullptr, "default"));
        check(provider != nullptr, "OpenSSL default provider is unavailable");
        const Fixture fixture;
        test_full_handshake_and_records(fixture);
        test_record_fail_closed(fixture);
        test_bidirectional_rekey(fixture);
        test_authentication_failures(fixture);
        test_component_mutation_and_stripping(fixture);
        test_factory_bounds_and_cancellation(fixture);
        std::cout << "YTP/1 OpenSSL security-provider tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "YTP/1 OpenSSL security-provider test failed: "
                  << error.what() << '\n';
        return 1;
    }
}
