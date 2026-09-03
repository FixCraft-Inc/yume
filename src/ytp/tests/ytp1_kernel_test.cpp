/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "ytp/protocol.hpp"
#include "ytp/security.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

using namespace yume::ytp1;

int g_failures = 0;

#define CHECK(condition)                                                        \
    do {                                                                        \
        if (!(condition)) {                                                     \
            std::cerr << __FILE__ << ':' << __LINE__                            \
                      << ": check failed: " #condition << '\n';                \
            ++g_failures;                                                       \
        }                                                                       \
    } while (false)

template <typename T, typename U>
void CheckEqual(const T& actual,
                const U& expected,
                const char* expression,
                int line) {
    if (!(actual == expected)) {
        std::cerr << __FILE__ << ':' << line << ": equality failed: "
                  << expression << '\n';
        ++g_failures;
    }
}

#define CHECK_EQ(actual, expected)                                              \
    CheckEqual((actual), (expected), #actual " == " #expected, __LINE__)

[[nodiscard]] std::string Hex(std::span<const std::uint8_t> bytes) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (const std::uint8_t byte : bytes) {
        output << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return output.str();
}

void CheckHex(std::span<const std::uint8_t> actual,
              std::string_view expected,
              int line) {
    const std::string encoded = Hex(actual);
    if (encoded != expected) {
        std::cerr << __FILE__ << ':' << line << ": hex mismatch\nexpected: "
                  << expected << "\nactual:   " << encoded << '\n';
        ++g_failures;
    }
}

#define CHECK_HEX(actual, expected) CheckHex((actual), (expected), __LINE__)

[[nodiscard]] std::uint16_t ReadU16(std::span<const std::uint8_t> input,
                                    std::size_t offset) {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(input[offset]) << 8U) |
        input[offset + 1]);
}

[[nodiscard]] std::uint32_t ReadU32(std::span<const std::uint8_t> input,
                                    std::size_t offset) {
    return (static_cast<std::uint32_t>(input[offset]) << 24U) |
           (static_cast<std::uint32_t>(input[offset + 1]) << 16U) |
           (static_cast<std::uint32_t>(input[offset + 2]) << 8U) |
           input[offset + 3];
}

void WriteU16(std::span<std::uint8_t> output,
              std::size_t offset,
              std::uint16_t value) {
    output[offset] = static_cast<std::uint8_t>(value >> 8U);
    output[offset + 1] = static_cast<std::uint8_t>(value);
}

void WriteU32(std::span<std::uint8_t> output,
              std::size_t offset,
              std::uint32_t value) {
    output[offset] = static_cast<std::uint8_t>(value >> 24U);
    output[offset + 1] = static_cast<std::uint8_t>(value >> 16U);
    output[offset + 2] = static_cast<std::uint8_t>(value >> 8U);
    output[offset + 3] = static_cast<std::uint8_t>(value);
}

[[nodiscard]] std::vector<std::size_t> AuthFieldOffsets(
    std::span<const std::uint8_t> encoded) {
    std::vector<std::size_t> offsets;
    const std::size_t count = ReadU16(encoded, 2);
    std::size_t offset = 8;
    for (std::size_t i = 0; i < count; ++i) {
        offsets.push_back(offset);
        const std::size_t length = ReadU32(encoded, offset + 4);
        offset += 8 + length;
    }
    return offsets;
}

[[nodiscard]] std::uint64_t Fnv1a64(
    std::span<const std::uint8_t> input) noexcept {
    std::uint64_t hash = 0xcbf29ce484222325ULL;
    for (const std::uint8_t byte : input) {
        hash ^= byte;
        hash *= 0x100000001b3ULL;
    }
    return hash;
}

void TestStreamIdsAndFrameHeader() {
    const auto control = StreamId::FromWire(0);
    const auto client = StreamId::FromWire(1);
    const auto server = StreamId::FromWire(2);
    const auto max_client = StreamId::FromWire(kMaxStreamId);
    const auto max_server = StreamId::FromWire(kMaxStreamId - 1U);
    CHECK(control && control.value->is_control());
    CHECK(client && client.value->is_owned_by(EndpointRole::Client));
    CHECK(server && server.value->is_owned_by(EndpointRole::Server));
    CHECK(!client.value->is_owned_by(EndpointRole::Server));
    CHECK(!StreamId::FromWire(0x8000'0000U));
    CHECK_EQ(StreamId::FirstOwnedBy(EndpointRole::Client).value->value(), 1U);
    CHECK_EQ(StreamId::FirstOwnedBy(EndpointRole::Server).value->value(), 2U);
    CHECK_EQ(StreamId::FirstOwnedBy(static_cast<EndpointRole>(3)).status.code,
             ErrorCode::InvalidEnum);
    CHECK(max_client && !max_client.value->NextOwned());
    CHECK(max_server && !max_server.value->NextOwned());
    CHECK_EQ(max_client.value->NextOwned().status.code,
             ErrorCode::StreamIdExhausted);
    CHECK(ValidateOpenStreamOwner(*client.value, EndpointRole::Client));
    CHECK_EQ(ValidateOpenStreamOwner(*client.value, EndpointRole::Server).code,
             ErrorCode::WrongStreamOwner);
    CHECK_EQ(ValidateOpenStreamOwner(*control.value, EndpointRole::Client).code,
             ErrorCode::WrongStreamClass);

    FrameHeader header{RecordType::Data, 0, *client.value, 3};
    std::array<std::uint8_t, kFrameHeaderSize> encoded{};
    CHECK(EncodeFrameHeader(header, encoded));
    CHECK_HEX(encoded, "010500000000000100000003");
    const auto decoded = DecodeFrameHeader(encoded);
    CHECK(decoded);
    CHECK_EQ(decoded.value->type, RecordType::Data);
    CHECK_EQ(decoded.value->stream_id, *client.value);
    CHECK_EQ(decoded.value->payload_length, 3U);

    std::vector<std::uint8_t> record(encoded.begin(), encoded.end());
    record.insert(record.end(), {0xaa, 0xbb, 0xcc});
    const auto record_view = DecodeRecord(record);
    CHECK(record_view);
    CHECK_EQ(record_view.value->payload.size(), 3U);
    record.pop_back();
    CHECK_EQ(DecodeRecord(record).status.code, ErrorCode::Truncated);
    record.push_back(0xcc);
    record.push_back(0xdd);
    CHECK_EQ(DecodeRecord(record).status.code, ErrorCode::TrailingData);

    auto malformed = encoded;
    malformed[0] = 2;
    CHECK_EQ(DecodeFrameHeader(malformed).status.code,
             ErrorCode::UnsupportedVersion);
    malformed = encoded;
    malformed[2] = 1;
    CHECK_EQ(DecodeFrameHeader(malformed).status.code,
             ErrorCode::InvalidFlags);
    malformed = encoded;
    malformed[4] = 0x80;
    CHECK_EQ(DecodeFrameHeader(malformed).status.code,
             ErrorCode::InvalidStreamId);
    malformed = encoded;
    WriteU32(malformed, 8, kDefaultMaxFramePayload + 1U);
    CHECK_EQ(DecodeFrameHeader(malformed).status.code,
             ErrorCode::PayloadTooLarge);
    CHECK_EQ(DecodeFrameHeader(std::span<const std::uint8_t>(encoded).first(11))
                 .status.code,
             ErrorCode::Truncated);

    header.type = RecordType::Auth;
    CHECK_EQ(ValidateFrameHeader(header).code, ErrorCode::WrongStreamClass);
    header.type = RecordType::Data;
    header.stream_id = StreamId::Control();
    CHECK_EQ(ValidateFrameHeader(header).code, ErrorCode::WrongStreamClass);

    FrameHeader connection_credit{RecordType::ConnectionCredit, 0,
                                  StreamId::Control(), 4};
    FrameHeader stream_credit{RecordType::StreamCredit, 0, *server.value, 4};
    CHECK(ValidateFrameHeader(connection_credit));
    CHECK(ValidateFrameHeader(stream_credit));
}

Destination TcpDns(std::string name, std::uint16_t port) {
    Destination destination;
    destination.transport = TransportProtocol::Tcp;
    destination.address_kind = AddressKind::Dns;
    destination.dns_name = std::move(name);
    destination.port = port;
    return destination;
}

void TestOpenCodec() {
    OpenRequest named{ServiceKind::ByteStream, "echo", {}};
    const auto named_encoded = EncodeOpen(named);
    CHECK(named_encoded);
    CHECK_HEX(*named_encoded.value, "01010000000400006563686f");
    const auto named_decoded = DecodeOpen(*named_encoded.value);
    CHECK(named_decoded);
    CHECK_EQ(*named_decoded.value, named);

    OpenRequest tcp{ServiceKind::ByteStream, "direct.tcp",
                    TcpDns("example.com", 443)};
    const auto tcp_encoded = EncodeOpen(tcp);
    CHECK(tcp_encoded);
    CHECK_HEX(*tcp_encoded.value,
              "01010103000a000e6469726563742e74637001bb0b6578616d706c652e636f6d");
    const auto tcp_decoded = DecodeOpen(*tcp_encoded.value);
    CHECK(tcp_decoded);
    CHECK_EQ(*tcp_decoded.value, tcp);

    Destination udp_destination;
    udp_destination.transport = TransportProtocol::Udp;
    udp_destination.address_kind = AddressKind::Ipv4;
    udp_destination.address_length = 4;
    udp_destination.address[0] = 192;
    udp_destination.address[1] = 0;
    udp_destination.address[2] = 2;
    udp_destination.address[3] = 1;
    udp_destination.port = 53;
    OpenRequest udp{ServiceKind::Packet, "direct.udp", udp_destination};
    const auto udp_encoded = EncodeOpen(udp);
    CHECK(udp_encoded);
    CHECK_EQ(*DecodeOpen(*udp_encoded.value).value, udp);

    OpenRequest unicode{ServiceKind::ByteStream, "echo-\xf0\x9f\x8c\x99", {}};
    CHECK_EQ(EncodeOpen(unicode).status.code,
             ErrorCode::InvalidServiceName);
    OpenRequest invalid_utf8{ServiceKind::ByteStream, std::string("bad\xc0\x80", 5),
                             {}};
    CHECK_EQ(EncodeOpen(invalid_utf8).status.code,
             ErrorCode::InvalidServiceName);
    OpenRequest control_name{ServiceKind::ByteStream, "bad\nname", {}};
    CHECK_EQ(EncodeOpen(control_name).status.code,
             ErrorCode::InvalidServiceName);
    OpenRequest long_name{ServiceKind::ByteStream,
                          std::string(kMaxServiceNameBytes + 1, 'a'), {}};
    CHECK_EQ(EncodeOpen(long_name).status.code,
             ErrorCode::InvalidServiceName);
    OpenRequest maximum_name{ServiceKind::ByteStream,
                             std::string(kMaxServiceNameBytes, 'a'), {}};
    CHECK(EncodeOpen(maximum_name));

    OpenRequest wrong_transport{ServiceKind::ByteStream, "direct",
                                udp_destination};
    CHECK_EQ(EncodeOpen(wrong_transport).status.code,
             ErrorCode::InvalidDestination);
    OpenRequest zero_port{ServiceKind::ByteStream, "direct",
                          TcpDns("example.com", 0)};
    CHECK_EQ(EncodeOpen(zero_port).status.code, ErrorCode::InvalidPort);
    OpenRequest uppercase_dns{ServiceKind::ByteStream, "direct",
                              TcpDns("Example.com", 443)};
    CHECK_EQ(EncodeOpen(uppercase_dns).status.code,
             ErrorCode::InvalidDestination);
    OpenRequest bad_dns{ServiceKind::ByteStream, "direct",
                        TcpDns("-bad.example", 443)};
    CHECK_EQ(EncodeOpen(bad_dns).status.code,
             ErrorCode::InvalidDestination);

    auto malformed = *tcp_encoded.value;
    malformed.pop_back();
    CHECK_EQ(DecodeOpen(malformed).status.code, ErrorCode::Truncated);
    malformed = *tcp_encoded.value;
    malformed.push_back(0);
    CHECK_EQ(DecodeOpen(malformed).status.code, ErrorCode::TrailingData);
    malformed = *named_encoded.value;
    malformed[8] = 0xc0;
    CHECK_EQ(DecodeOpen(malformed).status.code, ErrorCode::InvalidUtf8);
    malformed = *tcp_encoded.value;
    malformed[2] = static_cast<std::uint8_t>(TransportProtocol::Udp);
    CHECK_EQ(DecodeOpen(malformed).status.code,
             ErrorCode::InvalidDestination);
    malformed = *tcp_encoded.value;
    WriteU16(malformed, 6, 1);
    malformed.resize(8 + 10 + 1);
    CHECK_EQ(DecodeOpen(malformed).status.code, ErrorCode::Truncated);
}

CapabilityManifest ExampleCapabilities() {
    return {{{"udp", ServiceKind::Packet, 4},
             {"echo", ServiceKind::ByteStream, 8}}};
}

void TestCapabilitiesAndCredit() {
    const auto encoded = EncodeCapabilityManifest(ExampleCapabilities());
    CHECK(encoded);
    CHECK_HEX(*encoded.value,
              "0100000201000004000000086563686f0200000300000004756470");
    const auto decoded = DecodeCapabilityManifest(*encoded.value);
    CHECK(decoded);
    CHECK_EQ(decoded.value->entries.size(), 2U);
    CHECK_EQ(decoded.value->entries[0].service_name, "echo");
    CHECK_EQ(decoded.value->entries[1].service_name, "udp");

    CapabilityManifest canonical_order{
        {{"z", ServiceKind::ByteStream, 1},
         {"app.echo-v1", ServiceKind::ByteStream, 1}}};
    const auto canonical_encoded = EncodeCapabilityManifest(canonical_order);
    CHECK(canonical_encoded);
    const auto canonical_decoded =
        DecodeCapabilityManifest(*canonical_encoded.value);
    CHECK(canonical_decoded);
    CHECK_EQ(canonical_decoded.value->entries[0].service_name, "app.echo-v1");
    CHECK_EQ(canonical_decoded.value->entries[1].service_name, "z");

    for (const std::string_view invalid_name : {
             std::string_view("Uppercase"), std::string_view("bad/name"),
             std::string_view(".leading"), std::string_view("trailing."),
             std::string_view("bad.-segment"),
             std::string_view("bad_segment-"),
             std::string_view("\xc3\xa9")}) {
        CapabilityManifest invalid{{
            {std::string(invalid_name), ServiceKind::ByteStream, 1}}};
        CHECK_EQ(EncodeCapabilityManifest(invalid).status.code,
                 ErrorCode::InvalidServiceName);
    }

    CapabilityManifest duplicate{{{"echo", ServiceKind::ByteStream, 1},
                                  {"echo", ServiceKind::ByteStream, 2}}};
    CHECK_EQ(EncodeCapabilityManifest(duplicate).status.code,
             ErrorCode::DuplicateField);
    CapabilityManifest invalid_count{{{"echo", ServiceKind::ByteStream, 0}}};
    CHECK_EQ(EncodeCapabilityManifest(invalid_count).status.code,
             ErrorCode::InvalidField);

    auto malformed = *encoded.value;
    // Change the first canonical name from "echo" to "zcho", placing it after
    // the following "udp" entry.
    malformed[12] = 'z';
    CHECK_EQ(ValidateCapabilityManifestEncoding(malformed).code,
             ErrorCode::OutOfOrderField);
    malformed = *encoded.value;
    malformed.push_back(0);
    CHECK_EQ(ValidateCapabilityManifestEncoding(malformed).code,
             ErrorCode::TrailingData);
    malformed = *encoded.value;
    malformed[1] = 1;
    CHECK_EQ(ValidateCapabilityManifestEncoding(malformed).code,
             ErrorCode::InvalidFlags);

    const auto credit = EncodeCreditUpdate(65'536);
    CHECK(credit);
    CHECK_HEX(*credit.value, "00010000");
    CHECK_EQ(*DecodeCreditUpdate(*credit.value).value, 65'536U);
    CHECK_EQ(EncodeCreditUpdate(0).status.code, ErrorCode::CreditOutOfRange);
    CHECK_EQ(EncodeCreditUpdate(kMaxCreditIncrement + 1U).status.code,
             ErrorCode::CreditOutOfRange);
    CHECK_EQ(DecodeCreditUpdate(std::array<std::uint8_t, 3>{}).status.code,
             ErrorCode::Truncated);
    CHECK_EQ(DecodeCreditUpdate(std::array<std::uint8_t, 5>{}).status.code,
             ErrorCode::TrailingData);
}

AuthRecord ExampleAuthRecord(const std::vector<std::uint8_t>& capabilities) {
    AuthRecord record;
    record.type = AuthMessageType::Challenge;
    record.sender_role = EndpointRole::Server;
    record.fields.push_back(
        {static_cast<std::uint16_t>(AuthFieldId::TranscriptHash), true,
         std::vector<std::uint8_t>(kTranscriptHashSize, 0x11)});
    record.fields.push_back(
        {static_cast<std::uint16_t>(AuthFieldId::CapabilityManifest), true,
         capabilities});
    record.fields.push_back(
        {static_cast<std::uint16_t>(AuthFieldId::Nonce), true,
         std::vector<std::uint8_t>(32, 0x22)});
    return record;
}

void TestAuthCodec() {
    const auto capabilities = EncodeCapabilityManifest(ExampleCapabilities());
    CHECK(capabilities);
    AuthRecord record = ExampleAuthRecord(*capabilities.value);
    const auto encoded = EncodeAuthRecord(record);
    CHECK(encoded);
    const auto decoded = DecodeAuthRecord(*encoded.value);
    CHECK(decoded);
    CHECK_EQ(*decoded.value, record);

    AuthRecord mandatory_only;
    mandatory_only.type = AuthMessageType::Accepted;
    mandatory_only.sender_role = EndpointRole::Client;
    const auto mandatory_encoded = EncodeAuthRecord(mandatory_only);
    CHECK(mandatory_encoded);
    CHECK_HEX(
        *mandatory_encoded.value,
        "010300030000007c000100010000004b5954502f313a544c5331333a48323a4544"
        "32353531392b4d4c2d4453412d38373a5832353531392b4d4c2d4b454d2d313032"
        "343a484b44462d5348413235363a4145532d3235362d47434d0002000100000018"
        "010101010101010101200c10202020200620062000400100000300010000000101");

    const auto offsets = AuthFieldOffsets(*encoded.value);
    CHECK_EQ(offsets.size(), 6U);
    auto malformed = *encoded.value;
    malformed.pop_back();
    CHECK_EQ(DecodeAuthRecord(malformed).status.code, ErrorCode::Truncated);
    malformed = *encoded.value;
    malformed.push_back(0);
    CHECK_EQ(DecodeAuthRecord(malformed).status.code, ErrorCode::TrailingData);
    malformed = *encoded.value;
    WriteU16(malformed, 2, static_cast<std::uint16_t>(kMaxAuthFields + 1));
    CHECK_EQ(DecodeAuthRecord(malformed).status.code, ErrorCode::TooManyFields);

    malformed = *encoded.value;
    // Last field (nonce) duplicates the preceding capability field.
    WriteU16(malformed, offsets[5],
             static_cast<std::uint16_t>(AuthFieldId::CapabilityManifest));
    CHECK_EQ(DecodeAuthRecord(malformed).status.code,
             ErrorCode::DuplicateField);
    malformed = *encoded.value;
    WriteU16(malformed, offsets[5], 2);
    CHECK_EQ(DecodeAuthRecord(malformed).status.code,
             ErrorCode::OutOfOrderField);
    malformed = *encoded.value;
    WriteU16(malformed, offsets[5], 100);
    CHECK_EQ(DecodeAuthRecord(malformed).status.code,
             ErrorCode::UnknownCriticalField);
    WriteU16(malformed, offsets[5] + 2, 0);
    const auto unknown_optional = DecodeAuthRecord(malformed);
    CHECK(unknown_optional);
    CHECK_EQ(unknown_optional.value->fields.back().id, 100U);

    malformed = *encoded.value;
    WriteU16(malformed, offsets[5] + 2, 2);
    CHECK_EQ(DecodeAuthRecord(malformed).status.code, ErrorCode::InvalidFlags);
    malformed = *encoded.value;
    WriteU32(malformed, offsets[5] + 4, 0xffff'ffffU);
    CHECK_EQ(DecodeAuthRecord(malformed).status.code, ErrorCode::Truncated);

    malformed = *encoded.value;
    malformed[offsets[0] + 8] ^= 1;
    CHECK_EQ(DecodeAuthRecord(malformed).status.code, ErrorCode::InvalidField);
    malformed = *encoded.value;
    malformed[offsets[1] + 8] ^= 1;
    CHECK_EQ(DecodeAuthRecord(malformed).status.code, ErrorCode::InvalidField);
    malformed = *encoded.value;
    malformed[offsets[2] + 8] = 3;
    CHECK_EQ(DecodeAuthRecord(malformed).status.code, ErrorCode::InvalidEnum);

    AuthRecord bad_width;
    bad_width.fields.push_back(
        {static_cast<std::uint16_t>(AuthFieldId::MlKemPublicKey), true,
         std::vector<std::uint8_t>(kMlKem1024PublicKeySize - 1, 0)});
    CHECK_EQ(EncodeAuthRecord(bad_width).status.code,
             ErrorCode::InvalidLength);
    bad_width.fields[0] =
        {static_cast<std::uint16_t>(AuthFieldId::MlKemCiphertext), true,
         std::vector<std::uint8_t>(kMlKem1024CiphertextSize + 1, 0)};
    CHECK_EQ(EncodeAuthRecord(bad_width).status.code,
             ErrorCode::InvalidLength);
    bad_width.fields[0] =
        {static_cast<std::uint16_t>(AuthFieldId::X25519PublicKey), true,
         std::vector<std::uint8_t>(31, 0)};
    CHECK_EQ(EncodeAuthRecord(bad_width).status.code,
             ErrorCode::InvalidLength);
    bad_width.fields[0] =
        {static_cast<std::uint16_t>(AuthFieldId::PskAuthenticator), true,
         std::vector<std::uint8_t>(31, 0)};
    CHECK_EQ(EncodeAuthRecord(bad_width).status.code,
             ErrorCode::InvalidLength);
    bad_width.fields[0] =
        {static_cast<std::uint16_t>(AuthFieldId::KeyConfirmation), true,
         std::vector<std::uint8_t>(33, 0)};
    CHECK_EQ(EncodeAuthRecord(bad_width).status.code,
             ErrorCode::InvalidLength);

    std::vector<std::uint8_t> oversized(kMaxAuthRecordSize + 1, 0);
    CHECK_EQ(DecodeAuthRecord(oversized).status.code,
             ErrorCode::PayloadTooLarge);
}

template <std::size_t Size>
std::array<std::uint8_t, Size> Pattern(std::uint8_t seed) {
    std::array<std::uint8_t, Size> output{};
    for (std::size_t i = 0; i < output.size(); ++i) {
        output[i] = static_cast<std::uint8_t>(seed + (i % 251));
    }
    return output;
}

struct KeyFixture {
    std::array<std::uint8_t, kTranscriptHashSize> transcript = Pattern<32>(1);
    std::array<std::uint8_t, kExporterSize> exporter = Pattern<32>(2);
    std::vector<std::uint8_t> client_identity{0x43, 0x4c, 0x49, 0x45, 0x4e, 0x54};
    std::vector<std::uint8_t> server_identity{0x53, 0x45, 0x52, 0x56, 0x45, 0x52};
    std::vector<std::uint8_t> capabilities;
    std::array<std::uint8_t, kPskSize> psk = Pattern<32>(3);
    std::array<std::uint8_t, kX25519PublicKeySize> client_x = Pattern<32>(4);
    std::array<std::uint8_t, kX25519PublicKeySize> server_x = Pattern<32>(5);
    std::array<std::uint8_t, kX25519SharedSecretSize> x_secret = Pattern<32>(6);
    std::array<std::uint8_t, kMlKem1024PublicKeySize> ml_public = Pattern<1568>(7);
    std::array<std::uint8_t, kMlKem1024CiphertextSize> ml_ciphertext =
        Pattern<1568>(8);
    std::array<std::uint8_t, kMlKem1024SharedSecretSize> ml_secret =
        Pattern<32>(9);

    KeyFixture() {
        const auto encoded = EncodeCapabilityManifest(ExampleCapabilities());
        if (encoded) {
            capabilities = std::move(*encoded.value);
        }
    }

    [[nodiscard]] KeyScheduleInput Input() const {
        return {
            .initiator_role = EndpointRole::Client,
            .responder_role = EndpointRole::Server,
            .transcript_hash = transcript,
            .exporter = exporter,
            .client_identity = client_identity,
            .server_identity = server_identity,
            .client_capability_manifest = capabilities,
            .server_capability_manifest = capabilities,
            .access_psk = psk,
            .client_x25519_public_key = client_x,
            .server_x25519_public_key = server_x,
            .x25519_shared_secret = x_secret,
            .mlkem_public_key = ml_public,
            .mlkem_ciphertext = ml_ciphertext,
            .mlkem_shared_secret = ml_secret,
        };
    }
};

[[nodiscard]] std::vector<std::uint8_t> EncodeKeyInput(
    const KeyScheduleInput& input) {
    const auto size = KeyScheduleInputEncodedSize(input);
    CHECK(size);
    if (!size) {
        return {};
    }
    std::vector<std::uint8_t> output(*size.value);
    std::size_t written = 0;
    CHECK(EncodeKeyScheduleInput(input, output, written));
    CHECK_EQ(written, output.size());
    return output;
}

void TestKeyScheduleInput() {
    KeyFixture fixture;
    const KeyScheduleInput input = fixture.Input();
    CHECK(ValidateKeyScheduleInput(input));
    const std::vector<std::uint8_t> baseline = EncodeKeyInput(input);
    CHECK(!baseline.empty());
    CHECK_EQ(ReadU16(baseline, 2), 18U);
    CHECK_EQ(baseline.size(), 3657U);
    CHECK_EQ(Fnv1a64(baseline), 0x6ab12ea0049e3c94ULL);

    const auto size = KeyScheduleInputEncodedSize(input);
    CHECK(size);
    std::vector<std::uint8_t> short_output(*size.value - 1);
    std::size_t written = 99;
    CHECK_EQ(EncodeKeyScheduleInput(input, short_output, written).code,
             ErrorCode::OutputTooSmall);
    CHECK_EQ(written, 0U);

    std::vector<std::uint8_t> aliased_output(*size.value, 0);
    std::copy(fixture.client_identity.begin(), fixture.client_identity.end(),
              aliased_output.begin() + 128);
    KeyScheduleInput aliased = input;
    aliased.client_identity = std::span<const std::uint8_t>(aliased_output)
                                  .subspan(128, fixture.client_identity.size());
    CHECK_EQ(EncodeKeyScheduleInput(aliased, aliased_output, written).code,
             ErrorCode::OverlappingBuffer);
    CHECK_EQ(written, 0U);

    KeyScheduleInput changed = input;
    changed.initiator_role = EndpointRole::Server;
    changed.responder_role = EndpointRole::Client;
    CHECK(ValidateKeyScheduleInput(changed));
    CHECK(EncodeKeyInput(changed) != baseline);
    changed = input;
    changed.responder_role = EndpointRole::Client;
    CHECK_EQ(ValidateKeyScheduleInput(changed).code, ErrorCode::InvalidField);

    auto changed_transcript = fixture.transcript;
    changed_transcript[0] ^= 1;
    changed = input;
    changed.transcript_hash = changed_transcript;
    CHECK(EncodeKeyInput(changed) != baseline);
    auto changed_exporter = fixture.exporter;
    changed_exporter[31] ^= 1;
    changed = input;
    changed.exporter = changed_exporter;
    CHECK(EncodeKeyInput(changed) != baseline);

    changed = input;
    changed.x25519_shared_secret =
        std::span<const std::uint8_t>(fixture.x_secret).first(31);
    CHECK_EQ(ValidateKeyScheduleInput(changed).code, ErrorCode::InvalidLength);
    changed = input;
    changed.mlkem_public_key =
        std::span<const std::uint8_t>(fixture.ml_public).first(1567);
    CHECK_EQ(ValidateKeyScheduleInput(changed).code, ErrorCode::InvalidLength);
    changed = input;
    changed.mlkem_ciphertext =
        std::span<const std::uint8_t>(fixture.ml_ciphertext).first(1567);
    CHECK_EQ(ValidateKeyScheduleInput(changed).code, ErrorCode::InvalidLength);
    changed = input;
    changed.mlkem_shared_secret = {};
    CHECK_EQ(ValidateKeyScheduleInput(changed).code, ErrorCode::InvalidLength);

    auto bad_capabilities = fixture.capabilities;
    bad_capabilities.push_back(0);
    changed = input;
    changed.client_capability_manifest = bad_capabilities;
    CHECK_EQ(ValidateKeyScheduleInput(changed).code, ErrorCode::TrailingData);
    changed = input;
    changed.server_capability_manifest = bad_capabilities;
    CHECK_EQ(ValidateKeyScheduleInput(changed).code, ErrorCode::TrailingData);

    KeyFixture distinct_capabilities_fixture;
    const auto server_capabilities = EncodeCapabilityManifest(
        {{{"server-only", ServiceKind::ByteStream, 3}}});
    CHECK(server_capabilities);
    changed = distinct_capabilities_fixture.Input();
    changed.server_capability_manifest = *server_capabilities.value;
    CHECK(ValidateKeyScheduleInput(changed));
    CHECK(EncodeKeyInput(changed) != baseline);
}

void TestDomains() {
    const std::array<std::string_view, 12> domains{
        kAuthSignatureDomain, kRoleBindingDomain, kTranscriptDomain, kRootDomain,
        kPskDomain, kHandshakeConfirmationDomain, kCompositeIdentityDomain,
        kClientToServerDomain, kServerToClientDomain, kMessageDomain,
        kAadDomain, kRatchetDomain};
    for (const std::string_view domain : domains) {
        CHECK(domain.starts_with("yume/ytp/1/"));
        CHECK(domain.find("2.0") == std::string_view::npos);
    }
    CHECK(kExporterLabel.starts_with("EXPORTER-yume/ytp/1/"));
    CHECK(kExporterLabel.find("2.0") == std::string_view::npos);
    CHECK(IsRequiredSecurityParameters(kRequiredSecurityParameters));
    auto mismatched = kRequiredSecurityParameters;
    mismatched[0] = 2;
    CHECK(!IsRequiredSecurityParameters(mismatched));
}

} // namespace

int main() {
    TestStreamIdsAndFrameHeader();
    TestOpenCodec();
    TestCapabilitiesAndCredit();
    TestAuthCodec();
    TestKeyScheduleInput();
    TestDomains();

    if (g_failures != 0) {
        std::cerr << g_failures << " YTP/1 kernel test(s) failed\n";
        return 1;
    }
    std::cout << "YTP/1 protocol/security kernel tests passed\n";
    return 0;
}
