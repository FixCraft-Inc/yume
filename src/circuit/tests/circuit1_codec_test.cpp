/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "circuit/protocol.hpp"
#include "circuit/tests/circuit1_vectors.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iostream>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace {

using namespace yume::circuit1;
using Bytes = std::vector<std::uint8_t>;

int g_failures = 0;

#define CHECK(condition)                                        \
    do {                                                        \
        if (!(condition)) {                                     \
            std::cerr << __FILE__ << ':' << __LINE__            \
                      << ": check failed: " #condition << '\n'; \
            ++g_failures;                                       \
        }                                                       \
    } while (false)

const test::Vectors& vectors() {
    static const test::Vectors loaded(YUME_CIRCUIT1_VECTORS_FILE);
    return loaded;
}

Direction direction_of(const std::string& name) {
    return vectors().text("relay." + name + ".direction") == "forward"
               ? Direction::Forward
               : Direction::Backward;
}

Bytes encode_relay(const std::string& name) {
    const auto bucket = vectors().number("relay." + name + ".bucket");
    Bytes output(RelayCapacity(bucket));
    const auto status = EncodeRelayMessage(
        direction_of(name),
        static_cast<RelayType>(vectors().number("relay." + name + ".type")),
        static_cast<std::uint32_t>(
            vectors().number("relay." + name + ".stream")),
        vectors().bytes("relay." + name + ".payload"), output);
    CHECK(status.ok());
    return output;
}

Bytes create_body() {
    const auto client = vectors().bytes("handshake.client");
    const auto body =
        EncodeCreate(2U, std::span<const std::uint8_t, kClientHandshakeBytes>(
                             client.data(), client.size()));
    CHECK(body.ok());
    return body.ok() ? Bytes(body.value->begin(), body.value->end()) : Bytes{};
}

void TestBuckets() {
    CHECK(RelayCapacity(512) == 460U);
    CHECK(RelayCapacity(4096) == 4044U);
    CHECK(RelayCapacity(16384) == 16332U);
    CHECK(RelayCapacity(1024) == 0U);
    CHECK(BucketForPayload(0U) == 512U);
    CHECK(BucketForPayload(452U) == 512U);
    CHECK(BucketForPayload(453U) == 4096U);
    CHECK(BucketForPayload(4036U) == 4096U);
    CHECK(BucketForPayload(4037U) == 16384U);
    CHECK(BucketForPayload(16324U) == 16384U);
    CHECK(!BucketForPayload(16325U).has_value());
    CHECK(BucketForPayload(kExtendPayloadBytes) == 4096U);
    CHECK(BucketForPayload(kHopHandshakeBytes) == 16384U);
}

void TestHandshakes() {
    const auto client = vectors().bytes("handshake.client");
    const auto decoded = DecodeClientHandshake(client);
    CHECK(decoded.ok());
    if (decoded.ok()) {
        const auto encoded = EncodeClientHandshake(*decoded.value);
        CHECK(Bytes(encoded.begin(), encoded.end()) == client);
        const auto alice = vectors().bytes("x25519.alice_public");
        CHECK(std::equal(alice.begin(), alice.end(),
                         decoded.value->x25519_public.begin()));
    }
    const auto hop = vectors().bytes("handshake.hop");
    const auto decoded_hop = DecodeHopHandshake(hop);
    CHECK(decoded_hop.ok());
    if (decoded_hop.ok()) CHECK(EncodeHopHandshake(*decoded_hop.value) == hop);

    const auto body = create_body();
    const auto create = DecodeCreate(body);
    CHECK(create.ok() && create.value->depth == 2U &&
          Bytes(create.value->client_handshake.begin(),
                create.value->client_handshake.end()) == client);
    const auto span = std::span<const std::uint8_t, kClientHandshakeBytes>(
        client.data(), client.size());
    CHECK(EncodeCreate(0U, span).status.code == ErrorCode::InvalidDepth);
    CHECK(EncodeCreate(4U, span).status.code == ErrorCode::InvalidDepth);
    auto bad = client;
    bad[0] = 2U;
    CHECK(EncodeCreate(1U, std::span<const std::uint8_t, kClientHandshakeBytes>(
                               bad.data(), bad.size()))
              .status.code == ErrorCode::UnsupportedVersion);
}

void TestCells() {
    for (const auto* name :
         {"layers.forward0", "layers.forward1", "layers.backward0"}) {
        const auto cell = vectors().bytes(std::string(name) + ".cell");
        const auto decoded = DecodeCell(cell);
        CHECK(decoded.ok());
        if (!decoded.ok()) continue;
        CHECK(decoded.value->command == Command::Relay);
        CHECK(decoded.value->bucket == 512U);
        CHECK(decoded.value->layers == 3U);
        CHECK(decoded.value->body.size() == 508U);
        const auto encoded =
            EncodeCell(Command::Relay, 512U, decoded.value->body);
        CHECK(encoded.ok() && *encoded.value == cell);
    }
    const auto body = create_body();
    const auto create = EncodeCell(Command::Create, 4096U, body);
    CHECK(create.ok());
    if (create.ok()) {
        const auto decoded = DecodeCell(*create.value);
        CHECK(decoded.ok() && decoded.value->command == Command::Create &&
              decoded.value->layers == 0U &&
              Bytes(decoded.value->body.begin(), decoded.value->body.end()) ==
                  body);
    }
    const auto hop = vectors().bytes("handshake.hop");
    CHECK(EncodeCell(Command::Created, 16384U, hop).ok());
    // A CREATE body fits a 16384-byte cell but that bucket is not allowed.
    CHECK(EncodeCell(Command::Create, 16384U, body).status.code ==
          ErrorCode::InvalidBucket);
    // A hop handshake does not fit a 4096-byte cell at all, and the length
    // bound comes before the command's bucket rule.
    CHECK(EncodeCell(Command::Created, 4096U, hop).status.code ==
          ErrorCode::InvalidLength);
    CHECK(EncodeCell(Command::Created, 512U, Bytes(10U)).status.code ==
          ErrorCode::InvalidBucket);
    CHECK(EncodeCell(Command::Relay, 512U, Bytes(460U)).status.code ==
          ErrorCode::InvalidLength);
    CHECK(EncodeCell(Command::Relay, 512U, Bytes(476U)).ok());
    CHECK(EncodeCell(Command::Relay, 1000U, Bytes(16U)).status.code ==
          ErrorCode::InvalidBucket);
    std::array<std::uint8_t, 511> small{};
    CHECK(EncodeCell(Command::Relay, 512U, Bytes(476U), small).code ==
          ErrorCode::OutputTooSmall);
}

void TestRelayMessages() {
    for (const auto& key : vectors().names("relay.")) {
        if (!key.ends_with(".type")) continue;
        const auto name = key.substr(6U, key.size() - 6U - 5U);
        const auto encoded = encode_relay(name);
        const auto decoded = DecodeRelayMessage(direction_of(name), encoded);
        CHECK(decoded.ok());
        if (!decoded.ok()) {
            std::cerr << "  relay message " << name << ": "
                      << ErrorName(decoded.status.code) << '\n';
            continue;
        }
        CHECK(static_cast<std::uint64_t>(decoded.value->type) ==
              vectors().number("relay." + name + ".type"));
        CHECK(decoded.value->stream ==
              vectors().number("relay." + name + ".stream"));
        CHECK(Bytes(decoded.value->payload.begin(),
                    decoded.value->payload.end()) ==
              vectors().bytes("relay." + name + ".payload"));
        if (vectors().number("relay." + name + ".bucket") == 512U) {
            CHECK(encoded == vectors().bytes("relay." + name + ".message"));
        }
        // The opposite direction accepts only the types both may send.
        const auto reversed = DecodeRelayMessage(
            direction_of(name) == Direction::Forward ? Direction::Backward
                                                     : Direction::Forward,
            encoded);
        const auto type = decoded.value->type;
        const bool both = type == RelayType::Data || type == RelayType::End ||
                          type == RelayType::StreamCredit;
        CHECK(reversed.ok() == both);
        if (!both) CHECK(reversed.status.code == ErrorCode::WrongDirection);
    }
    for (const auto* name :
         {"layers.forward0.message", "layers.forward1.message"}) {
        const auto message = vectors().bytes(name);
        const auto decoded = DecodeRelayMessage(Direction::Forward, message);
        CHECK(decoded.ok() && decoded.value->type == RelayType::Data &&
              decoded.value->stream == 7U);
    }
    const auto connected = DecodeRelayMessage(
        Direction::Backward, vectors().bytes("layers.backward0.message"));
    CHECK(connected.ok() && connected.value->type == RelayType::Connected &&
          connected.value->payload.empty());

    // BEGIN destinations decode to YTP/1 destinations and encode back.
    for (const auto* name : {"begin_ipv4", "begin_ipv6", "begin_dns"}) {
        const auto payload =
            vectors().bytes(std::string("relay.") + name + ".payload");
        const auto destination = DecodeBeginPayload(payload);
        CHECK(destination.ok());
        if (!destination.ok()) continue;
        const auto encoded = EncodeBeginPayload(*destination.value);
        CHECK(encoded.ok() && *encoded.value == payload);
    }
    const auto dns =
        DecodeBeginPayload(vectors().bytes("relay.begin_dns.payload"));
    CHECK(dns.ok() && dns.value->dns_name == "example.org" &&
          dns.value->port == 443U);
    yume::ytp1::Destination none;
    CHECK(EncodeBeginPayload(none).status.code ==
          ErrorCode::InvalidDestination);

    // EXTEND payloads carry the next fingerprint and the client handshake.
    const auto extend_payload = vectors().bytes("relay.extend.payload");
    const auto extend = DecodeExtendPayload(extend_payload);
    CHECK(extend.ok());
    if (extend.ok()) {
        const auto fingerprint = vectors().bytes("hop_fingerprint");
        CHECK(std::equal(fingerprint.begin(), fingerprint.end(),
                         extend.value->next_identity.begin()));
        const auto again = EncodeExtendPayload(
            extend.value->next_identity,
            extend.value->client_handshake.first<kClientHandshakeBytes>());
        CHECK(Bytes(again.begin(), again.end()) == extend_payload);
    }

    // Encoders refuse what decoders refuse.
    Bytes capacity(RelayCapacity(512));
    CHECK(EncodeRelayMessage(Direction::Forward, RelayType::Connected, 1U, {},
                             capacity)
              .code == ErrorCode::WrongDirection);
    CHECK(EncodeRelayMessage(Direction::Forward, RelayType::Data, 0U, Bytes{1},
                             capacity)
              .code == ErrorCode::InvalidStream);
    CHECK(EncodeRelayMessage(Direction::Forward, RelayType::Data, 1U,
                             Bytes(453U), capacity)
              .code == ErrorCode::InvalidLength);
    CHECK(EncodeRelayMessage(Direction::Forward, RelayType::Data, 1U,
                             Bytes(452U, 1U), capacity)
              .ok());
    Bytes wrong(100U);
    CHECK(EncodeRelayMessage(Direction::Forward, RelayType::Data, 1U, Bytes{1},
                             wrong)
              .code == ErrorCode::OutputTooSmall);
}

// Applies one negative vector: base, mutation and expected error.
void TestNegative(const std::string& name, const std::string& line) {
    const auto first = line.find(' ');
    const auto second = line.find(' ', first + 1U);
    const auto base = line.substr(0U, first);
    const auto mutation = line.substr(first + 1U, second - first - 1U);
    const auto expected = line.substr(second + 1U);

    Bytes bytes;
    if (base == "cell.forward") {
        bytes = vectors().bytes("layers.forward0.cell");
    } else if (base == "cell.create") {
        bytes = *EncodeCell(Command::Create, 4096U, create_body()).value;
    } else if (base == "create.body") {
        bytes = create_body();
    } else if (base == "handshake.client" || base == "handshake.hop") {
        bytes = vectors().bytes(base);
    } else if (base.starts_with("relay.")) {
        bytes = encode_relay(base.substr(6U));
    } else if (base.starts_with("begin.")) {
        bytes = vectors().bytes("relay." + base.substr(6U) + ".payload");
    } else {
        std::cerr << "unknown negative base " << base << '\n';
        ++g_failures;
        return;
    }
    if (mutation.starts_with("xor:")) {
        const auto colon = mutation.find(':', 4U);
        const auto offset = std::stoul(mutation.substr(4U, colon - 4U));
        const auto mask = std::stoul(mutation.substr(colon + 1U), nullptr, 16);
        if (offset >= bytes.size()) {
            std::cerr << name << ": offset past the base\n";
            ++g_failures;
            return;
        }
        bytes[offset] ^= static_cast<std::uint8_t>(mask);
    } else if (mutation.starts_with("resize:")) {
        bytes.resize(std::stoul(mutation.substr(7U)), 0U);
    }

    ErrorCode code = ErrorCode::Ok;
    if (base.starts_with("cell.")) {
        code = DecodeCell(bytes).status.code;
    } else if (base == "create.body") {
        code = DecodeCreate(bytes).status.code;
    } else if (base == "handshake.client") {
        code = DecodeClientHandshake(bytes).status.code;
    } else if (base == "handshake.hop") {
        code = DecodeHopHandshake(bytes).status.code;
    } else if (base.starts_with("relay.")) {
        code = DecodeRelayMessage(direction_of(base.substr(6U)), bytes)
                   .status.code;
    } else {
        code = DecodeBeginPayload(bytes).status.code;
    }
    std::string actual(ErrorName(code));
    std::string wanted;
    for (const char value : expected) {
        if (value >= 'A' && value <= 'Z') {
            if (!wanted.empty()) wanted.push_back(' ');
            wanted.push_back(static_cast<char>(value - 'A' + 'a'));
        } else {
            wanted.push_back(value);
        }
    }
    if (actual != wanted) {
        std::cerr << name << ": expected " << wanted << ", got " << actual
                  << '\n';
        ++g_failures;
    }
}

void TestNegatives() {
    const auto names = vectors().names("negative.");
    CHECK(names.size() >= 40U);
    for (const auto& name : names) TestNegative(name, vectors().text(name));
}

}  // namespace

int main() {
    try {
        TestBuckets();
        TestHandshakes();
        TestCells();
        TestRelayMessages();
        TestNegatives();
    } catch (const std::exception& error) {
        std::cerr << "circuit 1 codec test aborted: " << error.what() << '\n';
        return 1;
    }
    if (g_failures != 0) {
        std::cerr << g_failures << " circuit 1 codec check(s) failed\n";
        return 1;
    }
    std::cout << "circuit 1 codec tests passed\n";
    return 0;
}
