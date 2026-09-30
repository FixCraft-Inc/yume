/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/circuit_crypto.hpp"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include "circuit/tests/circuit1_vectors.hpp"

namespace {

using namespace yume;
using namespace yume::providers::circuit;
using circuit1::Direction;
using engine::StatusCode;
using Bytes = std::vector<std::uint8_t>;
namespace keys = yume::providers::keys;
namespace ytp1_crypto = yume::providers::ytp1_crypto;

int g_failures = 0;

#define CHECK(condition)                                        \
    do {                                                        \
        if (!(condition)) {                                     \
            std::cerr << __FILE__ << ':' << __LINE__            \
                      << ": check failed: " #condition << '\n'; \
            ++g_failures;                                       \
        }                                                       \
    } while (false)

const circuit1::test::Vectors& vectors() {
    static const circuit1::test::Vectors loaded(YUME_CIRCUIT1_VECTORS_FILE);
    return loaded;
}

const CircuitCrypto& crypto() {
    static const CircuitCrypto instance;
    return instance;
}

template <typename Container>
Bytes bytes_of(const Container& value) {
    return Bytes(value.begin(), value.end());
}

Bytes sha256(std::span<const std::uint8_t> input) {
    return bytes_of(ytp1_crypto::sha256(crypto().crypto(), {input}));
}

Fingerprint fingerprint(const std::string& name) {
    const auto value = vectors().bytes(name);
    Fingerprint output{};
    std::copy(value.begin(), value.end(), output.begin());
    return output;
}

void TestDeterministicSteps() {
    const auto client = vectors().bytes("handshake.client");
    const auto hop =
        circuit1::DecodeHopHandshake(vectors().bytes("handshake.hop"));
    CHECK(hop.ok());
    if (!hop.ok()) return;
    const auto x_shared = vectors().bytes("x25519.shared");
    const auto ml_shared = vectors().bytes("mlkem_shared");
    for (const std::string name : {"depth2", "depth1"}) {
        const bool entry = name == "depth1";
        const auto predecessor =
            entry ? Fingerprint{} : fingerprint("predecessor_fingerprint");
        const auto transcript = transcript_hash(
            crypto(), fingerprint("hop_fingerprint"), predecessor,
            entry ? 1U : 2U,
            std::span<const std::uint8_t, circuit1::kClientHandshakeBytes>(
                client.data(), client.size()),
            hop.value->x25519_public, hop.value->mlkem_ciphertext);
        CHECK(bytes_of(transcript) == vectors().bytes(name + ".transcript"));
        const auto keys =
            derive_hop_keys(crypto(), x_shared, ml_shared, transcript);
        CHECK(bytes_of(keys.forward_key.span()) ==
              vectors().bytes(name + ".forward_key"));
        CHECK(bytes_of(keys.backward_key.span()) ==
              vectors().bytes(name + ".backward_key"));
        CHECK(bytes_of(keys.forward_iv.span()) ==
              vectors().bytes(name + ".forward_iv"));
        CHECK(bytes_of(keys.backward_iv.span()) ==
              vectors().bytes(name + ".backward_iv"));
        CHECK(bytes_of(keys.confirmation_key.span()) ==
              vectors().bytes(name + ".confirmation_key"));
        const auto confirmed =
            confirmation(crypto(), keys.confirmation_key.span(), transcript);
        CHECK(bytes_of(confirmed) == vectors().bytes(name + ".confirmation"));
        CHECK(signed_bytes(transcript, confirmed) ==
              vectors().bytes(name + ".signed"));
    }

    const auto iv = vectors().bytes("nonce.iv");
    const auto iv_span =
        std::span<const std::uint8_t, kLayerIvBytes>(iv.data(), iv.size());
    for (const std::uint64_t counter : {0ULL, 1ULL, 0xffffffffULL}) {
        CHECK(bytes_of(layer_nonce(iv_span, counter)) ==
              vectors().bytes("nonce." + std::to_string(counter)));
    }
    CHECK(layer_aad(Direction::Forward, 512U) ==
          vectors().bytes("aad.forward_512"));
    CHECK(layer_aad(Direction::Forward, 16311U) ==
          vectors().bytes("aad.forward_16311"));
    CHECK(layer_aad(Direction::Backward, 16315U) ==
          vectors().bytes("aad.backward_16315"));

    CHECK(fingerprint_bytes(std::string(64U, 'a')).has_value());
    CHECK(!fingerprint_bytes(std::string(64U, 'A')).has_value());
    CHECK(!fingerprint_bytes(std::string(63U, 'a')).has_value());
}

void TestX25519KnownAnswer() {
    const auto alice = vectors().bytes("x25519.alice_private");
    ytp1_crypto::PkeyPtr key(EVP_PKEY_new_raw_private_key_ex(
        crypto().crypto().library_context(), "X25519", "provider=default",
        alice.data(), alice.size()));
    CHECK(key != nullptr);
    if (!key) return;
    const auto shared = ytp1_crypto::derive_x25519(
        crypto().crypto(), key.get(), vectors().bytes("x25519.bob_public"));
    CHECK(bytes_of(shared.span()) == vectors().bytes("x25519.shared"));
}

void TestEncodingDigests() {
    for (const auto& key : vectors().names("relay.")) {
        if (!key.ends_with(".type")) continue;
        const auto name = key.substr(6U, key.size() - 11U);
        const auto bucket = vectors().number("relay." + name + ".bucket");
        const auto direction =
            vectors().text("relay." + name + ".direction") == "forward"
                ? Direction::Forward
                : Direction::Backward;
        Bytes message(circuit1::RelayCapacity(direction, bucket));
        CHECK(circuit1::EncodeRelayMessage(
                  direction,
                  static_cast<circuit1::RelayType>(
                      vectors().number("relay." + name + ".type")),
                  static_cast<std::uint32_t>(
                      vectors().number("relay." + name + ".stream")),
                  vectors().bytes("relay." + name + ".payload"), message)
                  .ok());
        CHECK(sha256(message) == vectors().bytes("relay." + name + ".sha256"));
    }
    const auto client = vectors().bytes("handshake.client");
    const auto body = circuit1::EncodeCreate(
        2U, std::span<const std::uint8_t, circuit1::kClientHandshakeBytes>(
                client.data(), client.size()));
    CHECK(body.ok());
    if (!body.ok()) return;
    CHECK(sha256(*body.value) == vectors().bytes("create.body_sha256"));
    const auto create = circuit1::EncodeCell(
        Direction::Forward, circuit1::Command::Create, 4096U, *body.value);
    CHECK(create.ok() &&
          sha256(*create.value) == vectors().bytes("cell.create_sha256"));
    const auto created =
        circuit1::EncodeCell(Direction::Backward, circuit1::Command::Created,
                             16315U, vectors().bytes("handshake.hop"));
    CHECK(created.ok() &&
          sha256(*created.value) == vectors().bytes("cell.created_sha256"));
}

struct HopLayers {
    LayerCipher forward;
    LayerCipher backward;
};

// Layer ciphers from the vectors' direct keys, sealing as a client does
// forward and a hop does backward, or opening in the other roles.
HopLayers layers_of(int hop, bool client) {
    const auto prefix = "layers.hop" + std::to_string(hop) + ".";
    using Mode = LayerCipher::Mode;
    return {
        LayerCipher(crypto(), client ? Mode::Seal : Mode::Open,
                    Direction::Forward, vectors().bytes(prefix + "forward_key"),
                    vectors().bytes(prefix + "forward_iv")),
        LayerCipher(crypto(), client ? Mode::Open : Mode::Seal,
                    Direction::Backward,
                    vectors().bytes(prefix + "backward_key"),
                    vectors().bytes(prefix + "backward_iv"))};
}

Bytes seal_with(LayerCipher& cipher, std::size_t bucket,
                const Bytes& plaintext) {
    Bytes output(plaintext.size() + circuit1::kLayerTagBytes);
    CHECK(cipher.seal(bucket, plaintext, output).ok());
    return output;
}

Bytes open_with(LayerCipher& cipher, std::size_t bucket,
                const Bytes& ciphertext) {
    Bytes output(ciphertext.size() - circuit1::kLayerTagBytes);
    CHECK(cipher.open(bucket, ciphertext, output).ok());
    return output;
}

void TestLayerVectors() {
    std::vector<HopLayers> client;
    std::vector<HopLayers> relays;
    for (int hop = 1; hop <= 3; ++hop) {
        client.push_back(layers_of(hop, true));
        relays.push_back(layers_of(hop, false));
    }
    for (int counter = 0; counter < 2; ++counter) {
        const auto prefix = "layers.forward" + std::to_string(counter);
        auto body = vectors().bytes(prefix + ".message");
        for (int hop = 3; hop >= 1; --hop) {
            body = seal_with(client[hop - 1].forward, 512U, body);
            CHECK(sha256(body) ==
                  vectors().bytes(prefix + ".after_hop" + std::to_string(hop) +
                                  "_sha256"));
        }
        const auto cell = circuit1::EncodeCell(
            Direction::Forward, circuit1::Command::Relay, 512U, body);
        CHECK(cell.ok() && *cell.value == vectors().bytes(prefix + ".cell"));
        for (int hop = 1; hop <= 3; ++hop) {
            body = open_with(relays[hop - 1].forward, 512U, body);
        }
        CHECK(body == vectors().bytes(prefix + ".message"));
    }
    auto body = vectors().bytes("layers.backward0.message");
    for (int hop = 3; hop >= 1; --hop) {
        body = seal_with(relays[hop - 1].backward, 512U, body);
        CHECK(sha256(body) == vectors().bytes("layers.backward0.after_hop" +
                                              std::to_string(hop) + "_sha256"));
    }
    const auto cell = circuit1::EncodeCell(
        Direction::Backward, circuit1::Command::Relay, 512U, body);
    CHECK(cell.ok() && *cell.value == vectors().bytes("layers.backward0.cell"));
    for (int hop = 1; hop <= 3; ++hop)
        body = open_with(client[hop - 1].backward, 512U, body);
    CHECK(body == vectors().bytes("layers.backward0.message"));

    // EXTENDED from hop 2 in the largest backward cell, at each layer's
    // counter 1.
    Bytes extended(circuit1::RelayCapacity(Direction::Backward, 16315U));
    CHECK(circuit1::EncodeRelayMessage(
              Direction::Backward, circuit1::RelayType::Extended, 0U,
              vectors().bytes("handshake.hop"), extended)
              .ok());
    CHECK(sha256(extended) ==
          vectors().bytes("layers.extended.message_sha256"));
    body = seal_with(relays[1].backward, 16315U, extended);
    body = seal_with(relays[0].backward, 16315U, body);
    const auto big = circuit1::EncodeCell(
        Direction::Backward, circuit1::Command::Relay, 16315U, body);
    CHECK(big.ok() &&
          sha256(*big.value) == vectors().bytes("layers.extended.cell_sha256"));
}

void TestLayerRefusals() {
    auto sealer = layers_of(1, true);
    auto opener = layers_of(1, false);
    const Bytes message(460U, 7U);
    const auto first = seal_with(sealer.forward, 512U, message);
    const auto second = seal_with(sealer.forward, 512U, message);
    CHECK(first != second);
    CHECK(sealer.forward.cells() == 2U);

    // Wrong mode.
    Bytes out(message.size());
    CHECK(sealer.forward.open(512U, first, out).code() ==
          StatusCode::FailedPrecondition);
    Bytes sealed(message.size() + 16U);
    CHECK(opener.forward.seal(512U, message, sealed).code() ==
          StatusCode::FailedPrecondition);
    // Sizes and buckets.
    CHECK(sealer.forward.seal(513U, message, sealed).code() ==
          StatusCode::InvalidArgument);
    // The largest backward bucket is no forward bucket, and the reverse.
    CHECK(sealer.forward.seal(16315U, message, sealed).code() ==
          StatusCode::InvalidArgument);
    CHECK(opener.backward.seal(16311U, message, sealed).code() ==
          StatusCode::InvalidArgument);
    Bytes short_output(message.size());
    CHECK(sealer.forward.seal(512U, message, short_output).code() ==
          StatusCode::InvalidArgument);

    // A cell opened under the wrong bucket fails its tag and the layer stops.
    {
        auto layer = layers_of(1, false);
        CHECK(layer.forward.open(4096U, first, out).code() ==
              StatusCode::PermissionDenied);
        CHECK(std::all_of(out.begin(), out.end(),
                          [](std::uint8_t b) { return b == 0U; }));
        CHECK(layer.forward.open(512U, first, out).code() ==
              StatusCode::FailedPrecondition);
    }
    // Out of order: the second cell at counter 0 fails.
    {
        auto layer = layers_of(1, false);
        CHECK(layer.forward.open(512U, second, out).code() ==
              StatusCode::PermissionDenied);
    }
    // Replay: the first cell again at counter 1 fails.
    {
        auto layer = layers_of(1, false);
        CHECK(layer.forward.open(512U, first, out).ok());
        CHECK(layer.forward.open(512U, first, out).code() ==
              StatusCode::PermissionDenied);
    }
    // One flipped bit anywhere fails.
    for (std::size_t offset :
         {std::size_t{0}, std::size_t{200}, first.size() - 1U}) {
        auto layer = layers_of(1, false);
        auto tampered = first;
        tampered[offset] ^= 1U;
        CHECK(layer.forward.open(512U, tampered, out).code() ==
              StatusCode::PermissionDenied);
    }
    // Moving keeps the counter and disables the source.
    LayerCipher moved(std::move(sealer.forward));
    CHECK(moved.cells() == 2U);
    CHECK(sealer.forward.seal(512U, message, sealed).code() ==
          StatusCode::FailedPrecondition);
    bool refused = false;
    try {
        LayerCipher bad(crypto(), LayerCipher::Mode::Seal, Direction::Forward,
                        Bytes(31U), Bytes(12U));
    } catch (const std::invalid_argument&) {
        refused = true;
    }
    CHECK(refused);
}

std::string pem_of(EVP_PKEY* key) {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()),
                                                  BIO_free);
    if (!bio || PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0,
                                         nullptr, nullptr) != 1) {
        throw std::runtime_error("PEM export failed");
    }
    char* data = nullptr;
    const long size = BIO_get_mem_data(bio.get(), &data);
    return std::string(data, static_cast<std::size_t>(size));
}

keys::CompositePrivate make_identity() {
    ytp1_crypto::PkeyPtr classical(
        EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"));
    ytp1_crypto::PkeyPtr post_quantum(
        EVP_PKEY_Q_keygen(nullptr, nullptr, "ML-DSA-87"));
    if (!classical || !post_quantum)
        throw std::runtime_error("key generation failed");
    return keys::composite_private_from_pem(
        crypto().key_context(),
        pem_of(classical.get()) + pem_of(post_quantum.get()));
}

bool same_keys(const HopKeys& left, const HopKeys& right) {
    return bytes_of(left.forward_key.span()) ==
               bytes_of(right.forward_key.span()) &&
           bytes_of(left.backward_key.span()) ==
               bytes_of(right.backward_key.span()) &&
           bytes_of(left.forward_iv.span()) ==
               bytes_of(right.forward_iv.span()) &&
           bytes_of(left.backward_iv.span()) ==
               bytes_of(right.backward_iv.span()) &&
           bytes_of(left.confirmation_key.span()) ==
               bytes_of(right.confirmation_key.span());
}

StatusCode finish_code(const Bytes& answer_message,
                       const keys::CompositePublic& hop,
                       const Fingerprint& predecessor, std::uint8_t depth,
                       ClientExchange& exchange) {
    return exchange.finish(crypto(), answer_message, hop, predecessor, depth)
        .status()
        .code();
}

void TestHandshake() {
    const auto hop = make_identity();
    const auto other = make_identity();
    const auto predecessor = fingerprint("predecessor_fingerprint");

    // A composite signature made here verifies, and a changed message fails.
    const Bytes message{1, 2, 3};
    const auto signature = keys::sign_composite(
        crypto().key_context(), hop, std::as_bytes(std::span(message)));
    CHECK(signature.size() == 4691U);
    CHECK(keys::verify_composite(crypto().key_context(), hop.identity,
                                 std::as_bytes(std::span(message)), signature));
    const Bytes changed{1, 2, 4};
    CHECK(!keys::verify_composite(crypto().key_context(), hop.identity,
                                  std::as_bytes(std::span(changed)),
                                  signature));

    for (const std::uint8_t depth :
         {std::uint8_t{1}, std::uint8_t{2}, std::uint8_t{3}}) {
        const auto pred = depth == 1U ? Fingerprint{} : predecessor;
        auto started = ClientExchange::start(crypto());
        CHECK(started.ok());
        if (!started.ok()) return;
        auto exchange = std::move(started).take_value();
        auto answered = answer(crypto(), exchange.message(), hop, pred, depth);
        CHECK(answered.ok());
        if (!answered.ok()) return;
        auto reply = std::move(answered).take_value();
        CHECK(reply.message.size() == circuit1::kHopHandshakeBytes);
        auto finished =
            exchange.finish(crypto(), reply.message, hop.identity, pred, depth);
        CHECK(finished.ok());
        if (!finished.ok()) return;
        CHECK(same_keys(finished.value(), reply.keys));
        // The exchange runs once.
        CHECK(finish_code(reply.message, hop.identity, pred, depth, exchange) ==
              StatusCode::FailedPrecondition);

        // Both sides now share working layers.
        using Mode = LayerCipher::Mode;
        LayerCipher client_forward(crypto(), Mode::Seal, Direction::Forward,
                                   finished.value().forward_key.span(),
                                   finished.value().forward_iv.span());
        LayerCipher hop_forward(crypto(), Mode::Open, Direction::Forward,
                                reply.keys.forward_key.span(),
                                reply.keys.forward_iv.span());
        const Bytes plain(4044U, 0x5aU);
        CHECK(open_with(hop_forward, 4096U,
                        seal_with(client_forward, 4096U, plain)) == plain);
    }

    // Each answer that the client must refuse, on a fresh exchange each time.
    const auto refused = [&](auto mutate, const keys::CompositePublic& expected,
                             const Fingerprint& expected_predecessor,
                             std::uint8_t expected_depth) {
        auto exchange = ClientExchange::start(crypto()).take_value();
        auto reply = answer(crypto(), exchange.message(), hop, predecessor, 2U)
                         .take_value();
        mutate(reply.message);
        return finish_code(reply.message, expected, expected_predecessor,
                           expected_depth, exchange);
    };
    const auto keep = [](Bytes&) {};
    constexpr std::size_t kSignature = 4U + 32U + 1568U + 32U;
    // A node that routes the circuit through a helper: the hop signs the
    // helper as its predecessor, not the node the client chose.
    auto elsewhere = predecessor;
    elsewhere[0] ^= 1U;
    CHECK(refused(keep, hop.identity, elsewhere, 2U) ==
          StatusCode::PermissionDenied);
    CHECK(refused(keep, hop.identity, predecessor, 3U) ==
          StatusCode::PermissionDenied);
    CHECK(refused(keep, other.identity, predecessor, 2U) ==
          StatusCode::PermissionDenied);
    CHECK(refused([](Bytes& m) { m[kSignature] ^= 1U; }, hop.identity,
                  predecessor, 2U) == StatusCode::PermissionDenied);
    CHECK(refused([](Bytes& m) { m[kSignature + 64U + 100U] ^= 1U; },
                  hop.identity, predecessor,
                  2U) == StatusCode::PermissionDenied);
    CHECK(refused(
              [](Bytes& m) {
                  std::fill(m.begin() + kSignature + 64, m.end(),
                            std::uint8_t{0});
              },
              hop.identity, predecessor, 2U) == StatusCode::PermissionDenied);
    CHECK(refused(
              [](Bytes& m) {
                  std::fill(m.begin() + kSignature, m.begin() + kSignature + 64,
                            std::uint8_t{0});
              },
              hop.identity, predecessor, 2U) == StatusCode::PermissionDenied);
    CHECK(refused([](Bytes& m) { m[4U + 32U + 1568U] ^= 1U; }, hop.identity,
                  predecessor, 2U) == StatusCode::PermissionDenied);
    CHECK(refused([](Bytes& m) { m[4U + 32U + 10U] ^= 1U; }, hop.identity,
                  predecessor, 2U) == StatusCode::PermissionDenied);
    CHECK(refused([](Bytes& m) { m[4U + 5U] ^= 1U; }, hop.identity, predecessor,
                  2U) == StatusCode::PermissionDenied);
    CHECK(refused([](Bytes& m) { m[0] = 2U; }, hop.identity, predecessor, 2U) ==
          StatusCode::InvalidArgument);
    CHECK(refused([](Bytes& m) { m.pop_back(); }, hop.identity, predecessor,
                  2U) == StatusCode::InvalidArgument);
    CHECK(refused(keep, hop.identity, Fingerprint{}, 2U) ==
          StatusCode::InvalidArgument);
    CHECK(refused(keep, hop.identity, predecessor, 1U) ==
          StatusCode::InvalidArgument);
    CHECK(refused(keep, hop.identity, predecessor, 4U) ==
          StatusCode::InvalidArgument);
    auto unnamed = hop.identity;
    unnamed.fingerprint = "not a fingerprint";
    CHECK(refused(keep, unnamed, predecessor, 2U) ==
          StatusCode::InvalidArgument);

    // A hop that signs a confirmation its keys do not produce, with its own
    // valid key, still fails at the confirmation check.
    {
        auto exchange = ClientExchange::start(crypto()).take_value();
        auto reply = answer(crypto(), exchange.message(), hop, predecessor, 2U)
                         .take_value();
        auto decoded = *circuit1::DecodeHopHandshake(reply.message).value;
        const auto hop_fingerprint =
            *fingerprint_bytes(hop.identity.fingerprint);
        const auto transcript = transcript_hash(
            crypto(), hop_fingerprint, predecessor, 2U, exchange.message(),
            decoded.x25519_public, decoded.mlkem_ciphertext);
        decoded.confirmation[0] ^= 1U;
        const auto input = signed_bytes(transcript, decoded.confirmation);
        const auto resigned = keys::sign_composite(
            crypto().key_context(), hop, std::as_bytes(std::span(input)));
        std::transform(
            resigned.begin(), resigned.end(), decoded.signature.begin(),
            [](std::byte value) { return static_cast<std::uint8_t>(value); });
        const auto forged = circuit1::EncodeHopHandshake(decoded);
        const auto result =
            exchange.finish(crypto(), forged, hop.identity, predecessor, 2U);
        CHECK(result.status().code() == StatusCode::PermissionDenied);
        CHECK(result.status().message() == "circuit hop confirmation failed");
    }

    // What the hop refuses.
    auto exchange = ClientExchange::start(crypto()).take_value();
    Bytes request(exchange.message().begin(), exchange.message().end());
    CHECK(answer(crypto(), request, hop, Fingerprint{}, 2U).status().code() ==
          StatusCode::InvalidArgument);
    CHECK(answer(crypto(), request, hop, predecessor, 1U).status().code() ==
          StatusCode::InvalidArgument);
    CHECK(answer(crypto(), request, hop, predecessor, 0U).status().code() ==
          StatusCode::InvalidArgument);
    auto schema = request;
    schema[0] = 2U;
    CHECK(answer(crypto(), schema, hop, predecessor, 2U).status().code() ==
          StatusCode::InvalidArgument);
    auto bad_kem = request;
    std::fill(bad_kem.begin() + 4 + 32 + 32, bad_kem.end(), std::uint8_t{0xff});
    CHECK(answer(crypto(), bad_kem, hop, predecessor, 2U).status().code() ==
          StatusCode::InvalidArgument);
    auto zero_x = request;
    std::fill(zero_x.begin() + 4 + 32, zero_x.begin() + 4 + 32 + 32,
              std::uint8_t{0});
    CHECK(answer(crypto(), zero_x, hop, predecessor, 2U).status().code() ==
          StatusCode::InvalidArgument);
    request.pop_back();
    CHECK(answer(crypto(), request, hop, predecessor, 2U).status().code() ==
          StatusCode::InvalidArgument);
}

}  // namespace

int main() {
    try {
        TestDeterministicSteps();
        TestX25519KnownAnswer();
        TestEncodingDigests();
        TestLayerVectors();
        TestLayerRefusals();
        TestHandshake();
    } catch (const std::exception& error) {
        std::cerr << "circuit crypto test aborted: " << error.what() << '\n';
        return 1;
    }
    if (g_failures != 0) {
        std::cerr << g_failures << " circuit crypto check(s) failed\n";
        return 1;
    }
    std::cout << "circuit crypto tests passed\n";
    return 0;
}
