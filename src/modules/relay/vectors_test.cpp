/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// Known answers for the relay channel's frozen labels and layouts. The
// fixture comes from testdata/generate_relay_vectors.py, which implements the
// formulas in docs/protocol/RELAY_CHANNEL.md without YUME code. A mismatch
// means the code, the page or the fixture changed a frozen value.

#include "modules/relay/frame.hpp"
#include "modules/relay/handshake_detail.hpp"
#include "modules/relay/ratchet.hpp"
#include "modules/relay/record.hpp"
#include "modules/relay/session_ratchet.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

namespace relay = yume::relay;
namespace ratchet = yume::relay::ratchet;
using relay::Bytes;

void Check(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

class Vectors final {
public:
    Vectors() {
        std::ifstream input(YUME_RELAY_VECTORS_FILE);
        Check(input.is_open(), "cannot open the relay vectors");
        std::string line;
        while (std::getline(input, line)) {
            if (line.empty() || line.front() == '#') continue;
            const auto separator = line.find('=');
            Check(separator != std::string::npos && separator != 0U,
                  "invalid relay vector entry");
            const std::string name = line.substr(0U, separator);
            const std::string_view encoded(line.data() + separator + 1U,
                                           line.size() - separator - 1U);
            Check(encoded.size() % 2U == 0U && encoded.size() <= 65536U,
                  "invalid relay vector size: " + name);
            Bytes bytes;
            bytes.reserve(encoded.size() / 2U);
            for (std::size_t offset = 0U; offset < encoded.size(); offset += 2U) {
                const auto nibble = [&](char value) -> std::uint8_t {
                    if (value >= '0' && value <= '9') {
                        return static_cast<std::uint8_t>(value - '0');
                    }
                    Check(value >= 'a' && value <= 'f', "invalid relay vector hex: " + name);
                    return static_cast<std::uint8_t>(value - 'a' + 10);
                };
                bytes.push_back(static_cast<std::uint8_t>(
                    (nibble(encoded[offset]) << 4U) | nibble(encoded[offset + 1U])));
            }
            Check(values_.emplace(name, std::move(bytes)).second,
                  "duplicate relay vector entry: " + name);
        }
        Check(input.eof(), "relay vector read failed");
    }

    const Bytes& get(std::string_view name) const {
        const auto found = values_.find(name);
        Check(found != values_.end(), "missing relay vector: " + std::string(name));
        return found->second;
    }

    void matches(std::string_view name, std::span<const std::uint8_t> actual) const {
        const Bytes& expected = get(name);
        Check(std::equal(actual.begin(), actual.end(), expected.begin(), expected.end()),
              "relay known-answer mismatch: " + std::string(name));
    }

private:
    std::map<std::string, Bytes, std::less<>> values_;
};

void TestHandshakeDerivations(const Vectors& vectors) {
    vectors.matches("request_signature_input",
                    relay::detail::BuildRequestSignatureInput(
                        vectors.get("unsigned_request")).bytes());
    vectors.matches("response_signature_input",
                    relay::detail::BuildResponseSignatureInput(
                        vectors.get("request"), vectors.get("unsigned_response")).bytes());
    vectors.matches("request_digest", relay::detail::RequestDigest(vectors.get("request")));

    const relay::detail::DerivedPair with_psk = relay::detail::DeriveSecrets(
        vectors.get("request"), vectors.get("response"), vectors.get("mlkem_shared"),
        vectors.get("x25519_shared"), vectors.get("relay_psk"));
    vectors.matches("initial_root", with_psk.initial_root.bytes());
    vectors.matches("epoch_psk", with_psk.epoch_psk.bytes());

    const relay::detail::DerivedPair without_psk = relay::detail::DeriveSecrets(
        vectors.get("request"), vectors.get("response"), vectors.get("mlkem_shared"),
        vectors.get("x25519_shared"), Bytes{});
    vectors.matches("initial_root_without_psk", without_psk.initial_root.bytes());
    vectors.matches("epoch_psk_without_psk", without_psk.epoch_psk.bytes());
}

void TestRatchetAndRecords(const Vectors& vectors) {
    const Bytes& initial_root = vectors.get("initial_root");
    const Bytes& epoch_psk = vectors.get("epoch_psk");
    const auto now = std::chrono::steady_clock::time_point{};

    const Bytes c2s_root =
        ratchet::DeriveDirectionRoot(initial_root, ratchet::Direction::ClientToServer);
    const Bytes s2c_root =
        ratchet::DeriveDirectionRoot(initial_root, ratchet::Direction::ServerToClient);
    vectors.matches("c2s_root", c2s_root);
    vectors.matches("s2c_root", s2c_root);

    // Two records from one client pin the envelope, the record header and the
    // chain step between frames. The server's first record pins the other
    // direction's root and direction byte.
    ratchet::SessionRatchet client(ratchet::EndpointRole::Client, initial_root, epoch_psk);
    ratchet::SessionRatchet server(ratchet::EndpointRole::Server, initial_root, epoch_psk);
    const Bytes c2s_record_0 =
        relay::record::SealApplication(client, vectors.get("plaintext_0"), now);
    const Bytes c2s_record_1 =
        relay::record::SealApplication(client, vectors.get("plaintext_1"), now);
    vectors.matches("c2s_record_0", c2s_record_0);
    vectors.matches("c2s_record_1", c2s_record_1);
    vectors.matches("s2c_record_0",
                    relay::record::SealApplication(server, vectors.get("plaintext_0"), now));

    // The reference bytes also open on the receiving side.
    for (const auto& [name, plaintext] :
         {std::pair{"c2s_record_0", "plaintext_0"}, std::pair{"c2s_record_1", "plaintext_1"}}) {
        const ratchet::OpenResult opened =
            relay::record::OpenRecord(server, vectors.get(name), now);
        Check(opened.application_frame.has_value() &&
                  opened.application_frame->payload == vectors.get(plaintext),
              std::string("reference record did not open: ") + name);
    }

    // A REKEY_INIT frame on a fresh chain differs from DATA only in the type
    // byte of the associated data.
    ratchet::DirectionalRatchet rekey_chain(ratchet::Direction::ClientToServer, c2s_root);
    vectors.matches("c2s_rekey_ciphertext",
                    rekey_chain
                        .Encrypt(relay::kFrameRekeyInit, 0, relay::kFlagInnerEncrypted,
                                 vectors.get("rekey_payload"), now, false)
                        .ciphertext);

    vectors.matches("c2s_epoch_psk_1",
                    ratchet::DeriveEpochPskContribution(
                        epoch_psk, ratchet::Direction::ClientToServer, 1));
    vectors.matches("s2c_epoch_psk_1",
                    ratchet::DeriveEpochPskContribution(
                        epoch_psk, ratchet::Direction::ServerToClient, 1));
    const ratchet::DirectionalRatchet epoch_0(ratchet::Direction::ClientToServer, c2s_root);
    const auto epoch_1 = epoch_0.MakeAdvanced(vectors.get("rekey_mlkem_shared"),
                                              vectors.get("rekey_x25519_shared"), epoch_psk);
    const ratchet::SealedFrame sealed = epoch_1->Encrypt(
        relay::kFrameData, 0, relay::kFlagInnerEncrypted, vectors.get("plaintext_0"), now);
    Check(sealed.epoch == 1 && sealed.sequence == 0, "advanced epoch did not start at zero");
    vectors.matches("c2s_epoch_1_ciphertext", sealed.ciphertext);
}

}  // namespace

int main() {
    try {
        const Vectors vectors;
        TestHandshakeDerivations(vectors);
        TestRatchetAndRecords(vectors);
    } catch (const std::exception& error) {
        std::cerr << "relay vectors test failed: " << error.what() << '\n';
        return 1;
    }
    std::cout << "relay vectors test ok\n";
    return 0;
}
