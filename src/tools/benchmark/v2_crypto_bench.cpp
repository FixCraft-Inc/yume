/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "tools/benchmark/v2_crypto_bench.hpp"

#include <algorithm>
#include <chrono>
#include <stdexcept>
#include <utility>

#include <basefwx/crypto.hpp>
#include <basefwx/pq.hpp>
#include <basefwx/x25519.hpp>

#include "core/protocol/protocol.hpp"
#include "core/security/session_ratchet.hpp"

namespace yume::tools::benchmark {
namespace {

using Clock = std::chrono::steady_clock;
using Bytes = std::vector<std::uint8_t>;

double elapsed_seconds(Clock::time_point start, Clock::time_point end) {
    return std::chrono::duration<double>(end - start).count();
}

void require_same(const Bytes& left, const Bytes& right,
                  const char* description) {
    if (left != right) {
        throw std::runtime_error(description);
    }
}

struct PairSecrets {
    basefwx::crypto::SecureBytes root;
    basefwx::crypto::SecureBytes psk_key;
};

PairSecrets make_pair_secrets() {
    basefwx::crypto::SecureBytes file_psk{
        basefwx::crypto::RandomBytes(32)};
    const Bytes salt = basefwx::crypto::RandomBytes(32);
    basefwx::crypto::SecureBytes psk_key{
        ratchet::DerivePskKey(file_psk.bytes(), salt)};
    return {
        basefwx::crypto::SecureBytes{basefwx::crypto::RandomBytes(32)},
        std::move(psk_key),
    };
}

}  // namespace

void verify_hybrid_establishment() {
    auto mlkem = basefwx::pq::GenerateKeyPair(
        basefwx::pq::KemAlgorithm::MlKem1024);
    auto encapsulated = basefwx::pq::KemEncrypt(
        basefwx::pq::KemAlgorithm::MlKem1024, mlkem.public_key);
    basefwx::crypto::SecureBytes decapsulated{
        basefwx::pq::KemDecrypt(basefwx::pq::KemAlgorithm::MlKem1024,
                                mlkem.private_key,
                                encapsulated.ciphertext)};
    require_same(encapsulated.shared, decapsulated.bytes(),
                 "ML-KEM-1024 peers derived different secrets");

    auto server_x25519 = basefwx::x25519::GenerateKeyPair();
    auto client_x25519 = basefwx::x25519::GenerateKeyPair();
    basefwx::crypto::SecureBytes client_x_shared{
        basefwx::x25519::DeriveSharedSecret(client_x25519.private_key,
                                            server_x25519.public_key)};
    basefwx::crypto::SecureBytes server_x_shared{
        basefwx::x25519::DeriveSharedSecret(server_x25519.private_key,
                                            client_x25519.public_key)};
    require_same(client_x_shared.bytes(), server_x_shared.bytes(),
                 "X25519 peers derived different secrets");

    basefwx::crypto::SecureBytes file_psk{
        basefwx::crypto::RandomBytes(32)};
    const Bytes psk_salt = basefwx::crypto::RandomBytes(32);
    const Bytes transcript_salt = basefwx::crypto::RandomBytes(32);
    basefwx::crypto::SecureBytes client_psk{
        ratchet::DerivePskKey(file_psk.bytes(), psk_salt)};
    basefwx::crypto::SecureBytes server_psk{
        ratchet::DerivePskKey(file_psk.bytes(), psk_salt)};

    basefwx::crypto::SecureBytes client_root{ratchet::DeriveInitialRoot(
        encapsulated.shared, client_x_shared.bytes(), client_psk.bytes(),
        transcript_salt)};
    basefwx::crypto::SecureBytes server_root{ratchet::DeriveInitialRoot(
        decapsulated.bytes(), server_x_shared.bytes(), server_psk.bytes(),
        transcript_salt)};
    require_same(client_root.bytes(), server_root.bytes(),
                 "hybrid peers derived different initial roots");
}

class SessionPair::Impl {
public:
    explicit Impl(PairSecrets secrets)
        : client_(ratchet::EndpointRole::Client,
                  secrets.root.bytes(), secrets.psk_key.bytes()),
          server_(ratchet::EndpointRole::Server,
                  secrets.root.bytes(), secrets.psk_key.bytes()) {}

    TransferResult transfer(std::uint64_t total_bytes,
                            std::size_t chunk_bytes,
                            ratchet::Direction direction) {
        const std::size_t chunk = std::clamp<std::size_t>(
            chunk_bytes, 1, ratchet::kMaxProtectedPayload);
        std::vector<std::uint8_t> payload(chunk, 0x5a);
        TransferResult result;
        const auto started = Clock::now();

        while (result.plaintext_bytes < total_bytes) {
            const std::size_t take = static_cast<std::size_t>(
                std::min<std::uint64_t>(chunk,
                    total_bytes - result.plaintext_bytes));
            payload.resize(take);
            protocol::Frame plain{
                {static_cast<std::uint32_t>(take), protocol::DATA, 7, 0},
                payload,
            };
            auto& sender = direction == ratchet::Direction::ClientToServer
                ? client_ : server_;
            auto& receiver = direction == ratchet::Direction::ClientToServer
                ? server_ : client_;
            const auto now = Clock::now();
            if (sender.ShouldStartRekey(plain, now)) {
                exchange_rekey(sender, receiver, now);
                ++result.rekeys;
            }
            auto opened = receiver.Open(sender.Seal(plain, now), now);
            if (!opened.application_frame.has_value() ||
                opened.application_frame->payload != payload) {
                throw std::runtime_error("ratchet transfer verification failed");
            }
            result.plaintext_bytes += take;
            ++result.frames;
        }
        result.seconds = elapsed_seconds(started, Clock::now());
        return result;
    }

    void rekey(ratchet::Direction direction) {
        auto& sender = direction == ratchet::Direction::ClientToServer
            ? client_ : server_;
        auto& receiver = direction == ratchet::Direction::ClientToServer
            ? server_ : client_;
        const auto now = Clock::now();
        exchange_rekey(sender, receiver, now);

        // The receiver retires its old chain only after authenticating the
        // first new-epoch frame. Include that boundary in the measurement.
        protocol::Frame boundary{{1, protocol::DATA, 7, 0}, {0xa5}};
        auto opened = receiver.Open(sender.Seal(boundary, now), now);
        if (!opened.application_frame.has_value() ||
            opened.application_frame->payload != boundary.payload) {
            throw std::runtime_error("ratchet rekey boundary verification failed");
        }
    }

private:
    static void exchange_rekey(ratchet::SessionRatchet& sender,
                               ratchet::SessionRatchet& receiver,
                               Clock::time_point now) {
        auto init = sender.BeginOutboundRekey(now);
        auto received = receiver.Open(init, now);
        if (!received.control_response.has_value()) {
            throw std::runtime_error("ratchet peer did not return REKEY_ACK");
        }
        auto completed = sender.Open(*received.control_response, now);
        if (!completed.outbound_rekey_completed) {
            throw std::runtime_error("ratchet sender did not complete rekey");
        }
    }

    ratchet::SessionRatchet client_;
    ratchet::SessionRatchet server_;
};

SessionPair::SessionPair()
    : impl_(std::make_unique<Impl>(make_pair_secrets())) {}
SessionPair::~SessionPair() = default;
SessionPair::SessionPair(SessionPair&&) noexcept = default;
SessionPair& SessionPair::operator=(SessionPair&&) noexcept = default;

TransferResult SessionPair::transfer(std::uint64_t plaintext_bytes,
                                     std::size_t chunk_bytes,
                                     ratchet::Direction direction) {
    return impl_->transfer(plaintext_bytes, chunk_bytes, direction);
}

void SessionPair::rekey(ratchet::Direction direction) {
    impl_->rekey(direction);
}

}  // namespace yume::tools::benchmark
