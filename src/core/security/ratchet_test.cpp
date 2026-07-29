/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/security/ratchet.hpp"

#include <cassert>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace {

using yume::ratchet::Bytes;
using yume::ratchet::Direction;
using yume::ratchet::DirectionalRatchet;

Bytes Filled(std::size_t size, std::uint8_t value) {
    return Bytes(size, value);
}

std::string Hex(const Bytes& value) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (const auto byte : value) out << std::setw(2) << static_cast<int>(byte);
    return out.str();
}

template <typename Fn>
bool Throws(Fn&& fn) {
    try {
        fn();
        return false;
    } catch (const std::exception&) {
        return true;
    }
}

void TestDirectionalRoundTripAndReplayRejection() {
    const Bytes raw_psk = Filled(32, 0x31);
    const Bytes psk_salt = Filled(32, 0x32);
    const Bytes psk_key = yume::ratchet::DerivePskKey(raw_psk, psk_salt);
    assert(psk_key.size() == 32);
    assert(psk_key != raw_psk);
    assert(Hex(psk_key) ==
           "0710f2aeea8b711e4d1983a34ab4c224028141ce3e2b6bc22ee4ac6f503e59be");
    yume::ratchet::InitialSecrets secrets{
        Filled(32, 0x11), Filled(32, 0x22), psk_key, Filled(32, 0x44),
        Filled(32, 0x55)};
    Bytes root = yume::ratchet::DeriveInitialRoot(secrets);
    assert(Hex(root) ==
           "d947df7ab4bda8bf86c833b57ffd91320ef22b9c159013f473cfbe13114d33a0");

    // Two endpoints that read different TLS exporters — the live-relay shape —
    // never reach the same root, independently of the AUTH signature check.
    yume::ratchet::InitialSecrets relayed = secrets;
    relayed.channel_binding = Filled(32, 0x56);
    assert(yume::ratchet::DeriveInitialRoot(relayed) != root);

    // There is no unbound root: a missing or short binding is fatal, so no
    // build can quietly establish a session without channel binding.
    for (std::size_t bad_size : {std::size_t{0}, std::size_t{16},
                                 std::size_t{33}}) {
        yume::ratchet::InitialSecrets unbound = secrets;
        unbound.channel_binding = Filled(bad_size, 0x55);
        assert(Throws([&] { (void)yume::ratchet::DeriveInitialRoot(unbound); }));
    }

    Bytes direction = yume::ratchet::DeriveDirectionRoot(root, Direction::ClientToServer);
    assert(Hex(direction) ==
           "dde2b21896272ad2d8abc5d69a2d0ddb5e7ae63f5c2bf4ec819b52bb9ca34ccb");
    DirectionalRatchet sender(Direction::ClientToServer, direction);
    DirectionalRatchet receiver(
        Direction::ClientToServer,
        yume::ratchet::DeriveDirectionRoot(root, Direction::ClientToServer));

    const auto now = std::chrono::steady_clock::time_point{};
    const Bytes plaintext{'h', 'e', 'l', 'l', 'o'};
    auto sealed = sender.Encrypt(3, 7, 0x0042, plaintext, now);
    assert(Hex(sealed.ciphertext) ==
           "e7166514ea6be0fb27fe7ea2b617b5341fed414769");
    assert(receiver.Decrypt(3, 7, 0x0042, sealed, now) == plaintext);
    assert(Throws([&] { (void)receiver.Decrypt(3, 7, 0x0042, sealed, now); }));

    DirectionalRatchet wrong_direction(
        Direction::ServerToClient,
        yume::ratchet::DeriveDirectionRoot(root, Direction::ServerToClient));
    assert(Throws([&] { (void)wrong_direction.Decrypt(3, 7, 0x0042, sealed, now); }));
}

void TestMessageBoundaryAndIdleSilence() {
    DirectionalRatchet sender(Direction::ClientToServer, Filled(32, 0x81));
    const auto start = std::chrono::steady_clock::time_point{};
    assert(!sender.ShouldRekey(0, start + std::chrono::hours(24)));
    for (std::uint64_t i = 0; i < yume::ratchet::kEpochMessageLimit; ++i) {
        (void)sender.Encrypt(3, 1, 0, {}, start);
    }
    assert(sender.ShouldRekey(0, start));
    assert(Throws([&] { (void)sender.Encrypt(3, 1, 0, {}, start); }));
}

void TestAadTamperAndTimeBoundary() {
    Bytes root = Filled(32, 0x51);
    DirectionalRatchet sender(Direction::ClientToServer, root);
    DirectionalRatchet receiver(Direction::ClientToServer, Filled(32, 0x51));
    const auto start = std::chrono::steady_clock::time_point{};
    auto sealed = sender.Encrypt(3, 1, 0, Bytes{1, 2, 3}, start);
    assert(Throws([&] { (void)receiver.Decrypt(3, 2, 0, sealed, start); }));
    assert(!sender.ShouldRekey(1, start + std::chrono::milliseconds(499)));
    assert(sender.ShouldRekey(1, start + std::chrono::milliseconds(500)));
}

void TestByteBoundaryAndEpochAdvance() {
    DirectionalRatchet sender(Direction::ClientToServer, Filled(32, 0x61));
    DirectionalRatchet receiver(Direction::ClientToServer, Filled(32, 0x61));
    const auto now = std::chrono::steady_clock::time_point{};
    const Bytes block(yume::ratchet::kMaxProtectedPayload, 0x7a);
    for (std::size_t i = 0;
         i < yume::ratchet::kEpochByteLimit / yume::ratchet::kMaxProtectedPayload;
         ++i) {
        auto sealed = sender.Encrypt(3, 1, 0, block, now);
        assert(receiver.Decrypt(3, 1, 0, sealed, now) == block);
    }
    assert(sender.ShouldRekey(1, now));
    assert(Throws([&] { (void)sender.Encrypt(3, 1, 0, Bytes{1}, now); }));

    const Bytes kem = Filled(32, 0x71);
    const Bytes x25519 = Filled(32, 0x72);
    const Bytes psk = Filled(32, 0x73);
    const Bytes c2s_epoch_psk = yume::ratchet::DeriveEpochPskContribution(
        psk, Direction::ClientToServer, 1);
    const Bytes s2c_epoch_psk = yume::ratchet::DeriveEpochPskContribution(
        psk, Direction::ServerToClient, 1);
    assert(c2s_epoch_psk != s2c_epoch_psk);
    sender.Advance(kem, x25519, psk);
    receiver.Advance(kem, x25519, psk);
    assert(sender.epoch() == 1 && receiver.epoch() == 1);
    auto sealed = sender.Encrypt(3, 1, 0, Bytes{9, 8, 7}, now);
    assert(receiver.Decrypt(3, 1, 0, sealed, now) == Bytes({9, 8, 7}));
}

void TestReceiverRejectsNonconformingEpochUsage() {
    const auto now = std::chrono::steady_clock::time_point{};

    DirectionalRatchet byte_sender(Direction::ClientToServer, Filled(32, 0x91));
    DirectionalRatchet byte_receiver(Direction::ClientToServer, Filled(32, 0x91));
    auto full_epoch = byte_sender.Encrypt(
        3, 1, 0, Filled(yume::ratchet::kEpochByteLimit, 0x92), now, false);
    assert(byte_receiver.Decrypt(3, 1, 0, full_epoch, now) ==
           Filled(yume::ratchet::kEpochByteLimit, 0x92));
    auto extra_byte = byte_sender.Encrypt(3, 1, 0, Bytes{0x93}, now, false);
    assert(Throws([&] {
        (void)byte_receiver.Decrypt(3, 1, 0, extra_byte, now);
    }));

    DirectionalRatchet frame_sender(Direction::ClientToServer, Filled(32, 0xa1));
    DirectionalRatchet frame_receiver(Direction::ClientToServer, Filled(32, 0xa1));
    for (std::uint64_t i = 0; i < yume::ratchet::kEpochMessageLimit; ++i) {
        auto frame = frame_sender.Encrypt(3, 1, 0, {}, now, false);
        assert(frame_receiver.Decrypt(3, 1, 0, frame, now).empty());
    }
    auto extra_frame = frame_sender.Encrypt(3, 1, 0, {}, now, false);
    assert(Throws([&] {
        (void)frame_receiver.Decrypt(3, 1, 0, extra_frame, now);
    }));
}

void TestPipelinedPreparationThresholds() {
    using namespace std::chrono_literals;
    const auto start = std::chrono::steady_clock::time_point{};
    const std::size_t byte_threshold =
        yume::ratchet::kEpochByteLimit - yume::ratchet::kRekeyByteLead;

    DirectionalRatchet bytes(Direction::ClientToServer, Filled(32, 0xb1));
    assert(!bytes.ShouldPrepareRekey(byte_threshold - 1, start));
    assert(bytes.ShouldPrepareRekey(byte_threshold, start));
    assert(!bytes.ShouldRekey(byte_threshold, start));

    DirectionalRatchet time(Direction::ClientToServer, Filled(32, 0xb2));
    (void)time.Encrypt(3, 1, 0, Bytes{0x01}, start);
    assert(!time.ShouldPrepareRekey(1, start + 399ms));
    assert(time.ShouldPrepareRekey(1, start + 400ms));
    assert(!time.ShouldRekey(1, start + 499ms));

    DirectionalRatchet messages(Direction::ClientToServer, Filled(32, 0xb3));
    const std::uint64_t frames_before_prepare =
        yume::ratchet::kEpochMessageLimit -
        yume::ratchet::kRekeyMessageLead - 2;
    for (std::uint64_t i = 0; i < frames_before_prepare; ++i) {
        (void)messages.Encrypt(3, 1, 0, {}, start);
    }
    assert(!messages.ShouldPrepareRekey(0, start));
    (void)messages.Encrypt(3, 1, 0, {}, start);
    assert(messages.ShouldPrepareRekey(0, start));
    assert(!messages.ShouldRekey(0, start));
}

}  // namespace

int main() {
    TestDirectionalRoundTripAndReplayRejection();
    TestAadTamperAndTimeBoundary();
    TestByteBoundaryAndEpochAdvance();
    TestMessageBoundaryAndIdleSilence();
    TestReceiverRejectsNonconformingEpochUsage();
    TestPipelinedPreparationThresholds();
    return 0;
}
