/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "modules/relay/ratchet.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>

#include "test_support/allocation_failure.hpp"

namespace {

using yume::relay::ratchet::Bytes;
using yume::relay::ratchet::Direction;
using yume::relay::ratchet::DirectionalRatchet;

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

Bytes FromHex(std::string_view hex) {
    Bytes out;
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<std::uint8_t>(std::stoi(std::string(hex.substr(i, 2)), nullptr, 16)));
    }
    return out;
}

constexpr std::uint8_t kRekeyProbeRootByte = 0xd3U;
constexpr std::size_t kRekeyProbePrefixBytes = 4U + 32U;

struct RekeyAllocation {
    void* storage{nullptr};
    std::size_t size{0};
    bool contains_input{false};
};

struct RekeyInputProbe {
    std::array<RekeyAllocation, 32> allocations{};
    std::size_t observed{0};
    std::size_t released{0};
    std::size_t unwiped{0};
    bool overflow{false};
    bool fail_after_input{false};
    bool failed{false};
};

RekeyInputProbe rekey_probe;

void recognize_rekey_input(RekeyAllocation& allocation) noexcept {
    if (!allocation.storage || allocation.contains_input) return;
    const auto* bytes = static_cast<const std::uint8_t*>(allocation.storage);
    if (bytes[0] == 0U && bytes[1] == 0U && bytes[2] == 0U && bytes[3] == 32U &&
        std::all_of(
            bytes + 4U, bytes + kRekeyProbePrefixBytes,
            [](std::uint8_t byte) { return byte == kRekeyProbeRootByte; })) {
        allocation.contains_input = true;
        ++rekey_probe.observed;
    }
}

void before_rekey_allocation(std::size_t) {
    for (auto& allocation : rekey_probe.allocations) {
        recognize_rekey_input(allocation);
    }
    if (rekey_probe.fail_after_input && rekey_probe.observed != 0U &&
        !rekey_probe.failed) {
        rekey_probe.failed = true;
        throw std::bad_alloc();
    }
}

void observe_rekey_allocation(void* storage, std::size_t size) {
    if (size < kRekeyProbePrefixBytes || size > 512U) return;
    // Initialize the storage before construction so recognition never reads
    // indeterminate bytes from unrelated allocations or spare capacity.
    std::memset(storage, 0, size);
    for (auto& allocation : rekey_probe.allocations) {
        if (!allocation.storage) {
            allocation = {storage, size, false};
            return;
        }
    }
    rekey_probe.overflow = true;
}

void observe_rekey_release(void* storage) noexcept {
    if (!storage) return;
    for (auto& allocation : rekey_probe.allocations) {
        if (allocation.storage != storage) continue;
        recognize_rekey_input(allocation);
        if (allocation.contains_input) {
            ++rekey_probe.released;
            const auto* bytes = static_cast<const std::uint8_t*>(storage);
            if (!std::all_of(bytes, bytes + allocation.size,
                             [](std::uint8_t byte) { return byte == 0U; })) {
                ++rekey_probe.unwiped;
            }
        }
        allocation = {};
        return;
    }
}

class RekeyAllocationObserver {
public:
    RekeyAllocationObserver() noexcept {
        yume::test::before_allocate = before_rekey_allocation;
        yume::test::after_allocate = observe_rekey_allocation;
        yume::test::before_deallocate = observe_rekey_release;
    }
    ~RekeyAllocationObserver() {
        yume::test::before_allocate = nullptr;
        yume::test::after_allocate = nullptr;
        yume::test::before_deallocate = nullptr;
    }
    RekeyAllocationObserver(const RekeyAllocationObserver&) = delete;
    RekeyAllocationObserver& operator=(const RekeyAllocationObserver&) = delete;
};

void test_rekey_input_wiped_before_release() {
    // Negative control: ordinary vector growth releases the marked input
    // without wiping it, which the observer must detect.
    rekey_probe = {};
    {
        RekeyAllocationObserver observer;
        Bytes unguarded(kRekeyProbePrefixBytes, 0U);
        unguarded[3] = 32U;
        std::fill(unguarded.begin() + 4U, unguarded.end(), kRekeyProbeRootByte);
        yume::test::keep_contents(unguarded.data());
        unguarded.reserve(2U * kRekeyProbePrefixBytes);
    }
    assert(!rekey_probe.overflow && rekey_probe.observed != 0U &&
           rekey_probe.released == rekey_probe.observed &&
           rekey_probe.unwiped != 0U);

    DirectionalRatchet source(Direction::ClientToServer,
                              Filled(32U, kRekeyProbeRootByte));
    const Bytes kem = Filled(32U, 0x71U);
    const Bytes x25519 = Filled(32U, 0x72U);
    const Bytes psk = Filled(32U, 0x73U);
    for (const bool fail : {false, true}) {
        rekey_probe = {};
        rekey_probe.fail_after_input = fail;
        bool completed = false;
        {
            RekeyAllocationObserver observer;
            try {
                auto advanced = source.MakeAdvanced(kem, x25519, psk);
                assert(advanced->epoch() == 1U);
                completed = true;
            } catch (const std::bad_alloc&) {
                assert(fail);
            }
        }
        assert(!rekey_probe.overflow && rekey_probe.observed != 0U &&
               rekey_probe.released == rekey_probe.observed &&
               rekey_probe.unwiped == 0U);
        assert(completed != fail && rekey_probe.failed == fail);
        assert(source.epoch() == 0U);
    }
}

// Known answers from the transport-v2 ratchet this copy came from. The root is
// the one its own test derived. Matching them shows that the labels, the
// associated data with its profile label, and the nonce layout are unchanged.
void TestDirectionalRoundTripAndReplayRejection() {
    const Bytes root = FromHex(
        "2aaed7289f27db3197d4cb0b47197c132a53402d688cb544190dd724258e8b48");
    Bytes direction = yume::relay::ratchet::DeriveDirectionRoot(root, Direction::ClientToServer);
    assert(Hex(direction) ==
           "91ac5244bb48d9ffffd23b927c42a9a1f8ecacfff28b2726ae999e19f9396308");
    DirectionalRatchet sender(Direction::ClientToServer, direction);
    DirectionalRatchet receiver(
        Direction::ClientToServer,
        yume::relay::ratchet::DeriveDirectionRoot(root, Direction::ClientToServer));

    const auto now = std::chrono::steady_clock::time_point{};
    const Bytes plaintext{'h', 'e', 'l', 'l', 'o'};
    auto sealed = sender.Encrypt(3, 7, 0x0042, plaintext, now);
    assert(Hex(sealed.ciphertext) ==
           "185d299a151e660b0b56088b937ccc358ea22ee6c5");
    assert(receiver.Decrypt(3, 7, 0x0042, sealed, now) == plaintext);
    assert(Throws([&] { (void)receiver.Decrypt(3, 7, 0x0042, sealed, now); }));

    DirectionalRatchet wrong_direction(
        Direction::ServerToClient,
        yume::relay::ratchet::DeriveDirectionRoot(root, Direction::ServerToClient));
    assert(Throws([&] { (void)wrong_direction.Decrypt(3, 7, 0x0042, sealed, now); }));
    assert(Throws([&] { (void)yume::relay::ratchet::DeriveDirectionRoot(Bytes(31, 1), Direction::ClientToServer); }));
}

void TestMessageBoundaryAndIdleSilence() {
    DirectionalRatchet sender(Direction::ClientToServer, Filled(32, 0x81));
    const auto start = std::chrono::steady_clock::time_point{};
    assert(!sender.ShouldRekey(0, start + std::chrono::hours(24)));
    for (std::uint64_t i = 0; i < yume::relay::ratchet::kEpochMessageLimit; ++i) {
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
    const Bytes block(yume::relay::ratchet::kMaxProtectedPayload, 0x7a);
    for (std::size_t i = 0;
         i < yume::relay::ratchet::kEpochByteLimit / yume::relay::ratchet::kMaxProtectedPayload;
         ++i) {
        auto sealed = sender.Encrypt(3, 1, 0, block, now);
        assert(receiver.Decrypt(3, 1, 0, sealed, now) == block);
    }
    assert(sender.ShouldRekey(1, now));
    assert(Throws([&] { (void)sender.Encrypt(3, 1, 0, Bytes{1}, now); }));

    const Bytes kem = Filled(32, 0x71);
    const Bytes x25519 = Filled(32, 0x72);
    const Bytes psk = Filled(32, 0x73);
    const Bytes c2s_epoch_psk = yume::relay::ratchet::DeriveEpochPskContribution(
        psk, Direction::ClientToServer, 1);
    const Bytes s2c_epoch_psk = yume::relay::ratchet::DeriveEpochPskContribution(
        psk, Direction::ServerToClient, 1);
    assert(c2s_epoch_psk != s2c_epoch_psk);
    // Known answers from the transport-v2 ratchet for the epoch PSK and the
    // advanced epoch. An epoch derives from the old root, not the chain, so the
    // traffic above does not change them.
    assert(Hex(c2s_epoch_psk) ==
           "4ebc5a195e5d8008dc11a967fb5c681a6ea5814c5ea44de6a33ad8373ae0df18");
    sender.Advance(kem, x25519, psk);
    receiver.Advance(kem, x25519, psk);
    assert(sender.epoch() == 1 && receiver.epoch() == 1);
    auto sealed = sender.Encrypt(3, 1, 0, Bytes{9, 8, 7}, now);
    assert(sealed.epoch == 1 && sealed.sequence == 0);
    assert(Hex(sealed.ciphertext) == "f289ddb2a79e2f232fad37ebed3538020762d3");
    assert(receiver.Decrypt(3, 1, 0, sealed, now) == Bytes({9, 8, 7}));
}

void TestReceiverRejectsNonconformingEpochUsage() {
    const auto now = std::chrono::steady_clock::time_point{};

    DirectionalRatchet byte_sender(Direction::ClientToServer, Filled(32, 0x91));
    DirectionalRatchet byte_receiver(Direction::ClientToServer, Filled(32, 0x91));
    auto full_epoch = byte_sender.Encrypt(
        3, 1, 0, Filled(yume::relay::ratchet::kEpochByteLimit, 0x92), now, false);
    assert(byte_receiver.Decrypt(3, 1, 0, full_epoch, now) ==
           Filled(yume::relay::ratchet::kEpochByteLimit, 0x92));
    auto extra_byte = byte_sender.Encrypt(3, 1, 0, Bytes{0x93}, now, false);
    assert(Throws([&] {
        (void)byte_receiver.Decrypt(3, 1, 0, extra_byte, now);
    }));

    DirectionalRatchet frame_sender(Direction::ClientToServer, Filled(32, 0xa1));
    DirectionalRatchet frame_receiver(Direction::ClientToServer, Filled(32, 0xa1));
    for (std::uint64_t i = 0; i < yume::relay::ratchet::kEpochMessageLimit; ++i) {
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
        yume::relay::ratchet::kEpochByteLimit - yume::relay::ratchet::kRekeyByteLead;

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
        yume::relay::ratchet::kEpochMessageLimit -
        yume::relay::ratchet::kRekeyMessageLead - 2;
    for (std::uint64_t i = 0; i < frames_before_prepare; ++i) {
        (void)messages.Encrypt(3, 1, 0, {}, start);
    }
    assert(!messages.ShouldPrepareRekey(0, start));
    (void)messages.Encrypt(3, 1, 0, {}, start);
    assert(messages.ShouldPrepareRekey(0, start));
    assert(!messages.ShouldRekey(0, start));
}

void TestExactCustomTiming() {
    using namespace std::chrono_literals;
    using namespace yume::relay::ratchet;

    const RatchetPolicy exact{
        4ULL * 1024ULL * 1024ULL,
        4096,
        4281ms,
    };
    assert(IsRatchetPolicyValid(exact));
    DirectionalRatchet sender(
        Direction::ClientToServer, Filled(32, 0xc1), exact);
    const auto start = std::chrono::steady_clock::time_point{};
    (void)sender.Encrypt(3, 1, 0, Bytes{0x01}, start);
    assert(!sender.ShouldRekey(1, start + 4280ms));
    assert(sender.ShouldRekey(1, start + 4281ms));

    // A policy outside the reviewed bounds never reaches a chain.
    RatchetPolicy too_small = kExtremePolicy;
    too_small.epoch_byte_limit = kMinEpochByteLimit - 1;
    assert(!IsRatchetPolicyValid(too_small));
    assert(Throws([&] {
        (void)DirectionalRatchet(Direction::ClientToServer, Filled(32, 0xc2), too_small);
    }));
    RatchetPolicy no_time = kExtremePolicy;
    no_time.epoch_active_limit = 0ms;
    assert(Throws([&] {
        (void)DirectionalRatchet(Direction::ClientToServer, Filled(32, 0xc3), no_time);
    }));
}

}  // namespace

int main() {
    test_rekey_input_wiped_before_release();
    TestDirectionalRoundTripAndReplayRejection();
    TestAadTamperAndTimeBoundary();
    TestByteBoundaryAndEpochAdvance();
    TestMessageBoundaryAndIdleSilence();
    TestReceiverRejectsNonconformingEpochUsage();
    TestPipelinedPreparationThresholds();
    TestExactCustomTiming();
    return 0;
}
