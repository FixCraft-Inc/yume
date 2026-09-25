/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

#include <basefwx/crypto.hpp>

#include "modules/relay/ratchet_policy.hpp"

namespace yume::relay::ratchet {

using Bytes = std::vector<std::uint8_t>;

// The ratchet binds this label into its associated data. It is the
// transport-v2 evidence profile the relay v2 ratchet was defined with, frozen
// here as a protocol label: YUME's current evidence profile has its own
// version and may change without changing relay keys.
inline constexpr std::string_view kProfileLabel = "chrome151-node24-v1";

// Extreme-policy limits used by the boundary tests. Each chain enforces the
// RatchetPolicy it was built with.
inline constexpr std::size_t kEpochByteLimit =
    static_cast<std::size_t>(kExtremePolicy.epoch_byte_limit);
inline constexpr std::uint64_t kEpochMessageLimit =
    kExtremePolicy.epoch_frame_limit;
inline constexpr auto kEpochActiveLimit = kExtremePolicy.epoch_active_limit;

// Preparation of the next hybrid epoch starts with enough current-epoch
// traffic left to hide a normal LAN round trip. These are scheduling
// thresholds only: the hard byte, message and time limits above stay
// unchanged and both sides enforce them independently.
inline constexpr std::size_t kRekeyByteLead = 192U * 1024U;
inline constexpr std::uint64_t kRekeyMessageLead = 64;
inline constexpr auto kRekeyTimeLead = std::chrono::milliseconds(100);
static_assert(kRekeyByteLead < kEpochByteLimit);
static_assert(kRekeyMessageLead < kEpochMessageLimit);
static_assert(kRekeyTimeLead < kEpochActiveLimit);

// ACK deadlines bound liveness and how long ephemeral keys are kept. They do
// not widen epoch budgets.
inline constexpr auto kMinRekeyAckDeadline = std::chrono::seconds(5);
inline constexpr auto kMaxRekeyAckDeadline = std::chrono::seconds(30);
static_assert(kMinRekeyAckDeadline < kMaxRekeyAckDeadline);

// How many future epochs a peer accepts. A deeper window hides ACK latency
// but keeps more roots in memory. Pending epochs stay contiguous and do not
// widen any per-epoch limit.
inline constexpr std::uint16_t kMinRekeyWindow = 1;
inline constexpr std::uint16_t kMaxRekeyWindow = 64;
inline constexpr std::uint16_t kDefaultRekeyWindow = 8;
static_assert(kMinRekeyWindow >= 1);
static_assert(kDefaultRekeyWindow >= kMinRekeyWindow);
static_assert(kDefaultRekeyWindow <= kMaxRekeyWindow);

// Clamps a locally configured depth into the supported range.
constexpr std::uint16_t ClampRekeyWindow(std::uint32_t requested) noexcept {
    if (requested < kMinRekeyWindow) return kMinRekeyWindow;
    if (requested > kMaxRekeyWindow) return kMaxRekeyWindow;
    return static_cast<std::uint16_t>(requested);
}

enum class Direction : std::uint8_t {
    ClientToServer = 0,
    ServerToClient = 1,
};

Bytes DeriveEpochPskContribution(const Bytes& established_psk_key,
                                 Direction direction,
                                 std::uint64_t next_epoch);
Bytes DeriveDirectionRoot(const Bytes& initial_root, Direction direction);

struct SealedFrame {
    std::uint64_t epoch{0};
    std::uint64_t sequence{0};
    Bytes ciphertext;
};

// One direction of a relay channel's ratchet. A channel owns two, so either
// side can rekey its sending direction without blocking the other. The class
// is move-only and wipes its root and chain key when replaced or destroyed.
class DirectionalRatchet {
public:
    DirectionalRatchet(Direction direction,
                       Bytes direction_root,
                       RatchetPolicy policy = kExtremePolicy);
    DirectionalRatchet(const DirectionalRatchet&) = delete;
    DirectionalRatchet& operator=(const DirectionalRatchet&) = delete;
    DirectionalRatchet(DirectionalRatchet&&) noexcept = default;
    DirectionalRatchet& operator=(DirectionalRatchet&&) noexcept = default;
    ~DirectionalRatchet() = default;

    Direction direction() const noexcept { return direction_; }
    std::uint64_t epoch() const noexcept { return epoch_; }
    std::uint64_t next_sequence() const noexcept { return sequence_; }
    // Application usage counted against this epoch's hard limits. Callers use
    // it to pace preparation, never to relax a limit.
    std::uint64_t epoch_bytes() const noexcept { return epoch_bytes_; }
    std::uint64_t epoch_messages() const noexcept { return epoch_messages_; }
    const RatchetPolicy& policy() const noexcept { return policy_; }

    bool ShouldRekey(std::size_t next_plaintext_bytes,
                     std::chrono::steady_clock::time_point now) const;
    bool ShouldPrepareRekey(std::size_t next_plaintext_bytes,
                            std::chrono::steady_clock::time_point now) const;

    SealedFrame Encrypt(std::uint8_t frame_type,
                        std::uint8_t stream_id,
                        std::uint16_t flags,
                        const Bytes& plaintext,
                        std::chrono::steady_clock::time_point now,
                        bool application = true);
    Bytes Decrypt(std::uint8_t frame_type,
                  std::uint8_t stream_id,
                  std::uint16_t flags,
                  const SealedFrame& sealed,
                  std::chrono::steady_clock::time_point now,
                  bool application = true);

    std::unique_ptr<DirectionalRatchet> MakeAdvanced(
        const Bytes& mlkem_shared,
        const Bytes& x25519_shared,
        const Bytes& established_psk_key) const;
    void Advance(const Bytes& mlkem_shared,
                 const Bytes& x25519_shared,
                 const Bytes& established_psk_key);

private:
    bool WouldExceedUsage(std::size_t next_plaintext_bytes) const;
    Bytes BuildAad(std::uint8_t frame_type,
                   std::uint8_t stream_id,
                   std::uint16_t flags,
                   std::uint64_t epoch,
                   std::uint64_t sequence) const;
    Bytes BuildNonce(std::uint64_t sequence) const;
    Bytes DeriveMessageKey() const;
    void StepChain();
    void Account(std::size_t plaintext_bytes,
                 std::chrono::steady_clock::time_point now);

    Direction direction_;
    RatchetPolicy policy_;
    basefwx::crypto::SecureBytes root_;
    basefwx::crypto::SecureBytes chain_;
    std::uint64_t epoch_{0};
    std::uint64_t sequence_{0};
    std::uint64_t epoch_bytes_{0};
    std::uint64_t epoch_messages_{0};
    bool active_{false};
    std::chrono::steady_clock::time_point first_active_{};
};

}  // namespace yume::relay::ratchet
