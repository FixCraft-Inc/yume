/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "core/security/ratchet_policy.hpp"

#if YUME_USE_BASEFWX
#include <basefwx/crypto.hpp>
#endif

namespace yume::ratchet {

using Bytes = std::vector<std::uint8_t>;

// Extreme-profile limits used by the boundary tests. Each runtime chain
// enforces the RatchetPolicy authenticated for that direction.
inline constexpr std::size_t kEpochByteLimit =
    static_cast<std::size_t>(kExtremePolicy.epoch_byte_limit);
inline constexpr std::uint64_t kEpochMessageLimit =
    kExtremePolicy.epoch_frame_limit;
inline constexpr auto kEpochActiveLimit = kExtremePolicy.epoch_active_limit;

// Begin preparing the next hybrid epoch with enough current-epoch traffic left
// to hide a normal LAN round trip. These are scheduling thresholds only: the
// hard byte, message, and time limits above remain unchanged and are enforced
// independently by both sender and receiver.
inline constexpr std::size_t kRekeyByteLead = 192U * 1024U;
inline constexpr std::uint64_t kRekeyMessageLead = 64;
inline constexpr auto kRekeyTimeLead = std::chrono::milliseconds(100);
static_assert(kRekeyByteLead < kEpochByteLimit);
static_assert(kRekeyMessageLead < kEpochMessageLimit);
static_assert(kRekeyTimeLead < kEpochActiveLimit);

// ACK deadlines bound liveness and retained ephemeral-key lifetime. They do
// not widen epoch budgets: both peers enforce byte/frame limits, while active
// time is sender-local because delivery can be delayed by the network.
// The 30 s cap closes a stalled rekey before the 60 s transport stall timeout.
inline constexpr auto kMinRekeyAckDeadline = std::chrono::seconds(5);
inline constexpr auto kMaxRekeyAckDeadline = std::chrono::seconds(30);
static_assert(kMinRekeyAckDeadline < kMaxRekeyAckDeadline);

// Each peer advertises how many future epochs it will accept. A deeper
// window can hide ACK latency but retains more roots under process compromise.
// Pending epochs stay contiguous and do not widen any per-epoch limit.
inline constexpr std::uint16_t kMinRekeyWindow = 1;
inline constexpr std::uint16_t kMaxRekeyWindow = 64;
inline constexpr std::uint16_t kDefaultRekeyWindow = 8;
static_assert(kMinRekeyWindow >= 1);
static_assert(kDefaultRekeyWindow >= kMinRekeyWindow);
static_assert(kDefaultRekeyWindow <= kMaxRekeyWindow);

// Clamp locally configured depth into the supported range. Values below one
// select the minimum supported depth; decoded peer records are validated
// separately and zero is rejected.
constexpr std::uint16_t ClampRekeyWindow(std::uint32_t requested) noexcept {
    if (requested < kMinRekeyWindow) return kMinRekeyWindow;
    if (requested > kMaxRekeyWindow) return kMaxRekeyWindow;
    return static_cast<std::uint16_t>(requested);
}

enum class Direction : std::uint8_t {
    ClientToServer = 0,
    ServerToClient = 1,
};

struct InitialSecrets {
    Bytes mlkem_shared;
    Bytes x25519_shared;
    Bytes psk_key;
    Bytes transcript_salt;
    // 32-byte TLS 1.3 exporter each endpoint computes from its own live
    // connection. AUTH already refuses a signature over a different binding,
    // so this is defence in depth: even a transcript check that was somehow
    // bypassed still yields unrelated roots on the two sides of a relay.
    Bytes channel_binding;
};

// The v2 PSK is exactly 32 uniformly random bytes loaded from a protected
// file.  It is expanded once at establishment with salted HKDF.  Argon2 is
// intentionally not part of this path: it adds no brute-force resistance to a
// 256-bit random secret and must never run in the per-epoch hot path.
Bytes DerivePskKey(const Bytes& file_psk, const Bytes& handshake_psk_salt);
Bytes DeriveEpochPskContribution(const Bytes& established_psk_key,
                                 Direction direction,
                                 std::uint64_t next_epoch);

Bytes DeriveInitialRoot(const InitialSecrets& secrets);
Bytes DeriveInitialRoot(const Bytes& mlkem_shared,
                        const Bytes& x25519_shared,
                        const Bytes& psk_key,
                        const Bytes& transcript_salt,
                        const Bytes& channel_binding);
Bytes DeriveDirectionRoot(const Bytes& initial_root, Direction direction);

struct SealedFrame {
    std::uint64_t epoch{0};
    std::uint64_t sequence{0};
    Bytes ciphertext;
};

// One direction of the v2 transport ratchet. A connection owns two instances,
// so either side can rekey its outbound direction without blocking or racing
// the reverse direction. The class is move-only and wipes its retained root
// and chain key when replaced or destroyed.
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
    // Application usage accounted against this epoch's hard limits. Callers use
    // it to pace preparation against real progress, never to relax a limit.
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
#if YUME_USE_BASEFWX
    basefwx::crypto::SecureBytes root_;
    basefwx::crypto::SecureBytes chain_;
#else
    Bytes root_;
    Bytes chain_;
#endif
    std::uint64_t epoch_{0};
    std::uint64_t sequence_{0};
    std::uint64_t epoch_bytes_{0};
    std::uint64_t epoch_messages_{0};
    bool active_{false};
    std::chrono::steady_clock::time_point first_active_{};
};

}  // namespace yume::ratchet
