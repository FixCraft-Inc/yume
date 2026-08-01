/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/security/ratchet.hpp"

#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string_view>

// The AUTH codec owns the channel-binding length, the way this header owns the
// negotiated window range that `auth_v2.cpp` reads back.
#include "core/security/auth_v2.hpp"

#if YUME_USE_BASEFWX
#include <basefwx/crypto.hpp>
#endif

namespace yume::ratchet {
namespace {

using auth_v2::kChannelBindingLen;

// v2 folds the per-connection TLS exporter into the establishment transcript.
constexpr std::string_view kInitialRootLabel = "yume/2.0/root/v2";
constexpr std::string_view kPskLabel = "yume/2.0/psk/v1";
constexpr std::string_view kEpochPskLabel = "yume/2.0/epoch-psk/v1";
constexpr std::string_view kClientRootLabel = "yume/2.0/c2s-root/v1";
constexpr std::string_view kServerRootLabel = "yume/2.0/s2c-root/v1";
constexpr std::string_view kChainLabel = "yume/2.0/chain/v1";
constexpr std::string_view kMessageLabel = "yume/2.0/message/v1";
constexpr std::string_view kChainNextLabel = "yume/2.0/chain-next/v1";
constexpr std::string_view kEpochRootLabel = "yume/2.0/epoch-root/v1";
constexpr std::string_view kAadDomain = "yume/2.0/aad/v1";

void AppendU16(Bytes& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xffU));
    out.push_back(static_cast<std::uint8_t>(value & 0xffU));
}

void AppendU32(Bytes& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>((value >> 24) & 0xffU));
    out.push_back(static_cast<std::uint8_t>((value >> 16) & 0xffU));
    out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xffU));
    out.push_back(static_cast<std::uint8_t>(value & 0xffU));
}

void AppendU64(Bytes& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffU));
    }
}

void AppendLengthPrefixed(Bytes& out, const Bytes& value) {
    if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::runtime_error("ratchet input is too large");
    }
    AppendU32(out, static_cast<std::uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

#if YUME_USE_BASEFWX
const Bytes& SecretBytes(const basefwx::crypto::SecureBytes& bytes) {
    return bytes.bytes();
}
#else
const Bytes& SecretBytes(const Bytes& bytes) {
    return bytes;
}
#endif

Bytes Hkdf(const Bytes& input,
           const Bytes& salt,
           std::string_view label,
           std::size_t length) {
#if YUME_USE_BASEFWX
    return basefwx::crypto::HkdfSha256(input, salt, label, length);
#else
    (void)input;
    (void)salt;
    (void)label;
    (void)length;
    throw std::runtime_error("YUME 2.0 ratchet requires BaseFWX");
#endif
}

}  // namespace

Bytes DerivePskKey(const Bytes& file_psk, const Bytes& handshake_psk_salt) {
    if (file_psk.size() != 32 || handshake_psk_salt.size() != 32) {
        throw std::runtime_error("YUME 2.0 PSK and PSK salt must be 32 bytes");
    }
    return Hkdf(file_psk, handshake_psk_salt, kPskLabel, 32);
}

Bytes DeriveEpochPskContribution(const Bytes& established_psk_key,
                                 Direction direction,
                                 std::uint64_t next_epoch) {
    if (established_psk_key.size() != 32 || next_epoch == 0) {
        throw std::runtime_error("invalid YUME 2.0 epoch PSK input");
    }
    Bytes salt;
    salt.reserve(9);
    salt.push_back(static_cast<std::uint8_t>(direction));
    AppendU64(salt, next_epoch);
    return Hkdf(established_psk_key, salt, kEpochPskLabel, 32);
}

Bytes DeriveInitialRoot(const InitialSecrets& secrets) {
    return DeriveInitialRoot(secrets.mlkem_shared, secrets.x25519_shared,
                             secrets.psk_key, secrets.transcript_salt,
                             secrets.channel_binding);
}

Bytes DeriveInitialRoot(const Bytes& mlkem_shared,
                        const Bytes& x25519_shared,
                        const Bytes& psk_key,
                        const Bytes& transcript_salt,
                        const Bytes& channel_binding) {
    if (mlkem_shared.empty() || x25519_shared.empty() ||
        psk_key.empty() || transcript_salt.size() < 16) {
        throw std::runtime_error("incomplete YUME 2.0 initial secrets");
    }
    // Same fail-closed rule as the AUTH transcript: no unbound root exists.
    if (channel_binding.size() != kChannelBindingLen) {
        throw std::runtime_error("invalid YUME 2.0 channel binding");
    }
    Bytes input;
    input.reserve(mlkem_shared.size() + x25519_shared.size() +
                  psk_key.size() + channel_binding.size() + 16);
    AppendLengthPrefixed(input, mlkem_shared);
    AppendLengthPrefixed(input, x25519_shared);
    AppendLengthPrefixed(input, psk_key);
    AppendLengthPrefixed(input, channel_binding);
    Bytes root = Hkdf(input, transcript_salt, kInitialRootLabel, 32);
#if YUME_USE_BASEFWX
    basefwx::crypto::SecureClear(input);
#endif
    return root;
}

Bytes DeriveDirectionRoot(const Bytes& initial_root, Direction direction) {
    if (initial_root.size() != 32) {
        throw std::runtime_error("YUME 2.0 initial root must be 32 bytes");
    }
    return Hkdf(initial_root, {},
                direction == Direction::ClientToServer ? kClientRootLabel
                                                        : kServerRootLabel,
                32);
}

DirectionalRatchet::DirectionalRatchet(Direction direction,
                                       Bytes direction_root,
                                       RatchetPolicy policy)
    : direction_(direction), policy_(policy), root_(std::move(direction_root)) {
    if (!IsRatchetPolicyValid(policy_)) {
        throw std::runtime_error("invalid YUME 2.0 ratchet policy");
    }
    if (SecretBytes(root_).size() != 32) {
        throw std::runtime_error("YUME 2.0 direction root must be 32 bytes");
    }
    Bytes chain = Hkdf(SecretBytes(root_), {}, kChainLabel, 32);
#if YUME_USE_BASEFWX
    chain_.Reset(std::move(chain));
#else
    chain_ = std::move(chain);
#endif
}

bool DirectionalRatchet::ShouldRekey(
    std::size_t next_plaintext_bytes,
    std::chrono::steady_clock::time_point now) const {
    if (next_plaintext_bytes > kMaxProtectedPayload) {
        throw std::runtime_error("YUME 2.0 protected payload exceeds 256 KiB");
    }
    if (!active_) {
        return false;
    }
    const bool time_exhausted =
        now - first_active_ >= policy_.epoch_active_limit;
    return WouldExceedUsage(next_plaintext_bytes) || time_exhausted;
}

bool DirectionalRatchet::ShouldPrepareRekey(
    std::size_t next_plaintext_bytes,
    std::chrono::steady_clock::time_point now) const {
    if (ShouldRekey(next_plaintext_bytes, now)) {
        return true;
    }

    const std::uint64_t byte_prepare_threshold =
        policy_.epoch_byte_limit / 4U;
    const bool bytes_near_boundary =
        epoch_bytes_ >= byte_prepare_threshold ||
        next_plaintext_bytes >= byte_prepare_threshold - epoch_bytes_;
    const std::uint64_t message_prepare_threshold =
        policy_.epoch_frame_limit - policy_.epoch_frame_limit / 8U;
    const bool messages_near_boundary =
        epoch_messages_ >= message_prepare_threshold - 1U;
    const bool time_near_boundary = active_ &&
        now - first_active_ >=
            policy_.epoch_active_limit - policy_.epoch_active_limit / 5;
    return bytes_near_boundary || messages_near_boundary ||
           time_near_boundary;
}

SealedFrame DirectionalRatchet::Encrypt(
    std::uint8_t frame_type,
    std::uint8_t stream_id,
    std::uint16_t flags,
    const Bytes& plaintext,
    std::chrono::steady_clock::time_point now,
    bool application) {
    if (sequence_ == std::numeric_limits<std::uint64_t>::max()) {
        throw std::runtime_error("YUME 2.0 sequence exhausted");
    }
    if (application && ShouldRekey(plaintext.size(), now)) {
        throw std::runtime_error("YUME 2.0 epoch rekey required before data");
    }
    const std::uint64_t sequence = sequence_;
    Bytes key = DeriveMessageKey();
    Bytes nonce = BuildNonce(sequence);
    Bytes aad = BuildAad(frame_type, stream_id, flags, epoch_, sequence);
#if YUME_USE_BASEFWX
    basefwx::crypto::SecureBytes guarded_key{std::move(key)};
    Bytes ciphertext = basefwx::crypto::AesGcmEncryptWithIv(
        guarded_key.bytes(), nonce, plaintext, aad);
#else
    throw std::runtime_error("YUME 2.0 ratchet requires BaseFWX");
#endif
    StepChain();
    ++sequence_;
    if (application) Account(plaintext.size(), now);
    return SealedFrame{epoch_, sequence, std::move(ciphertext)};
}

Bytes DirectionalRatchet::Decrypt(
    std::uint8_t frame_type,
    std::uint8_t stream_id,
    std::uint16_t flags,
    const SealedFrame& sealed,
    std::chrono::steady_clock::time_point now,
    bool application) {
    if (sealed.epoch != epoch_ || sealed.sequence != sequence_) {
        throw std::runtime_error(
            "YUME 2.0 replay or unexpected epoch/sequence"
            " (expected epoch=" + std::to_string(epoch_) +
            " sequence=" + std::to_string(sequence_) +
            ", received epoch=" + std::to_string(sealed.epoch) +
            " sequence=" + std::to_string(sealed.sequence) + ")");
    }
    if (sequence_ == std::numeric_limits<std::uint64_t>::max()) {
        throw std::runtime_error("YUME 2.0 sequence exhausted");
    }
    Bytes key = DeriveMessageKey();
    Bytes nonce = BuildNonce(sealed.sequence);
    Bytes aad = BuildAad(frame_type, stream_id, flags, sealed.epoch,
                         sealed.sequence);
#if YUME_USE_BASEFWX
    basefwx::crypto::SecureBytes guarded_key{std::move(key)};
    Bytes plaintext = basefwx::crypto::AesGcmDecryptWithIv(
        guarded_key.bytes(), nonce, sealed.ciphertext, aad);
#else
    throw std::runtime_error("YUME 2.0 ratchet requires BaseFWX");
#endif
    if (plaintext.size() > kMaxProtectedPayload) {
        throw std::runtime_error("YUME 2.0 decrypted payload exceeds 256 KiB");
    }
    // The sender normally rekeys before reaching either usage boundary, but
    // the receiver must not rely on a malicious or buggy peer to preserve the
    // advertised epoch blast radius. Check only authenticated plaintext. The
    // wall-clock boundary remains sender-local because queued network data can
    // arrive more than 500 ms after it was sealed without violating the wire.
    if (application && active_ && WouldExceedUsage(plaintext.size())) {
        throw std::runtime_error("YUME 2.0 inbound epoch usage limit exceeded");
    }
    StepChain();
    ++sequence_;
    if (application) Account(plaintext.size(), now);
    return plaintext;
}

bool DirectionalRatchet::WouldExceedUsage(
    std::size_t next_plaintext_bytes) const {
    const bool bytes_exhausted =
        epoch_bytes_ > policy_.epoch_byte_limit ||
        next_plaintext_bytes > (policy_.epoch_byte_limit - epoch_bytes_);
    const bool messages_exhausted =
        epoch_messages_ >= policy_.epoch_frame_limit;
    return bytes_exhausted || messages_exhausted;
}

std::unique_ptr<DirectionalRatchet> DirectionalRatchet::MakeAdvanced(
    const Bytes& mlkem_shared,
    const Bytes& x25519_shared,
    const Bytes& established_psk_key) const {
    if (epoch_ == std::numeric_limits<std::uint64_t>::max()) {
        throw std::runtime_error("YUME 2.0 epoch exhausted");
    }
    if (mlkem_shared.empty() || x25519_shared.empty() ||
        established_psk_key.size() != 32) {
        throw std::runtime_error("incomplete YUME 2.0 epoch secrets");
    }
    Bytes epoch_psk_contribution = DeriveEpochPskContribution(
        established_psk_key, direction_, epoch_ + 1);
    Bytes input;
    AppendLengthPrefixed(input, SecretBytes(root_));
    AppendLengthPrefixed(input, mlkem_shared);
    AppendLengthPrefixed(input, x25519_shared);
    AppendLengthPrefixed(input, epoch_psk_contribution);
    Bytes next_root = Hkdf(input, SecretBytes(root_), kEpochRootLabel, 32);
#if YUME_USE_BASEFWX
    basefwx::crypto::SecureClear(epoch_psk_contribution);
    basefwx::crypto::SecureClear(input);
#endif
    auto next = std::make_unique<DirectionalRatchet>(
        direction_, std::move(next_root), policy_);
    next->epoch_ = epoch_ + 1;
    return next;
}

void DirectionalRatchet::Advance(const Bytes& mlkem_shared,
                                 const Bytes& x25519_shared,
                                 const Bytes& established_psk_key) {
    auto next = MakeAdvanced(mlkem_shared, x25519_shared,
                             established_psk_key);
    *this = std::move(*next);
}

Bytes DirectionalRatchet::BuildAad(std::uint8_t frame_type,
                                   std::uint8_t stream_id,
                                   std::uint16_t flags,
                                   std::uint64_t epoch,
                                   std::uint64_t sequence) const {
    Bytes aad(kAadDomain.begin(), kAadDomain.end());
    aad.push_back(static_cast<std::uint8_t>(direction_));
    AppendU64(aad, epoch);
    AppendU64(aad, sequence);
    aad.push_back(frame_type);
    aad.push_back(stream_id);
    AppendU16(aad, flags);
    return aad;
}

Bytes DirectionalRatchet::BuildNonce(std::uint64_t sequence) const {
    Bytes nonce(12, 0);
    nonce[0] = static_cast<std::uint8_t>(direction_);
    for (std::size_t i = 0; i < 8; ++i) {
        nonce[4 + i] = static_cast<std::uint8_t>(
            (sequence >> (56U - static_cast<unsigned>(i) * 8U)) & 0xffU);
    }
    return nonce;
}

Bytes DirectionalRatchet::DeriveMessageKey() const {
    return Hkdf(SecretBytes(chain_), {}, kMessageLabel, 32);
}

void DirectionalRatchet::StepChain() {
    Bytes next = Hkdf(SecretBytes(chain_), {}, kChainNextLabel, 32);
#if YUME_USE_BASEFWX
    chain_.Reset(std::move(next));
#else
    chain_ = std::move(next);
#endif
}

void DirectionalRatchet::Account(
    std::size_t plaintext_bytes,
    std::chrono::steady_clock::time_point now) {
    if (!active_) {
        active_ = true;
        first_active_ = now;
    }
    epoch_bytes_ += plaintext_bytes;
    ++epoch_messages_;
}

}  // namespace yume::ratchet
