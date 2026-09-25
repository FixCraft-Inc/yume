/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "modules/relay/ratchet.hpp"

#include <limits>
#include <stdexcept>
#include <string>
#include <utility>

namespace yume::relay::ratchet {
namespace {

// Protocol labels, unchanged from the relay v2 ratchet.
constexpr std::string_view kEpochPskLabel = "yume/2.0/epoch-psk/v1";
constexpr std::string_view kClientRootLabel = "yume/2.0/c2s-root/v1";
constexpr std::string_view kServerRootLabel = "yume/2.0/s2c-root/v1";
constexpr std::string_view kChainLabel = "yume/2.0/chain/v1";
constexpr std::string_view kMessageLabel = "yume/2.0/message/v1";
constexpr std::string_view kChainNextLabel = "yume/2.0/chain-next/v1";
constexpr std::string_view kEpochRootLabel = "yume/2.0/epoch-root/v1";
constexpr std::string_view kAadDomain = "yume/2.0/aad/v2";

using basefwx::crypto::SecureBytes;

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

Bytes Hkdf(const Bytes& input,
           const Bytes& salt,
           std::string_view label,
           std::size_t length) {
    return basefwx::crypto::HkdfSha256(input, salt, label, length);
}

}  // namespace

Bytes DeriveEpochPskContribution(const Bytes& established_psk_key,
                                 Direction direction,
                                 std::uint64_t next_epoch) {
    if (established_psk_key.size() != 32 || next_epoch == 0) {
        throw std::runtime_error("invalid relay epoch PSK input");
    }
    Bytes salt;
    salt.reserve(9);
    salt.push_back(static_cast<std::uint8_t>(direction));
    AppendU64(salt, next_epoch);
    return Hkdf(established_psk_key, salt, kEpochPskLabel, 32);
}

Bytes DeriveDirectionRoot(const Bytes& initial_root, Direction direction) {
    if (initial_root.size() != 32) {
        throw std::runtime_error("relay initial root must be 32 bytes");
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
        throw std::runtime_error("invalid relay ratchet policy");
    }
    if (root_.bytes().size() != 32) {
        throw std::runtime_error("relay direction root must be 32 bytes");
    }
    chain_.Reset(Hkdf(root_.bytes(), {}, kChainLabel, 32));
}

bool DirectionalRatchet::ShouldRekey(
    std::size_t next_plaintext_bytes,
    std::chrono::steady_clock::time_point now) const {
    if (next_plaintext_bytes > kMaxProtectedPayload) {
        throw std::runtime_error("relay protected payload exceeds 256 KiB");
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
        throw std::runtime_error("relay sequence exhausted");
    }
    if (application && ShouldRekey(plaintext.size(), now)) {
        throw std::runtime_error("relay epoch rekey required before data");
    }
    const std::uint64_t sequence = sequence_;
    Bytes nonce = BuildNonce(sequence);
    Bytes aad = BuildAad(frame_type, stream_id, flags, epoch_, sequence);
    SecureBytes guarded_key{DeriveMessageKey()};
    Bytes ciphertext = basefwx::crypto::AesGcmEncryptWithIv(
        guarded_key.bytes(), nonce, plaintext, aad);
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
            "relay replay or unexpected epoch/sequence"
            " (expected epoch=" + std::to_string(epoch_) +
            " sequence=" + std::to_string(sequence_) +
            ", received epoch=" + std::to_string(sealed.epoch) +
            " sequence=" + std::to_string(sealed.sequence) + ")");
    }
    if (sequence_ == std::numeric_limits<std::uint64_t>::max()) {
        throw std::runtime_error("relay sequence exhausted");
    }
    Bytes nonce = BuildNonce(sealed.sequence);
    Bytes aad = BuildAad(frame_type, stream_id, flags, sealed.epoch,
                         sealed.sequence);
    SecureBytes guarded_key{DeriveMessageKey()};
    SecureBytes guarded_plaintext{basefwx::crypto::AesGcmDecryptWithIv(
        guarded_key.bytes(), nonce, sealed.ciphertext, aad)};
    const Bytes& plaintext = guarded_plaintext.bytes();
    if (plaintext.size() > kMaxProtectedPayload) {
        throw std::runtime_error("relay decrypted payload exceeds 256 KiB");
    }
    // The sender normally rekeys before either usage boundary, but a malicious
    // or buggy peer must not widen the epoch's reach. Only authenticated
    // plaintext is checked. The time boundary stays with the sender, because
    // queued data can arrive later than it was sealed.
    if (application && active_ && WouldExceedUsage(plaintext.size())) {
        throw std::runtime_error("relay inbound epoch usage limit exceeded");
    }
    StepChain();
    ++sequence_;
    if (application) Account(plaintext.size(), now);
    return guarded_plaintext.Release();
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
        throw std::runtime_error("relay epoch exhausted");
    }
    if (mlkem_shared.empty() || x25519_shared.empty() ||
        established_psk_key.size() != 32) {
        throw std::runtime_error("incomplete relay epoch secrets");
    }
    SecureBytes guarded_epoch_psk{
        DeriveEpochPskContribution(established_psk_key, direction_, epoch_ + 1)};
    SecureBytes guarded_input;
    Bytes& input = guarded_input.bytes();
    AppendLengthPrefixed(input, root_.bytes());
    AppendLengthPrefixed(input, mlkem_shared);
    AppendLengthPrefixed(input, x25519_shared);
    AppendLengthPrefixed(input, guarded_epoch_psk.bytes());
    SecureBytes guarded_next_root{
        Hkdf(input, root_.bytes(), kEpochRootLabel, 32)};
    // The new ratchet copies the root into its own wiped storage before any
    // check that can throw, and this guard wipes the one held here.
    auto next = std::make_unique<DirectionalRatchet>(
        direction_, guarded_next_root.bytes(), policy_);
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
    AppendLengthPrefixed(aad, Bytes(kProfileLabel.begin(), kProfileLabel.end()));
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
    return Hkdf(chain_.bytes(), {}, kMessageLabel, 32);
}

void DirectionalRatchet::StepChain() {
    chain_.Reset(Hkdf(chain_.bytes(), {}, kChainNextLabel, 32));
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

}  // namespace yume::relay::ratchet
