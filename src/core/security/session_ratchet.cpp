/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/security/session_ratchet.hpp"

#include <limits>
#include <mutex>
#include <stdexcept>

#if YUME_USE_BASEFWX
#include <basefwx/crypto.hpp>
#include <basefwx/pq.hpp>
#include <basefwx/x25519.hpp>
#endif

#include "core/security/auth_v2.hpp"

namespace yume::ratchet {
namespace {

constexpr auto kRekeyTimeout = std::chrono::seconds(5);
constexpr std::size_t kEnvelopePrefix = 16;
constexpr std::size_t kGcmTagBytes = 16;

void WriteU64(Bytes& out, std::size_t offset, std::uint64_t value) {
    if (offset > out.size() || out.size() - offset < 8) {
        throw std::runtime_error("ratchet envelope output is too small");
    }
    for (std::size_t i = 0; i < 8; ++i) {
        out[offset + i] = static_cast<std::uint8_t>(
            value >> (56U - static_cast<unsigned>(i) * 8U));
    }
}

std::uint64_t ReadU64(const Bytes& input, std::size_t offset) {
    if (offset > input.size() || input.size() - offset < 8) {
        throw std::runtime_error("ratchet envelope truncated");
    }
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < 8; ++i) value = (value << 8) | input[offset + i];
    return value;
}

}  // namespace

class SessionRatchet::Impl {
public:
    Impl(EndpointRole role, Bytes initial_root, Bytes psk_key)
        : role_(role),
          outbound_(role == EndpointRole::Client ? Direction::ClientToServer
                                                 : Direction::ServerToClient,
                    DeriveDirectionRoot(initial_root,
                        role == EndpointRole::Client ? Direction::ClientToServer
                                                     : Direction::ServerToClient)),
          inbound_(role == EndpointRole::Client ? Direction::ServerToClient
                                                : Direction::ClientToServer,
                   DeriveDirectionRoot(initial_root,
                       role == EndpointRole::Client ? Direction::ServerToClient
                                                    : Direction::ClientToServer)),
#if YUME_USE_BASEFWX
          psk_key_(std::move(psk_key)) {
        basefwx::crypto::SecureClear(initial_root);
#else
          psk_key_(std::move(psk_key)) {
        (void)initial_root;
#endif
        if (Psk().size() != 32) {
            throw std::runtime_error("YUME 2.0 established PSK key must be 32 bytes");
        }
    }

    bool ShouldStartRekey(const protocol::Frame& plaintext,
                          std::chrono::steady_clock::time_point now) const {
        std::lock_guard<std::mutex> lock(mu_);
        return IsApplicationFrame(plaintext.header.type) && !pending_outbound_ &&
               outbound_.ShouldPrepareRekey(plaintext.payload.size(), now);
    }

    bool ApplicationWriteBlocked(
        const protocol::Frame& plaintext,
        std::chrono::steady_clock::time_point now) const {
        std::lock_guard<std::mutex> lock(mu_);
        return IsApplicationFrame(plaintext.header.type) && pending_outbound_ &&
               outbound_.ShouldRekey(plaintext.payload.size(), now);
    }

    protocol::Frame BeginOutboundRekey(
        std::chrono::steady_clock::time_point now) {
        std::lock_guard<std::mutex> lock(mu_);
        if (pending_outbound_) {
            throw std::runtime_error("YUME 2.0 outbound rekey already pending");
        }
        if (outbound_.epoch() == std::numeric_limits<std::uint64_t>::max()) {
            throw std::runtime_error("YUME 2.0 outbound epoch exhausted");
        }
#if YUME_USE_BASEFWX
        auto pending = std::make_unique<PendingOutbound>();
        pending->next_epoch = outbound_.epoch() + 1;
        pending->mlkem = basefwx::pq::GenerateKeyPair(
            basefwx::pq::KemAlgorithm::MlKem1024);
        pending->x25519 = basefwx::x25519::GenerateKeyPair();
        pending->started = now;
        protocol::Frame init{{0, protocol::REKEY_INIT, 0, 0},
            auth_v2::BuildRekeyInit(pending->next_epoch,
                                    pending->mlkem.public_key,
                                    pending->x25519.public_key)};
        pending_outbound_ = std::move(pending);
        try {
            return SealLocked(init, now, false);
        } catch (...) {
            pending_outbound_.reset();
            throw;
        }
#else
        (void)now;
        throw std::runtime_error("YUME 2.0 rekey requires BaseFWX");
#endif
    }

    protocol::Frame Seal(const protocol::Frame& plaintext,
                         std::chrono::steady_clock::time_point now) {
        std::lock_guard<std::mutex> lock(mu_);
        const bool application = IsApplicationFrame(plaintext.header.type);
        return SealLocked(plaintext, now, application);
    }

    OpenResult Open(const protocol::Frame& frame,
                    std::chrono::steady_clock::time_point now) {
        std::lock_guard<std::mutex> lock(mu_);
        if ((frame.header.flags & protocol::kFlagInnerEncrypted) == 0 ||
            frame.payload.size() < kEnvelopePrefix + kGcmTagBytes) {
            throw std::runtime_error("YUME 2.0 frame lacks ratchet envelope");
        }
        SealedFrame sealed;
        sealed.epoch = ReadU64(frame.payload, 0);
        sealed.sequence = ReadU64(frame.payload, 8);
        sealed.ciphertext.assign(frame.payload.begin() +
                                     static_cast<std::ptrdiff_t>(kEnvelopePrefix),
                                 frame.payload.end());
        const bool application = IsApplicationFrame(frame.header.type);
        Bytes plaintext;
        bool authenticated_pending_epoch = false;
        if (sealed.epoch == inbound_.epoch()) {
            // dev2 pipelines the authenticated next-epoch exchange ahead of
            // the hard boundary. Ordered H2/TCP permits bounded old-epoch data
            // after INIT; DirectionalRatchet still enforces 256 KiB/512 frames.
            // The first authenticated new-epoch frame retires this chain.
            plaintext = inbound_.Decrypt(frame.header.type, frame.header.stream_id,
                                         frame.header.flags, sealed, now,
                                         application);
        } else if (pending_inbound_ &&
                   sealed.epoch == pending_inbound_->epoch()) {
            plaintext = pending_inbound_->Decrypt(
                frame.header.type, frame.header.stream_id, frame.header.flags,
                sealed, now, application);
            authenticated_pending_epoch = true;
        } else {
            throw std::runtime_error("YUME 2.0 unexpected or retired epoch");
        }
        if (authenticated_pending_epoch) {
            inbound_ = std::move(*pending_inbound_);
            pending_inbound_.reset();
        }

        protocol::Frame opened{{static_cast<std::uint32_t>(plaintext.size()),
                                frame.header.type, frame.header.stream_id,
                                static_cast<std::uint16_t>(
                                    frame.header.flags &
                                    ~protocol::kFlagInnerEncrypted)},
                               std::move(plaintext)};
        OpenResult result;
        if (opened.header.type == protocol::REKEY_INIT) {
            result.control_response = HandleRekeyInitLocked(opened, now);
        } else if (opened.header.type == protocol::REKEY_ACK) {
            HandleRekeyAckLocked(opened);
            result.outbound_rekey_completed = true;
        } else {
            result.application_frame = std::move(opened);
        }
        return result;
    }

    bool outbound_rekey_pending() const {
        std::lock_guard<std::mutex> lock(mu_);
        return pending_outbound_ != nullptr;
    }

    std::optional<std::chrono::steady_clock::time_point> rekey_deadline() const {
        std::lock_guard<std::mutex> lock(mu_);
        if (!pending_outbound_) return std::nullopt;
        return pending_outbound_->started + kRekeyTimeout;
    }

    bool rekey_timed_out(std::chrono::steady_clock::time_point now) const {
        const auto deadline = rekey_deadline();
        return deadline.has_value() && now >= *deadline;
    }

    std::uint64_t outbound_epoch() const {
        std::lock_guard<std::mutex> lock(mu_);
        return outbound_.epoch();
    }

    std::uint64_t inbound_epoch() const {
        std::lock_guard<std::mutex> lock(mu_);
        return inbound_.epoch();
    }

private:
#if YUME_USE_BASEFWX
    struct PendingOutbound {
        std::uint64_t next_epoch{0};
        basefwx::pq::KemKeyPair mlkem;
        basefwx::x25519::KeyPair x25519;
        std::chrono::steady_clock::time_point started{};
    };
#else
    struct PendingOutbound {};
#endif

    const Bytes& Psk() const {
#if YUME_USE_BASEFWX
        return psk_key_.bytes();
#else
        return psk_key_;
#endif
    }

    protocol::Frame SealLocked(const protocol::Frame& plaintext,
                               std::chrono::steady_clock::time_point now,
                               bool application) {
        const std::uint16_t flags = static_cast<std::uint16_t>(
            plaintext.header.flags | protocol::kFlagInnerEncrypted);
        SealedFrame sealed = outbound_.Encrypt(
            plaintext.header.type, plaintext.header.stream_id, flags,
            plaintext.payload, now, application);
        Bytes envelope(kEnvelopePrefix);
        envelope.reserve(kEnvelopePrefix + sealed.ciphertext.size());
        WriteU64(envelope, 0, sealed.epoch);
        WriteU64(envelope, 8, sealed.sequence);
        envelope.insert(envelope.end(), sealed.ciphertext.begin(),
                        sealed.ciphertext.end());
        return protocol::Frame{{static_cast<std::uint32_t>(envelope.size()),
                                plaintext.header.type,
                                plaintext.header.stream_id, flags},
                               std::move(envelope)};
    }

    protocol::Frame HandleRekeyInitLocked(
        const protocol::Frame& frame,
        std::chrono::steady_clock::time_point now) {
        if (pending_inbound_) {
            throw std::runtime_error("YUME 2.0 duplicate inbound rekey");
        }
        const auto init = auth_v2::ParseRekeyInit(frame.payload);
        if (init.next_epoch != inbound_.epoch() + 1) {
            throw std::runtime_error("YUME 2.0 inbound rekey epoch mismatch");
        }
#if YUME_USE_BASEFWX
        basefwx::pq::KemResult kem = basefwx::pq::KemEncrypt(
            basefwx::pq::KemAlgorithm::MlKem1024, init.mlkem_public_key);
        basefwx::x25519::KeyPair x25519 = basefwx::x25519::GenerateKeyPair();
        basefwx::crypto::SecureBytes x_shared{
            basefwx::x25519::DeriveSharedSecret(x25519.private_key,
                                                init.x25519_public_key)};
        pending_inbound_ = inbound_.MakeAdvanced(kem.shared,
                                                 x_shared.bytes(), Psk());
        protocol::Frame ack{{0, protocol::REKEY_ACK, 0, 0},
            auth_v2::BuildRekeyAck(init.next_epoch, kem.ciphertext,
                                   x25519.public_key)};
        return SealLocked(ack, now, false);
#else
        (void)now;
        throw std::runtime_error("YUME 2.0 rekey requires BaseFWX");
#endif
    }

    void HandleRekeyAckLocked(const protocol::Frame& frame) {
        if (!pending_outbound_) {
            throw std::runtime_error("YUME 2.0 unsolicited rekey ACK");
        }
        const auto ack = auth_v2::ParseRekeyAck(frame.payload);
#if YUME_USE_BASEFWX
        if (ack.next_epoch != pending_outbound_->next_epoch ||
            ack.next_epoch != outbound_.epoch() + 1) {
            throw std::runtime_error("YUME 2.0 outbound rekey epoch mismatch");
        }
        basefwx::crypto::SecureBytes kem_shared{
            basefwx::pq::KemDecrypt(basefwx::pq::KemAlgorithm::MlKem1024,
                                    pending_outbound_->mlkem.private_key,
                                    ack.mlkem_ciphertext)};
        basefwx::crypto::SecureBytes x_shared{
            basefwx::x25519::DeriveSharedSecret(
                pending_outbound_->x25519.private_key,
                ack.x25519_public_key)};
        outbound_.Advance(kem_shared.bytes(), x_shared.bytes(), Psk());
        pending_outbound_.reset();
#else
        (void)ack;
        throw std::runtime_error("YUME 2.0 rekey requires BaseFWX");
#endif
    }

    EndpointRole role_;
    mutable std::mutex mu_;
    DirectionalRatchet outbound_;
    DirectionalRatchet inbound_;
    std::unique_ptr<DirectionalRatchet> pending_inbound_;
    std::unique_ptr<PendingOutbound> pending_outbound_;
#if YUME_USE_BASEFWX
    basefwx::crypto::SecureBytes psk_key_;
#else
    Bytes psk_key_;
#endif
};

SessionRatchet::SessionRatchet(EndpointRole role, Bytes initial_root,
                               Bytes psk_key)
    : impl_(std::make_unique<Impl>(role, std::move(initial_root),
                                   std::move(psk_key))) {}
SessionRatchet::SessionRatchet(SessionRatchet&&) noexcept = default;
SessionRatchet& SessionRatchet::operator=(SessionRatchet&&) noexcept = default;
SessionRatchet::~SessionRatchet() = default;

bool SessionRatchet::ShouldStartRekey(
    const protocol::Frame& frame,
    std::chrono::steady_clock::time_point now) const {
    return impl_->ShouldStartRekey(frame, now);
}
bool SessionRatchet::ApplicationWriteBlocked(
    const protocol::Frame& frame,
    std::chrono::steady_clock::time_point now) const {
    return impl_->ApplicationWriteBlocked(frame, now);
}
protocol::Frame SessionRatchet::BeginOutboundRekey(
    std::chrono::steady_clock::time_point now) {
    return impl_->BeginOutboundRekey(now);
}
protocol::Frame SessionRatchet::Seal(
    const protocol::Frame& frame,
    std::chrono::steady_clock::time_point now) {
    return impl_->Seal(frame, now);
}
OpenResult SessionRatchet::Open(
    const protocol::Frame& frame,
    std::chrono::steady_clock::time_point now) {
    return impl_->Open(frame, now);
}
bool SessionRatchet::outbound_rekey_pending() const {
    return impl_->outbound_rekey_pending();
}
std::optional<std::chrono::steady_clock::time_point>
SessionRatchet::rekey_deadline() const {
    return impl_->rekey_deadline();
}
bool SessionRatchet::rekey_timed_out(
    std::chrono::steady_clock::time_point now) const {
    return impl_->rekey_timed_out(now);
}
std::uint64_t SessionRatchet::outbound_epoch() const {
    return impl_->outbound_epoch();
}
std::uint64_t SessionRatchet::inbound_epoch() const {
    return impl_->inbound_epoch();
}

bool SessionRatchet::IsApplicationFrame(std::uint8_t type) noexcept {
    switch (type) {
        case protocol::OPEN:
        case protocol::DATA:
        case protocol::CLOSE:
        case protocol::EXEC:
        case protocol::RLISTEN:
        case protocol::ROPEN:
        case protocol::CONTROL:
        case protocol::SOPEN:
            return true;
        default:
            return false;
    }
}

}  // namespace yume::ratchet
