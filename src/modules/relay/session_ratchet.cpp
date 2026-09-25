/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "modules/relay/session_ratchet.hpp"

#include <algorithm>
#include <deque>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <utility>

#include <basefwx/pq.hpp>
#include <basefwx/x25519.hpp>

#include "modules/relay/rekey_record.hpp"

namespace yume::relay::ratchet {
namespace {

using basefwx::crypto::SecureBytes;

// RFC 6298 estimator gains as shifts, so the update is exact integer
// arithmetic: SRTT += (R - SRTT) / 8, RTTVAR += (|SRTT - R| - RTTVAR) / 4,
// deadline base = SRTT + 4 * RTTVAR. A single jitter spike moves the deadline
// by an eighth of its excess.
constexpr std::int64_t kRttGainDivisor = 8;
constexpr std::int64_t kRttVarGainDivisor = 4;
constexpr std::int64_t kRttVarWeight = 4;

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

// The only frames a relay ratchet carries. Anything else would be decrypted
// without application accounting, so it is refused before any key is used.
void RequireRelayFrameType(std::uint8_t type) {
    if (type != kFrameData && type != kFrameRekeyInit && type != kFrameRekeyAck) {
        throw std::runtime_error("relay ratchet frame type is not allowed");
    }
}

}  // namespace

class SessionRatchet::Impl {
public:
    Impl(EndpointRole role, SecureBytes initial_root, SecureBytes psk_key,
         std::uint16_t outbound_window, std::uint16_t inbound_window,
         RatchetPolicy outbound_policy, RatchetPolicy inbound_policy)
        : outbound_window_(ClampRekeyWindow(outbound_window)),
          inbound_window_(ClampRekeyWindow(inbound_window)),
          outbound_(role == EndpointRole::Client ? Direction::ClientToServer
                                                 : Direction::ServerToClient,
                    DeriveDirectionRoot(initial_root.bytes(),
                        role == EndpointRole::Client ? Direction::ClientToServer
                                                     : Direction::ServerToClient),
                    outbound_policy),
          inbound_(role == EndpointRole::Client ? Direction::ServerToClient
                                                : Direction::ClientToServer,
                   DeriveDirectionRoot(initial_root.bytes(),
                       role == EndpointRole::Client ? Direction::ServerToClient
                                                    : Direction::ClientToServer),
                   inbound_policy),
          psk_key_(std::move(psk_key)) {
        if (psk_key_.bytes().size() != 32) {
            throw std::runtime_error("relay established PSK key must be 32 bytes");
        }
    }

    bool ShouldStartRekey(const Frame& plaintext,
                          std::chrono::steady_clock::time_point now) const {
        std::lock_guard<std::mutex> lock(mu_);
        if (!IsApplicationFrame(plaintext.header.type)) return false;
        if (OutboundDepthLocked() >= outbound_window_) return false;
        // Pace preparation against application progress. Without this an
        // exhausted epoch would offer again on every write pass and send the
        // whole window as one visible burst of rekey records. The first
        // exchange is always allowed so a stalled direction can recover.
        if (OutboundDepthLocked() > 0 && OutboundMarkLocked() == last_init_mark_) {
            return false;
        }
        return outbound_.ShouldPrepareRekey(plaintext.payload.size(), now);
    }

    bool ApplicationWriteBlocked(
        const Frame& plaintext,
        std::chrono::steady_clock::time_point now) const {
        std::lock_guard<std::mutex> lock(mu_);
        // Blocked only when the current epoch is spent, nothing prepared can
        // take over and an exchange is already in flight. With nothing in
        // flight the caller must start one instead.
        return IsApplicationFrame(plaintext.header.type) &&
               prepared_outbound_.empty() && !pending_outbound_.empty() &&
               outbound_.ShouldRekey(plaintext.payload.size(), now);
    }

    Frame BeginOutboundRekey(std::chrono::steady_clock::time_point now) {
        std::lock_guard<std::mutex> lock(mu_);
        if (OutboundDepthLocked() >= outbound_window_) {
            throw std::runtime_error("relay outbound rekey window is full");
        }
        const std::uint64_t depth =
            static_cast<std::uint64_t>(OutboundDepthLocked());
        if (outbound_.epoch() >
            std::numeric_limits<std::uint64_t>::max() - depth - 1) {
            throw std::runtime_error("relay outbound epoch exhausted");
        }
        auto pending = std::make_unique<PendingOutbound>();
        pending->next_epoch = outbound_.epoch() + depth + 1;
        pending->mlkem = basefwx::pq::GenerateKeyPair(
            basefwx::pq::KemAlgorithm::MlKem1024);
        pending->x25519 = basefwx::x25519::GenerateKeyPair();
        pending->started = now;
        pending->deadline = now + RekeyAllowanceLocked();
        // Keep the queue's deadlines non-decreasing. ACKs arrive in offer
        // order, so a later offer waits on the earlier ones and must never
        // expire before them.
        if (!pending_outbound_.empty() &&
            pending->deadline < pending_outbound_.back()->deadline) {
            pending->deadline = pending_outbound_.back()->deadline;
        }
        Frame init{{0, kFrameRekeyInit, 0, 0},
                   BuildRekeyInit(pending->next_epoch, pending->mlkem.public_key,
                                  pending->x25519.public_key)};
        pending_outbound_.push_back(std::move(pending));
        try {
            Frame sealed = SealLocked(init, now, false);
            last_init_mark_ = OutboundMarkLocked();
            return sealed;
        } catch (...) {
            pending_outbound_.pop_back();
            throw;
        }
    }

    Frame Seal(const Frame& plaintext, std::chrono::steady_clock::time_point now) {
        RequireRelayFrameType(plaintext.header.type);
        std::lock_guard<std::mutex> lock(mu_);
        const bool application = IsApplicationFrame(plaintext.header.type);
        if (application && outbound_.ShouldRekey(plaintext.payload.size(), now)) {
            // The epoch is spent. Commit the next prepared one rather than
            // advancing when the ACK arrives: every prepared epoch is used in
            // order, so its whole budget is usable and the receiver never has
            // to accept a gap.
            CommitNextOutboundLocked();
        }
        return SealLocked(plaintext, now, application);
    }

    OpenResult Open(const Frame& frame, std::chrono::steady_clock::time_point now) {
        RequireRelayFrameType(frame.header.type);
        std::lock_guard<std::mutex> lock(mu_);
        if ((frame.header.flags & kFlagInnerEncrypted) == 0 ||
            frame.payload.size() < kEnvelopePrefix + kGcmTagBytes) {
            throw std::runtime_error("relay frame lacks ratchet envelope");
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
            // Preparation of the next epochs runs ahead of the hard boundary,
            // so bounded old-epoch data may follow an INIT. The chain still
            // enforces its limits, and the first authenticated new-epoch frame
            // retires it.
            plaintext = inbound_.Decrypt(frame.header.type, frame.header.stream_id,
                                         frame.header.flags, sealed, now,
                                         application);
        } else if (!prepared_inbound_.empty() &&
                   sealed.epoch == prepared_inbound_.front()->epoch()) {
            // Only the next prepared epoch is acceptable. A conforming sender
            // uses prepared epochs in order, so skipping one is a gap and stays
            // fatal at any window depth.
            plaintext = prepared_inbound_.front()->Decrypt(
                frame.header.type, frame.header.stream_id, frame.header.flags,
                sealed, now, application);
            authenticated_pending_epoch = true;
        } else {
            throw std::runtime_error("relay unexpected or retired epoch");
        }
        if (authenticated_pending_epoch) {
            inbound_ = std::move(*prepared_inbound_.front());
            prepared_inbound_.pop_front();
        }

        Frame opened{{static_cast<std::uint32_t>(plaintext.size()),
                      frame.header.type, frame.header.stream_id,
                      static_cast<std::uint16_t>(frame.header.flags &
                                                 ~kFlagInnerEncrypted)},
                     std::move(plaintext)};
        OpenResult result;
        if (opened.header.type == kFrameRekeyInit) {
            result.control_response = HandleRekeyInitLocked(opened, now);
        } else if (opened.header.type == kFrameRekeyAck) {
            HandleRekeyAckLocked(opened, now);
            result.outbound_rekey_completed = true;
        } else {
            result.application_frame = std::move(opened);
        }
        return result;
    }

    bool outbound_rekey_pending() const {
        std::lock_guard<std::mutex> lock(mu_);
        return !pending_outbound_.empty();
    }

    std::optional<std::chrono::steady_clock::time_point> rekey_deadline() const {
        std::lock_guard<std::mutex> lock(mu_);
        if (pending_outbound_.empty()) return std::nullopt;
        // ACKs arrive in order and the queue's deadlines never decrease, so
        // the oldest exchange bounds them all.
        return pending_outbound_.front()->deadline;
    }

    RekeyRttEstimate rekey_rtt_estimate() const {
        std::lock_guard<std::mutex> lock(mu_);
        using Ms = std::chrono::milliseconds;
        return {rtt_samples_,
                std::chrono::duration_cast<Ms>(srtt_),
                std::chrono::duration_cast<Ms>(rttvar_),
                std::chrono::duration_cast<Ms>(RekeyAllowanceLocked())};
    }

    std::size_t outbound_rekeys_in_flight() const {
        std::lock_guard<std::mutex> lock(mu_);
        return pending_outbound_.size();
    }

    std::size_t prepared_outbound_epochs() const {
        std::lock_guard<std::mutex> lock(mu_);
        return prepared_outbound_.size();
    }

    std::size_t prepared_inbound_epochs() const {
        std::lock_guard<std::mutex> lock(mu_);
        return prepared_inbound_.size();
    }

    std::uint16_t outbound_window() const noexcept { return outbound_window_; }
    std::uint16_t inbound_window() const noexcept { return inbound_window_; }
    RatchetPolicy outbound_policy() const noexcept { return outbound_.policy(); }
    RatchetPolicy inbound_policy() const noexcept { return inbound_.policy(); }

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
    struct PendingOutbound {
        std::uint64_t next_epoch{0};
        basefwx::pq::KemKeyPair mlkem;
        basefwx::x25519::KeyPair x25519;
        std::chrono::steady_clock::time_point started{};
        // Fixed when the offer is made. A later estimator update must not
        // shorten a deadline already granted, and a caller arms a one-shot
        // timer at this instant.
        std::chrono::steady_clock::time_point deadline{};
    };

    // Epochs already spoken for: offered but unanswered, plus answered but
    // not yet used.
    std::size_t OutboundDepthLocked() const noexcept {
        return pending_outbound_.size() + prepared_outbound_.size();
    }

    // Application progress of the current sending epoch. Two offers may not
    // share one mark, which paces preparation without a clock.
    std::pair<std::uint64_t, std::uint64_t> OutboundMarkLocked() const noexcept {
        return {outbound_.epoch(), outbound_.epoch_messages()};
    }

    // Deadline for the next offer, clamped into the reviewed range.
    std::chrono::steady_clock::duration RekeyAllowanceLocked() const noexcept {
        if (rtt_samples_ == 0) {
            // No authenticated sample yet: the first exchange of a channel
            // uses the static fallback.
            return kMinRekeyAckDeadline;
        }
        using D = std::chrono::steady_clock::duration;
        const std::chrono::nanoseconds base = srtt_ + kRttVarWeight * rttvar_;
        if (base <= kMinRekeyAckDeadline) return std::chrono::duration_cast<D>(
            kMinRekeyAckDeadline);
        if (base >= kMaxRekeyAckDeadline) return std::chrono::duration_cast<D>(
            kMaxRekeyAckDeadline);
        return std::chrono::duration_cast<D>(base);
    }

    // Folds one authenticated ACK round trip into the estimator. The ACK has
    // already been decrypted and matched against the oldest offer, so an
    // off-path attacker cannot inject a sample, and an on-path one can only
    // delay a genuine ACK, which widens a liveness allowance and no security
    // limit.
    void ObserveAckRttLocked(std::chrono::steady_clock::duration sample) {
        // A now before the send instant is not a measurement.
        if (sample < std::chrono::steady_clock::duration::zero()) return;
        // Clamp before folding so one pathological exchange cannot pin the
        // estimator near the cap for the rest of the channel.
        auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::min<std::chrono::steady_clock::duration>(
                sample, kMaxRekeyAckDeadline));
        if (rtt_samples_ == 0) {
            srtt_ = ns;
            rttvar_ = ns / 2;
        } else {
            const std::chrono::nanoseconds deviation =
                srtt_ > ns ? srtt_ - ns : ns - srtt_;
            // Integer division truncates toward zero, so rttvar_ decays to zero
            // without crossing it.
            rttvar_ += (deviation - rttvar_) / kRttVarGainDivisor;
            srtt_ += (ns - srtt_) / kRttGainDivisor;
        }
        ++rtt_samples_;
    }

    void CommitNextOutboundLocked() {
        if (prepared_outbound_.empty()) {
            throw std::runtime_error("relay epoch rekey required before data");
        }
        // Move assignment wipes the retiring root and chain key.
        outbound_ = std::move(*prepared_outbound_.front());
        prepared_outbound_.pop_front();
    }

    Frame SealLocked(const Frame& plaintext,
                     std::chrono::steady_clock::time_point now,
                     bool application) {
        const std::uint16_t flags = static_cast<std::uint16_t>(
            plaintext.header.flags | kFlagInnerEncrypted);
        SealedFrame sealed = outbound_.Encrypt(
            plaintext.header.type, plaintext.header.stream_id, flags,
            plaintext.payload, now, application);
        Bytes envelope(kEnvelopePrefix);
        envelope.reserve(kEnvelopePrefix + sealed.ciphertext.size());
        WriteU64(envelope, 0, sealed.epoch);
        WriteU64(envelope, 8, sealed.sequence);
        envelope.insert(envelope.end(), sealed.ciphertext.begin(),
                        sealed.ciphertext.end());
        return Frame{{static_cast<std::uint32_t>(envelope.size()),
                      plaintext.header.type, plaintext.header.stream_id, flags},
                     std::move(envelope)};
    }

    // Returns the plaintext ACK, which the caller seals and queues on its own
    // ordered write path.
    Frame HandleRekeyInitLocked(const Frame& frame,
                                std::chrono::steady_clock::time_point now) {
        // The peer can never make this endpoint hold more than the depth it
        // accepts, so ML-KEM work and kept roots stay bounded per channel.
        if (prepared_inbound_.size() >= inbound_window_) {
            throw std::runtime_error("relay inbound rekey window overflow");
        }
        const auto init = ParseRekeyInit(frame.payload);
        const std::uint64_t expected_epoch =
            inbound_.epoch() + prepared_inbound_.size() + 1;
        if (init.next_epoch != expected_epoch) {
            throw std::runtime_error("relay inbound rekey epoch mismatch");
        }
        // Each offer chains from the newest prepared epoch, so the window is
        // a contiguous extension of the receiving chain.
        const DirectionalRatchet& base = prepared_inbound_.empty()
            ? inbound_ : *prepared_inbound_.back();
        basefwx::pq::KemResult kem = basefwx::pq::KemEncrypt(
            basefwx::pq::KemAlgorithm::MlKem1024, init.mlkem_public_key);
        SecureBytes kem_shared{std::move(kem.shared)};
        basefwx::x25519::KeyPair x25519 = basefwx::x25519::GenerateKeyPair();
        SecureBytes x_shared{basefwx::x25519::DeriveSharedSecret(
            x25519.private_key, init.x25519_public_key)};
        prepared_inbound_.push_back(
            base.MakeAdvanced(kem_shared.bytes(), x_shared.bytes(), psk_key_.bytes()));
        (void)now;
        return Frame{{0, kFrameRekeyAck, 0, 0},
                     BuildRekeyAck(init.next_epoch, kem.ciphertext, x25519.public_key)};
    }

    void HandleRekeyAckLocked(const Frame& frame,
                              std::chrono::steady_clock::time_point now) {
        if (pending_outbound_.empty()) {
            throw std::runtime_error("relay unsolicited rekey ACK");
        }
        const auto ack = ParseRekeyAck(frame.payload);
        // ACKs are matched in offer order. The reverse chain is ordered, so a
        // reordered or repeated ACK is fatal.
        const PendingOutbound& oldest = *pending_outbound_.front();
        const std::uint64_t expected_epoch =
            outbound_.epoch() + prepared_outbound_.size() + 1;
        if (ack.next_epoch != oldest.next_epoch ||
            ack.next_epoch != expected_epoch) {
            throw std::runtime_error("relay outbound rekey epoch mismatch");
        }
        SecureBytes kem_shared{basefwx::pq::KemDecrypt(
            basefwx::pq::KemAlgorithm::MlKem1024, oldest.mlkem.private_key,
            ack.mlkem_ciphertext)};
        SecureBytes x_shared{basefwx::x25519::DeriveSharedSecret(
            oldest.x25519.private_key, ack.x25519_public_key)};
        const DirectionalRatchet& base = prepared_outbound_.empty()
            ? outbound_ : *prepared_outbound_.back();
        prepared_outbound_.push_back(
            base.MakeAdvanced(kem_shared.bytes(), x_shared.bytes(), psk_key_.bytes()));
        // Sampled only here, after every check above passed. The interval runs
        // from sending the offer to accepting its ACK, including the offer's
        // wait behind ordered traffic, so it never underestimates the delay a
        // deadline has to tolerate.
        ObserveAckRttLocked(now - oldest.started);
        // Retires this exchange's ephemeral ML-KEM and X25519 private keys,
        // which both wipe on destruction.
        pending_outbound_.pop_front();
    }

    std::uint16_t outbound_window_;
    std::uint16_t inbound_window_;
    mutable std::mutex mu_;
    DirectionalRatchet outbound_;
    DirectionalRatchet inbound_;
    // Contiguous windows. prepared_inbound_ covers inbound_.epoch()+1..+n,
    // prepared_outbound_ covers outbound_.epoch()+1..+m, and pending_outbound_
    // continues from there in offer order.
    std::deque<std::unique_ptr<DirectionalRatchet>> prepared_inbound_;
    std::deque<std::unique_ptr<DirectionalRatchet>> prepared_outbound_;
    std::deque<std::unique_ptr<PendingOutbound>> pending_outbound_;
    std::pair<std::uint64_t, std::uint64_t> last_init_mark_{
        std::numeric_limits<std::uint64_t>::max(),
        std::numeric_limits<std::uint64_t>::max()};
    // Held in nanoseconds so the shift updates stay exact. The rep is signed,
    // which the difference terms rely on.
    std::uint64_t rtt_samples_{0};
    std::chrono::nanoseconds srtt_{0};
    std::chrono::nanoseconds rttvar_{0};
    SecureBytes psk_key_;
};

SessionRatchet::SessionRatchet(EndpointRole role,
                               SecureBytes initial_root,
                               SecureBytes psk_key,
                               std::uint16_t outbound_window,
                               std::uint16_t inbound_window,
                               RatchetPolicy outbound_policy,
                               RatchetPolicy inbound_policy)
    : impl_(std::make_unique<Impl>(
          role, std::move(initial_root), std::move(psk_key),
          outbound_window, inbound_window, outbound_policy, inbound_policy)) {}

SessionRatchet::SessionRatchet(EndpointRole role, Bytes initial_root,
                               Bytes psk_key, std::uint16_t outbound_window,
                               std::uint16_t inbound_window,
                               RatchetPolicy outbound_policy,
                               RatchetPolicy inbound_policy)
    : SessionRatchet(role, SecureBytes{std::move(initial_root)},
                     SecureBytes{std::move(psk_key)}, outbound_window,
                     inbound_window, outbound_policy, inbound_policy) {}

SessionRatchet::SessionRatchet(SessionRatchet&&) noexcept = default;
SessionRatchet& SessionRatchet::operator=(SessionRatchet&&) noexcept = default;
SessionRatchet::~SessionRatchet() = default;

bool SessionRatchet::ShouldStartRekey(
    const Frame& frame, std::chrono::steady_clock::time_point now) const {
    return impl_->ShouldStartRekey(frame, now);
}
bool SessionRatchet::ApplicationWriteBlocked(
    const Frame& frame, std::chrono::steady_clock::time_point now) const {
    return impl_->ApplicationWriteBlocked(frame, now);
}
Frame SessionRatchet::BeginOutboundRekey(std::chrono::steady_clock::time_point now) {
    return impl_->BeginOutboundRekey(now);
}
Frame SessionRatchet::Seal(const Frame& frame,
                           std::chrono::steady_clock::time_point now) {
    return impl_->Seal(frame, now);
}
OpenResult SessionRatchet::Open(const Frame& frame,
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
RekeyRttEstimate SessionRatchet::rekey_rtt_estimate() const {
    return impl_->rekey_rtt_estimate();
}
bool SessionRatchet::rekey_timed_out(std::chrono::steady_clock::time_point now) const {
    return impl_->rekey_timed_out(now);
}
std::uint64_t SessionRatchet::outbound_epoch() const {
    return impl_->outbound_epoch();
}
std::uint64_t SessionRatchet::inbound_epoch() const {
    return impl_->inbound_epoch();
}
std::size_t SessionRatchet::outbound_rekeys_in_flight() const {
    return impl_->outbound_rekeys_in_flight();
}
std::size_t SessionRatchet::prepared_outbound_epochs() const {
    return impl_->prepared_outbound_epochs();
}
std::size_t SessionRatchet::prepared_inbound_epochs() const {
    return impl_->prepared_inbound_epochs();
}
std::uint16_t SessionRatchet::outbound_window() const {
    return impl_->outbound_window();
}
std::uint16_t SessionRatchet::inbound_window() const {
    return impl_->inbound_window();
}
RatchetPolicy SessionRatchet::outbound_policy() const {
    return impl_->outbound_policy();
}
RatchetPolicy SessionRatchet::inbound_policy() const {
    return impl_->inbound_policy();
}

bool SessionRatchet::IsApplicationFrame(std::uint8_t type) noexcept {
    return type == kFrameData;
}

}  // namespace yume::relay::ratchet
