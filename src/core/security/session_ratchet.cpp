/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/security/session_ratchet.hpp"

#include <algorithm>
#include <cstdint>
#include <deque>
#include <limits>
#include <mutex>
#include <stdexcept>
#include <utility>

#if YUME_USE_BASEFWX
#include <basefwx/crypto.hpp>
#include <basefwx/pq.hpp>
#include <basefwx/x25519.hpp>
#endif

#include "core/security/auth_v2.hpp"

namespace yume::ratchet {
namespace {

// RFC 6298 estimator gains, expressed as shifts so the update is exact integer
// arithmetic with no rounding drift: SRTT += (R - SRTT) / 8,
// RTTVAR += (|SRTT - R| - RTTVAR) / 4, deadline base = SRTT + 4 * RTTVAR.
// A 1/8 gain is roughly an eight-sample time constant, which is the hysteresis
// the design calls for: a single jitter spike moves the deadline by an eighth
// of its excess, and a burst has to persist to move it far.
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

#if YUME_USE_BASEFWX
const Bytes& SecretBytes(const basefwx::crypto::SecureBytes& bytes) noexcept {
    return bytes.bytes();
}
#else
const Bytes& SecretBytes(const Bytes& bytes) noexcept {
    return bytes;
}
#endif

}  // namespace

class SessionRatchet::Impl {
public:
#if YUME_USE_BASEFWX
    Impl(EndpointRole role,
         basefwx::crypto::SecureBytes initial_root,
         basefwx::crypto::SecureBytes psk_key,
#else
    Impl(EndpointRole role, Bytes initial_root, Bytes psk_key,
#endif
         std::uint16_t outbound_window, std::uint16_t inbound_window,
         RatchetPolicy outbound_policy, RatchetPolicy inbound_policy)
        : outbound_window_(ClampRekeyWindow(outbound_window)),
          inbound_window_(ClampRekeyWindow(inbound_window)),
          outbound_(role == EndpointRole::Client ? Direction::ClientToServer
                                                 : Direction::ServerToClient,
                    DeriveDirectionRoot(SecretBytes(initial_root),
                        role == EndpointRole::Client ? Direction::ClientToServer
                                                     : Direction::ServerToClient),
                    outbound_policy),
          inbound_(role == EndpointRole::Client ? Direction::ServerToClient
                                                : Direction::ClientToServer,
                   DeriveDirectionRoot(SecretBytes(initial_root),
                       role == EndpointRole::Client ? Direction::ServerToClient
                                                    : Direction::ClientToServer),
                   inbound_policy),
#if YUME_USE_BASEFWX
          psk_key_(std::move(psk_key)) {
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
        if (!IsApplicationFrame(plaintext.header.type)) return false;
        if (OutboundDepthLocked() >= outbound_window_) return false;
        // TODO(yume/offer-pacing): adaptive preparation remains a classifier-
        // gated research item, not a known throughput fix. The old attribution
        // to this rule came from a probe that omitted sealed application frames
        // and desynchronised the peer's record sequence. The corrected probe
        // reaches the negotiated preparation window, and live-path sweeps now
        // show H2/ratchet credit -- not mark pacing -- setting the WAN knee.
        // Do not implement the rejected offer-pacing design. If a future
        // capture campaign motivates adaptation, first measure live prepared
        // depth and preserve the negotiated root-retention bound. Any pacing
        // change is timing-visible and remains behind the classifier gate.
        // Pace preparation against real application progress. Without this an
        // exhausted epoch would re-offer on every selector pass and emit the
        // whole window as one classifier-visible burst of rekey records. The
        // first exchange is always allowed so a stalled direction can recover.
        if (OutboundDepthLocked() > 0 && OutboundMarkLocked() == last_init_mark_) {
            return false;
        }
        return outbound_.ShouldPrepareRekey(plaintext.payload.size(), now);
    }

    bool ApplicationWriteBlocked(
        const protocol::Frame& plaintext,
        std::chrono::steady_clock::time_point now) const {
        std::lock_guard<std::mutex> lock(mu_);
        // Blocked only when the current epoch is spent, nothing is prepared to
        // take over, and an exchange is already in flight to wait for. With
        // nothing in flight the caller must be allowed to start one instead.
        return IsApplicationFrame(plaintext.header.type) &&
               prepared_outbound_.empty() && !pending_outbound_.empty() &&
               outbound_.ShouldRekey(plaintext.payload.size(), now);
    }

    protocol::Frame BeginOutboundRekey(
        std::chrono::steady_clock::time_point now) {
        std::lock_guard<std::mutex> lock(mu_);
        if (OutboundDepthLocked() >= outbound_window_) {
            throw std::runtime_error("YUME 2.0 outbound rekey window is full");
        }
        const std::uint64_t depth =
            static_cast<std::uint64_t>(OutboundDepthLocked());
        if (outbound_.epoch() >
            std::numeric_limits<std::uint64_t>::max() - depth - 1) {
            throw std::runtime_error("YUME 2.0 outbound epoch exhausted");
        }
#if YUME_USE_BASEFWX
        auto pending = std::make_unique<PendingOutbound>();
        pending->next_epoch = outbound_.epoch() + depth + 1;
        pending->mlkem = basefwx::pq::GenerateKeyPair(
            basefwx::pq::KemAlgorithm::MlKem1024);
        pending->x25519 = basefwx::x25519::GenerateKeyPair();
        pending->started = now;
        pending->deadline = now + RekeyAllowanceLocked();
        // Keep the queue's deadlines non-decreasing. ACKs are answered in offer
        // order, so a later offer is waiting on the earlier ones and must never
        // expire before them; without this a shrinking estimator could make the
        // queue front jump to an already-past deadline the moment the exchange
        // ahead of it completes.
        if (!pending_outbound_.empty() &&
            pending->deadline < pending_outbound_.back()->deadline) {
            pending->deadline = pending_outbound_.back()->deadline;
        }
        protocol::Frame init{{0, protocol::REKEY_INIT, 0, 0},
            auth_v2::BuildRekeyInit(pending->next_epoch,
                                    pending->mlkem.public_key,
                                    pending->x25519.public_key)};
        pending_outbound_.push_back(std::move(pending));
        try {
            protocol::Frame sealed = SealLocked(init, now, false);
            last_init_mark_ = OutboundMarkLocked();
            return sealed;
        } catch (...) {
            pending_outbound_.pop_back();
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
        if (application && outbound_.ShouldRekey(plaintext.payload.size(), now)) {
            // The epoch is spent. Commit the next prepared one instead of
            // advancing on ACK arrival: every prepared epoch must be consumed
            // in order so its full 256 KiB budget is usable and the receiver
            // never has to accept a gap.
            CommitNextOutboundLocked();
        }
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
            // Preparation of the next epochs is pipelined ahead of the hard
            // boundary. Ordered H2/TCP permits bounded old-epoch data after
            // INIT; DirectionalRatchet still enforces 256 KiB/512 frames. The
            // first authenticated new-epoch frame retires this chain.
            plaintext = inbound_.Decrypt(frame.header.type, frame.header.stream_id,
                                         frame.header.flags, sealed, now,
                                         application);
        } else if (!prepared_inbound_.empty() &&
                   sealed.epoch == prepared_inbound_.front()->epoch()) {
            // Only the immediately next prepared epoch is acceptable. A
            // conforming sender consumes prepared epochs in order, so a jump
            // over one is a gap and stays fatal at any window depth.
            plaintext = prepared_inbound_.front()->Decrypt(
                frame.header.type, frame.header.stream_id, frame.header.flags,
                sealed, now, application);
            authenticated_pending_epoch = true;
        } else {
            throw std::runtime_error("YUME 2.0 unexpected or retired epoch");
        }
        if (authenticated_pending_epoch) {
            inbound_ = std::move(*prepared_inbound_.front());
            prepared_inbound_.pop_front();
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
        // ACKs are answered in order and the queue's deadlines are
        // non-decreasing, so the oldest exchange bounds them all. The whole
        // queue is still bounded: the front expires at most
        // `kMaxRekeyAckDeadline` after the oldest unanswered offer was sent.
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
#if YUME_USE_BASEFWX
    struct PendingOutbound {
        std::uint64_t next_epoch{0};
        basefwx::pq::KemKeyPair mlkem;
        basefwx::x25519::KeyPair x25519;
        std::chrono::steady_clock::time_point started{};
        // Frozen when the offer is created, never recomputed. A later estimator
        // update must not be able to retroactively shorten a deadline that has
        // already been granted, and the transport arms a one-shot timer at this
        // instant, so a moving target would fire early and never re-arm.
        std::chrono::steady_clock::time_point deadline{};
    };
#else
    struct PendingOutbound {};
#endif

    // Epochs that are already spoken for: offered but unacknowledged, plus
    // acknowledged but not yet consumed.
    std::size_t OutboundDepthLocked() const noexcept {
        return pending_outbound_.size() + prepared_outbound_.size();
    }

    // Application progress of the current sending epoch. Two offers may not
    // share one mark, which paces preparation without consulting a clock.
    std::pair<std::uint64_t, std::uint64_t> OutboundMarkLocked() const noexcept {
        return {outbound_.epoch(), outbound_.epoch_messages()};
    }

    // Deadline the next offer receives. Monotone in the estimator and clamped
    // into the reviewed range, so it is never shorter than the previous fixed
    // deadline and never longer than the cap.
    std::chrono::steady_clock::duration RekeyAllowanceLocked() const noexcept {
        if (rtt_samples_ == 0) {
            // No authenticated sample yet: the first exchange of a session
            // always uses the conservative static fallback.
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

    // Folds one authenticated ACK round trip into the estimator. The caller must
    // already have verified the ACK: it is decrypted and AEAD-authenticated by
    // the inbound chain and matched strictly against the oldest outstanding
    // offer's epoch before this runs. An off-path attacker therefore cannot
    // inject a sample, and an on-path attacker can only delay a genuine ACK,
    // which enlarges a liveness allowance and no security limit.
    void ObserveAckRttLocked(std::chrono::steady_clock::duration sample) {
        // A caller-supplied `now` earlier than the send instant is not a usable
        // measurement; drop it rather than corrupt the estimator with it.
        if (sample < std::chrono::steady_clock::duration::zero()) return;
        // Clamp before folding so one pathological exchange cannot pin the
        // estimator near the cap for the rest of the session.
        auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::min<std::chrono::steady_clock::duration>(
                sample, kMaxRekeyAckDeadline));
        if (rtt_samples_ == 0) {
            srtt_ = ns;
            rttvar_ = ns / 2;
        } else {
            const std::chrono::nanoseconds deviation =
                srtt_ > ns ? srtt_ - ns : ns - srtt_;
            // Integer division truncates toward zero, so `rttvar_` decays to
            // zero without ever crossing it.
            rttvar_ += (deviation - rttvar_) / kRttVarGainDivisor;
            srtt_ += (ns - srtt_) / kRttGainDivisor;
        }
        ++rtt_samples_;
    }

    void CommitNextOutboundLocked() {
        if (prepared_outbound_.empty()) {
            throw std::runtime_error("YUME 2.0 epoch rekey required before data");
        }
        // Move-assignment wipes the retiring root and chain key.
        outbound_ = std::move(*prepared_outbound_.front());
        prepared_outbound_.pop_front();
    }

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

    // Returns the plaintext ACK; the caller seals and queues it on its own
    // ordered write path.
    protocol::Frame HandleRekeyInitLocked(
        const protocol::Frame& frame,
        std::chrono::steady_clock::time_point now) {
        // The peer can never make this endpoint hold more than the depth it
        // advertised, so ML-KEM work and retained roots stay bounded per
        // session no matter how many offers arrive.
        if (prepared_inbound_.size() >= inbound_window_) {
            throw std::runtime_error("YUME 2.0 inbound rekey window overflow");
        }
        const auto init = auth_v2::ParseRekeyInit(frame.payload);
        const std::uint64_t expected_epoch =
            inbound_.epoch() + prepared_inbound_.size() + 1;
        if (init.next_epoch != expected_epoch) {
            throw std::runtime_error("YUME 2.0 inbound rekey epoch mismatch");
        }
#if YUME_USE_BASEFWX
        // Each offer chains from the newest prepared epoch, so the window is a
        // strictly contiguous extension of the receiving chain.
        const DirectionalRatchet& base = prepared_inbound_.empty()
            ? inbound_ : *prepared_inbound_.back();
        basefwx::pq::KemResult kem = basefwx::pq::KemEncrypt(
            basefwx::pq::KemAlgorithm::MlKem1024, init.mlkem_public_key);
        basefwx::crypto::SecureBytes kem_shared{std::move(kem.shared)};
        basefwx::x25519::KeyPair x25519 = basefwx::x25519::GenerateKeyPair();
        basefwx::crypto::SecureBytes x_shared{
            basefwx::x25519::DeriveSharedSecret(x25519.private_key,
                                                init.x25519_public_key)};
        prepared_inbound_.push_back(
            base.MakeAdvanced(kem_shared.bytes(), x_shared.bytes(), Psk()));
        (void)now;
        // Returned unsealed on purpose; see OpenResult::control_response.
        return protocol::Frame{{0, protocol::REKEY_ACK, 0, 0},
            auth_v2::BuildRekeyAck(init.next_epoch, kem.ciphertext,
                                   x25519.public_key)};
#else
        (void)now;
        throw std::runtime_error("YUME 2.0 rekey requires BaseFWX");
#endif
    }

    void HandleRekeyAckLocked(const protocol::Frame& frame,
                              std::chrono::steady_clock::time_point now) {
        if (pending_outbound_.empty()) {
            throw std::runtime_error("YUME 2.0 unsolicited rekey ACK");
        }
        const auto ack = auth_v2::ParseRekeyAck(frame.payload);
#if YUME_USE_BASEFWX
        // ACKs are matched strictly in offer order; the reverse chain is
        // ordered, so a reordered or duplicated ACK is fatal.
        const PendingOutbound& oldest = *pending_outbound_.front();
        const std::uint64_t expected_epoch =
            outbound_.epoch() + prepared_outbound_.size() + 1;
        if (ack.next_epoch != oldest.next_epoch ||
            ack.next_epoch != expected_epoch) {
            throw std::runtime_error("YUME 2.0 outbound rekey epoch mismatch");
        }
        basefwx::crypto::SecureBytes kem_shared{
            basefwx::pq::KemDecrypt(basefwx::pq::KemAlgorithm::MlKem1024,
                                    oldest.mlkem.private_key,
                                    ack.mlkem_ciphertext)};
        basefwx::crypto::SecureBytes x_shared{
            basefwx::x25519::DeriveSharedSecret(oldest.x25519.private_key,
                                                ack.x25519_public_key)};
        const DirectionalRatchet& base = prepared_outbound_.empty()
            ? outbound_ : *prepared_outbound_.back();
        prepared_outbound_.push_back(
            base.MakeAdvanced(kem_shared.bytes(), x_shared.bytes(), Psk()));
        // Sampled only here, once every acceptance check above has passed. The
        // interval measured is offer-send to ACK-accept, which includes this
        // offer's wait behind ordered carrier traffic and is therefore an upper
        // bound on network RTT, never an underestimate. That is the conservative
        // direction: it is exactly the delay the deadline has to tolerate.
        ObserveAckRttLocked(now - oldest.started);
        // Retires this exchange's ephemeral ML-KEM and X25519 private keys:
        // both key pair types wipe on destruction.
        pending_outbound_.pop_front();
#else
        (void)now;
        (void)ack;
        throw std::runtime_error("YUME 2.0 rekey requires BaseFWX");
#endif
    }

    std::uint16_t outbound_window_;
    std::uint16_t inbound_window_;
    mutable std::mutex mu_;
    DirectionalRatchet outbound_;
    DirectionalRatchet inbound_;
    // Contiguous windows. `prepared_inbound_` covers inbound_.epoch()+1..+n,
    // `prepared_outbound_` covers outbound_.epoch()+1..+m, and
    // `pending_outbound_` continues from there in offer order.
    std::deque<std::unique_ptr<DirectionalRatchet>> prepared_inbound_;
    std::deque<std::unique_ptr<DirectionalRatchet>> prepared_outbound_;
    std::deque<std::unique_ptr<PendingOutbound>> pending_outbound_;
    std::pair<std::uint64_t, std::uint64_t> last_init_mark_{
        std::numeric_limits<std::uint64_t>::max(),
        std::numeric_limits<std::uint64_t>::max()};
    // Authenticated-ACK round-trip estimator. Held in nanoseconds so the shift
    // updates stay exact; `std::chrono::nanoseconds::rep` is signed, which the
    // difference terms rely on.
    std::uint64_t rtt_samples_{0};
    std::chrono::nanoseconds srtt_{0};
    std::chrono::nanoseconds rttvar_{0};
#if YUME_USE_BASEFWX
    basefwx::crypto::SecureBytes psk_key_;
#else
    Bytes psk_key_;
#endif
};

#if YUME_USE_BASEFWX
SessionRatchet::SessionRatchet(
    EndpointRole role,
    basefwx::crypto::SecureBytes initial_root,
    basefwx::crypto::SecureBytes psk_key,
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
    : SessionRatchet(
          role,
          basefwx::crypto::SecureBytes{std::move(initial_root)},
          basefwx::crypto::SecureBytes{std::move(psk_key)},
          outbound_window, inbound_window, outbound_policy, inbound_policy) {}
#else
SessionRatchet::SessionRatchet(EndpointRole role, Bytes initial_root,
                               Bytes psk_key, std::uint16_t outbound_window,
                               std::uint16_t inbound_window,
                               RatchetPolicy outbound_policy,
                               RatchetPolicy inbound_policy)
    : impl_(std::make_unique<Impl>(role, std::move(initial_root),
                                   std::move(psk_key), outbound_window,
                                   inbound_window, outbound_policy,
                                   inbound_policy)) {}
#endif
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

RekeyRttEstimate SessionRatchet::rekey_rtt_estimate() const {
    return impl_->rekey_rtt_estimate();
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
