#include "core/security/session_ratchet.hpp"

#include <cassert>
#include <cstdio>
#include <deque>
#include <chrono>
#include <stdexcept>
#include <vector>

#include "core/security/auth_v2.hpp"

#if YUME_USE_BASEFWX
#include <basefwx/pq.hpp>
#include <basefwx/x25519.hpp>
#endif

namespace {

void AppendU64(yume::ratchet::Bytes& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

yume::protocol::Frame Envelope(std::uint8_t type,
                               std::uint8_t stream_id,
                               yume::ratchet::SealedFrame sealed) {
    yume::ratchet::Bytes payload;
    AppendU64(payload, sealed.epoch);
    AppendU64(payload, sealed.sequence);
    payload.insert(payload.end(), sealed.ciphertext.begin(),
                   sealed.ciphertext.end());
    return {{static_cast<std::uint32_t>(payload.size()), type, stream_id,
             yume::protocol::kFlagInnerEncrypted},
            std::move(payload)};
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

void TestX25519RejectsAllZeroPeer() {
#if YUME_USE_BASEFWX
    auto local = basefwx::x25519::GenerateKeyPair();
    assert(Throws([&] {
        (void)basefwx::x25519::DeriveSharedSecret(
            local.private_key, basefwx::x25519::Bytes(32, 0));
    }));
#endif
}

void TestOldEpochApplicationRejectedAfterCommit() {
    using namespace yume;
    using namespace std::chrono_literals;
    const ratchet::Bytes root(32, 0x71);
    const ratchet::Bytes psk(32, 0x82);
    ratchet::SessionRatchet client(ratchet::EndpointRole::Client, root, psk);
    ratchet::SessionRatchet server(ratchet::EndpointRole::Server, root, psk);
    // Mirrors every frame the client seals on the old chain, so a stale frame
    // later carries the exact sequence a conforming sender would have used.
    ratchet::DirectionalRatchet old_sender(
        ratchet::Direction::ClientToServer,
        ratchet::DeriveDirectionRoot(root,
                                     ratchet::Direction::ClientToServer));
    const auto now = std::chrono::steady_clock::time_point{};

    auto init = client.BeginOutboundRekey(now);
    auto init_result = server.Open(init, now);
    assert(init_result.control_response.has_value());
    (void)old_sender.Encrypt(protocol::REKEY_INIT, 0,
                             protocol::kFlagInnerEncrypted, {}, now, false);

    // Bounded old-epoch DATA stays valid while the hybrid exchange is pending.
    protocol::Frame overlapping{{1, protocol::DATA, 1, 0}, {0x55}};
    auto opened_overlapping = server.Open(client.Seal(overlapping, now), now);
    assert(opened_overlapping.application_frame.has_value());
    (void)old_sender.Encrypt(protocol::DATA, 1,
                             protocol::kFlagInnerEncrypted, {0x55}, now);

    auto ack_result = client.Open(
        server.Seal(*init_result.control_response, now), now);
    assert(ack_result.outbound_rekey_completed);
    // The ACK only prepares the epoch. It is committed by the first frame that
    // no longer fits the current one, here at the 500 ms active boundary.
    assert(client.outbound_epoch() == 0);
    assert(client.prepared_outbound_epochs() == 1);

    protocol::Frame new_plain{{1, protocol::DATA, 1, 0}, {0x66}};
    auto new_epoch = client.Seal(new_plain, now + 501ms);
    assert(client.outbound_epoch() == 1);
    auto opened_new_epoch = server.Open(new_epoch, now + 501ms);
    assert(opened_new_epoch.application_frame.has_value());
    assert(server.inbound_epoch() == 1);

    // Once an authenticated new-epoch frame commits the receiver, even a
    // correctly sequenced/authenticated old-chain frame is permanently stale.
    auto stale = old_sender.Encrypt(
        protocol::DATA, 1, protocol::kFlagInnerEncrypted, {0x77}, now);
    assert(Throws([&] {
        (void)server.Open(Envelope(protocol::DATA, 1, std::move(stale)), now);
    }));
}

void TestRekeyPreparationOverlapsWithoutCrossingLimits() {
    using namespace yume;
    const ratchet::Bytes root(32, 0x91);
    const ratchet::Bytes psk(32, 0xa2);
    ratchet::SessionRatchet client(ratchet::EndpointRole::Client, root, psk);
    ratchet::SessionRatchet server(ratchet::EndpointRole::Server, root, psk);
    const auto now = std::chrono::steady_clock::time_point{};

    // A maximum-sized application frame must start the next hybrid exchange
    // before it consumes the current epoch. The authenticated old epoch stays
    // usable only up to its unchanged byte/frame boundary while the ACK is in
    // flight.
    protocol::Frame full{{static_cast<std::uint32_t>(
                              ratchet::kEpochByteLimit),
                          protocol::DATA, 1, 0},
                         ratchet::Bytes(ratchet::kEpochByteLimit, 0xb3)};
    assert(client.ShouldStartRekey(full, now));
    auto init = client.BeginOutboundRekey(now);
    auto opened_init = server.Open(init, now);
    assert(opened_init.control_response.has_value());
    assert(!client.ApplicationWriteBlocked(full, now));

    auto old_epoch_data = client.Seal(full, now);
    assert(old_epoch_data.header.type == protocol::DATA);
    auto opened_old_epoch_data = server.Open(old_epoch_data, now);
    assert(opened_old_epoch_data.application_frame.has_value());
    assert(opened_old_epoch_data.application_frame->payload == full.payload);

    protocol::Frame extra{{1, protocol::DATA, 1, 0}, {0xc4}};
    assert(client.ApplicationWriteBlocked(extra, now));
    assert(Throws([&] { (void)client.Seal(extra, now); }));

    // A malicious implementation cannot bypass the limit by treating DATA as
    // unaccounted control while the receiver retains both chains.
    ratchet::DirectionalRatchet malicious_old_sender(
        ratchet::Direction::ClientToServer,
        ratchet::DeriveDirectionRoot(root,
                                     ratchet::Direction::ClientToServer));
    (void)malicious_old_sender.Encrypt(
        protocol::REKEY_INIT, 0, protocol::kFlagInnerEncrypted, {}, now, false);
    (void)malicious_old_sender.Encrypt(
        protocol::DATA, 1, protocol::kFlagInnerEncrypted, full.payload, now);
    auto over_limit = malicious_old_sender.Encrypt(
        protocol::DATA, 1, protocol::kFlagInnerEncrypted, {0xd5}, now, false);
    assert(Throws([&] {
        (void)server.Open(
            Envelope(protocol::DATA, 1, std::move(over_limit)), now);
    }));

    auto opened_ack = client.Open(
        server.Seal(*opened_init.control_response, now), now);
    assert(opened_ack.outbound_rekey_completed);
    auto new_epoch_data = client.Seal(extra, now);
    auto opened_new_epoch_data = server.Open(new_epoch_data, now);
    assert(opened_new_epoch_data.application_frame.has_value());
    assert(opened_new_epoch_data.application_frame->payload == extra.payload);
    assert(client.outbound_epoch() == 1);
    assert(server.inbound_epoch() == 1);
}

void TestSimultaneousDirectionalRekey() {
    using namespace yume;
    using namespace std::chrono_literals;
    const ratchet::Bytes root(32, 0x51);
    const ratchet::Bytes psk(32, 0x62);
    ratchet::SessionRatchet client(ratchet::EndpointRole::Client, root, psk);
    ratchet::SessionRatchet server(ratchet::EndpointRole::Server, root, psk);
    const auto now = std::chrono::steady_clock::time_point{} + 2s;

    auto client_init = client.BeginOutboundRekey(now);
    auto server_init = server.BeginOutboundRekey(now);
    assert(!client.rekey_timed_out(now + 4999ms));
    assert(client.rekey_timed_out(now + 5s));

    auto server_received_init = server.Open(client_init, now + 1ms);
    auto client_received_init = client.Open(server_init, now + 1ms);
    assert(server_received_init.control_response.has_value());
    assert(client_received_init.control_response.has_value());

    auto client_received_ack = client.Open(
        server.Seal(*server_received_init.control_response, now + 2ms),
        now + 2ms);
    auto server_received_ack = server.Open(
        client.Seal(*client_received_init.control_response, now + 2ms),
        now + 2ms);
    assert(client_received_ack.outbound_rekey_completed);
    assert(server_received_ack.outbound_rekey_completed);
    assert(client.prepared_outbound_epochs() == 1 &&
           server.prepared_outbound_epochs() == 1);
    assert(client.outbound_epoch() == 0 && server.outbound_epoch() == 0);

    // Make both epochs active so the 500 ms boundary applies, then cross it.
    protocol::Frame c2s_warm{{1, protocol::DATA, 1, 0}, {0xa0}};
    protocol::Frame s2c_warm{{1, protocol::DATA, 2, 0}, {0xb0}};
    (void)server.Open(client.Seal(c2s_warm, now + 3ms), now + 3ms);
    (void)client.Open(server.Seal(s2c_warm, now + 3ms), now + 3ms);

    protocol::Frame c2s{{1, protocol::DATA, 1, 0}, {0xa1}};
    protocol::Frame s2c{{1, protocol::DATA, 2, 0}, {0xb2}};
    auto opened_c2s = server.Open(client.Seal(c2s, now + 504ms), now + 504ms);
    auto opened_s2c = client.Open(server.Seal(s2c, now + 504ms), now + 504ms);
    assert(opened_c2s.application_frame->payload == c2s.payload);
    assert(opened_s2c.application_frame->payload == s2c.payload);
    assert(client.outbound_epoch() == 1 && server.outbound_epoch() == 1);
    assert(client.inbound_epoch() == 1 && server.inbound_epoch() == 1);
}

// The point of the window: N prepared epochs make N * 256 KiB usable from one
// rekey round trip instead of 256 KiB, with every per-epoch limit unchanged.
void TestBoundedMultiEpochWindowRaisesUsableBudget() {
    using namespace yume;
    constexpr std::uint16_t kWindow = 4;
    const ratchet::Bytes root(32, 0x13);
    const ratchet::Bytes psk(32, 0x24);
    ratchet::SessionRatchet client(ratchet::EndpointRole::Client, root, psk,
                                   kWindow, kWindow);
    ratchet::SessionRatchet server(ratchet::EndpointRole::Server, root, psk,
                                   kWindow, kWindow);
    const auto now = std::chrono::steady_clock::time_point{};
    assert(client.outbound_window() == kWindow);

    std::vector<protocol::Frame> acks;
    for (std::uint16_t i = 0; i < kWindow; ++i) {
        auto init = client.BeginOutboundRekey(now);
        auto opened = server.Open(init, now);
        assert(opened.control_response.has_value());
        acks.push_back(server.Seal(*opened.control_response, now));
    }
    assert(client.outbound_rekeys_in_flight() == kWindow);
    assert(server.prepared_inbound_epochs() == kWindow);
    // The negotiated depth is a hard cap, not a hint.
    assert(Throws([&] { (void)client.BeginOutboundRekey(now); }));

    for (auto& ack : acks) {
        assert(client.Open(ack, now).outbound_rekey_completed);
    }
    assert(client.outbound_rekeys_in_flight() == 0);
    assert(client.prepared_outbound_epochs() == kWindow);
    // Acknowledged epochs are prepared, not entered: each one must still be
    // consumed in turn so none of its byte budget is skipped.
    assert(client.outbound_epoch() == 0);

    const ratchet::Bytes payload(ratchet::kEpochByteLimit, 0x5a);
    for (std::uint64_t epoch = 0; epoch <= kWindow; ++epoch) {
        protocol::Frame full{{static_cast<std::uint32_t>(payload.size()),
                              protocol::DATA, 1, 0}, payload};
        auto opened = server.Open(client.Seal(full, now), now);
        assert(client.outbound_epoch() == epoch);
        assert(server.inbound_epoch() == epoch);
        assert(opened.application_frame.has_value());
        assert(opened.application_frame->payload == payload);
    }
    assert(client.prepared_outbound_epochs() == 0);

    // With the window spent and nothing in flight the sender is not "blocked":
    // it must offer again, and sealing without a prepared epoch stays fatal.
    protocol::Frame more{{1, protocol::DATA, 1, 0}, {0x01}};
    assert(!client.ApplicationWriteBlocked(more, now));
    assert(client.ShouldStartRekey(more, now));
    assert(Throws([&] { (void)client.Seal(more, now); }));
}

// Offers are paced by application progress. Without this an exhausted epoch
// re-offers on every write-selector pass and emits the window as one burst.
void TestOffersArePacedByApplicationProgress() {
    using namespace yume;
    constexpr std::uint16_t kWindow = 4;
    const ratchet::Bytes root(32, 0x35);
    const ratchet::Bytes psk(32, 0x46);
    ratchet::SessionRatchet client(ratchet::EndpointRole::Client, root, psk,
                                   kWindow, kWindow);
    ratchet::SessionRatchet server(ratchet::EndpointRole::Server, root, psk,
                                   kWindow, kWindow);
    const auto now = std::chrono::steady_clock::time_point{};

    const ratchet::Bytes payload(ratchet::kEpochByteLimit, 0x77);
    protocol::Frame full{{static_cast<std::uint32_t>(payload.size()),
                          protocol::DATA, 1, 0}, payload};
    assert(client.ShouldStartRekey(full, now));
    auto init = client.BeginOutboundRekey(now);
    // Same epoch, same application progress: no second offer.
    assert(!client.ShouldStartRekey(full, now));
    assert(client.outbound_rekeys_in_flight() == 1);

    // One sealed application frame is progress, so the next offer is allowed.
    auto opened_init = server.Open(init, now);
    assert(opened_init.control_response.has_value());
    (void)server.Open(client.Seal(full, now), now);
    assert(client.ShouldStartRekey(full, now));
}

// A peer that ignores the negotiated depth must be rejected rather than
// trusted, because every accepted offer costs an ML-KEM encapsulation and a
// retained epoch root.
void TestInboundWindowOverflowRejected() {
    using namespace yume;
    const ratchet::Bytes root(32, 0x57);
    const ratchet::Bytes psk(32, 0x68);
    ratchet::SessionRatchet greedy(ratchet::EndpointRole::Client, root, psk,
                                   /*outbound_window=*/5, /*inbound_window=*/5);
    ratchet::SessionRatchet strict(ratchet::EndpointRole::Server, root, psk,
                                   /*outbound_window=*/1, /*inbound_window=*/4);
    const auto now = std::chrono::steady_clock::time_point{};

    for (int i = 0; i < 4; ++i) {
        auto init = greedy.BeginOutboundRekey(now);
        assert(strict.Open(init, now).control_response.has_value());
    }
    auto overflow = greedy.BeginOutboundRekey(now);
    assert(Throws([&] { (void)strict.Open(overflow, now); }));
    assert(strict.prepared_inbound_epochs() == 4);
}

// The window extends the receiving chain contiguously. A skipped epoch is a
// gap, and stays fatal at any depth.
void TestNonContiguousOfferRejected() {
#if YUME_USE_BASEFWX
    using namespace yume;
    constexpr std::uint16_t kWindow = 4;
    const ratchet::Bytes root(32, 0x79);
    const ratchet::Bytes psk(32, 0x8a);
    ratchet::SessionRatchet client(ratchet::EndpointRole::Client, root, psk,
                                   kWindow, kWindow);
    ratchet::SessionRatchet server(ratchet::EndpointRole::Server, root, psk,
                                   kWindow, kWindow);
    const auto now = std::chrono::steady_clock::time_point{};

    auto first = client.BeginOutboundRekey(now);
    assert(server.Open(first, now).control_response.has_value());
    assert(server.prepared_inbound_epochs() == 1);

    auto mlkem = basefwx::pq::GenerateKeyPair(
        basefwx::pq::KemAlgorithm::MlKem1024);
    auto x25519 = basefwx::x25519::GenerateKeyPair();
    protocol::Frame skipped{{0, protocol::REKEY_INIT, 0, 0},
        auth_v2::BuildRekeyInit(server.inbound_epoch() + 3,
                                mlkem.public_key, x25519.public_key)};
    assert(Throws([&] {
        (void)server.Open(client.Seal(skipped, now), now);
    }));
    assert(server.prepared_inbound_epochs() == 1);
#endif
}


// Completes one offer/ACK exchange whose measured interval is exactly `rtt`.
void ExchangeRekey(yume::ratchet::SessionRatchet& sender,
                   yume::ratchet::SessionRatchet& receiver,
                   std::chrono::steady_clock::time_point sent,
                   std::chrono::steady_clock::duration rtt) {
    const auto init = sender.BeginOutboundRekey(sent);
    const auto arrival = sent + rtt / 2;
    auto offered = receiver.Open(init, arrival);
    assert(offered.control_response.has_value());
    auto acked = sender.Open(receiver.Seal(*offered.control_response, arrival),
                             sent + rtt);
    assert(acked.outbound_rekey_completed);
}

// Seals a fixed application workload and reports how far the sending chain
// advanced. The hard epoch boundary is a security limit, so this number must not
// depend on anything the round-trip estimator has observed.
std::uint64_t SealFixedWorkload(yume::ratchet::SessionRatchet& sender,
                                std::chrono::steady_clock::time_point at) {
    const yume::ratchet::Bytes chunk(64U * 1024U, 0x7A);
    const yume::protocol::Frame frame{
        {static_cast<std::uint32_t>(chunk.size()), yume::protocol::DATA, 1, 0},
        chunk};
    for (int i = 0; i < 16; ++i) (void)sender.Seal(frame, at);
    return sender.outbound_epoch();
}

// The deadline is a liveness allowance derived only from authenticated ACKs, and
// it is clamped into a reviewed range in both directions.
void TestAckDeadlineClampedInBothDirections() {
#if YUME_USE_BASEFWX
    using namespace std::chrono_literals;
    const yume::ratchet::Bytes root(32, 0x51);
    const yume::ratchet::Bytes psk(32, 0x52);
    const auto base = std::chrono::steady_clock::time_point{} + 1s;

    // No authenticated sample yet: the conservative static fallback is exactly
    // the deadline this endpoint used before adaptation existed.
    {
        yume::ratchet::SessionRatchet client(yume::ratchet::EndpointRole::Client,
                                             root, psk, 8, 8);
        yume::ratchet::SessionRatchet server(yume::ratchet::EndpointRole::Server,
                                             root, psk, 8, 8);
        assert(client.rekey_rtt_estimate().samples == 0);
        (void)client.BeginOutboundRekey(base);
        assert(*client.rekey_deadline() ==
               base + yume::ratchet::kMinRekeyAckDeadline);
        (void)server;
    }

    // A fast path measures a small round trip and still gets the floor: a peer
    // that answers quickly must not shorten the allowance below the reviewed
    // minimum, or ordinary jitter would start closing healthy sessions.
    {
        yume::ratchet::SessionRatchet client(yume::ratchet::EndpointRole::Client,
                                             root, psk, 8, 8);
        yume::ratchet::SessionRatchet server(yume::ratchet::EndpointRole::Server,
                                             root, psk, 8, 8);
        ExchangeRekey(client, server, base, 10ms);
        const auto estimate = client.rekey_rtt_estimate();
        assert(estimate.samples == 1);
        assert(estimate.smoothed == 10ms);
        assert(estimate.allowance == yume::ratchet::kMinRekeyAckDeadline);
        (void)client.BeginOutboundRekey(base + 1s);
        assert(*client.rekey_deadline() ==
               base + 1s + yume::ratchet::kMinRekeyAckDeadline);
    }

    // A genuinely slow path lifts the allowance above the floor instead of
    // closing the session, but stays bounded by the reviewed cap.
    {
        yume::ratchet::SessionRatchet client(yume::ratchet::EndpointRole::Client,
                                             root, psk, 8, 8);
        yume::ratchet::SessionRatchet server(yume::ratchet::EndpointRole::Server,
                                             root, psk, 8, 8);
        ExchangeRekey(client, server, base, 6s);
        // First sample seeds SRTT = R and RTTVAR = R/2, so the base is 3R.
        const auto estimate = client.rekey_rtt_estimate();
        assert(estimate.smoothed == 6s);
        assert(estimate.variation == 3s);
        assert(estimate.allowance == 18s);
        assert(estimate.allowance > yume::ratchet::kMinRekeyAckDeadline);
        assert(estimate.allowance < yume::ratchet::kMaxRekeyAckDeadline);
        (void)client.BeginOutboundRekey(base + 10s);
        assert(*client.rekey_deadline() == base + 10s + 18s);
    }

    // An extreme or pathological exchange cannot push the allowance past the
    // cap, so a stalled session still fails closed within a bounded time.
    {
        yume::ratchet::SessionRatchet client(yume::ratchet::EndpointRole::Client,
                                             root, psk, 8, 8);
        yume::ratchet::SessionRatchet server(yume::ratchet::EndpointRole::Server,
                                             root, psk, 8, 8);
        ExchangeRekey(client, server, base, 20min);
        assert(client.rekey_rtt_estimate().allowance ==
               yume::ratchet::kMaxRekeyAckDeadline);
        const auto sent = base + 1h;
        (void)client.BeginOutboundRekey(sent);
        assert(*client.rekey_deadline() ==
               sent + yume::ratchet::kMaxRekeyAckDeadline);
        // Still fails closed, just later: bounded, never indefinite.
        assert(!client.rekey_timed_out(
            sent + yume::ratchet::kMaxRekeyAckDeadline - 1ms));
        assert(client.rekey_timed_out(
            sent + yume::ratchet::kMaxRekeyAckDeadline));
    }
#endif
}

// A deadline is frozen when its offer is created. A later estimator update must
// never move it: the server arms a one-shot timer at this instant, and a
// deadline that moved outward would fire early and never re-arm.
void TestGrantedAckDeadlineIsFrozenAtOfferTime() {
#if YUME_USE_BASEFWX
    using namespace std::chrono_literals;
    const yume::ratchet::Bytes root(32, 0x61);
    const yume::ratchet::Bytes psk(32, 0x62);
    yume::ratchet::SessionRatchet client(yume::ratchet::EndpointRole::Client,
                                         root, psk, 8, 8);
    yume::ratchet::SessionRatchet server(yume::ratchet::EndpointRole::Server,
                                         root, psk, 8, 8);
    const auto base = std::chrono::steady_clock::time_point{} + 1s;
    ExchangeRekey(client, server, base, 6s);
    const auto granted = client.rekey_rtt_estimate().allowance;
    assert(granted == 18s);

    const auto first_sent = base + 10s;
    const auto second_sent = base + 11s;
    auto first_offer = client.BeginOutboundRekey(first_sent);
    auto second_offer = client.BeginOutboundRekey(second_sent);
    assert(client.outbound_rekeys_in_flight() == 2);
    // The oldest unanswered offer bounds the queue.
    assert(*client.rekey_deadline() == first_sent + granted);

    auto first_ack = server.Open(first_offer, first_sent);
    auto second_ack = server.Open(second_offer, second_sent);
    assert(first_ack.control_response.has_value());
    assert(second_ack.control_response.has_value());
    // Sealed in offer order; the reverse chain is ordered.
    auto sealed_first = server.Seal(*first_ack.control_response, second_sent);
    (void)server.Seal(*second_ack.control_response, second_sent);

    // Answering the first offer almost instantly moves the estimator. Note the
    // direction: a 1 ms reply after a 6 s one *widens* the bound rather than
    // narrowing it, because RTTVAR is updated from the deviation against the old
    // SRTT before SRTT itself moves. That is the intended RFC 6298 behaviour --
    // a path that swings between 1 ms and 6 s needs more headroom than either
    // endpoint alone -- and it makes this a decisive test: a deadline that was
    // recomputed instead of frozen would land strictly later than the assertion.
    assert(client.Open(sealed_first, first_sent + 1ms).outbound_rekey_completed);
    const auto updated = client.rekey_rtt_estimate();
    assert(updated.samples == 2);
    assert(updated.smoothed == 5250ms);   // 6s - (6s - 1ms)/8
    assert(updated.variation == 3749ms);  // 3s + (5999ms - 3s)/4
    assert(updated.allowance == 20249ms);
    assert(updated.allowance > granted);
    // The already-granted deadline did not follow the estimator.
    assert(*client.rekey_deadline() == second_sent + granted);
#endif
}

// The security boundary: what one epoch key protects is fixed by the negotiated
// policy. Measuring a slow path must not extend an epoch, skip a rekey, or in
// any other way enlarge the cryptographic blast radius.
void TestRttAdaptationNeverWidensEpochLimits() {
#if YUME_USE_BASEFWX
    using namespace std::chrono_literals;
    const yume::ratchet::Bytes root(32, 0x71);
    const yume::ratchet::Bytes psk(32, 0x72);
    const auto base = std::chrono::steady_clock::time_point{} + 1s;

    yume::ratchet::SessionRatchet fast(yume::ratchet::EndpointRole::Client,
                                       root, psk, 16, 16);
    yume::ratchet::SessionRatchet fast_peer(yume::ratchet::EndpointRole::Server,
                                            root, psk, 16, 16);
    yume::ratchet::SessionRatchet slow(yume::ratchet::EndpointRole::Client,
                                       root, psk, 16, 16);
    yume::ratchet::SessionRatchet slow_peer(yume::ratchet::EndpointRole::Server,
                                            root, psk, 16, 16);

    // Identical preparation depth, wildly different measured paths.
    for (int i = 0; i < 8; ++i) {
        ExchangeRekey(fast, fast_peer, base + std::chrono::milliseconds(i), 1ms);
        ExchangeRekey(slow, slow_peer, base + std::chrono::milliseconds(i), 20s);
    }
    // The two estimators have converged to very different liveness allowances:
    // a steady path settles on its own round trip, so the fast one sits on the
    // floor and the slow one well above it, still under the cap.
    const auto fast_allowance = fast.rekey_rtt_estimate().allowance;
    const auto slow_allowance = slow.rekey_rtt_estimate().allowance;
    assert(fast_allowance == yume::ratchet::kMinRekeyAckDeadline);
    assert(slow_allowance > fast_allowance);
    assert(slow_allowance <= yume::ratchet::kMaxRekeyAckDeadline);

    // Same negotiated policy, and the same sealing workload advances both
    // chains by exactly the same number of epochs.
    assert(fast.outbound_policy() == slow.outbound_policy());
    const auto at = base + 1min;
    assert(SealFixedWorkload(fast, at) == SealFixedWorkload(slow, at));
    assert(fast.outbound_epoch() == slow.outbound_epoch());
    assert(fast.outbound_epoch() > 0);
#endif
}


// Characterises how deep the outbound window gets on a delayed path with the
// transport removed: an unconstrained local sender, and every record reaching
// the peer exactly one half-RTT after it is sealed.
//
// The peer must receive the sealed *application* frames as well as the offers.
// Records carry a per-direction sequence, so a probe that forwards only
// REKEY_INIT desynchronises the peer after the first data frame; every later
// offer is then rejected at the record layer and silently never acknowledged.
// An earlier version of this probe did exactly that and reported a preparation
// ceiling that belonged to the harness. `refused` exists to keep that failure
// loud rather than silent.
struct DelayedPathProbe {
    std::size_t max_prepared{0};
    std::size_t max_in_flight{0};
    std::size_t refused{0};
    std::uint64_t bytes_sent{0};
};

DelayedPathProbe ProbeDelayedPath(std::uint16_t window,
                                  std::size_t frame_bytes,
                                  std::chrono::milliseconds rtt,
                                  int rtt_budget) {
    using namespace std::chrono_literals;
    using Tp = std::chrono::steady_clock::time_point;
    const yume::ratchet::Bytes root(32, 0x91);
    const yume::ratchet::Bytes psk(32, 0x92);
    yume::ratchet::SessionRatchet client(yume::ratchet::EndpointRole::Client,
                                         root, psk, window, window);
    yume::ratchet::SessionRatchet server(yume::ratchet::EndpointRole::Server,
                                         root, psk, window, window);
    const yume::ratchet::Bytes payload(frame_bytes, 0x5A);
    const yume::protocol::Frame data{
        {static_cast<std::uint32_t>(frame_bytes), yume::protocol::DATA, 1, 0},
        payload};

    const auto start = Tp{} + 1s;
    const auto deadline = start + rtt * rtt_budget;
    const auto one_way = rtt / 2;
    std::deque<std::pair<Tp, yume::protocol::Frame>> to_server;
    std::deque<std::pair<Tp, yume::protocol::Frame>> to_client;
    DelayedPathProbe probe;

    for (auto now = start; now < deadline; now += 1ms) {
        // Client to server, in seal order: offers and application frames share
        // one record sequence.
        while (!to_server.empty() && to_server.front().first <= now) {
            try {
                auto opened = server.Open(to_server.front().second, now);
                if (opened.control_response.has_value()) {
                    to_client.emplace_back(
                        now + one_way,
                        server.Seal(*opened.control_response, now));
                }
            } catch (const std::exception&) {
                ++probe.refused;
            }
            to_server.pop_front();
        }
        while (!to_client.empty() && to_client.front().first <= now) {
            (void)client.Open(to_client.front().second, now);
            to_client.pop_front();
        }
        if (client.ShouldStartRekey(data, now)) {
            try {
                to_server.emplace_back(now + one_way,
                                       client.BeginOutboundRekey(now));
            } catch (const std::exception&) {
                // Window full or epoch exhausted; nothing to record.
            }
        }
        probe.max_prepared = std::max(probe.max_prepared,
                                      client.prepared_outbound_epochs());
        probe.max_in_flight = std::max(probe.max_in_flight,
                                       client.outbound_rekeys_in_flight());
        if (client.ApplicationWriteBlocked(data, now)) continue;
        try {
            to_server.emplace_back(now + one_way, client.Seal(data, now));
            probe.bytes_sent += frame_bytes;
        } catch (const std::exception&) {
            // Hard boundary with nothing prepared.
        }
    }
    return probe;
}

// Pins that the negotiated window is reachable on a delayed path: preparation
// depth and delivered bytes both grow with it, so a regression that serialises
// preparation behind a single round trip fails here.
//
// This replaces an assertion that a wide window moved no more data than a
// narrow one. That result came from the harness defect described above, not
// from `ShouldStartRekey`; the mark-pacing rule does not cap preparation depth.
// Later live-path work attributed the relevant ceilings to TCP/H2/ratchet
// credit, not anything this test exercises. This test only protects the
// corrected conclusion that the negotiated preparation window is reachable.
void TestDelayedPathWindowIsReachable() {
#if YUME_USE_BASEFWX
    using namespace std::chrono_literals;
    const std::size_t frame = 64U * 1024U;
    const auto narrow = ProbeDelayedPath(1, frame, 60ms, 20);
    const auto wide = ProbeDelayedPath(16, frame, 60ms, 20);

    // A desynchronised peer would refuse offers and mask every result below.
    assert(narrow.refused == 0);
    assert(wide.refused == 0);

    // Offers pipeline up to the negotiated depth.
    assert(narrow.max_in_flight == 1);
    assert(wide.max_in_flight > narrow.max_in_flight);

    // Epochs ready to carry data accumulate; that is what throughput needs.
    assert(narrow.max_prepared == 1);
    assert(wide.max_prepared > narrow.max_prepared);
    assert(wide.max_prepared <= 16);

    // And the depth is delivered as bytes, not just as outstanding exchanges.
    assert(wide.bytes_sent > narrow.bytes_sent * 4);
#endif
}

}  // namespace

int main() {
    using namespace yume;
    using namespace std::chrono_literals;
    const ratchet::Bytes root(32, 0x31);
    const ratchet::Bytes psk(32, 0x42);
    ratchet::SessionRatchet client(ratchet::EndpointRole::Client, root, psk);
    ratchet::SessionRatchet server(ratchet::EndpointRole::Server, root, psk);

    const auto start = std::chrono::steady_clock::time_point{} + 1s;
    protocol::Frame first{{3, protocol::DATA, 7, 0}, {1, 2, 3}};
    auto opened = server.Open(client.Seal(first, start), start);
    assert(opened.application_frame.has_value());
    assert(opened.application_frame->payload == first.payload);

    protocol::Frame next{{1, protocol::DATA, 7, 0}, {4}};
    assert(client.ShouldStartRekey(next, start + 501ms));
    const auto init = client.BeginOutboundRekey(start + 501ms);
    assert(client.outbound_rekey_pending());
    auto init_result = server.Open(init, start + 502ms);
    assert(init_result.control_response.has_value());
    const auto ack_result = client.Open(
        server.Seal(*init_result.control_response, start + 502ms),
        start + 503ms);
    assert(ack_result.outbound_rekey_completed);
    assert(!client.outbound_rekey_pending());
    assert(client.prepared_outbound_epochs() == 1);
    assert(client.outbound_epoch() == 0);

    auto epoch_one = client.Seal(next, start + 504ms);
    assert(client.outbound_epoch() == 1);
    auto epoch_one_open = server.Open(epoch_one, start + 505ms);
    assert(epoch_one_open.application_frame.has_value());
    assert(server.inbound_epoch() == 1);
    // The default construction is the single-exchange behavior.
    assert(client.outbound_window() == ratchet::kMinRekeyWindow);
    TestSimultaneousDirectionalRekey();
    TestX25519RejectsAllZeroPeer();
    TestOldEpochApplicationRejectedAfterCommit();
    TestRekeyPreparationOverlapsWithoutCrossingLimits();
    TestBoundedMultiEpochWindowRaisesUsableBudget();
    TestOffersArePacedByApplicationProgress();
    TestInboundWindowOverflowRejected();
    TestNonContiguousOfferRejected();
    TestAckDeadlineClampedInBothDirections();
    TestGrantedAckDeadlineIsFrozenAtOfferTime();
    TestRttAdaptationNeverWidensEpochLimits();
    TestDelayedPathWindowIsReachable();
    return 0;
}
