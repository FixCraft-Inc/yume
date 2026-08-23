/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/relay/relay_v2_crypto.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace {

namespace relay_v2 = yume::client::relay_v2;
using relay_v2::Bytes;

void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

template <typename Function>
void ExpectFailure(Function&& function, const char* message) {
    bool threw = false;
    try {
        std::forward<Function>(function)();
    } catch (const std::exception&) {
        threw = true;
    }
    Check(threw, message);
}

struct FieldLocation {
    std::size_t length_offset{0};
    std::size_t value_offset{0};
    std::size_t length{0};
};

FieldLocation FindField(const Bytes& record, std::uint8_t wanted) {
    Check(record.size() >= 8, "test record header missing");
    const std::size_t count =
        (static_cast<std::size_t>(record[6]) << 8) | record[7];
    std::size_t offset = 8;
    for (std::size_t index = 0; index < count; ++index) {
        Check(offset + 3 <= record.size(), "test field header truncated");
        const std::uint8_t id = record[offset++];
        const std::size_t length_offset = offset;
        const std::size_t length =
            (static_cast<std::size_t>(record[offset]) << 8) |
            record[offset + 1];
        offset += 2;
        Check(length <= record.size() - offset, "test field value truncated");
        if (id == wanted) return {length_offset, offset, length};
        offset += length;
    }
    throw std::runtime_error("test field not found");
}

[[maybe_unused]] Bytes MutateField(const Bytes& record, std::uint8_t id,
                                  std::size_t relative_offset = 0) {
    Bytes mutated = record;
    const FieldLocation field = FindField(mutated, id);
    Check(relative_offset < field.length, "test mutation offset invalid");
    mutated[field.value_offset + relative_offset] ^= 0x01U;
    return mutated;
}

[[maybe_unused]] Bytes CopyField(const Bytes& from, std::uint8_t from_id,
                                Bytes into, std::uint8_t into_id) {
    const FieldLocation source = FindField(from, from_id);
    const FieldLocation destination = FindField(into, into_id);
    Check(source.length == destination.length,
          "test fields have different widths");
    std::copy_n(from.begin() + static_cast<std::ptrdiff_t>(source.value_offset),
                source.length,
                into.begin() +
                    static_cast<std::ptrdiff_t>(destination.value_offset));
    return into;
}

relay_v2::HandshakeContext Context(
    relay_v2::PasswordPolicy policy =
        relay_v2::PasswordPolicy::Required) {
    relay_v2::HandshakeContext context;
    context.channel_kind = yume::control::ChannelKind::file;
    context.initiator_endpoint_id = "00112233445566778899aabbccddeeff";
    context.responder_endpoint_id = "ffeeddccbbaa99887766554433221100";
    for (std::size_t index = 0; index < context.nonce.size(); ++index) {
        context.nonce[index] = static_cast<std::uint8_t>(index + 1U);
        context.metadata_digest[index] =
            static_cast<std::uint8_t>(0xa0U + (index & 0x0fU));
    }
    context.password_policy = policy;
    return context;
}

Bytes Psk(std::uint8_t byte = 0x5a) {
    return Bytes(relay_v2::kRelayPskBytes, byte);
}

[[maybe_unused]] bool Equal(std::span<const std::uint8_t> left,
                           std::span<const std::uint8_t> right) {
    return left.size() == right.size() &&
           std::equal(left.begin(), left.end(), right.begin());
}

#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX

struct Identities {
    yume::crypto::CompositeKeyPair initiator{
        yume::crypto::generate_composite_keypair()};
    yume::crypto::CompositeKeyPair responder{
        yume::crypto::generate_composite_keypair()};
    yume::crypto::CompositeKeyPair other{
        yume::crypto::generate_composite_keypair()};
    Bytes initiator_encoded{relay_v2::EncodeIdentity(initiator)};
    Bytes responder_encoded{relay_v2::EncodeIdentity(responder)};
    Bytes other_encoded{relay_v2::EncodeIdentity(other)};
};

void TestParityAndDomainSeparation(const Identities& identities) {
    auto pending = relay_v2::BeginInitiator(
        Context(), identities.initiator, identities.responder_encoded, Psk());
    Check(relay_v2::InspectInitiatorRequest(pending.encoded) == Context(),
          "strict request context inspection did not preserve fields");
    Check(pending.state.valid(), "initiator state was not live");
    Check(!pending.encoded.empty() &&
              pending.encoded.size() <= relay_v2::kMaxRecordBytes,
          "request record size is invalid");
    auto responder = relay_v2::Respond(
        pending.encoded, Context(), identities.initiator_encoded,
        identities.responder, Psk());
    Check(responder.secrets.valid(), "responder secrets were not live");
    Check(!responder.encoded.empty() &&
              responder.encoded.size() <= relay_v2::kMaxRecordBytes,
          "response record size is invalid");
    auto initiator = relay_v2::CompleteInitiator(
        std::move(pending.state), responder.encoded);
    Check(initiator.valid(), "initiator secrets were not live");
    Check(initiator.initial_root().size() == 32 &&
              initiator.epoch_psk().size() == 32,
          "derived relay-v2 secret width is invalid");
    Check(Equal(initiator.initial_root(),
                responder.secrets.initial_root()),
          "initiator and responder roots differ");
    Check(Equal(initiator.epoch_psk(), responder.secrets.epoch_psk()),
          "initiator and responder epoch PSKs differ");
    Check(!Equal(initiator.initial_root(), initiator.epoch_psk()),
          "root and epoch PSK domains collided");

    relay_v2::SessionSecrets moved = std::move(initiator);
    Check(moved.valid() && !initiator.valid(),
          "SessionSecrets move ownership is invalid");
    auto ratchet = relay_v2::MakeSessionRatchet(
        std::move(moved), yume::ratchet::EndpointRole::Client);
    Check(ratchet != nullptr && !moved.valid(),
          "SessionRatchet did not consume relay-v2 secrets");
}

void TestPasswordPolicyAndPskBinding(const Identities& identities) {
    ExpectFailure(
        [&] {
            (void)relay_v2::BeginInitiator(
                Context(), identities.initiator,
                identities.responder_encoded, {});
        },
        "required policy accepted an empty PSK");
    ExpectFailure(
        [&] {
            (void)relay_v2::BeginInitiator(
                Context(relay_v2::PasswordPolicy::NotRequired),
                identities.initiator, identities.responder_encoded, Psk());
        },
        "not-required policy accepted a PSK");

    const auto no_psk_context =
        Context(relay_v2::PasswordPolicy::NotRequired);
    auto no_psk_pending = relay_v2::BeginInitiator(
        no_psk_context, identities.initiator, identities.responder_encoded,
        {});
    auto no_psk_responder = relay_v2::Respond(
        no_psk_pending.encoded, no_psk_context,
        identities.initiator_encoded, identities.responder, {});
    auto no_psk_initiator = relay_v2::CompleteInitiator(
        std::move(no_psk_pending.state), no_psk_responder.encoded);
    Check(Equal(no_psk_initiator.initial_root(),
                no_psk_responder.secrets.initial_root()),
          "no-PSK handshake roots differ");

    auto mismatched_pending = relay_v2::BeginInitiator(
        Context(), identities.initiator, identities.responder_encoded,
        Psk(0x11));
    auto mismatched_responder = relay_v2::Respond(
        mismatched_pending.encoded, Context(), identities.initiator_encoded,
        identities.responder, Psk(0x22));
    auto mismatched_initiator = relay_v2::CompleteInitiator(
        std::move(mismatched_pending.state), mismatched_responder.encoded);
    Check(!Equal(mismatched_initiator.initial_root(),
                 mismatched_responder.secrets.initial_root()) &&
              !Equal(mismatched_initiator.epoch_psk(),
                     mismatched_responder.secrets.epoch_psk()),
          "different relay PSKs did not separate session secrets");
}

void TestRequestTamperAndIdentitySwap(const Identities& identities) {
    auto pending = relay_v2::BeginInitiator(
        Context(), identities.initiator, identities.responder_encoded, Psk());

    for (std::uint8_t id = 1; id <= 11; ++id) {
        const Bytes mutated = MutateField(pending.encoded, id);
        ExpectFailure(
            [&] {
                (void)relay_v2::Respond(
                    mutated, Context(), identities.initiator_encoded,
                    identities.responder, Psk());
            },
            "mutated request field was accepted");
    }

    const Bytes ed_tamper = MutateField(pending.encoded, 12, 0);
    const Bytes pq_tamper = MutateField(
        pending.encoded, 12, yume::crypto::kEd25519SignatureLen);
    for (const Bytes* tampered : {&ed_tamper, &pq_tamper}) {
        ExpectFailure(
            [&] {
                (void)relay_v2::Respond(
                    *tampered, Context(), identities.initiator_encoded,
                    identities.responder, Psk());
            },
            "single-half request signature forgery was accepted");
    }

    ExpectFailure(
        [&] {
            (void)relay_v2::Respond(
                pending.encoded, Context(), identities.other_encoded,
                identities.responder, Psk());
        },
        "initiator identity swap was accepted");
    ExpectFailure(
        [&] {
            (void)relay_v2::Respond(
                pending.encoded, Context(), identities.initiator_encoded,
                identities.other, Psk());
        },
        "responder identity swap was accepted");

    Bytes trailing = pending.encoded;
    trailing.push_back(0);
    ExpectFailure(
        [&] {
            (void)relay_v2::Respond(
                trailing, Context(), identities.initiator_encoded,
                identities.responder, Psk());
        },
        "request trailing bytes were accepted");

    Bytes bad_length = pending.encoded;
    const FieldLocation nonce = FindField(bad_length, 5);
    bad_length[nonce.length_offset] = 0xff;
    bad_length[nonce.length_offset + 1] = 0xff;
    ExpectFailure(
        [&] {
            (void)relay_v2::Respond(
                bad_length, Context(), identities.initiator_encoded,
                identities.responder, Psk());
        },
        "oversized request field length was accepted");

    Bytes near_cap = pending.encoded;
    const FieldLocation signature = FindField(near_cap, 12);
    const std::size_t padding = relay_v2::kMaxRecordBytes - near_cap.size();
    const std::size_t widened_length = signature.length + padding;
    Check(widened_length <= 0xffffU,
          "near-cap test field no longer fits the wire length");
    near_cap[signature.length_offset] =
        static_cast<std::uint8_t>(widened_length >> 8);
    near_cap[signature.length_offset + 1] =
        static_cast<std::uint8_t>(widened_length);
    near_cap.insert(near_cap.end(), padding, 0);
    Check(near_cap.size() == relay_v2::kMaxRecordBytes,
          "near-cap test record size is wrong");
    ExpectFailure(
        [&] {
            (void)relay_v2::Respond(
                near_cap, Context(), identities.initiator_encoded,
                identities.responder, Psk());
        },
        "near-cap invalid request was accepted");
    near_cap.push_back(0);
    ExpectFailure(
        [&] {
            (void)relay_v2::Respond(
                near_cap, Context(), identities.initiator_encoded,
                identities.responder, Psk());
        },
        "record above the 32-KiB cap was accepted");
}

void TestResponseFieldMutations(const Identities& identities) {
    for (std::uint8_t id = 1; id <= 15; ++id) {
        auto pending = relay_v2::BeginInitiator(
            Context(), identities.initiator, identities.responder_encoded,
            Psk());
        auto responder = relay_v2::Respond(
            pending.encoded, Context(), identities.initiator_encoded,
            identities.responder, Psk());
        const Bytes mutated = MutateField(responder.encoded, id);
        ExpectFailure(
            [&] {
                (void)relay_v2::CompleteInitiator(
                    std::move(pending.state), mutated);
            },
            "mutated response field was accepted");
    }

    auto pq_pending = relay_v2::BeginInitiator(
        Context(), identities.initiator, identities.responder_encoded, Psk());
    auto pq_responder = relay_v2::Respond(
        pq_pending.encoded, Context(), identities.initiator_encoded,
        identities.responder, Psk());
    const Bytes pq_tamper = MutateField(
        pq_responder.encoded, 15, yume::crypto::kEd25519SignatureLen);
    ExpectFailure(
        [&] {
            (void)relay_v2::CompleteInitiator(
                std::move(pq_pending.state), pq_tamper);
        },
        "single-half response signature forgery was accepted");
}

void TestSignatureDomainSeparation(const Identities& identities) {
    // Use the same composite key in both roles so key mismatch cannot be the
    // reason substitution fails; only the request/response domains differ.
    auto pending = relay_v2::BeginInitiator(
        Context(), identities.other, identities.other_encoded, Psk());
    auto responder = relay_v2::Respond(
        pending.encoded, Context(), identities.other_encoded,
        identities.other, Psk());
    const Bytes substituted = CopyField(
        pending.encoded, 12, responder.encoded, 15);
    ExpectFailure(
        [&] {
            (void)relay_v2::CompleteInitiator(
                std::move(pending.state), substituted);
        },
        "request signature was accepted in the response domain");
}

void TestStrictInputBounds(const Identities& identities) {
    Check(relay_v2::CanonicalizeIdentity(identities.responder_encoded) ==
              identities.responder_encoded,
          "canonical identity did not round-trip exactly");
    auto bad = Context();
    bad.initiator_endpoint_id.clear();
    ExpectFailure(
        [&] {
            (void)relay_v2::BeginInitiator(
                bad, identities.initiator, identities.responder_encoded,
                Psk());
        },
        "empty endpoint id was accepted");

    bad = Context();
    bad.initiator_endpoint_id.assign(
        relay_v2::kMaxEndpointIdBytes + 1U, 'a');
    ExpectFailure(
        [&] {
            (void)relay_v2::BeginInitiator(
                bad, identities.initiator, identities.responder_encoded,
                Psk());
        },
        "oversized endpoint id was accepted");

    bad = Context();
    bad.initiator_endpoint_id[0] = '/';
    ExpectFailure(
        [&] {
            (void)relay_v2::BeginInitiator(
                bad, identities.initiator, identities.responder_encoded,
                Psk());
        },
        "noncanonical endpoint id was accepted");

    bad = Context();
    bad.nonce.fill(0);
    ExpectFailure(
        [&] {
            (void)relay_v2::BeginInitiator(
                bad, identities.initiator, identities.responder_encoded,
                Psk());
        },
        "all-zero nonce was accepted");

    Bytes noncanonical_identity = identities.responder_encoded;
    noncanonical_identity.push_back('\n');
    ExpectFailure(
        [&] {
            (void)relay_v2::BeginInitiator(
                Context(), identities.initiator, noncanonical_identity,
                Psk());
        },
        "noncanonical identity spelling was accepted");
}

#endif

}  // namespace

int main() {
    static_assert(!std::is_copy_constructible_v<relay_v2::InitiatorState>);
    static_assert(!std::is_copy_assignable_v<relay_v2::InitiatorState>);
    static_assert(std::is_nothrow_move_constructible_v<
                  relay_v2::InitiatorState>);
    static_assert(!std::is_copy_constructible_v<relay_v2::SessionSecrets>);
    static_assert(std::is_nothrow_move_constructible_v<
                  relay_v2::SessionSecrets>);

#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
    const Identities identities;
    TestParityAndDomainSeparation(identities);
    TestPasswordPolicyAndPskBinding(identities);
    TestRequestTamperAndIdentitySwap(identities);
    TestResponseFieldMutations(identities);
    TestSignatureDomainSeparation(identities);
    TestStrictInputBounds(identities);
#else
    yume::crypto::CompositeKeyPair unavailable_identity;
    ExpectFailure(
        [&] {
            (void)relay_v2::BeginInitiator(
                Context(), unavailable_identity, {}, Psk());
        },
        "relay-v2 hybrid crypto did not fail closed without BaseFWX");
#endif

    std::cout << "relay_v2_crypto_test ok\n";
    return 0;
}
