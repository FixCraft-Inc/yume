/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/relay/relay_v2_record.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace {

using yume::client::relay_v2::record::Bytes;

bool Throws(const std::function<void()>& fn) {
    try {
        fn();
        return false;
    } catch (const std::exception&) {
        return true;
    }
}

void PutU32(Bytes& bytes, std::size_t offset, std::uint32_t value) {
    assert(offset <= bytes.size() && bytes.size() - offset >= 4U);
    bytes[offset] = static_cast<std::uint8_t>(value >> 24U);
    bytes[offset + 1U] = static_cast<std::uint8_t>(value >> 16U);
    bytes[offset + 2U] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 3U] = static_cast<std::uint8_t>(value);
}

yume::protocol::Frame Sealed(std::uint8_t type = yume::protocol::DATA,
                             std::size_t payload_size = 32U) {
    Bytes payload(payload_size, 0x5a);
    return {{static_cast<std::uint32_t>(payload.size()), type, 0,
             yume::protocol::kFlagInnerEncrypted},
            std::move(payload)};
}

void TestCanonicalEncodingAndAllowedTypes() {
    using namespace yume;
    using namespace client::relay_v2::record;

    const auto frame = Sealed();
    const Bytes encoded = EncodeSealedFrame(frame);
    assert(encoded.size() == kWireHeaderBytes + frame.payload.size());
    assert(std::equal(kMagic.begin(), kMagic.end(), encoded.begin()));
    assert(encoded[4] == kSchemaVersion);
    assert(encoded[5] == 0);
    assert(encoded[6] == 0 && encoded[7] == kWireProtocolVersion);
    assert(encoded[8] == 0 && encoded[9] == 0 && encoded[10] == 0 &&
           encoded[11] == encoded.size());
    assert(encoded[12] == 0 && encoded[13] == 0 && encoded[14] == 0 &&
           encoded[15] == frame.payload.size());
    assert(encoded[16] == protocol::DATA && encoded[17] == 0);
    assert(encoded[18] == 0x80 && encoded[19] == 0x00);

    const auto decoded = DecodeSealedFrame(encoded);
    assert(decoded.header.len == frame.header.len);
    assert(decoded.header.type == frame.header.type);
    assert(decoded.header.stream_id == 0);
    assert(decoded.header.flags == protocol::kFlagInnerEncrypted);
    assert(decoded.payload == frame.payload);

    for (const std::uint8_t type :
         {static_cast<std::uint8_t>(protocol::DATA),
          static_cast<std::uint8_t>(protocol::REKEY_INIT),
          static_cast<std::uint8_t>(protocol::REKEY_ACK)}) {
        assert(IsAllowedFrameType(type));
        assert(DecodeSealedFrame(EncodeSealedFrame(Sealed(type))).header.type ==
               type);
    }
    assert(!IsAllowedFrameType(protocol::OPEN));
}

void TestStrictHeaderAndLengthRejection() {
    using namespace yume::client::relay_v2::record;

    const Bytes canonical = EncodeSealedFrame(Sealed());
    for (std::size_t size = 0; size < kWireHeaderBytes; ++size) {
        const Bytes truncated(canonical.begin(), canonical.begin() +
                                                   static_cast<std::ptrdiff_t>(size));
        assert(Throws([&] { (void)DecodeSealedFrame(truncated); }));
    }

    Bytes changed = canonical;
    changed[0] ^= 0x01;
    assert(Throws([&] { (void)DecodeSealedFrame(changed); }));
    changed = canonical;
    changed[4] = static_cast<std::uint8_t>(kSchemaVersion + 1U);
    assert(Throws([&] { (void)DecodeSealedFrame(changed); }));
    changed = canonical;
    changed[5] = 1;
    assert(Throws([&] { (void)DecodeSealedFrame(changed); }));
    changed = canonical;
    changed[7] = static_cast<std::uint8_t>(kWireProtocolVersion + 1U);
    assert(Throws([&] { (void)DecodeSealedFrame(changed); }));

    changed = canonical;
    changed.pop_back();
    assert(Throws([&] { (void)DecodeSealedFrame(changed); }));
    changed = canonical;
    changed.push_back(0);
    assert(Throws([&] { (void)DecodeSealedFrame(changed); }));
    changed = canonical;
    PutU32(changed, 8, std::numeric_limits<std::uint32_t>::max());
    assert(Throws([&] { (void)DecodeSealedFrame(changed); }));
    changed = canonical;
    PutU32(changed, 8, static_cast<std::uint32_t>(kWireHeaderBytes - 1U));
    assert(Throws([&] { (void)DecodeSealedFrame(changed); }));
    changed = canonical;
    PutU32(changed, 12, std::numeric_limits<std::uint32_t>::max());
    assert(Throws([&] { (void)DecodeSealedFrame(changed); }));
    changed = canonical;
    PutU32(changed, 12, 31);
    assert(Throws([&] { (void)DecodeSealedFrame(changed); }));
}

void TestStrictFrameShapeAndBoundaries() {
    using namespace yume;
    using namespace client::relay_v2::record;

    for (const std::uint8_t type :
         {static_cast<std::uint8_t>(protocol::AUTH),
          static_cast<std::uint8_t>(protocol::OPEN),
          static_cast<std::uint8_t>(protocol::CLOSE),
          static_cast<std::uint8_t>(protocol::CONTROL),
          static_cast<std::uint8_t>(0xff)}) {
        assert(Throws([&] { (void)EncodeSealedFrame(Sealed(type)); }));
    }

    auto bad = Sealed();
    bad.header.stream_id = 1;
    assert(Throws([&] { (void)EncodeSealedFrame(bad); }));
    for (const std::uint16_t flags :
         {static_cast<std::uint16_t>(0), protocol::kFlagPadded,
          static_cast<std::uint16_t>(protocol::kFlagInnerEncrypted |
                                     protocol::kFlagPadded),
          protocol::kFlagOpenOk,
          static_cast<std::uint16_t>(protocol::kFlagInnerEncrypted | 0x20)}) {
        bad = Sealed();
        bad.header.flags = flags;
        assert(Throws([&] { (void)EncodeSealedFrame(bad); }));
    }
    bad = Sealed();
    --bad.header.len;
    assert(Throws([&] { (void)EncodeSealedFrame(bad); }));
    assert(Throws([&] { (void)EncodeSealedFrame(Sealed(protocol::DATA, 31)); }));

    const auto maximum = Sealed(protocol::DATA, kMaxSealedPayloadBytes);
    const Bytes encoded = EncodeSealedFrame(maximum);
    assert(encoded.size() == kMaxEncodedRecordBytes);
    assert(DecodeSealedFrame(encoded).payload.size() ==
           kMaxSealedPayloadBytes);
    assert(Throws([&] {
        (void)EncodeSealedFrame(
            Sealed(protocol::DATA, kMaxSealedPayloadBytes + 1U));
    }));
    Bytes oversized(kMaxEncodedRecordBytes + 1U, 0);
    assert(Throws([&] { (void)DecodeSealedFrame(oversized); }));

    Bytes changed = EncodeSealedFrame(Sealed());
    changed[16] = protocol::OPEN;
    assert(Throws([&] { (void)DecodeSealedFrame(changed); }));
    changed = EncodeSealedFrame(Sealed());
    changed[17] = 1;
    assert(Throws([&] { (void)DecodeSealedFrame(changed); }));
    changed = EncodeSealedFrame(Sealed());
    changed[19] = 1;
    assert(Throws([&] { (void)DecodeSealedFrame(changed); }));
}

void TestRatchetRoundTripAndRekey() {
#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
    using namespace std::chrono_literals;
    using namespace yume;
    using namespace client::relay_v2::record;

    const ratchet::Bytes root(32, 0x31);
    const ratchet::Bytes psk(32, 0x42);
    ratchet::SessionRatchet initiator(
        ratchet::EndpointRole::Client, root, psk);
    ratchet::SessionRatchet responder(
        ratchet::EndpointRole::Server, root, psk);
    const auto now = std::chrono::steady_clock::time_point{} + 1s;

    const std::string transfer_json =
        std::string("{\"data_b64\":\"") +
        std::string(kTransferChunkBase64Bytes, 'A') +
        "\",\"type\":\"file_chunk\"}";
    assert(transfer_json.size() <= kMaxPlaintextPayloadBytes);
    Bytes transfer_payload(transfer_json.begin(), transfer_json.end());
    const Bytes first = SealApplication(
        initiator, transfer_payload, now);
    auto opened = OpenRecord(responder, first, now);
    assert(opened.application_frame.has_value());
    assert(opened.application_frame->payload == transfer_payload);
    assert(!opened.control_response.has_value());

    const protocol::Frame init = initiator.BeginOutboundRekey(now + 1ms);
    assert(init.header.type == protocol::REKEY_INIT);
    const Bytes encoded_init = EncodeSealedFrame(init);
    auto offer = OpenRecord(responder, encoded_init, now + 2ms);
    assert(!offer.application_frame.has_value());
    assert(offer.control_response.has_value());
    assert(offer.control_response->header.type == protocol::REKEY_ACK);
    assert(offer.control_response->header.len ==
           offer.control_response->payload.size());
    assert(initiator.outbound_rekey_pending());
    assert(responder.prepared_inbound_epochs() == 1);

    const Bytes encoded_ack = SealControlResponse(
        responder, std::move(*offer.control_response), now + 3ms);
    auto ack = OpenRecord(initiator, encoded_ack, now + 4ms);
    assert(ack.outbound_rekey_completed);
    assert(!ack.application_frame.has_value());
    assert(!ack.control_response.has_value());
    assert(!initiator.outbound_rekey_pending());
    assert(initiator.prepared_outbound_epochs() == 1);

    // The first application frame after the Extreme profile's active-time
    // boundary commits the prepared epoch on both sides.
    const Bytes after_rekey = SealApplication(
        initiator, Bytes{'n', 'e', 'w'}, now + 501ms);
    assert(initiator.outbound_epoch() == 1);
    auto opened_after_rekey = OpenRecord(
        responder, after_rekey, now + 501ms);
    assert(opened_after_rekey.application_frame.has_value());
    assert((opened_after_rekey.application_frame->payload ==
            Bytes{'n', 'e', 'w'}));
    assert(responder.inbound_epoch() == 1);

    assert(Throws([&] {
        (void)SealApplication(
            initiator, Bytes(kMaxPlaintextPayloadBytes + 1U, 0), now);
    }));

    // The record header is ratchet AAD. A permitted-but-tampered type reaches
    // AEAD verification and fails rather than being reinterpreted.
    ratchet::SessionRatchet tamper_sender(
        ratchet::EndpointRole::Client, root, psk);
    ratchet::SessionRatchet tamper_receiver(
        ratchet::EndpointRole::Server, root, psk);
    Bytes tampered = SealApplication(tamper_sender, Bytes{'x'}, now);
    tampered[16] = protocol::REKEY_ACK;
    assert(Throws([&] { (void)OpenRecord(tamper_receiver, tampered, now); }));

    ratchet::SessionRatchet body_sender(
        ratchet::EndpointRole::Client, root, psk);
    ratchet::SessionRatchet body_receiver(
        ratchet::EndpointRole::Server, root, psk);
    tampered = SealApplication(body_sender, Bytes{'x'}, now);
    tampered.back() ^= 0x01;
    assert(Throws([&] { (void)OpenRecord(body_receiver, tampered, now); }));
#endif
}

}  // namespace

int main() {
    TestCanonicalEncodingAndAllowedTypes();
    TestStrictHeaderAndLengthRejection();
    TestStrictFrameShapeAndBoundaries();
    TestRatchetRoundTripAndRekey();
    return 0;
}
