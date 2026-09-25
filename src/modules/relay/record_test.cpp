/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "modules/relay/record.hpp"

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

using yume::relay::record::Bytes;

// Transport-v2 frame types and flags a relay record must refuse.
constexpr std::uint8_t kV2Auth = 1;
constexpr std::uint8_t kV2Open = 2;
constexpr std::uint8_t kV2Close = 4;
constexpr std::uint8_t kV2Control = 11;
constexpr std::uint16_t kV2FlagOpenOk = 0x0001;
constexpr std::uint16_t kV2FlagPadded = 0x4000;

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

yume::relay::Frame Sealed(std::uint8_t type = yume::relay::kFrameData,
                             std::size_t payload_size = 32U) {
    Bytes payload(payload_size, 0x5a);
    return {{static_cast<std::uint32_t>(payload.size()), type, 0,
             yume::relay::kFlagInnerEncrypted},
            std::move(payload)};
}

void TestCanonicalEncodingAndAllowedTypes() {
    using namespace yume::relay;
    using namespace yume::relay::record;

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
    assert(encoded[16] == kFrameData && encoded[17] == 0);
    assert(encoded[18] == 0x80 && encoded[19] == 0x00);

    const auto decoded = DecodeSealedFrame(encoded);
    assert(decoded.header.len == frame.header.len);
    assert(decoded.header.type == frame.header.type);
    assert(decoded.header.stream_id == 0);
    assert(decoded.header.flags == kFlagInnerEncrypted);
    assert(decoded.payload == frame.payload);

    for (const std::uint8_t type :
         {static_cast<std::uint8_t>(kFrameData),
          static_cast<std::uint8_t>(kFrameRekeyInit),
          static_cast<std::uint8_t>(kFrameRekeyAck)}) {
        assert(IsAllowedFrameType(type));
        assert(DecodeSealedFrame(EncodeSealedFrame(Sealed(type))).header.type ==
               type);
    }
    assert(!IsAllowedFrameType(kV2Open));
}

void TestStrictHeaderAndLengthRejection() {
    using namespace yume::relay::record;

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
    using namespace yume::relay;
    using namespace yume::relay::record;

    for (const std::uint8_t type :
         {static_cast<std::uint8_t>(kV2Auth),
          static_cast<std::uint8_t>(kV2Open),
          static_cast<std::uint8_t>(kV2Close),
          static_cast<std::uint8_t>(kV2Control),
          static_cast<std::uint8_t>(0xff)}) {
        assert(Throws([&] { (void)EncodeSealedFrame(Sealed(type)); }));
    }

    auto bad = Sealed();
    bad.header.stream_id = 1;
    assert(Throws([&] { (void)EncodeSealedFrame(bad); }));
    for (const std::uint16_t flags :
         {static_cast<std::uint16_t>(0), kV2FlagPadded,
          static_cast<std::uint16_t>(kFlagInnerEncrypted |
                                     kV2FlagPadded),
          kV2FlagOpenOk,
          static_cast<std::uint16_t>(kFlagInnerEncrypted | 0x20)}) {
        bad = Sealed();
        bad.header.flags = flags;
        assert(Throws([&] { (void)EncodeSealedFrame(bad); }));
    }
    bad = Sealed();
    --bad.header.len;
    assert(Throws([&] { (void)EncodeSealedFrame(bad); }));
    assert(Throws([&] { (void)EncodeSealedFrame(Sealed(kFrameData, 31)); }));

    const auto maximum = Sealed(kFrameData, kMaxSealedPayloadBytes);
    const Bytes encoded = EncodeSealedFrame(maximum);
    assert(encoded.size() == kMaxEncodedRecordBytes);
    assert(DecodeSealedFrame(encoded).payload.size() ==
           kMaxSealedPayloadBytes);
    assert(Throws([&] {
        (void)EncodeSealedFrame(
            Sealed(kFrameData, kMaxSealedPayloadBytes + 1U));
    }));
    Bytes oversized(kMaxEncodedRecordBytes + 1U, 0);
    assert(Throws([&] { (void)DecodeSealedFrame(oversized); }));

    Bytes changed = EncodeSealedFrame(Sealed());
    changed[16] = kV2Open;
    assert(Throws([&] { (void)DecodeSealedFrame(changed); }));
    changed = EncodeSealedFrame(Sealed());
    changed[17] = 1;
    assert(Throws([&] { (void)DecodeSealedFrame(changed); }));
    changed = EncodeSealedFrame(Sealed());
    changed[19] = 1;
    assert(Throws([&] { (void)DecodeSealedFrame(changed); }));
}

std::string Hex(const Bytes& value) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    for (const auto byte : value) {
        out += kDigits[byte >> 4U];
        out += kDigits[byte & 15U];
    }
    return out;
}

// Whole records sealed by the transport-v2 relay code for the same roots.
// They pin the header, envelope, labels and associated data together.
void TestKnownRecords() {
    using namespace yume::relay;
    using namespace yume::relay::record;
    const auto now = std::chrono::steady_clock::time_point{};
    ratchet::SessionRatchet client(ratchet::EndpointRole::Client,
                                   ratchet::Bytes(32, 0x31), ratchet::Bytes(32, 0x42));
    ratchet::SessionRatchet server(ratchet::EndpointRole::Server,
                                   ratchet::Bytes(32, 0x31), ratchet::Bytes(32, 0x42));
    const Bytes hi = SealApplication(client, Bytes{'h', 'i'}, now);
    assert(Hex(hi) ==
           "59525232010000020000003600000022030080000000000000000000000000000000000022"
           "dd285b2d3c6347e437034810086b579efa");
    const Bytes ok = SealApplication(server, Bytes{'o', 'k'}, now);
    assert(Hex(ok) ==
           "595252320100000200000036000000220300800000000000000000000000000000000000c6"
           "3df63a6f2dbd3af0131e3c53edabb8d8bf");
    assert(OpenRecord(server, hi, now).application_frame->payload == Bytes({'h', 'i'}));
    assert(OpenRecord(client, ok, now).application_frame->payload == Bytes({'o', 'k'}));
}

void TestRatchetRoundTripAndRekey() {
    using namespace std::chrono_literals;
    using namespace yume::relay;
    using namespace yume::relay::record;

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

    const Frame init = initiator.BeginOutboundRekey(now + 1ms);
    assert(init.header.type == kFrameRekeyInit);
    const Bytes encoded_init = EncodeSealedFrame(init);
    auto offer = OpenRecord(responder, encoded_init, now + 2ms);
    assert(!offer.application_frame.has_value());
    assert(offer.control_response.has_value());
    assert(offer.control_response->header.type == kFrameRekeyAck);
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
    tampered[16] = kFrameRekeyAck;
    assert(Throws([&] { (void)OpenRecord(tamper_receiver, tampered, now); }));

    ratchet::SessionRatchet body_sender(
        ratchet::EndpointRole::Client, root, psk);
    ratchet::SessionRatchet body_receiver(
        ratchet::EndpointRole::Server, root, psk);
    tampered = SealApplication(body_sender, Bytes{'x'}, now);
    tampered.back() ^= 0x01;
    assert(Throws([&] { (void)OpenRecord(body_receiver, tampered, now); }));
}

}  // namespace

int main() {
    TestCanonicalEncodingAndAllowedTypes();
    TestStrictHeaderAndLengthRejection();
    TestStrictFrameShapeAndBoundaries();
    TestKnownRecords();
    TestRatchetRoundTripAndRekey();
    return 0;
}
