/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "modules/relay/rekey_record.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace {

using yume::relay::ratchet::RecordBytes;
using yume::relay::ratchet::RecordField;
using yume::relay::ratchet::RekeyRecordKind;

template <typename Fn>
bool Throws(Fn&& fn) {
    try {
        fn();
        return false;
    } catch (const std::runtime_error&) {
        return true;
    }
}

const RecordBytes kKem(1568, 0x21);
const RecordBytes kX25519(32, 0x33);

// The record layout the relay v2 ratchet defined, byte by byte.
void TestExactLayout() {
    using namespace yume::relay::ratchet;
    const RecordBytes init = BuildRekeyInit(0x0102030405060708ULL, kKem, kX25519);
    const RecordBytes header{3, 4, 0, 3};
    assert(RecordBytes(init.begin(), init.begin() + 4) == header);
    // Field 1: critical, id 1, length 8, the epoch.
    const RecordBytes epoch_field{1, 1, 0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8};
    assert(RecordBytes(init.begin() + 4, init.begin() + 18) == epoch_field);
    // Field 2: critical, id 2, length 1568 (0x620).
    const RecordBytes kem_header{1, 2, 0, 0, 0x06, 0x20};
    assert(RecordBytes(init.begin() + 18, init.begin() + 24) == kem_header);
    const std::size_t x_offset = 24 + kKem.size();
    const RecordBytes x_header{1, 3, 0, 0, 0, 32};
    assert(RecordBytes(init.begin() + static_cast<std::ptrdiff_t>(x_offset),
                       init.begin() + static_cast<std::ptrdiff_t>(x_offset + 6)) == x_header);
    assert(init.size() == x_offset + 6 + kX25519.size());

    const RecordBytes ack = BuildRekeyAck(1, kKem, kX25519);
    assert(ack.size() == init.size() && ack[0] == 3 && ack[1] == 5);
}

void TestRoundTripAndWidths() {
    using namespace yume::relay::ratchet;
    const auto init = ParseRekeyInit(BuildRekeyInit(1, kKem, kX25519));
    assert(init.next_epoch == 1 && init.mlkem_public_key == kKem &&
           init.x25519_public_key == kX25519);
    const auto ack = ParseRekeyAck(BuildRekeyAck(9, kKem, kX25519));
    assert(ack.next_epoch == 9 && ack.mlkem_ciphertext == kKem &&
           ack.x25519_public_key == kX25519);

    assert(Throws([&] { (void)BuildRekeyInit(0, kKem, kX25519); }));
    assert(Throws([&] { (void)BuildRekeyAck(0, kKem, kX25519); }));
    assert(Throws([&] { (void)BuildRekeyInit(1, kKem, RecordBytes(31, 1)); }));

    // Each peer-facing parser refuses the wrong ML-KEM width, not only the
    // local builder.
    for (const std::size_t size : {1024U, 1567U, 1569U, 4096U}) {
        const RecordBytes wrong_kem(size, 0x22);
        assert(Throws([&] { (void)BuildRekeyInit(1, wrong_kem, kX25519); }));
        assert(Throws([&] { (void)BuildRekeyAck(1, wrong_kem, kX25519); }));
        auto bad_init = DecodeRekeyRecord(BuildRekeyInit(1, kKem, kX25519),
                                          RekeyRecordKind::Init, {1, 2, 3});
        bad_init.fields[1].value = wrong_kem;
        assert(Throws([&] {
            (void)ParseRekeyInit(EncodeRekeyRecord(RekeyRecordKind::Init, bad_init.fields));
        }));
        auto bad_ack = DecodeRekeyRecord(BuildRekeyAck(1, kKem, kX25519),
                                         RekeyRecordKind::Ack, {1, 2, 3});
        bad_ack.fields[1].value = wrong_kem;
        assert(Throws([&] {
            (void)ParseRekeyAck(EncodeRekeyRecord(RekeyRecordKind::Ack, bad_ack.fields));
        }));
    }

    // An INIT is not an ACK.
    assert(Throws([&] { (void)ParseRekeyAck(BuildRekeyInit(1, kKem, kX25519)); }));
    // A zero epoch from a peer is refused.
    auto zero = DecodeRekeyRecord(BuildRekeyInit(1, kKem, kX25519),
                                  RekeyRecordKind::Init, {1, 2, 3});
    zero.fields[0].value = RecordBytes(8, 0);
    assert(Throws([&] {
        (void)ParseRekeyInit(EncodeRekeyRecord(RekeyRecordKind::Init, zero.fields));
    }));
}

void TestCanonicalFields() {
    using namespace yume::relay::ratchet;
    const RecordBytes init = BuildRekeyInit(1, kKem, kX25519);
    RecordBytes trailing = init;
    trailing.push_back(0);
    assert(Throws([&] { (void)ParseRekeyInit(trailing); }));
    RecordBytes truncated(init.begin(), init.end() - 1);
    assert(Throws([&] { (void)ParseRekeyInit(truncated); }));
    RecordBytes schema = init;
    schema[0] = 2;
    assert(Throws([&] { (void)ParseRekeyInit(schema); }));
    RecordBytes flags = init;
    flags[4] = 0x03;
    assert(Throws([&] { (void)ParseRekeyInit(flags); }));

    assert(Throws([&] {
        (void)EncodeRekeyRecord(RekeyRecordKind::Init,
                                {{1, true, RecordBytes{'a'}}, {1, true, RecordBytes{'b'}}});
    }));
    std::vector<RecordField> too_many_fields;
    for (std::uint16_t id = 1; id <= 65; ++id) {
        too_many_fields.push_back(RecordField{static_cast<std::uint8_t>(id), false, {}});
    }
    assert(Throws([&] { (void)EncodeRekeyRecord(RekeyRecordKind::Init, too_many_fields); }));
    assert(Throws([&] {
        (void)EncodeRekeyRecord(RekeyRecordKind::Init,
                                {{1, true, RecordBytes(yume::relay::ratchet::kMaxRekeyRecordBytes, 0)}});
    }));

    // An unknown field is refused when critical and kept otherwise.
    const RecordBytes unknown_critical = EncodeRekeyRecord(RekeyRecordKind::Init, {
        {1, true, RecordBytes{0, 0, 0, 0, 0, 0, 0, 1}}, {2, true, kKem},
        {3, true, kX25519}, {4, true, RecordBytes{0}},
    });
    assert(Throws([&] { (void)ParseRekeyInit(unknown_critical); }));
    const RecordBytes unknown_optional = EncodeRekeyRecord(RekeyRecordKind::Init, {
        {1, true, RecordBytes{0, 0, 0, 0, 0, 0, 0, 1}}, {2, true, kKem},
        {3, true, kX25519}, {4, false, RecordBytes{0}},
    });
    assert(ParseRekeyInit(unknown_optional).next_epoch == 1);
    // A required field that is not critical does not count.
    const RecordBytes optional_epoch = EncodeRekeyRecord(RekeyRecordKind::Init, {
        {1, false, RecordBytes{0, 0, 0, 0, 0, 0, 0, 1}}, {2, true, kKem},
        {3, true, kX25519},
    });
    assert(Throws([&] { (void)ParseRekeyInit(optional_epoch); }));
}

}  // namespace

int main() {
    TestExactLayout();
    TestRoundTripAndWidths();
    TestCanonicalFields();
    return 0;
}
