/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "ytp/protocol.hpp"
#include "ytp/security.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace {

using namespace yume::ytp1;

// The encoder takes fields described by the input: one byte of ID, a flags
// byte whose low bit is the critical flag, a length byte and that many value
// bytes. Whatever it accepts must decode back to the same record with its
// fields in ID order.
void check_encoder(std::span<const std::uint8_t> input) {
    if (input.size() < 2U) return;
    AuthRecord record;
    record.type = static_cast<AuthMessageType>(input[0] % 7U);
    record.sender_role = static_cast<EndpointRole>(input[1] % 4U);
    std::size_t offset = 2U;
    while (offset + 3U <= input.size() && record.fields.size() < kMaxAuthFields) {
        AuthField field;
        field.id = input[offset];
        field.critical = (input[offset + 1U] & 1U) != 0U;
        const std::size_t length =
            std::min<std::size_t>(input[offset + 2U], input.size() - offset - 3U);
        offset += 3U;
        field.value.assign(input.begin() + static_cast<std::ptrdiff_t>(offset),
                           input.begin() + static_cast<std::ptrdiff_t>(offset + length));
        offset += length;
        record.fields.push_back(std::move(field));
    }
    const auto encoded = EncodeAuthRecord(record);
    if (!encoded) return;
    const auto decoded = DecodeAuthRecord(*encoded.value);
    std::stable_sort(record.fields.begin(), record.fields.end(),
                     [](const AuthField& lhs, const AuthField& rhs) {
                         return lhs.id < rhs.id;
                     });
    if (!decoded || !(*decoded.value == record)) __builtin_trap();
}

// The key-schedule encoder takes local values, never peer bytes, but its
// size, validation and output must agree. Each field takes its required
// length or one octet more or less, as one input byte selects, so both valid
// and refused inputs are common. Values repeat the input.
void check_key_schedule(std::span<const std::uint8_t> input) {
    if (input.size() < 20U) return;
    static std::array<std::uint8_t, kMlKem1024CiphertextSize + 1U> pool{};
    for (std::size_t index = 0U; index < pool.size(); ++index) {
        pool[index] = input[index % input.size()];
    }
    std::size_t selector = 0U;
    const auto slice = [&](std::size_t required) {
        const std::uint8_t choice = input[2U + selector++ % (input.size() - 2U)];
        std::size_t length = required;
        if (choice % 5U == 3U) length = required + 1U;
        if (choice % 5U == 4U && required > 0U) length = required - 1U;
        return std::span<const std::uint8_t>(pool.data(), std::min(length, pool.size()));
    };
    CapabilityManifest manifest;
    manifest.entries.push_back({"echo", ServiceKind::ByteStream, 8U});
    const auto encoded_manifest = EncodeCapabilityManifest(manifest);
    if (!encoded_manifest) __builtin_trap();
    const std::span<const std::uint8_t> valid_manifest(*encoded_manifest.value);

    KeyScheduleInput schedule;
    schedule.initiator_role = static_cast<EndpointRole>(input[0] % 4U);
    schedule.responder_role = static_cast<EndpointRole>(input[1] % 4U);
    schedule.transcript_hash = slice(kTranscriptHashSize);
    schedule.exporter = slice(kExporterSize);
    schedule.client_identity = slice(64U);
    schedule.server_identity = slice(64U);
    schedule.client_capability_manifest =
        input[3] % 7U == 0U ? slice(8U) : valid_manifest;
    schedule.server_capability_manifest =
        input[4] % 7U == 0U ? slice(8U) : valid_manifest;
    schedule.access_psk = slice(kPskSize);
    schedule.client_x25519_public_key = slice(kX25519PublicKeySize);
    schedule.server_x25519_public_key = slice(kX25519PublicKeySize);
    schedule.x25519_shared_secret = slice(kX25519SharedSecretSize);
    schedule.mlkem_public_key = slice(kMlKem1024PublicKeySize);
    schedule.mlkem_ciphertext = slice(kMlKem1024CiphertextSize);
    schedule.mlkem_shared_secret = slice(kMlKem1024SharedSecretSize);

    const bool valid = static_cast<bool>(ValidateKeyScheduleInput(schedule));
    const auto size = KeyScheduleInputEncodedSize(schedule);
    if (valid != static_cast<bool>(size)) __builtin_trap();
    std::vector<std::uint8_t> output(valid ? *size.value : 64U);
    std::size_t written = 0U;
    const Status status = EncodeKeyScheduleInput(schedule, output, written);
    if (static_cast<bool>(status) != valid) __builtin_trap();
    if (!valid) {
        if (written != 0U) __builtin_trap();
        return;
    }
    if (written != output.size() || output.size() > kMaxKeyScheduleInputSize) {
        __builtin_trap();
    }
    std::vector<std::uint8_t> short_output(output.size() - 1U);
    const Status short_status = EncodeKeyScheduleInput(schedule, short_output, written);
    if (short_status || short_status.code != ErrorCode::OutputTooSmall || written != 0U) {
        __builtin_trap();
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
    if (size > kMaxAuthRecordSize + 1) return 0;
    const std::span<const std::uint8_t> input(data, size);
    if (const auto record = DecodeAuthRecord(input)) {
        // Unknown noncritical fields must survive. Unknown critical fields,
        // duplicate IDs, reordered TLVs and wrong suite values must refuse.
        const auto encoded = EncodeAuthRecord(*record.value);
        if (!encoded || !std::equal(input.begin(), input.end(),
                                    encoded.value->begin(), encoded.value->end())) {
            __builtin_trap();
        }
    }
    check_encoder(input);
    check_key_schedule(input);
    return 0;
}
