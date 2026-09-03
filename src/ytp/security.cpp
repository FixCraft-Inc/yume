/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "ytp/security.hpp"

#include <algorithm>
#include <cstring>
#include <limits>

namespace yume::ytp1 {
namespace {

constexpr std::size_t kAuthPrefixSize = 8;
constexpr std::size_t kAuthFieldPrefixSize = 8;
constexpr std::uint8_t kAuthSchema = 1;
constexpr std::uint16_t kMandatoryAuthFieldCount = 3;
constexpr std::uint16_t kKeyScheduleFieldCount = 18;
constexpr std::size_t kKeySchedulePrefixSize = 4;
constexpr std::size_t kKeyScheduleFieldPrefixSize = 6;

[[nodiscard]] constexpr std::uint16_t ReadU16(
    std::span<const std::uint8_t> input,
    std::size_t offset) noexcept {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(input[offset]) << 8U) |
        static_cast<std::uint16_t>(input[offset + 1]));
}

[[nodiscard]] constexpr std::uint32_t ReadU32(
    std::span<const std::uint8_t> input,
    std::size_t offset) noexcept {
    return (static_cast<std::uint32_t>(input[offset]) << 24U) |
           (static_cast<std::uint32_t>(input[offset + 1]) << 16U) |
           (static_cast<std::uint32_t>(input[offset + 2]) << 8U) |
           static_cast<std::uint32_t>(input[offset + 3]);
}

constexpr void WriteU16(std::span<std::uint8_t> output,
                        std::size_t offset,
                        std::uint16_t value) noexcept {
    output[offset] = static_cast<std::uint8_t>(value >> 8U);
    output[offset + 1] = static_cast<std::uint8_t>(value);
}

constexpr void WriteU32(std::span<std::uint8_t> output,
                        std::size_t offset,
                        std::uint32_t value) noexcept {
    output[offset] = static_cast<std::uint8_t>(value >> 24U);
    output[offset + 1] = static_cast<std::uint8_t>(value >> 16U);
    output[offset + 2] = static_cast<std::uint8_t>(value >> 8U);
    output[offset + 3] = static_cast<std::uint8_t>(value);
}

[[nodiscard]] constexpr bool IsKnownAuthMessageType(
    AuthMessageType type) noexcept {
    switch (type) {
    case AuthMessageType::Challenge:
    case AuthMessageType::Response:
    case AuthMessageType::Accepted:
    case AuthMessageType::RekeyInit:
    case AuthMessageType::RekeyAck:
        return true;
    }
    return false;
}

[[nodiscard]] constexpr bool IsKnownRole(EndpointRole role) noexcept {
    return role == EndpointRole::Client || role == EndpointRole::Server;
}

[[nodiscard]] constexpr bool IsKnownAuthField(std::uint16_t id) noexcept {
    return id >= static_cast<std::uint16_t>(AuthFieldId::SuiteId) &&
           id <= static_cast<std::uint16_t>(AuthFieldId::KeyConfirmation);
}

[[nodiscard]] std::span<const std::uint8_t> BytesOf(
    std::string_view text) noexcept {
    return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}

[[nodiscard]] bool BytesEqual(std::span<const std::uint8_t> lhs,
                              std::span<const std::uint8_t> rhs) noexcept {
    return lhs.size() == rhs.size() &&
           std::equal(lhs.begin(), lhs.end(), rhs.begin());
}

[[nodiscard]] Status ValidateAdditionalAuthField(
    std::uint16_t id,
    bool critical,
    std::span<const std::uint8_t> value,
    std::size_t value_offset) noexcept {
    if (id <= static_cast<std::uint16_t>(AuthFieldId::SenderRole)) {
        return {ErrorCode::InvalidField, value_offset};
    }
    if (!IsKnownAuthField(id)) {
        if (critical) {
            return {ErrorCode::UnknownCriticalField, value_offset};
        }
        return Status::Success();
    }
    if (!critical) {
        return {ErrorCode::InvalidField, value_offset};
    }

    const auto field = static_cast<AuthFieldId>(id);
    std::size_t required_length = 0;
    switch (field) {
    case AuthFieldId::TranscriptHash:
        required_length = kTranscriptHashSize;
        break;
    case AuthFieldId::Identity:
        if (value.empty() || value.size() > kMaxCompositeIdentitySize) {
            return {ErrorCode::InvalidLength, value_offset};
        }
        return Status::Success();
    case AuthFieldId::CompositeSignature:
        required_length = kCompositeSignatureSize;
        break;
    case AuthFieldId::MlKemPublicKey:
        required_length = kMlKem1024PublicKeySize;
        break;
    case AuthFieldId::MlKemCiphertext:
        required_length = kMlKem1024CiphertextSize;
        break;
    case AuthFieldId::X25519PublicKey:
        required_length = kX25519PublicKeySize;
        break;
    case AuthFieldId::CapabilityManifest: {
        const Status status = ValidateCapabilityManifestEncoding(value);
        if (!status) {
            return {status.code, value_offset + status.offset};
        }
        return Status::Success();
    }
    case AuthFieldId::Nonce:
    case AuthFieldId::PskAuthenticator:
    case AuthFieldId::KeyConfirmation:
        required_length = 32;
        break;
    case AuthFieldId::SuiteId:
    case AuthFieldId::SecurityParameters:
    case AuthFieldId::SenderRole:
        return {ErrorCode::InvalidField, value_offset};
    }

    if (value.size() != required_length) {
        return {ErrorCode::InvalidLength, value_offset};
    }
    return Status::Success();
}

void WriteAuthField(std::span<std::uint8_t> output,
                    std::size_t& offset,
                    std::uint16_t id,
                    bool critical,
                    std::span<const std::uint8_t> value) {
    WriteU16(output, offset, id);
    WriteU16(output, offset + 2, critical ? kAuthFieldFlagCritical : 0);
    WriteU32(output, offset + 4, static_cast<std::uint32_t>(value.size()));
    offset += kAuthFieldPrefixSize;
    std::copy(value.begin(), value.end(),
              output.begin() + static_cast<std::ptrdiff_t>(offset));
    offset += value.size();
}

struct TaggedView {
    std::uint16_t id;
    std::span<const std::uint8_t> value;
};

[[nodiscard]] bool BuffersOverlap(std::span<const std::uint8_t> lhs,
                                  std::span<const std::uint8_t> rhs) noexcept {
    if (lhs.empty() || rhs.empty()) {
        return false;
    }
    const auto lhs_address =
        reinterpret_cast<std::uintptr_t>(lhs.data());
    const auto rhs_address =
        reinterpret_cast<std::uintptr_t>(rhs.data());
    if (lhs_address <= rhs_address) {
        return rhs_address - lhs_address < lhs.size();
    }
    return lhs_address - rhs_address < rhs.size();
}

[[nodiscard]] std::array<TaggedView, kKeyScheduleFieldCount>
KeyScheduleFields(const KeyScheduleInput& input,
                  const std::array<std::uint8_t, 1>& initiator_role,
                  const std::array<std::uint8_t, 1>& responder_role) noexcept {
    return {{{1, BytesOf(kRootDomain)},
             {2, BytesOf(kSuiteId)},
             {3, initiator_role},
             {4, responder_role},
             {5, input.transcript_hash},
             {6, input.exporter},
             {7, input.client_identity},
             {8, input.server_identity},
             {9, input.client_capability_manifest},
             {10, input.server_capability_manifest},
             {11, RequiredSecurityParameters()},
             {12, input.access_psk},
             {13, input.client_x25519_public_key},
             {14, input.server_x25519_public_key},
             {15, input.x25519_shared_secret},
             {16, input.mlkem_public_key},
             {17, input.mlkem_ciphertext},
             {18, input.mlkem_shared_secret}}};
}

} // namespace

bool IsRequiredSecurityParameters(
    std::span<const std::uint8_t> encoded) noexcept {
    return BytesEqual(encoded, RequiredSecurityParameters());
}

Result<std::vector<std::uint8_t>> EncodeAuthRecord(const AuthRecord& record) {
    if (!IsKnownAuthMessageType(record.type) ||
        !IsKnownRole(record.sender_role)) {
        return Result<std::vector<std::uint8_t>>::Failure(ErrorCode::InvalidEnum);
    }
    if (record.fields.size() > kMaxAuthFields - kMandatoryAuthFieldCount) {
        return Result<std::vector<std::uint8_t>>::Failure(
            ErrorCode::TooManyFields);
    }

    std::vector<const AuthField*> fields;
    fields.reserve(record.fields.size());
    for (const AuthField& field : record.fields) {
        const Status status = ValidateAdditionalAuthField(
            field.id, field.critical, field.value, 0);
        if (!status) {
            return Result<std::vector<std::uint8_t>>::Failure(status.code,
                                                              status.offset);
        }
        fields.push_back(&field);
    }
    std::sort(fields.begin(), fields.end(),
              [](const AuthField* lhs, const AuthField* rhs) {
                  return lhs->id < rhs->id;
              });
    for (std::size_t i = 1; i < fields.size(); ++i) {
        if (fields[i - 1]->id == fields[i]->id) {
            return Result<std::vector<std::uint8_t>>::Failure(
                ErrorCode::DuplicateField);
        }
    }

    const std::array<std::uint8_t, 1> role{
        static_cast<std::uint8_t>(record.sender_role)};
    std::size_t total = kAuthPrefixSize;
    const std::array<std::span<const std::uint8_t>, 3> mandatory{
        BytesOf(kSuiteId), RequiredSecurityParameters(), role};
    for (const auto value : mandatory) {
        if (total > kMaxAuthRecordSize - kAuthFieldPrefixSize ||
            value.size() >
                kMaxAuthRecordSize - total - kAuthFieldPrefixSize) {
            return Result<std::vector<std::uint8_t>>::Failure(
                ErrorCode::PayloadTooLarge);
        }
        total += kAuthFieldPrefixSize + value.size();
    }
    for (const AuthField* field : fields) {
        if (total > kMaxAuthRecordSize - kAuthFieldPrefixSize ||
            field->value.size() >
                kMaxAuthRecordSize - total - kAuthFieldPrefixSize) {
            return Result<std::vector<std::uint8_t>>::Failure(
                ErrorCode::PayloadTooLarge);
        }
        total += kAuthFieldPrefixSize + field->value.size();
    }

    std::vector<std::uint8_t> output(total);
    output[0] = kAuthSchema;
    output[1] = static_cast<std::uint8_t>(record.type);
    WriteU16(output, 2,
             static_cast<std::uint16_t>(kMandatoryAuthFieldCount +
                                        fields.size()));
    WriteU32(output, 4, static_cast<std::uint32_t>(total - kAuthPrefixSize));

    std::size_t offset = kAuthPrefixSize;
    WriteAuthField(output, offset,
                   static_cast<std::uint16_t>(AuthFieldId::SuiteId), true,
                   mandatory[0]);
    WriteAuthField(output, offset,
                   static_cast<std::uint16_t>(AuthFieldId::SecurityParameters),
                   true, mandatory[1]);
    WriteAuthField(output, offset,
                   static_cast<std::uint16_t>(AuthFieldId::SenderRole), true,
                   mandatory[2]);
    for (const AuthField* field : fields) {
        WriteAuthField(output, offset, field->id, field->critical,
                       field->value);
    }
    return Result<std::vector<std::uint8_t>>::Success(std::move(output));
}

Result<AuthRecord> DecodeAuthRecord(std::span<const std::uint8_t> encoded) {
    if (encoded.size() > kMaxAuthRecordSize) {
        return Result<AuthRecord>::Failure(ErrorCode::PayloadTooLarge);
    }
    if (encoded.size() < kAuthPrefixSize) {
        return Result<AuthRecord>::Failure(ErrorCode::Truncated, encoded.size());
    }
    if (encoded[0] != kAuthSchema) {
        return Result<AuthRecord>::Failure(ErrorCode::UnsupportedVersion, 0);
    }

    const auto message_type = static_cast<AuthMessageType>(encoded[1]);
    if (!IsKnownAuthMessageType(message_type)) {
        return Result<AuthRecord>::Failure(ErrorCode::InvalidEnum, 1);
    }
    const std::size_t field_count = ReadU16(encoded, 2);
    if (field_count > kMaxAuthFields) {
        return Result<AuthRecord>::Failure(ErrorCode::TooManyFields, 2);
    }
    if (field_count < kMandatoryAuthFieldCount) {
        return Result<AuthRecord>::Failure(ErrorCode::MissingField, 2);
    }
    const std::size_t body_length = ReadU32(encoded, 4);
    if (body_length > encoded.size() - kAuthPrefixSize) {
        return Result<AuthRecord>::Failure(ErrorCode::Truncated,
                                           encoded.size());
    }
    if (body_length < encoded.size() - kAuthPrefixSize) {
        return Result<AuthRecord>::Failure(ErrorCode::TrailingData,
                                           kAuthPrefixSize + body_length);
    }

    AuthRecord record;
    record.type = message_type;
    record.fields.reserve(field_count - kMandatoryAuthFieldCount);
    bool have_suite = false;
    bool have_security_parameters = false;
    bool have_role = false;
    std::uint16_t previous_id = 0;
    std::size_t offset = kAuthPrefixSize;

    for (std::size_t i = 0; i < field_count; ++i) {
        if (encoded.size() - offset < kAuthFieldPrefixSize) {
            return Result<AuthRecord>::Failure(ErrorCode::Truncated, offset);
        }
        const std::uint16_t id = ReadU16(encoded, offset);
        const std::uint16_t flags = ReadU16(encoded, offset + 2);
        const std::size_t length = ReadU32(encoded, offset + 4);
        if (id == 0) {
            return Result<AuthRecord>::Failure(ErrorCode::InvalidField, offset);
        }
        if (id == previous_id) {
            return Result<AuthRecord>::Failure(ErrorCode::DuplicateField,
                                               offset);
        }
        if (id < previous_id) {
            return Result<AuthRecord>::Failure(ErrorCode::OutOfOrderField,
                                               offset);
        }
        previous_id = id;
        if ((flags & ~kAuthFieldFlagCritical) != 0) {
            return Result<AuthRecord>::Failure(ErrorCode::InvalidFlags,
                                               offset + 2);
        }
        const bool critical = (flags & kAuthFieldFlagCritical) != 0;
        offset += kAuthFieldPrefixSize;
        if (length > encoded.size() - offset) {
            return Result<AuthRecord>::Failure(ErrorCode::Truncated, offset);
        }
        const auto value = encoded.subspan(offset, length);

        switch (static_cast<AuthFieldId>(id)) {
        case AuthFieldId::SuiteId:
            if (!critical || !BytesEqual(value, BytesOf(kSuiteId))) {
                return Result<AuthRecord>::Failure(ErrorCode::InvalidField,
                                                   offset);
            }
            have_suite = true;
            break;
        case AuthFieldId::SecurityParameters:
            if (!critical || !IsRequiredSecurityParameters(value)) {
                return Result<AuthRecord>::Failure(ErrorCode::InvalidField,
                                                   offset);
            }
            have_security_parameters = true;
            break;
        case AuthFieldId::SenderRole:
            if (!critical || value.size() != 1) {
                return Result<AuthRecord>::Failure(ErrorCode::InvalidField,
                                                   offset);
            }
            record.sender_role = static_cast<EndpointRole>(value[0]);
            if (!IsKnownRole(record.sender_role)) {
                return Result<AuthRecord>::Failure(ErrorCode::InvalidEnum,
                                                   offset);
            }
            have_role = true;
            break;
        default: {
            const Status status = ValidateAdditionalAuthField(
                id, critical, value, offset);
            if (!status) {
                return Result<AuthRecord>::Failure(status.code, status.offset);
            }
            AuthField field;
            field.id = id;
            field.critical = critical;
            field.value.assign(value.begin(), value.end());
            record.fields.push_back(std::move(field));
            break;
        }
        }
        offset += length;
    }

    if (offset != encoded.size()) {
        return Result<AuthRecord>::Failure(ErrorCode::TrailingData, offset);
    }
    if (!have_suite || !have_security_parameters || !have_role) {
        return Result<AuthRecord>::Failure(ErrorCode::MissingField, offset);
    }
    return Result<AuthRecord>::Success(std::move(record));
}

Status ValidateKeyScheduleInput(const KeyScheduleInput& input) noexcept {
    if (!IsKnownRole(input.initiator_role) ||
        !IsKnownRole(input.responder_role)) {
        return {ErrorCode::InvalidEnum, 0};
    }
    if (input.initiator_role == input.responder_role) {
        return {ErrorCode::InvalidField, 0};
    }
    if (input.transcript_hash.size() != kTranscriptHashSize ||
        input.exporter.size() != kExporterSize ||
        input.access_psk.size() != kPskSize ||
        input.client_x25519_public_key.size() != kX25519PublicKeySize ||
        input.server_x25519_public_key.size() != kX25519PublicKeySize ||
        input.x25519_shared_secret.size() != kX25519SharedSecretSize ||
        input.mlkem_public_key.size() != kMlKem1024PublicKeySize ||
        input.mlkem_ciphertext.size() != kMlKem1024CiphertextSize ||
        input.mlkem_shared_secret.size() != kMlKem1024SharedSecretSize) {
        return {ErrorCode::InvalidLength, 0};
    }
    if (input.client_identity.empty() || input.server_identity.empty() ||
        input.client_identity.size() > kMaxCompositeIdentitySize ||
        input.server_identity.size() > kMaxCompositeIdentitySize) {
        return {ErrorCode::InvalidLength, 0};
    }
    const Status client_capabilities = ValidateCapabilityManifestEncoding(
        input.client_capability_manifest);
    if (!client_capabilities) {
        return {client_capabilities.code, client_capabilities.offset};
    }
    const Status server_capabilities = ValidateCapabilityManifestEncoding(
        input.server_capability_manifest);
    if (!server_capabilities) {
        return {server_capabilities.code, server_capabilities.offset};
    }
    return Status::Success();
}

Result<std::size_t> KeyScheduleInputEncodedSize(
    const KeyScheduleInput& input) noexcept {
    const Status status = ValidateKeyScheduleInput(input);
    if (!status) {
        return Result<std::size_t>::Failure(status.code, status.offset);
    }

    const std::array<std::uint8_t, 1> initiator{
        static_cast<std::uint8_t>(input.initiator_role)};
    const std::array<std::uint8_t, 1> responder{
        static_cast<std::uint8_t>(input.responder_role)};
    const auto fields = KeyScheduleFields(input, initiator, responder);
    std::size_t total = kKeySchedulePrefixSize;
    for (const TaggedView& field : fields) {
        if (total > kMaxKeyScheduleInputSize - kKeyScheduleFieldPrefixSize ||
            field.value.size() >
                kMaxKeyScheduleInputSize - total -
                    kKeyScheduleFieldPrefixSize) {
            return Result<std::size_t>::Failure(ErrorCode::PayloadTooLarge);
        }
        total += kKeyScheduleFieldPrefixSize + field.value.size();
    }
    return Result<std::size_t>::Success(total);
}

Status EncodeKeyScheduleInput(const KeyScheduleInput& input,
                              std::span<std::uint8_t> output,
                              std::size_t& written) noexcept {
    written = 0;
    const auto required = KeyScheduleInputEncodedSize(input);
    if (!required) {
        return required.status;
    }
    if (output.size() < *required.value) {
        return {ErrorCode::OutputTooSmall, output.size()};
    }

    const std::array<std::uint8_t, 1> initiator{
        static_cast<std::uint8_t>(input.initiator_role)};
    const std::array<std::uint8_t, 1> responder{
        static_cast<std::uint8_t>(input.responder_role)};
    const auto fields = KeyScheduleFields(input, initiator, responder);

    const std::span<const std::uint8_t> destination(
        output.data(), *required.value);
    for (const TaggedView& field : fields) {
        if (BuffersOverlap(destination, field.value)) {
            return {ErrorCode::OverlappingBuffer, 0};
        }
    }

    output[0] = kWireVersion;
    output[1] = 0;
    WriteU16(output, 2, kKeyScheduleFieldCount);
    std::size_t offset = kKeySchedulePrefixSize;
    for (const TaggedView& field : fields) {
        WriteU16(output, offset, field.id);
        WriteU32(output, offset + 2,
                 static_cast<std::uint32_t>(field.value.size()));
        offset += kKeyScheduleFieldPrefixSize;
        std::memmove(output.data() + offset, field.value.data(),
                     field.value.size());
        offset += field.value.size();
    }
    written = offset;
    return Status::Success();
}

} // namespace yume::ytp1
