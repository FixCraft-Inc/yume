/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/relay/relay_v2_crypto.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <memory>
#include <string_view>
#include <utility>

#include <openssl/crypto.h>

#include "core/security/secure_erase.hpp"

#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
#include <basefwx/crypto.hpp>
#include <basefwx/pq.hpp>
#include <basefwx/x25519.hpp>
#endif

namespace yume::client::relay_v2 {
namespace {

constexpr std::array<std::uint8_t, 4> kRecordMagic{'Y', 'R', 'V', '2'};
constexpr std::uint8_t kRequestKind = 1;
constexpr std::uint8_t kResponseKind = 2;
constexpr std::size_t kRecordHeaderBytes = 8;

constexpr std::string_view kRequestSignatureDomain =
    "yume/relay/v2/request-signature/v1";
constexpr std::string_view kResponseSignatureDomain =
    "yume/relay/v2/response-signature/v1";
constexpr std::string_view kTranscriptHashDomain =
    "yume/relay/v2/transcript-hash/v1";
constexpr std::string_view kHybridInputDomain =
    "yume/relay/v2/hybrid-input/v1";
constexpr std::string_view kInitialRootDomain =
    "yume/relay/v2/initial-root/v1";
constexpr std::string_view kEpochPskDomain =
    "yume/relay/v2/epoch-psk/v1";

constexpr std::array<std::uint8_t, 12> kRequestFieldIds{
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
constexpr std::array<std::uint8_t, 15> kResponseFieldIds{
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

struct Field {
    std::uint8_t id{0};
    Bytes value;
};

class WipeBytesOnExit {
public:
    explicit WipeBytesOnExit(Bytes& bytes) noexcept : bytes_(bytes) {}
    WipeBytesOnExit(const WipeBytesOnExit&) = delete;
    WipeBytesOnExit& operator=(const WipeBytesOnExit&) = delete;
    ~WipeBytesOnExit() { security::secure_erase(bytes_); }

private:
    Bytes& bytes_;
};

void AppendU16(Bytes& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value >> 8));
    out.push_back(static_cast<std::uint8_t>(value));
}

[[maybe_unused]] void AppendU32(Bytes& out, std::uint32_t value) {
    out.push_back(static_cast<std::uint8_t>(value >> 24));
    out.push_back(static_cast<std::uint8_t>(value >> 16));
    out.push_back(static_cast<std::uint8_t>(value >> 8));
    out.push_back(static_cast<std::uint8_t>(value));
}

std::uint16_t ReadU16(std::span<const std::uint8_t> bytes,
                      std::size_t* offset) {
    if (offset == nullptr || *offset > bytes.size() ||
        bytes.size() - *offset < 2) {
        throw Error("relay-v2 record contains a truncated uint16");
    }
    const std::uint16_t value = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(bytes[*offset]) << 8) |
        static_cast<std::uint16_t>(bytes[*offset + 1]));
    *offset += 2;
    return value;
}

Bytes U16Bytes(std::uint16_t value) {
    Bytes out;
    out.reserve(2);
    AppendU16(out, value);
    return out;
}

std::uint16_t ParseU16(const Bytes& value, std::string_view name) {
    if (value.size() != 2) {
        throw Error("relay-v2 invalid " + std::string(name) + " size");
    }
    std::size_t offset = 0;
    return ReadU16(value, &offset);
}

Bytes ToBytes(std::string_view value) {
    return Bytes(value.begin(), value.end());
}

template <std::size_t N>
Bytes ToBytes(const std::array<std::uint8_t, N>& value) {
    return Bytes(value.begin(), value.end());
}

template <std::size_t N>
std::array<std::uint8_t, N> ParseArray(const Bytes& value,
                                       std::string_view name) {
    if (value.size() != N) {
        throw Error("relay-v2 invalid " + std::string(name) + " size");
    }
    std::array<std::uint8_t, N> out{};
    std::copy(value.begin(), value.end(), out.begin());
    return out;
}

std::uint8_t EncodeChannelKind(control::ChannelKind kind) {
    switch (kind) {
        case control::ChannelKind::chat:
            return 1;
        case control::ChannelKind::file:
            return 2;
        case control::ChannelKind::bytes:
            return 3;
        case control::ChannelKind::admin:
            return 4;
    }
    throw Error("relay-v2 channel kind is invalid");
}

control::ChannelKind DecodeChannelKind(const Bytes& value) {
    if (value.size() != 1) {
        throw Error("relay-v2 channel kind size is invalid");
    }
    switch (value[0]) {
        case 1:
            return control::ChannelKind::chat;
        case 2:
            return control::ChannelKind::file;
        case 3:
            return control::ChannelKind::bytes;
        case 4:
            return control::ChannelKind::admin;
        default:
            throw Error("relay-v2 channel kind value is invalid");
    }
}

Bytes EncodePasswordPolicy(PasswordPolicy policy) {
    switch (policy) {
        case PasswordPolicy::NotRequired:
            return {1};
        case PasswordPolicy::Required:
            return {2};
    }
    throw Error("relay-v2 password policy is invalid");
}

PasswordPolicy DecodePasswordPolicy(const Bytes& value) {
    if (value.size() != 1) {
        throw Error("relay-v2 password policy size is invalid");
    }
    if (value[0] == 1) return PasswordPolicy::NotRequired;
    if (value[0] == 2) return PasswordPolicy::Required;
    throw Error("relay-v2 password policy value is invalid");
}

bool IsEndpointCharacter(std::uint8_t value) noexcept {
    return (value >= 'a' && value <= 'z') ||
           (value >= 'A' && value <= 'Z') ||
           (value >= '0' && value <= '9') || value == '-' || value == '_' ||
           value == '.' || value == ':';
}

void ValidateEndpointId(std::string_view value, std::string_view role) {
    if (value.empty() || value.size() > kMaxEndpointIdBytes ||
        !std::all_of(value.begin(), value.end(), [](char character) {
            return IsEndpointCharacter(static_cast<std::uint8_t>(character));
        })) {
        throw Error("relay-v2 " + std::string(role) +
                    " endpoint id is invalid");
    }
}

void ValidateContext(const HandshakeContext& context) {
    (void)EncodeChannelKind(context.channel_kind);
    (void)EncodePasswordPolicy(context.password_policy);
    ValidateEndpointId(context.initiator_endpoint_id, "initiator");
    ValidateEndpointId(context.responder_endpoint_id, "responder");
    if (context.initiator_endpoint_id == context.responder_endpoint_id) {
        throw Error("relay-v2 endpoint ids must differ");
    }
    if (std::none_of(context.nonce.begin(), context.nonce.end(),
                     [](std::uint8_t byte) { return byte != 0; })) {
        throw Error("relay-v2 nonce must not be all zero");
    }
}

[[maybe_unused]] void ValidateRelayPsk(PasswordPolicy policy,
                                      const Bytes& relay_psk) {
    switch (policy) {
        case PasswordPolicy::NotRequired:
            if (!relay_psk.empty()) {
                throw Error("relay-v2 PSK is forbidden by password policy");
            }
            return;
        case PasswordPolicy::Required:
            if (relay_psk.size() != kRelayPskBytes) {
                throw Error("relay-v2 required PSK must be exactly 32 bytes");
            }
            return;
    }
    throw Error("relay-v2 password policy is invalid");
}

std::vector<Field> DecodeRecord(
    const Bytes& encoded,
    std::uint8_t expected_kind,
    std::span<const std::uint8_t> expected_ids) {
    if (encoded.size() < kRecordHeaderBytes ||
        encoded.size() > kMaxRecordBytes) {
        throw Error("relay-v2 record size is invalid");
    }
    if (!std::equal(kRecordMagic.begin(), kRecordMagic.end(),
                    encoded.begin()) ||
        encoded[4] != kRecordSchemaVersion ||
        encoded[5] != expected_kind) {
        throw Error("relay-v2 record magic, schema, or kind is invalid");
    }
    std::size_t offset = 6;
    const std::uint16_t field_count = ReadU16(encoded, &offset);
    if (field_count != expected_ids.size()) {
        throw Error("relay-v2 record field count is invalid");
    }

    std::vector<Field> fields;
    fields.reserve(field_count);
    for (std::size_t index = 0; index < expected_ids.size(); ++index) {
        if (offset >= encoded.size()) {
            throw Error("relay-v2 record contains a truncated field id");
        }
        const std::uint8_t id = encoded[offset++];
        if (id != expected_ids[index]) {
            throw Error("relay-v2 record fields are not canonical");
        }
        const std::uint16_t length = ReadU16(encoded, &offset);
        if (length > encoded.size() - offset) {
            throw Error("relay-v2 record contains a truncated field");
        }
        Field field{id, {}};
        field.value.assign(
            encoded.begin() + static_cast<std::ptrdiff_t>(offset),
            encoded.begin() + static_cast<std::ptrdiff_t>(offset + length));
        offset += length;
        fields.push_back(std::move(field));
    }
    if (offset != encoded.size()) {
        throw Error("relay-v2 record contains trailing bytes");
    }
    return fields;
}

Bytes EncodeRecord(std::uint8_t kind, const std::vector<Field>& fields) {
    if (fields.empty() ||
        fields.size() > std::numeric_limits<std::uint16_t>::max()) {
        throw Error("relay-v2 record field count is invalid");
    }
    std::size_t total = kRecordHeaderBytes;
    std::uint8_t previous = 0;
    for (const Field& field : fields) {
        if (field.id == 0 || field.id <= previous ||
            field.value.size() > std::numeric_limits<std::uint16_t>::max()) {
            throw Error("relay-v2 record fields are not canonical");
        }
        if (total > kMaxRecordBytes - 3U ||
            field.value.size() > kMaxRecordBytes - total - 3U) {
            throw Error("relay-v2 record exceeds the size cap");
        }
        total += 3U + field.value.size();
        previous = field.id;
    }

    // Populate a size-checked destination directly.  Besides avoiding
    // reallocations, this keeps GCC 11 from misdiagnosing vector::insert's
    // growth path as a zero-sized destination under Release inlining.
    Bytes out(total);
    std::size_t offset = 0;
    for (const std::uint8_t byte : kRecordMagic) {
        out[offset++] = byte;
    }
    out[offset++] = kRecordSchemaVersion;
    out[offset++] = kind;
    out[offset++] = static_cast<std::uint8_t>(fields.size() >> 8U);
    out[offset++] = static_cast<std::uint8_t>(fields.size());
    for (const Field& field : fields) {
        out[offset++] = field.id;
        out[offset++] = static_cast<std::uint8_t>(field.value.size() >> 8U);
        out[offset++] = static_cast<std::uint8_t>(field.value.size());
        for (const std::uint8_t byte : field.value) {
            out[offset++] = byte;
        }
    }
    return out;
}

const Bytes& Value(const std::vector<Field>& fields, std::uint8_t id) {
    const auto found = std::find_if(
        fields.begin(), fields.end(),
        [id](const Field& field) { return field.id == id; });
    if (found == fields.end()) {
        throw Error("relay-v2 required field is missing");
    }
    return found->value;
}

crypto::CompositePublicKey ParseCanonicalIdentity(const Bytes& identity) {
    if (identity.empty() || identity.size() > kMaxIdentityBytes) {
        throw Error("relay-v2 composite identity size is invalid");
    }
    crypto::CompositePublicKey parsed =
        crypto::parse_composite_identity(identity);
    if (!parsed.valid()) {
        throw Error("relay-v2 composite identity is invalid");
    }
    const Bytes canonical = crypto::encode_composite_identity(
        parsed.classical.get(), parsed.pq.get());
    if (canonical != identity) {
        throw Error("relay-v2 composite identity is not canonical");
    }
    return parsed;
}

HandshakeContext ParseContext(const std::vector<Field>& fields) {
    if (ParseU16(Value(fields, 1), "protocol version") !=
        kProtocolVersion) {
        throw Error("relay-v2 protocol version mismatch");
    }
    HandshakeContext context;
    context.channel_kind = DecodeChannelKind(Value(fields, 2));
    context.initiator_endpoint_id = std::string(
        Value(fields, 3).begin(), Value(fields, 3).end());
    context.responder_endpoint_id = std::string(
        Value(fields, 4).begin(), Value(fields, 4).end());
    context.nonce = ParseArray<kNonceBytes>(Value(fields, 5), "nonce");
    context.password_policy = DecodePasswordPolicy(Value(fields, 6));
    context.metadata_digest = ParseArray<kMetadataDigestBytes>(
        Value(fields, 7), "metadata digest");
    ValidateContext(context);
    return context;
}

std::vector<Field> CommonFields(const HandshakeContext& context,
                                const Bytes& initiator_identity,
                                const Bytes& responder_identity,
                                const Bytes& initiator_mlkem_public_key,
                                const Bytes& initiator_x25519_public_key) {
    ValidateContext(context);
    (void)ParseCanonicalIdentity(initiator_identity);
    (void)ParseCanonicalIdentity(responder_identity);
    if (initiator_mlkem_public_key.size() !=
        kMlKem1024PublicKeyBytes) {
        throw Error("relay-v2 ML-KEM-1024 public key size is invalid");
    }
    if (initiator_x25519_public_key.size() != kX25519PublicKeyBytes) {
        throw Error("relay-v2 X25519 public key size is invalid");
    }
    return {
        {1, U16Bytes(kProtocolVersion)},
        {2, {EncodeChannelKind(context.channel_kind)}},
        {3, ToBytes(context.initiator_endpoint_id)},
        {4, ToBytes(context.responder_endpoint_id)},
        {5, ToBytes(context.nonce)},
        {6, EncodePasswordPolicy(context.password_policy)},
        {7, ToBytes(context.metadata_digest)},
        {8, initiator_identity},
        {9, responder_identity},
        {10, initiator_mlkem_public_key},
        {11, initiator_x25519_public_key},
    };
}

[[maybe_unused]] Bytes EncodeUnsignedRequest(const HandshakeContext& context,
                            const Bytes& initiator_identity,
                            const Bytes& responder_identity,
                            const Bytes& initiator_mlkem_public_key,
                            const Bytes& initiator_x25519_public_key) {
    return EncodeRecord(
        kRequestKind,
        CommonFields(context, initiator_identity, responder_identity,
                     initiator_mlkem_public_key,
                     initiator_x25519_public_key));
}

[[maybe_unused]] Bytes EncodeRequest(const HandshakeContext& context,
                    const Bytes& initiator_identity,
                    const Bytes& responder_identity,
                    const Bytes& initiator_mlkem_public_key,
                    const Bytes& initiator_x25519_public_key,
                    const Bytes& signature) {
    if (signature.size() != crypto::kCompositeSignatureLen) {
        throw Error("relay-v2 initiator signature size is invalid");
    }
    std::vector<Field> fields = CommonFields(
        context, initiator_identity, responder_identity,
        initiator_mlkem_public_key, initiator_x25519_public_key);
    fields.push_back({12, signature});
    return EncodeRecord(kRequestKind, fields);
}

[[maybe_unused]] Bytes EncodeUnsignedResponse(const HandshakeContext& context,
                             const Bytes& initiator_identity,
                             const Bytes& responder_identity,
                             const Bytes& initiator_mlkem_public_key,
                             const Bytes& initiator_x25519_public_key,
                             const Bytes& responder_mlkem_ciphertext,
                             const Bytes& responder_x25519_public_key,
                             const Bytes& request_digest) {
    if (responder_mlkem_ciphertext.size() !=
        kMlKem1024CiphertextBytes) {
        throw Error("relay-v2 ML-KEM-1024 ciphertext size is invalid");
    }
    if (responder_x25519_public_key.size() != kX25519PublicKeyBytes) {
        throw Error("relay-v2 responder X25519 public key size is invalid");
    }
    if (request_digest.size() != 32) {
        throw Error("relay-v2 request digest size is invalid");
    }
    std::vector<Field> fields = CommonFields(
        context, initiator_identity, responder_identity,
        initiator_mlkem_public_key, initiator_x25519_public_key);
    fields.push_back({12, responder_mlkem_ciphertext});
    fields.push_back({13, responder_x25519_public_key});
    fields.push_back({14, request_digest});
    return EncodeRecord(kResponseKind, fields);
}

[[maybe_unused]] Bytes EncodeResponse(const HandshakeContext& context,
                     const Bytes& initiator_identity,
                     const Bytes& responder_identity,
                     const Bytes& initiator_mlkem_public_key,
                     const Bytes& initiator_x25519_public_key,
                     const Bytes& responder_mlkem_ciphertext,
                     const Bytes& responder_x25519_public_key,
                     const Bytes& request_digest,
                     const Bytes& signature) {
    if (signature.size() != crypto::kCompositeSignatureLen) {
        throw Error("relay-v2 responder signature size is invalid");
    }
    std::vector<Field> fields = CommonFields(
        context, initiator_identity, responder_identity,
        initiator_mlkem_public_key, initiator_x25519_public_key);
    fields.push_back({12, responder_mlkem_ciphertext});
    fields.push_back({13, responder_x25519_public_key});
    fields.push_back({14, request_digest});
    fields.push_back({15, signature});
    return EncodeRecord(kResponseKind, fields);
}

struct ParsedRequest {
    HandshakeContext context;
    Bytes initiator_identity;
    Bytes responder_identity;
    Bytes initiator_mlkem_public_key;
    Bytes initiator_x25519_public_key;
    Bytes signature;
    crypto::CompositePublicKey initiator_public_key;
};

[[maybe_unused]] ParsedRequest ParseRequest(const Bytes& encoded) {
    const std::vector<Field> fields = DecodeRecord(
        encoded, kRequestKind, kRequestFieldIds);
    ParsedRequest request;
    request.context = ParseContext(fields);
    request.initiator_identity = Value(fields, 8);
    request.responder_identity = Value(fields, 9);
    request.initiator_mlkem_public_key = Value(fields, 10);
    request.initiator_x25519_public_key = Value(fields, 11);
    request.signature = Value(fields, 12);
    request.initiator_public_key =
        ParseCanonicalIdentity(request.initiator_identity);
    (void)ParseCanonicalIdentity(request.responder_identity);
    if (request.initiator_mlkem_public_key.size() !=
        kMlKem1024PublicKeyBytes) {
        throw Error("relay-v2 ML-KEM-1024 public key size is invalid");
    }
    if (request.initiator_x25519_public_key.size() !=
        kX25519PublicKeyBytes) {
        throw Error("relay-v2 initiator X25519 public key size is invalid");
    }
    if (request.signature.size() != crypto::kCompositeSignatureLen) {
        throw Error("relay-v2 initiator signature size is invalid");
    }
    return request;
}

struct ParsedResponse {
    HandshakeContext context;
    Bytes initiator_identity;
    Bytes responder_identity;
    Bytes initiator_mlkem_public_key;
    Bytes initiator_x25519_public_key;
    Bytes responder_mlkem_ciphertext;
    Bytes responder_x25519_public_key;
    Bytes request_digest;
    Bytes signature;
    crypto::CompositePublicKey responder_public_key;
};

[[maybe_unused]] ParsedResponse ParseResponse(const Bytes& encoded) {
    const std::vector<Field> fields = DecodeRecord(
        encoded, kResponseKind, kResponseFieldIds);
    ParsedResponse response;
    response.context = ParseContext(fields);
    response.initiator_identity = Value(fields, 8);
    response.responder_identity = Value(fields, 9);
    response.initiator_mlkem_public_key = Value(fields, 10);
    response.initiator_x25519_public_key = Value(fields, 11);
    response.responder_mlkem_ciphertext = Value(fields, 12);
    response.responder_x25519_public_key = Value(fields, 13);
    response.request_digest = Value(fields, 14);
    response.signature = Value(fields, 15);
    (void)ParseCanonicalIdentity(response.initiator_identity);
    response.responder_public_key =
        ParseCanonicalIdentity(response.responder_identity);
    if (response.initiator_mlkem_public_key.size() !=
        kMlKem1024PublicKeyBytes ||
        response.responder_mlkem_ciphertext.size() !=
        kMlKem1024CiphertextBytes) {
        throw Error("relay-v2 ML-KEM-1024 field size is invalid");
    }
    if (response.initiator_x25519_public_key.size() !=
            kX25519PublicKeyBytes ||
        response.responder_x25519_public_key.size() !=
            kX25519PublicKeyBytes) {
        throw Error("relay-v2 X25519 field size is invalid");
    }
    if (response.request_digest.size() != 32) {
        throw Error("relay-v2 request digest size is invalid");
    }
    if (response.signature.size() != crypto::kCompositeSignatureLen) {
        throw Error("relay-v2 responder signature size is invalid");
    }
    return response;
}

[[maybe_unused]] bool EqualBytes(const Bytes& left,
                                const Bytes& right) noexcept {
    if (left.size() != right.size()) return false;
    if (left.empty()) return true;
    return CRYPTO_memcmp(left.data(), right.data(), left.size()) == 0;
}

#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX

using SecureBytes = basefwx::crypto::SecureBytes;

void AppendLengthPrefixed(Bytes& out, const Bytes& value) {
    if (value.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw Error("relay-v2 transcript component is too large");
    }
    AppendU32(out, static_cast<std::uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

SecureBytes BuildRequestSignatureInput(const Bytes& unsigned_request) {
    SecureBytes guarded;
    Bytes& out = guarded.bytes();
    out.reserve(kRequestSignatureDomain.size() + 4U +
                unsigned_request.size());
    out.insert(out.end(), kRequestSignatureDomain.begin(),
               kRequestSignatureDomain.end());
    AppendLengthPrefixed(out, unsigned_request);
    return guarded;
}

SecureBytes BuildResponseSignatureInput(const Bytes& request,
                                        const Bytes& unsigned_response) {
    if (request.size() > kMaxRecordBytes ||
        unsigned_response.size() > kMaxRecordBytes) {
        throw Error("relay-v2 signature transcript exceeds the size cap");
    }
    SecureBytes guarded;
    Bytes& out = guarded.bytes();
    out.reserve(kResponseSignatureDomain.size() + 8U + request.size() +
                unsigned_response.size());
    out.insert(out.end(), kResponseSignatureDomain.begin(),
               kResponseSignatureDomain.end());
    AppendLengthPrefixed(out, request);
    AppendLengthPrefixed(out, unsigned_response);
    return guarded;
}

SecureBytes Sha256Secret(std::string_view domain,
                         const Bytes& first,
                         const Bytes* second) {
    try {
        crypto::Sha256Stream context;
        const auto update = [&](std::span<const std::uint8_t> bytes) {
            context.Update(bytes);
        };
        update(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(domain.data()),
            domain.size()));
        std::array<std::uint8_t, 4> length{};
        const auto update_length = [&](std::size_t size) {
            if (size > std::numeric_limits<std::uint32_t>::max()) {
                throw Error("relay-v2 SHA-256 input exceeds the size cap");
            }
            const auto value = static_cast<std::uint32_t>(size);
            length = {static_cast<std::uint8_t>(value >> 24),
                      static_cast<std::uint8_t>(value >> 16),
                      static_cast<std::uint8_t>(value >> 8),
                      static_cast<std::uint8_t>(value)};
            update(length);
        };
        update_length(first.size());
        update(first);
        if (second != nullptr) {
            update_length(second->size());
            update(*second);
        }
        Bytes digest = context.Finish();
        WipeBytesOnExit digest_wiper(digest);
        if (digest.size() != 32U) {
            throw Error("relay-v2 SHA-256 finalization failed");
        }
        return SecureBytes{std::move(digest)};
    } catch (const Error&) {
        throw;
    } catch (const std::exception& ex) {
        throw Error(std::string("relay-v2 SHA-256 failed: ") + ex.what());
    }
}

Bytes RequestDigest(const Bytes& request) {
    SecureBytes guarded = Sha256Secret(
        "yume/relay/v2/request-digest/v1", request, nullptr);
    return guarded.Release();
}

struct DerivedPair {
    SecureBytes initial_root;
    SecureBytes epoch_psk;
};

DerivedPair DeriveSecrets(const Bytes& request,
                          const Bytes& response,
                          const Bytes& mlkem_shared,
                          const Bytes& x25519_shared,
                          const Bytes& relay_psk) {
    if (mlkem_shared.size() != 32 || x25519_shared.size() != 32 ||
        request.size() > kMaxRecordBytes ||
        response.size() > kMaxRecordBytes) {
        throw Error("relay-v2 hybrid secret or transcript size is invalid");
    }
    SecureBytes transcript_hash = Sha256Secret(
        kTranscriptHashDomain, request, &response);
    SecureBytes hybrid_input;
    Bytes& input = hybrid_input.bytes();
    input.reserve(kHybridInputDomain.size() + 12U + mlkem_shared.size() +
                  x25519_shared.size() + relay_psk.size());
    input.insert(input.end(), kHybridInputDomain.begin(),
                 kHybridInputDomain.end());
    AppendLengthPrefixed(input, mlkem_shared);
    AppendLengthPrefixed(input, x25519_shared);
    AppendLengthPrefixed(input, relay_psk);

    SecureBytes initial_root{basefwx::crypto::HkdfSha256(
        input, transcript_hash.bytes(), kInitialRootDomain, 32)};
    SecureBytes epoch_psk{basefwx::crypto::HkdfSha256(
        input, transcript_hash.bytes(), kEpochPskDomain, 32)};
    if (initial_root.size() != 32 || epoch_psk.size() != 32 ||
        CRYPTO_memcmp(initial_root.data(), epoch_psk.data(), 32) == 0) {
        throw Error("relay-v2 key derivation failed domain separation");
    }
    return {std::move(initial_root), std::move(epoch_psk)};
}

#endif

[[maybe_unused]] void RequireRequestMatches(const ParsedRequest& request,
                           const HandshakeContext& context,
                           const Bytes& initiator_identity,
                           const Bytes& responder_identity) {
    if (!(request.context == context) ||
        request.initiator_identity != initiator_identity ||
        request.responder_identity != responder_identity) {
        throw Error("relay-v2 request context or peer identity mismatch");
    }
}

}  // namespace

#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
struct SessionSecrets::Impl {
    Impl(SecureBytes root, SecureBytes psk) noexcept
        : initial_root(std::move(root)), epoch_psk(std::move(psk)) {}

    SecureBytes initial_root;
    SecureBytes epoch_psk;
};

struct InitiatorState::Impl {
    Impl(Bytes signed_request,
         basefwx::pq::KemKeyPair mlkem_keypair,
         basefwx::x25519::KeyPair x25519_keypair,
         SecureBytes psk) noexcept
        : request(std::move(signed_request)),
          mlkem(std::move(mlkem_keypair)),
          x25519(std::move(x25519_keypair)),
          relay_psk(std::move(psk)) {}

    Bytes request;
    basefwx::pq::KemKeyPair mlkem;
    basefwx::x25519::KeyPair x25519;
    SecureBytes relay_psk;
};
#else
struct SessionSecrets::Impl {};
struct InitiatorState::Impl {};
#endif

SessionSecrets::SessionSecrets() noexcept = default;
SessionSecrets::SessionSecrets(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}
SessionSecrets::SessionSecrets(SessionSecrets&&) noexcept = default;
SessionSecrets& SessionSecrets::operator=(SessionSecrets&&) noexcept = default;
SessionSecrets::~SessionSecrets() = default;

bool SessionSecrets::valid() const noexcept {
#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
    return impl_ != nullptr && impl_->initial_root.size() == 32 &&
           impl_->epoch_psk.size() == 32;
#else
    return false;
#endif
}

std::span<const std::uint8_t> SessionSecrets::initial_root() const noexcept {
#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
    if (impl_ != nullptr) {
        return {impl_->initial_root.data(), impl_->initial_root.size()};
    }
#endif
    return {};
}

std::span<const std::uint8_t> SessionSecrets::epoch_psk() const noexcept {
#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
    if (impl_ != nullptr) {
        return {impl_->epoch_psk.data(), impl_->epoch_psk.size()};
    }
#endif
    return {};
}

InitiatorState::InitiatorState() noexcept = default;
InitiatorState::InitiatorState(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}
InitiatorState::InitiatorState(InitiatorState&&) noexcept = default;
InitiatorState& InitiatorState::operator=(InitiatorState&&) noexcept = default;
InitiatorState::~InitiatorState() = default;

bool InitiatorState::valid() const noexcept {
#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
    return impl_ != nullptr && !impl_->request.empty() &&
           impl_->mlkem.public_key.size() == kMlKem1024PublicKeyBytes &&
           impl_->x25519.public_key.size() == kX25519PublicKeyBytes;
#else
    return false;
#endif
}

InitiatorRequest::InitiatorRequest(Bytes encoded_request,
                                   InitiatorState pending) noexcept
    : encoded(std::move(encoded_request)), state(std::move(pending)) {}

ResponderResult::ResponderResult(Bytes encoded_response,
                                 SessionSecrets derived) noexcept
    : encoded(std::move(encoded_response)), secrets(std::move(derived)) {}

Bytes EncodeIdentity(const crypto::CompositeKeyPair& identity) {
    const Bytes encoded = crypto::encode_composite_identity(
        identity.classical.public_key.get(), identity.pq.public_key.get());
    (void)ParseCanonicalIdentity(encoded);
    return encoded;
}

Bytes CanonicalizeIdentity(const Bytes& pem_bundle) {
    if (pem_bundle.empty() || pem_bundle.size() > kMaxIdentityBytes) {
        throw Error("relay-v2 composite identity size is invalid");
    }
    crypto::CompositePublicKey parsed =
        crypto::parse_composite_identity(pem_bundle);
    if (!parsed.valid()) {
        throw Error("relay-v2 composite identity is invalid");
    }
    const Bytes canonical = crypto::encode_composite_identity(
        parsed.classical.get(), parsed.pq.get());
    if (canonical.size() > kMaxIdentityBytes) {
        throw Error("relay-v2 canonical identity exceeds the size cap");
    }
    return canonical;
}

HandshakeContext InspectInitiatorRequest(const Bytes& request) {
    return ParseRequest(request).context;
}

InitiatorRequest BeginInitiator(
    const HandshakeContext& context,
    const crypto::CompositeKeyPair& initiator_identity,
    const Bytes& responder_identity,
    Bytes relay_psk) {
    WipeBytesOnExit wipe_psk(relay_psk);
#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
    ValidateContext(context);
    ValidateRelayPsk(context.password_policy, relay_psk);
    SecureBytes guarded_psk{std::move(relay_psk)};
    const Bytes initiator_encoded = EncodeIdentity(initiator_identity);
    (void)ParseCanonicalIdentity(responder_identity);

    basefwx::pq::KemKeyPair mlkem = basefwx::pq::GenerateKeyPair(
        basefwx::pq::KemAlgorithm::MlKem1024);
    basefwx::x25519::KeyPair x25519 =
        basefwx::x25519::GenerateKeyPair();
    const Bytes unsigned_request = EncodeUnsignedRequest(
        context, initiator_encoded, responder_identity, mlkem.public_key,
        x25519.public_key);
    SecureBytes signature_input =
        BuildRequestSignatureInput(unsigned_request);
    const Bytes signature = crypto::sign_composite(
        initiator_identity, signature_input.bytes());
    Bytes request = EncodeRequest(
        context, initiator_encoded, responder_identity, mlkem.public_key,
        x25519.public_key, signature);
    auto pending = std::make_unique<InitiatorState::Impl>(
        request, std::move(mlkem), std::move(x25519),
        std::move(guarded_psk));
    return InitiatorRequest{
        std::move(request), InitiatorState{std::move(pending)}};
#else
    (void)context;
    (void)initiator_identity;
    (void)responder_identity;
    throw Error("relay-v2 hybrid crypto requires BaseFWX");
#endif
}

ResponderResult Respond(
    const Bytes& request,
    const HandshakeContext& expected_context,
    const Bytes& expected_initiator_identity,
    const crypto::CompositeKeyPair& responder_identity,
    Bytes relay_psk) {
    WipeBytesOnExit wipe_psk(relay_psk);
#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
    ValidateContext(expected_context);
    ValidateRelayPsk(expected_context.password_policy, relay_psk);
    SecureBytes guarded_psk{std::move(relay_psk)};
    ParsedRequest parsed = ParseRequest(request);
    const Bytes expected_initiator =
        CanonicalizeIdentity(expected_initiator_identity);
    if (expected_initiator != expected_initiator_identity) {
        throw Error("relay-v2 expected initiator identity is not canonical");
    }
    const Bytes responder_encoded = EncodeIdentity(responder_identity);
    RequireRequestMatches(parsed, expected_context, expected_initiator,
                          responder_encoded);

    const Bytes unsigned_request = EncodeUnsignedRequest(
        parsed.context, parsed.initiator_identity, parsed.responder_identity,
        parsed.initiator_mlkem_public_key,
        parsed.initiator_x25519_public_key);
    SecureBytes request_signature_input =
        BuildRequestSignatureInput(unsigned_request);
    if (!crypto::verify_composite(
            parsed.initiator_public_key.classical.get(),
            parsed.initiator_public_key.pq.get(),
            request_signature_input.bytes(), parsed.signature)) {
        throw Error("relay-v2 initiator composite signature rejected");
    }

    basefwx::pq::KemResult kem = basefwx::pq::KemEncrypt(
        basefwx::pq::KemAlgorithm::MlKem1024,
        parsed.initiator_mlkem_public_key);
    SecureBytes kem_shared{std::move(kem.shared)};
    basefwx::x25519::KeyPair x25519 =
        basefwx::x25519::GenerateKeyPair();
    SecureBytes x25519_shared{
        basefwx::x25519::DeriveSharedSecret(
            x25519.private_key, parsed.initiator_x25519_public_key)};
    const Bytes request_digest = RequestDigest(request);
    const Bytes unsigned_response = EncodeUnsignedResponse(
        parsed.context, parsed.initiator_identity, responder_encoded,
        parsed.initiator_mlkem_public_key,
        parsed.initiator_x25519_public_key, kem.ciphertext,
        x25519.public_key, request_digest);
    SecureBytes response_signature_input =
        BuildResponseSignatureInput(request, unsigned_response);
    const Bytes signature = crypto::sign_composite(
        responder_identity, response_signature_input.bytes());
    Bytes response = EncodeResponse(
        parsed.context, parsed.initiator_identity, responder_encoded,
        parsed.initiator_mlkem_public_key,
        parsed.initiator_x25519_public_key, kem.ciphertext,
        x25519.public_key, request_digest, signature);

    DerivedPair derived = DeriveSecrets(
        request, response, kem_shared.bytes(), x25519_shared.bytes(),
        guarded_psk.bytes());
    auto secrets_impl = std::make_unique<SessionSecrets::Impl>(
        std::move(derived.initial_root), std::move(derived.epoch_psk));
    return ResponderResult{
        std::move(response), SessionSecrets{std::move(secrets_impl)}};
#else
    (void)request;
    (void)expected_context;
    (void)expected_initiator_identity;
    (void)responder_identity;
    throw Error("relay-v2 hybrid crypto requires BaseFWX");
#endif
}

SessionSecrets CompleteInitiator(InitiatorState state,
                                 const Bytes& response) {
#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
    if (!state.impl_) {
        throw Error("relay-v2 initiator state is empty or already consumed");
    }
    ParsedRequest request = ParseRequest(state.impl_->request);
    ParsedResponse parsed = ParseResponse(response);
    if (!(parsed.context == request.context) ||
        parsed.initiator_identity != request.initiator_identity ||
        parsed.responder_identity != request.responder_identity ||
        parsed.initiator_mlkem_public_key !=
            request.initiator_mlkem_public_key ||
        parsed.initiator_x25519_public_key !=
            request.initiator_x25519_public_key) {
        throw Error("relay-v2 response context, identity, or KEX echo mismatch");
    }
    const Bytes expected_request_digest = RequestDigest(state.impl_->request);
    if (!EqualBytes(parsed.request_digest, expected_request_digest)) {
        throw Error("relay-v2 response is bound to a different request");
    }

    const Bytes unsigned_response = EncodeUnsignedResponse(
        parsed.context, parsed.initiator_identity, parsed.responder_identity,
        parsed.initiator_mlkem_public_key,
        parsed.initiator_x25519_public_key,
        parsed.responder_mlkem_ciphertext,
        parsed.responder_x25519_public_key, parsed.request_digest);
    SecureBytes signature_input = BuildResponseSignatureInput(
        state.impl_->request, unsigned_response);
    if (!crypto::verify_composite(
            parsed.responder_public_key.classical.get(),
            parsed.responder_public_key.pq.get(), signature_input.bytes(),
            parsed.signature)) {
        throw Error("relay-v2 responder composite signature rejected");
    }
    ValidateRelayPsk(request.context.password_policy,
                     state.impl_->relay_psk.bytes());
    SecureBytes kem_shared{basefwx::pq::KemDecrypt(
        basefwx::pq::KemAlgorithm::MlKem1024,
        state.impl_->mlkem.private_key,
        parsed.responder_mlkem_ciphertext)};
    SecureBytes x25519_shared{
        basefwx::x25519::DeriveSharedSecret(
            state.impl_->x25519.private_key,
            parsed.responder_x25519_public_key)};
    DerivedPair derived = DeriveSecrets(
        state.impl_->request, response, kem_shared.bytes(),
        x25519_shared.bytes(), state.impl_->relay_psk.bytes());
    auto secrets_impl = std::make_unique<SessionSecrets::Impl>(
        std::move(derived.initial_root), std::move(derived.epoch_psk));
    return SessionSecrets{std::move(secrets_impl)};
#else
    (void)state;
    (void)response;
    throw Error("relay-v2 hybrid crypto requires BaseFWX");
#endif
}

std::unique_ptr<ratchet::SessionRatchet> MakeSessionRatchet(
    SessionSecrets secrets,
    ratchet::EndpointRole role,
    std::uint16_t outbound_window,
    std::uint16_t inbound_window,
    ratchet::RatchetPolicy outbound_policy,
    ratchet::RatchetPolicy inbound_policy) {
#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
    if (!secrets.valid()) {
        throw Error("relay-v2 session secrets are empty or already consumed");
    }
    std::unique_ptr<SessionSecrets::Impl> owned = std::move(secrets.impl_);
    return std::make_unique<ratchet::SessionRatchet>(
        role, std::move(owned->initial_root), std::move(owned->epoch_psk),
        outbound_window, inbound_window, outbound_policy, inbound_policy);
#else
    (void)secrets;
    (void)role;
    (void)outbound_window;
    (void)inbound_window;
    (void)outbound_policy;
    (void)inbound_policy;
    throw Error("relay-v2 hybrid crypto requires BaseFWX");
#endif
}

}  // namespace yume::client::relay_v2
