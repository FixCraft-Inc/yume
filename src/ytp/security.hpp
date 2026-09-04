/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include "ytp/protocol.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace yume::ytp1 {

// YTP/1 has one mandatory suite. These identifiers are protocol constants,
// not provider-selection strings and not negotiation offers.
inline constexpr std::string_view kSuiteId =
    "YTP/1:TLS13:H2:ED25519+ML-DSA-87:X25519+ML-KEM-1024:"
    "HKDF-SHA256:AES-256-GCM";

inline constexpr std::string_view kAuthSignatureDomain =
    "yume/ytp/1/auth-signature/v1";
inline constexpr std::string_view kCompositeIdentityDomain =
    "yume/ytp/1/composite-identity/v1";
inline constexpr std::string_view kRoleBindingDomain =
    "yume/ytp/1/auth-role/v1";
inline constexpr std::string_view kTranscriptDomain =
    "yume/ytp/1/transcript/v1";
inline constexpr std::string_view kRootDomain = "yume/ytp/1/root/v1";
inline constexpr std::string_view kPskDomain = "yume/ytp/1/psk/v1";
inline constexpr std::string_view kHandshakeConfirmationDomain =
    "yume/ytp/1/handshake-confirmation/v1";
inline constexpr std::string_view kClientToServerDomain =
    "yume/ytp/1/c2s-root/v1";
inline constexpr std::string_view kServerToClientDomain =
    "yume/ytp/1/s2c-root/v1";
inline constexpr std::string_view kMessageDomain =
    "yume/ytp/1/message/v1";
inline constexpr std::string_view kAadDomain = "yume/ytp/1/aad/v1";
inline constexpr std::string_view kRatchetDomain =
    "yume/ytp/1/ratchet/v1";
inline constexpr std::string_view kExporterLabel =
    "EXPORTER-yume/ytp/1/channel-binding/v1";

inline constexpr std::size_t kTranscriptHashSize = 32;
inline constexpr std::size_t kExporterSize = 32;
inline constexpr std::size_t kPskSize = 32;
inline constexpr std::size_t kX25519PublicKeySize = 32;
inline constexpr std::size_t kX25519SharedSecretSize = 32;
inline constexpr std::size_t kMlKem1024PublicKeySize = 1568;
inline constexpr std::size_t kMlKem1024CiphertextSize = 1568;
inline constexpr std::size_t kMlKem1024SharedSecretSize = 32;
inline constexpr std::size_t kEd25519SignatureSize = 64;
inline constexpr std::size_t kMlDsa87SignatureSize = 4627;
inline constexpr std::size_t kCompositeSignatureSize =
    kEd25519SignatureSize + kMlDsa87SignatureSize;
inline constexpr std::size_t kMaxCompositeIdentitySize = 16U << 10;

// Exact YTP/1 security-parameter encoding. Every byte is mandatory. A future
// alternative composition requires a different suite and wire version rather
// than changing this value in place.
inline constexpr std::array<std::uint8_t, 24> kRequiredSecurityParameters{
    1,  // parameter schema
    1,  // composite authentication
    1,  // Ed25519
    1,  // ML-DSA-87
    1,  // hybrid establishment
    1,  // X25519
    1,  // ML-KEM-1024
    1,  // HKDF-SHA256
    1,  // AES-256-GCM
    32, // AEAD key bytes
    12, // AEAD nonce bytes
    16, // AEAD tag bytes
    32, // per-identity access PSK bytes
    32, // TLS exporter bytes
    32, // X25519 shared-secret bytes
    32, // ML-KEM shared-secret bytes
    0x06, 0x20, // ML-KEM-1024 public key bytes: 1568
    0x06, 0x20, // ML-KEM-1024 ciphertext bytes: 1568
    0x00, 0x40, // maximum prepared/in-flight ratchet epochs: 64
    1,          // one-use message keys required
    0,          // reserved; must remain zero
};

[[nodiscard]] constexpr std::span<const std::uint8_t>
RequiredSecurityParameters() noexcept {
    return kRequiredSecurityParameters;
}

[[nodiscard]] bool IsRequiredSecurityParameters(
    std::span<const std::uint8_t> encoded) noexcept;

enum class AuthMessageType : std::uint8_t {
    Challenge = 1,
    Response = 2,
    Accepted = 3,
    RekeyInit = 4,
    RekeyAck = 5,
};

enum class AuthFieldId : std::uint16_t {
    SuiteId = 1,
    SecurityParameters = 2,
    SenderRole = 3,
    TranscriptHash = 4,
    Identity = 5,
    CompositeSignature = 6,
    MlKemPublicKey = 7,
    MlKemCiphertext = 8,
    X25519PublicKey = 9,
    CapabilityManifest = 10,
    Nonce = 11,
    PskAuthenticator = 12,
    KeyConfirmation = 13,
};

inline constexpr std::uint16_t kAuthFieldFlagCritical = 0x0001;
inline constexpr std::size_t kMaxAuthFields = 32;
inline constexpr std::size_t kMaxAuthRecordSize = 64U << 10;

struct AuthField {
    std::uint16_t id{0};
    bool critical{false};
    std::vector<std::uint8_t> value;

    friend bool operator==(const AuthField&, const AuthField&) = default;
};

// SuiteId, SecurityParameters, and SenderRole are inserted by the encoder and
// verified by the decoder. Callers supply only fields with IDs greater than 3.
struct AuthRecord {
    AuthMessageType type{AuthMessageType::Challenge};
    EndpointRole sender_role{EndpointRole::Client};
    std::vector<AuthField> fields;

    friend bool operator==(const AuthRecord&, const AuthRecord&) = default;
};

// AUTH record prefix:
//   u8 schema | u8 message_type | u16 field_count | u32 field_bytes
// Each canonical TLV is:
//   u16 field_id | u16 flags | u32 value_bytes | value
// IDs increase strictly. Flag bit zero means critical; all other bits are
// reserved. Unknown critical fields fail closed, while bounded noncritical
// fields survive a decode/re-encode cycle.

[[nodiscard]] Result<std::vector<std::uint8_t>> EncodeAuthRecord(
    const AuthRecord& record);
[[nodiscard]] Result<AuthRecord> DecodeAuthRecord(
    std::span<const std::uint8_t> encoded);

inline constexpr std::size_t kMaxKeyScheduleInputSize = 128U << 10;

// All spans are borrowed for the duration of a synchronous call. Secret
// contributors remain in caller-owned, wipeable storage. The encoder writes to
// caller-owned memory so it never creates an untracked copy of PSK or shared
// secret material.
struct KeyScheduleInput {
    EndpointRole initiator_role{EndpointRole::Client};
    EndpointRole responder_role{EndpointRole::Server};
    std::span<const std::uint8_t> transcript_hash;
    std::span<const std::uint8_t> exporter;
    std::span<const std::uint8_t> client_identity;
    std::span<const std::uint8_t> server_identity;
    std::span<const std::uint8_t> client_capability_manifest;
    std::span<const std::uint8_t> server_capability_manifest;
    std::span<const std::uint8_t> access_psk;
    std::span<const std::uint8_t> client_x25519_public_key;
    std::span<const std::uint8_t> server_x25519_public_key;
    std::span<const std::uint8_t> x25519_shared_secret;
    std::span<const std::uint8_t> mlkem_public_key;
    std::span<const std::uint8_t> mlkem_ciphertext;
    std::span<const std::uint8_t> mlkem_shared_secret;
};

// The canonical key-schedule encoding contains 18 strictly ordered tagged
// fields: root domain, suite, initiator/responder roles, transcript, exporter,
// client/server identities, both endpoints' capabilities, fixed security
// parameters, PSK, both X25519 public keys and shared contribution, and
// ML-KEM public key, ciphertext, and shared contribution. There are no
// optional security fields.

[[nodiscard]] Status ValidateKeyScheduleInput(
    const KeyScheduleInput& input) noexcept;
[[nodiscard]] Result<std::size_t> KeyScheduleInputEncodedSize(
    const KeyScheduleInput& input) noexcept;
[[nodiscard]] Status EncodeKeyScheduleInput(
    const KeyScheduleInput& input,
    std::span<std::uint8_t> output,
    std::size_t& written) noexcept;

} // namespace yume::ytp1
