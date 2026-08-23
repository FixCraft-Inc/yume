/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include "core/protocol/control_protocol.hpp"
#include "core/security/crypto.hpp"
#include "core/security/session_ratchet.hpp"

namespace yume::client::relay_v2 {

using Bytes = std::vector<std::uint8_t>;
using Digest32 = std::array<std::uint8_t, 32>;

inline constexpr std::uint16_t kProtocolVersion = 2;
inline constexpr std::uint8_t kRecordSchemaVersion = 1;
inline constexpr std::size_t kNonceBytes = 32;
inline constexpr std::size_t kMetadataDigestBytes = 32;
inline constexpr std::size_t kRelayPskBytes = 32;
inline constexpr std::size_t kX25519PublicKeyBytes = 32;
inline constexpr std::size_t kMlKem1024PublicKeyBytes = 1568;
inline constexpr std::size_t kMlKem1024CiphertextBytes = 1568;
inline constexpr std::size_t kMaxEndpointIdBytes = 255;
inline constexpr std::size_t kMaxIdentityBytes = 16U * 1024U;
inline constexpr std::size_t kMaxRecordBytes = 32U * 1024U;

class Error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// This is a signed policy value, not a password or KDF selection. A required
// policy accepts exactly one already-derived 32-byte out-of-band relay PSK;
// NotRequired accepts no PSK. Human-password processing stays outside the
// handshake and cannot be selected by an untrusted record.
enum class PasswordPolicy : std::uint8_t {
    NotRequired = 1,
    Required = 2,
};

// Public context supplied by the already-authorized relay/invite layer. The
// metadata digest is over the exact metadata representation chosen by that
// layer; this codec binds the digest and deliberately does not canonicalize
// JSON or reinterpret metadata itself.
struct HandshakeContext {
    control::ChannelKind channel_kind{control::ChannelKind::chat};
    std::string initiator_endpoint_id;
    std::string responder_endpoint_id;
    Digest32 nonce{};
    PasswordPolicy password_policy{PasswordPolicy::Required};
    Digest32 metadata_digest{};

    bool operator==(const HandshakeContext&) const = default;
};

class InitiatorState;
struct InitiatorRequest;
struct ResponderResult;

// Move-only ownership for the two establishment outputs. Accessors borrow the
// live secret bytes without copying; destruction wipes both buffers. The relay
// ratchet integration should consume these spans synchronously and must not
// retain them past this object's lifetime.
class SessionSecrets {
public:
    SessionSecrets() noexcept;
    SessionSecrets(const SessionSecrets&) = delete;
    SessionSecrets& operator=(const SessionSecrets&) = delete;
    SessionSecrets(SessionSecrets&&) noexcept;
    SessionSecrets& operator=(SessionSecrets&&) noexcept;
    ~SessionSecrets();

    bool valid() const noexcept;
    std::span<const std::uint8_t> initial_root() const noexcept;
    std::span<const std::uint8_t> epoch_psk() const noexcept;

private:
    struct Impl;
    explicit SessionSecrets(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;

    friend struct ResponderResult;
    friend SessionSecrets CompleteInitiator(
        InitiatorState state, const Bytes& response);
    friend ResponderResult Respond(
        const Bytes& request,
        const HandshakeContext& expected_context,
        const Bytes& expected_initiator_identity,
        const crypto::CompositeKeyPair& responder_identity,
        Bytes relay_psk);
    friend std::unique_ptr<ratchet::SessionRatchet> MakeSessionRatchet(
        SessionSecrets secrets,
        ratchet::EndpointRole role,
        std::uint16_t outbound_window,
        std::uint16_t inbound_window,
        ratchet::RatchetPolicy outbound_policy,
        ratchet::RatchetPolicy inbound_policy);
};

// Owns the initiator's ephemeral ML-KEM-1024/X25519 private keys, the exact
// signed request, and (when required) the relay PSK. It is one-shot and
// move-only. CompleteInitiator takes it by value so every success or failure
// retires and wipes the pending state.
class InitiatorState {
public:
    InitiatorState() noexcept;
    InitiatorState(const InitiatorState&) = delete;
    InitiatorState& operator=(const InitiatorState&) = delete;
    InitiatorState(InitiatorState&&) noexcept;
    InitiatorState& operator=(InitiatorState&&) noexcept;
    ~InitiatorState();

    bool valid() const noexcept;

private:
    struct Impl;
    explicit InitiatorState(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;

    friend struct InitiatorRequest;
    friend InitiatorRequest BeginInitiator(
        const HandshakeContext& context,
        const crypto::CompositeKeyPair& initiator_identity,
        const Bytes& responder_identity,
        Bytes relay_psk);
    friend SessionSecrets CompleteInitiator(
        InitiatorState state, const Bytes& response);
};

struct InitiatorRequest {
    Bytes encoded;
    InitiatorState state;

    InitiatorRequest(Bytes encoded_request,
                     InitiatorState pending) noexcept;
    InitiatorRequest(const InitiatorRequest&) = delete;
    InitiatorRequest& operator=(const InitiatorRequest&) = delete;
    InitiatorRequest(InitiatorRequest&&) noexcept = default;
    InitiatorRequest& operator=(InitiatorRequest&&) noexcept = default;
};

struct ResponderResult {
    Bytes encoded;
    SessionSecrets secrets;

    ResponderResult(Bytes encoded_response,
                    SessionSecrets derived) noexcept;
    ResponderResult(const ResponderResult&) = delete;
    ResponderResult& operator=(const ResponderResult&) = delete;
    ResponderResult(ResponderResult&&) noexcept = default;
    ResponderResult& operator=(ResponderResult&&) noexcept = default;
};

// Produces the exact public identity representation accepted in transcript
// fields. CanonicalizeIdentity rejects anything other than an exact two-key
// Ed25519 + ML-DSA-87 PEM bundle, then re-encodes it so alternate PEM spelling
// cannot create two transcript representations for one identity.
Bytes EncodeIdentity(const crypto::CompositeKeyPair& identity);
Bytes CanonicalizeIdentity(const Bytes& pem_bundle);

// Strictly decodes the public context carried by an initiator request. The
// returned nonce is initiator-chosen and still untrusted; a responder uses it
// only after independently replacing/checking the routable fields (kind,
// endpoint IDs, password policy, and metadata digest) before Respond verifies
// the composite signature over the complete request.
HandshakeContext InspectInitiatorRequest(const Bytes& request);

// relay_psk is taken by value and wiped on every exit. Pass a temporary or
// std::move an owned buffer to avoid leaving an extra caller-side copy.
InitiatorRequest BeginInitiator(
    const HandshakeContext& context,
    const crypto::CompositeKeyPair& initiator_identity,
    const Bytes& responder_identity,
    Bytes relay_psk);

ResponderResult Respond(
    const Bytes& request,
    const HandshakeContext& expected_context,
    const Bytes& expected_initiator_identity,
    const crypto::CompositeKeyPair& responder_identity,
    Bytes relay_psk);

SessionSecrets CompleteInitiator(InitiatorState state,
                                 const Bytes& response);

// Consumes both establishment secrets directly into SessionRatchet's preferred
// SecureBytes constructor. There is no plaintext vector export or duplicate;
// callers map initiator/responder to Client/Server explicitly at integration.
std::unique_ptr<ratchet::SessionRatchet> MakeSessionRatchet(
    SessionSecrets secrets,
    ratchet::EndpointRole role,
    std::uint16_t outbound_window = ratchet::kMinRekeyWindow,
    std::uint16_t inbound_window = ratchet::kMinRekeyWindow,
    ratchet::RatchetPolicy outbound_policy = ratchet::kExtremePolicy,
    ratchet::RatchetPolicy inbound_policy = ratchet::kExtremePolicy);

}  // namespace yume::client::relay_v2
